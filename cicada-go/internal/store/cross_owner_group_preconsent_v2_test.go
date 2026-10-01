package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCrossOwnerGroupPreconsentPreviewIsExactReadOnlyAndOwnerBound(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, false)
	s := f.base.store
	network, err := s.CreateNetwork(Network{HubID: f.base.hubID, OwnerID: f.base.source.ownerID,
		Name: "synthetic pre-consent Network"})
	if err != nil {
		t.Fatal(err)
	}
	for _, groupID := range []string{f.base.source.groupID, f.base.target.groupID} {
		if _, err := s.db.Exec(`UPDATE groups SET context_policy='group_scoped' WHERE id=?`, groupID); err != nil {
			t.Fatal(err)
		}
		group, err := s.GetGroup(groupID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.PrepareGroupNetworkMapping(groupID, network.ID, "synthetic pre-consent mapping", group.Version); err != nil {
			t.Fatal(err)
		}
		if err := s.ApproveGroupNetworkMapping(groupID, network.ID, group.Version); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []externalThreadInviteTestEndpoint{f.base.source, f.base.target} {
		if _, err := s.db.Exec(`UPDATE fabric_endpoints SET owner=? WHERE id=?`, endpoint.ownerID, endpoint.endpointID); err != nil {
			t.Fatal(err)
		}
		ep, err := s.GetEndpointV2(endpoint.endpointID)
		if err != nil {
			t.Fatal(err)
		}
		stamp := now()
		if _, err := s.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
VALUES(?,?,?,'[]','active','',1,?,?)`, NewID("nm"), network.ID, ep.PrincipalID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
VALUES(?,?,'active',1,?,0,?,?)`, network.ID, endpoint.endpointID, endpoint.endpointID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	group, err := s.GetGroup(f.base.source.groupID)
	if err != nil {
		t.Fatal(err)
	}
	sequence := map[string]uint64{}
	acceptRequest := func(owner, deviceID, route string) string {
		t.Helper()
		sequence[owner]++
		device, err := s.GetClientDevice(owner, deviceID)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(NewID("synthetic_preconsent_cipher")))
		accepted, err := s.AcceptClientRequest(AcceptClientRequestInput{
			OwnerID: owner, DeviceID: deviceID,
			SessionEpoch: device.SessionEpoch, Sequence: sequence[owner], OperationID: NewID("synthetic_preconsent_op"),
			RouteOperation: route, CiphertextDigest: hex.EncodeToString(digest[:]),
		})
		if err != nil {
			t.Fatal(err)
		}
		return accepted.Request.ID
	}
	admitRequest := acceptRequest(f.base.source.ownerID, f.sourceOwner.clientDeviceID,
		CrossOwnerMemberAdmitOperation)
	admission, err := s.AdmitCrossOwnerGroupMemberForClientRequest(admitRequest, f.base.source.ownerID,
		group.ID, f.base.target.endpointID, []string{"space.read", "space.write"},
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), group.Revision, 0)
	if err != nil {
		t.Fatal(err)
	}
	beforeJoins, beforeProofs := countCrossOwnerRows(t, s, "cross_owner_group_joins_v2"),
		countCrossOwnerRows(t, s, "cross_owner_group_key_proofs_v2")
	previewRequest := acceptRequest(f.base.target.ownerID, f.targetOwner.clientDeviceID,
		CrossOwnerAdmissionPreviewOperation)
	preview, err := s.PreviewCrossOwnerGroupPreconsentForClientRequest(previewRequest,
		f.base.target.ownerID, admission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if preview.AdmissionID != admission.ID || preview.NetworkID != network.ID || preview.NetworkName != network.Name ||
		preview.GroupID != group.ID || preview.GroupName == "" ||
		preview.GroupOwnerID != f.base.source.ownerID || preview.GroupOwnerName == "" ||
		preview.EndpointID != f.base.target.endpointID || preview.EndpointName == "" ||
		preview.EndpointOwnerID != f.base.target.ownerID || preview.EndpointOwnerName == "" ||
		preview.MembershipID != admission.MembershipID || preview.MembershipRevision != admission.MembershipRevision ||
		preview.GroupRevision != admission.GroupRevision || preview.BindingID == "" || preview.BindingEpoch == 0 ||
		preview.ContextPolicy != "group_scoped" || !preview.CrossOwnerContextShared || preview.HistoryIncluded ||
		len(preview.Grants) != 2 || preview.AdmissionState != "ACTIVE" {
		t.Fatalf("exact pre-consent preview is incomplete or unsafe: %+v", preview)
	}
	encoded, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	for _, privateField := range []string{"native_session_id", "node_id", "workspace", "candidate", "reader_roster"} {
		if strings.Contains(string(encoded), privateField) {
			t.Fatalf("pre-consent preview leaked forbidden field %q: %s", privateField, encoded)
		}
	}
	if got := countCrossOwnerRows(t, s, "cross_owner_group_joins_v2"); got != beforeJoins {
		t.Fatalf("read-only preview changed join rows: %d -> %d", beforeJoins, got)
	}
	if got := countCrossOwnerRows(t, s, "cross_owner_group_key_proofs_v2"); got != beforeProofs {
		t.Fatalf("read-only preview changed key proof rows: %d -> %d", beforeProofs, got)
	}
	if _, err := s.PreviewCrossOwnerGroupPreconsentForClientRequest(previewRequest,
		f.base.source.ownerID, admission.ID); !errors.Is(err, ErrCrossOwnerGroupDenied) {
		t.Fatalf("Group Owner read the Endpoint Owner pre-consent view: %v", err)
	}
	wrongRoute := acceptRequest(f.base.target.ownerID, f.targetOwner.clientDeviceID,
		"space.key_manifest_v2")
	if _, err := s.PreviewCrossOwnerGroupPreconsentForClientRequest(wrongRoute,
		f.base.target.ownerID, admission.ID); !errors.Is(err, ErrCrossOwnerGroupDenied) {
		t.Fatalf("wrong encrypted operation route read pre-consent view: %v", err)
	}
	assertDenied := func(reason string) {
		t.Helper()
		request := acceptRequest(f.base.target.ownerID, f.targetOwner.clientDeviceID,
			CrossOwnerAdmissionPreviewOperation)
		if _, err := s.PreviewCrossOwnerGroupPreconsentForClientRequest(request,
			f.base.target.ownerID, admission.ID); !errors.Is(err, ErrCrossOwnerGroupDenied) {
			t.Fatalf("preview succeeded after %s was revoked: %v", reason, err)
		}
	}
	if _, err := s.db.Exec(`UPDATE memberships SET status='revoked',revision=revision+1 WHERE id=?`, admission.MembershipID); err != nil {
		t.Fatal(err)
	}
	assertDenied("Group membership")
	if _, err := s.db.Exec(`UPDATE memberships SET status='active',revision=? WHERE id=?`, admission.MembershipRevision, admission.MembershipID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE network_memberships_v2 SET status='revoked' WHERE network_id=? AND principal_id=?`, network.ID, preview.PrincipalID); err != nil {
		t.Fatal(err)
	}
	assertDenied("Network membership")
	if _, err := s.db.Exec(`UPDATE network_memberships_v2 SET status='active' WHERE network_id=? AND principal_id=?`, network.ID, preview.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE endpoint_network_memberships_v2 SET status='revoked' WHERE network_id=? AND endpoint_id=?`, network.ID, preview.EndpointID); err != nil {
		t.Fatal(err)
	}
	assertDenied("Endpoint Network membership")
	if _, err := s.db.Exec(`UPDATE endpoint_network_memberships_v2 SET status='active' WHERE network_id=? AND endpoint_id=?`, network.ID, preview.EndpointID); err != nil {
		t.Fatal(err)
	}
	var nodeID string
	if err := s.db.QueryRow(`SELECT machine_id FROM fabric_endpoints WHERE id=?`, preview.EndpointID).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE node_owner_bindings_v2 SET state='REVOKED' WHERE node_id=? AND owner_id=?`, nodeID, f.base.target.ownerID); err != nil {
		t.Fatal(err)
	}
	assertDenied("Node owner binding")
	if _, err := s.db.Exec(`UPDATE node_owner_bindings_v2 SET state='ACTIVE' WHERE node_id=? AND owner_id=?`, nodeID, f.base.target.ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE session_bindings SET status='revoked' WHERE id=?`, preview.BindingID); err != nil {
		t.Fatal(err)
	}
	assertDenied("session binding")
}

func countCrossOwnerRows(t *testing.T, s *Store, table string) int {
	t.Helper()
	switch table {
	case "cross_owner_group_joins_v2", "cross_owner_group_key_proofs_v2":
	default:
		t.Fatalf("test helper does not allow table %q", table)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
