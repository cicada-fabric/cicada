package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestClientTopologyEndpointAdmissionEncryptedPreviewAndApply(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"),
		WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "synthetic-manager-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	database, err := store.New(filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	const ownerID, networkID, deviceID = "synthetic-admission-owner", "synthetic-admission-network", "synthetic-admission-phone"
	if _, err := database.CreatePrincipal(store.Principal{ID: ownerID, Kind: store.PrincipalKindHuman,
		OwnerID: ownerID, TrustDomainID: ownerID, Name: "Synthetic Owner", Status: store.PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	hubID, err := manager.ClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateNetwork(store.Network{ID: networkID, HubID: hubID,
		Name: "Synthetic admission Network", OwnerID: ownerID}); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(manager)
	hubPublic := manager.ClientControlPublicIdentity()
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceGrant, err := ownerKey.SignOwnerDeviceGrant(ownerID, deviceID, device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID, "device_id": deviceID,
		"device_public_identity": device.Public(), "owner_device_grant": deviceGrant,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrolled := httptest.NewRecorder()
	handler.ServeHTTP(enrolled, httptest.NewRequest(http.MethodPost, "/v2/client/devices/enroll", bytes.NewReader(enrollment)))
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("synthetic Client enrollment: %d %s", enrolled.Code, enrolled.Body.String())
	}

	const nodeID, nativeSessionID = "node_admission_fixture", "native_admission_fixture"
	nodeCredentialHash := sha256.Sum256([]byte("synthetic Node bearer"))
	nodeCredentialDigest := base64.RawURLEncoding.EncodeToString(nodeCredentialHash[:])
	codeDigest := admissionTestDigest("synthetic one-time device code")
	if _, err := database.CreatePendingNodeDeviceBinding(nodeID, "Synthetic admission Node",
		nodeCredentialDigest, codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	grants := []string{"directory.publish", "task.offer.list", "task.offer.publish"}
	invitation := "synthetic-admission-network-invitation-aaaaaaaaaaaaaaaaaaaa"
	if err := database.IssueNetworkInvitation(networkID, ownerID, ownerID, invitation,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
		t.Fatal(err)
	}
	issuedAt, expiresAt := time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour)
	joinProof, err := ownerKey.SignOwnerNetworkJoinGrant(ownerID, hubID, networkID, nodeID, nativeSessionID,
		store.NetworkInvitationDigest(invitation), ownerKey.Public().ID, grants, true, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Nonce     string `json:"nonce"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(joinProof, &claims); err != nil {
		t.Fatal(err)
	}
	joined, err := database.AcceptNetworkJoin(store.AcceptNetworkJoinInput{
		NetworkID: networkID, OwnerID: ownerID, TrustDomainID: ownerID, NodeID: nodeID,
		NativeSessionID: nativeSessionID, Harness: "codex", EndpointName: "Synthetic Network-only Endpoint",
		InvitationToken: invitation, ProofNonce: claims.Nonce,
		ProofDigest: store.NetworkInvitationDigest(string(joinProof)), ProofExpiresAt: claims.ExpiresAt,
		OwnerKeyID: ownerKey.Public().ID, OwnerJoinProof: string(joinProof), NodeCredentialHash: nodeCredentialDigest,
		Grants: grants, Discoverable: true, CredentialHash: admissionTestDigest("synthetic access credential"),
		LeaseOwner: "admission-fixture-lease", LeaseExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := store.NetworkAccessScope{NetworkID: networkID, PrincipalID: joined.PrincipalID,
		EndpointID: joined.EndpointID, AccessSessionID: joined.AccessSessionID,
		AccessEpoch: joined.AccessSessionEpoch, LeaseOwner: "admission-fixture-lease",
		MembershipID: joined.MembershipID, MembershipRevision: joined.MembershipRevision,
		EndpointMembershipRevision: joined.EndpointRevision}
	if _, err := database.EnsureNetworkDirectNativeBinding(scope); err != nil {
		t.Fatal(err)
	}

	binding := clientwire.Binding{HubID: hubID, OwnerID: ownerID, DeviceID: deviceID,
		SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	var sequence uint64
	call := func(operation string, value any) (bool, json.RawMessage) {
		t.Helper()
		sequence++
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
			HubID: hubID, OwnerID: ownerID, DeviceID: deviceID, SessionEpoch: 1,
			Sequence: sequence, OperationID: fmt.Sprintf("synthetic-admission-%d", sequence),
			Operation: operation, SenderKeyID: device.Public().ID, SenderKeyVersion: 1,
			ReceiverKeyID: hubPublic.ID, ReceiverKeyVersion: 1}
		packet, err := clientwire.SealRequest(device, hubPublic, binding, route, body)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(packet)))
		if response.Code != http.StatusOK {
			t.Fatalf("encrypted %s status=%d body=%s", operation, response.Code, response.Body.String())
		}
		opened, err := clientwire.OpenResponse(device, hubPublic, binding, response.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if err := json.Unmarshal(opened.Plaintext, &result); err != nil {
			t.Fatal(err)
		}
		if !result.OK {
			return false, json.RawMessage(result.Error)
		}
		return true, result.Result
	}
	directoryOK, directoryResult := call("network.directory", map[string]any{
		"network_id": networkID, "limit": 64,
	})
	if !directoryOK {
		t.Fatalf("exact encrypted Network directory operation failed: %s", directoryResult)
	}
	var directory struct {
		NetworkID  string            `json:"network_id"`
		Endpoints  []json.RawMessage `json:"endpoints"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.Unmarshal(directoryResult, &directory); err != nil || directory.NetworkID != networkID || len(directory.Endpoints) != 1 {
		t.Fatalf("opted-in directory page: %+v err=%v", directory, err)
	}
	var card map[string]json.RawMessage
	if err := json.Unmarshal(directory.Endpoints[0], &card); err != nil || len(card) != 4 ||
		card["network_id"] == nil || card["endpoint_id"] == nil || card["alias"] == nil || card["presence"] == nil {
		t.Fatalf("directory exposed an unexpected projection: %s err=%v", directory.Endpoints[0], err)
	}
	groupOK, groupResult := call("topology.apply", map[string]any{
		"kind": "group.create", "create_group": map[string]any{"group": map[string]any{
			"network_id": networkID, "name": "Admission Group",
		}},
	})
	if !groupOK {
		t.Fatalf("Owner Group creation failed: %s", groupResult)
	}
	var created control.ClientTopologyChangeResult
	if err := json.Unmarshal(groupResult, &created); err != nil || created.Group == nil || created.Group.ContextPolicy != "group_scoped" {
		t.Fatalf("Group projection: %+v err=%v", created, err)
	}
	previewOK, previewResult := call("topology.endpoint_admission_preview", map[string]string{
		"network_id": networkID, "group_id": created.Group.GroupID, "endpoint_id": joined.EndpointID,
	})
	if !previewOK {
		t.Fatalf("Owner endpoint admission preview failed: %s", previewResult)
	}
	var preview store.ClientTopologyEndpointAdmissionPreview
	if err := json.Unmarshal(previewResult, &preview); err != nil || preview.EndpointMigrationState != store.EndpointMigrationPendingGroup ||
		preview.EndpointPrincipalID != joined.PrincipalID || preview.GroupContextPolicy != "group_scoped" ||
		len(preview.AdmissionGrants) != 0 || len(preview.AdmissionRoles) != 1 || preview.AdmissionRoles[0] != "member" ||
		preview.HistoryIncluded || preview.KeyGrantCreated || !preview.ExistingThreadMemoryRetained {
		t.Fatalf("exact minimum admission preview: %+v err=%v", preview, err)
	}
	input := store.ClientTopologyEndpointAdmissionInput{
		NetworkID: preview.NetworkID, GroupID: preview.GroupID, EndpointID: preview.EndpointID,
		ExpectedEndpointMigrationState: preview.EndpointMigrationState,
		ExpectedNetworkVersion:         preview.NetworkVersion, ExpectedGroupVersion: preview.GroupVersion,
		ExpectedNetworkMembership: preview.NetworkMembershipRevision,
		ExpectedEndpointNetwork:   preview.EndpointNetworkRevision,
		NetworkAccessBindingID:    preview.NetworkAccessBindingID, NetworkAccessEpoch: preview.NetworkAccessEpoch,
		NativeBindingID: preview.NativeBindingID, NativeBindingEpoch: preview.NativeBindingEpoch,
		ExpectedMembership: preview.MembershipRevision, ExpectedEndpointGroup: preview.EndpointGroupRevision,
	}
	action := control.ClientTopologyAction{Kind: control.ClientTopologyAdmitEndpoint,
		AdmitEndpoint: &control.ClientTopologyAdmitEndpointAction{Admission: input}}
	applyOK, applyResult := call("topology.apply", action)
	if !applyOK {
		t.Fatalf("exact same-Owner Endpoint admission failed: %s", applyResult)
	}
	var admitted control.ClientTopologyChangeResult
	if err := json.Unmarshal(applyResult, &admitted); err != nil || admitted.EndpointMember == nil ||
		admitted.EndpointMember.Role != "member" || len(admitted.EndpointMember.Roles) != 1 ||
		admitted.EndpointMember.Roles[0] != "member" ||
		admitted.EndpointMember.BroadcastPermissionEnabled ||
		admitted.EndpointGroup == nil || admitted.EndpointGroup.Status != "active" {
		t.Fatalf("admission result exceeded minimum or omitted reference: %+v err=%v", admitted, err)
	}
	snapshotOK, snapshotResult := call("topology.snapshot", struct{}{})
	if !snapshotOK {
		t.Fatalf("topology reconciliation after admission failed: %s", snapshotResult)
	}
	var snapshot control.ClientTopologySnapshot
	if err := json.Unmarshal(snapshotResult, &snapshot); err != nil {
		t.Fatal(err)
	}
	visible := false
	for _, endpoint := range snapshot.Endpoints {
		if endpoint.EndpointID == joined.EndpointID {
			for _, groupID := range endpoint.GroupIDs {
				visible = visible || groupID == created.Group.GroupID
			}
		}
	}
	if !visible {
		t.Fatalf("admitted Network-only Endpoint is not visible in the Owner topology snapshot: %+v", snapshot.Endpoints)
	}
}

func admissionTestDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
