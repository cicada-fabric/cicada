package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

// This exercises the actual encrypted Client device boundary on an ACTIVE Hub.
// The test owner has no Group when first selecting a Network.
func TestClientActiveNetworkTopologyEncryptedOwnerScope(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"),
		WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "legacy-manager"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	database, err := store.New(filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	const ownerID = "synthetic-client-network-owner"
	if _, err := database.CreatePrincipal(store.Principal{ID: ownerID, Kind: store.PrincipalKindHuman,
		OwnerID: ownerID, TrustDomainID: ownerID, Name: "synthetic owner", Status: store.PrincipalStatusActive}); err != nil {
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
	for _, network := range []store.Network{
		{ID: "synthetic-network-a", HubID: hubID, Name: "Network A", OwnerID: ownerID},
		{ID: "synthetic-network-b", HubID: hubID, Name: "Network B", OwnerID: ownerID},
		{ID: "synthetic-network-foreign", HubID: hubID, Name: "Manager private", OwnerID: manager.Identity().ID},
	} {
		if _, err := database.CreateNetwork(network); err != nil {
			t.Fatal(err)
		}
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
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "synthetic-phone", device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "synthetic-phone", "device_public_identity": device.Public(), "owner_device_grant": grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrolled := httptest.NewRecorder()
	handler.ServeHTTP(enrolled, httptest.NewRequest(http.MethodPost, "/v2/client/devices/enroll", bytes.NewReader(enrollment)))
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("synthetic Client enrollment: %d %s", enrolled.Code, enrolled.Body.String())
	}
	binding := clientwire.Binding{HubID: hubID, OwnerID: ownerID, DeviceID: "synthetic-phone",
		SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	var sequence uint64
	call := func(operation, body string) (bool, json.RawMessage, []byte) {
		t.Helper()
		sequence++
		route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
			HubID: hubID, OwnerID: ownerID, DeviceID: binding.DeviceID, SessionEpoch: 1,
			Sequence: sequence, OperationID: fmt.Sprintf("synthetic-topology-%d", sequence),
			Operation: operation, SenderKeyID: device.Public().ID, SenderKeyVersion: 1,
			ReceiverKeyID: hubPublic.ID, ReceiverKeyVersion: 1}
		packet, err := clientwire.SealRequest(device, hubPublic, binding, route, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(packet))
		request.Header.Set("Authorization", "Bearer legacy-manager") // Must not elevate the guest.
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
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
		}
		if err := json.Unmarshal(opened.Plaintext, &result); err != nil {
			t.Fatal(err)
		}
		return result.OK, result.Result, packet
	}
	if ok, data, _ := call("topology.snapshot", `{}`); !ok {
		t.Fatalf("empty owner topology: %s", data)
	} else {
		var snapshot control.ClientTopologySnapshot
		if err := json.Unmarshal(data, &snapshot); err != nil || len(snapshot.Networks) != 2 ||
			len(snapshot.Groups) != 0 || snapshot.Networks[0].NetworkID != "synthetic-network-a" ||
			snapshot.Networks[1].NetworkID != "synthetic-network-b" {
			t.Fatalf("owner Network selection leaked or omitted scope: %#v err=%v", snapshot, err)
		}
	}
	// An Owner may see a foreign-owned Network only while their own Endpoint
	// has a current membership there. The encrypted projection must parse
	// expiry as an instant, not compare timestamp text or trust malformed rows.
	principal, err := database.CreatePrincipal(store.Principal{ID: "synthetic-network-only-agent",
		Kind: store.PrincipalKindAgent, OwnerID: ownerID, TrustDomainID: ownerID,
		Name: "synthetic network-only agent", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := database.UpsertEndpoint(store.Endpoint{ID: "synthetic-network-only-endpoint",
		Name: "synthetic network-only endpoint", Harness: "codex", NativeSessionID: "synthetic-network-only-native",
		MachineID: "synthetic-network-only-node", Owner: ownerID, Status: "online"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := raw.Exec(`UPDATE fabric_endpoints SET principal_id=? WHERE id=?`, principal.ID, endpoint.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
VALUES(?,?,?,'[]','active',?,1,?,?)`, "synthetic-network-only-membership", "synthetic-network-foreign",
		principal.ID, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
VALUES(?,?,'active',1,'synthetic endpoint',0,?,?)`, "synthetic-network-foreign", endpoint.ID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	for _, expiry := range []struct {
		value   string
		visible bool
	}{
		{value: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), visible: true},
		{value: time.Now().UTC().Add(-time.Hour).In(time.FixedZone("synthetic-plus-14", 14*3600)).Format(time.RFC3339Nano)},
		{value: "zz-not-rfc3339"},
	} {
		if _, err := raw.Exec(`UPDATE network_memberships_v2 SET expires_at=? WHERE id=?`,
			expiry.value, "synthetic-network-only-membership"); err != nil {
			t.Fatal(err)
		}
		ok, data, _ := call("topology.snapshot", `{}`)
		if !ok {
			t.Fatalf("owner topology with expiry %q: %s", expiry.value, data)
		}
		var snapshot control.ClientTopologySnapshot
		if err := json.Unmarshal(data, &snapshot); err != nil {
			t.Fatal(err)
		}
		var networkVisible, endpointVisible bool
		for _, card := range snapshot.Networks {
			if card.NetworkID == "synthetic-network-foreign" {
				networkVisible = true
			}
		}
		for _, card := range snapshot.Endpoints {
			if card.EndpointID == endpoint.ID {
				endpointVisible = true
			}
		}
		if networkVisible != expiry.visible || endpointVisible != expiry.visible {
			t.Fatalf("expiry %q leaked/omitted foreign topology: network=%t endpoint=%t want=%t",
				expiry.value, networkVisible, endpointVisible, expiry.visible)
		}
	}
	for _, body := range []string{
		`{"kind":"group.create","create_group":{"group":{"name":"missing-network"}}}`,
		`{"kind":"group.create","create_group":{"group":{"network_id":"synthetic-network-foreign","name":"foreign-network"}}}`,
		`{"kind":"group.create","create_group":{"group":{"network_id":"synthetic-network-a","name":"spoofed-owner","owner_id":"synthetic-network-foreign"}}}`,
	} {
		if ok, data, _ := call("topology.apply", body); ok {
			t.Fatalf("unauthorized Group creation accepted: %s", data)
		}
	}
	if ok, data, _ := call("topology.apply", `{"kind":"group.create","create_group":{"group":{"network_id":"synthetic-network-a","name":"root-a"}}}`); !ok {
		t.Fatalf("owner Group creation failed: %s", data)
	} else {
		var change control.ClientTopologyChangeResult
		if err := json.Unmarshal(data, &change); err != nil || change.Group == nil ||
			change.Group.NetworkID != "synthetic-network-a" {
			t.Fatalf("Group Network projection: %#v err=%v", change, err)
		}
		if ok, _, _ := call("topology.apply", fmt.Sprintf(`{"kind":"group.create","create_group":{"group":{"network_id":"synthetic-network-b","name":"wrong-child"},"parent_group_id":%q}}`, change.Group.GroupID)); ok {
			t.Fatal("cross-Network parent assignment created a Group")
		}
		if ok, data, _ := call("topology.apply", fmt.Sprintf(`{"kind":"group.create","create_group":{"group":{"network_id":"synthetic-network-a","name":"child-a"},"parent_group_id":%q}}`, change.Group.GroupID)); !ok {
			t.Fatalf("same-Network child creation failed: %s", data)
		}
	}
	legacy := httptest.NewRequest(http.MethodPost, "/v1/groups", bytes.NewBufferString(`{"network_id":"synthetic-network-a","name":"bearer-created"}`))
	legacy.Header.Set("Authorization", "Bearer legacy-manager")
	legacyResponse := httptest.NewRecorder()
	handler.ServeHTTP(legacyResponse, legacy)
	if legacyResponse.Code == http.StatusCreated {
		t.Fatal("operator bearer created a Network Group as the human Owner")
	}
	// The accepted Client request is not a standing grant. A different Store
	// instance can revoke its device before dispatch; the Group insert must
	// observe that revocation inside its own transaction.
	accepted, err := database.AcceptClientRequest(store.AcceptClientRequestInput{
		OwnerID: ownerID, DeviceID: binding.DeviceID, SessionEpoch: 1,
		Sequence: sequence + 1, OperationID: "synthetic-revoked-group-create",
		CiphertextDigest: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	otherStore, err := store.New(filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer otherStore.Close()
	currentDevice, err := otherStore.GetClientDevice(ownerID, binding.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherStore.RevokeClientDevice(ownerID, binding.DeviceID, currentDevice.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateGroupForNetworkOwner(store.Group{NetworkID: "synthetic-network-a",
		OwnerPrincipalID: ownerID, TrustDomainID: ownerID, Name: "revoked-device-group"}, accepted.Request.ID); err == nil {
		t.Fatal("revoked Client request created a Network Group")
	}
}
