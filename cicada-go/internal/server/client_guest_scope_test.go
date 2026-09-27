package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientcontract"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestExternalClientDeviceCanOnlyUseFederatedOperations(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"),
		WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "legacy-manager"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	if _, err := manager.CreateGroup(control.GroupCreateInput{Name: "manager-private-group"}); err != nil {
		t.Fatal(err)
	}
	ownerID := "guest-owner"
	database, err := store.New(filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateGoal("manager-legacy-goal", "resident-private-goal", "done", "", 1,
		"control-local", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreatePrincipal(store.Principal{ID: ownerID, Kind: store.PrincipalKindHuman,
		OwnerID: ownerID, TrustDomainID: ownerID, Name: "guest", Status: store.PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(manager)
	identity := httptest.NewRecorder()
	handler.ServeHTTP(identity, httptest.NewRequest(http.MethodGet, "/v2/client/identity", nil))
	var hub struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if err := json.Unmarshal(identity.Body.Bytes(), &hub); err != nil || hub.HubID == "" {
		t.Fatalf("Hub identity: %v", err)
	}
	deviceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "guest-phone", deviceKey.Public(), hub.HubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollBody, err := json.Marshal(map[string]any{"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "guest-phone", "device_public_identity": deviceKey.Public(), "owner_device_grant": grant})
	if err != nil {
		t.Fatal(err)
	}
	enroll := httptest.NewRecorder()
	handler.ServeHTTP(enroll, httptest.NewRequest(http.MethodPost, "/v2/client/devices/enroll", bytes.NewReader(enrollBody)))
	if enroll.Code != http.StatusCreated {
		t.Fatalf("independent owner grant enrollment failed: %d %s", enroll.Code, enroll.Body.String())
	}
	binding := clientwire.Binding{HubID: hub.HubID, OwnerID: ownerID, DeviceID: "guest-phone",
		SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	call := func(sequence uint64, operation, body string) (bool, []byte) {
		t.Helper()
		route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
			HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
			SessionEpoch: 1, Sequence: sequence, OperationID: fmt.Sprintf("guest-%d", sequence),
			Operation: operation, SenderKeyID: deviceKey.Public().ID, SenderKeyVersion: 1,
			ReceiverKeyID: hub.ControlPublicIdentity.ID, ReceiverKeyVersion: 1}
		packet, err := clientwire.SealRequest(deviceKey, hub.ControlPublicIdentity, binding, route, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(packet))
		request.Header.Set("Authorization", "Bearer legacy-manager")
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("encrypted RPC %s status=%d body=%s", operation, response.Code, response.Body.String())
		}
		opened, err := clientwire.OpenResponse(deviceKey, hub.ControlPublicIdentity, binding, response.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		var outcome struct {
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(opened.Plaintext, &outcome); err != nil {
			t.Fatal(err)
		}
		return outcome.OK, outcome.Result
	}
	if ok, result := call(1, "devices.list", `{}`); !ok || !bytes.Contains(result, []byte(`guest-phone`)) {
		t.Fatalf("guest cannot inspect own devices: ok=%t result=%s", ok, result)
	}
	guestCapabilitiesOK, guestCapabilitiesResult := call(2, "session.capabilities", `{}`)
	if !guestCapabilitiesOK || !bytes.Contains(guestCapabilitiesResult, []byte(`"role":"external"`)) ||
		!bytes.Contains(guestCapabilitiesResult, []byte(`nodes.confirm`)) ||
		!bytes.Contains(guestCapabilitiesResult, []byte(`status.snapshot`)) ||
		bytes.Contains(guestCapabilitiesResult, []byte(`intent.submit`)) {
		t.Fatalf("guest capabilities leaked manager operations: ok=%t result=%s", guestCapabilitiesOK, guestCapabilitiesResult)
	}
	var sessionCapabilities struct {
		Role                string   `json:"role"`
		ContractRevision    string   `json:"contract_revision"`
		CatalogSHA256       string   `json:"catalog_sha256"`
		AvailableOperations []string `json:"available_rpc_operations"`
	}
	if err := json.Unmarshal(guestCapabilitiesResult, &sessionCapabilities); err != nil {
		t.Fatalf("decode session capabilities: %v", err)
	}
	if sessionCapabilities.Role != "external" ||
		sessionCapabilities.ContractRevision != clientcontract.ContractRevision ||
		sessionCapabilities.CatalogSHA256 != clientcontract.CatalogSHA256() ||
		!reflect.DeepEqual(sessionCapabilities.AvailableOperations,
			clientcontract.OperationsForRole(clientcontract.RoleExternal)) {
		t.Fatalf("session capabilities lack current catalog provenance: %#v", sessionCapabilities)
	}
	if ok, result := call(3, "nodes.list", `{}`); !ok || string(result) != `[]` {
		t.Fatalf("guest cannot inspect own Node bindings: ok=%t result=%s", ok, result)
	}
	_, digest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := manager.StartNodeDeviceBinding("guest-node", "Guest Node", digest)
	if err != nil {
		t.Fatal(err)
	}
	codeBody, err := json.Marshal(map[string]string{"user_code": challenge.UserCode})
	if err != nil {
		t.Fatal(err)
	}
	if ok, result := call(4, "nodes.preview", string(codeBody)); !ok ||
		!bytes.Contains(result, []byte(`guest-node`)) {
		t.Fatalf("guest Node preview failed: ok=%t result=%s", ok, result)
	}
	if ok, result := call(5, "nodes.confirm", string(codeBody)); !ok ||
		!bytes.Contains(result, []byte(`guest-node`)) {
		t.Fatalf("guest Node confirmation failed: ok=%t result=%s", ok, result)
	}
	if ok, result := call(6, "nodes.list", `{}`); !ok ||
		!bytes.Contains(result, []byte(`guest-node`)) || bytes.Contains(result, []byte(`control-local`)) {
		t.Fatalf("guest Node list is not owner-scoped: ok=%t result=%s", ok, result)
	}
	managerNodes, err := manager.NodeDeviceBindings(manager.Identity().ID)
	if err != nil || len(managerNodes) != 0 {
		t.Fatalf("guest Node leaked to manager owner: nodes=%#v err=%v", managerNodes, err)
	}
	if ok, result := call(7, "topology.apply", `{"kind":"group.create","create_group":{"group":{"name":"guest-private-group"}}}`); !ok ||
		!bytes.Contains(result, []byte(`guest-private-group`)) {
		t.Fatalf("guest cannot create own Group: ok=%t result=%s", ok, result)
	}
	if ok, result := call(8, "topology.snapshot", `{}`); !ok ||
		!bytes.Contains(result, []byte(`guest-private-group`)) || bytes.Contains(result, []byte(`manager-private-group`)) {
		t.Fatalf("guest topology leaks another owner or omits own Group: ok=%t result=%s", ok, result)
	}
	if ok, result := call(9, "status.snapshot", `{}`); !ok ||
		!bytes.Contains(result, []byte(`"scope_mode":"owner_attributed_v2"`)) ||
		!bytes.Contains(result, []byte(`guest-private-group`)) ||
		bytes.Contains(result, []byte(`manager-private-group`)) ||
		bytes.Contains(result, []byte(`manager-legacy-goal`)) ||
		bytes.Contains(result, []byte(`control-local`)) {
		t.Fatalf("guest status leaked resident data or omitted own Group: ok=%t result=%s", ok, result)
	}
	if ok, result := call(10, "status.changes", `{}`); !ok ||
		!bytes.Contains(result, []byte(`"scope_mode":"owner_attributed_v2"`)) ||
		bytes.Contains(result, []byte(`manager-private-group`)) {
		t.Fatalf("guest status cursor leaked resident data: ok=%t result=%s", ok, result)
	}
	if ok, _ := call(11, "topology.apply", `{"kind":"group.create","create_group":{"group":{"name":"spoofed"}},"owner_id":"manager"}`); ok {
		t.Fatal("guest topology accepted caller-supplied owner_id")
	}
	for index, operation := range []string{"intent.submit", "approvals.list", "goal.lifecycle"} {
		if ok, result := call(uint64(index+12), operation, `{}`); ok || len(result) != 0 {
			t.Fatalf("guest reached Control management operation %s: ok=%t result=%s", operation, ok, result)
		}
	}
	if err := manager.ValidateClientOwnerScope(ownerID); err == nil {
		t.Fatal("external session became this Control's manager")
	}
}
