package server

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestClientLinkKeyOperationsRequireEncryptedBoundDevice(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"),
		WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "manager-bearer"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	handler := NewHandler(manager)
	ownerID := manager.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	persistence, err := store.New(filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	_ = persistence.Close()
	identityResponse := httptest.NewRecorder()
	handler.ServeHTTP(identityResponse, httptest.NewRequest(http.MethodGet, "/v2/client/identity", nil))
	var hub struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if err := json.Unmarshal(identityResponse.Body.Bytes(), &hub); err != nil || hub.HubID == "" {
		t.Fatalf("read Hub identity: %v", err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceGrant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "phone-link", device.Public(), hub.HubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "phone-link", "device_public_identity": device.Public(),
		"owner_device_grant": deviceGrant,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrolled := httptest.NewRecorder()
	handler.ServeHTTP(enrolled, httptest.NewRequest(http.MethodPost, "/v2/client/devices/enroll", bytes.NewReader(enrollment)))
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("device enrollment failed: %d %s", enrolled.Code, enrolled.Body.String())
	}
	capabilities := httptest.NewRecorder()
	handler.ServeHTTP(capabilities, httptest.NewRequest(http.MethodGet, "/v2/client/capabilities", nil))
	if !bytes.Contains(capabilities.Body.Bytes(), []byte(`"link_key_consent":true`)) ||
		!bytes.Contains(capabilities.Body.Bytes(), []byte(`"external_thread_links":false`)) {
		t.Fatalf("Hub capabilities misreported key consent versus routing: %s", capabilities.Body.String())
	}
	plain := httptest.NewRecorder()
	plainRequest := httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader([]byte(`{"operation":"link.key_grant"}`)))
	plainRequest.Header.Set("Authorization", "Bearer manager-bearer")
	handler.ServeHTTP(plain, plainRequest)
	if plain.Code == http.StatusOK {
		t.Fatal("manager bearer submitted plaintext key consent")
	}
	binding := clientwire.Binding{HubID: hub.HubID, OwnerID: ownerID, DeviceID: "phone-link",
		SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
		HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
		SessionEpoch: 1, Sequence: 1, OperationID: "link-key-manifest-1",
		Operation: "link.key_manifest", SenderKeyID: device.Public().ID,
		SenderKeyVersion: 1, ReceiverKeyID: hub.ControlPublicIdentity.ID, ReceiverKeyVersion: 1}
	packet, err := clientwire.SealRequest(device, hub.ControlPublicIdentity, binding, route,
		[]byte(`{"link_id":"missing"}`))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(packet)))
	if response.Code != http.StatusOK {
		t.Fatalf("encrypted operation transport failed: %d %s", response.Code, response.Body.String())
	}
	opened, err := clientwire.OpenResponse(device, hub.ControlPublicIdentity, binding, response.Body.Bytes())
	if err != nil {
		t.Fatalf("decrypt key manifest response: %v", err)
	}
	if !bytes.Contains(opened.Plaintext, []byte(`"ok":false`)) ||
		bytes.Contains(opened.Plaintext, []byte(`"result":`)) {
		t.Fatalf("missing link was not an encrypted business rejection: response=%s", opened.Plaintext)
	}
	route.Sequence = 2
	route.OperationID = "forged-link-consent-2"
	route.Operation = "link.key_grant"
	forged, err := clientwire.SealRequest(device, hub.ControlPublicIdentity, binding, route,
		[]byte(`{"link_id":"missing","side":"SOURCE","owner_key_id":"fake","signed_proof":"AA==","owner_id":"attacker","user_approved":true}`))
	if err != nil {
		t.Fatal(err)
	}
	forgedResponse := httptest.NewRecorder()
	handler.ServeHTTP(forgedResponse, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(forged)))
	if forgedResponse.Code != http.StatusOK {
		t.Fatalf("forged request was not rejected inside authenticated RPC: %d", forgedResponse.Code)
	}
	forgedOpened, err := clientwire.OpenResponse(device, hub.ControlPublicIdentity, binding, forgedResponse.Body.Bytes())
	if err != nil || !bytes.Contains(forgedOpened.Plaintext, []byte(`"ok":false`)) {
		t.Fatalf("model-supplied owner/approval fields were accepted: response=%#v err=%v", forgedOpened, err)
	}
}
