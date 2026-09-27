package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestClientDockerHubSmoke exercises an independently running Hub over a real
// Docker-published TCP port. It is opt-in because the owner-key bootstrap must
// access the isolated test Hub's local SQLite file. This is a protocol smoke
// test, not an Android implementation or a substitute for phone testing.
func TestClientDockerHubSmoke(t *testing.T) {
	baseURL := os.Getenv("CICADA_TEST_HUB_URL")
	dbPath := os.Getenv("CICADA_TEST_HUB_DB")
	legacyToken := os.Getenv("CICADA_TEST_HUB_TOKEN")
	if baseURL == "" || dbPath == "" || legacyToken == "" {
		t.Skip("set CICADA_TEST_HUB_URL, CICADA_TEST_HUB_DB and CICADA_TEST_HUB_TOKEN for isolated Docker Hub")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	call := func(method, path string, body []byte, bearer string, expectedStatus int) []byte {
		t.Helper()
		request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 300*1024))
		if err != nil || response.StatusCode != expectedStatus {
			t.Fatalf("%s %s: status=%d body=%s err=%v", method, path, response.StatusCode, data, err)
		}
		return data
	}
	var owner e2ee.PublicIdentity
	if err := json.Unmarshal(call(http.MethodGet, "/v1/identity", nil, legacyToken, http.StatusOK), &owner); err != nil {
		t.Fatal(err)
	}
	call(http.MethodPost, "/v1/groups", []byte(`{"name":"docker-client-smoke"}`), legacyToken, http.StatusCreated)
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	persistence, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterOwnerApprovalKeyLocal(owner.ID, ownerKey.Public()); err != nil {
		_ = persistence.Close()
		t.Fatal(err)
	}
	_ = persistence.Close()
	var hub struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if err := json.Unmarshal(call(http.MethodGet, "/v2/client/identity", nil, "", http.StatusOK), &hub); err != nil || hub.HubID == "" {
		t.Fatalf("invalid Hub identity: %v %#v", err, hub)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKey.SignOwnerDeviceGrant(owner.ID, "docker-phone", device.Public(), hub.HubID,
		e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := json.Marshal(map[string]any{
		"owner_id": owner.ID, "owner_key_id": ownerKey.Public().ID, "device_id": "docker-phone",
		"device_public_identity": device.Public(), "owner_device_grant": grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	call(http.MethodPost, "/v2/client/devices/enroll", enrollment, "", http.StatusCreated)
	binding := clientwire.Binding{HubID: hub.HubID, OwnerID: owner.ID, DeviceID: "docker-phone",
		SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
		HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
		SessionEpoch: 1, Sequence: 1, OperationID: "docker-snapshot-1", Operation: "status.snapshot",
		SenderKeyID: device.Public().ID, SenderKeyVersion: 1,
		ReceiverKeyID: hub.ControlPublicIdentity.ID, ReceiverKeyVersion: 1}
	packet, err := clientwire.SealRequest(device, hub.ControlPublicIdentity, binding, route, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	sealed := call(http.MethodPost, "/v2/client/rpc", packet, "", http.StatusOK)
	opened, err := clientwire.OpenResponse(device, hub.ControlPublicIdentity, binding, sealed)
	if err != nil {
		t.Fatalf("decrypt real Docker Hub response: %v", err)
	}
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			OwnerID string `json:"owner_principal_id"`
			Groups  []any  `json:"groups"`
		} `json:"result"`
	}
	if err := json.Unmarshal(opened.Plaintext, &result); err != nil || !result.OK ||
		result.Result.OwnerID != owner.ID || len(result.Result.Groups) == 0 {
		t.Fatalf("unexpected Docker Hub snapshot: err=%v result=%#v", err, result)
	}
	retry := call(http.MethodPost, "/v2/client/rpc", packet, "", http.StatusOK)
	if !bytes.Equal(retry, sealed) {
		t.Fatal("Docker Hub exact retry did not return cached sealed packet")
	}
	nodeToken, nodeDigest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	nodeStart, err := json.Marshal(map[string]string{
		"node_id": "docker-client-node", "node_name": "Docker Client Node", "credential_digest": nodeDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	var deviceCode struct {
		UserCode string `json:"user_code"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/v2/nodes/device-code", nodeStart, "", http.StatusCreated), &deviceCode); err != nil || deviceCode.UserCode == "" {
		t.Fatalf("Docker Node device-code start failed: %v", err)
	}
	callEncrypted := func(sequence uint64, operation string, requestBody []byte) []byte {
		t.Helper()
		operationRoute := route
		operationRoute.Sequence = sequence
		operationRoute.OperationID = operation + "-docker"
		operationRoute.Operation = operation
		operationPacket, err := clientwire.SealRequest(device, hub.ControlPublicIdentity, binding, operationRoute, requestBody)
		if err != nil {
			t.Fatal(err)
		}
		responsePacket := call(http.MethodPost, "/v2/client/rpc", operationPacket, "", http.StatusOK)
		opened, err := clientwire.OpenResponse(device, hub.ControlPublicIdentity, binding, responsePacket)
		if err != nil {
			t.Fatal(err)
		}
		return opened.Plaintext
	}
	codeBody, err := json.Marshal(map[string]string{"user_code": deviceCode.UserCode})
	if err != nil {
		t.Fatal(err)
	}
	preview := callEncrypted(2, "nodes.preview", codeBody)
	if !bytes.Contains(preview, []byte(`"node_id":"docker-client-node"`)) || bytes.Contains(preview, []byte(nodeDigest)) {
		t.Fatalf("Docker Node preview invalid: %s", preview)
	}
	confirmation := callEncrypted(3, "nodes.confirm", codeBody)
	if !bytes.Contains(confirmation, []byte(`"state":"ACTIVE"`)) || bytes.Contains(confirmation, []byte(nodeToken)) {
		t.Fatalf("Docker Node confirmation invalid: %s", confirmation)
	}
	heartbeat, err := http.NewRequest(http.MethodPost, baseURL+"/v2/relay/nodes/docker-client-node/heartbeat", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	heartbeat.Header.Set("Authorization", "CicadaNode "+nodeToken)
	heartbeat.Header.Set("Content-Type", "application/json")
	heartbeatResponse, err := client.Do(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	_ = heartbeatResponse.Body.Close()
	if heartbeatResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("Docker bound Node heartbeat status=%d", heartbeatResponse.StatusCode)
	}
	changes := callEncrypted(4, "status.changes", []byte(`{}`))
	if !bytes.Contains(changes, []byte(`"completeness":"partial"`)) ||
		!bytes.Contains(changes, []byte(`"docker-client-node"`)) {
		t.Fatalf("Docker status changes missing Node: %s", changes)
	}
}
