package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
)

// Legacy routes accepted a caller-supplied endpoint ID under a management
// bearer. They must not remain a shortcut around v2 session authentication.
func TestLegacyFabricPeerRoutesAreRemoved(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	handler := NewHandler(manager)
	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/fabric/list"},
		{http.MethodGet, "/v1/fabric/resolve?q=someone"},
		{http.MethodPost, "/v1/fabric/send"},
		{http.MethodPost, "/v1/fabric/ask"},
		{http.MethodPost, "/v1/fabric/reply"},
		{http.MethodPost, "/v1/endpoints"},
		{http.MethodGet, "/v1/endpoints"},
		{http.MethodGet, "/v1/endpoints/ep_fake"},
		{http.MethodDelete, "/v1/endpoints/ep_fake"},
		{http.MethodPost, "/v1/endpoints/ep_fake/heartbeat"},
		{http.MethodPost, "/v1/endpoints/ep_fake/leave"},
		{http.MethodPost, "/v1/endpoints/ep_fake/messages"},
		{http.MethodPost, "/v1/threads/sessions"},
		{http.MethodPost, "/v1/threads/queue"},
		{http.MethodGet, "/v1/threads/deliveries"},
		{http.MethodPost, "/v1/threads/messages"},
		{http.MethodPost, "/v1/peer-messages"},
		{http.MethodPost, "/v1/peer-messages/legacy/deliver"},
		{http.MethodPost, "/v1/federation/messages"},
		{http.MethodGet, "/v1/contacts/contact-fake/session"},
		{http.MethodPost, "/v1/contacts/contact-fake/session/rotate"},
		{http.MethodPost, "/v1/machines/node-a/relay-credential"},
		{http.MethodGet, "/v1/machines/node-a/fabric-deliveries"},
		{http.MethodPost, "/v1/machines/node-a/fabric-deliveries/message-a"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("legacy peer route %s %s remains available: status=%d body=%s",
				test.method, test.path, response.Code, response.Body.String())
		}
	}
}

func TestManagementEndpointReadProjectionReplacesLegacyPath(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "manager-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	group, err := manager.CreateGroup(control.GroupCreateInput{Name: "operator panel"})
	if err != nil {
		t.Fatal(err)
	}
	joined, err := manager.Fabric().Join(fabricpkg.JoinInput{GroupID: group.ID,
		EndpointName: "benchmark", Harness: "codex", NativeSessionID: "native-panel-b",
		NodeID: "node-panel-b"})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(manager)
	request := httptest.NewRequest(http.MethodGet, "/v2/management/endpoints", nil)
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, request)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("management projection exposed without bearer: %d", unauthorized.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v2/management/endpoints", nil)
	request.Header.Set("Authorization", "Bearer manager-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("management projection unavailable: %d %s", response.Code, response.Body.String())
	}
	var listed struct {
		Endpoints []struct {
			EndpointID string `json:"endpoint_id"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil ||
		len(listed.Endpoints) != 1 || listed.Endpoints[0].EndpointID != joined.Endpoint.ID {
		t.Fatalf("joined v2 Endpoint missing from operator panel: %#v err=%v", listed, err)
	}
	for _, check := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/v2/management/endpoints/missing", http.StatusNotFound},
		{http.MethodPost, "/v2/management/endpoints", http.StatusMethodNotAllowed},
	} {
		request := httptest.NewRequest(check.method, check.path, nil)
		request.Header.Set("Authorization", "Bearer manager-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != check.want {
			t.Fatalf("management Endpoint %s %s: got %d want %d", check.method, check.path,
				response.Code, check.want)
		}
	}
}
