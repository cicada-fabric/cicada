package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
)

func TestAndroidClientCapabilitiesFailClosedWithoutPQControlEnvelope(t *testing.T) {
	handler := NewFabricHandler(nil, "management-secret")
	request := httptest.NewRequest(http.MethodGet, "/v2/client/capabilities", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("capabilities status=%d body=%s", response.Code, response.Body.String())
	}
	var capabilities map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities["status"] != "not_ready" || capabilities["planned_platform"] != "android" {
		t.Fatalf("unexpected Android contract: %#v", capabilities)
	}
	for _, field := range []string{
		"client_control_pq_e2ee", "authenticated_client_session", "status_snapshot",
		"status_events", "status_changes_partial", "control_intents", "device_binding", "external_thread_links", "client_device_management", "topology_management",
	} {
		if capabilities[field] != false {
			t.Fatalf("%s advertised before secure implementation: %#v", field, capabilities[field])
		}
	}
	if _, ok := capabilities["token"]; ok {
		t.Fatal("capability response exposed credential")
	}
	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/v2/client/capabilities", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("capability write accepted: status=%d", post.Code)
	}
}

func TestAndroidClientCapabilitiesAdvertiseOnlyImplementedHubOperations(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	result := httptest.NewRecorder()
	NewHandler(manager).ServeHTTP(result, httptest.NewRequest(http.MethodGet, "/v2/client/capabilities", nil))
	if result.Code != http.StatusOK {
		t.Fatalf("capabilities status=%d", result.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(result.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "partial" || body["client_control_pq_e2ee"] != true ||
		body["authenticated_client_session"] != true || body["status_snapshot"] != true ||
		body["client_device_enrollment"] != true || body["client_device_management"] != true ||
		body["topology_management"] != true || body["control_intents"] != true ||
		body["device_binding"] != true || body["status_changes_partial"] != true ||
		body["approval_read_and_decide"] != true {
		t.Fatalf("implemented Client operations not advertised precisely: %#v", body)
	}
	for _, unavailable := range []string{"status_events", "external_thread_links"} {
		if body[unavailable] != false {
			t.Fatalf("unfinished capability %s was advertised", unavailable)
		}
	}
	operations, ok := body["available_rpc_operations"].([]any)
	if !ok {
		t.Fatalf("available operations have invalid shape: %#v", body["available_rpc_operations"])
	}
	for _, required := range []string{"status.changes", "nodes.preview", "nodes.confirm", "nodes.list", "nodes.revoke"} {
		found := false
		for _, operation := range operations {
			if operation == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("implemented operation %s not advertised", required)
		}
	}
}
