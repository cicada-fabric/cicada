package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/clientcontract"
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
	if capabilities["contract_revision"] != clientcontract.ContractRevision ||
		capabilities["catalog_sha256"] != clientcontract.CatalogSHA256() {
		t.Fatalf("not-ready response omitted contract provenance: %#v", capabilities)
	}
	for _, field := range []string{
		"client_control_pq_e2ee", "authenticated_client_session", "status_snapshot",
		"status_events", "status_changes_partial", "control_intents", "device_binding", "external_thread_links", "external_link_invites", "external_client_sessions", "client_device_management", "topology_management", "queued_goal_lifecycle", "rpc_recovery",
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
		body["external_link_invites"] != true || body["external_client_sessions"] != true ||
		body["approval_read_and_decide"] != true || body["queued_goal_lifecycle"] != true ||
		body["group_endpoint_key_grants"] != true || body["rpc_recovery"] != true {
		t.Fatalf("implemented Client operations not advertised precisely: %#v", body)
	}
	if body["contract_revision"] != clientcontract.ContractRevision ||
		body["catalog_sha256"] != clientcontract.CatalogSHA256() {
		t.Fatalf("public capabilities do not identify their operation catalog: %#v", body)
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
	if err := compareCapabilityOperations(operations, clientcontract.OperationsForRole(clientcontract.RoleManager)); err != nil {
		t.Fatalf("manager capabilities drifted from catalog: %v", err)
	}
	for _, required := range []string{"session.capabilities", "status.changes", "goal.lifecycle", "nodes.preview", "nodes.confirm", "nodes.list", "nodes.revoke", "link.list", "link.invite_create", "link.invite_preview", "link.invite_accept", "group.key_manifest", "group.key_grant", "group.key_status"} {
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
	externalOperations, ok := body["external_rpc_operations"].([]any)
	if !ok {
		t.Fatalf("external operation list has invalid shape: %#v", body["external_rpc_operations"])
	}
	if err := compareCapabilityOperations(externalOperations, clientcontract.OperationsForRole(clientcontract.RoleExternal)); err != nil {
		t.Fatalf("external capabilities drifted from catalog: %v", err)
	}
	for _, required := range []string{"status.snapshot", "status.changes", "topology.snapshot", "topology.apply", "link.list", "group.key_manifest", "group.key_grant", "group.key_status"} {
		found := false
		for _, operation := range externalOperations {
			if operation == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("owner-scoped external operation %s not advertised", required)
		}
	}
	for _, forbidden := range []string{"approvals.decide", "intent.submit", "goal.lifecycle"} {
		for _, operation := range externalOperations {
			if operation == forbidden {
				t.Fatalf("manager operation %s advertised to external owner", forbidden)
			}
		}
	}
}

func compareCapabilityOperations(actual []any, expected []string) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("got %d operations, want %d", len(actual), len(expected))
	}
	for index, operation := range expected {
		if actual[index] != operation {
			return fmt.Errorf("operation[%d]=%v, want %s", index, actual[index], operation)
		}
	}
	return nil
}
