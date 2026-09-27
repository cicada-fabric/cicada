package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestCicadaMCPAdvertisesExplicitFabricTools(t *testing.T) {
	required := map[string]bool{
		"cicada_join":                     false,
		"cicada_use_group":                false,
		"cicada_leave_group":              false,
		"cicada_leave":                    false,
		"cicada_whoami":                   false,
		"cicada_members":                  false,
		"cicada_find":                     false,
		"cicada_send":                     false,
		"cicada_ask":                      false,
		"cicada_reply":                    false,
		"cicada_receive":                  false,
		"cicada_request_status":           false,
		"cicada_request_cancel":           false,
		"cicada_representative_claim":     false,
		"cicada_federate_request":         false,
		"cicada_federation_accept":        false,
		"cicada_federation_result":        false,
		"cicada_federation_accept_result": false,
		"cicada_federation_status":        false,
		"cicada_task_list":                false,
		"cicada_task_claim":               false,
		"cicada_task_submit":              false,
		"cicada_task_accept":              false,
		"cicada_task_handoff_propose":     false,
		"cicada_task_handoff_accept":      false,
		"cicada_artifact_read":            false,
	}
	for _, tool := range cicadaMCPTools() {
		name, _ := tool["name"].(string)
		if _, ok := required[name]; ok {
			required[name] = true
		}
	}
	for name, found := range required {
		if !found {
			t.Fatalf("MCP tool %q is missing", name)
		}
	}
}

func TestCicadaMCPToolsRequireExplicitJoin(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		http.Error(response, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()

	mcp := &mcpServer{baseURL: server.URL, stop: make(chan struct{})}
	defer close(mcp.stop)
	for _, name := range []string{
		"cicada_whoami", "cicada_members", "cicada_find", "cicada_list", "cicada_resolve", "cicada_inspect",
		"cicada_send", "cicada_ask", "cicada_reply", "cicada_receive", "cicada_request_status", "cicada_request_cancel",
		"cicada_representative_claim", "cicada_federate_request", "cicada_federation_accept",
		"cicada_federation_result", "cicada_federation_accept_result", "cicada_federation_status",
		"cicada_task_list", "cicada_task_claim", "cicada_task_submit", "cicada_task_accept",
		"cicada_task_handoff_propose", "cicada_task_handoff_accept", "cicada_artifact_read",
	} {
		if _, err := mcp.callTool(name, map[string]any{}); err == nil || !strings.Contains(err.Error(), "cicada_join") {
			t.Fatalf("tool %s did not require explicit join: %v", name, err)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("unjoined tool made %d control requests", requests.Load())
	}
	if err := mcp.ensureEndpoint(); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("automatic ensureEndpoint was not disabled: %v", err)
	}
}

func TestCicadaMCPExplicitJoinBindsCurrentSessionAndUsesSessionAuthorization(t *testing.T) {
	t.Setenv("CICADA_HARNESS", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CODEX_THREAD_ID", "thread-current")
	t.Setenv("CICADA_MACHINE_ID", "gpu1")
	t.Setenv("CICADA_WORKSPACE", "/work/project")
	t.Setenv("CICADA_GROUP_ID", "group-a")
	t.Setenv("CICADA_API_TOKEN", "admin-token")
	t.Setenv("CICADA_API_TOKEN_FILE", "")

	var joinCalls atomic.Int32
	var sessionCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v2/fabric/join":
			joinCalls.Add(1)
			if got := request.Header.Get("Authorization"); got != "Bearer admin-token" {
				t.Errorf("join authorization = %q, want management bearer", got)
			}
			var raw map[string]any
			if err := json.NewDecoder(request.Body).Decode(&raw); err != nil {
				t.Errorf("decode join: %v", err)
				return
			}
			if (raw["group_id"] != "group-a" && raw["group_id"] != "group-b") || raw["harness"] != "codex" || raw["native_session_id"] != "thread-current" || raw["node_id"] != "gpu1" || raw["workspace"] != "/work/project" {
				t.Errorf("unexpected join body: %#v", raw)
			}
			if raw["group_id"] == "group-b" && raw["endpoint_id"] != "ep_current" {
				t.Errorf("second Group join replaced Endpoint identity: %#v", raw)
			}
			for _, forbidden := range []string{"sender", "sender_endpoint_id", "principal_id", "role", "approval", "approved"} {
				if _, ok := raw[forbidden]; ok {
					t.Errorf("join body accepted model identity field %q: %#v", forbidden, raw)
				}
			}
			token := "cicada_session_test-token"
			if raw["group_id"] == "group-b" {
				token = "cicada_session_test-token-b"
			}
			_ = json.NewEncoder(response).Encode(fabricpkg.JoinResult{
				Endpoint:     store.Endpoint{ID: "ep_current", Name: "project", Harness: "codex", NativeSessionID: "thread-current"},
				SessionToken: token, BindingID: "binding-1", BindingEpoch: 1,
			})
		case "/v2/fabric/whoami":
			sessionCalls.Add(1)
			if got := request.Header.Get("Authorization"); got != "CicadaSession cicada_session_test-token" && got != "CicadaSession cicada_session_test-token-b" {
				t.Errorf("whoami authorization = %q, want session credential", got)
			}
			if strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
				t.Errorf("whoami used management bearer")
			}
			groupID := request.Header.Get("Cicada-Group-Scope")
			if groupID != "group-a" && groupID != "group-b" {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(response).Encode(fabricpkg.NetworkCard{EndpointID: "ep_current", GroupID: groupID, BindingID: "binding-1", Address: "project@gpu1:/work/project"})
		case "/v2/fabric/leave-group":
			groupID := request.Header.Get("Cicada-Group-Scope")
			remaining := "group-b"
			if groupID == "group-b" {
				remaining = ""
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"status": "left_group", "left_group_id": groupID, "remaining_group_id": remaining})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	mcp := &mcpServer{baseURL: server.URL, stop: make(chan struct{})}
	defer close(mcp.stop)
	if _, err := mcp.callTool("cicada_whoami", nil); err == nil {
		t.Fatal("whoami succeeded before explicit join")
	}
	result, err := mcp.callTool("cicada_join", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || mcp.endpointID != "ep_current" || mcp.sessionToken != "cicada_session_test-token" || joinCalls.Load() != 1 {
		t.Fatalf("unexpected join state: endpoint=%q joins=%d result=%#v", mcp.endpointID, joinCalls.Load(), result)
	}
	joinedJSON, _ := json.Marshal(result)
	if strings.Contains(string(joinedJSON), "cicada_session_test-token") || strings.Contains(string(joinedJSON), fabricpkg.HashSessionCredential("cicada_session_test-token")) {
		t.Fatalf("join tool result exposed a session credential: %s", joinedJSON)
	}
	if _, err := mcp.callTool("cicada_whoami", nil); err != nil {
		t.Fatal(err)
	}
	if sessionCalls.Load() != 1 {
		t.Fatalf("whoami requests=%d, want 1", sessionCalls.Load())
	}
	if _, err := mcp.callTool("cicada_join", map[string]any{"group_id": "group-a"}); err != nil {
		t.Fatalf("idempotent join failed: %v", err)
	}
	if joinCalls.Load() != 1 {
		t.Fatalf("idempotent join rotated the credential: joins=%d", joinCalls.Load())
	}
	if _, err := mcp.callTool("cicada_join", map[string]any{"group_id": "group-b"}); err != nil {
		t.Fatalf("explicit second Group join failed: %v", err)
	}
	if joinCalls.Load() != 2 || mcp.endpointID != "ep_current" || mcp.sessionGroupID != "group-b" {
		t.Fatalf("second Group join did not preserve Endpoint/scope: joins=%d endpoint=%q group=%q", joinCalls.Load(), mcp.endpointID, mcp.sessionGroupID)
	}
	if _, err := mcp.callTool("cicada_use_group", map[string]any{"group_id": "group-a"}); err != nil || mcp.sessionGroupID != "group-a" {
		t.Fatalf("selecting previously joined Group failed: %v group=%q", err, mcp.sessionGroupID)
	}
	if _, err := mcp.callTool("cicada_use_group", map[string]any{"group_id": "group-hidden"}); err == nil || mcp.sessionGroupID != "group-a" || !mcp.isJoined() {
		t.Fatalf("unauthorized Group selection changed active session: %v group=%q", err, mcp.sessionGroupID)
	}
	if _, err := mcp.callTool("cicada_leave_group", nil); err != nil || mcp.sessionGroupID != "group-b" || !mcp.isJoined() {
		t.Fatalf("leaving Group A did not activate remaining Group B: %v group=%q", err, mcp.sessionGroupID)
	}
	if _, err := mcp.callTool("cicada_leave_group", nil); err != nil || mcp.isJoined() {
		t.Fatalf("leaving last Group retained joined MCP state: %v", err)
	}
}

func TestCicadaMCPRejectsForgedIdentityAndCredentialArguments(t *testing.T) {
	mcp := &mcpServer{stop: make(chan struct{})}
	defer close(mcp.stop)
	for _, test := range []struct {
		name string
		args map[string]any
	}{
		{name: "cicada_join", args: map[string]any{"group_id": "group-a", "principal_id": "forged"}},
		{name: "cicada_join", args: map[string]any{"group_id": "group-a", "role": "admin"}},
		{name: "cicada_join", args: map[string]any{"group_id": "group-a", "session_token": "cicada_session_forged"}},
		{name: "cicada_whoami", args: map[string]any{"group_id": "group-a"}},
		{name: "cicada_whoami", args: map[string]any{"sender_endpoint_id": "forged"}},
	} {
		if _, err := mcp.callTool(test.name, test.args); err == nil {
			t.Fatalf("forged identity argument was accepted by %s", test.name)
		}
	}
}

func TestCicadaMCPJoinUsesGroupEnvironment(t *testing.T) {
	t.Setenv("CICADA_GROUP_ID", "group-from-env")
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	t.Setenv("CICADA_HARNESS", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CODEX_THREAD_ID", "thread-env")

	var joined atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/fabric/join" {
			http.NotFound(response, request)
			return
		}
		joined.Add(1)
		var input fabricpkg.JoinInput
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Errorf("decode join: %v", err)
		}
		if input.GroupID != "group-from-env" || input.NativeSessionID != "thread-env" {
			t.Errorf("unexpected environment join: %#v", input)
		}
		_ = json.NewEncoder(response).Encode(fabricpkg.JoinResult{Endpoint: store.Endpoint{ID: "ep-env"}, SessionToken: "cicada_session_env-token"})
	}))
	defer server.Close()

	mcp := &mcpServer{baseURL: server.URL, stop: make(chan struct{})}
	defer close(mcp.stop)
	if _, err := mcp.callTool("cicada_join", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if joined.Load() != 1 {
		t.Fatalf("join requests=%d, want 1", joined.Load())
	}
}

func TestCicadaMCPRestartRestoresSessionAfterServerValidation(t *testing.T) {
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "thread-restart")
	t.Setenv("CODEX_THREAD_ID", "")
	t.Setenv("CODEX_SESSION_ID", "")
	t.Setenv("CICADA_MACHINE_ID", "node-restart")
	t.Setenv("CICADA_WORKSPACE", "/work/restart")
	t.Setenv("CICADA_API_TOKEN", "management-token")
	t.Setenv("CICADA_API_TOKEN_FILE", "")

	var joinCalls, whoamiCalls, heartbeatCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v2/fabric/join":
			joinCalls.Add(1)
			_ = json.NewEncoder(response).Encode(fabricpkg.JoinResult{
				Endpoint:     store.Endpoint{ID: "ep-restart", GroupID: "group-restart", Name: "restart", Harness: "codex", NativeSessionID: "thread-restart", MachineID: "node-restart", Workspace: "/work/restart"},
				NetworkCard:  fabricpkg.NetworkCard{EndpointID: "ep-restart", GroupID: "group-restart", Name: "restart", Harness: "codex", NodeID: "node-restart", Workspace: "/work/restart", Status: "online", BindingID: "binding-restart", BindingEpoch: 1},
				SessionToken: "cicada_session_restart-token", BindingID: "binding-restart", BindingEpoch: 1,
			})
		case "/v2/fabric/whoami":
			whoamiCalls.Add(1)
			if request.Header.Get("Authorization") != "CicadaSession cicada_session_restart-token" {
				t.Errorf("restore whoami used unexpected authorization")
			}
			_ = json.NewEncoder(response).Encode(fabricpkg.NetworkCard{EndpointID: "ep-restart", GroupID: "group-restart", Name: "restart", Harness: "codex", NodeID: "node-restart", Workspace: "/work/restart", Status: "online", BindingID: "binding-restart", BindingEpoch: 1})
		case "/v2/fabric/heartbeat":
			heartbeatCalls.Add(1)
			_ = json.NewEncoder(response).Encode(fabricpkg.Actor{EndpointID: "ep-restart", GroupID: "group-restart", BindingID: "binding-restart", BindingEpoch: 1})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	context, err := harness.DetectCurrentSession()
	if err != nil {
		t.Fatal(err)
	}
	first := newMCPServer(server.URL, "", statePath)
	if _, err := first.callTool("cicada_join", map[string]any{"group_id": "group-restart"}); err != nil {
		t.Fatal(err)
	}
	close(first.stop)
	second := newMCPServer(server.URL, "", statePath)
	if err := second.restoreSession(context); err != nil {
		t.Fatal(err)
	}
	defer close(second.stop)
	if !second.isJoined() || second.endpointID != "ep-restart" {
		t.Fatalf("restart did not restore the authenticated session: joined=%t endpoint=%q", second.isJoined(), second.endpointID)
	}
	if joinCalls.Load() != 1 || whoamiCalls.Load() != 1 || heartbeatCalls.Load() != 1 {
		t.Fatalf("restore requests join=%d whoami=%d heartbeat=%d", joinCalls.Load(), whoamiCalls.Load(), heartbeatCalls.Load())
	}
}

func TestCicadaMCPRestoreDoesNotUseStaleCredentialOrManagementFallback(t *testing.T) {
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "thread-stale")
	t.Setenv("CODEX_THREAD_ID", "")
	t.Setenv("CODEX_SESSION_ID", "")
	t.Setenv("CICADA_MACHINE_ID", "node-stale")
	t.Setenv("CICADA_WORKSPACE", "/work/stale")
	t.Setenv("CICADA_API_TOKEN", "management-token")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	var joinCalls, whoamiCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/join":
			joinCalls.Add(1)
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(fabricpkg.JoinResult{Endpoint: store.Endpoint{ID: "ep-stale", GroupID: "group-stale"}, SessionToken: "cicada_session_stale-token"})
		case "/v2/fabric/whoami":
			whoamiCalls.Add(1)
			http.Error(response, `{"error":"fabric session is not authenticated"}`, http.StatusUnauthorized)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	context, err := harness.DetectCurrentSession()
	if err != nil {
		t.Fatal(err)
	}
	first := newMCPServer(server.URL, "", statePath)
	if _, err := first.callTool("cicada_join", map[string]any{"group_id": "group-stale"}); err != nil {
		t.Fatal(err)
	}
	close(first.stop)
	second := newMCPServer(server.URL, "", statePath)
	if err := second.restoreSession(context); err == nil {
		t.Fatal("revoked session restored successfully")
	}
	defer close(second.stop)
	if second.isJoined() {
		t.Fatal("stale credential remained active after restore failure")
	}
	if joinCalls.Load() != 1 || whoamiCalls.Load() != 1 {
		t.Fatalf("stale restore used an unexpected fallback: joins=%d whoami=%d", joinCalls.Load(), whoamiCalls.Load())
	}
	if cached, err := newMCPSessionStateStore(statePath).load(server.URL, context); err != nil {
		t.Fatal(err)
	} else if cached != nil {
		t.Fatal("stale credential remained in local state")
	}
}
