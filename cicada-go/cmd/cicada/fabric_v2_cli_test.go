package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestFabricV2CLIJoinUsesManagementBearerAndStoresSessionCredential(t *testing.T) {
	t.Setenv("CICADA_API_TOKEN", "management-token")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	t.Setenv(fabricV2SessionTokenEnv, "")
	tokenPath := filepath.Join(t.TempDir(), "session.token")
	t.Setenv(fabricV2SessionFileEnv, tokenPath)

	var joinBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v2/fabric/join" {
			t.Fatalf("unexpected join route: %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer management-token" {
			t.Fatalf("join authorization = %q", got)
		}
		if err := json.NewDecoder(request.Body).Decode(&joinBody); err != nil {
			t.Fatalf("decode join body: %v", err)
		}
		_ = json.NewEncoder(response).Encode(fabricpkg.JoinResult{
			Endpoint:     store.Endpoint{ID: "ep_cli", Name: "planner", GroupID: "grp_cli"},
			SessionToken: "cicada_session_cli-secret",
			BindingID:    "binding_cli", BindingEpoch: 1,
		})
	}))
	defer server.Close()

	var output strings.Builder
	if err := fabricV2CommandOutput(server.URL, []string{
		"join", "--group", "grp_cli", "--session", "native_cli", "--node", "node_cli", "--harness", "codex",
	}, &output); err != nil {
		t.Fatal(err)
	}
	if got := joinBody["group_id"]; got != "grp_cli" {
		t.Fatalf("group_id = %#v", got)
	}
	if got := joinBody["native_session_id"]; got != "native_cli" {
		t.Fatalf("native_session_id = %#v", got)
	}
	if got := joinBody["node_id"]; got != "node_cli" {
		t.Fatalf("node_id = %#v", got)
	}
	for _, field := range []string{"principal_id", "sender", "role", "authorization", "approval"} {
		if _, ok := joinBody[field]; ok {
			t.Fatalf("join accepted caller identity field %q", field)
		}
	}
	if strings.Contains(output.String(), "cicada_session_cli-secret") || strings.Contains(output.String(), "session_token") {
		t.Fatalf("join output exposed session credential: %s", output.String())
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	var state fabricV2SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("decode stored session credential: %v", err)
	}
	if state.SessionToken != "cicada_session_cli-secret" || state.APIOrigin != server.URL || state.GroupID != "grp_cli" || state.NativeSessionID != "native_cli" {
		t.Fatalf("stored session credential metadata = %#v", state)
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("session credential mode = %o, want 600", got)
	}
}

func TestFabricV2CLIPeerOperationUsesSessionBindingWithoutIdentityFields(t *testing.T) {
	t.Setenv("CICADA_API_TOKEN", "management-token")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	t.Setenv(fabricV2SessionTokenEnv, "")
	tokenPath := filepath.Join(t.TempDir(), "session.token")

	var sendBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v2/fabric/send" {
			t.Fatalf("unexpected send route: %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "CicadaSession cicada_session_peer-secret" {
			t.Fatalf("send authorization = %q", got)
		}
		if err := json.NewDecoder(request.Body).Decode(&sendBody); err != nil {
			t.Fatalf("decode send body: %v", err)
		}
		_ = json.NewEncoder(response).Encode(map[string]string{"message_id": "msg_cli"})
	}))
	defer server.Close()
	if err := writeFabricV2SessionState(tokenPath, fabricV2SessionState{
		APIOrigin: server.URL, Harness: "codex", NativeSessionID: "native-peer",
		NodeID: "node-peer", GroupID: "grp-peer", EndpointID: "ep-peer",
		SessionToken: "cicada_session_peer-secret",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fabricV2SessionFileEnv, tokenPath)

	var output strings.Builder
	if err := fabricV2CommandOutput(server.URL, []string{"send", "benchmark", "hello", "peer"}, &output); err != nil {
		t.Fatal(err)
	}
	if got := sendBody["target"]; got != "benchmark" {
		t.Fatalf("target = %#v", got)
	}
	if got := sendBody["body"]; got != "hello peer" {
		t.Fatalf("body = %#v", got)
	}
	for _, field := range []string{"sender", "sender_endpoint_id", "principal_id", "group_id", "role", "approval"} {
		if _, ok := sendBody[field]; ok {
			t.Fatalf("peer operation accepted caller identity field %q", field)
		}
	}
}

func TestFabricV2CLIRequiresExplicitJoinCredential(t *testing.T) {
	t.Setenv(fabricV2SessionTokenEnv, "")
	t.Setenv(fabricV2SessionFileEnv, filepath.Join(t.TempDir(), "missing.token"))
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	var output strings.Builder
	err := fabricV2CommandOutput(server.URL, []string{"send", "benchmark", "hello"}, &output)
	if err == nil || !strings.Contains(err.Error(), "no active Cicada session credential") {
		t.Fatalf("missing-session error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("peer request count = %d, want 0", requests)
	}
}

func TestFabricV2CLISessionFileRejectsOriginAndNativeContextReuse(t *testing.T) {
	t.Setenv(fabricV2SessionTokenEnv, "")
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "native-b")
	t.Setenv("CICADA_MACHINE_ID", "node-a")
	t.Setenv("CICADA_WORKSPACE", "/workspace/a")
	tokenPath := filepath.Join(t.TempDir(), "session.json")
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		_ = json.NewEncoder(response).Encode(map[string]string{"message_id": "unexpected"})
	}))
	defer server.Close()

	if err := writeFabricV2SessionState(tokenPath, fabricV2SessionState{
		APIOrigin: "http://control.example", Harness: "codex", NativeSessionID: "native-a",
		NodeID: "node-a", Workspace: "/workspace/a", GroupID: "grp-a", EndpointID: "ep-a",
		SessionToken: "cicada_session_scoped-secret",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fabricV2SessionFileEnv, tokenPath)
	var output strings.Builder
	err := fabricV2CommandOutput(server.URL, []string{"send", "benchmark", "hello"}, &output)
	if err == nil || !strings.Contains(err.Error(), "different API origin") {
		t.Fatalf("cross-origin error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("cross-origin request count = %d, want 0", requests)
	}

	if err := writeFabricV2SessionState(tokenPath, fabricV2SessionState{
		APIOrigin: server.URL, Harness: "codex", NativeSessionID: "native-a",
		NodeID: "node-a", Workspace: "/workspace/a", GroupID: "grp-a", EndpointID: "ep-a",
		SessionToken: "cicada_session_scoped-secret",
	}); err != nil {
		t.Fatal(err)
	}
	err = fabricV2CommandOutput(server.URL, []string{"send", "benchmark", "hello"}, &output)
	if err == nil || !strings.Contains(err.Error(), "different native session") {
		t.Fatalf("cross-session error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("cross-session request count = %d, want 0", requests)
	}
}

func TestFabricV2CLIRedactsSessionCredentialFromAPIError(t *testing.T) {
	t.Setenv(fabricV2SessionTokenEnv, "cicada_session_error-secret")
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(`{"error":"cicada_session_error-secret"}`))
	}))
	defer server.Close()

	err := fabricV2CommandOutput(server.URL, []string{"send", "benchmark", "hello"}, &strings.Builder{})
	if err == nil || strings.Contains(err.Error(), "cicada_session_error-secret") || !strings.Contains(err.Error(), "<redacted>") {
		t.Fatalf("redacted API error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("API request count = %d, want 1", requests)
	}
}

func TestFabricV2CLIJoinRequiresGroup(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
	}))
	defer server.Close()

	err := fabricV2CommandOutput(server.URL, []string{"join", "--session", "native", "--node", "node"}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "requires --group GROUP_ID") {
		t.Fatalf("missing-group error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("join request count = %d, want 0", requests)
	}
}

func TestFabricV2CLISelectsAndLeavesOnlyCurrentGroup(t *testing.T) {
	t.Setenv(fabricV2SessionTokenEnv, "")
	t.Setenv("CICADA_SESSION_GROUP_ID", "")
	tokenPath := filepath.Join(t.TempDir(), "session.json")
	t.Setenv(fabricV2SessionFileEnv, tokenPath)
	var observedScopes []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "CicadaSession cicada_session_multi-secret" {
			t.Errorf("wrong session authorization")
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		scope := request.Header.Get("Cicada-Group-Scope")
		observedScopes = append(observedScopes, scope)
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			if scope != "grp_a" && scope != "grp_b" {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(response).Encode(fabricpkg.NetworkCard{
				EndpointID: "ep_multi", BindingID: "bind_multi", GroupID: scope,
			})
		case "/v2/fabric/leave-group":
			if scope != "grp_b" {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]string{
				"status": "left_group", "left_group_id": scope, "remaining_group_id": "grp_a",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	if err := writeFabricV2SessionState(tokenPath, fabricV2SessionState{
		APIOrigin: server.URL, Harness: "codex", NativeSessionID: "native-multi",
		NodeID: "node-a", GroupID: "grp_a", EndpointID: "ep_multi",
		BindingID: "bind_multi", SessionToken: "cicada_session_multi-secret",
	}); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := fabricV2CommandOutput(server.URL, []string{"use-group", "grp_b"}, &output); err != nil {
		t.Fatal(err)
	}
	if err := fabricV2CommandOutput(server.URL, []string{"whoami"}, &output); err != nil {
		t.Fatal(err)
	}
	if err := fabricV2CommandOutput(server.URL, []string{"leave-group"}, &output); err != nil {
		t.Fatal(err)
	}
	if err := fabricV2CommandOutput(server.URL, []string{"whoami"}, &output); err != nil {
		t.Fatal(err)
	}
	state, err := readFabricV2SessionState(tokenPath)
	if err != nil || state.GroupID != "grp_a" || state.EndpointID != "ep_multi" {
		t.Fatalf("remaining Group did not preserve native session identity: state=%#v err=%v", state, err)
	}
	want := []string{"grp_b", "grp_b", "grp_b", "grp_a"}
	if len(observedScopes) != len(want) {
		t.Fatalf("scope calls=%#v want=%#v", observedScopes, want)
	}
	for index, scope := range observedScopes {
		if scope != want[index] {
			t.Fatalf("scope calls=%#v want=%#v", observedScopes, want)
		}
	}
}
