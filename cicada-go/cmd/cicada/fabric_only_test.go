package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/server"
)

func TestFabricOnlyManagementRoutesFailClosed(t *testing.T) {
	handler := server.NewFabricHandler(nil, "test-manager")
	for _, path := range []string{"/v1/machines", "/v1/goals", "/v1/approvals", "/v1/identity"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer test-manager")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: %d", path, response.Code)
		}
	}
}

func TestSessionAndNodeCredentialsCannotApproveAsUser(t *testing.T) {
	handler := server.NewFabricHandler(nil, "test-manager")
	for _, authorization := range []string{"CicadaSession cicada_session_actor", "CicadaNode cicada_node_actor"} {
		request := httptest.NewRequest(http.MethodPost, "/v1/approvals/approval-test", strings.NewReader(`{"decision":"approve","user_approved":true,"role":"monitor"}`))
		request.Header.Set("Authorization", authorization)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("peer credential entered approval handler: %d", response.Code)
		}
	}
}

func TestRelayOnlyAgentDoesNotStartBeforeOwnerBinding(t *testing.T) {
	t.Setenv("CICADA_NODE_TOKEN", "must-not-be-used")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	var calls []string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/v2/relay/nodes/test-node/events":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "CicadaNode ") || r.Header.Get("Authorization") == "CicadaNode must-not-be-used" {
				t.Errorf("agent did not use its locally generated Node credential: %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "/v2/nodes/device-code":
			if r.Header.Get("Authorization") != "" {
				t.Errorf("unauthenticated enrollment had Authorization: %q", r.Header.Get("Authorization"))
			}
			var input struct {
				NodeID           string `json:"node_id"`
				CredentialDigest string `json:"credential_digest"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.NodeID != "test-node" || len(input.CredentialDigest) != 43 {
				t.Errorf("invalid digest-only enrollment request: %+v err=%v", input, err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_code":"ABCD-EFGH-JKLM","verification_uri":"/client/device"}`))
		default:
			t.Errorf("agent used an unexpected API before binding: %s", r.URL.Path)
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer remote.Close()
	err := runMachineAgent([]string{"--id", "test-node", "--control-url", remote.URL, "--state-dir", t.TempDir(), "--once", "--relay-only"})
	if err == nil || !strings.Contains(err.Error(), "owner confirmation") {
		t.Fatalf("expected to wait for owner binding, got %v", err)
	}
	if len(calls) != 2 || calls[0] != "/v2/relay/nodes/test-node/events" || calls[1] != "/v2/nodes/device-code" {
		t.Fatalf("calls=%v", calls)
	}
}

func TestMachineAgentRejectsRemoteHTTPHubForNodeCredentials(t *testing.T) {
	err := runMachineAgent([]string{"--id", "test-node", "--control-url", "http://hub.example", "--state-dir", t.TempDir(), "--once", "--relay-only"})
	if err == nil || !strings.Contains(err.Error(), "remote Node enrollment requires an HTTPS Hub URL") {
		t.Fatalf("got %v", err)
	}
}

func TestRetiredThreadAndEndpointCLICommandsAreUnavailable(t *testing.T) {
	for _, command := range []string{"thread", "endpoint"} {
		if err := clientCommand([]string{command, "join"}); err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Fatalf("retired %s command remained available: %v", command, err)
		}
	}
}
