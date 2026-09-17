package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestCicadaMCPAdvertisesFabricTools(t *testing.T) {
	required := map[string]bool{
		"cicada_whoami":  false,
		"cicada_list":    false,
		"cicada_resolve": false,
		"cicada_inspect": false,
		"cicada_send":    false,
		"cicada_ask":     false,
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

func TestCicadaMCPAutoJoinsCurrentCodexThread(t *testing.T) {
	t.Setenv("CICADA_HARNESS", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CODEX_THREAD_ID", "thread-current")
	t.Setenv("CICADA_MACHINE_ID", "gpu1")
	t.Setenv("CICADA_WORKSPACE", "/work/project")
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_API_TOKEN_FILE", "")

	var joins atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/endpoints":
			joins.Add(1)
			var input control.EndpointJoinInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode join: %v", err)
			}
			if input.Harness != "codex" || input.NativeSessionID != "thread-current" || input.MachineID != "gpu1" || input.Workspace != "/work/project" {
				t.Errorf("unexpected join input: %#v", input)
			}
			response.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(response).Encode(store.Endpoint{ID: "ep_current", Name: "project", Harness: "codex", NativeSessionID: "thread-current"})
		case "/v1/fabric/whoami":
			if request.URL.Query().Get("endpoint_id") != "ep_current" {
				t.Errorf("unexpected endpoint query: %s", request.URL.RawQuery)
			}
			_ = json.NewEncoder(response).Encode(control.NetworkCard{EndpointID: "ep_current", Address: "project@gpu1:/work/project"})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	mcp := &mcpServer{baseURL: server.URL, stop: make(chan struct{})}
	defer close(mcp.stop)
	result, err := mcp.callTool("cicada_whoami", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	if mcp.endpointID != "ep_current" || joins.Load() != 1 || !json.Valid(encoded) {
		t.Fatalf("unexpected MCP join: endpoint=%q joins=%d result=%s", mcp.endpointID, joins.Load(), encoded)
	}
	if _, err := mcp.callTool("cicada_whoami", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if joins.Load() != 1 {
		t.Fatalf("MCP join was not idempotent within the process: %d", joins.Load())
	}
}

func TestCicadaMCPRetriesJoinAfterTransientControlFailure(t *testing.T) {
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "thread-retry")
	t.Setenv("CICADA_MACHINE_ID", "gpu1")
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		attempt := attempts.Add(1)
		response.Header().Set("Content-Type", "application/json")
		if attempt == 1 {
			response.WriteHeader(http.StatusServiceUnavailable)
			_, _ = response.Write([]byte(`{"error":"temporarily unavailable"}`))
			return
		}
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(store.Endpoint{ID: "ep_retry", Name: "retry", Harness: "codex", NativeSessionID: "thread-retry"})
	}))
	defer server.Close()

	mcp := &mcpServer{baseURL: server.URL, stop: make(chan struct{})}
	defer close(mcp.stop)
	if err := mcp.ensureEndpoint(); err == nil {
		t.Fatal("expected the first transient join to fail")
	}
	if err := mcp.ensureEndpoint(); err != nil {
		t.Fatalf("retry did not recover: %v", err)
	}
	if attempts.Load() != 2 || mcp.endpointID != "ep_retry" {
		t.Fatalf("unexpected retry state: attempts=%d endpoint=%q", attempts.Load(), mcp.endpointID)
	}
}
