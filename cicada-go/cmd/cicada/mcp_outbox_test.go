package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type mcpOutboxHTTPFixture struct {
	t           *testing.T
	server      *httptest.Server
	requests    atomic.Int32
	accepted    atomic.Int32
	mu          sync.Mutex
	keys        []string
	groupScopes []string
	byKey       map[string]string
	token       string
	expectGroup string
	dropFirst   bool
	forbidden   bool
	whoamiCalls atomic.Int32
}

func newMCPOutboxHTTPFixture(t *testing.T) *mcpOutboxHTTPFixture {
	t.Helper()
	fixture := &mcpOutboxHTTPFixture{t: t, byKey: make(map[string]string), token: "session-token"}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		expectedAuthorization := "CicadaSession " + fixture.token
		if request.URL.Path == "/v2/fabric/whoami" {
			fixture.whoamiCalls.Add(1)
			if request.Header.Get("Authorization") != expectedAuthorization {
				t.Errorf("whoami authorization = %q", request.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"endpoint_id": "endpoint-a", "group_id": "group-a", "harness": "codex", "node_id": "node-a", "workspace": "/work/a"})
			return
		}
		if request.URL.Path != "/v2/fabric/send" && request.URL.Path != "/v2/fabric/ask" && request.URL.Path != "/v2/fabric/reply" {
			http.NotFound(response, request)
			return
		}
		fixture.requests.Add(1)
		if request.Header.Get("Authorization") != expectedAuthorization {
			t.Errorf("operation authorization = %q", request.Header.Get("Authorization"))
		}
		groupScope := request.Header.Get("Cicada-Group-Scope")
		fixture.mu.Lock()
		fixture.groupScopes = append(fixture.groupScopes, groupScope)
		fixture.mu.Unlock()
		if fixture.expectGroup != "" && groupScope != fixture.expectGroup {
			response.WriteHeader(http.StatusNotFound)
			_, _ = response.Write([]byte(`{"error":"not found or not authorized"}`))
			return
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode operation body: %v", err)
			return
		}
		key, _ := body["idempotency_key"].(string)
		if key == "" {
			t.Errorf("operation omitted idempotency key: %#v", body)
		}
		encoded, _ := json.Marshal(body)
		fixture.mu.Lock()
		fixture.keys = append(fixture.keys, key)
		previous, seen := fixture.byKey[key]
		if !seen {
			fixture.byKey[key] = string(encoded)
			fixture.accepted.Add(1)
		}
		fixture.mu.Unlock()
		if seen && previous != string(encoded) {
			response.WriteHeader(http.StatusConflict)
			_, _ = response.Write([]byte(`{"error":"idempotency conflict"}`))
			return
		}
		if fixture.forbidden {
			response.WriteHeader(http.StatusForbidden)
			_, _ = response.Write([]byte(`{"error":"operation forbidden"}`))
			return
		}
		if fixture.dropFirst {
			fixture.dropFirst = false
			if hijacker, ok := response.(http.Hijacker); ok {
				connection, _, err := hijacker.Hijack()
				if err == nil {
					_ = connection.Close()
				}
				return
			}
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"message_id": "message-1", "request_id": "request-1", "state": "OPEN"})
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func mcpOutboxTestServer(t *testing.T, fixture *mcpOutboxHTTPFixture, statePath string, nativeSession string, endpoint string, group string) *mcpServer {
	t.Helper()
	server := newMCPServer(fixture.server.URL, endpoint, statePath)
	context := mcpTestContext("codex", nativeSession, "node-a", "/work/a")
	scope, trusted, err := mcpSessionScope(fixture.server.URL, context)
	if err != nil {
		t.Fatal(err)
	}
	server.setSession("session-token", endpoint, group, trusted, scope, mcpPublicJoinResult{})
	t.Cleanup(func() {
		if server.outbox != nil {
			_ = server.outbox.close()
		}
		close(server.stop)
	})
	return server
}

func mcpOutboxOperationID(t *testing.T, result any) string {
	t.Helper()
	object, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("outbox result type = %T, want map", result)
	}
	operationID, _ := object["operation_id"].(string)
	if operationID == "" {
		t.Fatalf("outbox result omitted operation_id: %#v", object)
	}
	return operationID
}

func TestMCPOutboxLostResponseRestartRetriesSameOperation(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	fixture.dropFirst = true
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	first := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	result, err := first.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "same payload", "idempotency_key": "operation-lost-response"})
	if err != nil {
		t.Fatal(err)
	}
	operationID := mcpOutboxOperationID(t, result)
	if status := result.(map[string]any)["status"]; status != mcpOutboxStatusUnknown {
		t.Fatalf("lost response status = %#v, want UNKNOWN", status)
	}
	if fixture.requests.Load() != 1 || fixture.accepted.Load() != 1 {
		t.Fatalf("first attempt requests=%d accepted=%d", fixture.requests.Load(), fixture.accepted.Load())
	}
	_ = first.outbox.close()

	second := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	retried, err := second.callTool("cicada_operation_retry", map[string]any{"operation_id": operationID})
	if err != nil {
		t.Fatal(err)
	}
	if status := retried.(map[string]any)["status"]; status != mcpOutboxStatusSent {
		t.Fatalf("retry status = %#v, want SENT", status)
	}
	if fixture.requests.Load() != 2 || fixture.accepted.Load() != 1 {
		t.Fatalf("retry requests=%d accepted=%d, want two HTTP attempts and one accepted operation", fixture.requests.Load(), fixture.accepted.Load())
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.keys) != 2 || fixture.keys[0] != fixture.keys[1] {
		t.Fatalf("retry did not reuse idempotency key: %#v", fixture.keys)
	}
}

func TestMCPOutboxAskUsesSelectedGroupOnInitialAndRestartedRetry(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	fixture.expectGroup = "group-b"
	fixture.dropFirst = true
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	first := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-b")
	result, err := first.callTool("cicada_ask", map[string]any{"target": "endpoint-b", "question": "current result?"})
	if err != nil {
		t.Fatal(err)
	}
	operationID := mcpOutboxOperationID(t, result)
	if got := result.(map[string]any)["status"]; got != mcpOutboxStatusUnknown {
		t.Fatalf("first attempt status = %v, want UNKNOWN", got)
	}
	_ = first.outbox.close()
	wrongGroup := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	if _, err := wrongGroup.callTool("cicada_operation_retry", map[string]any{"operation_id": operationID}); !errors.Is(err, errMCPOutboxContext) {
		t.Fatalf("retry from another selected Group = %v, want %v", err, errMCPOutboxContext)
	}
	if got := fixture.requests.Load(); got != 1 {
		t.Fatalf("cross-Group retry reached HTTP: requests=%d", got)
	}
	_ = wrongGroup.outbox.close()
	second := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-b")
	retried, err := second.callTool("cicada_operation_retry", map[string]any{"operation_id": operationID})
	if err != nil {
		t.Fatal(err)
	}
	if got := retried.(map[string]any)["status"]; got != mcpOutboxStatusSent {
		t.Fatalf("retry status = %v, want SENT", got)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.groupScopes) != 2 || fixture.groupScopes[0] != "group-b" || fixture.groupScopes[1] != "group-b" {
		t.Fatalf("initial/retry Group scopes = %#v, want group-b twice", fixture.groupScopes)
	}
	if fixture.accepted.Load() != 1 {
		t.Fatalf("accepted operations = %d, want one", fixture.accepted.Load())
	}
}

func TestMCPOutboxSameKeyDifferentInputConflictsBeforeHTTP(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	server := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	if _, err := server.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "first", "idempotency_key": "same-key"}); err != nil {
		t.Fatal(err)
	}
	before := fixture.requests.Load()
	if _, err := server.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "different", "idempotency_key": "same-key"}); !errors.Is(err, errMCPOutboxConflict) {
		t.Fatalf("different body conflict = %v, want %v", err, errMCPOutboxConflict)
	}
	if fixture.requests.Load() != before {
		t.Fatalf("conflicting operation reached HTTP: before=%d after=%d", before, fixture.requests.Load())
	}
}

func TestMCPOutboxSameBodyWithoutExplicitKeyCreatesDistinctOperations(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	server := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	first, err := server.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "repeatable payload"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := server.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "repeatable payload"})
	if err != nil {
		t.Fatal(err)
	}
	if mcpOutboxOperationID(t, first) == mcpOutboxOperationID(t, second) {
		t.Fatalf("two deliberate sends without an explicit key reused one operation: first=%#v second=%#v", first, second)
	}
	if fixture.requests.Load() != 2 || fixture.accepted.Load() != 2 {
		t.Fatalf("same-body sends requests=%d accepted=%d, want two distinct operations", fixture.requests.Load(), fixture.accepted.Load())
	}
}

func TestMCPOutboxDoesNotPersistCredential(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	server := mcpOutboxTestServer(t, fixture, statePath, "thread-secret", "endpoint-a", "group-a")
	server.sessionMu.Lock()
	server.sessionToken = "cicada_session_secret_should_not_persist"
	server.sessionMu.Unlock()
	fixture.token = "cicada_session_secret_should_not_persist"
	if _, err := server.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "private body"}); err != nil {
		t.Fatal(err)
	}
	if server.outbox == nil {
		t.Fatal("outbox was not initialized")
	}
	_ = server.outbox.close()
	for _, path := range []string{mcpOutboxStatePath(statePath), mcpOutboxStatePath(statePath) + "-wal", mcpOutboxStatePath(statePath) + "-shm"} {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "cicada_session_secret_should_not_persist") {
			t.Fatalf("session credential was persisted in %s", path)
		}
	}
}

func TestMCPOutboxCrossContextStatusAndRetryAreRejected(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	first := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	fixture.dropFirst = true
	result, err := first.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "payload"})
	if err != nil {
		t.Fatal(err)
	}
	operationID := mcpOutboxOperationID(t, result)
	_ = first.outbox.close()
	second := mcpOutboxTestServer(t, fixture, statePath, "thread-other", "endpoint-a", "group-a")
	if _, err := second.callTool("cicada_operation_status", map[string]any{"operation_id": operationID}); !errors.Is(err, errMCPOutboxContext) {
		t.Fatalf("cross-context status = %v, want %v", err, errMCPOutboxContext)
	}
	if _, err := second.callTool("cicada_operation_retry", map[string]any{"operation_id": operationID}); !errors.Is(err, errMCPOutboxContext) {
		t.Fatalf("cross-context retry = %v, want %v", err, errMCPOutboxContext)
	}
	if fixture.requests.Load() != 1 {
		t.Fatalf("cross-context retry sent HTTP: requests=%d", fixture.requests.Load())
	}
}

func TestMCPForbiddenOperationDoesNotDestroySession(t *testing.T) {
	var requests atomic.Int32
	var whoami atomic.Int32
	serverHTTP := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/fabric/send" {
			requests.Add(1)
			response.WriteHeader(http.StatusForbidden)
			_, _ = response.Write([]byte(`{"error":"operation forbidden"}`))
			return
		}
		if request.URL.Path == "/v2/fabric/whoami" {
			whoami.Add(1)
			_ = json.NewEncoder(response).Encode(map[string]any{"endpoint_id": "endpoint-a", "group_id": "group-a"})
			return
		}
		http.NotFound(response, request)
	}))
	defer serverHTTP.Close()
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	server := newMCPServer(serverHTTP.URL, "endpoint-a", statePath)
	context := mcpTestContext("codex", "thread-a", "node-a", "/work/a")
	scope, trusted, err := mcpSessionScope(serverHTTP.URL, context)
	if err != nil {
		t.Fatal(err)
	}
	server.setSession("session-token", "endpoint-a", "group-a", trusted, scope, mcpPublicJoinResult{})
	defer func() {
		_ = server.outbox.close()
		close(server.stop)
	}()
	result, err := server.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "denied"})
	if err != nil {
		t.Fatal(err)
	}
	if status := result.(map[string]any)["status"]; status != mcpOutboxStatusFailed {
		t.Fatalf("forbidden operation status = %#v, want FAILED", status)
	}
	if _, err := server.callTool("cicada_whoami", nil); err != nil {
		t.Fatalf("valid session was cleared by per-operation 403: %v", err)
	}
	if requests.Load() != 1 || whoami.Load() != 1 {
		t.Fatalf("requests=%d whoami=%d", requests.Load(), whoami.Load())
	}
}

func TestMCPOutboxPersistenceFailureDoesNotSendHTTP(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(parent, "sessions.json")
	server := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	if _, err := server.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "must not send"}); err == nil {
		t.Fatal("outbox persistence failure was ignored")
	}
	if fixture.requests.Load() != 0 {
		t.Fatalf("HTTP request sent after outbox persistence failure: %d", fixture.requests.Load())
	}
}

func TestMCPOutboxFilesArePrivate(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	server := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	if _, err := server.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "private"}); err != nil {
		t.Fatal(err)
	}
	path := mcpOutboxStatePath(statePath)
	_ = server.outbox.close()
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("outbox directory mode = %o, want 700", mode)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fileInfo.Mode().Perm(); mode != 0o600 {
		t.Fatalf("outbox file mode = %o, want 600", mode)
	}
}
