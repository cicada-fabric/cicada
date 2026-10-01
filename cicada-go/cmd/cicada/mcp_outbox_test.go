package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestSealedHandoffRetryTransferred(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	fixture.sourceCapabilities = map[string]any{"local_peer_delivery": "sealed_v1"}
	fixture.directoryTargets = map[string]fabricpkg.NetworkCard{
		"receiver-alias": {
			PrincipalID: "principal-b", EndpointID: "endpoint-b", GroupID: "group-b",
			Name: "receiver-alias", Harness: "codex", NodeID: "node-b", Status: "online",
			Capabilities: map[string]any{"local_peer_delivery": "sealed_v1"},
		},
	}
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	server := mcpOutboxTestServer(t, fixture, filepath.Join(t.TempDir(), "mcp", "sessions.json"),
		"thread-handoff", "endpoint-a", "group-b")
	scope, err := server.currentMCPOutboxScope()
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := server.ensureMCPOutbox()
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	expiresText := expiresAt.Format(time.RFC3339Nano)
	input := mcpOutboxInput{TaskID: "task_synthetic_12345678901234567890", Target: "endpoint-b",
		RequestedTarget: "receiver-alias", ExpectedRevision: 8, OwnerEpoch: 3,
		Body: "synthetic sealed handoff context", ExpiresAt: expiresText, RequiredArtifactRefsJSON: "[]"}
	operation, created, err := outbox.prepare(scope, "sealed_task_handoff", "handoff-retry-key", input)
	if err != nil || !created {
		t.Fatalf("prepare durable handoff: created=%v err=%v", created, err)
	}
	if _, err := outbox.markError(scope, operation.OperationID, mcpOutboxStatusUnknown,
		errors.New("simulated lost proposal response")); err != nil {
		t.Fatal(err)
	}
	messageID := "shared-task-handoff.v1:" + strconv.FormatInt(expiresAt.UnixMilli(), 10) + ":" + operation.OperationID
	digest := strings.Repeat("a", 64)
	fixture.mu.Lock()
	fixture.taskHandoffResponse = store.SealedSharedTaskHandoff{
		ID: operation.OperationID, TaskID: input.TaskID, GroupID: scope.GroupID,
		FromPrincipalID: "principal-a", FromEndpointID: scope.EndpointID,
		ToPrincipalID: "principal-b", ToEndpointID: input.Target,
		TaskRevision: input.ExpectedRevision, FromOwnerEpoch: input.OwnerEpoch,
		MessageID: messageID, MessageDigest: digest, RequiredArtifactRefs: []store.SealedTaskHandoffArtifactRef{},
		ExpiresAt: expiresText, Status: store.SealedTaskHandoffTransferred, Version: 2,
	}
	fixture.mu.Unlock()

	socketPath := machineAgentJoinSocketPath(stateDir, "node-a")
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		t.Fatalf("make synthetic Node socket private: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	requests := make(chan crossNodeGroupRequest, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request crossNodeGroupRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			return
		}
		requests <- request
		_ = json.NewEncoder(connection).Encode(localJoinResponse{
			Version: localJoinProtocolVersion,
			CrossNodeGroup: &crossNodeGroupResult{MessageID: messageID, TargetEndpointID: input.Target,
				State: "RELAY_ACCEPTED", Delivery: "RELAY_PERSISTED", PayloadMode: store.RelayPayloadModeSealedV1,
				Digest: digest},
		})
	}()

	arguments := map[string]any{
		"task_id": input.TaskID, "target": input.RequestedTarget, "body": input.Body,
		"expires_at": expiresText, "idempotency_key": operation.IdempotencyKey,
	}
	result, err := server.callTool("cicada_task_handoff_send", arguments)
	if err != nil {
		t.Fatal(err)
	}
	public := result.(map[string]any)
	if public["operation_id"] != operation.OperationID || public["status"] != mcpOutboxStatusSent {
		t.Fatalf("retry did not recover the exact outbox operation: %#v", public)
	}
	var recovered map[string]any
	encoded, _ := json.Marshal(public["result"])
	if err := json.Unmarshal(encoded, &recovered); err != nil {
		t.Fatal(err)
	}
	handoff, _ := recovered["handoff"].(map[string]any)
	if handoff["status"] != store.SealedTaskHandoffTransferred {
		t.Fatalf("transferred proposal was not recovered: %#v", handoff)
	}
	select {
	case nodeRequest := <-requests:
		if nodeRequest.Operation != "cross_node_task_handoff" || nodeRequest.TargetEndpointID != input.Target ||
			nodeRequest.TaskID != input.TaskID || nodeRequest.ExpectedRevision != input.ExpectedRevision ||
			nodeRequest.OwnerEpoch != input.OwnerEpoch || nodeRequest.HandoffMessageID != messageID {
			t.Fatalf("retry changed its durable Node request: %#v", nodeRequest)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry did not query the durable local Node operation")
	}
	if fixture.taskGetCalls.Load() != 0 || fixture.resolveCalls.Load() != 1 ||
		fixture.taskHandoffGetCalls.Load() != 1 || fixture.taskHandoffProposalCalls.Load() != 0 {
		t.Fatalf("retry did not resolve its durable target exactly once or reproposed: task=%d resolve=%d GET=%d POST=%d",
			fixture.taskGetCalls.Load(), fixture.resolveCalls.Load(), fixture.taskHandoffGetCalls.Load(),
			fixture.taskHandoffProposalCalls.Load())
	}

	// Exact repeat is returned from the durable SENT result. Same-key edits to
	// body, requested target or deadline cannot replace the original packet.
	if _, err := server.callTool("cicada_task_handoff_send", arguments); err != nil {
		t.Fatalf("exact same-key retry failed: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"body":   func(args map[string]any) { args["body"] = "changed body" },
		"target": func(args map[string]any) { args["target"] = "different-alias" },
		"deadline": func(args map[string]any) {
			args["expires_at"] = expiresAt.Add(time.Minute).Format(time.RFC3339Nano)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := make(map[string]any, len(arguments))
			for key, value := range arguments {
				changed[key] = value
			}
			mutate(changed)
			if _, err := server.callTool("cicada_task_handoff_send", changed); !errors.Is(err, errMCPOutboxConflict) {
				t.Fatalf("changed same-key %s returned %v, want conflict", name, err)
			}
		})
	}
	if fixture.taskGetCalls.Load() != 0 || fixture.resolveCalls.Load() != 1 ||
		fixture.taskHandoffGetCalls.Load() != 1 || fixture.taskHandoffProposalCalls.Load() != 0 {
		t.Fatalf("cached retry or intent conflict touched network: task=%d resolve=%d GET=%d POST=%d",
			fixture.taskGetCalls.Load(), fixture.resolveCalls.Load(), fixture.taskHandoffGetCalls.Load(),
			fixture.taskHandoffProposalCalls.Load())
	}
}

type mcpOutboxFixtureSession struct {
	nativeSession string
	endpoint      string
	group         string
	workspace     string
	principal     string
	binding       string
	bindingEpoch  uint64
	capabilities  map[string]any
}

type mcpOutboxHTTPFixture struct {
	server                   *httptest.Server
	requests                 atomic.Int32
	receiveCalls             atomic.Int32
	whoamiCalls              atomic.Int32
	resolveCalls             atomic.Int32
	taskGetCalls             atomic.Int32
	taskHandoffGetCalls      atomic.Int32
	taskHandoffProposalCalls atomic.Int32
	taskHandoffPostCalls     atomic.Int32
	mu                       sync.Mutex
	preflightGroupScopes     []string
	token                    string
	workspace                string
	sourceCapabilities       map[string]any
	targetCapabilities       map[string]any
	targetNodeID             string
	directoryTargets         map[string]fabricpkg.NetworkCard
	currentSession           mcpOutboxFixtureSession
	taskHandoffResponse      any
}

func newMCPOutboxHTTPFixture(t *testing.T) *mcpOutboxHTTPFixture {
	t.Helper()
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	fixture := &mcpOutboxHTTPFixture{
		token:     "session-token",
		workspace: workspace, targetNodeID: "node-b",
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		expectedAuthorization := "CicadaSession " + fixture.token
		if request.URL.Path == "/v2/fabric/receive" {
			fixture.receiveCalls.Add(1)
			http.Error(response, "legacy plaintext receive must not be called", http.StatusGone)
			return
		}
		if request.URL.Path == "/v2/fabric/whoami" {
			fixture.whoamiCalls.Add(1)
			if request.Header.Get("Authorization") != expectedAuthorization {
				t.Errorf("whoami authorization = %q", request.Header.Get("Authorization"))
			}
			fixture.mu.Lock()
			session := fixture.currentSession
			fixture.preflightGroupScopes = append(fixture.preflightGroupScopes, request.Header.Get("Cicada-Group-Scope"))
			fixture.mu.Unlock()
			_ = json.NewEncoder(response).Encode(fabricpkg.NetworkCard{
				PrincipalID: session.principal, EndpointID: session.endpoint, GroupID: session.group,
				Name: "Outbox fixture session", Harness: "codex", NodeID: "node-a",
				Workspace: session.workspace, Status: "online", BindingID: session.binding,
				BindingEpoch: session.bindingEpoch, NativeSessionID: session.nativeSession,
				Capabilities: session.capabilities,
			})
			return
		}
		if request.URL.Path == "/v2/fabric/resolve" {
			fixture.resolveCalls.Add(1)
			if request.Header.Get("Authorization") != expectedAuthorization {
				t.Errorf("resolve authorization = %q", request.Header.Get("Authorization"))
			}
			fixture.mu.Lock()
			session := fixture.currentSession
			fixture.preflightGroupScopes = append(fixture.preflightGroupScopes, request.Header.Get("Cicada-Group-Scope"))
			fixture.mu.Unlock()
			var input fabricpkg.ResolveInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode Directory resolve: %v", err)
				return
			}
			card, found := fixture.directoryTargets[input.Query]
			if !found {
				card = fabricpkg.NetworkCard{
					PrincipalID: "principal-b", EndpointID: input.Query, GroupID: session.group,
					Name: input.Query, Harness: "codex", NodeID: fixture.targetNodeID, Status: "online",
					Capabilities: fixture.targetCapabilities,
				}
			}
			_ = json.NewEncoder(response).Encode(card)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/v2/fabric/tasks/sealed-handoffs/") {
			if request.Method == http.MethodGet {
				fixture.taskHandoffGetCalls.Add(1)
				fixture.mu.Lock()
				handoff := fixture.taskHandoffResponse
				fixture.mu.Unlock()
				if handoff == nil {
					http.NotFound(response, request)
					return
				}
				_ = json.NewEncoder(response).Encode(handoff)
				return
			}
			if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/accept") {
				var input fabricpkg.SealedTaskHandoffAcceptInput
				if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
					t.Errorf("decode sealed Task handoff acceptance: %v", err)
					http.Error(response, "bad input", http.StatusBadRequest)
					return
				}
				fixture.taskHandoffPostCalls.Add(1)
				_ = json.NewEncoder(response).Encode(map[string]any{"accepted": true})
				return
			}
			if request.Method == http.MethodPost {
				fixture.taskHandoffProposalCalls.Add(1)
				http.Error(response, "unexpected duplicate proposal", http.StatusConflict)
				return
			}
		}
		if strings.HasPrefix(request.URL.Path, "/v2/fabric/tasks/") && request.Method == http.MethodGet {
			fixture.taskGetCalls.Add(1)
			http.Error(response, "unexpected Task reread", http.StatusInternalServerError)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/v2/fabric/requests/") && request.Method == http.MethodGet {
			if request.Header.Get("Authorization") != expectedAuthorization {
				t.Errorf("request metadata authorization = %q", request.Header.Get("Authorization"))
			}
			fixture.mu.Lock()
			session := fixture.currentSession
			fixture.preflightGroupScopes = append(fixture.preflightGroupScopes, request.Header.Get("Cicada-Group-Scope"))
			fixture.mu.Unlock()
			requestID := strings.TrimPrefix(request.URL.Path, "/v2/fabric/requests/")
			_ = json.NewEncoder(response).Encode(fabricpkg.RequestView{
				RequestID: requestID, SenderEndpointID: "endpoint-b", SenderGroupID: session.group,
				State: "OPEN", Delivery: "RELAY_ACCEPTED", ReplyMode: "asynchronous",
			})
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
		response.WriteHeader(http.StatusInternalServerError)
		_, _ = response.Write([]byte(`{"error":"unexpected plaintext peer HTTP request"}`))
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func mcpOutboxTestServer(t *testing.T, fixture *mcpOutboxHTTPFixture, statePath string, nativeSession string, endpoint string, group string) *mcpServer {
	t.Helper()
	bindingID := "binding-" + nativeSession
	session := mcpOutboxFixtureSession{
		nativeSession: nativeSession, endpoint: endpoint, group: group,
		workspace: fixture.workspace, principal: "principal-a", binding: bindingID, bindingEpoch: 1,
		capabilities: fixture.sourceCapabilities,
	}
	fixture.mu.Lock()
	fixture.currentSession = session
	fixture.mu.Unlock()
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_MACHINE_ID", "node-a")
	t.Setenv("CICADA_WORKSPACE", fixture.workspace)
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CODEX_THREAD_ID", nativeSession)
	t.Setenv("CODEX_SESSION_ID", "")
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	writeCodexSessionRecord(t, codexHome, nativeSession, fixture.workspace)
	server := newMCPServer(fixture.server.URL, endpoint, statePath)
	context := mcpTestContext("codex", nativeSession, "node-a", fixture.workspace)
	scope, trusted, err := mcpSessionScope(fixture.server.URL, context)
	if err != nil {
		t.Fatal(err)
	}
	card := fabricpkg.NetworkCard{
		PrincipalID: session.principal, EndpointID: endpoint, GroupID: group,
		Name: "Outbox fixture session", Harness: "codex", NodeID: "node-a",
		Workspace: fixture.workspace, Status: "online", BindingID: bindingID,
		BindingEpoch: 1, NativeSessionID: nativeSession, Capabilities: fixture.sourceCapabilities,
	}
	server.setSession("session-token", endpoint, group, trusted, scope, mcpPublicJoinResult{
		Endpoint: store.Endpoint{
			ID: endpoint, GroupID: group, Owner: "owner-a", PrincipalID: session.principal,
			Harness: "codex", NativeSessionID: nativeSession, MachineID: "node-a",
			Workspace: fixture.workspace, BindingID: bindingID, Capabilities: fixture.sourceCapabilities,
		},
		NetworkCard: card, BindingID: bindingID, BindingEpoch: 1,
	})
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

func TestMCPOutboxUnsealedSendFailsClosedAndRetryNeverPostsPlaintext(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	first := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	result, err := first.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "same payload", "idempotency_key": "operation-lost-response"})
	if err != nil {
		t.Fatal(err)
	}
	operationID := mcpOutboxOperationID(t, result)
	if status := result.(map[string]any)["status"]; status != mcpOutboxStatusFailed {
		t.Fatalf("unsealed send status = %#v, want terminal FAILED", status)
	}
	if fixture.requests.Load() != 0 {
		t.Fatalf("unsealed send reached plaintext peer HTTP: requests=%d", fixture.requests.Load())
	}
	// Simulate a crash after an uncertain local attempt. Retrying must recheck
	// current capabilities and may not fall back to the old Hub SEND endpoint.
	scope, err := first.currentMCPOutboxScope()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.outbox.markError(scope, operationID, mcpOutboxStatusUnknown, errors.New("simulated uncertain attempt")); err != nil {
		t.Fatal(err)
	}

	retried, err := first.callTool("cicada_operation_retry", map[string]any{"operation_id": operationID})
	if err != nil {
		t.Fatal(err)
	}
	if status := retried.(map[string]any)["status"]; status != mcpOutboxStatusFailed {
		t.Fatalf("retry without sealed capability status = %#v, want FAILED", status)
	}
	if fixture.requests.Load() != 0 {
		t.Fatalf("retry reached plaintext peer HTTP: requests=%d", fixture.requests.Load())
	}
	if fixture.whoamiCalls.Load() != 2 || fixture.resolveCalls.Load() != 0 {
		t.Fatalf("source capability checks whoami=%d resolve=%d, want 2/0", fixture.whoamiCalls.Load(), fixture.resolveCalls.Load())
	}
}

func TestMCPReceiveWithoutSealedNodeCapabilityDoesNotFallbackToHub(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	server := mcpOutboxTestServer(t, fixture, statePath, "thread-receive", "endpoint-a", "group-a")
	if _, err := server.callTool("cicada_receive", map[string]any{"limit": 8}); !errors.Is(err, fabricpkg.ErrPlaintextInboxReceiveRetired) {
		t.Fatalf("receive without Node sealed-delivery capability error = %v", err)
	}
	if fixture.whoamiCalls.Load() != 1 {
		t.Fatalf("expected one authenticated capability refresh, got %d", fixture.whoamiCalls.Load())
	}
	if fixture.receiveCalls.Load() != 0 || fixture.requests.Load() != 0 {
		t.Fatalf("receive fell back to legacy Hub inbox: receive=%d peer=%d", fixture.receiveCalls.Load(), fixture.requests.Load())
	}
}

func TestMCPOutboxAskUsesSelectedGroupAndNeverFallsBackToHubPlaintext(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	fixture.sourceCapabilities = map[string]any{"local_peer_delivery": "sealed_v1"}
	fixture.targetCapabilities = map[string]any{"local_peer_delivery": "sealed_v1"}
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(stateRoot, "node-state")
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	first := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-b")
	result, err := first.callTool("cicada_ask", map[string]any{"target": "endpoint-b", "question": "current result?"})
	if err != nil {
		t.Fatal(err)
	}
	operationID := mcpOutboxOperationID(t, result)
	if public := result.(map[string]any); public["status"] != mcpOutboxStatusUnknown || public["retryable"] != true {
		t.Fatalf("unavailable sealed Node attempt result = %#v, want retryable UNKNOWN", result)
	}
	_ = first.outbox.close()
	wrongGroup := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	if _, err := wrongGroup.callTool("cicada_operation_retry", map[string]any{"operation_id": operationID}); !errors.Is(err, errMCPOutboxContext) {
		t.Fatalf("retry from another selected Group = %v, want %v", err, errMCPOutboxContext)
	}
	if got := fixture.requests.Load(); got != 0 {
		t.Fatalf("sealed Group retry reached legacy Hub plaintext endpoint: requests=%d", got)
	}
	_ = wrongGroup.outbox.close()
	if len(fixture.preflightGroupScopes) != 4 || fixture.whoamiCalls.Load() != 2 || fixture.resolveCalls.Load() != 2 {
		t.Fatalf("fresh sealed-route metadata calls whoami=%d resolve=%d scopes=%#v, want two of each in group-b", fixture.whoamiCalls.Load(), fixture.resolveCalls.Load(), fixture.preflightGroupScopes)
	}
	for _, groupScope := range fixture.preflightGroupScopes {
		if groupScope != "group-b" {
			t.Fatalf("sealed route metadata escaped selected Group: scopes=%#v", fixture.preflightGroupScopes)
		}
	}
	if fixture.requests.Load() != 0 {
		t.Fatalf("sealed same-Group retry reached plaintext Hub endpoint: requests=%d", fixture.requests.Load())
	}
}

func TestMCPOutboxUnsealedTargetFailsClosed(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	fixture.sourceCapabilities = map[string]any{"local_peer_delivery": "sealed_v1"}
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	server := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	result, err := server.callTool("cicada_send", map[string]any{"target": "endpoint-b", "body": "must remain local"})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.(map[string]any)["status"]; got != mcpOutboxStatusFailed {
		t.Fatalf("unsealed target status = %v, want terminal FAILED", got)
	}
	if fixture.requests.Load() != 0 || fixture.resolveCalls.Load() != 1 {
		t.Fatalf("unsealed target reached peer HTTP or skipped Directory check: peer requests=%d resolve=%d", fixture.requests.Load(), fixture.resolveCalls.Load())
	}
}

func TestMCPOutboxUnknownTargetCapabilityFailsClosed(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	fixture.sourceCapabilities = map[string]any{"local_peer_delivery": "sealed_v1"}
	fixture.targetCapabilities = map[string]any{"local_peer_delivery": "future-v9"}
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	server := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	result, err := server.callTool("cicada_ask", map[string]any{"target": "endpoint-b", "question": "private?"})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.(map[string]any)["status"]; got != mcpOutboxStatusFailed {
		t.Fatalf("unknown target capability status = %v, want terminal FAILED", got)
	}
	if fixture.requests.Load() != 0 || fixture.resolveCalls.Load() != 1 {
		t.Fatalf("unknown capability reached peer HTTP or skipped Directory check: peer requests=%d resolve=%d", fixture.requests.Load(), fixture.resolveCalls.Load())
	}
}

func TestMCPOutboxCorruptInputCannotFallThrough(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	server := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	scope, err := server.currentMCPOutboxScope()
	if err != nil {
		t.Fatal(err)
	}
	operation, _, err := server.outbox.prepare(scope, "send", "corrupt-retry",
		mcpOutboxInput{Target: "endpoint-b", Body: "do not deliver"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.outbox.markError(scope, operation.OperationID, mcpOutboxStatusUnknown, errors.New("simulated crash")); err != nil {
		t.Fatal(err)
	}
	server.outbox.mu.Lock()
	db, err := server.outbox.withDBLocked()
	if err == nil {
		_, err = db.Exec(`UPDATE mcp_outbox_operations SET input_json = ? WHERE operation_id = ?`, "{", operation.OperationID)
	}
	server.outbox.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	result, err := server.callTool("cicada_operation_retry", map[string]any{"operation_id": operation.OperationID})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.(map[string]any)["status"]; got != mcpOutboxStatusFailed {
		t.Fatalf("corrupt input status = %v, want terminal FAILED", got)
	}
	if fixture.requests.Load() != 0 || fixture.whoamiCalls.Load() != 0 || fixture.resolveCalls.Load() != 0 {
		t.Fatalf("corrupt input reached network: peer=%d whoami=%d resolve=%d", fixture.requests.Load(), fixture.whoamiCalls.Load(), fixture.resolveCalls.Load())
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
	if fixture.requests.Load() != 0 {
		t.Fatalf("unsealed same-body sends reached Hub peer endpoint: requests=%d", fixture.requests.Load())
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
	if fixture.requests.Load() != 0 {
		t.Fatalf("cross-context retry sent HTTP: requests=%d", fixture.requests.Load())
	}
}

func TestMCPOutboxFailureDoesNotDestroySession(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	server := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
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
	if fixture.requests.Load() != 0 || fixture.whoamiCalls.Load() != 2 || fixture.resolveCalls.Load() != 0 {
		t.Fatalf("operation requests=%d fresh whoami=%d resolve=%d, want 0/2/0", fixture.requests.Load(), fixture.whoamiCalls.Load(), fixture.resolveCalls.Load())
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

// Explicit Link RPC continues to use its sealed local Node bridge and has no
// Hub peer-message fallback when that bridge is unavailable.
func TestMCPOutboxExplicitLinkAskNeverPostsPlaintextToHub(t *testing.T) {
	fixture := newMCPOutboxHTTPFixture(t)
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_NODE_STATE_DIR", filepath.Join(stateRoot, "node-state"))
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	server := mcpOutboxTestServer(t, fixture, statePath, "thread-a", "endpoint-a", "group-a")
	result, err := server.callTool("cicada_ask", map[string]any{
		"link_id": "link-a", "data_scope": "summary", "question": "private question",
	})
	if err != nil {
		t.Fatal(err)
	}
	if public := result.(map[string]any); public["status"] != mcpOutboxStatusUnknown || public["retryable"] != true {
		t.Fatalf("unavailable sealed Node bridge result = %#v, want retryable UNKNOWN", result)
	}
	if fixture.requests.Load() != 0 || fixture.resolveCalls.Load() != 0 {
		t.Fatalf("explicit Link Ask reached Hub peer endpoint or Directory target resolution: peer=%d resolve=%d", fixture.requests.Load(), fixture.resolveCalls.Load())
	}
}

func TestMCPSealedAskUnknownKeepsQueryableCorrelationWithoutBody(t *testing.T) {
	input, err := json.Marshal(mcpOutboxInput{LinkID: "link-a", DataScope: "summary", Question: "private question"})
	if err != nil {
		t.Fatal(err)
	}
	op := mcpOutboxOperation{OperationID: "op_0123456789abcdef0123456789abcdef", Kind: "ask",
		Status: mcpOutboxStatusUnknown, InputJSON: string(input)}
	public := mcpOutboxPublicResult(op)
	if public["request_id"] != "rq_0123456789abcdef0123456789abcdef" ||
		public["link_id"] != "link-a" || public["status"] != mcpOutboxStatusUnknown {
		t.Fatalf("uncertain sealed ASK lost recovery correlation: %#v", public)
	}
	encoded, err := json.Marshal(public)
	if err != nil || strings.Contains(string(encoded), "private question") {
		t.Fatalf("uncertain sealed ASK leaked its body: %s err=%v", encoded, err)
	}
}
