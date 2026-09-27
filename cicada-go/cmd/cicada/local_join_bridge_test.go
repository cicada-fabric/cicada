package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

func writeCodexSessionRecord(t *testing.T, codexHome, nativeID, workspace string) {
	t.Helper()
	path := filepath.Join(codexHome, "sessions", "2026", "09", "23", "rollout-2026-09-23T00-00-00-"+nativeID+".jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	record := map[string]any{
		"type": "session_meta",
		"payload": map[string]any{
			"id": nativeID, "session_id": "session-" + nativeID, "cwd": workspace,
		},
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func prepareMCPJoinSessionRecord(t *testing.T, nativeID string) string {
	t.Helper()
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_WORKSPACE", workspace)
	t.Setenv("CICADA_NODE_STATE_DIR", shortLocalJoinStateDir(t))
	writeCodexSessionRecord(t, codexHome, nativeID, workspace)
	return workspace
}

func shortLocalJoinStateDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "cjoin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func startTestMCPNodeBridge(t *testing.T, baseURL, nodeID string) (*machineAgentJoinBridge, string) {
	t.Helper()
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	bridge, err := startMachineAgentJoinBridge(ctx, machineAgentStateDir(), baseURL, nodeID, nodeToken)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = bridge.Close()
	})
	return bridge, nodeToken
}

func TestDetectCodexMCPJoinSessionRequiresMatchingLocalRecord(t *testing.T) {
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_HARNESS", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "forged-compat-id")
	t.Setenv("CODEX_THREAD_ID", "thread-local-record")
	t.Setenv("CODEX_SESSION_ID", "session-thread-local-record")
	t.Setenv("CICADA_WORKSPACE", workspace)
	writeCodexSessionRecord(t, codexHome, "thread-local-record", workspace)

	context, err := detectCodexMCPJoinSession()
	if err != nil {
		t.Fatal(err)
	}
	if context.Harness != "codex" || context.NativeSessionID != "thread-local-record" || context.Workspace != workspace {
		t.Fatalf("join did not use the Codex record identity/workspace: %#v", context)
	}

	otherWorkspace := t.TempDir()
	writeCodexSessionRecord(t, codexHome, "thread-wrong-workspace", otherWorkspace)
	t.Setenv("CODEX_THREAD_ID", "thread-wrong-workspace")
	if _, err := detectCodexMCPJoinSession(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched native session workspace was accepted: %v", err)
	}

	t.Setenv("CODEX_THREAD_ID", "")
	t.Setenv("CODEX_SESSION_ID", "")
	if _, err := detectCodexMCPJoinSession(); err == nil || !strings.Contains(err.Error(), "refusing to guess") {
		t.Fatalf("compatibility ID was accepted without Codex identity: %v", err)
	}
}

func TestDetectCodexMCPJoinSameUIDCanForgeLocalMetadataTrustBoundary(t *testing.T) {
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "ignored-compat-id")
	t.Setenv("CODEX_THREAD_ID", "thread-created-by-same-user")
	t.Setenv("CODEX_SESSION_ID", "")
	t.Setenv("CICADA_MACHINE_ID", "node-a")
	t.Setenv("CICADA_WORKSPACE", workspace)
	writeCodexSessionRecord(t, codexHome, "thread-created-by-same-user", workspace)

	// The local record is an ownership/workspace consistency check only. A
	// process running as the same OS user can create both the environment and
	// the record, so this must never be described as Hub-verifiable proof.
	if _, err := detectCodexMCPJoinSession(); err != nil {
		t.Fatalf("same-UID metadata forgery test no longer describes the local trust boundary: %v", err)
	}
}

func TestMachineAgentJoinBridgeSocketPermissionsAndReentry(t *testing.T) {
	workspace := t.TempDir()
	codexHome := t.TempDir()
	writeCodexSessionRecord(t, codexHome, "thread-bridge", workspace)
	t.Setenv("CODEX_HOME", codexHome)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/fabric/node/join" {
			http.NotFound(response, request)
			return
		}
		if request.Header.Get("Authorization") != "CicadaNode "+nodeToken {
			t.Errorf("Hub Join did not use the agent-held Node credential")
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode Hub Join request: %v", err)
			return
		}
		for _, key := range []string{"node_id", "owner_id", "principal_id", "endpoint_id", "lease_owner"} {
			if _, ok := body[key]; ok {
				t.Errorf("Node Join request included caller-asserted identity field %q", key)
			}
		}
		if body["native_session_id"] != "thread-bridge" || body["group_id"] != "group-a" {
			t.Errorf("unexpected trusted bridge payload: %#v", body)
		}
		requests.Add(1)
		_ = json.NewEncoder(response).Encode(fabricpkg.JoinResult{
			Endpoint:     store.Endpoint{ID: "ep-stable", Harness: "codex", NativeSessionID: "thread-bridge", MachineID: "node-a"},
			SessionToken: "cicada_session_private-token", BindingID: "binding-stable", BindingEpoch: uint64(requests.Load()),
		})
	}))
	defer server.Close()

	stateDir := shortLocalJoinStateDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-a", nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	path := machineAgentJoinSocketPath(stateDir, "node-a")
	socketInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0o600 {
		t.Fatalf("Unix socket mode=%v, want socket 0600", socketInfo.Mode())
	}
	directoryInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("socket directory mode=%v, want 0700", directoryInfo.Mode())
	}

	joinRequest := localJoinRequest{Version: localJoinProtocolVersion, GroupID: "group-a", Harness: "codex",
		NativeSessionID: "thread-bridge", Workspace: workspace}
	first, err := requestMachineAgentJoin(path, joinRequest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := requestMachineAgentJoin(path, joinRequest)
	if err != nil {
		t.Fatal(err)
	}
	if first.Endpoint.ID != "ep-stable" || second.Endpoint.ID != first.Endpoint.ID || requests.Load() != 2 {
		t.Fatalf("same native Thread reentry changed Endpoint identity: first=%#v second=%#v calls=%d", first, second, requests.Load())
	}
}

func TestMachineAgentJoinBridgeRejectsForgedIdentityFields(t *testing.T) {
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	var hubCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		hubCalls.Add(1)
		http.Error(response, "unexpected Hub call", http.StatusInternalServerError)
	}))
	defer server.Close()

	stateDir := shortLocalJoinStateDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-a", nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	connection, err := net.Dial("unix", machineAgentJoinSocketPath(stateDir, "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = connection.Write([]byte(`{"version":1,"group_id":"group-a","harness":"codex","native_session_id":"thread-forged","owner_id":"other-owner"}` + "\n"))
	if unix, ok := connection.(*net.UnixConn); ok {
		_ = unix.CloseWrite()
	}
	var response localJoinResponse
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error == "" || response.Join != nil || hubCalls.Load() != 0 {
		t.Fatalf("forged identity field reached Hub Join: response=%#v Hub calls=%d", response, hubCalls.Load())
	}
}

func TestMCPJoinUsesNodeBridgeAndOnlyCachesSessionToken(t *testing.T) {
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	stateDir := shortLocalJoinStateDir(t)
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_HARNESS", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "ignored-model-compatible-value")
	t.Setenv("CODEX_THREAD_ID", "thread-mcp-bridge")
	t.Setenv("CODEX_SESSION_ID", "session-thread-mcp-bridge")
	t.Setenv("CICADA_MACHINE_ID", "node-mcp")
	t.Setenv("CICADA_WORKSPACE", workspace)
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	writeCodexSessionRecord(t, codexHome, "thread-mcp-bridge", workspace)

	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	var joinCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/fabric/node/join" || request.Header.Get("Authorization") != "CicadaNode "+nodeToken {
			t.Errorf("MCP Join bypassed the Node bridge: path=%s authorization=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		joinCalls.Add(1)
		_ = json.NewEncoder(response).Encode(fabricpkg.JoinResult{
			Endpoint:     store.Endpoint{ID: "ep-mcp", Harness: "codex", NativeSessionID: "thread-mcp-bridge", MachineID: "node-mcp", Workspace: workspace},
			NetworkCard:  fabricpkg.NetworkCard{EndpointID: "ep-mcp", GroupID: "group-a", Harness: "codex", NodeID: "node-mcp", Workspace: workspace},
			SessionToken: "cicada_session_must-stay-local", BindingID: "binding-mcp", BindingEpoch: 1,
		})
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-mcp", nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	mcp := newMCPServer(server.URL, "", statePath)
	defer close(mcp.stop)
	result, err := mcp.callTool("cicada_join", map[string]any{"group_id": "group-a"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "cicada_session_must-stay-local") || strings.Contains(string(encoded), nodeToken) {
		t.Fatalf("MCP tool result exposed a Join credential: %s", encoded)
	}
	cached, err := newMCPSessionStateStore(statePath).load(server.URL, harness.SessionContext{
		Harness: "codex", NativeSessionID: "thread-mcp-bridge", MachineID: "node-mcp", Workspace: workspace,
	})
	if err != nil || cached == nil || cached.SessionToken != "cicada_session_must-stay-local" {
		t.Fatalf("session token was not stored in the MCP private cache: cached=%#v err=%v", cached, err)
	}
	if joinCalls.Load() != 1 || mcp.endpointID != "ep-mcp" {
		t.Fatalf("Node bridge Join did not complete: calls=%d endpoint=%q", joinCalls.Load(), mcp.endpointID)
	}
}

func TestMCPJoinDoesNotFallbackAfterNodeBridgeAuthorizationFailure(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			workspace := prepareMCPJoinSessionRecord(t, "thread-denied")
			t.Setenv("CICADA_HARNESS", "codex")
			t.Setenv("CICADA_NATIVE_SESSION_ID", "")
			t.Setenv("CODEX_THREAD_ID", "thread-denied")
			t.Setenv("CODEX_SESSION_ID", "session-thread-denied")
			t.Setenv("CICADA_MACHINE_ID", "node-denied")
			t.Setenv("CICADA_WORKSPACE", workspace)
			t.Setenv("CICADA_API_TOKEN", "manager-token-must-not-fallback")
			t.Setenv("CICADA_API_TOKEN_FILE", "")

			nodeToken, _, err := fabricpkg.NewNodeCredential()
			if err != nil {
				t.Fatal(err)
			}
			var nodeCalls, managerCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/v2/fabric/node/join":
					nodeCalls.Add(1)
					if request.Header.Get("Authorization") != "CicadaNode "+nodeToken {
						t.Errorf("expected Node-auth Join, got Authorization %q", request.Header.Get("Authorization"))
					}
					response.WriteHeader(status)
				case "/v2/fabric/join":
					managerCalls.Add(1)
					_ = json.NewEncoder(response).Encode(fabricpkg.JoinResult{
						Endpoint: store.Endpoint{ID: "ep-should-not-exist"}, SessionToken: "cicada_session_wrong-fallback",
					})
				default:
					http.NotFound(response, request)
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			bridge, err := startMachineAgentJoinBridge(ctx, machineAgentStateDir(), server.URL, "node-denied", nodeToken)
			if err != nil {
				t.Fatal(err)
			}
			defer bridge.Close()

			mcp := newMCPServer(server.URL, "", filepath.Join(t.TempDir(), "mcp", "sessions.json"))
			defer close(mcp.stop)
			if _, err := mcp.callTool("cicada_join", map[string]any{"group_id": "group-a"}); err == nil {
				t.Fatal("Node authorization failure was hidden by a manager fallback")
			}
			if nodeCalls.Load() != 1 || managerCalls.Load() != 0 {
				t.Fatalf("Node auth failure caused an unsafe fallback: Node calls=%d manager calls=%d", nodeCalls.Load(), managerCalls.Load())
			}
		})
	}
}
