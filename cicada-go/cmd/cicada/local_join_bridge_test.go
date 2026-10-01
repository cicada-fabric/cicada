package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/cicada-ai/cicada/internal/nodeinbox"
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

func TestLocalJoinBlockedAfterHubCommitPersistsSafeRecoveryStatus(t *testing.T) {
	for _, test := range []struct {
		name       string
		seed       func(*testing.T, *nodeinbox.NativeContextRegistry, string)
		coverage   string
		reasonCode string
	}{
		{name: "known dedicated scope conflict", coverage: nodeinbox.NativeContextHistoryCoverageCicadaKnownOnly,
			reasonCode: "KNOWN_SCOPE_CONFLICT", seed: func(t *testing.T, registry *nodeinbox.NativeContextRegistry, writerScope string) {
				seedNativeJoinContext(t, registry, nodeinbox.NativeContextScopeInput{AccountID: writerScope, Harness: "codex",
					NativeSessionID: "thread-blocked", HubID: "hub-join-test", GroupID: "group-old",
					ContextPolicy: nodeinbox.NativeContextPolicyDedicatedThread, EndpointID: "ep-old", BindingID: "bind-old", BindingEpoch: 1})
			}},
		{name: "history capacity", coverage: nodeinbox.NativeContextHistoryCoverageCicadaKnownOnly,
			reasonCode: "KNOWN_SCOPE_HISTORY_LIMIT", seed: func(t *testing.T, registry *nodeinbox.NativeContextRegistry, writerScope string) {
				for index := 0; index < 64; index++ {
					seedNativeJoinContext(t, registry, nodeinbox.NativeContextScopeInput{AccountID: writerScope, Harness: "codex",
						NativeSessionID: "thread-blocked", HubID: "hub-join-test", GroupID: fmt.Sprintf("old-group-%02d", index),
						ContextPolicy: nodeinbox.NativeContextPolicyGroupScoped, EndpointID: fmt.Sprintf("ep-old-%02d", index),
						BindingID: fmt.Sprintf("bind-old-%02d", index), BindingEpoch: 1})
				}
			}},
		{name: "registry unavailable", coverage: nodeinbox.NativeContextHistoryCoverageNotChecked,
			reasonCode: "SCOPE_CHECK_UNAVAILABLE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			codexHome := t.TempDir()
			writeCodexSessionRecord(t, codexHome, "thread-blocked", workspace)
			t.Setenv("CODEX_HOME", codexHome)
			var joins, unexpectedPeerKeyRequests atomic.Int32
			nodeToken, _, err := fabricpkg.NewNodeCredential()
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/v2/fabric/node/join" {
					unexpectedPeerKeyRequests.Add(1)
					http.NotFound(response, request)
					return
				}
				joins.Add(1)
				_ = json.NewEncoder(response).Encode(fabricpkg.JoinResult{
					Endpoint:     store.Endpoint{ID: "ep-join-blocked", Harness: "codex", NativeSessionID: "thread-blocked", MachineID: "node-join-test"},
					NetworkCard:  fabricpkg.NetworkCard{EndpointID: "ep-join-blocked", GroupID: "group-new", Harness: "codex", NodeID: "node-join-test"},
					SessionToken: "cicada_session_must-not-escape", BindingID: "bind-join", BindingEpoch: uint64(joins.Load()),
					LeaseExpiresAt: "2026-10-01T12:00:00Z",
					NativeContextScope: store.NativeContextScopeMetadata{HubID: "hub-join-test", GroupID: "group-new",
						GroupContextPolicy: nodeinbox.NativeContextPolicyGroupScoped},
				})
			}))
			defer server.Close()

			stateDir := shortLocalJoinStateDir(t)
			var registry *nodeinbox.NativeContextRegistry
			if test.seed != nil {
				registry, err = nodeinbox.OpenNativeContextRegistry(filepath.Join(stateDir, "native-context-history.sqlite3"))
				if err != nil {
					t.Fatal(err)
				}
				defer registry.Close()
				test.seed(t, registry, machineNativeWriterScope())
			}
			nodeContext := machineHubContext{HubID: "hub-join-test", Origin: server.URL, NodeID: "node-join-test",
				StateDir: stateDir, Token: nodeToken, WriterRoot: stateDir, WriterScope: machineNativeWriterScope(),
				RequireNativeContext: true, NativeContexts: registry}
			ctx, cancel := context.WithCancel(withMachineHubContext(context.Background(), nodeContext))
			defer cancel()
			bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-join-test", nodeToken)
			if err != nil {
				t.Fatal(err)
			}
			defer bridge.Close()

			_, _, _, err = requestMachineAgentJoinWithScopeAndRecovery(machineAgentJoinSocketPath(stateDir, "node-join-test"), localJoinRequest{
				GroupID: "group-new", Harness: "codex", NativeSessionID: "thread-blocked", Workspace: workspace,
			})
			status, ok := localJoinRecoveryFromError(err)
			if !ok || status.Status != localJoinBlockedStatus || status.RecoveryState != localJoinRecoveryNeeded ||
				status.ReasonCode != test.reasonCode || status.NativeHistoryCoverage != test.coverage || !status.RecoveryRecordSaved {
				t.Fatalf("Hub-committed scope block lacks explicit recovery status: status=%#v err=%v", status, err)
			}
			if strings.Contains(err.Error(), "cicada_session_must-not-escape") || strings.Contains(err.Error(), "thread-blocked") ||
				strings.Contains(status.Message, "cicada_session") {
				t.Fatalf("partial-commit response leaked a session credential or native identity: %#v", status)
			}
			if joins.Load() != 1 || unexpectedPeerKeyRequests.Load() != 0 {
				t.Fatalf("blocked Join should commit once and publish no Endpoint key/capability: joins=%d peer-key requests=%d",
					joins.Load(), unexpectedPeerKeyRequests.Load())
			}
			path := bridge.localJoinRecoveryPath("GROUP", "hub-join-test", "group-new", "", "ep-join-blocked")
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("recovery record is missing: %v", err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("recovery record is not a private regular file: mode=%v", info.Mode())
			}
			directoryInfo, err := os.Stat(filepath.Dir(path))
			if err != nil {
				t.Fatalf("inspect recovery directory: %v", err)
			}
			if directoryInfo.Mode().Perm() != 0o700 {
				t.Fatalf("recovery directory is not private: mode=%v", directoryInfo.Mode())
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "cicada_session_must-not-escape") || strings.Contains(string(data), "thread-blocked") || strings.Contains(string(data), workspace) {
				t.Fatalf("recovery record contains credential or native-session details: %s", data)
			}
		})
	}
}

func seedNativeJoinContext(t *testing.T, registry *nodeinbox.NativeContextRegistry, input nodeinbox.NativeContextScopeInput) {
	t.Helper()
	decision, err := registry.CheckAndRecordNativeContext(context.Background(), input)
	if err != nil || decision == nil || !decision.Accepted {
		t.Fatalf("seed synthetic native scope: decision=%#v err=%v", decision, err)
	}
}

func TestLocalNetworkJoinBlockedAfterHubCommitDoesNotReturnCredential(t *testing.T) {
	workspace := t.TempDir()
	codexHome := t.TempDir()
	writeCodexSessionRecord(t, codexHome, "thread-network-blocked", workspace)
	t.Setenv("CODEX_HOME", codexHome)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	var joins atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/fabric/node/networks/join" {
			t.Errorf("blocked Network Join unexpectedly called %s", request.URL.Path)
			http.NotFound(response, request)
			return
		}
		joins.Add(1)
		_ = json.NewEncoder(response).Encode(fabricpkg.NetworkJoinResult{
			Endpoint:     store.Endpoint{ID: "ep-network-blocked", Harness: "codex", NativeSessionID: "thread-network-blocked", MachineID: "node-network-test"},
			SessionToken: "cicada_session_network-must-not-escape", BindingID: "bind-network", BindingEpoch: 1,
			LeaseExpiresAt: "2026-10-01T12:00:00Z", NetworkID: "network-new",
			NativeContextScope: store.NativeContextScopeMetadata{HubID: "hub-network-test", NetworkID: "network-new",
				NetworkContextPolicy: nodeinbox.NativeContextPolicyDedicatedNetwork},
		})
	}))
	defer server.Close()
	stateDir := shortLocalJoinStateDir(t)
	registry, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(stateDir, "native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	seedNativeJoinContext(t, registry, nodeinbox.NativeContextScopeInput{AccountID: machineNativeWriterScope(), Harness: "codex",
		NativeSessionID: "thread-network-blocked", HubID: "hub-network-test", NetworkID: "network-old",
		ContextPolicy: nodeinbox.NativeContextPolicyDedicatedNetwork, EndpointID: "ep-old-network", BindingID: "bind-old-network", BindingEpoch: 1})
	ctx, cancel := context.WithCancel(withMachineHubContext(context.Background(), machineHubContext{
		HubID: "hub-network-test", Origin: server.URL, NodeID: "node-network-test", StateDir: stateDir, Token: nodeToken,
		WriterRoot: stateDir, WriterScope: machineNativeWriterScope(), RequireNativeContext: true, NativeContexts: registry,
	}))
	defer cancel()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-network-test", nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	_, _, _, err = requestMachineAgentNetworkJoinWithScopeAndRecovery(machineAgentJoinSocketPath(stateDir, "node-network-test"), localNetworkJoinRequest{
		NetworkID: "network-new", InvitationToken: "synthetic-invitation", OwnerJoinProof: "synthetic-proof",
		Harness: "codex", NativeSessionID: "thread-network-blocked", Workspace: workspace,
	})
	status, ok := localJoinRecoveryFromError(err)
	if !ok || status.Status != localJoinBlockedStatus || status.ScopeType != "NETWORK" ||
		status.NativeHistoryCoverage != nodeinbox.NativeContextHistoryCoverageCicadaKnownOnly ||
		status.ReasonCode != "KNOWN_SCOPE_CONFLICT" || !status.RecoveryRecordSaved {
		t.Fatalf("Network Join scope conflict did not produce explicit partial-commit status: status=%#v err=%v", status, err)
	}
	if joins.Load() != 1 || strings.Contains(err.Error(), "cicada_session_network-must-not-escape") {
		t.Fatalf("Network partial-commit handling leaked credential or changed Join count: joins=%d err=%v", joins.Load(), err)
	}
}

func TestLocalJoinRecoveryRecordBoundAllowsExactKeyUpdate(t *testing.T) {
	stateDir := shortLocalJoinStateDir(t)
	bridge := &machineAgentJoinBridge{stateDir: stateDir, nodeID: "node-recovery-bound"}
	path := bridge.localJoinRecoveryPath("GROUP", "hub-bound", "group-bound", "", "ep-bound")
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < localJoinRecoveryMaxFiles; index++ {
		name := filepath.Join(directory, fmt.Sprintf("%03d.json", index))
		if err := os.WriteFile(name, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	blockedErr := bridge.blockCommittedLocalJoin("GROUP", "hub-bound", "group-bound", "", "ep-bound",
		"binding-new", 1, "2026-10-01T12:00:00Z", errors.New("synthetic unavailable registry"))
	status, ok := localJoinRecoveryFromError(blockedErr)
	if !ok || status.RecoveryRecordSaved {
		t.Fatalf("new record at capacity should report unsaved recovery metadata: %#v", status)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bounded recovery directory grew beyond its record cap: %v", err)
	}
	previous := localJoinRecoveryStatus{Status: localJoinBlockedStatus, RecoveryState: localJoinRecoveryNeeded,
		RecoveryID: localJoinRecoveryKey("GROUP", "hub-bound", "group-bound", "", "ep-bound"),
		Message:    "existing exact-key record", RecoveryRecordSaved: true}
	data, err := json.Marshal(previous)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	blockedErr = bridge.blockCommittedLocalJoin("GROUP", "hub-bound", "group-bound", "", "ep-bound",
		"binding-new", 1, "2026-10-01T12:00:00Z", errors.New("synthetic unavailable registry"))
	status, ok = localJoinRecoveryFromError(blockedErr)
	if !ok || !status.RecoveryRecordSaved {
		t.Fatalf("exact existing recovery key should remain writable at capacity: %#v", status)
	}
	data, err = os.ReadFile(path)
	var persisted localJoinRecoveryStatus
	if err != nil || json.Unmarshal(data, &persisted) != nil || !persisted.RecoveryRecordSaved || persisted.RecoveryID != status.RecoveryID {
		t.Fatalf("exact-key update did not persist a truthful saved marker: %#v err=%v", persisted, err)
	}
}

func TestLocalJoinExactRetryMarksRecoveryWithoutCompensatingLeave(t *testing.T) {
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	stateDir := shortLocalJoinStateDir(t)
	const nativeID = "thread-exact-retry"
	writeCodexSessionRecord(t, codexHome, nativeID, workspace)
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CODEX_THREAD_ID", nativeID)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeID)
	t.Setenv("CICADA_MACHINE_ID", "node-retry")
	t.Setenv("CICADA_WORKSPACE", workspace)
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	var joins, leaves, peerKeyPublications atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/node/join":
			joins.Add(1)
			_ = json.NewEncoder(response).Encode(fabricpkg.JoinResult{
				Endpoint:     store.Endpoint{ID: "ep-exact-retry", GroupID: "group-retry", Harness: "codex", NativeSessionID: nativeID, MachineID: "node-retry"},
				NetworkCard:  fabricpkg.NetworkCard{EndpointID: "ep-exact-retry", GroupID: "group-retry", Harness: "codex", NodeID: "node-retry"},
				SessionToken: fmt.Sprintf("cicada_session_private-%d", joins.Load()), BindingID: "binding-retry",
				BindingEpoch: uint64(joins.Load()), LeaseExpiresAt: "2026-10-01T12:00:00Z",
				NativeContextScope: store.NativeContextScopeMetadata{HubID: "hub-retry", GroupID: "group-retry",
					GroupContextPolicy: nodeinbox.NativeContextPolicyGroupScoped},
			})
		case "/v2/fabric/node/endpoints/key-candidate":
			peerKeyPublications.Add(1)
			http.Error(response, "unexpected peer key publication", http.StatusForbidden)
		case "/v2/fabric/node/leave", "/v2/fabric/node/groups/leave":
			leaves.Add(1)
			http.Error(response, "compensating leave is forbidden in this test", http.StatusInternalServerError)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	initialContext := machineHubContext{HubID: "hub-retry", Origin: server.URL, NodeID: "node-retry", StateDir: stateDir,
		Token: nodeToken, WriterRoot: stateDir, WriterScope: machineNativeWriterScope(), RequireNativeContext: true}
	ctx, cancel := context.WithCancel(withMachineHubContext(context.Background(), initialContext))
	defer cancel()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-retry", nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	statePath := filepath.Join(t.TempDir(), "mcp-state", "sessions.json")
	mcp := newMCPServer(server.URL, "", statePath)
	defer close(mcp.stop)

	first, err := mcp.callTool("cicada_join", map[string]any{"group_id": "group-retry"})
	if err != nil {
		t.Fatal(err)
	}
	blocked, ok := first.(localJoinRecoveryStatus)
	if !ok || blocked.Status != localJoinBlockedStatus || blocked.RecoveryState != localJoinRecoveryNeeded ||
		blocked.NativeHistoryCoverage != nodeinbox.NativeContextHistoryCoverageNotChecked ||
		!strings.Contains(blocked.CoverageExplanation, "unknown") {
		t.Fatalf("MCP did not report the partial commit and unknown history coverage: %#v", first)
	}
	if mcp.sessionToken != "" || mcp.endpointID != "" {
		t.Fatalf("blocked Hub membership became an active MCP session: endpoint=%q", mcp.endpointID)
	}
	if cached, err := newMCPSessionStateStore(statePath).load(server.URL, harness.SessionContext{
		Harness: "codex", NativeSessionID: nativeID, MachineID: "node-retry", Workspace: workspace,
	}); err != nil || cached != nil {
		t.Fatalf("blocked Hub membership was cached as an active session: cached=%#v err=%v", cached, err)
	}

	registry, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(stateDir, "native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	bridge.ctx = withMachineHubContext(context.Background(), machineHubContext{HubID: "hub-retry", Origin: server.URL,
		NodeID: "node-retry", StateDir: stateDir, Token: nodeToken, WriterRoot: stateDir,
		WriterScope: machineNativeWriterScope(), RequireNativeContext: true, NativeContexts: registry})
	second, err := mcp.callTool("cicada_join", map[string]any{"group_id": "group-retry"})
	if err != nil {
		t.Fatal(err)
	}
	recovered, ok := second.(mcpPublicJoinResult)
	if !ok || recovered.JoinRecovery == nil || recovered.JoinRecovery.Status != "JOIN_RECOVERED" ||
		recovered.JoinRecovery.RecoveryState != localJoinRecoveryDone ||
		recovered.JoinRecovery.NativeHistoryCoverage != nodeinbox.NativeContextHistoryCoverageCicadaKnownOnly {
		t.Fatalf("exact rejoin did not report its recovery state: %#v", second)
	}
	if mcp.sessionToken == "" || mcp.endpointID != "ep-exact-retry" {
		t.Fatalf("successful exact rejoin did not establish the session: endpoint=%q", mcp.endpointID)
	}
	path := bridge.localJoinRecoveryPath("GROUP", "hub-retry", "group-retry", "", "ep-exact-retry")
	var persisted localJoinRecoveryStatus
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &persisted) != nil || persisted.RecoveryState != localJoinRecoveryDone {
		t.Fatalf("recovery state was not durably advanced: %#v err=%v", persisted, err)
	}
	if joins.Load() != 2 || leaves.Load() != 0 || peerKeyPublications.Load() != 0 {
		t.Fatalf("retry did not preserve membership safely: joins=%d compensating leaves=%d peer key publications=%d",
			joins.Load(), leaves.Load(), peerKeyPublications.Load())
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
