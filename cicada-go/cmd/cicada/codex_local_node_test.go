package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cicada-ai/cicada/internal/harness"
)

func TestCodexLocalNodeConsumerOriginalPathsIgnoreLegacyEnvironment(t *testing.T) {
	root := privateLocalNodeRoot(t)
	expected := syntheticLocalNodePin(t, root, "synthetic-node")
	var requests atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer hub.Close()
	expected.APIOrigin = hub.URL
	// The synthetic local description is independent of this consumer's
	// process environment, as a separately running Node daemon would be.
	mockLocalNode(t, expected, nil, false)
	poison := filepath.Join(privateLocalNodeRoot(t), "other-deployment")
	for _, name := range []string{"CICADA_API_URL", "CICADA_MACHINE_ID", "CICADA_USER_ROOT", "CICADA_NODE_STATE_DIR", "CICADA_STATE_DIR", "CICADA_MCP_SESSION_STATE_FILE", "CICADA_MCP_STATE_FILE", "CICADA_SESSION_STATE_DIR", "CICADA_MCP_STATE_DIR", "CICADA_MCP_OUTBOX_STATE_FILE", "CICADA_MCP_OUTBOX_FILE", "CICADA_MCP_OUTBOX_STATE_DIR", "CICADA_MCP_OUTBOX_DIR", "CICADA_NODE_PQTLS_CONFIG", "CICADA_NETWORK_JOIN_DIR", "CICADA_NETWORK_SESSION_DIR", "XDG_STATE_HOME"} {
		t.Setenv(name, poison)
	}
	server, err := newLocalNodeMCPServer(LocalNodeSelection{UserRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	defer close(server.stop)
	pin := server.localNode.Pin
	if server.baseURL != pin.APIOrigin || server.codexContext.nodeID != pin.NodeID || server.sessionStatePath != expected.MCPSessionStateFile ||
		server.outbox.path != expected.MCPOutboxStateFile || server.hubStateDir != pin.StateDir || server.writerRoot != pin.WriterRoot || server.pqtlsSelected {
		t.Fatal("formal MCP consumer inherited a legacy override")
	}
	if socket := server.joinSocketPath(harness.SessionContext{MachineID: "provider-supplied-other-node"}); socket != pin.SocketPath {
		t.Fatal("caller coordinates replaced the selected socket")
	}
	if _, err := os.Lstat(poison); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created another deployment's state")
	}
	for _, path := range []string{expected.MCPSessionStateFile, expected.MCPOutboxStateFile} {
		if _, err := os.Lstat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("startup initialized cache/outbox", path)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("consumer startup contacted Hub or requested authority")
	}
}

func TestCodexLocalNodeOfflineAndExplicitFlags(t *testing.T) {
	root := privateLocalNodeRoot(t)
	for _, args := range [][]string{
		{"--user-root", root},
		{"--user-root", root, "--codex-context", "--api-url", "https://other.invalid"},
		{"--user-root", root, "--codex-context", "--endpoint", "other"},
		{"--user-root", root, "--codex-context", "--state-root", root},
		{"--node-id", "other"},
	} {
		if err := runMCP(args); !errors.Is(err, ErrLocalNodeConfigRequired) {
			t.Fatal("accepted conflicting formal/legacy flags", args, err)
		}
	}
	if err := runMCP([]string{"--user-root", root, "--codex-context"}); !errors.Is(err, ErrLocalNodeNotRunning) || !strings.Contains(err.Error(), "手动") || !strings.Contains(err.Error(), "manually") {
		t.Fatal("offline startup did not return bounded bilingual guidance", err)
	}
	for _, event := range []codexHookInput{
		{Event: "UserPromptSubmit", Prompt: "ordinary prompt"},
		{Event: "UserPromptSubmit", Prompt: "$cicada-network"},
		{Event: "PreToolUse", ToolName: "another_tool"},
	} {
		raw, _ := json.Marshal(event)
		var output bytes.Buffer
		if err := runCodexHook([]string{"--user-root", root}, bytes.NewReader(raw), &output); err != nil || strings.TrimSpace(output.String()) != "{}" {
			t.Fatal("unrelated input required Node discovery", err, output.String())
		}
	}
	event := codexHookInput{Event: "UserPromptSubmit", Prompt: "cicada peers", SessionID: "synthetic-native-thread", CWD: root}
	raw, _ := json.Marshal(event)
	var output bytes.Buffer
	if err := runCodexHook([]string{"--user-root", root}, bytes.NewReader(raw), &output); err != nil || !strings.Contains(output.String(), "NODE_NOT_RUNNING") || !strings.Contains(output.String(), `"decision":"block"`) {
		t.Fatal("literal offline command escaped to model or lacked guidance", err, output.String())
	}
	event.Event, event.ToolName, event.ToolInput = "PreToolUse", "mcp__plugin_cicada_cicada__cicada_whoami", map[string]any{}
	raw, _ = json.Marshal(event)
	output.Reset()
	if err := runCodexHook([]string{"--user-root", root}, bytes.NewReader(raw), &output); err != nil || !strings.Contains(output.String(), "NODE_NOT_RUNNING") || !strings.Contains(output.String(), `"permissionDecision":"deny"`) {
		t.Fatal("offline PreToolUse was allowed", err, output.String())
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("offline consumers created product state", err)
	}
}

func TestCodexLocalNodeConsumerAmbiguityAndExplicitSelection(t *testing.T) {
	root := privateLocalNodeRoot(t)
	a, b := syntheticLocalNodePin(t, root, "synthetic-a"), syntheticLocalNodePin(t, root, "synthetic-b")
	mockLocalNode(t, a, nil, false)
	mockLocalNode(t, b, nil, false)
	if _, err := newLocalNodeMCPServer(LocalNodeSelection{UserRoot: root}); !errors.Is(err, ErrLocalNodeSelectionAmbiguous) {
		t.Fatal("ambiguity selected a Node", err)
	}
	server, err := newLocalNodeMCPServer(LocalNodeSelection{UserRoot: root, HubID: b.HubID, NodeID: b.NodeID})
	if err != nil {
		t.Fatal(err)
	}
	defer close(server.stop)
	if server.localNode.Pin != b {
		t.Fatal("explicit selection changed pin")
	}
}

func TestCodexLocalNodeConsumerRestartAndBindingFence(t *testing.T) {
	bridge, client, config, requests := localNodeRealFixture(t)
	if err := startLocalNodeDiscovery(bridge, config); err != nil {
		t.Fatal(err)
	}
	server, err := newLocalNodeMCPServer(LocalNodeSelection{UserRoot: config.UserRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer close(server.stop)
	original := *server.localNode
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
	if err := revalidateCodexLocalNode(context.Background(), server.localNode); !errors.Is(err, ErrLocalNodeNotRunning) {
		t.Fatal("offline pin was replaced", err)
	}
	hub, _ := machineHubFrom(bridge.ctx)
	next, err := startMachineAgentJoinBridge(withMachineHubContext(context.Background(), hub), client.stateDir, bridge.baseURL, bridge.nodeID, bridge.nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := startLocalNodeDiscovery(next, config); err != nil {
		t.Fatal(err)
	}
	if err := revalidateCodexLocalNode(context.Background(), server.localNode); err != nil {
		t.Fatal("same binding could not recover after restart", err)
	}
	if *server.localNode != original {
		t.Fatal("revalidation rewrote connection identity")
	}
	client.mu.Lock()
	client.state.NodeKeyEpoch++
	client.mu.Unlock()
	if _, err := server.callContextualTool("cicada_whoami", map[string]any{}); !errors.Is(err, ErrLocalNodeBindingChanged) {
		t.Fatal("changed binding reached tool dispatch", err)
	}
	h := &codexFrozenHeartbeat{connection: server.localNode}
	if _, err := h.renew(context.Background()); !errors.Is(err, ErrLocalNodeBindingChanged) {
		t.Fatal("frozen heartbeat ignored pin", err)
	}
	if requests.Load() != 0 {
		t.Fatal("binding mismatch requested Hub")
	}
}

func TestCodexLocalNodeCacheRetainsLegacyAndMismatchedPins(t *testing.T) {
	root := privateLocalNodeRoot(t)
	pin := syntheticLocalNodePin(t, root, "synthetic-node")
	pin.MCPSessionStateFile = filepath.Join(root, "sessions.json")
	context := harness.SessionContext{Harness: "codex", NativeSessionID: "synthetic-thread", MachineID: pin.NodeID, Workspace: root}
	scope, _, err := mcpSessionScope(pin.APIOrigin, context)
	if err != nil {
		t.Fatal(err)
	}
	entry := mcpCachedSession{Scope: scope, APIOrigin: pin.APIOrigin, Harness: "codex", NativeSessionID: context.NativeSessionID, NodeID: pin.NodeID, Workspace: root, GroupID: "synthetic-group", EndpointID: "synthetic-endpoint", SessionToken: "SYNTHETIC_TEST_CREDENTIAL_NOT_FOR_DEPLOYMENT"}
	state := newMCPSessionStateStore(pin.MCPSessionStateFile)
	if err := state.save(entry); err != nil {
		t.Fatal(err)
	}
	file := state.scopePath(scope)
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	server := newMCPServerWithPaths(pin.APIOrigin, "", pin.MCPSessionStateFile, pin.MCPOutboxStateFile)
	server.localNode = &LocalNodeConnection{Pin: pin}
	if err := server.restoreSession(context); !errors.Is(err, ErrLocalNodeConfigRequired) {
		t.Fatal("legacy cache activated in root mode", err)
	}
	entry.ConnectionPin = &pin
	if err := state.save(entry); !errors.Is(err, ErrLocalNodeConfigRequired) {
		t.Fatal("legacy cache was silently stamped", err)
	}
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("legacy cache bytes changed", err)
	}
	if err := state.remove(scope); err != nil {
		t.Fatal(err)
	} // Test-owned explicit reset only.
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := state.save(entry); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(root); err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("pinned cache changed installation-root permissions", err)
	}
	cached, err := state.load(pin.APIOrigin, context)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCodexCachedConnection(cached, server.localNode); err != nil {
		t.Fatal("matching pin did not restore", err)
	}
	before, err = os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	other := pin
	other.Binding.NodeKeyVersion++
	entry.ConnectionPin = &other
	if err := state.save(entry); !errors.Is(err, ErrLocalNodeBindingChanged) {
		t.Fatal("new binding overwrote original scope", err)
	}
	if err := validateCodexCachedConnection(cached, &LocalNodeConnection{Pin: other}); !errors.Is(err, ErrLocalNodeBindingChanged) {
		t.Fatal("new process activated old scope", err)
	}
	entry.ConnectionPin = nil
	if err := state.save(entry); !errors.Is(err, ErrLocalNodeConfigRequired) {
		t.Fatal("legacy writer removed pin", err)
	}
	after, err = os.ReadFile(file)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("pinned cache bytes changed on refusal", err)
	}
}

func TestCodexLocalNodeHTTPAndHeartbeatIgnorePQEnvironmentAndRejectRedirect(t *testing.T) {
	root := privateLocalNodeRoot(t)
	pin := syntheticLocalNodePin(t, root, "synthetic-node")
	var calls, leaks atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaks.Add(1); w.WriteHeader(200) }))
	defer other.Close()
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer hub.Close()
	pin.APIOrigin = hub.URL
	mockLocalNode(t, pin, nil, false)
	t.Setenv("CICADA_NODE_PQTLS_CONFIG", filepath.Join(root, "other-deployment-must-not-read"))
	server, err := newLocalNodeMCPServer(LocalNodeSelection{UserRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	defer close(server.stop)
	if _, err := server.requestWithGroup(http.MethodGet, "/v2/fabric/whoami", nil, "CicadaSession SYNTHETIC_CREDENTIAL", "synthetic-group"); err == nil {
		t.Fatal("formal HTTP followed redirect")
	}
	h := &codexFrozenHeartbeat{connection: server.localNode, cache: mcpCachedSession{APIOrigin: hub.URL, SessionToken: "SYNTHETIC_CREDENTIAL", GroupID: "synthetic-group"}}
	if _, err := h.renew(context.Background()); err == nil {
		t.Fatal("formal heartbeat followed redirect")
	}
	if calls.Load() != 2 || leaks.Load() != 0 {
		t.Fatal("legacy PQ environment affected formal HTTP or credentials followed redirect", calls.Load(), leaks.Load())
	}
	if _, err := server.networkTool("cicada_network_join", map[string]any{}); !errors.Is(err, ErrLocalNodeConfigRequired) {
		t.Fatal("Network guessed an environment root", err)
	}
	if _, err := server.currentMonitorBroadcastRequest(mcpOutboxOperation{}, "synthetic-approval"); !errors.Is(err, ErrLocalNodeConfigRequired) {
		t.Fatal("Monitor guessed an environment root", err)
	}
}
