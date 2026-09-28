package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cicada-ai/cicada/internal/harness"
)

func TestNetworkOnlyMCPStateCannotBecomeGroupAuthorization(t *testing.T) {
	const nativeID = "thread-network-only-active"
	workspace := prepareMCPJoinSessionRecord(t, nativeID)
	t.Setenv("CODEX_THREAD_ID", nativeID)
	t.Setenv("CODEX_SESSION_ID", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_MACHINE_ID", "node-network-only-active")
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_NETWORK_SESSION_DIR", stateRoot)
	var networkCalls, groupCalls atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/fabric/networks/net_active/directory" &&
			request.Header.Get("Authorization") == "Cicada-Network-Session private-access-token" {
			networkCalls.Add(1)
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`[]`))
			return
		}
		groupCalls.Add(1)
		http.Error(response, "unexpected Group HTTP route", http.StatusForbidden)
	}))
	defer hub.Close()
	context := harness.SessionContext{Harness: "codex", NativeSessionID: nativeID,
		MachineID: "node-network-only-active", Workspace: workspace}
	scope, _, err := mcpSessionScope(hub.URL, context)
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := privateNetworkScopeDir(stateRoot, scope, true)
	if err != nil {
		t.Fatal(err)
	}
	statePath, err := mcpNetworkFile(stateDir, "net_active", ".session.json")
	if err != nil {
		t.Fatal(err)
	}
	origin, err := normalizeMCPAPIOrigin(hub.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := networkCLIState{Version: 1, APIOrigin: origin, NetworkID: "net_active",
		EndpointID: "ep-network-only", Harness: "codex", NativeSessionID: nativeID,
		NodeID: context.MachineID, Workspace: workspace, SessionToken: "private-access-token"}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNewPrivateNetworkFile(statePath, data); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(statePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("synthetic Network credential state is not private")
	}
	mcp := newMCPServer(hub.URL, "", "")
	defer close(mcp.stop)
	if _, err := mcp.callTool("cicada_network_directory", map[string]any{"network_id": "net_active"}); err != nil {
		t.Fatalf("Network-only directory failed: %v", err)
	}
	for _, name := range []string{"cicada_whoami", "cicada_members", "cicada_task_list"} {
		if _, err := mcp.callTool(name, map[string]any{}); err == nil ||
			!strings.Contains(err.Error(), "requires an active Cicada session") {
			t.Fatalf("Network-only state reached Group MCP tool %s: %v", name, err)
		}
	}
	if networkCalls.Load() != 1 || groupCalls.Load() != 0 {
		t.Fatalf("Network calls=%d, Group HTTP calls=%d", networkCalls.Load(), groupCalls.Load())
	}
}
