package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func syntheticApprovedAgentHubClient(t *testing.T, origin string) *machineNodeControlClient {
	t.Helper()
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hub, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return &machineNodeControlClient{identity: node, base: origin, nodeID: "node-pin",
		state: machineNodeControlState{Version: machineNodeControlStateVersion,
			NodeID: "node-pin", HubOrigin: origin, HubID: "hub-pin",
			HubKeyID: hub.Public().ID, HubPublicIdentity: hub.Public(), HubKeyVersion: 1,
			HubFingerprint: nodewire.IdentityFingerprint(hub.Public()), NodeKeyVersion: 1,
			NodeKeyID: node.Public().ID, NodeKeyFingerprint: nodewire.IdentityFingerprint(node.Public()),
			BindingID: "approved-binding", BindingVersion: 1, NodeKeyEpoch: 1}}
}

func syntheticUnpinnedAgentContext(origin string) context.Context {
	return withMachineHubContext(context.Background(), machineHubContext{
		Origin: origin, NodeID: "node-pin", WriterScope: "synthetic-account",
		approvedHubID: &atomic.Pointer[string]{}})
}

func TestMachineAgentHubPinPreservesOriginalSIDLocalJoin(t *testing.T) {
	t.Setenv("CICADA_HUB_ID", "")
	const sid = "thread-original-hub-pin"
	workspace, home := t.TempDir(), t.TempDir()
	t.Setenv("CODEX_HOME", home)
	writeCodexSessionRecord(t, home, sid, workspace)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/fabric/node/join" ||
			r.Header.Get("Authorization") != "CicadaNode "+nodeToken {
			t.Error("Join escaped the owned Node-authenticated route")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var input struct {
			NativeSessionID string `json:"native_session_id"`
			Workspace       string `json:"workspace"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.NativeSessionID != sid || input.Workspace != workspace {
			t.Error("Join changed the original SID or workspace")
		}
		_ = json.NewEncoder(w).Encode(fabricpkg.JoinResult{
			Endpoint:     store.Endpoint{ID: "endpoint-pin", Harness: "codex", NativeSessionID: sid, MachineID: "node-pin"},
			SessionToken: "cicada_session_SYNTHETIC", BindingID: "session-binding-pin", BindingEpoch: 1,
			NativeContextScope: store.NativeContextScopeMetadata{HubID: "hub-pin", GroupID: "group-pin",
				GroupContextPolicy: nodeinbox.NativeContextPolicyGroupScoped}})
	}))
	defer server.Close()
	stateDir := shortLocalJoinStateDir(t)
	registry, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(stateDir, "history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	ctx := syntheticUnpinnedAgentContext(server.URL)
	hub, _ := machineHubFrom(ctx)
	hub.StateDir, hub.WriterRoot, hub.Token = stateDir, stateDir, nodeToken
	hub.NativeContexts, hub.RequireNativeContext = registry, true
	ctx = withMachineHubContext(ctx, hub)
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-pin", nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	// The bridge already captured the empty context; only trusted approval may pin it.
	if err := pinMachineAgentApprovedHubID(ctx, syntheticApprovedAgentHubClient(t, server.URL)); err != nil {
		t.Fatal(err)
	}
	joined, scope, err := requestMachineAgentJoinWithScope(bridge.path, localJoinRequest{
		Version: localJoinProtocolVersion, GroupID: "group-pin", Harness: "codex", NativeSessionID: sid, Workspace: workspace})
	if err != nil || scope == nil || !scope.Accepted || joined.Endpoint.NativeSessionID != sid {
		t.Fatalf("approved original-SID local scope failed: joined=%v scope=%v err=%v", joined, scope, err)
	}
	if os.Getenv("CICADA_HUB_ID") != "" {
		t.Fatal("Agent changed the global environment")
	}
}

func TestMachineAgentHubPinRejectsUnapprovedOrForeignIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*machineNodeControlClient)
	}{
		{"pending", func(c *machineNodeControlClient) { c.state.BindingID = "" }},
		{"missing Hub", func(c *machineNodeControlClient) { c.state.HubID = "" }},
		{"foreign Node", func(c *machineNodeControlClient) { c.state.NodeID = "foreign" }},
		{"foreign origin", func(c *machineNodeControlClient) { c.state.HubOrigin = "https://foreign.invalid" }},
		{"missing epoch", func(c *machineNodeControlClient) { c.state.NodeKeyEpoch = 0 }},
		{"stale Node key", func(c *machineNodeControlClient) { c.state.NodeKeyFingerprint = "stale" }},
		{"foreign Hub key", func(c *machineNodeControlClient) { c.state.HubKeyID = "foreign" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := syntheticUnpinnedAgentContext("https://synthetic.invalid")
			client := syntheticApprovedAgentHubClient(t, "https://synthetic.invalid")
			test.mutate(client)
			if pinMachineAgentApprovedHubID(ctx, client) == nil || machinePinnedHubID(ctx) != "" {
				t.Fatal("unapproved/foreign identity published a Hub pin")
			}
		})
	}
}

func TestMachineAgentHubPinStartupDoesNotPromotePendingOrCreateKeys(t *testing.T) {
	root := t.TempDir()
	ctx := syntheticUnpinnedAgentContext("https://synthetic.invalid")
	if err := pinExistingMachineAgentHubID(ctx, root, "https://synthetic.invalid", "node-pin", false); err != nil {
		t.Fatal(err)
	}
	if files, _ := os.ReadDir(root); len(files) != 0 || machinePinnedHubID(ctx) != "" {
		t.Fatal("unenrolled startup created state or trusted a Hub")
	}
	if err := pinExistingMachineAgentHubID(ctx, root, "https://synthetic.invalid", "node-pin", true); err == nil {
		t.Fatal("missing approval was accepted at the readiness hook")
	}
	client, err := openMachineNodeControlClient(root, "https://synthetic.invalid", "node-pin")
	if err != nil {
		t.Fatal(err)
	}
	if err := pinExistingMachineAgentHubID(ctx, root, "https://synthetic.invalid", "node-pin", false); err != nil || machinePinnedHubID(ctx) != "" {
		t.Fatalf("pending startup promoted its public candidate: %v", err)
	}
	if err := pinExistingMachineAgentHubID(ctx, root, "https://synthetic.invalid", "node-pin", true); err == nil {
		t.Fatal("pending approval was accepted at the readiness hook")
	}
	approved := syntheticApprovedAgentHubClient(t, "https://synthetic.invalid")
	client.mu.Lock()
	client.identity, client.state = approved.identity, approved.state
	client.mu.Unlock()
	if err := pinExistingMachineAgentHubID(ctx, root, "https://synthetic.invalid", "node-pin", false); err != nil || machinePinnedHubID(ctx) != "hub-pin" {
		t.Fatalf("approved startup did not pin: %v", err)
	}
	freshRoot := t.TempDir()
	identityPath, statePath := machineNodeControlPaths(freshRoot, "node-pin")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	stateJSON, err := json.Marshal(approved.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, stateJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	freshCtx := syntheticUnpinnedAgentContext("https://synthetic.invalid")
	if err := pinExistingMachineAgentHubID(freshCtx, freshRoot, "https://synthetic.invalid", "node-pin", false); err == nil {
		t.Fatal("state without its key was accepted")
	}
	if _, err := os.Lstat(identityPath); !os.IsNotExist(err) || machinePinnedHubID(freshCtx) != "" {
		t.Fatal("pin-only startup created a replacement key")
	}
	key, err := approved.identity.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	// This path has never entered the global client cache: exercise the real disk loader.
	if err := pinExistingMachineAgentHubID(freshCtx, freshRoot, "https://synthetic.invalid", "node-pin", false); err != nil || machinePinnedHubID(freshCtx) != "hub-pin" {
		t.Fatalf("fresh approved disk state did not pin: %v", err)
	}
}

func TestMachineAgentHubPinWriteOnceConcurrentCapturedContexts(t *testing.T) {
	ctx := syntheticUnpinnedAgentContext("https://synthetic.invalid")
	client := syntheticApprovedAgentHubClient(t, "https://synthetic.invalid")
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := pinMachineAgentApprovedHubID(ctx, client); err != nil {
				t.Error(err)
			}
			for n := 0; n < 100; n++ {
				if machinePinnedHubID(ctx) != "hub-pin" {
					t.Error("captured context lost its published pin")
				}
			}
		}()
	}
	workers.Wait()
	foreign := syntheticApprovedAgentHubClient(t, "https://synthetic.invalid")
	foreign.state.HubID = "replacement"
	if pinMachineAgentApprovedHubID(ctx, foreign) == nil || machinePinnedHubID(ctx) != "hub-pin" {
		t.Fatal("later approval replaced the first pin")
	}
	stored := ctx.Value(machineHubContextKey{}).(machineHubContext)
	if stored.HubID != "" {
		t.Fatal("pin publication mutated the original context value")
	}
}

func TestMachineAgentHubPinRejectsUnsafeExistingKey(t *testing.T) {
	for _, kind := range []string{"symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			keyPath, statePath := machineNodeControlPaths(root, "node-pin")
			if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(statePath, []byte(`{"version":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				target := filepath.Join(root, "public-synthetic-target")
				if err := os.WriteFile(target, []byte("PUBLIC SYNTHETIC FIXTURE"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, keyPath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(keyPath, 0o700); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			ctx := syntheticUnpinnedAgentContext("https://synthetic.invalid")
			if pinExistingMachineAgentHubID(ctx, root, "https://synthetic.invalid", "node-pin", false) == nil || machinePinnedHubID(ctx) != "" {
				t.Fatal("unsafe key path published authority")
			}
			after, err := os.Lstat(keyPath)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("pin-only check replaced the unsafe key object")
			}
		})
	}
}

func TestMachineAgentHubPinLeavesExplicitAndMultiHubContextsUnchanged(t *testing.T) {
	for _, multi := range []bool{false, true} {
		ctx := withMachineHubContext(context.Background(), machineHubContext{
			HubID: "configured", Origin: "https://synthetic.invalid", NodeID: "node-pin", MultiHub: multi})
		client := syntheticApprovedAgentHubClient(t, "https://synthetic.invalid")
		if err := pinMachineAgentApprovedHubID(ctx, client); err != nil || machinePinnedHubID(ctx) != "configured" {
			t.Fatalf("explicit Hub lifecycle changed: %v", err)
		}
		if _, err := machineNodeExecutionContext(ctx, client); err == nil {
			t.Fatal("existing explicit foreign-Hub validation was weakened")
		}
	}
}
