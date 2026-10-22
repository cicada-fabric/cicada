package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodetransport"
)

func privateLocalNodeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}
func localNodeRealFixture(t *testing.T) (*machineAgentJoinBridge, *machineNodeControlClient, localNodePublishConfig, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	t.Cleanup(server.Close)
	client, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, server.URL)
	token, _, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	hub, _ := machineHubFrom(ctx)
	hub.Token = token
	ctx = withMachineHubContext(context.Background(), hub)
	bridge, err := startMachineAgentJoinBridge(ctx, client.stateDir, server.URL, client.nodeID, token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridge.Close() })
	root := privateLocalNodeRoot(t)
	config := localNodePublishConfig{root, filepath.Join(root, "original-cache", "sessions.json"), filepath.Join(root, "different-outbox", "original.sqlite3")}
	return bridge, client, config, &requests
}
func TestLocalNodeDiscoveryLiveOriginalBindingRestartAndNoAuthority(t *testing.T) {
	b, client, config, requests := localNodeRealFixture(t)
	stateBefore, _ := os.ReadFile(client.statePath)
	identityPath, _ := machineNodeControlPaths(client.stateDir, client.nodeID)
	keyBefore, _ := os.ReadFile(identityPath)
	if _, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: config.UserRoot}, nil); !errors.Is(err, ErrLocalNodeNotRunning) {
		t.Fatal("low-level bridge published without opt-in", err)
	}
	if err := startLocalNodeDiscovery(b, config); err != nil {
		t.Fatal(err)
	}
	conn, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: config.UserRoot}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if conn.Pin.NodeID != client.nodeID || conn.Pin.MCPSessionStateFile != config.MCPSessionStateFile || conn.Pin.MCPOutboxStateFile != config.MCPOutboxStateFile || conn.Pin.Binding.NodeKeyVersion != 1 {
		t.Fatal("discovery changed original scope or independent paths")
	}
	if _, err := os.Stat(filepath.Dir(config.MCPSessionStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("describe created session state")
	}
	if _, err := os.Stat(filepath.Dir(config.MCPOutboxStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("describe created outbox")
	}
	after, _ := os.ReadFile(client.statePath)
	keyAfter, _ := os.ReadFile(identityPath)
	if !bytes.Equal(stateBefore, after) || !bytes.Equal(keyBefore, keyAfter) || requests.Load() != 0 {
		t.Fatal("discovery touched identity/outbox or requested Hub")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: config.UserRoot}, &conn.Pin); !errors.Is(err, ErrLocalNodeNotRunning) {
		t.Fatal("closed Node remained live", err)
	}
	hub, _ := machineHubFrom(b.ctx)
	ctx := withMachineHubContext(context.Background(), hub)
	next, err := startMachineAgentJoinBridge(ctx, client.stateDir, b.baseURL, b.nodeID, b.nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := startLocalNodeDiscovery(next, config); err != nil {
		t.Fatal(err)
	}
	resumed, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: config.UserRoot}, &conn.Pin)
	if err != nil || resumed.Pin != conn.Pin || resumed.InstanceID == conn.InstanceID {
		t.Fatal("restart replaced stable scope or reused instance", err)
	}
	client.mu.Lock()
	client.state.NodeKeyEpoch++
	client.mu.Unlock()
	if _, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: config.UserRoot}, &conn.Pin); !errors.Is(err, ErrLocalNodeBindingChanged) {
		t.Fatal("changed epoch reused original pin", err)
	}
}

func syntheticLocalNodePin(t *testing.T, root, node string) LocalNodeConnectionPin {
	t.Helper()
	state := filepath.Join(root, "synthetic-state-"+node)
	if err := os.MkdirAll(machineNodeStateDir(state, node), 0700); err != nil {
		t.Fatal(err)
	}
	socket, err := machineAgentJoinSocketPathChecked(state, node)
	if err != nil {
		t.Fatal(err)
	}
	return LocalNodeConnectionPin{UserRoot: root, HubID: "synthetic-hub-" + node, APIOrigin: "https://synthetic.invalid", NodeID: node, SocketPath: socket, StateDir: state, WriterRoot: state, MCPSessionStateFile: filepath.Join(root, "cache", "sessions.json"), MCPOutboxStateFile: filepath.Join(root, "separate-outbox", "outbox.sqlite3"), Binding: LocalNodeBinding{BindingID: "synthetic-binding", BindingVersion: 1, NodeKeyEpoch: 1, NodeKeyVersion: 1, HubKeyVersion: 1, NodeKeyID: "synthetic-node-key", NodeKeyFingerprint: strings.Repeat("a", 64), HubKeyID: "synthetic-hub-key", HubFingerprint: strings.Repeat("b", 64)}}
}
func mockLocalNode(t *testing.T, pin LocalNodeConnectionPin, alter func(*localNodeDescribeResponse), hang bool) *atomic.Int32 {
	t.Helper()
	if err := prepareLocalJoinSocket(pin.SocketPath); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", pin.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pin.SocketPath, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(pin.UserRoot, "run", "nodes")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	locator := localNodeLocator{localNodeLocatorFormat, strings.Repeat("a", 32), pin.SocketPath}
	data, _ := json.Marshal(locator)
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(dir, localNodeLocatorName(pin.StateDir, pin.NodeID)), data, 0600); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	var wg sync.WaitGroup
	var calls atomic.Int32
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				calls.Add(1)
				var q localNodeDescribeRequest
				if json.NewDecoder(c).Decode(&q) != nil {
					return
				}
				if hang {
					<-stopped
					return
				}
				response := localNodeDescribeResponse{Version: 1, Description: &localNodeDescription{q.Nonce, locator.InstanceID, localNodeDigest(data), pin}}
				if alter != nil {
					alter(&response)
				}
				_ = json.NewEncoder(c).Encode(response)
			}()
		}
	}()
	t.Cleanup(func() { close(stopped); _ = listener.Close(); wg.Wait() })
	return &calls
}
func TestLocalNodeDiscoveryAmbiguityBadCandidatesAndCommonDeadline(t *testing.T) {
	t.Run("ambiguity", func(t *testing.T) {
		root := privateLocalNodeRoot(t)
		a := syntheticLocalNodePin(t, root, "a")
		b := syntheticLocalNodePin(t, root, "b")
		mockLocalNode(t, a, nil, false)
		mockLocalNode(t, b, nil, false)
		if _, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: root}, nil); !errors.Is(err, ErrLocalNodeSelectionAmbiguous) {
			t.Fatal(err)
		}
		found, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: root, HubID: a.HubID, NodeID: a.NodeID}, nil)
		if err != nil || found.Pin != a {
			t.Fatal("explicit selection changed original", err)
		}
	})
	t.Run("invalid_cannot_choose_good", func(t *testing.T) {
		root := privateLocalNodeRoot(t)
		a := syntheticLocalNodePin(t, root, "a")
		mockLocalNode(t, a, nil, false)
		if err := os.WriteFile(filepath.Join(root, "run", "nodes", strings.Repeat("f", 64)+".json"), []byte("synthetic malformed"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: root}, nil); !errors.Is(err, ErrLocalNodeDiscoveryInvalid) {
			t.Fatal("bad candidate silently skipped", err)
		}
	})
	for _, parentBudget := range []time.Duration{0, 100 * time.Millisecond} {
		t.Run(parentBudget.String(), func(t *testing.T) {
			root := privateLocalNodeRoot(t)
			mockLocalNode(t, syntheticLocalNodePin(t, root, "a"), nil, true)
			mockLocalNode(t, syntheticLocalNodePin(t, root, "b"), nil, true)
			ctx := context.Background()
			cancel := func() {}
			if parentBudget != 0 {
				ctx, cancel = context.WithTimeout(ctx, parentBudget)
			}
			defer cancel()
			start := time.Now()
			if _, err := ResolveLocalNodeConnection(ctx, LocalNodeSelection{UserRoot: root}, nil); !errors.Is(err, ErrLocalNodeDiscoveryUnavailable) {
				t.Fatal(err)
			}
			limit := 3500 * time.Millisecond
			if parentBudget != 0 {
				limit = 700 * time.Millisecond
			}
			if time.Since(start) > limit {
				t.Fatal("candidate probes multiplied the shared timeout")
			}
		})
	}
}
func TestLocalNodeDiscoveryStrictReplyAndFileBounds(t *testing.T) {
	for _, kind := range []string{"nonce", "instance", "digest", "root", "socket", "not_ready", "key_version"} {
		t.Run(kind, func(t *testing.T) {
			root := privateLocalNodeRoot(t)
			pin := syntheticLocalNodePin(t, root, "a")
			mockLocalNode(t, pin, func(r *localNodeDescribeResponse) {
				switch kind {
				case "nonce":
					r.Description.Nonce = strings.Repeat("b", 64)
				case "instance":
					r.Description.InstanceID = strings.Repeat("b", 32)
				case "digest":
					r.Description.LocatorDigest = strings.Repeat("b", 64)
				case "root":
					r.Description.Connection.UserRoot = filepath.Join(root, "wrong")
				case "socket":
					r.Description.Connection.SocketPath = filepath.Join(root, "wrong.sock")
				case "not_ready":
					r.Description = nil
					r.Error = ErrLocalNodeNotReady.Error()
				case "key_version":
					r.Description.Connection.Binding.NodeKeyVersion++
				}
			}, false)
			_, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: root}, &pin)
			expected := ErrLocalNodeDiscoveryInvalid
			if kind == "not_ready" {
				expected = ErrLocalNodeNotReady
			}
			if kind == "key_version" {
				expected = ErrLocalNodeBindingChanged
			}
			if !errors.Is(err, expected) {
				t.Fatal("invalid live tuple accepted", err)
			}
		})
	}
	for _, kind := range []string{"bad_permission", "symlink", "unknown", "duplicate", "trailing", "oversize", "directory_limit"} {
		t.Run(kind, func(t *testing.T) {
			root := privateLocalNodeRoot(t)
			pin := syntheticLocalNodePin(t, root, "a")
			mockLocalNode(t, pin, nil, false)
			path := filepath.Join(root, "run", "nodes", localNodeLocatorName(pin.StateDir, pin.NodeID))
			data, _ := os.ReadFile(path)
			switch kind {
			case "bad_permission":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := path + ".held"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				data = bytes.Replace(data, []byte(`{"format"`), []byte(`{"unknown":true,"format"`), 1)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				data = bytes.Replace(data, []byte(`{"format"`), []byte(`{"format":"duplicate","format"`), 1)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "trailing":
				if err := os.WriteFile(path, append(data, []byte(`{}`)...), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(path, bytes.Repeat([]byte("x"), localNodeMaxLocatorBytes+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory_limit":
				for i := 0; i < localNodeMaxLocators; i++ {
					if err := os.WriteFile(filepath.Join(root, "run", "nodes", localNodeLocatorName(root, string(rune('a'+i)))), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			_, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: root}, nil)
			expected := ErrLocalNodeDiscoveryInvalid
			if kind == "oversize" || kind == "directory_limit" {
				expected = ErrLocalNodeDiscoveryLimit
			}
			if !errors.Is(err, expected) {
				t.Fatal(kind, err)
			}
		})
	}
}
func TestLocalNodeDiscoveryStopDoesNotRemoveReplacement(t *testing.T) {
	b, _, config, _ := localNodeRealFixture(t)
	if err := startLocalNodeDiscovery(b, config); err != nil {
		t.Fatal(err)
	}
	p := b.discovery.Load()
	path := filepath.Join(config.UserRoot, "run", "nodes", p.name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := bytes.ReplaceAll(data, []byte(p.instance), []byte(strings.Repeat("b", 32)))
	tmp := filepath.Join(config.UserRoot, "run", "replacement")
	if err := os.WriteFile(tmp, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, replacement) {
		t.Fatal("old close removed replacement locator", err)
	}
}
func TestLocalNodeDiscoveryExplicitConfigRejectsBeforeStateCreation(t *testing.T) {
	root := privateLocalNodeRoot(t)
	state := filepath.Join(root, "must-not-exist")
	for _, args := range [][]string{
		{"--id", "synthetic-node", "--state-dir", state, "--user-root", root},
		{"--id", "synthetic-node", "--state-dir", state, "--mcp-session-state-file", filepath.Join(root, "sessions.json")},
		{"--hubs-file", filepath.Join(root, "missing-hubs.json"), "--state-root", state, "--relay-only", "--user-root", root, "--mcp-session-state-file", filepath.Join(root, "sessions.json"), "--mcp-outbox-state-file", filepath.Join(root, "outbox.sqlite3")},
	} {
		if err := runMachineAgent(args); !errors.Is(err, ErrLocalNodeConfigRequired) {
			t.Fatal("invalid config reached Node initialization", err)
		}
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bad discovery config initialized Node state")
	}
	if _, err := os.Stat(filepath.Join(root, "run")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bad discovery config published locator")
	}
}

func TestCodexOperatorConnectionPinRetainsOriginalAcrossRestartAndRefusesRetarget(t *testing.T) {
	root := privateLocalNodeRoot(t)
	pin := syntheticLocalNodePin(t, root, "a")
	connection := LocalNodeConnection{pin, strings.Repeat("a", 32), strings.Repeat("a", 64)}
	path := filepath.Join(filepath.Dir(pin.MCPSessionStateFile), "scopes", strings.Repeat("a", 64), "operator-intent.json")
	client, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	q := syntheticCodexOperatorTemplate()
	q.APIOrigin = pin.APIOrigin
	calls := 0
	client.exchange = func(_ string, original localEndpointRequest) (*localEndpointResult, error) {
		calls++
		data, _ := os.ReadFile(path)
		var disk codexOperatorIntentDisk
		if json.Unmarshal(data, &disk) != nil || disk.Pending == nil || disk.Pending.ConnectionPin == nil || *disk.Pending.ConnectionPin != pin {
			t.Fatal("IPC preceded original connection pin persistence")
		}
		return nil, errors.New("synthetic IPC response lost")
	}
	if _, err := client.callForConnection(q, connection); err == nil || calls != 1 {
		t.Fatal("unknown response settled")
	}
	before, _ := os.ReadFile(path)
	for _, change := range []func(*LocalNodeConnectionPin){
		func(p *LocalNodeConnectionPin) { p.Binding.NodeKeyEpoch++ }, func(p *LocalNodeConnectionPin) { p.Binding.NodeKeyVersion++ }, func(p *LocalNodeConnectionPin) { p.Binding.HubKeyVersion++ }, func(p *LocalNodeConnectionPin) { p.Binding.BindingVersion++ }, func(p *LocalNodeConnectionPin) { p.Binding.BindingID += "-changed" }, func(p *LocalNodeConnectionPin) { p.Binding.NodeKeyFingerprint = strings.Repeat("c", 64) }, func(p *LocalNodeConnectionPin) { p.Binding.HubFingerprint = strings.Repeat("c", 64) }, func(p *LocalNodeConnectionPin) { p.APIOrigin = "https://changed.invalid" }, func(p *LocalNodeConnectionPin) { p.HubID += "-changed" }, func(p *LocalNodeConnectionPin) { p.WriterRoot = filepath.Join(root, "other-writer") }, func(p *LocalNodeConnectionPin) {
			p.StateDir = filepath.Join(root, "other-state")
			p.SocketPath, _ = machineAgentJoinSocketPathChecked(p.StateDir, p.NodeID)
		}, func(p *LocalNodeConnectionPin) { p.MCPOutboxStateFile = filepath.Join(root, "other-outbox") }, func(p *LocalNodeConnectionPin) {
			p.MCPSessionStateFile = filepath.Join(root, "other-cache", "sessions.json")
		},
	} {
		changed := connection
		change(&changed.Pin)
		if _, err := client.callForConnection(q, changed); err == nil {
			t.Fatal("pending retargeted")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) || calls != 1 {
			t.Fatal("retarget changed pending or issued IPC")
		}
	}
	restarted, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	connection.InstanceID = strings.Repeat("b", 32)
	connection.LocatorDigest = strings.Repeat("b", 64)
	restarted.exchange = func(_ string, original localEndpointRequest) (*localEndpointResult, error) {
		r := syntheticCodexOperatorResult(original, pin.NodeID)
		r.HubID = pin.HubID
		return r, nil
	}
	result, err := restarted.callForConnection(q, connection)
	if err != nil || result == nil {
		t.Fatal("same binding restart failed exact recovery", err)
	}
	if err := restarted.ack(result.RequestID, result.IntentDigest); err != nil {
		t.Fatal(err)
	}
	// Legacy material remains readable for its original explicit recovery, but
	// root mode cannot silently attest it under a newly discovered connection.
	old, err := restarted.prepare(q, pin.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	before, _ = os.ReadFile(path)
	if _, err := restarted.prepareForConnection(q, connection); !errors.Is(err, ErrLocalNodeConfigRequired) {
		t.Fatal("old pending automatically acquired current pin", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("legacy pending was rewritten")
	}
	if retry, err := restarted.prepare(q, pin.NodeID); err != nil || retry != old {
		t.Fatal("original explicit recovery lost", err)
	}
	if err := restarted.ack(old.RequestID, codexOperatorDigest(old, false)); err == nil {
		t.Fatal("unknown legacy pending became acknowledgeable")
	}
}

func TestLocalNodeDiscoveryStrictTransportRequiresOriginalExplicitFlow(t *testing.T) {
	b, _, config, requests := localNodeRealFixture(t)
	// A selected strict runtime is sufficient to reject discovery even though
	// this synthetic context has an HTTP loopback origin. No TLS request runs.
	hub, _ := machineHubFrom(b.ctx)
	hub.TLSRuntime = &nodetransport.Runtime{}
	child := withMachineHubContext(context.Background(), hub)
	// Stop/restart only this disposable bridge under the same original context.
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	strict, err := startMachineAgentJoinBridge(child, b.stateDir, b.baseURL, b.nodeID, b.nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer strict.Close()
	if err := startLocalNodeDiscovery(strict, config); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: config.UserRoot}, nil); !errors.Is(err, ErrLocalNodeConfigRequired) {
		t.Fatal("strict Node silently treated as standard HTTPS", err)
	}
	// Describe refusal must leave the Node's independent bridge running.
	if strict.ctx.Err() != nil || requests.Load() != 0 {
		t.Fatal("unsupported discovery stopped Node or requested Hub")
	}
}

func TestLocalNodeDiscoveryPreservesExistingProtected0755Root(t *testing.T) {
	b, _, config, requests := localNodeRealFixture(t)
	if err := os.Chmod(config.UserRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := startLocalNodeDiscovery(b, config); err != nil {
		t.Fatal("existing protected root rejected", err)
	}
	if _, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: config.UserRoot}, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(config.UserRoot)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("existing root permissions repaired", err)
	}
	for _, dir := range []string{filepath.Join(config.UserRoot, "run"), filepath.Join(config.UserRoot, "run", "nodes")} {
		info, err := os.Stat(dir)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("discovery runtime directory not private", err)
		}
	}
	for _, mode := range []os.FileMode{0775, 0777} {
		if err := os.Chmod(config.UserRoot, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: config.UserRoot}, nil); !errors.Is(err, ErrLocalNodeDiscoveryInvalid) {
			t.Fatal("writable root accepted", err)
		}
		info, err := os.Stat(config.UserRoot)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("reader changed unsafe permissions", err)
		}
	}
	if err := os.Chmod(config.UserRoot, 0755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(privateLocalNodeRoot(t), "symlink-root")
	if err := os.Symlink(config.UserRoot, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: alias}, nil); !errors.Is(err, ErrLocalNodeDiscoveryInvalid) {
		t.Fatal("symlink root accepted", err)
	}
	if requests.Load() != 0 {
		t.Fatal("root permission check requested Hub")
	}
}

func TestLocalNodeDiscoveryPublisherRetainsUnknownLocatorAndChecksOwnDigest(t *testing.T) {
	b, _, config, requests := localNodeRealFixture(t)
	dir := filepath.Join(config.UserRoot, "run", "nodes")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, localNodeLocatorName(b.stateDir, b.nodeID))
	original := []byte("synthetic unknown original locator\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := startLocalNodeDiscovery(b, config); !errors.Is(err, ErrLocalNodeDiscoveryInvalid) {
		t.Fatal("unknown locator overwritten", err)
	}
	retained, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(retained, original) || b.discovery.Load() != nil {
		t.Fatal("unknown locator not retained", err)
	}
	// This file belongs only to this negative fixture; removing it explicitly
	// does not authorize production readers to delete unknown/stale records.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := startLocalNodeDiscovery(b, config); err != nil {
		t.Fatal(err)
	}
	p := b.discovery.Load()
	q := localNodeDescribeRequest{1, "local_node_describe", strings.Repeat("a", 64), p.instance, strings.Repeat("f", 64)}
	if _, err := b.localNodeDescribe(q); !errors.Is(err, ErrLocalNodeDiscoveryInvalid) {
		t.Fatal("Node blindly echoed supplied locator digest", err)
	}
	q.LocatorDigest = p.digest
	q.InstanceID = strings.Repeat("f", 32)
	if _, err := b.localNodeDescribe(q); !errors.Is(err, ErrLocalNodeDiscoveryInvalid) {
		t.Fatal("Node accepted another published instance", err)
	}
	if requests.Load() != 0 {
		t.Fatal("bad describe requested Hub")
	}
}
