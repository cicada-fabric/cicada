//go:build linux && cicada_scoped_app_integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubnodes"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// This layer uses the actual manager, production workers, current scoped NPT,
// real App Controller and production Store/Guard over pinned TLS/TCP. It reuses
// the existing native-TLS and offline queue-process fixtures. It does not run
// installed Codex, a model, a resident service, or a public Hub. The direct
// serveNodeHubManager entry does not qualify systemd or Windows.
type nodeHubLifecycleHub struct {
	t             *testing.T
	native        nativeNodeFixture
	db            *store.Store
	app           appcore.Controller
	server        *httptest.Server
	dial          string
	mu            sync.Mutex
	paths         map[string]int
	control       int
	vaultRoot     string
	dropPath      string
	dropOperation string
	droppedDigest [32]byte
	droppedStatus int
}

type nodeHubAcceptancePacer struct {
	mu     sync.Mutex
	next   time.Time
	client *http.Client
}

func (p *nodeHubAcceptancePacer) Do(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost {
		// Preserve the production four-per-second App admission limit. These
		// are paced first sends, never retries or replacements of originals.
		p.mu.Lock()
		delay := time.Until(p.next)
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-r.Context().Done():
				timer.Stop()
				p.mu.Unlock()
				return nil, r.Context().Err()
			}
		}
		p.next = time.Now().Add(300 * time.Millisecond)
		p.mu.Unlock()
	}
	return p.client.Do(r)
}

func (p *nodeHubAcceptancePacer) CloseIdleConnections() { p.client.CloseIdleConnections() }

func newNodeHubLifecycleHub(t *testing.T) *nodeHubLifecycleHub {
	t.Helper()
	f := &nodeHubLifecycleHub{t: t, native: newNativeNodeFixture(t), paths: map[string]int{}}
	var err error
	state := filepath.Dir(f.native.file)
	f.db, err = store.New(filepath.Join(state, "cicada.sqlite3"))
	if err != nil {
		t.Fatal("synthetic scoped database", err)
	}
	t.Cleanup(func() { _ = f.db.Close() })
	ids, err := hubidentity.LoadOrCreate(state, "")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := hubowner.NewService(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := hubauth.NewServiceWithScopedNodeAuthority(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := hubnodes.NewService(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.NewHubNodesHandler(owner, auth, nodes)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths[r.Method+" "+r.URL.Path]++
		if r.URL.Path == "/v1/machines" || strings.HasPrefix(r.URL.Path, "/v1/actions") {
			f.control++
		}
		drop := r.Method == http.MethodPost && r.URL.Path == f.dropPath
		dropOperation := f.dropOperation
		if drop && dropOperation == "" {
			f.dropPath = ""
		}
		f.mu.Unlock()
		if drop {
			raw, readErr := io.ReadAll(io.LimitReader(r.Body, wire.MaxPacketBytes+1))
			r.Body.Close()
			if readErr != nil || len(raw) > wire.MaxPacketBytes {
				t.Error("synthetic lost-response packet bounds")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			if dropOperation != "" {
				packet, decodeErr := nodewire.DecodePacket(raw)
				if decodeErr != nil || packet.Route.Operation != dropOperation {
					handler.ServeHTTP(w, r)
					clear(raw)
					return
				}
				f.mu.Lock()
				f.dropPath, f.dropOperation = "", ""
				f.mu.Unlock()
			}
			capture := httptest.NewRecorder()
			handler.ServeHTTP(capture, r)
			f.mu.Lock()
			f.droppedDigest, f.droppedStatus = sha256.Sum256(raw), capture.Code
			f.mu.Unlock()
			clear(raw)
			// The actual Guard/Store committed before this unsigned transport
			// refusal. It cannot authenticate an application-level rejection.
			w.WriteHeader(http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	f.server.TLS = f.native.profile.TLSConfig()
	f.server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return f.native.profile.TLSConfig(), nil
	}
	f.server.StartTLS()
	f.dial = f.server.Listener.Addr().String()
	t.Cleanup(f.server.Close)
	vaultRoot := filepath.Join(privateLocalNodeRoot(t), "SYNTHETIC-app-vaults")
	f.vaultRoot = vaultRoot
	f.app, err = appcore.NewController(appcore.Config{
		UserRoot: privateLocalNodeRoot(t),
		OpenVault: func(_ context.Context, scope appvault.Scope, create bool) (*appvault.Vault, error) {
			raw, e := json.Marshal(scope)
			if e != nil {
				return nil, e
			}
			sum := sha256.Sum256(raw)
			path := filepath.Join(vaultRoot, hex.EncodeToString(sum[:])+".vault")
			if e = os.MkdirAll(vaultRoot, 0700); e != nil {
				return nil, e
			}
			protector, e := appvault.NewPasswordProtector([]byte("SYNTHETIC lifecycle acceptance vault only 42!"))
			if e != nil {
				return nil, e
			}
			if _, e = os.Lstat(path); errors.Is(e, os.ErrNotExist) && create {
				return appvault.Create(path, scope, protector)
			}
			return appvault.Open(path, scope, protector)
		},
		DirectHTTPFactory: func(d hubtransport.Descriptor, dial string, timeout time.Duration) (appcore.HTTPDoer, error) {
			c, e := hubtransport.NewHTTPClient(d, dial, timeout)
			if e != nil {
				return nil, e
			}
			return &nodeHubAcceptancePacer{client: c}, nil
		},
	})
	if err != nil {
		t.Fatal("real App Controller", err)
	}
	t.Cleanup(func() { _ = f.app.Close() })
	activation, err := auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	code, err := wire.EncodeActivationCode(*activation)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := hubtransport.EncodeBootstrap(f.native.d, code)
	if err != nil {
		t.Fatal(err)
	}
	f.dispatch(appcore.Action{Kind: appcore.ActionConnect, HubAddress: f.dial, BootstrapCode: bootstrap})
	f.dispatch(appcore.Action{Kind: appcore.ActionGenerateOwner})
	f.dispatch(appcore.Action{Kind: appcore.ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-node-hub-acceptance", Password: "SYNTHETIC lifecycle account password 42!"})
	f.dispatch(appcore.Action{Kind: appcore.ActionLogin, Username: "synthetic-node-hub-acceptance", Password: "SYNTHETIC lifecycle account password 42!"})
	return f
}

func (f *nodeHubLifecycleHub) dispatch(a appcore.Action) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := f.app.Dispatch(ctx, a); err != nil {
		// Actions redact their own secrets, but even failures record only the
		// closed action kind and sanitized App code, never the input/payload.
		snapshot := f.app.Snapshot()
		selected := snapshot.ThreadGroups.Selected
		classState := ""
		classCurrent, classCanChange, hasGesture := false, false, false
		if selected != nil && selected.Classification != nil {
			classState = selected.Classification.State
			classCurrent = selected.Classification.Current
			classCanChange = selected.Classification.CanChange
			hasGesture = selected.Classification.GestureID != ""
		}
		f.t.Fatalf("actual App action %s failed; code=%s coordination_code=%s coordination_pending=%t groups_current=%t class_state=%s class_current=%t class_can_change=%t class_gesture=%t", a.Kind, snapshot.ErrorCode, snapshot.Coordination.ErrorCode, snapshot.Coordination.Pending, snapshot.ThreadGroups.Current, classState, classCurrent, classCanChange, hasGesture)
	}
}

type nodeHubLifecycleAcceptance struct {
	t          *testing.T
	root       string
	hubs       [2]*nodeHubLifecycleHub
	ctx        context.Context
	cancel     context.CancelFunc
	managerEnd chan error
	queueRoot  string
	queueMu    sync.Mutex
	queueExit  int
}

func newNodeHubLifecycleAcceptance(t *testing.T) *nodeHubLifecycleAcceptance {
	return newNodeHubLifecycleAcceptanceMode(t, true)
}

func newNodeHubLifecycleAcceptanceMode(t *testing.T, managed bool) *nodeHubLifecycleAcceptance {
	t.Helper()
	f := &nodeHubLifecycleAcceptance{t: t, root: privateLocalNodeRoot(t), queueRoot: privateLocalNodeRoot(t)}
	for _, key := range []string{"CICADA_CONTROL_URL", "CICADA_NODE_PQTLS_CONFIG", "CICADA_API_URL", "CICADA_HUB_ID", "CICADA_MACHINE_ID", "CICADA_NODE_STATE_DIR", "CICADA_NATIVE_SESSION_ID", "CODEX_SESSION_ID", "CODEX_THREAD_ID"} {
		t.Setenv(key, "")
	}
	// A lost test dependency must fail closed instead of invoking installed
	// Codex, or recursively running this whole Go test binary as a CLI.
	t.Setenv("CICADA_CODEX_BIN", "/usr/bin/false")
	t.Setenv("CODEX_HOME", privateLocalNodeRoot(t))
	f.hubs = [2]*nodeHubLifecycleHub{newNodeHubLifecycleHub(t), newNodeHubLifecycleHub(t)}
	if f.hubs[0].native.d.Claims.Hub.HubID == f.hubs[1].native.d.Claims.Hub.HubID || f.hubs[0].dial == f.hubs[1].dial || reflect.DeepEqual(f.hubs[0].native.d.Claims.Hub.Public, f.hubs[1].native.d.Claims.Hub.Public) {
		t.Fatal("synthetic independent Hubs collided")
	}
	t.Cleanup(func() {
		f.stop()
		for _, hub := range f.hubs {
			hub.mu.Lock()
			control := hub.control
			hub.mu.Unlock()
			if control != 0 {
				t.Error("identity/lifecycle fixture entered Control inference")
			}
		}
	})
	if managed {
		if err := initializeNodeHubRegistry(context.Background(), f.root); err != nil {
			t.Fatal("actual empty manager registry", err)
		}
		f.start()
	} else {
		f.ctx = context.Background()
	}
	return f
}

func (f *nodeHubLifecycleAcceptance) start() {
	f.t.Helper()
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.ctx = context.WithValue(f.ctx, nodeHubOperationHooksKey{}, nodeHubOperationHooks{Output: io.Discard})
	// Only the queue executable is substituted. Start/Wait, native context
	// checks, writer lock/epoch, crypto, Guard and durable inbox stay real.
	f.ctx = context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: f.queueCommand})
	f.managerEnd = make(chan error, 1)
	go func() { f.managerEnd <- serveNodeHubManager(f.ctx, f.root, nodeHubProductionDriver(f.root)) }()
	f.eventually("actual manager IPC ready", 8*time.Second, func() bool {
		v, err := nodeHubManagerIPC(context.Background(), f.root, "STATUS", 0)
		return err == nil && v.ManagerState == "RUNNING"
	})
}

func (f *nodeHubLifecycleAcceptance) stop() {
	f.t.Helper()
	if f.cancel == nil {
		return
	}
	f.cancel()
	select {
	case err := <-f.managerEnd:
		if err != nil && !errors.Is(err, context.Canceled) {
			f.t.Errorf("isolated manager stop failed: %v", err)
		}
	case <-time.After(45 * time.Second):
		f.t.Error("isolated manager/workers did not stop")
	}
	f.cancel = nil
}

func (f *nodeHubLifecycleAcceptance) queueCommand(ctx context.Context, binary string, args ...string) *exec.Cmd {
	// Reuse the existing visibly synthetic offline queue subprocess. Its
	// private argv capture supplies a plaintext oracle without log payloads.
	if len(args) != 5 || args[0] != "queue" || args[1] != "--thread" || args[3] != "--message" {
		return exec.CommandContext(ctx, "/bin/false")
	}
	f.queueMu.Lock()
	defer f.queueMu.Unlock()
	sum := sha256.Sum256([]byte(args[2]))
	base := filepath.Join(f.queueRoot, hex.EncodeToString(sum[:]))
	q := nativeDeliveryProcessFixture{NativeID: args[2], ConfigPath: base + ".json", CounterPath: base + ".count", ArgsPath: base + ".argv", WitnessPath: base + ".witness", QueueExit: f.queueExit}
	raw, err := json.Marshal(q)
	if err != nil || os.WriteFile(q.ConfigPath, raw, 0600) != nil {
		return exec.CommandContext(ctx, "/bin/false")
	}
	return nativeDeliveryQueueCommand(q.ConfigPath)(ctx, binary, args...)
}

func (f *nodeHubLifecycleAcceptance) eventually(label string, limit time.Duration, ready func() bool) {
	f.t.Helper()
	deadline := time.Now().Add(limit)
	for {
		if ready() {
			return
		}
		if !time.Now().Before(deadline) {
			f.t.Fatal(label + " timed out")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (f *nodeHubLifecycleAcceptance) entry(alias string) (nodeHubRegistryEntry, bool) {
	r, _, err := nodeHubRoot(context.Background(), f.root, false)
	if err != nil {
		return nodeHubRegistryEntry{}, false
	}
	defer r.Close()
	registry, _, err := readNodeHubRegistry(r)
	if err != nil {
		return nodeHubRegistryEntry{}, false
	}
	for _, e := range registry.Connections {
		if e.Alias == alias {
			return e, true
		}
	}
	return nodeHubRegistryEntry{}, false
}

func (f *nodeHubLifecycleAcceptance) add(index int) LocalNodeConnection {
	f.t.Helper()
	hub := f.hubs[index]
	alias := []string{"SYNTHETIC-A", "SYNTHETIC-B"}[index]
	ctx, cancel := context.WithTimeout(f.ctx, 45*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := AddLocalNodeHubConnection(ctx, LocalNodeHubAddInput{UserRoot: f.root, HubAddress: hub.dial, Alias: alias})
		done <- err
	}()
	var entry nodeHubRegistryEntry
	f.eventually("actual add reserved its original state", 10*time.Second, func() bool {
		var found bool
		entry, found = f.entry(alias)
		return found
	})
	f.approvePendingNode(index, entry.StateDir, entry.NodeID)
	select {
	case err := <-done:
		if err != nil {
			f.t.Fatal("actual dynamic add did not settle", err)
		}
	case <-ctx.Done():
		f.t.Fatal("actual dynamic add/private ACK timed out")
	}
	hub.dispatch(appcore.Action{Kind: appcore.ActionRefreshNodePairing})
	connection, err := ResolveLocalNodeConnection(ctx, LocalNodeSelection{UserRoot: f.root, HubID: hub.native.d.Claims.Hub.HubID}, nil)
	if err != nil || connection.Pin.ConnectionID == "" || connection.Pin.ConnectionEpoch != 1 {
		f.t.Fatal("actual managed discovery/private ACK missing", err)
	}
	return connection
}

func (f *nodeHubLifecycleAcceptance) approvePendingNode(index int, state, node string) {
	f.t.Helper()
	hub := f.hubs[index]
	var code string
	f.eventually("real scoped NPT original committed", 20*time.Second, func() bool {
		c, err := openMachineNodeControlClientMode(state, hub.native.d.Claims.Origin, node, true)
		if err != nil {
			return false
		}
		s, err := loadMachineNodePairScopedState(state, node, c.identity)
		if err != nil {
			return false
		}
		defer clear(s.Secret)
		if s.Stage != wire.NodePairTrustScopedPending || s.Context == nil || s.Selector == "" || s.OOB == "" || s.PendingOperation != "" {
			return false
		}
		code, err = wire.EncodeNodePairTrustScopedCode(*s.Context, s.Selector, s.Secret)
		return err == nil
	})
	// Test-owned private RAM capture; the companion TTY's no-log behavior is
	// separately covered by its existing PTY test. Never print this code.
	hub.dispatch(appcore.Action{Kind: appcore.ActionReviewNodePairing, DevicePairingCode: code})
	code = ""
	p := hub.app.Snapshot().Node.Pairing
	if p == nil || p.State != "REVIEW" || p.ReviewID == "" {
		f.t.Fatal("actual App exact scoped review absent")
	}
	hub.dispatch(appcore.Action{Kind: appcore.ActionApproveNodePairing, NodePairingReviewID: p.ReviewID, ConfirmNodePairing: true})
}

func (f *nodeHubLifecycleAcceptance) assertUnchanged(original LocalNodeConnection) {
	f.t.Helper()
	current, err := ResolveLocalNodeConnection(f.ctx, LocalNodeSelection{UserRoot: f.root, HubID: original.Pin.HubID, NodeID: original.Pin.NodeID}, &original.Pin)
	if err != nil || current != original {
		f.t.Fatal("healthy original worker/pin/discovery changed", err)
	}
}

func (f *nodeHubLifecycleAcceptance) rejectForeignCredential(a, b LocalNodeConnection) {
	f.t.Helper()
	_, tokenA, err := loadMachineRecoveryClient(a.Pin.StateDir, a.Pin.NodeID)
	if err != nil {
		f.t.Fatal("original A credential unavailable", err)
	}
	_, tokenB, err := loadMachineRecoveryClient(b.Pin.StateDir, b.Pin.NodeID)
	if err != nil || tokenA == tokenB {
		f.t.Fatal("independent B credential unavailable or duplicated", err)
	}
	before, err := f.hubs[1].db.GetMachine(b.Pin.NodeID)
	if err != nil {
		f.t.Fatal(err)
	}
	client, err := hubtransport.NewHTTPClient(f.hubs[1].native.d, f.hubs[1].dial, 5*time.Second)
	if err != nil {
		f.t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for _, attempt := range []struct {
		token string
		want  int
	}{{tokenA, http.StatusUnauthorized}, {tokenB, http.StatusNoContent}} {
		r, err := http.NewRequest(http.MethodPost, b.Pin.APIOrigin+"/v2/relay/nodes/"+url.PathEscape(b.Pin.NodeID)+"/heartbeat", strings.NewReader("{}"))
		if err != nil {
			f.t.Fatal(err)
		}
		r.Header.Set("Authorization", "CicadaNode "+attempt.token)
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			f.t.Fatal("credential guard did not yield an exact HTTP decision", err)
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4097))
		response.Body.Close()
		if readErr != nil || response.StatusCode != attempt.want {
			f.t.Fatalf("credential guard status=%d want=%d", response.StatusCode, attempt.want)
		}
	}
	after, err := f.hubs[1].db.GetMachine(b.Pin.NodeID)
	// A live worker legitimately updates LastSeen/status. Compare durable
	// identity/ownership, not a whole liveness row that races its heartbeat.
	if err != nil || before.ID != after.ID || before.OwnerID != after.OwnerID || before.CreatedAt != after.CreatedAt {
		f.t.Fatal("foreign credential changed original Node identity/Owner", err)
	}
	wrong, err := hubtransport.NewHTTPClient(f.hubs[0].native.d, f.hubs[1].dial, 5*time.Second)
	if err != nil {
		f.t.Fatal(err)
	}
	defer wrong.CloseIdleConnections()
	response, err := wrong.Get(a.Pin.APIOrigin + "/v2/client/identity")
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		f.t.Fatal("B accepted A's original Hub cryptographic transport pin")
	}
	f.assertUnchanged(a)
	f.assertUnchanged(b)
}

func TestNodeHubLifecycleCurrentNPTAddRemoveColdAcceptance(t *testing.T) {
	f := newNodeHubLifecycleAcceptance(t)
	a := f.add(0)
	b := f.add(1)
	f.assertUnchanged(a)
	if a.Pin.NodeID != b.Pin.NodeID || a.Pin.WriterRoot != b.Pin.WriterRoot || a.Pin.WriterRoot == "" || a.Pin.StateDir == b.Pin.StateDir || a.Pin.SocketPath == b.Pin.SocketPath || a.Pin.MCPSessionStateFile == b.Pin.MCPSessionStateFile || a.Pin.MCPOutboxStateFile == b.Pin.MCPOutboxStateFile || a.Pin.Binding.NodeKeyID == b.Pin.Binding.NodeKeyID {
		t.Fatal("actual same physical Node did not retain independent Hub authorities and shared writer")
	}
	listed, err := ListVerifiedLocalNodeConnections(f.ctx, f.root)
	if err != nil || len(listed) != 2 {
		t.Fatal("actual verified enumerator did not expose two ready workers", err)
	}
	f.rejectForeignCredential(a, b)
	removal, err := RemoveLocalNodeHubConnection(f.ctx, LocalNodeHubSelection{UserRoot: f.root, ConnectionID: a.Pin.ConnectionID})
	if err != nil || removal.State != "LOCAL_STOPPED" || removal.LocalFence != a.Pin.ConnectionEpoch+1 || removal.RemoteRevocation != "NOT_REQUESTED" {
		t.Fatal("actual A local removal did not quiesce", err)
	}
	f.assertUnchanged(b)
	if _, err := ResolveLocalNodeConnection(f.ctx, LocalNodeSelection{UserRoot: f.root, HubID: a.Pin.HubID, NodeID: a.Pin.NodeID}, &a.Pin); err == nil {
		t.Fatal("removed A still admitted its original managed pin")
	}
	again, err := RemoveLocalNodeHubConnection(f.ctx, LocalNodeHubSelection{UserRoot: f.root, ConnectionID: a.Pin.ConnectionID})
	if err != nil || again != removal {
		t.Fatal("duplicate remove changed durable original result", err)
	}
	f.stop()
	f.start()
	f.eventually("cold B worker ready", 12*time.Second, func() bool {
		connections, err := ListVerifiedLocalNodeConnections(f.ctx, f.root)
		return err == nil && len(connections) == 1 && connections[0].Pin == b.Pin
	})
	if _, exists := f.entry("SYNTHETIC-A"); exists {
		t.Fatal("cold manager resurrected retired A")
	}
	if _, err := os.Stat(machineNodeCredentialPath(a.Pin.StateDir, a.Pin.NodeID)); err != nil {
		t.Fatal("local remove deleted retained original credentials", err)
	}
	t.Log("SYNTHETIC real TLS/SQLite/current NPT/private ACK/production Agent lifecycle; Control inference absent; native Runtime/systemd/Windows NOT_RUN")
}

// Classification is an explicit real Owner Core read/review/apply ceremony.
// The DB read locates only the existing Node-created public Endpoint; it never
// creates an anchor or supplies a role/proof to the Hub.
func (f *nodeHubLifecycleAcceptance) classifyThread(connection LocalNodeConnection, thread nodeHubAcceptanceThread, class string) wire.ThreadScopeView {
	f.t.Helper()
	var hub *nodeHubLifecycleHub
	for _, candidate := range f.hubs {
		if candidate.native.d.Claims.Hub.HubID == connection.Pin.HubID {
			hub = candidate
		}
	}
	if hub == nil {
		f.t.Fatal("exact Owner classification Hub absent")
	}
	locate := func() (string, string) {
		f.t.Helper()
		u := url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(filepath.Dir(hub.native.file), "cicada.sqlite3"))}
		db, err := sql.Open("sqlite", u.String()+"?mode=ro&_busy_timeout=5000")
		if err != nil {
			f.t.Fatal(err)
		}
		defer db.Close()
		var count int
		var endpoint, network string
		err = db.QueryRow(`SELECT count(*),coalesce(min(endpoint_id),''),coalesce(min(network_id),'') FROM hub_endpoint_groups_registrations_v1 WHERE node_id=? AND json_extract(anchor_json,'$.registration.harness')='codex' AND json_extract(anchor_json,'$.registration.native_session_id')=? AND json_extract(anchor_json,'$.registration.workspace')=?`, connection.Pin.NodeID, thread.native, thread.workspace).Scan(&count, &endpoint, &network)
		if err != nil || count != 1 || endpoint == "" || network == "" {
			f.t.Fatal("exact Node-created zero-attested registration anchor missing before Owner read", err)
		}
		return endpoint, network
	}
	endpoint, network := locate()
	read := func() *appcore.ThreadClassificationView {
		f.t.Helper()
		snapshot := hub.app.Snapshot()
		if snapshot.Node.Binding == nil || snapshot.Node.Binding.NodeID != connection.Pin.NodeID || snapshot.ThreadGroups.NetworkID != network {
			f.t.Fatal("actual App classification parent scope mismatch")
		}
		cursor := ""
		seen := map[string]bool{}
		var card appcore.GroupThreadView
		for {
			snapshot = hub.app.Snapshot()
			hub.dispatch(appcore.Action{Kind: appcore.ActionReadThreadGroups, ThreadGroups: appcore.ThreadGroupAction{GestureID: snapshot.ThreadGroups.GestureID, Cursor: cursor}})
			snapshot = hub.app.Snapshot()
			for _, candidate := range snapshot.ThreadGroups.Threads {
				if candidate.EndpointID == endpoint {
					card = candidate
				}
			}
			if card.EndpointID != "" {
				break
			}
			cursor = snapshot.ThreadGroups.ThreadsNextCursor
			if cursor == "" || seen[cursor] {
				f.t.Fatal("actual Owner directory did not locate the original Endpoint")
			}
			seen[cursor] = true
		}
		hub.dispatch(appcore.Action{Kind: appcore.ActionReadThreadRelations, ThreadGroups: appcore.ThreadGroupAction{GestureID: card.GestureID, EndpointID: card.EndpointID}})
		selected := hub.app.Snapshot().ThreadGroups.Selected
		if selected == nil || selected.EndpointID != endpoint || selected.CoordinationGestureID == "" {
			f.t.Fatal("actual App offered no scoped classification gesture")
		}
		hub.dispatch(appcore.Action{Kind: appcore.ActionReadThreadCoordination, Coordination: appcore.CoordinationAction{EndpointID: selected.EndpointID, GestureID: selected.CoordinationGestureID}})
		selected = hub.app.Snapshot().ThreadGroups.Selected
		if selected == nil || selected.Classification == nil || !selected.Classification.Current {
			f.t.Fatal("actual App classification observation is not current")
		}
		afterEndpoint, afterNetwork := locate()
		if endpoint != afterEndpoint || network != afterNetwork {
			f.t.Fatal("Owner read changed the registration anchor")
		}
		return selected.Classification
	}
	current := read()
	// A fresh registration receives an explicit Worker ceremony. Exact
	// registration recovery preserves a class already explicitly set by Owner.
	if class == "" {
		class = current.Classification
		if class == "" {
			class = wire.ThreadClassificationWorker
		}
	}
	if current.Classification != class {
		hub.dispatch(appcore.Action{Kind: appcore.ActionPrepareCoordination, Coordination: appcore.CoordinationAction{Change: wire.ThreadCollaborationSetClassification, EndpointID: endpoint, Classification: class, GestureID: current.GestureID}})
		review := hub.app.Snapshot().Coordination.Review
		if review == nil || !review.CanApply || review.Classification != class {
			f.t.Fatal("actual App classification review was not explicit/current")
		}
		hub.dispatch(appcore.Action{Kind: appcore.ActionApplyCoordination, Coordination: appcore.CoordinationAction{GestureID: review.GestureID, Confirm: true}})
		current = read()
	}
	if current.Classification != class || current.State != "CURRENT" {
		f.t.Fatal("real Owner Apply did not establish the requested single classification")
	}
	// Read the actual common DTO through the public Native MCP carrier. The
	// display model is never converted into an invented protocol observation.
	m, err := newLocalNodeMCPServer(LocalNodeSelection{UserRoot: f.root, HubID: connection.Pin.HubID, NodeID: connection.Pin.NodeID})
	if err != nil {
		f.t.Fatal(err)
	}
	defer closeCodexMCPChild(m)
	value, err := f.tool(m, thread, "cicada_thread_scope", map[string]any{})
	if err != nil {
		f.t.Fatal("actual Native classification read after Owner Apply", err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		f.t.Fatal(err)
	}
	var scope wire.ThreadScopeView
	if json.Unmarshal(raw, &scope) != nil || wire.ValidateThreadScopeView(scope) != nil || scope.HubID != connection.Pin.HubID || scope.NodeID != connection.Pin.NodeID || scope.EndpointID != endpoint || scope.NetworkID != network || scope.Classification != class || scope.State != "CURRENT" {
		f.t.Fatal("actual Native common scope did not confirm Owner classification")
	}
	return scope
}
