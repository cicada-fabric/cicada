package nodetransport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

func runtimeTestOptions(i *LocalTLSInstaller) RuntimeOptions {
	return RuntimeOptions{StateRoot: i.StateRoot, WriterRoot: i.WriterRoot, HubID: i.HubID, NodeID: i.NodeID, ApplicationOrigin: "https://hub.synthetic.invalid", ConfigPath: filepath.Join(i.base(), "active.json"), OpenLocal: func() (*LocalTLSInstaller, func(), error) { copy := *i; return &copy, func() {}, nil }, QueryCurrent: func(context.Context, *Config) (*store.NodeTLSAuthoritySnapshot, error) {
		return nil, ErrTLSCurrentAuthorityUnavailable
	}}
}
func TestNodeTLSRuntimeQuarantineBeforeLocalOrQueryNoWrites(t *testing.T) {
	i, _, _, _ := installSyntheticLocal(t)
	marker := filepath.Join(i.WriterRoot, "nodes", ".recovery-pending", "node-unrelated.json")
	if os.MkdirAll(filepath.Dir(marker), 0700) != nil || os.WriteFile(marker, []byte("synthetic quarantine"), 0600) != nil {
		t.Fatal("disposable marker")
	}
	o := runtimeTestOptions(i)
	o.OpenLocal = func() (*LocalTLSInstaller, func(), error) {
		t.Fatal("quarantine opened local trust")
		return nil, nil, nil
	}
	o.QueryCurrent = func(context.Context, *Config) (*store.NodeTLSAuthoritySnapshot, error) {
		t.Fatal("quarantine issued query")
		return nil, nil
	}
	before := installTree(t, i.StateRoot, i.WriterRoot)
	if _, err := OpenRuntime(context.Background(), o); !errors.Is(err, ErrTLSRecoveryQuarantine) {
		t.Fatal("quarantine classification", err)
	}
	if installTree(t, i.StateRoot, i.WriterRoot) != before {
		t.Fatal("quarantined startup mutated source tree")
	}
}
func TestNodeTLSRuntimeUnavailableTypedAndNoPublication(t *testing.T) {
	i, _, _, _ := installSyntheticLocal(t)
	o := runtimeTestOptions(i)
	o.QueryCurrent = nil
	before := installTree(t, i.StateRoot, i.WriterRoot)
	if _, err := OpenRuntime(context.Background(), o); !errors.Is(err, ErrTLSCurrentAuthorityUnavailable) {
		t.Fatal("missing independent current provider accepted", err)
	}
	if unavailable := pqtls.Available(); unavailable != nil {
		if os.Getenv("PQTLS_TEST_OPENSSL") != "" || !errors.Is(unavailable, pqtls.ErrUnavailable) {
			t.Fatal("requested native provider is unavailable")
		}
		o = runtimeTestOptions(i)
		if _, err := OpenRuntime(context.Background(), o); !errors.Is(err, pqtls.ErrUnavailable) {
			t.Fatal("default backend classification", err)
		}
	}
	if installTree(t, i.StateRoot, i.WriterRoot) != before {
		t.Fatal("unavailable startup changed private roots")
	}
}
func TestNodeTLSRuntimeNativeCheckedRestartAndHandoff(t *testing.T) {
	if !installNativeEnabled(t) {
		return
	}
	i, s, ca, _, hub := installSignedFixture(t)
	active := installActivate(t, i, s, ca, hub)
	if _, err := i.Apply(active, ca.at); err != nil {
		t.Fatal("disposable offline apply", err)
	}
	o := runtimeTestOptions(i)
	var reads, locals int
	o.OpenLocal = func() (*LocalTLSInstaller, func(), error) {
		locals++
		if lock, err := nodelock.AcquireWriterRootExclusive(i.WriterRoot); !errors.Is(err, nodelock.ErrBusy) {
			if lock != nil {
				lock.Close()
			}
			t.Fatal("local reader ran without WriterRoot fence", err)
		}
		if lock, err := nodelock.AcquireMaintenanceExclusive(i.StateRoot, i.NodeID); !errors.Is(err, nodelock.ErrBusy) {
			if lock != nil {
				lock.Close()
			}
			t.Fatal("local reader ran without Node fence", err)
		}
		copy := *i
		return &copy, func() {}, nil
	}
	o.QueryCurrent = func(context.Context, *Config) (*store.NodeTLSAuthoritySnapshot, error) {
		reads++
		copy := active
		return &copy, nil
	}
	runtime, err := OpenRuntime(context.Background(), o)
	if err != nil {
		t.Fatal("checked synthetic restart", err)
	}
	if reads != 2 || locals != 2 {
		runtime.Close()
		t.Fatal("startup did not independently recheck shared handoff")
	}
	if _, err := i.Apply(active, ca.at); !errors.Is(err, nodelock.ErrBusy) {
		runtime.Close()
		t.Fatal("running runtime admitted offline Apply", err)
	}
	copyBeforeClose := *runtime
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	copyBeforeClose.Close()
	request, _ := http.NewRequest(http.MethodGet, "https://hub.synthetic.invalid/v2/relay", nil)
	if _, err := copyBeforeClose.RoundTrip(request); !errors.Is(err, ErrTLSRuntimeClosed) {
		t.Fatal("copied closed runtime admitted request")
	}
	if _, err := i.LoadActive(ca.at); err != nil {
		t.Fatal("runtime did not release lifetime locks", err)
	}
	for _, kind := range []string{"missing-current", "precommit", "row-version", "csr", "issuer", "root", "leaf", "held-lock-inode"} {
		t.Run(kind, func(t *testing.T) {
			_, _, agentPath := runtimeLockPaths(o)
			replaced := false
			reads = 0
			o.QueryCurrent = func(context.Context, *Config) (*store.NodeTLSAuthoritySnapshot, error) {
				reads++
				copy := active
				if reads == 1 {
					return &copy, nil
				}
				switch kind {
				case "missing-current":
					return nil, errors.New("synthetic disconnected current source")
				case "precommit":
					copy.State = store.NodeTLSInstalled
				case "row-version":
					copy.RowVersion++
				case "csr":
					copy.CSRPEM = []byte("synthetic substitute CSR")
				case "issuer":
					copy.IssuerChainPEM = []byte("synthetic substitute issuer")
				case "root":
					copy.TrustAnchorPEM = []byte("synthetic substitute root")
				case "leaf":
					copy.LeafCertificatePEM = []byte("synthetic substitute leaf")
				case "held-lock-inode":
					if os.Rename(agentPath, agentPath+".synthetic-old") != nil || os.WriteFile(agentPath, nil, 0600) != nil {
						t.Fatal("synthetic held inode replacement")
					}
					replaced = true
				}
				return &copy, nil
			}
			before := installTree(t, i.StateRoot, i.WriterRoot)
			published, err := OpenRuntime(context.Background(), o)
			if replaced {
				if os.Remove(agentPath) != nil || os.Rename(agentPath+".synthetic-old", agentPath) != nil {
					t.Fatal("restore synthetic coordination inode")
				}
			}
			if published != nil {
				published.Close()
				t.Fatal("stale handoff published transport")
			}
			want := ErrTLSInstall
			if kind == "missing-current" {
				want = ErrTLSCurrentAuthorityUnavailable
			}
			if !errors.Is(err, want) {
				t.Fatal("handoff mismatch classification", err)
			}
			if installTree(t, i.StateRoot, i.WriterRoot) != before {
				t.Fatal("rejected handoff changed TLS tree")
			}
		})
	}
}

func TestNodeTLSRuntimeCopiesShareClosedStateAndCleanup(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "https://hub.synthetic.invalid/v2/relay", nil)
	for _, empty := range []*Runtime{nil, {}} {
		if _, err := empty.RoundTrip(request); !errors.Is(err, ErrTLSRuntimeClosed) {
			t.Fatal("nil/zero runtime admitted request")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var calls, cleanups atomic.Int32
	r := &Runtime{state: &runtimeState{ctx: ctx, cancel: cancel, bodies: make(map[*runtimeBody]struct{}), closeLocal: func() { cleanups.Add(1) }, base: runtimeTestRoundTripper(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("synthetic"))}, nil
	})}}
	copyBeforeClose := *r
	r.Close()
	copyBeforeClose.Close()
	if _, err := copyBeforeClose.RoundTrip(request); !errors.Is(err, ErrTLSRuntimeClosed) || calls.Load() != 0 || cleanups.Load() != 1 {
		t.Fatal("copied runtime did not synchronously deny or cleaned twice")
	}
	ctx, cancel = context.WithCancel(context.Background())
	started := make(chan struct{}, 16)
	r = &Runtime{state: &runtimeState{ctx: ctx, cancel: cancel, bodies: make(map[*runtimeBody]struct{}), closeLocal: func() { cleanups.Add(1) }, base: runtimeTestRoundTripper(func(request *http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}}
	copyBeforeClose = *r
	var workers sync.WaitGroup
	for n := 0; n < 16; n++ {
		workers.Add(1)
		target := r
		if n%2 == 0 {
			target = &copyBeforeClose
		}
		go func() {
			defer workers.Done()
			response, err := target.RoundTrip(request)
			if err == nil {
				response.Body.Close()
			} else if !errors.Is(err, ErrTLSRuntimeClosed) && !errors.Is(err, context.Canceled) {
				t.Error("copy close/request classification", err)
			}
		}()
	}
	for n := 0; n < 16; n++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("copied/original request did not enter base")
		}
	}
	workers.Add(2)
	go func() { defer workers.Done(); r.Close() }()
	go func() { defer workers.Done(); copyBeforeClose.Close() }()
	workers.Wait()
	if cleanups.Load() != 2 {
		t.Fatal("copy/original concurrently cleaned multiple times")
	}
}

type runtimeTestRoundTripper func(*http.Request) (*http.Response, error)

func (f runtimeTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type runtimeTestBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *runtimeTestBody) Close() error { b.closed.Store(true); return nil }
func TestNodeTLSRuntimeCloseCancelsBodiesAndConcurrentRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runtime{state: &runtimeState{ctx: ctx, cancel: cancel, bodies: make(map[*runtimeBody]struct{})}}
	body := &runtimeTestBody{Reader: strings.NewReader("synthetic body")}
	r.state.base = runtimeTestRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body, Request: req}, nil
	})
	req, _ := http.NewRequest(http.MethodGet, "https://hub.synthetic.invalid/v2/relay", nil)
	resp, err := r.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil || !body.closed.Load() {
		t.Fatal("active body not closed")
	}
	resp.Body.Close()
	if _, err := r.RoundTrip(req); !errors.Is(err, ErrTLSRuntimeClosed) {
		t.Fatal("closed generation admitted request")
	}
	ctx, cancel = context.WithCancel(context.Background())
	r = &Runtime{state: &runtimeState{ctx: ctx, cancel: cancel, bodies: make(map[*runtimeBody]struct{})}}
	started := make(chan struct{}, 8)
	r.state.base = runtimeTestRoundTripper(func(req *http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	var workers sync.WaitGroup
	for n := 0; n < 8; n++ {
		workers.Add(1)
		go func() { defer workers.Done(); r.RoundTrip(req) }()
	}
	for n := 0; n < 8; n++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("bounded request barrier")
		}
	}
	closed := make(chan struct{})
	go func() { r.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime shutdown leaked active request")
	}
	workers.Wait()
}

func runtimeSyntheticCoordination(t *testing.T, i *LocalTLSInstaller) {
	t.Helper()
	writer, err := nodelock.AcquireWriterRootExclusive(i.WriterRoot)
	if err != nil {
		t.Fatal(err)
	}
	writer.Close()
	node, err := nodelock.AcquireMaintenanceExclusive(i.StateRoot, i.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	node.Close()
}
func TestNodeTLSRuntimeMaintenanceReadScopeClosedAndNoWrites(t *testing.T) {
	i, _, _, _ := installSyntheticLocal(t)
	runtimeSyntheticCoordination(t, i)
	cap, err := AcquireTLSMaintenanceRead(i.StateRoot, i.WriterRoot, i.HubID, i.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer cap.Close()
	for _, o := range []RuntimeOptions{{StateRoot: i.StateRoot, WriterRoot: i.WriterRoot, HubID: "foreign", NodeID: i.NodeID}, {StateRoot: i.StateRoot, WriterRoot: i.WriterRoot, HubID: i.HubID, NodeID: "foreign"}, {StateRoot: installPrivateDir(t), WriterRoot: i.WriterRoot, HubID: i.HubID, NodeID: i.NodeID}, {StateRoot: i.StateRoot, WriterRoot: installPrivateDir(t), HubID: i.HubID, NodeID: i.NodeID}} {
		if _, err = cap.ReadCurrentAuthority(context.Background(), o); !errors.Is(err, ErrTLSInstall) {
			t.Fatal("maintenance foreign scope accepted", err)
		}
	}
	if lock, err := nodelock.AcquireWriterRootExclusive(i.WriterRoot); !errors.Is(err, nodelock.ErrBusy) {
		if lock != nil {
			lock.Close()
		}
		t.Fatal("cap did not hold WriterRootexclusive", err)
	}
	if lock, err := nodelock.AcquireMaintenanceExclusive(i.StateRoot, i.NodeID); !errors.Is(err, nodelock.ErrBusy) {
		if lock != nil {
			lock.Close()
		}
		t.Fatal("cap did not hold Nodeexclusive", err)
	}
	marker := filepath.Join(i.WriterRoot, "nodes", ".recovery-pending", "node-unrelated.json")
	if os.MkdirAll(filepath.Dir(marker), 0700) != nil || os.WriteFile(marker, []byte("synthetic pending recovery"), 0600) != nil {
		t.Fatal("synthetic pending")
	}
	before := installTree(t, i.StateRoot, i.WriterRoot)
	if _, err = i.Apply(store.NodeTLSAuthoritySnapshot{State: store.NodeTLSActive, ReservationVersion: 1}, time.Now().UTC().Truncate(time.Second)); !errors.Is(err, ErrTLSRecoveryQuarantine) {
		t.Fatal("maintenance read granted quarantine write", err)
	}
	if installTree(t, i.StateRoot, i.WriterRoot) != before {
		t.Fatal("maintenance changed pending or state")
	}
	duplicate := *cap
	cap.Close()
	duplicate.Close()
	o := runtimeTestOptions(i)
	o.OpenLocal = func() (*LocalTLSInstaller, func(), error) { t.Fatal("closed copy opened trust"); return nil, nil, nil }
	if _, err = duplicate.ReadCurrentAuthority(context.Background(), o); !errors.Is(err, ErrTLSRuntimeClosed) {
		t.Fatal("closed maintenance copy admitted current", err)
	}
	if _, err = duplicate.QueryRecovery(context.Background(), o, "", nil); !errors.Is(err, ErrTLSRuntimeClosed) {
		t.Fatal("closed maintenance copy admitted request", err)
	}
	writer, err := nodelock.AcquireWriterRootExclusive(i.WriterRoot)
	if err != nil {
		t.Fatal("copy cleanup did not release locks", err)
	}
	writer.Close()
}
func TestNodeTLSRuntimeExistingLockUnsafeReplacementAndBusy(t *testing.T) {
	for _, kind := range []string{"missing", "unsafe-mode", "symlink", "replaced-inode", "node-exclusive"} {
		t.Run(kind, func(t *testing.T) {
			i, _, _, _ := installSyntheticLocal(t)
			runtimeSyntheticCoordination(t, i)
			o := runtimeTestOptions(i)
			writer, node, _ := runtimeLockPaths(o)
			switch kind {
			case "missing":
				os.Remove(writer)
			case "unsafe-mode":
				os.Chmod(writer, 0644)
			case "symlink":
				os.Remove(writer)
				os.Symlink(node, writer)
			case "replaced-inode":
				cap, err := AcquireTLSMaintenanceRead(i.StateRoot, i.WriterRoot, i.HubID, i.NodeID)
				if err != nil {
					t.Fatal(err)
				}
				defer cap.Close()
				if os.Rename(writer, writer+".synthetic-old") != nil || os.WriteFile(writer, nil, 0600) != nil {
					t.Fatal("synthetic replacement")
				}
				before := installTree(t, i.StateRoot, i.WriterRoot)
				if _, err = cap.ReadAcceptedBinding(i.StateRoot, i.WriterRoot, i.HubID, i.NodeID); !errors.Is(err, ErrTLSInstall) {
					t.Fatal("cap accepted replacement inode", err)
				}
				if installTree(t, i.StateRoot, i.WriterRoot) != before {
					t.Fatal("unsafe inode read mutated")
				}
				return
			case "node-exclusive":
				held, err := nodelock.AcquireMaintenanceExclusive(i.StateRoot, i.NodeID)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
				start := time.Now()
				locks, err := runtimeAcquireShared(o)
				runtimeCloseLocks(locks)
				if !errors.Is(err, nodelock.ErrBusy) || time.Since(start) > time.Second {
					t.Fatal("Node-only exclusive did not deny immediately", err)
				}
				return
			}
			before := installTree(t, i.StateRoot, i.WriterRoot)
			if _, err := AcquireTLSMaintenanceRead(i.StateRoot, i.WriterRoot, i.HubID, i.NodeID); !errors.Is(err, ErrTLSInstall) {
				t.Fatal("unsafe lock accepted", err)
			}
			if installTree(t, i.StateRoot, i.WriterRoot) != before {
				t.Fatal("unsafe lock repaired")
			}
		})
	}
}
func TestNodeTLSRuntimeApplyProvisionsOnlyMissingAgentMetadata(t *testing.T) {
	if !installNativeEnabled(t) {
		return
	}
	i, s, ca, _, hub := installSignedFixture(t)
	active := installActivate(t, i, s, ca, hub)
	_, _, agent := runtimeLockPaths(runtimeTestOptions(i))
	if _, err := os.Lstat(agent); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture hid missing first Agent metadata")
	}
	if _, err := i.Apply(active, ca.at); err != nil {
		t.Fatal("fresh verified Apply", err)
	}
	if tlsPath(agent, false) != nil {
		t.Fatal("Apply did not provision private Agent metadata")
	}
	before := installTree(t, i.StateRoot, i.WriterRoot)
	if _, err := i.Apply(active, ca.at); err != nil || installTree(t, i.StateRoot, i.WriterRoot) != before {
		t.Fatal("duplicate Apply changed metadata", err)
	}
	if os.Chmod(agent, 0644) != nil {
		t.Fatal("synthetic unsafe metadata")
	}
	before = installTree(t, i.StateRoot, i.WriterRoot)
	if _, err := i.Apply(active, ca.at); !errors.Is(err, ErrTLSInstall) || installTree(t, i.StateRoot, i.WriterRoot) != before {
		t.Fatal("Apply repaired unsafe Agent metadata", err)
	}
	// A missing advisory Agent file cannot make a rejected local-floor rollback
	// write metadata. The altered floor is a disposable corruption fixture only.
	if os.Remove(agent) != nil {
		t.Fatal("remove synthetic metadata")
	}
	f, err := i.readFloor(false)
	if err != nil {
		t.Fatal(err)
	}
	f.Epoch++
	encoded, err := json.Marshal(f)
	if err != nil || os.WriteFile(i.floorPath(), encoded, 0600) != nil {
		t.Fatal("synthetic stale local floor")
	}
	before = installTree(t, i.StateRoot, i.WriterRoot)
	if _, err = i.Apply(active, ca.at); !errors.Is(err, ErrTLSInstall) || installTree(t, i.StateRoot, i.WriterRoot) != before {
		t.Fatal("rejected floor provisioned Agent metadata", err)
	}
	if _, err = os.Lstat(agent); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rollback created Agent metadata")
	}

}

func TestNodeTLSRuntimeMaintenanceReadCloseJoinsEnteredQuery(t *testing.T) {
	i, _, _, _ := installSyntheticLocal(t)
	runtimeSyntheticCoordination(t, i)
	cap, err := AcquireTLSMaintenanceRead(i.StateRoot, i.WriterRoot, i.HubID, i.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer cap.Close()
	duplicate := *cap
	started, finish := make(chan struct{}), make(chan struct{})
	o := runtimeTestOptions(i)
	o.OpenLocal = func() (*LocalTLSInstaller, func(), error) { close(started); <-finish; return nil, nil, ErrTLSInstall }
	queried := make(chan error, 1)
	go func() { _, err := duplicate.ReadCurrentAuthority(context.Background(), o); queried <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance query did not enter")
	}
	closed := make(chan struct{})
	go func() { cap.Close(); close(closed) }()
	// Wait until Close has synchronously marked this shared capability closed.
	deadline := time.Now().Add(2 * time.Second)
	for {
		cap.state.mu.Lock()
		stopped := cap.state.closed
		cap.state.mu.Unlock()
		if stopped {
			break
		}
		if time.Now().After(deadline) {
			close(finish)
			t.Fatal("maintenance close did not begin")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := duplicate.ReadCurrentAuthority(context.Background(), o); !errors.Is(err, ErrTLSRuntimeClosed) {
		close(finish)
		t.Fatal("Close admitted copied capability", err)
	}
	if lock, err := nodelock.AcquireWriterRootExclusive(i.WriterRoot); !errors.Is(err, nodelock.ErrBusy) {
		if lock != nil {
			lock.Close()
		}
		close(finish)
		t.Fatal("Close released hold before joined query", err)
	}
	select {
	case <-closed:
		close(finish)
		t.Fatal("Close failed to join active query")
	default:
	}
	close(finish)
	if err := <-queried; !errors.Is(err, ErrTLSInstall) {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance Close did not finish")
	}
	lock, err := nodelock.AcquireWriterRootExclusive(i.WriterRoot)
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
}
