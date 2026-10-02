package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

const nodeSSEReadyFrame = "event: ready\ndata: claim\n\n"

// This gate calls the production route and relayNodeEvents in a native Hub
// child, using its real Fabric subscriptions. Only the already-authorized ready
// Write is paused: subscriptions exist, and production tickers do not yet exist.
// It never blocks an event Write and then claims already-admitted byte recall.
type nodeSSEObservation struct {
	mu                                        sync.Mutex
	checks, denied, ready, wake, space, other int
	blocked, release, flushed, hint, done     chan struct{}
	blockedOnce, flushedOnce, hintOnce        sync.Once
}

func newNodeSSEObservation() *nodeSSEObservation {
	return &nodeSSEObservation{blocked: make(chan struct{}), release: make(chan struct{}), flushed: make(chan struct{}), hint: make(chan struct{}), done: make(chan struct{})}
}

func nodeSSEWait(ctx context.Context, signal <-chan struct{}) error {
	select {
	case <-signal:
		return nil
	case <-ctx.Done():
		return errors.New("production SSE phase watchdog expired")
	}
}

func nodeSSERequireNative(t *testing.T) bool {
	t.Helper()
	err := pqtls.Available()
	if err == nil {
		return true
	}
	// Root's native/race gate explicitly selects the accepted fixture executable.
	// A requested native gate must fail, rather than credit an unavailable build.
	if os.Getenv("PQTLS_TEST_OPENSSL") != "" {
		t.Fatal("requested native production SSE provider unavailable")
	}
	if !errors.Is(err, pqtls.ErrUnavailable) {
		t.Fatal("production SSE provider returned an untyped unavailable error")
	}
	return false
}

type nodeSSEReadyWriter struct {
	http.ResponseWriter
	ctx context.Context
	o   *nodeSSEObservation
}

func (w *nodeSSEReadyWriter) Write(b []byte) (int, error) {
	if bytes.Equal(b, []byte(nodeSSEReadyFrame)) {
		w.o.blockedOnce.Do(func() { close(w.o.blocked) })
		select {
		case <-w.o.release:
		case <-w.ctx.Done():
			return 0, w.ctx.Err()
		}
	}
	w.o.mu.Lock()
	switch string(b) {
	case nodeSSEReadyFrame:
		w.o.ready++
	case "event: wake\ndata: claim\n\n":
		w.o.wake++
	case "event: space\ndata: sync\n\n":
		w.o.space++
	default:
		w.o.other++
	}
	w.o.mu.Unlock()
	n, err := w.ResponseWriter.Write(b)
	if err == nil && (bytes.Equal(b, []byte("event: wake\ndata: claim\n\n")) || bytes.Equal(b, []byte("event: space\ndata: sync\n\n"))) {
		w.o.hintOnce.Do(func() { close(w.o.hint) })
	}
	return n, err
}

func (w *nodeSSEReadyWriter) Flush() {
	w.ResponseWriter.(http.Flusher).Flush()
	w.o.flushedOnce.Do(func() { close(w.o.flushed) })
}

func nodeSSERevoke(db *store.Store, service *fabric.Service, fixture nodeTLSProcessFixture) error {
	current, err := db.GetNodeTLSAuthorityReservationLocal(fixture.RequestID)
	if err != nil || current == nil || current.State != store.NodeTLSActive {
		return errors.New("synthetic current ACTIVE unavailable before SSE revoke")
	}
	if db.RevokeNodeTLSGrantLocal(fixture.RequestID, current.RowVersion) != nil {
		return errors.New("synthetic TLS revoke did not commit")
	}
	// Keep the bearer valid: this denial must come from current TLS authority,
	// not the legacy stream's throttled credential revalidation.
	if nodeID, err := service.AuthenticateNode(fixture.NodeToken); err != nil || nodeID != fixture.NodeConfig.Identity.NodeID {
		return errors.New("TLS-only revocation unexpectedly changed Node credential")
	}
	binding, err := db.CurrentNodeTransportBinding(fixture.NodeConfig.Identity.NodeID)
	if err != nil || binding == nil || binding.TLSAuthority != nil {
		return errors.New("committed TLS revoke remained current")
	}
	return nil
}

func nodeSSEDrive(ctx context.Context, mode string, o *nodeSSEObservation, db *store.Store, service *fabric.Service, fixture nodeTLSProcessFixture, cancelHub context.CancelFunc) error {
	if err := nodeSSEWait(ctx, o.blocked); err != nil {
		return err
	}
	switch mode {
	case "queued-wake", "active-wake":
		// Both notifications precede release, so the actual capacity-one
		// subscription coalesces them into one queued production wake.
		service.NotifyNodeClaimHint(fixture.NodeConfig.Identity.NodeID)
		service.NotifyNodeClaimHint(fixture.NodeConfig.Identity.NodeID)
	case "queued-space", "active-space":
		service.NotifyNodeSpaceHint(fixture.NodeConfig.Identity.NodeID)
		service.NotifyNodeSpaceHint(fixture.NodeConfig.Identity.NodeID)
	case "idle-current-revoke", "hub-context-shutdown":
	default:
		return errors.New("unknown synthetic production SSE scenario")
	}
	if strings.HasPrefix(mode, "queued-") {
		if err := nodeSSERevoke(db, service, fixture); err != nil {
			return err
		}
	}
	close(o.release)
	if err := nodeSSEWait(ctx, o.flushed); err != nil {
		return err
	}
	switch mode {
	case "active-wake", "active-space":
		if err := nodeSSEWait(ctx, o.hint); err != nil {
			return err
		}
		cancelHub()
	case "idle-current-revoke":
		// No hint is published in this scenario. The real one-second strict
		// transport ticker must run the live current check and close the stream.
		if err := nodeSSERevoke(db, service, fixture); err != nil {
			return err
		}
	case "hub-context-shutdown":
		cancelHub()
	}
	if err := nodeSSEWait(ctx, o.done); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	wantWake, wantSpace := 0, 0
	if mode == "active-wake" {
		wantWake = 1
	}
	if mode == "active-space" {
		wantSpace = 1
	}
	if o.ready != 1 || o.wake != wantWake || o.space != wantSpace || o.other != 0 || o.checks < 1 {
		return errors.New("production SSE frame or delegated-check count mismatch")
	}
	if strings.HasPrefix(mode, "queued-") || mode == "idle-current-revoke" {
		if o.denied < 1 {
			return errors.New("production SSE did not observe actual current-authority denial")
		}
	} else if o.denied != 0 {
		return errors.New("current synthetic authority denied a positive or shutdown stream")
	}
	return nil
}

func nodeSSEHubChild(t *testing.T, fixture nodeTLSProcessFixture, mode string) {
	t.Helper()
	db, err := store.New(fixture.DBPath)
	if err != nil {
		t.Fatal("open private synthetic SSE Store")
	}
	defer db.Close() // Every joined HTTP handler below finishes before Store closes.
	service, err := fabric.NewService(db, "synthetic-owner", "synthetic-domain")
	if err != nil {
		t.Fatal("open synthetic Fabric SSE service")
	}
	o := newNodeSSEObservation()
	hubCtx, cancelHub := context.WithCancel(context.Background())
	defer cancelHub()
	production, ok := NewFabricHandler(service, "synthetic-private-management-token").(*Handler)
	if !ok || production.control != nil || production.fabricService != service {
		t.Fatal("production SSE gate must use FabricOnly with Control nil")
	}
	observed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(o.done) // Production relayNodeEvents has already unsubscribed.
		original, ok := r.Context().Value(nodeTransportCheckKey{}).(nodeTransportCheck)
		if !ok {
			return
		}
		// Observe the trusted middleware's actual check; never replace its
		// identity, crypto, Store result, trusted clock or authorization result.
		counted := nodeTransportCheck(func() bool {
			allowed := original()
			o.mu.Lock()
			o.checks++
			if !allowed {
				o.denied++
			}
			o.mu.Unlock()
			return allowed
		})
		request := r.WithContext(context.WithValue(r.Context(), nodeTransportCheckKey{}, counted))
		production.ServeHTTP(&nodeSSEReadyWriter{w, r.Context(), o}, request)
	})
	listener, err := pqtls.Listen("tcp", fixture.HubConfig.Listen, fixture.HubConfig.TLSConfig())
	if err != nil {
		t.Fatal("open actual native Hub SSE listener")
	}
	defer listener.Close()
	server := &http.Server{Handler: WithNodePQTransport(observed, service, &fixture.HubConfig, true), ConnContext: pqtls.HTTPConnContext, BaseContext: func(net.Listener) context.Context { return hubCtx }, ReadHeaderTimeout: 5 * time.Second}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	fmt.Fprintln(os.Stdout, "CICADA_SSE_READY "+listener.Addr().String())
	driveCtx, stopDrive := context.WithTimeout(context.Background(), 12*time.Second)
	defer stopDrive()
	driveErr := nodeSSEDrive(driveCtx, mode, o, db, service, fixture, cancelHub)
	cancelHub()
	shutdownCtx, stopShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	shutdownErr := server.Shutdown(shutdownCtx)
	stopShutdown()
	closeErr := server.Close()
	serveErr := <-served
	if driveErr != nil {
		t.Fatal(driveErr)
	}
	if shutdownErr != nil || closeErr != nil || serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		t.Fatal("native production SSE Hub did not shut down and join cleanly")
	}
	// The Store is still open after handler return, unsubscribe and Serve join.
	if _, err := db.GetClientHubID(); err != nil {
		t.Fatal("synthetic Store closed before SSE HTTP lifecycle joined")
	}
	if err := db.Close(); err != nil {
		t.Fatal("close synthetic SSE Store last")
	}
	fmt.Fprintln(os.Stdout, "CICADA_SSE_HUB_COMPLETE "+mode)
}

func nodeSSENodeChild(t *testing.T, fixture nodeTLSProcessFixture, mode, address string) {
	t.Helper()
	client, err := pqtls.NewClient(fixture.NodeConfig.TLSConfig())
	if err != nil {
		t.Fatal("open actual native Node SSE client")
	}
	transport, err := client.HTTPTransport(address)
	if err != nil {
		t.Fatal("open native SSE HTTP transport")
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/v2/relay/nodes/"+fixture.NodeConfig.Identity.NodeID+"/events", nil)
	if err != nil {
		t.Fatal("create production Node SSE request")
	}
	request.Header.Set("Authorization", "CicadaNode "+fixture.NodeToken)
	httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return pqtls.ErrIdentity }}
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal("native production SSE request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal("production SSE response was not an admitted event stream")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	want := nodeSSEReadyFrame
	if mode == "active-wake" {
		want += "event: wake\ndata: claim\n\n"
	}
	if mode == "active-space" {
		want += "event: space\ndata: sync\n\n"
	}
	if err != nil || string(body) != want || ctx.Err() != nil {
		t.Fatal("production SSE leaked a queued hint or failed to close cleanly")
	}
	fmt.Fprintln(os.Stdout, "CICADA_SSE_NODE_COMPLETE "+mode)
}

func TestNodePQTLSProductionSSEUnavailable(t *testing.T) {
	if err := pqtls.Available(); err != nil {
		if os.Getenv("PQTLS_TEST_OPENSSL") != "" {
			t.Fatal("requested native production SSE provider unavailable")
		}
		if !errors.Is(err, pqtls.ErrUnavailable) {
			t.Fatal("default SSE gate has an untyped unavailable provider")
		}
		t.Log("typed native unavailable asserted; no native SSE child or fixture ran")
	}
}

func TestNodePQTLSProductionSSE(t *testing.T) {
	if role := os.Getenv("CICADA_SSE_PROCESS_ROLE"); role != "" {
		if !nodeSSERequireNative(t) {
			t.Fatal("native SSE child unavailable")
		}
		wire, err := os.ReadFile(os.Getenv("CICADA_SSE_PROCESS_FIXTURE"))
		var fixture nodeTLSProcessFixture
		if err != nil || json.Unmarshal(wire, &fixture) != nil {
			t.Fatal("read private synthetic SSE child fixture")
		}
		mode := os.Getenv("CICADA_SSE_PROCESS_MODE")
		switch role {
		case "hub":
			nodeSSEHubChild(t, fixture, mode)
		case "node":
			nodeSSENodeChild(t, fixture, mode, os.Getenv("CICADA_SSE_PROCESS_ADDRESS"))
		default:
			t.Fatal("unknown synthetic SSE child role")
		}
		return
	}
	if !nodeSSERequireNative(t) {
		t.Log("NOT_RUN native production SSE cases: default typed unavailable is covered separately")
		return
	}
	for _, mode := range []string{"queued-wake", "queued-space", "active-wake", "active-space", "idle-current-revoke", "hub-context-shutdown"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if os.Chmod(dir, 0700) != nil {
				t.Fatal("private native SSE fixture directory")
			}
			fixture := nodeTLSProcessBuild(t, dir)
			wire, err := json.Marshal(fixture)
			if err != nil {
				t.Fatal("encode private synthetic SSE fixture")
			}
			path := filepath.Join(dir, "private-sse-fixture.json")
			nodeTLSProcessWrite(t, path, wire)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			child := func(role, address string) *exec.Cmd {
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNodePQTLSProductionSSE$", "-test.count=1", "-test.timeout=25s")
				cmd.Env = append(os.Environ(), "CICADA_SSE_PROCESS_ROLE="+role, "CICADA_SSE_PROCESS_MODE="+mode, "CICADA_SSE_PROCESS_FIXTURE="+path, "CICADA_SSE_PROCESS_ADDRESS="+address)
				return cmd
			}
			hub := child("hub", "")
			stdout, err := hub.StdoutPipe()
			if err != nil {
				t.Fatal("open private Hub SSE observation pipe")
			}
			hub.Stderr = io.Discard
			if hub.Start() != nil {
				t.Fatal("start actual native Hub SSE child")
			}
			waited := false
			defer func() {
				if !waited {
					// Failed-child cleanup is never credited as successful shutdown.
					hub.Process.Kill()
					hub.Wait()
				}
			}()
			ready := make(chan string, 1)
			complete := make(chan bool, 1)
			go func() {
				scanner := bufio.NewScanner(stdout)
				announced := false
				completed := false
				for scanner.Scan() {
					line := scanner.Text()
					if strings.HasPrefix(line, "CICADA_SSE_READY ") && !announced {
						ready <- strings.TrimPrefix(line, "CICADA_SSE_READY ")
						announced = true
					}
					if line == "CICADA_SSE_HUB_COMPLETE "+mode {
						completed = true
					}
				}
				if !announced {
					ready <- ""
				}
				complete <- completed && scanner.Err() == nil
			}()
			var address string
			select {
			case address = <-ready:
			case <-ctx.Done():
				t.Fatal("native Hub SSE readiness watchdog expired")
			}
			if address == "" {
				t.Fatal("native Hub SSE child failed before readiness")
			}
			output, err := child("node", address).CombinedOutput()
			if err != nil || !bytes.Contains(output, []byte("CICADA_SSE_NODE_COMPLETE "+mode)) {
				t.Fatal("native Node SSE child failed; private child output suppressed")
			}
			select {
			case ok := <-complete:
				if !ok {
					t.Fatal("native Hub SSE child did not complete production lifecycle")
				}
			case <-ctx.Done():
				t.Fatal("native Hub SSE completion watchdog expired")
			}
			err = hub.Wait()
			waited = true
			if err != nil {
				t.Fatal("native Hub SSE child exited unsuccessfully")
			}
			t.Log("FabricOnly Control=nil; actual native Hub/Node exit=0; production SSE route, queues/checks and joined Store lifecycle observed")
		})
	}
}
