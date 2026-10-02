package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

// Same-process real native mTLS/socket gate, distinct from the existing six
// two-process SSE cases. Only test padding amplifies otherwise generic frames.
func nodeDeadlineNativeService(t *testing.T) (nodeTLSProcessFixture, *store.Store, *fabric.Service) {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private synthetic native deadline fixture")
	}
	fixture := nodeTLSProcessBuild(t, dir)
	db, err := store.New(fixture.DBPath)
	if err != nil {
		t.Fatal("open actual native authority Store")
	}
	t.Cleanup(func() { db.Close() })
	service, err := fabric.NewService(db, "synthetic-owner", "synthetic-domain")
	if err != nil {
		t.Fatal("create synthetic native Fabric service")
	}
	return fixture, db, service
}
func nodeDeadlineServe(t *testing.T, fixture nodeTLSProcessFixture, service *fabric.Service, base context.Context, inner http.Handler) (net.Listener, *http.Server, <-chan error) {
	t.Helper()
	listener, err := pqtls.Listen("tcp", fixture.HubConfig.Listen, fixture.HubConfig.TLSConfig())
	if err != nil {
		t.Fatal("open actual native deadline listener")
	}
	server := &http.Server{Handler: WithNodePQTransport(inner, service, &fixture.HubConfig, true), ConnContext: pqtls.HTTPConnContext, BaseContext: func(net.Listener) context.Context { return base }, ReadHeaderTimeout: 5 * time.Second}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() { server.Close(); listener.Close() })
	return listener, server, served
}
func nodeDeadlineJoin(t *testing.T, server *http.Server, served <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal("native deadline server did not join handlers", err)
	}
	select {
	case err := <-served:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatal("native Serve terminal error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("native Serve did not join")
	}
}
func TestNodePQTLSSEWriteDeadlineBackpressure(t *testing.T) {
	if !nodeSSERequireNative(t) {
		t.Log("typed native unavailable; real native deadline cases NOT_RUN")
		return
	}
	for _, mode := range []string{"write-revoke", "flush-cancel"} {
		t.Run(mode, func(t *testing.T) {
			fixture, db, service := nodeDeadlineNativeService(t)
			production := NewFabricHandler(service, "").(*Handler)
			if production.control != nil {
				t.Fatal("native deadline fixture constructed Control")
			}
			entered, done := make(chan struct{}), make(chan struct{})
			result := make(chan relayDeadlinePaddingResult, 1)
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			observed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				production.ServeHTTP(&relayDeadlinePaddingWriter{ResponseWriter: w, mode: strings.Split(mode, "-")[0], entered: entered, result: result}, r)
			})
			listener, server, served := nodeDeadlineServe(t, fixture, service, base, observed)
			client, err := pqtls.NewClient(fixture.NodeConfig.TLSConfig())
			if err != nil {
				t.Fatal("actual native deadline client")
			}
			dialCtx, stopDial := context.WithTimeout(context.Background(), 8*time.Second)
			defer stopDial()
			connection, err := client.DialContext(dialCtx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal("actual pinned native TLS handshake")
			}
			defer connection.Close()
			if err := connection.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			path := "/v2/relay/nodes/" + fixture.NodeConfig.Identity.NodeID + "/events"
			if _, err := io.WriteString(connection, "GET "+path+" HTTP/1.1\r\nHost: synthetic.invalid\r\nAuthorization: CicadaNode "+fixture.NodeToken+"\r\n\r\n"); err != nil {
				t.Fatal("send native SSE request")
			}
			if err := connection.SetWriteDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if err := connection.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
				t.Fatal(err)
			}
			request, _ := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+path, nil)
			response, err := http.ReadResponse(bufio.NewReader(connection), request)
			if err != nil {
				t.Fatal("read actual native SSE headers", err)
			}
			if response.StatusCode != 200 || relayDeadlineReadFrame(t, bufio.NewReader(response.Body)) != "event: ready\ndata: claim\n\n" {
				t.Fatal("established native SSE ready unavailable")
			}
			if err := connection.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			// The real stream and recheck ticker are running. No reads after ready.
			service.NotifyNodeClaimHint(fixture.NodeConfig.Identity.NodeID)
			relayDeadlineWait(t, entered, 8*time.Second)
			select {
			case <-done:
				t.Fatal("native socket padding did not reach an open admitted stream")
			case <-time.After(100 * time.Millisecond):
			}
			if strings.HasSuffix(mode, "revoke") {
				if err := nodeSSERevoke(db, service, fixture); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			relayDeadlineWait(t, done, relayNodeStreamWriteTimeout+3*time.Second)
			relayDeadlineRequireTimeout(t, result)
			relayDeadlineRequireUnsubscribed(t, service)
			nodeDeadlineJoin(t, server, served)
			if _, err := db.GetClientHubID(); err != nil {
				t.Fatal("Store closed before actual native handler unsubscribe/Serve join")
			}
			t.Log("actual native ACTIVE peer; padded socket write timed out; handler unsubscribed; HTTP lifecycle joined before Store close")
		})
	}
}
func TestNodePQTLSSEWriteDeadlineIdle(t *testing.T) {
	if !nodeSSERequireNative(t) {
		t.Log("typed native unavailable; real native idle deadline case NOT_RUN")
		return
	}
	fixture, db, service := nodeDeadlineNativeService(t)
	production := NewFabricHandler(service, "").(*Handler)
	if production.control != nil {
		t.Fatal("native idle fixture constructed Control")
	}
	done := make(chan struct{})
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, server, served := nodeDeadlineServe(t, fixture, service, base, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		production.ServeHTTP(relayDeadlineUnwrapper{w}, r)
	}))
	client, err := pqtls.NewClient(fixture.NodeConfig.TLSConfig())
	if err != nil {
		t.Fatal("actual native idle client")
	}
	transport, err := client.HTTPTransport(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+listener.Addr().String()+"/v2/relay/nodes/"+fixture.NodeConfig.Identity.NodeID+"/events", nil)
	request.Header.Set("Authorization", "CicadaNode "+fixture.NodeToken)
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return pqtls.ErrIdentity }}).Do(request)
	if err != nil {
		t.Fatal("actual native idle request")
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if response.StatusCode != 200 || relayDeadlineReadFrame(t, reader) != "event: ready\ndata: claim\n\n" {
		t.Fatal("actual native ready frame unavailable")
	}
	timer := time.NewTimer(relayNodeStreamWriteTimeout + time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-done:
		t.Fatal("native idle stream closed at frame deadline")
	case <-ctx.Done():
		t.Fatal("native idle watchdog")
	}
	service.NotifyNodeSpaceHint(fixture.NodeConfig.Identity.NodeID)
	if relayDeadlineReadFrame(t, reader) != "event: space\ndata: sync\n\n" {
		t.Fatal("native hint after frame-deadline idle failed")
	}
	if err := nodeSSERevoke(db, service, fixture); err != nil {
		t.Fatal(err)
	}
	relayDeadlineWait(t, done, 4*time.Second)
	response.Body.Close()
	relayDeadlineRequireUnsubscribed(t, service)
	nodeDeadlineJoin(t, server, served)
	if _, err := db.GetClientHubID(); err != nil {
		t.Fatal("native idle Store lifecycle not joined")
	}
}
