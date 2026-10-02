package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
)

type relayDeadlineWriter struct {
	header                       http.Header
	status, writes, flushes      int
	deadline                     time.Time
	deadlines                    []time.Time
	writeErr, flushErr, clearErr error
	short                        bool
	flushDeadline                time.Time
}

func (w *relayDeadlineWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *relayDeadlineWriter) WriteHeader(status int) { w.status = status }
func (w *relayDeadlineWriter) Write(b []byte) (int, error) {
	w.writes++
	if w.deadline.IsZero() {
		return 0, errors.New("missing frame deadline")
	}
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if w.short {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (w *relayDeadlineWriter) FlushError() error {
	w.flushes++
	w.flushDeadline = w.deadline
	return w.flushErr
}
func (w *relayDeadlineWriter) SetWriteDeadline(at time.Time) error {
	w.deadlines = append(w.deadlines, at)
	if at.IsZero() && w.clearErr != nil {
		return w.clearErr
	}
	w.deadline = at
	return nil
}

type relayDeadlineUnwrapper struct{ http.ResponseWriter }

func (w relayDeadlineUnwrapper) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestRelayNodeSSEWriteDeadlineFrame(t *testing.T) {
	marker := errors.New("synthetic frame failure")
	for _, mode := range []string{"success", "short-write", "write-error", "flush-error", "clear-error"} {
		t.Run(mode, func(t *testing.T) {
			w := &relayDeadlineWriter{}
			switch mode {
			case "short-write":
				w.short = true
			case "write-error":
				w.writeErr = marker
			case "flush-error":
				w.flushErr = marker
			}
			wrapped := relayDeadlineUnwrapper{w} // Only Unwrap; no Flusher or deadline method.
			controller, err := relayNodeStreamController(wrapped)
			if err != nil {
				t.Fatal("forwarding wrapper rejected", err)
			}
			if mode == "clear-error" {
				w.clearErr = marker
			}
			err = relayNodeStreamFrame(wrapped, controller, "event: wake\ndata: claim\n\n")
			if mode == "success" && err != nil {
				t.Fatal(err)
			}
			if mode == "short-write" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal("short write accepted", err)
			}
			if mode != "success" && mode != "short-write" && !errors.Is(err, marker) {
				t.Fatal("frame error was not propagated", err)
			}
			if len(w.deadlines) < 3 || !w.deadlines[1].IsZero() || w.deadlines[2].IsZero() {
				t.Fatal("frame deadline was not installed")
			}
			if mode == "success" {
				if len(w.deadlines) != 4 || !w.deadlines[3].IsZero() || !w.deadline.IsZero() {
					t.Fatal("successful frame deadline was not cleared")
				}
			} else {
				if w.deadline.IsZero() {
					t.Fatal("failure removed the finalization deadline")
				}
				if mode != "clear-error" && len(w.deadlines) != 3 {
					t.Fatal("failed frame attempted to clear its deadline")
				}
			}
			if w.deadlines[2].After(time.Now().Add(relayNodeStreamWriteTimeout)) {
				t.Fatal("frame budget widened")
			}
			if mode != "write-error" && mode != "short-write" && (w.flushes != 1 || !w.flushDeadline.Equal(w.deadlines[2])) {
				t.Fatal("Write and Flush did not share one deadline")
			}
			if (mode == "write-error" || mode == "short-write") && w.flushes != 0 {
				t.Fatal("failed write still flushed")
			}
		})
	}
}

type relayUnsupportedWriter struct {
	header         http.Header
	status, writes int
}

func (w *relayUnsupportedWriter) Header() http.Header         { return w.header }
func (w *relayUnsupportedWriter) WriteHeader(s int)           { w.status = s }
func (w *relayUnsupportedWriter) Write(b []byte) (int, error) { w.writes++; return len(b), nil }
func (w *relayUnsupportedWriter) Flush()                      {}

type relayDeadlineCycle struct{ relayUnsupportedWriter }

func (w *relayDeadlineCycle) Unwrap() http.ResponseWriter { return w }

// Reflection observes only lengths after the handler and all producers join;
// it never accesses keys/channels or adds a product subscriber-inspection API.
func relayDeadlineRequireUnsubscribed(t *testing.T, service *fabric.Service) {
	t.Helper()
	value := reflect.ValueOf(service).Elem()
	for _, name := range []string{"nodeEvents", "spaceEvents"} {
		if value.FieldByName(name).Len() != 0 {
			t.Fatal("SSE subscription retained after handler return", name)
		}
	}
}
func TestRelayNodeSSEWriteDeadlineUnsupported(t *testing.T) {
	service, db, _ := newRelayNodeTestService(t)
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, db, "node-deadline", digest)
	w := &relayUnsupportedWriter{header: make(http.Header)}
	if _, err := relayNodeStreamController(w); !errors.Is(err, http.ErrNotSupported) {
		t.Fatal("unsupported writer did not return typed ErrNotSupported", err)
	}
	cycle := &relayDeadlineCycle{}
	if _, err := relayNodeStreamController(cycle); !errors.Is(err, http.ErrNotSupported) {
		t.Fatal("cyclic wrapper without setter did not fail bounded capability traversal", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v2/relay/nodes/node-deadline/events", nil)
	NewFabricHandler(service, "").(*Handler).relayNodeEvents(cycle, req, "node-deadline", token)
	if cycle.status != http.StatusInternalServerError || cycle.writes != 0 {
		t.Fatal("cyclic unsupported wrapper emitted a stream/body")
	}
	NewFabricHandler(service, "").(*Handler).relayNodeEvents(w, req, "node-deadline", token)
	if w.status != http.StatusInternalServerError || w.writes != 0 {
		t.Fatal("unsupported writer did not fail before body IO")
	}
	relayDeadlineRequireUnsubscribed(t, service)
}

type relayDeadlinePaddingResult struct {
	bytes int
	err   error
}

// Artificial padding amplifies one admitted frame to saturate a real socket.
// The peer stops reading; the production frame helper owns the deadline.
// This proves blocked IO cleanup, not ordinary tiny-frame saturation frequency.
type relayDeadlinePaddingWriter struct {
	http.ResponseWriter
	mode    string
	entered chan struct{}
	result  chan relayDeadlinePaddingResult
	once    sync.Once
	pending bool // Only the handler goroutine writes/flushes this wrapper.
}

func (w *relayDeadlinePaddingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *relayDeadlinePaddingWriter) pad() error {
	var err error
	w.once.Do(func() {
		close(w.entered)
		padding := []byte(":" + strings.Repeat(" ", 16<<20) + "\n")
		n, e := w.ResponseWriter.Write(padding)
		w.result <- relayDeadlinePaddingResult{n, e}
		err = e
		if e == nil && n != len(padding) {
			err = io.ErrShortWrite
		}
	})
	return err
}
func (w *relayDeadlinePaddingWriter) Write(b []byte) (int, error) {
	if string(b) == "event: wake\ndata: claim\n\n" {
		w.pending = true
		if w.mode == "write" {
			if err := w.pad(); err != nil {
				return 0, err
			}
		}
	}
	return w.ResponseWriter.Write(b)
}
func (w *relayDeadlinePaddingWriter) FlushError() error {
	if w.mode == "flush" && w.pending {
		if err := w.pad(); err != nil {
			return err
		}
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func relayDeadlineWait(t *testing.T, ch <-chan struct{}, budget time.Duration) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(budget):
		t.Fatal("bounded SSE phase watchdog expired")
	}
}
func relayDeadlineRequireTimeout(t *testing.T, result <-chan relayDeadlinePaddingResult) {
	t.Helper()
	select {
	case got := <-result:
		var timeout net.Error
		if got.bytes >= 16<<20 || got.err == nil || !errors.As(got.err, &timeout) || !timeout.Timeout() {
			t.Fatal("real socket backpressure did not end in a partial timed-out write")
		}
	case <-time.After(time.Second):
		t.Fatal("padding IO did not report terminal result")
	}
}

func TestRelayNodeSSEWriteDeadlineTCPBackpressure(t *testing.T) {
	for _, mode := range []string{"write-cancel", "flush-revoke"} {
		t.Run(mode, func(t *testing.T) {
			service, db, _ := newRelayNodeTestService(t)
			token, digest, err := fabric.NewNodeCredential()
			if err != nil {
				t.Fatal(err)
			}
			binding := bindRelayNodeTestCredential(t, db, "node-deadline", digest)
			entered, done := make(chan struct{}), make(chan struct{})
			result := make(chan relayDeadlinePaddingResult, 1)
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			handler := NewFabricHandler(service, "")
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				handler.ServeHTTP(&relayDeadlinePaddingWriter{ResponseWriter: w, mode: strings.Split(mode, "-")[0], entered: entered, result: result}, r)
			}))
			server.Config.BaseContext = func(net.Listener) context.Context { return base }
			server.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
				if tcp, ok := c.(*net.TCPConn); ok {
					if err := tcp.SetWriteBuffer(1024); err != nil {
						t.Error("private test send buffer", err)
					}
				}
				return ctx
			}
			server.Start()
			defer server.Close()
			connection, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if err := connection.(*net.TCPConn).SetReadBuffer(1024); err != nil {
				t.Fatal(err)
			}
			if err := connection.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(connection, "GET /v2/relay/nodes/node-deadline/events HTTP/1.1\r\nHost: synthetic.invalid\r\nAuthorization: CicadaNode "+token+"\r\n\r\n"); err != nil {
				t.Fatal("send private SSE request")
			}
			if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			request, _ := http.NewRequest(http.MethodGet, server.URL+"/v2/relay/nodes/node-deadline/events", nil)
			response, err := http.ReadResponse(bufio.NewReader(connection), request)
			if err != nil {
				t.Fatal("read actual socket SSE headers", err)
			}
			if response.StatusCode != 200 || relayDeadlineReadFrame(t, bufio.NewReader(response.Body)) != "event: ready\ndata: claim\n\n" {
				t.Fatal("established socket SSE ready unavailable")
			}
			if err := connection.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			service.NotifyNodeClaimHint("node-deadline")
			relayDeadlineWait(t, entered, 3*time.Second)
			select {
			case <-done:
				t.Fatal("socket padding did not reach an open stream")
			case <-time.After(100 * time.Millisecond):
			}
			started := time.Now()
			if strings.HasSuffix(mode, "cancel") {
				cancel()
			} else if _, err := db.RevokeNodeDeviceBinding(binding.OwnerID, binding.ID, binding.Version); err != nil {
				t.Fatal("actual Owner binding revoke", err)
			}
			relayDeadlineWait(t, done, relayNodeStreamWriteTimeout+3*time.Second)
			if time.Since(started) > relayNodeStreamWriteTimeout+3*time.Second {
				t.Fatal("blocked stream exceeded bounded cleanup")
			}
			relayDeadlineRequireTimeout(t, result)
			relayDeadlineRequireUnsubscribed(t, service)
			if _, err := db.GetClientHubID(); err != nil {
				t.Fatal("Store closed before SSE cleanup")
			}
		})
	}
}

func relayDeadlineReadFrame(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var frame strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal("read bounded SSE frame", err)
		}
		frame.WriteString(line)
		if line == "\n" {
			return frame.String()
		}
	}
}
func TestRelayNodeSSEWriteDeadlineIdleKeepalive(t *testing.T) {
	service, db, _ := newRelayNodeTestService(t)
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, db, "node-deadline", digest)
	done := make(chan struct{})
	handler := NewFabricHandler(service, "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		handler.ServeHTTP(relayDeadlineUnwrapper{w}, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v2/relay/nodes/node-deadline/events", nil)
	request.Header.Set("Authorization", "CicadaNode "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if response.StatusCode != 200 || relayDeadlineReadFrame(t, reader) != "event: ready\ndata: claim\n\n" {
		t.Fatal("ready frame unavailable")
	}
	start := time.Now()
	if relayDeadlineReadFrame(t, reader) != ": keepalive\n\n" || time.Since(start) < relayNodeStreamWriteTimeout {
		t.Fatal("real 25s idle keepalive did not survive the short frame deadline")
	}
	service.NotifyNodeClaimHint("node-deadline")
	if relayDeadlineReadFrame(t, reader) != "event: wake\ndata: claim\n\n" {
		t.Fatal("hint after keepalive unavailable")
	}
	response.Body.Close()
	cancel()
	relayDeadlineWait(t, done, 3*time.Second)
	relayDeadlineRequireUnsubscribed(t, service)
}
