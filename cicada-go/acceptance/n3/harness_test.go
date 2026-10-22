// Package n3_test owns disposable acceptance infrastructure, not a replacement
// product implementation. Until the production N3 runtime is integrated, its
// self-tests use only the already-frozen N2 activation transport.
package n3_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/store"
)

const harnessPacketLimit = 2 << 20 // Harness memory bound, not a wire limit.

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func hash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func atomicPrivate(t *testing.T, path string, raw []byte) {
	t.Helper()
	f, err := os.OpenFile(path+".next", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("owned fixture checkpoint cannot be created")
	}
	n, writeErr := f.Write(raw)
	syncErr, closeErr := f.Sync(), f.Close()
	if n != len(raw) || writeErr != nil || syncErr != nil || closeErr != nil || os.Rename(path+".next", path) != nil {
		t.Fatal("owned fixture checkpoint cannot be committed")
	}
	dir := must(os.Open(filepath.Dir(path)))
	defer dir.Close()
	if dir.Sync() != nil {
		t.Fatal("owned fixture checkpoint directory cannot be synced")
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw := must(json.Marshal(value))
	defer clear(raw)
	atomicPrivate(t, path, raw)
}

func readPrivate(t *testing.T, path string) []byte {
	t.Helper()
	f := must(os.Open(path))
	defer f.Close()
	raw := must(io.ReadAll(io.LimitReader(f, harnessPacketLimit+1)))
	if len(raw) > harnessPacketLimit {
		t.Fatal("owned fixture file exceeds its harness bound")
	}
	return raw
}

func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw := readPrivate(t, path)
	defer clear(raw)
	if json.Unmarshal(raw, value) != nil {
		t.Fatal("owned fixture checkpoint is invalid")
	}
}

func loopback(t *testing.T, origin string) {
	t.Helper()
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.User != nil {
		t.Fatal("acceptance transport permits only literal loopback fixtures")
	}
}

type process struct {
	cmd                  *exec.Cmd
	done                 chan struct{}
	appStartupDiagnostic string
}

func startProcess(t *testing.T, cmd *exec.Cmd) *process {
	t.Helper()
	// Child stdout/stderr are intentionally not inherited by evidence. Tests
	// exchange bounded display-safe checkpoints instead of private payloads.
	if err := cmd.Start(); err != nil {
		t.Fatal("owned child process could not start")
	}
	p := &process{cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() { p.kill(t) })
	return p
}

func (p *process) kill(t *testing.T) {
	t.Helper()
	if p == nil {
		return
	}
	if !p.running() {
		return
	}
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Error("owned process did not exit after SIGKILL")
	}
}

func (p *process) running() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func awaitMarker(t *testing.T, p *process, marker string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		select {
		case <-p.done:
			if p.appStartupDiagnostic != "" {
				var d appStartupDiagnostic
				if raw, err := os.ReadFile(p.appStartupDiagnostic); err == nil && len(raw) <= 1024 && json.Unmarshal(raw, &d) == nil {
					d = safeAppStartupDiagnostic(d)
					t.Fatalf("owned App exited before safe checkpoint: exit=%d phase=%s action=%s code=%s", p.cmd.ProcessState.ExitCode(), d.Phase, d.Action, d.ErrorCode)
				}
			}
			t.Fatal("owned process exited before its safe checkpoint")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("owned process checkpoint deadline exceeded")
}

type exchange struct {
	Method         string `json:"method"`
	Path           string `json:"path"`
	RequestSHA256  string `json:"request_sha256"`
	ResponseSHA256 string `json:"response_sha256,omitempty"`
	Forwarded      bool   `json:"forwarded"`
	Status         int    `json:"status"`
	request        []byte
	response       []byte
}

type faultProxy struct {
	server *httptest.Server
	origin string
	client *http.Client
	mu     sync.Mutex
	path   string
	method string
	mode   string
	count  int
	gate   *pausePoint
	gates  []*pausePoint
	trace  []exchange
}

type pausePoint struct {
	entered, release       chan struct{}
	enterOnce, releaseOnce sync.Once
}

func (g *pausePoint) unblock() { g.releaseOnce.Do(func() { close(g.release) }) }

func newFaultProxy(t *testing.T, origin string) *faultProxy {
	t.Helper()
	loopback(t, origin)
	p := &faultProxy{origin: origin, client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	p.server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(func() {
		p.mu.Lock()
		for _, gate := range p.gates {
			gate.unblock()
		}
		p.mu.Unlock()
		p.server.Close()
		for _, ex := range p.snapshot() {
			clear(ex.request)
			clear(ex.response)
		}
	})
	return p
}

func (p *faultProxy) arm(path, mode string, count int) (<-chan struct{}, func()) {
	return p.armMethod(path, "", mode, count)
}

// Discovery GET and the authorized POST can share a path. A mutation fault
// must not accidentally consume the discovery request that precedes it.
func (p *faultProxy) armMethod(path, method, mode string, count int) (<-chan struct{}, func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.path, p.method, p.mode, p.count = path, method, mode, count
	p.gate = &pausePoint{entered: make(chan struct{}), release: make(chan struct{})}
	p.gates = append(p.gates, p.gate)
	return p.gate.entered, p.gate.unblock
}

func (p *faultProxy) snapshot() []exchange {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]exchange(nil), p.trace...)
}

func (p *faultProxy) record(ex exchange) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.trace = append(p.trace, ex)
}

func (p *faultProxy) serve(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, harnessPacketLimit+1))
	if err != nil || len(raw) > harnessPacketLimit {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	mode := ""
	var gate *pausePoint
	if p.count > 0 && r.URL.Path == p.path && (p.method == "" || r.Method == p.method) {
		mode, gate = p.mode, p.gate
		p.count--
	}
	p.mu.Unlock()
	ex := exchange{Method: r.Method, Path: r.URL.Path, RequestSHA256: hash(raw), request: bytes.Clone(raw)}
	if mode == "unsupported-before-forward" || mode == "unknown-profile-before-forward" {
		ex.Status = http.StatusNotFound
		if mode == "unknown-profile-before-forward" {
			ex.Status, ex.response = http.StatusOK, []byte(`{"format":"SYNTHETIC_UNRECOGNIZED_CAPABILITY_PROFILE"}`)
			ex.ResponseSHA256 = hash(ex.response)
			w.Header().Set("Content-Type", "application/json")
		}
		p.record(ex)
		w.WriteHeader(ex.Status)
		_, _ = w.Write(ex.response)
		return
	}
	if mode == "before-forward" {
		p.record(ex)
		dropConnection(w)
		return
	}
	if mode == "hold-before-forward" {
		gate.enterOnce.Do(func() { close(gate.entered) })
		select {
		case <-gate.release:
		case <-r.Context().Done():
			p.record(ex)
			return
		}
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, p.origin+r.URL.RequestURI(), bytes.NewReader(raw))
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	req.Header = r.Header.Clone()
	resp, err := p.client.Do(req)
	ex.Forwarded = true
	if err != nil {
		p.record(ex)
		dropConnection(w)
		return
	}
	// A real resident Node probes/subscribes to its existing Relay event
	// stream. Forward headers and bounded chunks immediately; buffering an SSE
	// body would change the product's readiness behavior. This branch never
	// manufactures events and is not used for an armed RPC fault.
	if mode == "" && strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		defer resp.Body.Close()
		ex.Status = resp.StatusCode
		p.record(ex)
		for name, values := range resp.Header {
			w.Header()[name] = append([]string(nil), values...)
		}
		w.WriteHeader(resp.StatusCode)
		if flush, ok := w.(http.Flusher); ok {
			flush.Flush()
		}
		buffer := make([]byte, 4096)
		for {
			n, readErr := resp.Body.Read(buffer)
			if n > 0 {
				if _, err := w.Write(buffer[:n]); err != nil {
					return
				}
				if flush, ok := w.(http.Flusher); ok {
					flush.Flush()
				}
			}
			if readErr != nil {
				return
			}
		}
	}
	response, err := io.ReadAll(io.LimitReader(resp.Body, harnessPacketLimit+1))
	resp.Body.Close()
	if err != nil || len(response) > harnessPacketLimit {
		p.record(ex)
		dropConnection(w)
		return
	}
	ex.Status, ex.ResponseSHA256, ex.response = resp.StatusCode, hash(response), bytes.Clone(response)
	p.record(ex)
	if mode == "hold-after-response" {
		gate.enterOnce.Do(func() { close(gate.entered) })
		select {
		case <-gate.release:
		case <-r.Context().Done():
			return
		}
	}
	if mode == "drop-after-response" {
		dropConnection(w)
		return
	}
	if mode == "unsigned-403" || mode == "unsigned-429" || mode == "unsigned-500" {
		status := http.StatusForbidden
		if mode == "unsigned-429" {
			status = http.StatusTooManyRequests
		} else if mode == "unsigned-500" {
			status = http.StatusInternalServerError
		}
		w.WriteHeader(status)
		return
	}
	if mode == "corrupt-response" && len(response) > 0 {
		response[len(response)/2] ^= 1
	}
	for name, values := range resp.Header {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(response)
}

func dropConnection(w http.ResponseWriter) {
	if h, ok := w.(http.Hijacker); ok {
		if conn, _, err := h.Hijack(); err == nil {
			conn.Close()
			return
		}
	}
	w.WriteHeader(http.StatusBadGateway)
}

type fixtureConfig struct {
	Origin   string                  `json:"origin"`
	Hub      wire.HubIdentity        `json:"hub"`
	Material wire.ActivationMaterial `json:"synthetic_n2_material"`
}

type hubFixture struct {
	dir    string
	cfg    fixtureConfig
	hub    *process
	proxy  *faultProxy
	parent *testing.T
	mode   string
	// Product integration keeps the public canonical loopback origin on the
	// opaque fault proxy and binds the real Hub to a separate private port.
	listenOrigin string
}

func newHubFixture(t *testing.T) *hubFixture {
	return newHubFixtureMode(t, "--hub-only")
}

func newNodeHubFixture(t *testing.T) *hubFixture {
	return newHubFixtureMode(t, "--hub-nodes-only")
}

func newHubFixtureMode(t *testing.T, mode string) *hubFixture {
	return newHubFixtureAt(t, mode, t.TempDir())
}

func newHubFixtureAt(t *testing.T, mode, dir string) *hubFixture {
	t.Helper()
	return newHubFixtureAtProxied(t, mode, dir, false)
}

func newHubFixtureAtProxied(t *testing.T, mode, dir string, proxied bool) *hubFixture {
	t.Helper()
	listener := must(net.Listen("tcp", "127.0.0.1:0"))
	origin := "http://" + listener.Addr().String()
	listener.Close()
	listenOrigin := origin
	var proxy *faultProxy
	if proxied {
		proxy = newFaultProxy(t, listenOrigin)
		origin = proxy.server.URL
	}
	state := filepath.Join(dir, "synthetic-hub")
	db := must(store.New(filepath.Join(state, "cicada.sqlite3")))
	must(db.InitializeHubOwnerLocal("Synthetic N3 harness transport ONLY", origin, true))
	ids := must(hubidentity.LoadOrCreate(state, ""))
	auth := must(hubauth.NewService(db, ids))
	f := &hubFixture{dir: dir, parent: t, mode: mode, cfg: fixtureConfig{Origin: origin, Hub: must(auth.HubIdentity()), Material: *must(auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false))}}
	f.listenOrigin, f.proxy = listenOrigin, proxy
	if db.Close() != nil {
		t.Fatal("owned Hub bootstrap Store did not close")
	}
	writeJSON(t, filepath.Join(dir, "synthetic-config.json"), f.cfg)
	f.start(t)
	if f.proxy == nil {
		f.proxy = newFaultProxy(t, origin)
	}
	return f
}

func (f *hubFixture) start(t *testing.T) {
	t.Helper()
	binary := os.Getenv("CICADA_N3_CICADA_BINARY")
	if binary == "" {
		t.Fatal("explicit acceptance-built Cicada executable required")
	}
	listenOrigin := f.listenOrigin
	if listenOrigin == "" {
		listenOrigin = f.cfg.Origin
	}
	u := must(url.Parse(listenOrigin))
	if f.mode != "--hub-only" && f.mode != "--hub-nodes-only" {
		t.Fatal("unreviewed acceptance Hub composition")
	}
	cmd := exec.Command(binary, "serve", f.mode, "--state-dir", filepath.Join(f.dir, "synthetic-hub"), "--host", u.Hostname(), "--port", u.Port())
	f.hub = startProcess(f.parent, cmd)
	deadline := time.Now().Add(15 * time.Second)
	client := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		select {
		case <-f.hub.done:
			t.Fatal("actual Hub CLI exited before exposing the reviewed composition")
		default:
		}
		resp, err := client.Get(f.cfg.Origin + "/v2/client/identity")
		if err == nil {
			raw := must(io.ReadAll(io.LimitReader(resp.Body, harnessPacketLimit)))
			resp.Body.Close()
			var got wire.HubIdentity
			if resp.StatusCode == 200 && json.Unmarshal(raw, &got) == nil && must(wire.HubFingerprint(got)) == must(wire.HubFingerprint(f.cfg.Hub)) {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("owned Hub CLI did not expose its expected identity")
}

func (f *hubFixture) db(t *testing.T) *store.Store {
	t.Helper()
	if f.hub.running() {
		t.Fatal("stop the owned Hub before opening another Store")
	}
	return must(store.New(filepath.Join(f.dir, "synthetic-hub", "cicada.sqlite3")))
}

type packetCheckpoint struct {
	Actor          string `json:"actor"`
	PacketSHA256   string `json:"packet_sha256"`
	ResponseSHA256 string `json:"response_sha256"`
	Status         int    `json:"status"`
	TransportError bool   `json:"transport_error"`
}

func startPacketProcess(t *testing.T, f *hubFixture, target, path, marker string) *process {
	t.Helper()
	executable := must(os.Executable())
	cmd := exec.Command(executable, "-test.run=^TestN3HarnessPacketProcess$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "CICADA_N3_PACKET_CHILD=1", "CICADA_N3_FIXTURE="+f.dir, "CICADA_N3_TARGET="+target, "CICADA_N3_PATH="+path, "CICADA_N3_MARKER="+marker)
	return startProcess(t, cmd)
}

// This child is a raw, opaque packet sender, NOT the production App. Its only
// role is to verify the crash/fault infrastructure. The production App core is
// a separate actor; no raw sender result accepts the N3 App or Node workflow.
func TestN3HarnessPacketProcess(t *testing.T) {
	if os.Getenv("CICADA_N3_PACKET_CHILD") == "" {
		return
	}
	dir, target := os.Getenv("CICADA_N3_FIXTURE"), os.Getenv("CICADA_N3_TARGET")
	loopback(t, target)
	var cfg fixtureConfig
	readJSON(t, filepath.Join(dir, "synthetic-config.json"), &cfg)
	loopback(t, cfg.Origin)
	raw := readPrivate(t, filepath.Join(dir, "synthetic-request.packet"))
	defer clear(raw)
	pending := filepath.Join(dir, "synthetic-pending.packet")
	if old, err := os.ReadFile(pending); err == nil {
		if !bytes.Equal(old, raw) {
			t.Fatal("packet harness tried replacing an uncertain original")
		}
		clear(old)
	} else if os.IsNotExist(err) {
		atomicPrivate(t, pending, raw)
	} else {
		t.Fatal("packet harness pending checkpoint unavailable")
	}
	req := must(http.NewRequest(http.MethodPost, target+os.Getenv("CICADA_N3_PATH"), bytes.NewReader(raw)))
	req.Header.Set("Origin", cfg.Origin)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	checkpoint := packetCheckpoint{Actor: "opaque-packet-harness-not-App", PacketSHA256: hash(raw), TransportError: err != nil}
	if err == nil {
		response := must(io.ReadAll(io.LimitReader(resp.Body, harnessPacketLimit+1)))
		resp.Body.Close()
		if len(response) > harnessPacketLimit {
			t.Fatal("packet harness response bound exceeded")
		}
		checkpoint.Status, checkpoint.ResponseSHA256 = resp.StatusCode, hash(response)
		atomicPrivate(t, filepath.Join(dir, "synthetic-response.packet"), response)
		clear(response)
	}
	writeJSON(t, os.Getenv("CICADA_N3_MARKER"), checkpoint)
	select {} // Parent must kill the actual process before reopening disk state.
}
