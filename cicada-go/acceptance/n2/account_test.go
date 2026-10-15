// Package n2_test is an independent acceptance consumer. It never supplies a
// replacement Hub/App implementation. Every key and credential is synthetic.
package n2_test

import (
	"bytes"
	"context"
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

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

const syntheticPassword = "Synthetic acceptance meadow 472!"

type fixtureConfig struct {
	Origin     string
	Card       wire.ClaimCard
	Hub        wire.HubIdentity
	Activation *wire.ActivationMaterial
}

type child struct {
	cmd  *exec.Cmd
	done chan error
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("fixture JSON encode failed")
	}
	defer clear(raw)
	if err := os.WriteFile(path+".next", raw, 0600); err != nil {
		t.Fatal("fixture file write failed")
	}
	if err := os.Rename(path+".next", path); err != nil {
		t.Fatal("fixture marker commit failed")
	}
}
func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture file read failed")
	}
	defer clear(raw)
	if json.Unmarshal(raw, value) != nil {
		t.Fatal("fixture JSON decode failed")
	}
}
func must[T any](value T, err error) T {
	if err != nil {
		panic("synthetic fixture operation failed")
	}
	return value
}
func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func spawn(t *testing.T, dir, role, marker string, extra ...string) *child {
	t.Helper()
	_ = os.Remove(marker) // exact owned marker only
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestN2ProcessHelper$", "-test.timeout=120s")
	cmd.Env = append(os.Environ(), "CICADA_N2_CHILD="+role, "CICADA_N2_DIR="+dir, "CICADA_N2_MARKER="+marker)
	cmd.Env = append(cmd.Env, extra...)
	// Child diagnostics cannot contain a full snapshot, key, request or response.
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal("fixture process start failed")
	}
	c := &child{cmd: cmd, done: make(chan error, 1)}
	go func() { c.done <- cmd.Wait() }()
	t.Cleanup(func() { c.kill(t) })
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-c.done:
			c.done = nil
			t.Fatalf("fixture %s exited before marker: %v; synthetic diagnostics: %s", role, err, output.String())
		case <-deadline.C:
			t.Fatalf("fixture %s did not reach bounded checkpoint", role)
		case <-tick.C:
			if _, err := os.Stat(marker); err == nil {
				return c
			}
		}
	}
}
func (c *child) kill(t *testing.T) {
	t.Helper()
	if c == nil || c.done == nil {
		return
	}
	_ = c.cmd.Process.Kill()
	select {
	case <-c.done:
		c.done = nil
	case <-time.After(5 * time.Second):
		t.Error("owned child did not exit after kill")
	}
}

type fixture struct {
	owner *testing.T
	dir   string
	cfg   fixtureConfig
	hub   *child
	proxy *faultProxy
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	listener := must(net.Listen("tcp", "127.0.0.1:0"))
	origin := "http://" + listener.Addr().String()
	listener.Close()
	db := must(store.New(filepath.Join(dir, "hub", "synthetic.sqlite3")))
	must(db.InitializeHubOwnerLocal("Synthetic N2 acceptance Owner", origin, true))
	ids := must(hubidentity.LoadOrCreate(filepath.Join(dir, "hub"), ""))
	auth := must(hubauth.NewService(db, ids))
	card := must(auth.IssueClaimLocal(false))
	cfg := fixtureConfig{Origin: origin, Card: *card, Hub: must(auth.HubIdentity())}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(dir, "synthetic-config.json"), cfg)
	f := &fixture{owner: t, dir: dir, cfg: cfg}
	f.start(t)
	f.proxy = newFaultProxy(t, origin)
	return f
}
func (f *fixture) start(t *testing.T) {
	f.hub = spawn(f.owner, f.dir, "hub", filepath.Join(f.dir, "hub-ready"))
}
func (f *fixture) restart(t *testing.T) { f.hub.kill(t); f.start(t) }
func (f *fixture) db(t *testing.T) *store.Store {
	t.Helper()
	// Caller must stop the Hub before opening a second Store.
	if f.hub.done != nil {
		t.Fatal("cannot inspect fixture Store while Hub is running")
	}
	return must(store.New(filepath.Join(f.dir, "hub", "synthetic.sqlite3")))
}

// This runs the production Hub identity/account handler without creating a
// Control service. The App helper uses the public Controller interface only.
func TestN2ProcessHelper(t *testing.T) {
	role := os.Getenv("CICADA_N2_CHILD")
	if role == "" {
		return
	}
	dir, marker := os.Getenv("CICADA_N2_DIR"), os.Getenv("CICADA_N2_MARKER")
	var cfg fixtureConfig
	readJSON(t, filepath.Join(dir, "synthetic-config.json"), &cfg)
	switch role {
	case "hub":
		db := must(store.New(filepath.Join(dir, "hub", "synthetic.sqlite3")))
		defer db.Close()
		ids := must(hubidentity.LoadOrCreate(filepath.Join(dir, "hub"), ""))
		owner := must(hubowner.NewService(db, ids))
		auth := must(hubauth.NewService(db, ids))
		address := must(url.Parse(cfg.Origin)).Host
		listener := must(net.Listen("tcp", address))
		h := &http.Server{Handler: server.NewHubHandlerWithAccount(owner, auth), ReadHeaderTimeout: 5 * time.Second}
		go h.Serve(listener)
		writeJSON(t, marker, struct{ Ready bool }{true})
	case "app":
		c := newController(t, dir, proxyDoer{target: os.Getenv("CICADA_N2_PROXY"), client: appcore.NewHTTPClient()})
		defer c.Close()
		code := must(appcore.NewActivationCode(cfg.Card)).Encode()
		if err := c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionConnect, ActivationCode: code}); err != nil {
			t.Fatal("App connect failed")
		}
		step := os.Getenv("CICADA_N2_STEP")
		action := actions()[step]
		if step == "complete" {
			if err := c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionGenerateOwner}); err != nil {
				t.Fatal("App Owner generation failed")
			}
		}
		err := c.Dispatch(context.Background(), action)
		uncertain := os.Getenv("CICADA_N2_UNCERTAIN") == "1"
		snapshot := c.Snapshot()
		if uncertain {
			if err == nil || (snapshot.ErrorCode != "ACCOUNT_RESPONSE_UNKNOWN" && snapshot.ErrorCode != "ACCOUNT_RESPONSE_INVALID") || !hasAction(snapshot, appcore.ActionRetry) {
				t.Fatal("unsigned/missing response settled pending operation")
			}
			if c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionLoginPrepare, Username: "synthetic-user"}) == nil {
				t.Fatal("uncertainty allowed replacement operation")
			}
		} else if err != nil {
			t.Fatal("App action/recovery failed")
		}
		snapshot = c.Snapshot()
		if snapshot.Management != appcore.ManagementUnavailable || snapshot.Account.RootState == appcore.RootStateActive || snapshot.Phase == appcore.PhaseOwnerReady {
			t.Fatal("account flow acquired Root/Manager authority")
		}
		if os.Getenv("CICADA_N2_EXPECT_SESSION") == "1" && (snapshot.Phase != appcore.PhaseAccountSession || snapshot.Account.RootState != appcore.RootStatePending) {
			t.Fatal("authenticated inspection did not report pending Root")
		}
		writeJSON(t, marker, struct {
			Ready bool
			Phase appcore.Phase
			Root  appcore.RootState
		}{true, snapshot.Phase, snapshot.Account.RootState})
	case "app-n2":
		runActivationAppProcess(t, dir, cfg, marker)
	default:
		t.Fatal("unknown fixture role")
	}
	// Parent deliberately SIGKILLs this process at a durable marker.
	select {}
}
func actions() map[string]appcore.Action {
	return map[string]appcore.Action{
		"prepare":        {Kind: appcore.ActionClaimPrepare},
		"complete":       {Kind: appcore.ActionClaimComplete, Username: "synthetic-user", Password: syntheticPassword},
		"login_prepare":  {Kind: appcore.ActionLoginPrepare, Username: "synthetic-user"},
		"login_complete": {Kind: appcore.ActionLoginComplete, Password: syntheticPassword},
		"inspect":        {Kind: appcore.ActionSessionInspect},
		"logout":         {Kind: appcore.ActionLogout},
		"retry":          {Kind: appcore.ActionRetry},
	}
}
func newController(t *testing.T, dir string, doer appcore.HTTPDoer) appcore.Controller {
	return newControllerWithClock(t, dir, doer, nil)
}
func newControllerWithClock(t *testing.T, dir string, doer appcore.HTTPDoer, now func() time.Time) appcore.Controller {
	t.Helper()
	opener := func(_ context.Context, scope appvault.Scope, create bool) (*appvault.Vault, error) {
		b, _ := json.Marshal(scope)
		root := filepath.Join(dir, "app")
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, err
		}
		path := filepath.Join(root, digest(b)+".vault")
		p, err := appvault.NewPasswordProtector([]byte("Synthetic acceptance vault passphrase"))
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(path); os.IsNotExist(err) && create {
			return appvault.Create(path, scope, p)
		}
		return appvault.Open(path, scope, p)
	}
	return must(appcore.NewController(appcore.Config{HTTP: doer, OpenVault: opener, DiscoverVaults: appcore.NewProfileDiscovery(filepath.Join(dir, "app")), AllowLoopbackHTTP: true, Now: now}))
}
func hasAction(s appcore.Snapshot, a appcore.ActionKind) bool {
	for _, x := range s.AvailableActions {
		if x == a {
			return true
		}
	}
	return false
}

type proxyDoer struct {
	target string
	client *http.Client
}

func (p proxyDoer) Do(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	target, err := url.Parse(p.target)
	if err != nil {
		return nil, err
	}
	clone.URL.Scheme, clone.URL.Host = target.Scheme, target.Host
	resp, err := p.client.Do(clone)
	if resp != nil {
		resp.Request = r
	}
	return resp, err
}

type exchange struct {
	Path           string
	RequestSHA256  string
	ResponseSHA256 string
	Status         int
	Forwarded      bool
	request        []byte // Memory only; never exported to evidence.
	response       []byte
}
type faultProxy struct {
	mu        sync.Mutex
	server    *httptest.Server
	origin    string
	mode      string
	path      string
	remaining int
	exchanges []exchange
}

func newFaultProxy(t *testing.T, origin string) *faultProxy {
	p := &faultProxy{origin: origin}
	p.server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(func() {
		p.server.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, ex := range p.exchanges {
			clear(ex.request)
			clear(ex.response)
		}
	})
	return p
}
func (p *faultProxy) arm(mode, path string) {
	p.armCount(mode, path, 1)
}
func (p *faultProxy) armCount(mode, path string, count int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mode, p.path, p.remaining = mode, path, count
}
func (p *faultProxy) snapshot() []exchange {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]exchange(nil), p.exchanges...)
}
func (p *faultProxy) serve(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxPacketBytes+1))
	if err != nil {
		w.WriteHeader(502)
		return
	}
	defer clear(raw)
	p.mu.Lock()
	mode := ""
	if r.Method == http.MethodPost && r.URL.Path == p.path {
		mode = p.mode
		p.remaining--
		if p.remaining <= 0 {
			p.mode = ""
		}
	}
	p.mu.Unlock()
	ex := exchange{Path: r.URL.Path, RequestSHA256: digest(raw), Forwarded: mode != "before", request: bytes.Clone(raw)}
	drop := func() {
		conn, _, e := w.(http.Hijacker).Hijack()
		if e == nil {
			conn.Close()
		}
	}
	if mode == "before" {
		p.mu.Lock()
		p.exchanges = append(p.exchanges, ex)
		p.mu.Unlock()
		drop()
		return
	}
	upstream, err := http.NewRequestWithContext(r.Context(), r.Method, p.origin+r.URL.RequestURI(), bytes.NewReader(raw))
	if err != nil {
		w.WriteHeader(502)
		return
	}
	upstream.Header = r.Header.Clone()
	response, err := http.DefaultClient.Do(upstream)
	if err != nil {
		w.WriteHeader(502)
		return
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxPacketBytes+1))
	if err != nil {
		w.WriteHeader(502)
		return
	}
	defer clear(body)
	ex.Status, ex.ResponseSHA256 = response.StatusCode, digest(body)
	ex.response = bytes.Clone(body)
	if r.Method == http.MethodPost {
		p.mu.Lock()
		p.exchanges = append(p.exchanges, ex)
		p.mu.Unlock()
	}
	switch mode {
	case "drop":
		drop()
		return
	case "unsigned403":
		w.WriteHeader(403)
		_, _ = io.WriteString(w, "synthetic untrusted intermediary denial")
		return
	case "corrupt":
		if len(body) > 0 {
			body[len(body)/2] ^= 1
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(body)
}

func TestN2AccountProcessRecovery(t *testing.T) {
	for _, mode := range []string{"before", "drop", "unsigned403", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			for _, step := range []string{"prepare", "complete", "login_prepare", "login_complete", "inspect", "logout"} {
				t.Run(step, func(t *testing.T) {
					path := map[string]string{"prepare": "claim/prepare", "complete": "claim/complete", "login_prepare": "login/prepare", "login_complete": "login/complete", "inspect": "session/inspect", "logout": "session/logout"}[step]
					f.proxy.arm(mode, "/v2/owner/account/"+path)
					app := spawn(t, f.dir, "app", filepath.Join(f.dir, "app-ready"), "CICADA_N2_PROXY="+f.proxy.server.URL, "CICADA_N2_STEP="+step, "CICADA_N2_UNCERTAIN=1")
					app.kill(t)
					before := f.proxy.snapshot()
					original := before[len(before)-1]
					if mode != "before" && original.Status != http.StatusOK {
						t.Fatal("fault was injected before a successful Hub commit")
					}
					f.restart(t) // actual SIGKILL + SQLite/key reopen at the same origin
					extra := []string{"CICADA_N2_PROXY=" + f.proxy.server.URL, "CICADA_N2_STEP=retry"}
					if step == "inspect" {
						extra = append(extra, "CICADA_N2_EXPECT_SESSION=1")
					}
					recovery := spawn(t, f.dir, "app", filepath.Join(f.dir, "app-ready"), extra...)
					recovery.kill(t)
					after := f.proxy.snapshot()
					delta := after[len(before):]
					if len(delta) == 0 {
						t.Fatal("recovery did not send the original packet")
					}
					retry := delta[0]
					if retry.Path != original.Path || !bytes.Equal(retry.request, original.request) || retry.Status != http.StatusOK {
						t.Fatal("recovery changed the original packet/path or did not authenticate")
					}
					if mode != "before" && !bytes.Equal(retry.response, original.response) {
						t.Fatal("exact retry did not recover the immutable original response")
					}
					if step == "inspect" {
						if len(delta) != 2 || delta[1].Path != retry.Path || delta[1].Status != http.StatusOK || bytes.Equal(delta[1].request, retry.request) {
							t.Fatal("inspection recovery did not follow the original receipt with a distinct fresh current-state inspection")
						}
						t.Logf("CURRENT_INSPECTION packet_sha256=%s response_sha256=%s", delta[1].RequestSHA256, delta[1].ResponseSHA256)
					} else if len(delta) != 1 {
						t.Fatal("recovery sent an unexpected replacement operation")
					}
					t.Logf("EXACT_RECOVERY mode=%s path=%s packet_sha256=%s response_sha256=%s", mode, retry.Path, retry.RequestSHA256, retry.ResponseSHA256)
				})
				if t.Failed() {
					return
				}
			}
			f.hub.kill(t)
			db := f.db(t)
			defer db.Close()
			status := must(db.HubAccountStatus(f.cfg.Card.AccountID))
			if status.RootActive || status.RootState != wire.RootPendingState || status.OwnerID != f.cfg.Card.OwnerID || len(status.Devices) != 1 {
				t.Fatal("durable identity/authority changed across process recovery")
			}
		})
	}
}

func TestN2AccountPinAndExpiryBeforeSecrets(t *testing.T) {
	f := newFixture(t)
	for _, kind := range []string{"wrong-full-pin", "expired"} {
		t.Run(kind, func(t *testing.T) {
			card := f.cfg.Card
			if kind == "wrong-full-pin" {
				other := must(e2ee.NewIdentity())
				fake := f.cfg.Hub
				fake.Public = other.Public()
				card.HubFingerprint = must(wire.HubFingerprint(fake))
			} else {
				now := time.Now().UTC()
				card.IssuedAt = now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
				card.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
			}
			calls := 0
			opener := func(context.Context, appvault.Scope, bool) (*appvault.Vault, error) {
				calls++
				return nil, appvault.ErrStateNotFound
			}
			c := must(appcore.NewController(appcore.Config{HTTP: proxyDoer{f.proxy.server.URL, appcore.NewHTTPClient()}, OpenVault: opener, AllowLoopbackHTTP: true}))
			defer c.Close()
			code := must(appcore.NewActivationCode(card)).Encode()
			if c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionConnect, ActivationCode: code}) == nil {
				t.Fatal("untrusted/expired connection was accepted")
			}
			if calls != 0 || len(f.proxy.snapshot()) != 0 || c.Snapshot().Hub.Verified {
				t.Fatal("rejected connection opened vault or sent a secret packet")
			}
		})
	}
}

func post(t *testing.T, f *fixture, path string, packet []byte) (int, []byte) {
	t.Helper()
	for attempt := 0; attempt < 80; attempt++ {
		req := must(http.NewRequest(http.MethodPost, f.cfg.Origin+path, bytes.NewReader(packet)))
		req.Header.Set("Origin", f.cfg.Origin)
		resp := must(http.DefaultClient.Do(req))
		raw := must(io.ReadAll(io.LimitReader(resp.Body, wire.MaxPacketBytes+1)))
		resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests {
			return resp.StatusCode, raw
		}
		clear(raw)
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("owned Hub admission did not recover within bounded exact retries")
	return 0, nil
}
func seal(t *testing.T, f *fixture, key *e2ee.Identity, body any) []byte {
	t.Helper()
	return must(wire.SealClientRequest(key, f.cfg.Hub, body))
}

func TestN2AccountConcurrentClaimAndConflictingReplay(t *testing.T) {
	f := newFixture(t)
	keys := []*e2ee.Identity{must(e2ee.NewIdentity()), must(e2ee.NewIdentity())}
	packets := make([][]byte, 2)
	for i := range keys {
		packets[i] = seal(t, f, keys[i], must(wire.NewClaimPrepare(f.cfg.Card, f.cfg.Hub, keys[i].Public(), time.Now().UTC())))
	}
	type result struct {
		code int
		body []byte
		err  error
	}
	results := make([]result, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range keys {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			req, e := http.NewRequest(http.MethodPost, f.cfg.Origin+"/v2/owner/account/claim/prepare", bytes.NewReader(packets[i]))
			if e != nil {
				results[i].err = e
				return
			}
			resp, e := http.DefaultClient.Do(req)
			if e != nil {
				results[i].err = e
				return
			}
			defer resp.Body.Close()
			results[i].code = resp.StatusCode
			results[i].body, results[i].err = io.ReadAll(resp.Body)
		}(i)
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, r := range results {
		if r.err != nil {
			t.Fatal("candidate transport failed")
		}
		if r.code == 200 {
			if winner != -1 {
				t.Fatal("two distinct candidates won the one-use claim")
			}
			winner = i
		} else if r.code != 403 {
			t.Fatalf("loser status=%d, want 403", r.code)
		}
	}
	if winner < 0 {
		t.Fatal("no candidate won")
	}
	var challenge wire.ClaimChallenge
	if wire.OpenClientResponse(keys[winner], f.cfg.Hub, packets[winner], results[winner].body, &challenge) != nil {
		t.Fatal("winner challenge is unauthenticated")
	}
	f.restart(t)
	code, body := post(t, f, "/v2/owner/account/claim/prepare", packets[winner])
	if code != 200 || !bytes.Equal(body, results[winner].body) {
		t.Fatal("winner exact prepare did not survive process restart")
	}
	changed := must(wire.NewClaimPrepare(f.cfg.Card, f.cfg.Hub, keys[winner].Public(), time.Now().UTC()))
	if code, _ := post(t, f, "/v2/owner/account/claim/prepare", seal(t, f, keys[winner], changed)); code != 403 {
		t.Fatal("changed request stole reserved claim")
	}
	candidate := must(e2ee.NewIdentity())
	complete := must(wire.NewClaimCompleteFromChallenge(f.cfg.Hub, challenge, keys[winner].Public(), "synthetic-user", syntheticPassword, candidate.Public(), time.Now().UTC()))
	packet := seal(t, f, keys[winner], complete)
	code, receipt := post(t, f, "/v2/owner/account/claim/complete", packet)
	if code != 200 {
		t.Fatal("winner account complete failed")
	}
	var accepted wire.ClaimReceipt
	if wire.OpenClientResponse(keys[winner], f.cfg.Hub, packet, receipt, &accepted) != nil || accepted.RootActive || accepted.RootState != wire.RootPendingState {
		t.Fatal("account receipt forged Root authority")
	}
	f.restart(t)
	if code, again := post(t, f, "/v2/owner/account/claim/complete", packet); code != 200 || !bytes.Equal(again, receipt) {
		t.Fatal("consumed exact completion lost receipt")
	}
	// Same request ID and body with newly randomized PQ ciphertext is a conflict.
	if code, _ := post(t, f, "/v2/owner/account/claim/complete", seal(t, f, keys[winner], complete)); code != 403 {
		t.Fatal("resealed consumed completion accepted")
	}
	f.hub.kill(t)
	db := f.db(t)
	defer db.Close()
	status := must(db.HubAccountStatus(f.cfg.Card.AccountID))
	if status.OwnerPublic.ID != candidate.Public().ID || status.OwnerID != f.cfg.Card.OwnerID || status.RootActive || len(status.Devices) != 1 {
		t.Fatal("concurrent claim changed durable candidate or authority")
	}
}

func TestN2AccountForeignScopeAndMissingDeviceProof(t *testing.T) {
	f := newFixture(t)
	key := must(e2ee.NewIdentity())
	request := must(wire.NewClaimPrepare(f.cfg.Card, f.cfg.Hub, key.Public(), time.Now().UTC()))
	packet := seal(t, f, key, request)
	for _, kind := range []string{"wrong-owner", "wrong-hub", "missing-signature", "forged-ciphertext"} {
		t.Run(kind, func(t *testing.T) {
			p := must(wire.DecodePacket(packet))
			switch kind {
			case "wrong-owner":
				p.Packet.Route.OwnerID = "synthetic-foreign-owner"
			case "wrong-hub":
				p.Packet.Route.HubID = "synthetic-foreign-hub"
			case "missing-signature":
				var envelope map[string]json.RawMessage
				if json.Unmarshal(p.Packet.Envelope, &envelope) != nil {
					t.Fatal("synthetic envelope decode failed")
				}
				delete(envelope, "signature")
				p.Packet.Envelope = must(json.Marshal(envelope))
			case "forged-ciphertext":
				p.Packet.Envelope[0] ^= 1
			}
			raw := must(json.Marshal(p))
			if code, _ := post(t, f, "/v2/owner/account/claim/prepare", raw); code != 403 {
				t.Fatal("foreign scope or missing/bad device proof accepted")
			}
		})
	}
	// None of the rejected packets may consume the real claim.
	if code, _ := post(t, f, "/v2/owner/account/claim/prepare", packet); code != 200 {
		t.Fatal("rejected packet changed finite claim state")
	}
}

// This deliberately describes a baseline boundary, not an N2 activation test.
func TestN2AccountUnknownDeviceCannotUsePassword(t *testing.T) {
	f := newFixture(t)
	for _, step := range []string{"prepare", "complete", "login_prepare", "login_complete", "inspect"} {
		extra := []string{"CICADA_N2_PROXY=" + f.proxy.server.URL, "CICADA_N2_STEP=" + step}
		if step == "inspect" {
			extra = append(extra, "CICADA_N2_EXPECT_SESSION=1")
		}
		app := spawn(t, f.dir, "app", filepath.Join(f.dir, "app-ready"), extra...)
		app.kill(t)
	}
	f.hub.kill(t)
	db := f.db(t)
	status := must(db.HubAccountStatus(f.cfg.Card.AccountID))
	db.Close()
	f.start(t)
	attacker := must(e2ee.NewIdentity())
	req := must(wire.NewLoginPrepare(f.cfg.Hub, f.cfg.Origin, f.cfg.Card.AccountID, f.cfg.Card.OwnerID, status.Devices[0].DeviceID, "synthetic-user", attacker.Public(), time.Now().UTC()))
	if code, _ := post(t, f, "/v2/owner/account/login/prepare", seal(t, f, attacker, req)); code != 403 {
		t.Fatal("substituted App key inherited enrolled device identity")
	}
	req.OwnerID = "synthetic-foreign-owner"
	if code, _ := post(t, f, "/v2/owner/account/login/prepare", seal(t, f, attacker, req)); code != 403 {
		t.Fatal("foreign Owner selected account")
	}
	// Cookie/bearer-only traffic cannot replace the signed PQ account packet.
	request := must(http.NewRequest(http.MethodPost, f.cfg.Origin+"/v2/owner/account/session/inspect", strings.NewReader(`{}`)))
	request.AddCookie(&http.Cookie{Name: "session", Value: "synthetic-untrusted-hint"})
	response := must(http.DefaultClient.Do(request))
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("cookie-only request acquired account authority")
	}
}
