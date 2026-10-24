package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubnodes"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

type nodePairLocalFixture struct {
	native               nativeNodeFixture
	state, node, address string
	http                 *http.Client
	server               *httptest.Server
}

func newNodePairLocalFixture(t *testing.T) nodePairLocalFixture {
	t.Helper()
	t.Setenv("CICADA_CONTROL_URL", "")
	t.Setenv("CICADA_NODE_PQTLS_CONFIG", "")
	f := nodePairLocalFixture{native: newNativeNodeFixture(t), state: filepath.Join(t.TempDir(), "node"), node: "SYNTHETIC-local-pair"}
	hubState := filepath.Dir(f.native.file)
	db, e := store.New(filepath.Join(hubState, "cicada.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	ids, e := hubidentity.LoadOrCreate(hubState, "")
	if e != nil {
		t.Fatal(e)
	}
	owner, e := hubowner.NewService(db, ids)
	if e != nil {
		t.Fatal(e)
	}
	auth, e := hubauth.NewServiceWithNodeAuthority(db, ids)
	if e != nil {
		t.Fatal(e)
	}
	nodes, e := hubnodes.NewService(db, ids)
	if e != nil {
		t.Fatal(e)
	}
	handler := serverpkg.NewHubNodesHandler(owner, auth, nodes)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hubauth.NodePairTrustOperationForPath(r.URL.Path) != "" && (r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "") {
			t.Error("preproof pairing sent a credential header")
		}
		handler.ServeHTTP(w, r)
	}))
	f.server.TLS = f.native.profile.TLSConfig()
	f.server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return f.native.profile.TLSConfig(), nil }
	f.server.StartTLS()
	f.address = f.server.Listener.Addr().String()
	f.http, e = hubtransport.NewHTTPClient(f.native.d, f.address, 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		f.http.CloseIdleConnections()
		f.server.Close()
		db.Close()
		_, path := machineNodeControlPaths(f.state, f.node)
		machineNodeControlClients.Delete(path)
	})
	return f
}
func (f nodePairLocalFixture) pending(t *testing.T) (*machineNodeControlClient, *machineNodePairState) {
	t.Helper()
	e := runMachineAgentWithContext(context.Background(), []string{"--hub-address", f.address, "--state-dir", f.state, "--id", f.node, "--name", f.node, "--relay-only", "--once"}, nil)
	if !errors.Is(e, errMachineNodePairPending) {
		t.Fatal("real Node did not wait for Owner", e)
	}
	c, e := openMachineNodeControlClientMode(f.state, f.native.d.Claims.Origin, f.node, true)
	if e != nil {
		t.Fatal(e)
	}
	s, e := loadMachineNodePairState(f.state, f.node, c.identity)
	if e != nil || s.Context == nil || s.Stage != wire.NodePairTrustPending {
		t.Fatal("pending original not persisted", e)
	}
	return c, s
}
func (f nodePairLocalFixture) cancel(t *testing.T, c *machineNodeControlClient, s *machineNodePairState) {
	t.Helper()
	b := wire.NodePairTrustCancel{Format: wire.NodePairTrustFormat, Context: *s.Context, OOBCommitment: s.OOB, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	id, _ := wire.NewRequestID()
	raw, e := wire.SealNodePairTrustRequest(c.identity, f.native.d.Claims.Hub, wire.NodePairTrustPacket{Operation: wire.OperationNodePairTrustCancel, RequestID: id, AttemptID: s.AttemptID}, b, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := machineNodePairPOST(context.Background(), f.http, f.native.d.Claims.Origin, wire.OperationNodePairTrustCancel, raw)
	if e != nil {
		t.Fatal(e)
	}
	r, e := wire.OpenNodePairTrustResponse(c.identity, f.native.d.Claims.Hub, raw, receipt, b)
	if e != nil || r.State != wire.NodePairTrustCancelled {
		t.Fatal("real Node cancellation", e)
	}
}
func TestNodePairLocalExplicitRetryRequiresTerminalAndRepairsMarkerCrash(t *testing.T) {
	f := newNodePairLocalFixture(t)
	c, s := f.pending(t)
	defer clear(s.Secret)
	keyPath, _ := machineNodeControlPaths(f.state, f.node)
	beforeKey, _ := os.ReadFile(keyPath)
	defer clear(beforeKey)
	beforeCred, _ := os.ReadFile(machineNodeCredentialPath(f.state, f.node))
	defer clear(beforeCred)
	if _, e := retryMachineNodePair(context.Background(), f.state, f.node, c, s, f.native.d, f.http); !errors.Is(e, errMachineNodePairPending) {
		t.Fatal("active attempt silently got new S", e)
	}
	unchanged, e := loadMachineNodePairState(f.state, f.node, c.identity)
	if e != nil || unchanged.AttemptID != s.AttemptID || !bytes.Equal(unchanged.Secret, s.Secret) {
		t.Fatal("uncertain retry changed local identity/secret", e)
	}
	clear(unchanged.Secret)
	f.cancel(t, c, s)
	next, e := retryMachineNodePair(context.Background(), f.state, f.node, c, s, f.native.d, f.http)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(next.Secret)
	if next.AttemptID == s.AttemptID || bytes.Equal(next.Secret, s.Secret) || next.DescriptorText != s.DescriptorText || machineNodePairCredentialDigest(next) != machineNodePairCredentialDigest(s) {
		t.Fatal("explicit new attempt replaced retained coordinates")
	}
	// Inject only the public marker's old bytes: exactly the crash window after
	// the new sealed state write and before the public marker commit.
	c.mu.Lock()
	c.state.NodePairTrustAttemptID = s.AttemptID
	e = c.persistLocked()
	c.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	machineNodeControlClients.Delete(c.statePath)
	reopened, recovered, e := beginMachineNodePair(context.Background(), f.state, f.node, f.node, f.address, "", false)
	if e != nil {
		t.Fatal("two-file retry did not recover", e)
	}
	defer clear(recovered.Secret)
	if recovered.AttemptID != next.AttemptID || !bytes.Equal(recovered.Secret, next.Secret) || reopened.state.NodePairTrustAttemptID != next.AttemptID {
		t.Fatal("retry crash generated another secret")
	}
	// Honor the unchanged five-second server reissue guard; only old candidate
	// retirement changes. No rate limit or authorization is relaxed for retry.
	time.Sleep(5100 * time.Millisecond)
	_, active := f.pending(t)
	defer clear(active.Secret)
	if active.AttemptID != next.AttemptID || active.Context.Candidate.RequestID == s.Context.Candidate.RequestID {
		t.Fatal("new candidate reused a cancelled original")
	}
	afterKey, _ := os.ReadFile(keyPath)
	defer clear(afterKey)
	afterCred, _ := os.ReadFile(machineNodeCredentialPath(f.state, f.node))
	defer clear(afterCred)
	if !bytes.Equal(beforeKey, afterKey) || !bytes.Equal(beforeCred, afterCred) {
		t.Fatal("retry regenerated original key or credential")
	}
}

func TestNodePairLocalExpiredUnforwardedStartNeedsAuthenticatedFence(t *testing.T) {
	f := newNodePairLocalFixture(t)
	c, s, e := beginMachineNodePair(context.Background(), f.state, f.node, f.node, f.address, "", false)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(s.Secret)
	var body wire.NodePairTrustStart
	if json.Unmarshal(s.StartBody, &body) != nil {
		t.Fatal("initial body")
	}
	at := time.Now().UTC().Add(-11 * time.Minute)
	body.IssuedAt = at.Format(time.RFC3339Nano)
	body.ExpiresAt = at.Add(10 * time.Minute).Format(time.RFC3339Nano)
	s.StartBody, _ = json.Marshal(body)
	id, _ := wire.NewRequestID()
	raw, e := wire.SealNodePairTrustRequest(c.identity, f.native.d.Claims.Hub, wire.NodePairTrustPacket{Operation: s.StartOperation, RequestID: id, AttemptID: s.AttemptID}, body, at)
	if e != nil {
		t.Fatal(e)
	}
	s.PendingOperation = s.StartOperation
	s.PendingPacket = raw
	s.PendingBody = append([]byte(nil), s.StartBody...)
	if e = saveMachineNodePairState(f.state, c.identity, s); e != nil {
		t.Fatal(e)
	}
	// It is an authenticated historical synthetic journal. Never forward this
	// expired original; production recovery first obtains its real Hub fence.
	next, e := retryMachineNodePair(context.Background(), f.state, f.node, c, s, f.native.d, f.http)
	if e != nil {
		t.Fatal("expired unforwarded START cannot retire", e)
	}
	defer clear(next.Secret)
	old, e := loadMachineNodePairStateAtPath(machineNodePairArchivePath(f.state, f.node, s.AttemptID), f.node, c.identity)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(old.Secret)
	if !machineNodePairNoContextRetired(old, c.identity) || old.Context != nil || len(old.FencedOriginals) != 1 || next.AttemptID == old.AttemptID {
		t.Fatal("single fence was mistaken for admission/attempt terminal")
	}
	response, e := machineNodePairPOST(context.Background(), f.http, f.native.d.Claims.Origin, s.StartOperation, raw)
	if e != nil {
		t.Fatal(e)
	}
	terminal, e := wire.OpenNodePairTrustResponse(c.identity, f.native.d.Claims.Hub, raw, response, body)
	if e != nil || terminal.ErrorCode != "FENCED" {
		t.Fatal("late original was dispatched after fence", e)
	}
}
