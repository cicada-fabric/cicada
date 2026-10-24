package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubnodes"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func newNodePairTLSFixture(t *testing.T) (*hubAccountTCPFixture, hubtransport.DiscoveryCandidate) {
	t.Helper()
	f := &hubAccountTCPFixture{stateDir: filepath.Join(t.TempDir(), "SYNTHETIC-node-pair-Hub")}
	f.dbPath = filepath.Join(f.stateDir, "cicada.sqlite3")
	var err error
	f.db, err = store.New(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.client != nil {
			f.client.CloseIdleConnections()
		}
		if f.http != nil {
			f.http.Close()
		}
		if f.db != nil {
			f.db.Close()
		}
	})
	id, err := f.db.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	origin, err := hubtransport.DefaultOrigin(id)
	if err != nil {
		t.Fatal(err)
	}
	f.setup, err = f.db.InitializeHubOwnerLocal("SYNTHETIC TLS pairing Owner", origin, false)
	if err != nil {
		t.Fatal(err)
	}
	f.ids, err = hubidentity.LoadOrCreate(f.stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	f.owner, err = hubowner.NewService(f.db, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	f.auth, err = hubauth.NewServiceWithNodeAuthority(f.db, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	f.hub, err = f.auth.HubIdentity()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := hubtransport.InitializeProfile(f.stateDir, f.ids.ClientControl, f.hub, f.ids.NodeControl.Public(), origin, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.BindHubNativeTLSLocal(profile.DescriptorText()); err != nil {
		t.Fatal(err)
	}
	nodes, err := hubnodes.NewService(f.db, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHubNodesHandler(f.owner, f.auth, nodes).(*hubNodesHandler)
	if handler.base.control != nil {
		t.Fatal("pairing constructed Control inference")
	}
	f.http = httptest.NewUnstartedServer(handler)
	f.http.TLS = profile.TLSConfig()
	// httptest otherwise inserts its unrelated fallback leaf when the numeric
	// first probe sends no SNI. Production ServeTLS uses this profile directly.
	f.http.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return profile.TLSConfig(), nil }
	f.http.StartTLS()
	dial := f.http.Listener.Addr().String()
	candidate, err := hubtransport.DiscoverCandidate(context.Background(), dial)
	if err != nil || candidate.DescriptorText != profile.DescriptorText() {
		t.Fatal("real public descriptor discovery", err)
	}
	f.client, err = hubtransport.NewHTTPClient(candidate.Descriptor, dial, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Keep logical origin and numeric locator separate; no global trust mutation.
	f.http.URL = origin
	return f, candidate
}

func nptPacket(t *testing.T, hub wire.HubIdentity, key *e2ee.Identity, attempt, op string, body any) []byte {
	t.Helper()
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := wire.SealNodePairTrustRequest(key, hub, wire.NodePairTrustPacket{Operation: op, RequestID: id, AttemptID: attempt}, body, time.Now().UTC())
	if err != nil {
		t.Fatal("seal pairing request", op, err)
	}
	return raw
}
func nptHTTP(t *testing.T, f *hubAccountTCPFixture, key *e2ee.Identity, attempt, op string, body any) (wire.NodePairTrustResult, []byte, []byte) {
	t.Helper()
	raw := nptPacket(t, f.hub, key, attempt, op, body)
	status, receipt := n3HTTP(t, f, http.MethodPost, wire.NodePairTrustHTTPPath(op), "", raw)
	if status != 200 {
		t.Fatal("pairing HTTP", op, status)
	}
	result, err := wire.OpenNodePairTrustResponse(key, f.hub, raw, receipt, body)
	if err != nil {
		t.Fatal("pairing sealed receipt", op, err)
	}
	return result, raw, receipt
}
func nptStamp() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func TestNodePairTrustRealTLSOwnerApprovalACKAndOriginalReceipt(t *testing.T) {
	f, candidate := newNodePairTLSFixture(t)
	status, metadata := n3HTTP(t, f, http.MethodGet, wire.NodePairTrustCapabilitiesPath, "", nil)
	var caps wire.NodePairTrustCapabilities
	if status != 200 || json.Unmarshal(metadata, &caps) != nil || caps.Available {
		t.Fatal("unfinished carrier advertised availability")
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	material, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	enroll, ch, _, _ := n2Prepare(t, f, *material, device, owner)
	complete, err := wire.NewActivationComplete(ch, f.hub, device.Public(), owner, "synthetic-npt-tls", "synthetic NPT retained password", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	n2RoundTrip(t, f, wire.OperationActivationComplete, device, complete, &wire.ActivationResult{})
	login := n2Login(t, f, device, enroll.DeviceID, "synthetic-npt-tls", "synthetic NPT retained password")
	session := wire.AppNodeSession{Hub: f.hub, Origin: f.setup.Origin, AccountID: f.setup.AccountID, OwnerID: f.setup.OwnerID, DeviceID: enroll.DeviceID, AccountEpoch: login.AccountEpoch, DeviceEpoch: login.DeviceEpoch, Token: login.SessionToken}
	query, err := wire.NewAppNodeStatus(session, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, bootstrap := n3Authority(t, f, device, query)
	if bootstrap.Result.Authority.CurrentHeadVersion != 0 || bootstrap.Result.Node != nil {
		t.Fatal("login acquired a Node grant")
	}
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, credentialDigest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	start := wire.NodePairTrustStart{Format: wire.NodePairTrustFormat, Hub: f.hub, Origin: f.setup.Origin, DescriptorDigest: wire.NodePairTrustDescriptorDigest(candidate.DescriptorText), NodeID: "SYNTHETIC-npt-TLS-node", NodeName: "SYNTHETIC NPT Node", CredentialDigest: credentialDigest, RequestNonce: nonce, HubNodeControlPublic: f.ids.NodeControl.Public(), HubNodeControlKeyVersion: 1, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(9 * time.Minute).Format(time.RFC3339Nano)}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: f.hub.HubID, NodeID: start.NodeID, RequestNonce: nonce, CredentialDigest: credentialDigest, NodePublicIdentity: node.Public(), HubPublicIdentity: f.ids.NodeControl.Public(), HubKeyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	start.PairingProof, err = e2ee.Seal(node, f.ids.NodeControl.Public(), transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	started, rawStart, receiptStart := nptHTTP(t, f, node, attempt, wire.OperationNodePairTrustStart, start)
	status, exact := n3HTTP(t, f, http.MethodPost, wire.NodePairTrustHTTPPath(wire.OperationNodePairTrustStart), "", rawStart)
	if status != 200 || !bytes.Equal(exact, receiptStart) {
		t.Fatal("lost START response changed")
	}
	if started.Context == nil || started.Context.Candidate == nil || !reflect.DeepEqual(started.Context.Candidate.NodePublic, node.Public()) {
		t.Fatal("original Node candidate missing")
	}
	ctx := *started.Context
	secret := bytes.Repeat([]byte{0x53}, 32)
	defer clear(secret)
	code, err := wire.EncodeNodePairTrustCode(ctx, started.Selector, secret)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := wire.DecodeNodePairTrustCode(code, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ticket.OOBSecret)
	o, err := wire.MatchNodePairTrustCode(ticket, ctx, f.hub, f.ids.NodeControl.Public(), f.setup.Origin, start.DescriptorDigest, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	commit := wire.NodePairTrustCommit{Format: wire.NodePairTrustFormat, Context: ctx, OOBCommitment: o, IssuedAt: nptStamp()}
	nptHTTP(t, f, node, attempt, wire.OperationNodePairTrustCommit, commit)
	d, _ := wire.NodePairTrustContextDigest(ctx)
	lookup := wire.NodePairTrustOwnerLookup{Format: wire.NodePairTrustFormat, SessionToken: session.Token, Scope: bootstrap.Result.Authority.Scope, Selector: ticket.Selector, ContextDigest: d, IssuedAt: nptStamp()}
	found, _, _ := nptHTTP(t, f, device, attempt, wire.OperationOwnerNodePairTrustLookup, lookup)
	if found.Context == nil || !reflect.DeepEqual(*found.Context, ctx) || found.OOBCommitment != o {
		t.Fatal("App reconstructed a different candidate")
	}
	stranger, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	stolen := lookup
	stolen.Scope.DevicePublic = stranger.Public()
	wrongApp := nptPacket(t, f.hub, stranger, attempt, wire.OperationOwnerNodePairTrustLookup, stolen)
	status, _ = n3HTTP(t, f, http.MethodPost, wire.NodePairTrustHTTPPath(wire.OperationOwnerNodePairTrustLookup), "", wrongApp)
	if status != http.StatusForbidden {
		t.Fatal("different App key reused current session scope", status)
	}
	wrongHub := f.hub
	wrongHub.Public = stranger.Public()
	foreign := lookup
	foreign.Scope.HubFingerprint, _ = wire.HubFingerprint(wrongHub)
	wrongRecipient := nptPacket(t, wrongHub, device, attempt, wire.OperationOwnerNodePairTrustLookup, foreign)
	status, _ = n3HTTP(t, f, http.MethodPost, wire.NodePairTrustHTTPPath(wire.OperationOwnerNodePairTrustLookup), "", wrongRecipient)
	if status != http.StatusForbidden {
		t.Fatal("different Hub packet reached stored attempt", status)
	}
	prep, err := wire.NewAppNodePrepare(session, bootstrap.Result.Authority.Scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: ticket.Selector}, owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	original, _, preview := n3Authority(t, f, device, prep)
	grantComplete, err := wire.NewAppNodeComplete(session, prep, original, *preview.Challenge, owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	n3Authority(t, f, device, grantComplete)
	g := preview.Challenge.Claims
	confirm, err := wire.SealAppNodeConfirmation(device, f.hub, g, ticket.Selector, bootstrap.Result.Authority.Counters.LastRequestSequence+1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	status, _ = n3HTTP(t, f, http.MethodPost, "/v2/client/rpc", "", confirm)
	if status != http.StatusConflict {
		t.Fatal("original confirm bypassed Node ACK", status)
	}
	prepare := wire.NodePairTrustOwnerPrepare{Format: wire.NodePairTrustFormat, SessionToken: session.Token, Scope: g.Scope, Context: ctx, OOBCommitment: o, GrantProof: grantComplete.OwnerGrant, ConfirmationPacket: confirm, IssuedAt: nptStamp()}
	prepared, _, _ := nptHTTP(t, f, device, attempt, wire.OperationOwnerNodePairTrustPrepare, prepare)
	x := bytes.Repeat([]byte{0x58}, 32)
	defer clear(x)
	proof, capsule, err := wire.SealNodePairTrustApproval(owner, ctx, o, *prepared.Approval, secret, x, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	approval := wire.NodePairTrustOwnerComplete{Format: wire.NodePairTrustFormat, SessionToken: session.Token, Scope: g.Scope, Context: ctx, OOBCommitment: o, OwnerProof: proof, TrustCapsule: capsule, IssuedAt: nptStamp()}
	approved, _, _ := nptHTTP(t, f, device, attempt, wire.OperationOwnerNodePairTrustComplete, approval)
	if approved.State != wire.NodePairTrustOwnerApproved || approved.Binding != nil {
		t.Fatal("Owner complete activated binding")
	}
	// Closing the App connection is not logout. Node needs no online App callback.
	f.client.CloseIdleConnections()
	poll := wire.NodePairTrustPoll{Format: wire.NodePairTrustFormat, Context: ctx, OOBCommitment: o, IssuedAt: nptStamp()}
	polled, pollPacket, pollReceipt := nptHTTP(t, f, node, attempt, wire.OperationNodePairTrustPoll, poll)
	opened, err := wire.OpenNodePairTrustCapsule(node, ctx, o, polled.OwnerProof, polled.TrustCapsule, secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened.OOBSecret)
	defer clear(opened.ACKNonce)
	ack := wire.NodePairTrustACK{Format: wire.NodePairTrustFormat, Context: ctx, OOBCommitment: o, PollPacketDigest: wire.NodePairTrustPacketDigest(pollPacket), PollReceiptDigest: wire.NodePairTrustPacketDigest(pollReceipt), OwnerProofDigest: wire.NodePairTrustProofDigest(proof), CapsuleDigest: wire.NodePairTrustCapsuleDigest(capsule), ACKNonce: opened.ACKNonce, IssuedAt: nptStamp()}
	acked, ackPacket, ackReceipt := nptHTTP(t, f, node, attempt, wire.OperationNodePairTrustACK, ack)
	if acked.State != wire.NodePairTrustACKed || acked.Binding == nil || wire.ValidateNodePairTrustAccepted(ctx, *prepared.Approval, *acked.Binding) != nil {
		t.Fatal("ACK did not finish exact original binding")
	}
	status, exact = n3HTTP(t, f, http.MethodPost, wire.NodePairTrustHTTPPath(wire.OperationNodePairTrustACK), "", ackPacket)
	if status != 200 || !bytes.Equal(exact, ackReceipt) {
		t.Fatal("lost ACK response changed", status, len(exact), len(ackReceipt))
	}
	q := wire.NodePairTrustOwnerStatus{Format: wire.NodePairTrustFormat, SessionToken: session.Token, Scope: g.Scope, Context: ctx, OOBCommitment: o, IssuedAt: nptStamp()}
	observed, _, _ := nptHTTP(t, f, device, attempt, wire.OperationOwnerNodePairTrustStatus, q)
	originalResponse, err := wire.OpenAppNodeConfirmationResponse(device, f.hub, g, confirm, observed.ConfirmationResponse, bootstrap.Result.Authority.Counters.NextResponseSequence)
	if err != nil || !originalResponse.OK || !reflect.DeepEqual(originalResponse.Binding, acked.Binding) {
		t.Fatal("old Client packet/counter did not settle exactly", err)
	}
	status, exact = n3HTTP(t, f, http.MethodPost, "/v2/client/rpc", "", confirm)
	if status != 200 || !bytes.Equal(exact, observed.ConfirmationResponse) {
		t.Fatal("old exact confirm receipt unavailable")
	}
	q.IssuedAt = nptStamp()
	closed, _, _ := nptHTTP(t, f, device, attempt, wire.OperationOwnerNodePairTrustCancel, q)
	if closed.State != wire.NodePairTrustACKed || !bytes.Equal(closed.ConfirmationResponse, observed.ConfirmationResponse) {
		t.Fatal("late Owner cancel lost exact original ACKED receipt")
	}
	if _, err := wire.OpenAppNodeConfirmationResponse(device, f.hub, g, confirm, closed.ConfirmationResponse, bootstrap.Result.Authority.Counters.NextResponseSequence); err != nil {
		t.Fatal("late Owner cancel cannot authenticate original Client result", err)
	}
	status, _ = n3HTTP(t, f, http.MethodPost, wire.NodePairTrustHTTPPath(wire.OperationNodePairTrustPoll), "SYNTHETIC-forbidden-bearer", pollPacket)
	if status != http.StatusBadRequest {
		t.Fatal("pairing accepted Node bearer header")
	}
}
