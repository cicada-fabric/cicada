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

func newNodePairScopedTLSFixture(t *testing.T) (*hubAccountTCPFixture, hubtransport.DiscoveryCandidate) {
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

func nptScopedPacket(t *testing.T, hub wire.HubIdentity, key *e2ee.Identity, attempt, op string, body any) []byte {
	t.Helper()
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := wire.SealNodePairTrustScopedRequest(key, hub, wire.NodePairTrustScopedPacket{Operation: op, RequestID: id, AttemptID: attempt}, body, time.Now().UTC())
	if err != nil {
		t.Fatal("seal pairing request", op, err)
	}
	return raw
}
func nptScopedHTTP(t *testing.T, f *hubAccountTCPFixture, key *e2ee.Identity, attempt, op string, body any) (wire.NodePairTrustScopedResult, []byte, []byte) {
	t.Helper()
	raw := nptScopedPacket(t, f.hub, key, attempt, op, body)
	status, receipt := n3HTTP(t, f, http.MethodPost, wire.NodePairTrustScopedHTTPPath(op), "", raw)
	if status != 200 {
		t.Fatal("pairing HTTP", op, status)
	}
	result, err := wire.OpenNodePairTrustScopedResponse(key, f.hub, raw, receipt, body)
	if err != nil {
		t.Fatal("pairing sealed receipt", op, err)
	}
	return result, raw, receipt
}
func nptScopedStamp() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func TestNodePairTrustScopedRealTLSTwoNodesOwnerApprovalACKAndOriginalReceipt(t *testing.T) {
	f, candidate := newNodePairScopedTLSFixture(t)
	status, metadata := n3HTTP(t, f, http.MethodGet, wire.NodePairTrustScopedCapabilitiesPath, "", nil)
	var caps wire.NodePairTrustScopedCapabilities
	if status != 200 || json.Unmarshal(metadata, &caps) != nil || !caps.Available {
		t.Fatal("pairing carrier availability drift")
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

	first := exerciseScopedTLSNode(t, f, candidate, session, owner, device, "SYNTHETIC-scoped-TLS-A")
	read := func(g scopedTLSNodeOutcome) wire.AppNodeScopedResult {
		t.Helper()
		q, err := wire.NewAppNodeScopedStatus(session, wire.AppNodeScopedStatusTarget{NodeID: g.Scope.AuthorityNodeID}, g.GrantID, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		_, _, r := scopedTLSAuthority(t, f, device, q)
		if r.Result == nil {
			t.Fatal("exact scoped result")
		}
		return *r.Result
	}
	before := read(first)
	second := exerciseScopedTLSNode(t, f, candidate, session, owner, device, "SYNTHETIC-scoped-TLS-B")
	after := read(first)
	other := read(second)
	if before.Authority.CurrentHeadVersion != 1 || after.Authority.CurrentHeadVersion != 1 || before.Authority.ConfirmationProvenanceID == "" || after.Authority.ConfirmationProvenanceID != before.Authority.ConfirmationProvenanceID || after.Node == nil || after.Node.NodeID != first.Scope.AuthorityNodeID || after.Authority.State != wire.AppNodeScopedActive {
		t.Fatal("second actual Node changed first head/provenance")
	}
	if other.Authority.CurrentHeadVersion != 1 || other.Authority.ConfirmationProvenanceID == "" || other.Authority.ConfirmationProvenanceID == after.Authority.ConfirmationProvenanceID || other.Node == nil || other.Node.NodeID != second.Scope.AuthorityNodeID || other.Authority.Counters.LastRequestSequence != 2 || other.Authority.Counters.NextResponseSequence != 3 {
		t.Fatal("per-Node authority did not share original App counters")
	}

	// A's exact cached originals must never be relabeled under B's scope.
	for _, target := range []struct {
		kind     string
		original []byte
	}{
		{wire.AppNodeScopedOriginalClient, first.ConfirmationPacket},
		{wire.AppNodeScopedOriginalAuthority, first.PreparePacket},
	} {
		query, err := wire.NewAppNodeScopedReconcile(session, second.Scope.AuthorityNodeID, target.kind, first.GrantID, target.original, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := wire.SealClientRequest(device, f.hub, query)
		if err != nil {
			t.Fatal(err)
		}
		status, _ := n3HTTP(t, f, http.MethodPost, wire.AppNodeScopedHTTPPath(wire.OperationAppNodeScopedReconcile), "", raw)
		if status != http.StatusForbidden {
			t.Fatal("B reconcile accepted A original", target.kind, status)
		}
	}
	// This authenticated status original has never been admitted or cached.
	unadmitted, err := wire.NewAppNodeScopedStatus(session, wire.AppNodeScopedStatusTarget{NodeID: first.Scope.AuthorityNodeID}, first.GrantID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	originalStatus, err := wire.SealClientRequest(device, f.hub, unadmitted)
	if err != nil {
		t.Fatal(err)
	}
	wrongScope, err := wire.NewAppNodeScopedReconcile(session, second.Scope.AuthorityNodeID, wire.AppNodeScopedOriginalAuthority, first.GrantID, originalStatus, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	wrongPacket, err := wire.SealClientRequest(device, f.hub, wrongScope)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := n3HTTP(t, f, http.MethodPost, wire.AppNodeScopedHTTPPath(wire.OperationAppNodeScopedReconcile), "", wrongPacket); status != http.StatusForbidden {
		t.Fatal("B reconcile fenced unadmitted A original")
	}
	cancel, err := wire.NewAppNodeScopedCancel(session, first.Scope.AuthorityNodeID, first.GrantID, 1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	scopedTLSAuthority(t, f, device, cancel)

	// Same-Node historical recovery remains valid after A's current head changes.
	recoverA, err := wire.NewAppNodeScopedReconcile(session, first.Scope.AuthorityNodeID, wire.AppNodeScopedOriginalClient, first.GrantID, first.ConfirmationPacket, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, recovered := scopedTLSAuthority(t, f, device, recoverA)
	if recovered.Reconciled == nil || recovered.Reconciled.AuthorityNodeID != first.Scope.AuthorityNodeID || recovered.Reconciled.CurrentHeadVersion != 2 || wire.ValidateAppNodeScopedReconcileTarget(*recovered.Reconciled, first.Scope.AuthorityNodeID, wire.AppNodeScopedOriginalClient, first.ConfirmationPacket) != nil {
		t.Fatal("same Node historical original was blocked by current head")
	}
	if _, err := wire.OpenAppNodeScopedConfirmationResponse(device, f.hub, first.OwnerAppNodeScopedGrantClaims, first.ConfirmationPacket, recovered.Reconciled.ReceiptPacket, first.ResponseSequence); err != nil {
		t.Fatal("historical original response changed", err)
	}
	recoverStatus, err := wire.NewAppNodeScopedReconcile(session, first.Scope.AuthorityNodeID, wire.AppNodeScopedOriginalAuthority, first.GrantID, originalStatus, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, fenced := scopedTLSAuthority(t, f, device, recoverStatus)
	if fenced.Reconciled == nil || fenced.Reconciled.AuthorityNodeID != first.Scope.AuthorityNodeID || fenced.Reconciled.State != wire.AppNodeScopedReadExpired {
		t.Fatal("wrong-scope recovery admitted or relabeled the original read")
	}
	retained := read(second)
	if retained.Authority.CurrentHeadVersion != other.Authority.CurrentHeadVersion || retained.Authority.ConfirmationProvenanceID != other.Authority.ConfirmationProvenanceID || retained.Authority.State != wire.AppNodeScopedActive || retained.Node == nil || retained.Node.NodeID != second.Scope.AuthorityNodeID {
		t.Fatal("cancel A affected B authority")
	}
}

func exerciseScopedTLSNode(t *testing.T, f *hubAccountTCPFixture, candidate hubtransport.DiscoveryCandidate, session wire.AppNodeSession, owner, device *e2ee.Identity, nodeID string) scopedTLSNodeOutcome {
	t.Helper()
	var err error
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
	start := wire.NodePairTrustScopedStart{ScopeVersion: 2, Format: wire.NodePairTrustScopedFormat, Hub: f.hub, Origin: f.setup.Origin, DescriptorDigest: wire.NodePairTrustScopedDescriptorDigest(candidate.DescriptorText), NodeID: nodeID, NodeName: "SYNTHETIC NPT Node", CredentialDigest: credentialDigest, RequestNonce: nonce, HubNodeControlPublic: f.ids.NodeControl.Public(), HubNodeControlKeyVersion: 1, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(9 * time.Minute).Format(time.RFC3339Nano)}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: f.hub.HubID, NodeID: start.NodeID, RequestNonce: nonce, CredentialDigest: credentialDigest, NodePublicIdentity: node.Public(), HubPublicIdentity: f.ids.NodeControl.Public(), HubKeyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	start.PairingProof, err = e2ee.Seal(node, f.ids.NodeControl.Public(), transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	started, rawStart, receiptStart := nptScopedHTTP(t, f, node, attempt, wire.OperationNodePairTrustScopedStart, start)
	status, exact := n3HTTP(t, f, http.MethodPost, wire.NodePairTrustScopedHTTPPath(wire.OperationNodePairTrustScopedStart), "", rawStart)
	if status != 200 || !bytes.Equal(exact, receiptStart) {
		t.Fatal("lost START response changed")
	}
	if started.Context == nil || started.Context.Candidate == nil || !reflect.DeepEqual(started.Context.Candidate.NodePublic, node.Public()) {
		t.Fatal("original Node candidate missing")
	}
	ctx := *started.Context
	secret := bytes.Repeat([]byte{0x53}, 32)
	defer clear(secret)
	code, err := wire.EncodeNodePairTrustScopedCode(ctx, started.Selector, secret)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := wire.DecodeNodePairTrustScopedCode(code, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ticket.OOBSecret)
	o, err := wire.MatchNodePairTrustScopedCode(ticket, ctx, f.hub, f.ids.NodeControl.Public(), f.setup.Origin, start.DescriptorDigest, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	commit := wire.NodePairTrustScopedCommit{Format: wire.NodePairTrustScopedFormat, Context: ctx, OOBCommitment: o, IssuedAt: nptScopedStamp()}
	nptScopedHTTP(t, f, node, attempt, wire.OperationNodePairTrustScopedCommit, commit)
	query, err := wire.NewAppNodeScopedStatus(session, wire.AppNodeScopedStatusTarget{NodeID: ticket.AuthorityNodeID}, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, bootstrap := scopedTLSAuthority(t, f, device, query)
	if bootstrap.Result.Authority.CurrentHeadVersion != 0 || bootstrap.Result.Node != nil {
		t.Fatal("login acquired a Node grant")
	}
	d, _ := wire.NodePairTrustScopedContextDigest(ctx)
	lookup := wire.NodePairTrustScopedOwnerLookup{Format: wire.NodePairTrustScopedFormat, SessionToken: session.Token, Scope: bootstrap.Result.Authority.Scope, Selector: ticket.Selector, ContextDigest: d, IssuedAt: nptScopedStamp()}
	found, _, _ := nptScopedHTTP(t, f, device, attempt, wire.OperationOwnerNodePairTrustScopedLookup, lookup)
	if found.Context == nil || !reflect.DeepEqual(*found.Context, ctx) || found.OOBCommitment != o {
		t.Fatal("App reconstructed a different candidate")
	}
	stranger, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	stolen := lookup
	stolen.Scope.DevicePublic = stranger.Public()
	wrongApp := nptScopedPacket(t, f.hub, stranger, attempt, wire.OperationOwnerNodePairTrustScopedLookup, stolen)
	status, _ = n3HTTP(t, f, http.MethodPost, wire.NodePairTrustScopedHTTPPath(wire.OperationOwnerNodePairTrustScopedLookup), "", wrongApp)
	if status != http.StatusForbidden {
		t.Fatal("different App key reused current session scope", status)
	}
	wrongHub := f.hub
	wrongHub.Public = stranger.Public()
	foreign := lookup
	foreign.Scope.HubFingerprint, _ = wire.HubFingerprint(wrongHub)
	wrongRecipient := nptScopedPacket(t, wrongHub, device, attempt, wire.OperationOwnerNodePairTrustScopedLookup, foreign)
	status, _ = n3HTTP(t, f, http.MethodPost, wire.NodePairTrustScopedHTTPPath(wire.OperationOwnerNodePairTrustScopedLookup), "", wrongRecipient)
	if status != http.StatusForbidden {
		t.Fatal("different Hub packet reached stored attempt", status)
	}
	prep, err := wire.NewAppNodeScopedPrepare(session, bootstrap.Result.Authority.Scope, wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetInitial, Code: ticket.Selector}, owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	original, _, preview := scopedTLSAuthority(t, f, device, prep)
	grantComplete, err := wire.NewAppNodeScopedComplete(session, prep, original, *preview.Challenge, owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	scopedTLSAuthority(t, f, device, grantComplete)
	g := preview.Challenge.Claims
	confirm, err := wire.SealAppNodeScopedConfirmation(device, f.hub, g, ticket.Selector, bootstrap.Result.Authority.Counters.LastRequestSequence+1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	status, _ = n3HTTP(t, f, http.MethodPost, "/v2/client/rpc", "", confirm)
	if status != http.StatusConflict {
		t.Fatal("original confirm bypassed Node ACK", status)
	}
	prepare := wire.NodePairTrustScopedOwnerPrepare{Format: wire.NodePairTrustScopedFormat, SessionToken: session.Token, Scope: g.Scope, Context: ctx, OOBCommitment: o, GrantProof: grantComplete.OwnerGrant, ConfirmationPacket: confirm, IssuedAt: nptScopedStamp()}
	prepared, _, _ := nptScopedHTTP(t, f, device, attempt, wire.OperationOwnerNodePairTrustScopedPrepare, prepare)
	x := bytes.Repeat([]byte{0x58}, 32)
	defer clear(x)
	proof, capsule, err := wire.SealNodePairTrustScopedApproval(owner, ctx, o, *prepared.Approval, secret, x, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	approval := wire.NodePairTrustScopedOwnerComplete{Format: wire.NodePairTrustScopedFormat, SessionToken: session.Token, Scope: g.Scope, Context: ctx, OOBCommitment: o, OwnerProof: proof, TrustCapsule: capsule, IssuedAt: nptScopedStamp()}
	approved, _, _ := nptScopedHTTP(t, f, device, attempt, wire.OperationOwnerNodePairTrustScopedComplete, approval)
	if approved.State != wire.NodePairTrustScopedOwnerApproved || approved.Binding != nil {
		t.Fatal("Owner complete activated binding")
	}
	// Closing the App connection is not logout. Node needs no online App callback.
	f.client.CloseIdleConnections()
	poll := wire.NodePairTrustScopedPoll{Format: wire.NodePairTrustScopedFormat, Context: ctx, OOBCommitment: o, IssuedAt: nptScopedStamp()}
	polled, pollPacket, pollReceipt := nptScopedHTTP(t, f, node, attempt, wire.OperationNodePairTrustScopedPoll, poll)
	opened, err := wire.OpenNodePairTrustScopedCapsule(node, ctx, o, polled.OwnerProof, polled.TrustCapsule, secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened.OOBSecret)
	defer clear(opened.ACKNonce)
	ack := wire.NodePairTrustScopedACK{Format: wire.NodePairTrustScopedFormat, Context: ctx, OOBCommitment: o, PollPacketDigest: wire.NodePairTrustScopedPacketDigest(pollPacket), PollReceiptDigest: wire.NodePairTrustScopedPacketDigest(pollReceipt), OwnerProofDigest: wire.NodePairTrustScopedProofDigest(proof), CapsuleDigest: wire.NodePairTrustScopedCapsuleDigest(capsule), ACKNonce: opened.ACKNonce, IssuedAt: nptScopedStamp()}
	acked, ackPacket, ackReceipt := nptScopedHTTP(t, f, node, attempt, wire.OperationNodePairTrustScopedACK, ack)
	if acked.State != wire.NodePairTrustScopedACKed || acked.Binding == nil || wire.ValidateNodePairTrustScopedAccepted(ctx, *prepared.Approval, *acked.Binding) != nil {
		t.Fatal("ACK did not finish exact original binding")
	}
	status, exact = n3HTTP(t, f, http.MethodPost, wire.NodePairTrustScopedHTTPPath(wire.OperationNodePairTrustScopedACK), "", ackPacket)
	if status != 200 || !bytes.Equal(exact, ackReceipt) {
		t.Fatal("lost ACK response changed", status, len(exact), len(ackReceipt))
	}
	q := wire.NodePairTrustScopedOwnerStatus{Format: wire.NodePairTrustScopedFormat, SessionToken: session.Token, Scope: g.Scope, Context: ctx, OOBCommitment: o, IssuedAt: nptScopedStamp()}
	observed, _, _ := nptScopedHTTP(t, f, device, attempt, wire.OperationOwnerNodePairTrustScopedStatus, q)
	originalResponse, err := wire.OpenAppNodeScopedConfirmationResponse(device, f.hub, g, confirm, observed.ConfirmationResponse, bootstrap.Result.Authority.Counters.NextResponseSequence)
	if err != nil || !originalResponse.OK || !reflect.DeepEqual(originalResponse.Binding, acked.Binding) {
		t.Fatal("old Client packet/counter did not settle exactly", err)
	}
	status, exact = n3HTTP(t, f, http.MethodPost, "/v2/client/rpc", "", confirm)
	if status != 200 || !bytes.Equal(exact, observed.ConfirmationResponse) {
		t.Fatal("old exact confirm receipt unavailable")
	}
	q.IssuedAt = nptScopedStamp()
	closed, _, _ := nptScopedHTTP(t, f, device, attempt, wire.OperationOwnerNodePairTrustScopedCancel, q)
	if closed.State != wire.NodePairTrustScopedACKed || !bytes.Equal(closed.ConfirmationResponse, observed.ConfirmationResponse) {
		t.Fatal("late Owner cancel lost exact original ACKED receipt")
	}
	if _, err := wire.OpenAppNodeScopedConfirmationResponse(device, f.hub, g, confirm, closed.ConfirmationResponse, bootstrap.Result.Authority.Counters.NextResponseSequence); err != nil {
		t.Fatal("late Owner cancel cannot authenticate original Client result", err)
	}
	status, _ = n3HTTP(t, f, http.MethodPost, wire.NodePairTrustScopedHTTPPath(wire.OperationNodePairTrustScopedPoll), "SYNTHETIC-forbidden-bearer", pollPacket)
	if status != http.StatusBadRequest {
		t.Fatal("pairing accepted Node bearer header")
	}

	return scopedTLSNodeOutcome{OwnerAppNodeScopedGrantClaims: g, ConfirmationPacket: confirm, PreparePacket: original, ResponseSequence: bootstrap.Result.Authority.Counters.NextResponseSequence}
}

type scopedTLSNodeOutcome struct {
	e2ee.OwnerAppNodeScopedGrantClaims
	ConfirmationPacket, PreparePacket []byte
	ResponseSequence                  uint64
}

func scopedTLSAuthority(t *testing.T, f *hubAccountTCPFixture, device *e2ee.Identity, body any) ([]byte, []byte, wire.AppNodeScopedResponse) {
	t.Helper()
	raw, err := wire.SealClientRequest(device, f.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	_, route, err := wire.NewClientRoute(f.hub, body, device.Public())
	if err != nil {
		t.Fatal(err)
	}
	status, packet := n3HTTP(t, f, http.MethodPost, wire.AppNodeScopedHTTPPath(route.Operation), "", raw)
	if status != http.StatusOK {
		t.Fatalf("N3 authority %s HTTP %d", route.Operation, status)
	}
	out, err := wire.OpenAppNodeScopedResponse(device, f.hub, raw, packet)
	if err != nil {
		t.Fatal("N3 response crypto/schema", err)
	}
	return raw, packet, out
}
