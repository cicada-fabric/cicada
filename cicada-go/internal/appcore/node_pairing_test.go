package appcore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Crypto actor only: actual App signer, PQ envelopes and encrypted vault;
// server Guards, atomic writer and real Node ACK belong to the Hub/QA gate.
type nodePairingFixture struct {
	savedSession                                  wire.SessionContext
	logoutPosts                                   int
	t                                             *testing.T
	n                                             *nodeActorFixture
	context                                       wire.NodePairTrustContext
	o                                             string
	secret                                        []byte
	code                                          string
	state                                         string
	approval                                      *wire.NodePairTrustApproval
	confirm, confirmationResponse, proof, capsule []byte
	receipts                                      map[string][]byte
	requests                                      map[string][][]byte
	bodies                                        map[string]any
	drop, deny, errorCode                         string
	failBefore                                    string
	denyPacket                                    string
	stateSizes                                    map[string]int
	expiredOuterPosts                             int
	trap                                          *connectionHTTPProbe
	caps                                          bool
	capsResponse                                  []byte
	descriptor                                    hubtransport.Descriptor
}

func newNodePairingFixture(t *testing.T) *nodePairingFixture {
	t.Helper()
	n := newNodeActorFixture(t)
	tls := newAppTLSFixture(t)
	claims := tls.descriptor.Claims
	claims.Origin = n.c.connection.Origin
	claims.ServerName = "hub.synthetic.invalid"
	claims.Hub = n.c.hub
	claims.HubFingerprint = n.c.connection.HubFingerprint
	claims.NodeControl = n.controlKey.Public()
	descriptor, err := hubtransport.SignDescriptor(n.n2.hubKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	text, err := hubtransport.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	codeDigest, _ := wire.AppNodeCodeDigest(n.scope.HubID, n.code)
	candidate := e2ee.OwnerAppNodeCandidate{RequestID: "nctrlreq_synthetic", Version: 1, Mode: "INITIAL", State: "PENDING", HubID: n.scope.HubID, NodeID: "synthetic-node", NodeName: "Synthetic Ubuntu Node", NodePublic: n.nodeKey.Public(), NodeKeyFingerprint: nodewire.IdentityFingerprint(n.nodeKey.Public()), NodeKeyEpoch: 1, HubNodeControlPublic: n.controlKey.Public(), HubNodeControlKeyVersion: 1, HubNodeControlFingerprint: nodewire.IdentityFingerprint(n.controlKey.Public()), CandidateDigest: strings.Repeat("c", 64), CodeDigest: codeDigest, ExpiresAt: n.stamp(n.n2.now.Add(10 * time.Minute))}
	ctx := wire.NodePairTrustContext{Format: wire.NodePairTrustFormat, AttemptID: strings.Repeat("2a", 16), Hub: n.c.hub, Origin: n.c.connection.Origin, DescriptorDigest: wire.NodePairTrustDescriptorDigest(text), NodeNonce: strings.Repeat("4b", 32), Mode: wire.NodePairTrustInitial, Candidate: &candidate, IssuedAt: n.stamp(n.n2.now), ExpiresAt: candidate.ExpiresAt}
	f := &nodePairingFixture{t: t, n: n, context: ctx, secret: bytes.Repeat([]byte{0x53}, 32), state: wire.NodePairTrustPending, receipts: map[string][]byte{}, requests: map[string][][]byte{}, bodies: map[string]any{}, trap: new(connectionHTTPProbe), caps: true, descriptor: descriptor}
	f.code, err = wire.EncodeNodePairTrustCode(ctx, n.code, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := wire.NodePairTrustContextDigest(ctx)
	f.o, _ = wire.NodePairTrustOOBCommitment(digest, f.secret)
	record := &localTransportRecord{Format: localTransportFormat, Version: 1, Descriptor: descriptor, DialAddress: "127.0.0.1:8443"}
	n.c.state.Transport = cloneLocalTransport(record)
	n.c.connectionTransport = cloneLocalTransport(record)
	n.c.directConnection = true
	n.c.connectionHTTP = f
	n.c.cfg.HTTP = f.trap
	n.c.cfg.DirectHTTPFactory = func(hubtransport.Descriptor, string, time.Duration) (HTTPDoer, error) { return f, nil }
	if err := n.c.persistState(); err != nil {
		t.Fatal(err)
	}
	n.c.session.DeviceKeyFingerprint, _ = e2ee.OwnerDevicePublicKeyFingerprint(n.c.device.Public())
	f.savedSession = *n.c.session
	f.savedSession.SessionToken = bytes.Clone(n.c.session.SessionToken)
	return f
}
func (f *nodePairingFixture) Do(req *http.Request) (*http.Response, error) {
	reply := func(raw []byte, status int) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header), Request: req}, nil
	}
	if req.URL.Path == "/v2/owner/account/session/logout" {
		f.logoutPosts++
		if f.n.c.state.Pending == nil || f.n.c.state.Pending.Operation != wire.OperationSessionLogout {
			f.t.Fatal("logout network preceded durable safety action")
		}
		return reply(nil, 503)
	}
	if req.URL.Path == wire.NodePairTrustCapabilitiesPath {
		if f.capsResponse != nil {
			return reply(f.capsResponse, 200)
		}
		caps := wire.NodePairTrustContractCapabilities()
		caps.Available = f.caps
		raw, _ := json.Marshal(caps)
		return reply(raw, 200)
	}
	if req.URL.Path == wire.AppNodeHTTPPath(wire.OperationAppNodeReconcile) && f.n.c.node.PairTrust != nil && f.n.c.node.PairTrust.Confirmation != nil {
		return f.confirmationFence(req)
	}
	if !strings.HasPrefix(req.URL.Path, "/v2/owner/node-pair-trust/") && req.URL.Path != wire.NodePairTrustHTTPPath(wire.OperationNodePairTrustReconcile) {
		if req.URL.Path == "/v2/client/rpc" && f.n.c.nodePairTrustBusy() {
			f.t.Error("App sent reserved original confirmation instead of waiting for Node ACK")
			return reply(nil, 409)
		}
		return f.n.Do(req)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var h wire.NodePairTrustPacket
	if json.Unmarshal(raw, &h) != nil {
		f.t.Fatal("invalid NPT packet")
	}
	f.requests[h.Operation] = append(f.requests[h.Operation], bytes.Clone(raw))
	saved, _, _, err := f.n.c.vault.LoadState(nodeStateNamespace)
	if err != nil {
		f.t.Fatal(err)
	}
	var state nodeAuthorityState
	if decodeStateJSON(saved, &state) != nil {
		f.t.Fatal("bad durable NPT state")
	}
	clear(saved)
	if f.stateSizes == nil {
		f.stateSizes = map[string]int{}
	}
	p := state.PairTrust.Pending
	if h.Operation == wire.OperationNodePairTrustReconcile {
		b, _, _, err := f.n.c.vault.LoadState(nodeRecoveryNamespace)
		if err != nil {
			f.t.Fatal(err)
		}
		var record nodeOperation
		if decodeStateJSON(b, &record) != nil || record.PairTrustRecovery == nil {
			f.t.Fatal("missing durable NPT recovery")
		}
		clear(b)
		p = &record.PairTrustRecovery.Operation
	}
	if p == nil || !bytes.Equal(raw, p.Request) {
		f.t.Fatal("NPT network preceded exact packet persistence")
	}
	if f.deny == h.Operation {
		return reply(nil, 503)
	}
	if f.denyPacket == wire.NodePairTrustPacketDigest(raw) {
		return reply(nil, 503)
	}
	if f.failBefore == h.Operation {
		f.failBefore = ""
		return reply(nil, 503)
	}
	digest := wire.NodePairTrustPacketDigest(raw)
	if h.Operation == wire.OperationNodePairTrustReconcile {
		// Match the real carrier: even a cached outer receipt is behind the
		// request's sixty-second admission check. Original target stays historical.
		var q wire.NodePairTrustReconcile
		if _, err := wire.OpenNodePairTrustRequest(f.n.n2.hubKey, f.n.c.hub, raw, h.Operation, &q, f.n.n2.now); err != nil {
			f.expiredOuterPosts++
			return reply(nil, 403)
		}
	}
	if prior := f.receipts[digest]; prior != nil {
		return reply(bytes.Clone(prior), 200)
	}
	var body any
	switch h.Operation {
	case wire.OperationOwnerNodePairTrustLookup:
		body = new(wire.NodePairTrustOwnerLookup)
	case wire.OperationOwnerNodePairTrustPrepare:
		body = new(wire.NodePairTrustOwnerPrepare)
	case wire.OperationOwnerNodePairTrustComplete:
		body = new(wire.NodePairTrustOwnerComplete)
	case wire.OperationOwnerNodePairTrustStatus, wire.OperationOwnerNodePairTrustCancel:
		body = new(wire.NodePairTrustOwnerStatus)
	case wire.OperationNodePairTrustReconcile:
		body = new(wire.NodePairTrustReconcile)
	default:
		f.t.Fatal("unexpected NPT operation")
	}
	if _, err := wire.OpenNodePairTrustRequest(f.n.n2.hubKey, f.n.c.hub, raw, h.Operation, body, f.n.n2.now); err != nil {
		f.t.Fatal("NPT request failed shared crypto", h.Operation)
	}
	f.bodies[digest] = body
	plain, _ := json.Marshal(body)
	if bytes.Contains(plain, []byte(f.code)) || bytes.Contains(plain, []byte(base64.RawURLEncoding.EncodeToString(f.secret))) {
		f.t.Fatal("S or whole device code reached Hub plaintext")
	}
	r := wire.NodePairTrustResult{Format: wire.NodePairTrustFormat, Operation: h.Operation, RequestID: h.RequestID, AttemptID: h.AttemptID, RequestPacketDigest: digest, State: f.state, Context: &f.context, OOBCommitment: f.o, ObservedAt: f.n.stamp(f.n.n2.now)}
	switch b := body.(type) {
	case *wire.NodePairTrustOwnerPrepare:
		if f.context.Mode == wire.NodePairTrustExisting {
			if len(b.GrantProof) != 0 || len(b.ConfirmationPacket) != 0 {
				f.t.Fatal("trust-only path manufactured INITIAL authorization")
			}
			d, _ := wire.NodePairTrustContextDigest(f.context)
			f.approval = &wire.NodePairTrustApproval{Format: wire.NodePairTrustFormat, ContextDigest: d, OOBCommitment: f.o, Scope: b.Scope, PrepareRequestID: h.RequestID, PreparePacketDigest: digest, ServerNonce: strings.Repeat("6b", 32), PreparedAt: f.n.stamp(f.n.n2.now), AcceptBefore: f.n.stamp(f.n.n2.now.Add(4 * time.Minute))}
			r.Approval = f.approval
			r.State = wire.NodePairTrustPending
			break
		}
		grant, err := e2ee.VerifyOwnerAppNodeGrant(f.n.scope.OwnerPublic, b.GrantProof, f.n.n2.now)
		if err != nil {
			f.t.Fatal(err)
		}
		d, _ := wire.NodePairTrustContextDigest(f.context)
		f.approval = &wire.NodePairTrustApproval{Format: wire.NodePairTrustFormat, ContextDigest: d, OOBCommitment: f.o, Scope: b.Scope, GrantID: grant.GrantID, GrantProofDigest: wire.AppNodeProofDigest(b.GrantProof), ConfirmationPacketDigest: wire.AppNodePacketDigest(b.ConfirmationPacket), PrepareRequestID: h.RequestID, PreparePacketDigest: digest, ServerNonce: strings.Repeat("6b", 32), PreparedAt: f.n.stamp(f.n.n2.now), AcceptBefore: f.n.stamp(f.n.n2.now.Add(4 * time.Minute))}
		if wire.ValidateNodePairTrustInitialAuthorization(f.context, *f.approval, b.GrantProof, b.ConfirmationPacket, f.n.n2.now) != nil {
			f.t.Fatal("original finite authorization did not match reserved packet")
		}
		f.confirm = bytes.Clone(b.ConfirmationPacket)
		r.Approval = f.approval
		r.State = wire.NodePairTrustPending
	case *wire.NodePairTrustOwnerComplete:
		capsule, err := wire.OpenNodePairTrustCapsule(f.n.nodeKey, f.context, f.o, b.OwnerProof, b.TrustCapsule, f.secret, f.n.n2.now)
		if err != nil || !reflect.DeepEqual(capsule.OwnerPublic, f.n.c.owner.Public()) {
			f.t.Fatal("actual original Node failed independent S/Owner capsule")
		}
		f.proof, f.capsule = bytes.Clone(b.OwnerProof), bytes.Clone(b.TrustCapsule)
		f.state = wire.NodePairTrustOwnerApproved
		r.State = f.state
	case *wire.NodePairTrustOwnerStatus:
		if !pairTrustTerminal(f.state) && f.state != wire.NodePairTrustACKed && !f.n.n2.now.Before(parseExpiry(f.context.ExpiresAt)) {
			f.state = wire.NodePairTrustExpired
			r.State = f.state
		}
		if h.Operation == wire.OperationOwnerNodePairTrustCancel && !pairTrustTerminal(f.state) && f.state != wire.NodePairTrustACKed {
			f.state = wire.NodePairTrustCancelled
			r.State = f.state
		}
		if f.state == wire.NodePairTrustACKed {
			b := f.n.bindingDTO()
			r.Binding = &b
			if f.context.Mode == wire.NodePairTrustInitial {
				r.ConfirmationResponse = bytes.Clone(f.confirmationResponse)
			}
		}
	case *wire.NodePairTrustReconcile:
		r.Context, r.OOBCommitment = nil, ""
		if prior := f.receipts[b.OriginalPacketDigest]; prior != nil {
			r.State = wire.NodePairTrustRecovered
			r.OriginalPacketDigest = b.OriginalPacketDigest
			r.OriginalReceipt = bytes.Clone(prior)
		} else {
			r.State, r.ErrorCode = wire.NodePairTrustFenced, "FENCED"
		}
	}
	if f.errorCode != "" {
		r.ErrorCode = f.errorCode
		r.Context = nil
		r.OOBCommitment = ""
		r.Approval = nil
		r.Binding = nil
		r.ConfirmationResponse = nil
		r.State = wire.NodePairTrustPending
	}
	response, err := wire.SealNodePairTrustResponse(f.n.n2.hubKey, f.n.c.hub, raw, body, r)
	if err != nil {
		f.t.Fatal("NPT actor response failed crypto", h.Operation, err)
	}
	if len(response) > f.n.c.nodePairTrustResponseLimit(h.Operation) {
		f.t.Fatal("actual normal PQ response exceeds reserved local receipt budget")
	}
	p.Response = bytes.Clone(response)
	projected, _ := json.Marshal(state)
	f.stateSizes[h.Operation] = max(f.stateSizes[h.Operation], len(projected))
	clear(projected)
	if h.Operation == wire.OperationNodePairTrustReconcile {
		record := nodeOperation{Operation: wire.OperationNodePairTrustReconcile, PairTrustRecovery: &nodePairTrustRecoveryRecord{state.Scope, state.PairTrust.Code.AttemptID, wire.NodePairTrustPacketDigest(state.PairTrust.Pending.Request), *p}}
		b, _ := json.Marshal(record)
		f.stateSizes[h.Operation+".recovery_namespace"] = max(f.stateSizes[h.Operation+".recovery_namespace"], len(b))
		clear(b)
	}
	if f.errorCode == "" {
		f.receipts[digest] = bytes.Clone(response)
	}
	if f.drop == h.Operation {
		f.drop = ""
		return reply([]byte("SYNTHETIC UNAUTHENTICATED HTTP ERROR"), 503)
	}
	return reply(response, 200)
}
func (f *nodePairingFixture) ack() {
	f.t.Helper()
	if f.state != wire.NodePairTrustOwnerApproved || (f.context.Mode == wire.NodePairTrustInitial && len(f.confirm) == 0) {
		f.t.Fatal("ACK preceded approval")
	}
	capsule, err := wire.OpenNodePairTrustCapsule(f.n.nodeKey, f.context, f.o, f.proof, f.capsule, f.secret, f.n.n2.now)
	if err != nil {
		f.t.Fatal(err)
	}
	ack := wire.NodePairTrustACK{Format: wire.NodePairTrustFormat, Context: f.context, OOBCommitment: f.o, PollPacketDigest: strings.Repeat("1a", 32), PollReceiptDigest: strings.Repeat("2b", 32), OwnerProofDigest: wire.NodePairTrustProofDigest(f.proof), CapsuleDigest: wire.NodePairTrustCapsuleDigest(f.capsule), ACKNonce: capsule.ACKNonce, IssuedAt: f.n.stamp(f.n.n2.now)}
	if wire.VerifyNodePairTrustACK(f.context, f.o, f.proof, f.capsule, ack, f.n.n2.now) != nil {
		f.t.Fatal("Node ACK did not prove X")
	}
	if f.context.Mode == wire.NodePairTrustInitial {
		f.confirmationResponse = f.n.confirm(f.confirm)
	}
	f.state = wire.NodePairTrustACKed
}
func (f *nodePairingFixture) review() {
	f.t.Helper()
	if err := f.n.c.Dispatch(context.Background(), Action{Kind: ActionReviewNodePairing, DevicePairingCode: f.code}); err != nil {
		f.t.Fatal(err)
	}
	if f.n.c.Snapshot().Node.Pairing.State != "REVIEW" {
		f.t.Fatal("missing exact Node review")
	}
}
func (f *nodePairingFixture) approve() error {
	return f.n.c.Dispatch(context.Background(), Action{Kind: ActionApproveNodePairing, NodePairingReviewID: f.n.c.Snapshot().Node.Pairing.ReviewID, ConfirmNodePairing: true})
}
func (f *nodePairingFixture) reopen() {
	f.t.Helper()
	old := f.n.c
	session := f.savedSession
	if old.session != nil {
		session = *old.session
	}
	session.SessionToken = bytes.Clone(session.SessionToken)
	f.savedSession = session
	f.savedSession.SessionToken = bytes.Clone(session.SessionToken)
	if err := old.Close(); err != nil {
		f.t.Fatal(err)
	}
	c := f.n.n2.controller(f.t, f.n.root).(*nativeController)
	f.n.c = c
	c.cfg.HTTP = f.trap
	c.cfg.DirectHTTPFactory = func(hubtransport.Descriptor, string, time.Duration) (HTTPDoer, error) { return f, nil }
	ctx := context.Background()
	if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		f.t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: c.Snapshot().Profiles[0].ID}); err != nil {
		f.t.Fatal(err)
	}
	c.session = &session
	c.sessionInspected, c.sessionNeedsCheck = true, false
	c.state.AccountState = AccountStateSessionActive
	if c.hasNodePending() {
		return
	}
	if err := c.refreshNodePairingContext(ctx); err != nil {
		f.t.Fatalf("reopen context: %v (ready=%t pending=%t begin=%t history=%t owner=%t root=%s)", err, c.nodeAccountReady(), c.hasNodePending(), c.canBeginOperation(), c.nodeHasN2History(), c.localOwnerMatchesHub(), c.state.RootState)
	}
}
func TestNodePairingOneConsentWaitsForAuthenticatedOriginalACK(t *testing.T) {
	f := newNodePairingFixture(t)
	c := f.n.c
	owner, device := c.owner.Public(), c.device.Public()
	f.review()
	if c.nodeConfirmation != nil || f.n.binding != nil || len(f.requests[wire.OperationOwnerNodePairTrustPrepare]) != 0 {
		t.Fatal("lookup/preview granted trust or admission")
	}
	if c.Dispatch(context.Background(), Action{Kind: ActionApproveNodePairing, NodePairingReviewID: "SYNTHETIC_WRONG_REVIEW", ConfirmNodePairing: true}) == nil {
		t.Fatal("stale review approved")
	}
	if err := f.approve(); err != nil {
		t.Fatal(err)
	}
	if c.nodeConfirmation != nil || f.n.binding != nil || c.node.Client.NextRequest != 1 || c.node.Client.NextResponse != 1 || c.Snapshot().Node.Pairing.State != wire.NodePairTrustOwnerApproved {
		t.Fatal("Owner approval became admission before ACK")
	}
	if c.Dispatch(context.Background(), Action{Kind: ActionApproveNode, ConfirmNodeIdentity: true, ConfirmNodeAccess: true}) == nil {
		t.Fatal("old confirmation bypassed pending ACK")
	}
	snapshot, _ := json.Marshal(c.Snapshot())
	if bytes.Contains(snapshot, []byte(f.code)) || bytes.Contains(snapshot, []byte("OOBSecret")) {
		t.Fatal("pairing secret reached snapshot")
	}
	f.ack()
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRefreshNodePairing}); err != nil {
		t.Fatal(err)
	}
	if c.nodeConfirmation == nil || !bytes.Equal(c.nodeConfirmation.Operation.Request, f.confirm) || !bytes.Equal(c.nodeConfirmation.Operation.Response, f.confirmationResponse) || c.node.Client.NextRequest != 2 || c.node.Client.NextResponse != 2 || c.Snapshot().Node.Pairing.State != wire.NodePairTrustACKed {
		t.Fatal("ACK did not apply exact original confirmation once")
	}
	if !reflect.DeepEqual(owner, c.owner.Public()) || !reflect.DeepEqual(device, c.device.Public()) || f.trap.calls != 0 {
		t.Fatal("pairing replaced keys or fell back")
	}
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRefreshNodePairing}); err != nil {
		t.Fatal(err)
	}
	if c.node.Client.NextRequest != 2 || c.node.Client.NextResponse != 2 {
		t.Fatal("duplicate ACK advanced original slot twice")
	}
}
func TestNodePairingLostResponseRestoresOriginalCodeAndPackets(t *testing.T) {
	for _, op := range []string{wire.OperationOwnerNodePairTrustLookup, wire.OperationOwnerNodePairTrustPrepare, wire.OperationOwnerNodePairTrustComplete, wire.OperationOwnerNodePairTrustStatus} {
		t.Run(op, func(t *testing.T) {
			f := newNodePairingFixture(t)
			c := f.n.c
			if op != wire.OperationOwnerNodePairTrustLookup {
				f.review()
			}
			f.drop = op
			switch op {
			case wire.OperationOwnerNodePairTrustLookup:
				if c.Dispatch(context.Background(), Action{Kind: ActionReviewNodePairing, DevicePairingCode: f.code}) == nil {
					t.Fatal("lost lookup reported success")
				}
			case wire.OperationOwnerNodePairTrustPrepare, wire.OperationOwnerNodePairTrustComplete:
				if f.approve() == nil {
					t.Fatal("lost approval response reported success")
				}
			case wire.OperationOwnerNodePairTrustStatus:
				if err := f.approve(); err != nil {
					t.Fatal(err)
				}
				f.ack()
				if c.Dispatch(context.Background(), Action{Kind: ActionRefreshNodePairing}) == nil {
					t.Fatal("lost ACK status reported success")
				}
			}
			original := bytes.Clone(c.node.PairTrust.Pending.Request)
			secret := bytes.Clone(c.node.PairTrust.Code.OOBSecret)
			owner := c.owner.Public().ID
			f.reopen()
			c = f.n.c
			if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
				t.Fatal(err)
			}
			requests := f.requests[op]
			if len(requests) < 2 || !bytes.Equal(requests[0], original) || !bytes.Equal(requests[1], original) || !bytes.Equal(secret, c.node.PairTrust.Code.OOBSecret) || c.owner.Public().ID != owner {
				t.Fatal("reopen changed original packet, S or Owner")
			}
		})
	}
}
func TestNodePairingAuthenticatedUncertaintyKeepsOriginalPending(t *testing.T) {
	for _, code := range []string{"OUTCOME_UNCERTAIN", "UNAVAILABLE", "ACK_REQUIRED", "FENCED"} {
		t.Run(code, func(t *testing.T) {
			f := newNodePairingFixture(t)
			f.review()
			f.errorCode = code
			if f.approve() == nil {
				t.Fatal("uncertain signed result reported success")
			}
			c := f.n.c
			p := c.node.PairTrust.Pending
			original := bytes.Clone(p.Request)
			if p.Applied || c.node.PairTrust.ConsentReviewID == "" || c.nodeConfirmation != nil {
				t.Fatal("signed uncertainty settled pending")
			}
			f.errorCode = ""
			if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
				t.Fatal(err)
			}
			requests := f.requests[p.Operation]
			if len(requests) < 2 || !bytes.Equal(requests[1], original) {
				t.Fatal("uncertain result created a new approval")
			}
		})
	}
}

func TestNodePairingActualVaultReconcileBudget(t *testing.T) {
	f := newNodePairingFixture(t)
	defer func() {
		for operation, size := range f.stateSizes {
			t.Logf("encrypted-vault node record operation=%s plaintext_bytes=%d", operation, size)
		}
		raw, _ := json.Marshal(f.n.c.node)
		t.Logf("current node plaintext_bytes=%d", len(raw))
		clear(raw)
		for name, value := range map[string]any{"old_pending": f.n.c.node.Pending, "proposal": f.n.c.node.Proposal, "recovery": f.n.c.node.PairTrust.Recovery, "original": f.n.c.node.PairTrust.Pending} {
			b, _ := json.Marshal(value)
			t.Logf("component=%s plaintext_bytes=%d", name, len(b))
			clear(b)
		}
	}()
	f.review()
	f.drop = wire.OperationOwnerNodePairTrustComplete
	if f.approve() == nil {
		t.Fatal("missing uncertain complete")
	}
	f.deny = wire.OperationOwnerNodePairTrustComplete
	f.reopen()
	if err := f.n.c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	if len(f.requests[wire.OperationNodePairTrustReconcile]) == 0 || f.n.c.node.PairTrust.Stage != wire.NodePairTrustOwnerApproved {
		t.Fatal("actual encrypted reconciliation did not restore approval")
	}
	f.ack()
	if err := f.n.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNodePairing}); err != nil {
		t.Fatal(err)
	}
	for operation, size := range f.stateSizes {
		t.Logf("encrypted-vault node record operation=%s plaintext_bytes=%d", operation, size)
		if size > maxNodeStateRecordBytes {
			t.Fatal("normal actual PQ receipt exceeds vault namespace")
		}
	}
}
func TestNodePairingRejectsWrongHubAndUnavailableBeforeSecretPost(t *testing.T) {
	f := newNodePairingFixture(t)
	c := f.n.c
	before := len(f.requests)
	c.connection.HubFingerprint = strings.Repeat("0", 64)
	if c.Dispatch(context.Background(), Action{Kind: ActionReviewNodePairing, DevicePairingCode: f.code}) == nil || len(f.requests) != before {
		t.Fatal("wrong retained Hub accepted code")
	}
	c.connection.HubFingerprint, _ = wire.HubFingerprint(f.context.Hub)
	f.caps = false
	if c.Dispatch(context.Background(), Action{Kind: ActionReviewNodePairing, DevicePairingCode: f.code}) == nil || len(f.requests) != before {
		t.Fatal("public unavailable allowed credential POST")
	}
	if f.trap.calls != 0 {
		t.Fatal("new pairing fell back to another transport")
	}
}

func TestNodePairingCapabilitiesHTTPEncoderFraming(t *testing.T) {
	for _, kind := range []string{"encoder_newline", "unknown_field", "duplicate_field", "second_object"} {
		t.Run(kind, func(t *testing.T) {
			f := newNodePairingFixture(t)
			caps := wire.NodePairTrustContractCapabilities()
			caps.Available = true
			var encoded bytes.Buffer
			if err := json.NewEncoder(&encoded).Encode(caps); err != nil {
				t.Fatal(err)
			}
			body := bytes.TrimSuffix(encoded.Bytes(), []byte("\n"))
			switch kind {
			case "encoder_newline":
				f.capsResponse = bytes.Clone(encoded.Bytes())
			case "unknown_field":
				f.capsResponse = append(bytes.Clone(body[:len(body)-1]), []byte(",\"extra\":true}\n")...)
			case "duplicate_field":
				f.capsResponse = append(bytes.Clone(body[:len(body)-1]), []byte(",\"available\":true}\n")...)
			case "second_object":
				f.capsResponse = append(bytes.Clone(encoded.Bytes()), []byte("{}\n")...)
			}
			err := f.n.c.discoverNodePairTrust(context.Background())
			if kind == "encoder_newline" {
				if err != nil || !f.n.c.pairTrustAvailable {
					t.Fatal("valid HTTP Encoder JSON framing was refused")
				}
			} else if err == nil || f.n.c.pairTrustAvailable {
				t.Fatal("HTTP framing relaxed closed/canonical metadata checks")
			}
			if len(f.requests) != 0 || f.n.c.node.PairTrust != nil {
				t.Fatal("availability parsing posted pairing secrets or created authority")
			}
		})
	}
}

var _ HTTPDoer = (*nodePairingFixture)(nil)

func (f *nodePairingFixture) confirmationFence(req *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	packet, err := wire.DecodePacket(raw)
	if err != nil {
		f.t.Fatal(err)
	}
	binding := clientwire.Binding{HubID: f.n.scope.HubID, OwnerID: f.n.scope.OwnerID, DeviceID: f.n.scope.DeviceID, SessionEpoch: wire.HandshakeEpoch, HubKeyVersion: 1, DeviceKeyVersion: 1}
	var q wire.AppNodeReconcileRequest
	f.n.open(binding, packet, raw, &q)
	saved, _, _, err := f.n.c.vault.LoadState(nodeRecoveryNamespace)
	if err != nil {
		f.t.Fatal(err)
	}
	var durable nodeOperation
	if decodeStateJSON(saved, &durable) != nil || !bytes.Equal(durable.Request, raw) {
		f.t.Fatal("confirmation reconcile not persisted before POST")
	}
	clear(saved)
	if q.OriginalKind != wire.AppNodeOriginalClient || !bytes.Equal(q.OriginalPacket, f.confirm) {
		f.t.Fatal("reconcile changed the reserved confirmation")
	}
	if !pairTrustTerminal(f.state) {
		return &http.Response{StatusCode: 409, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header), Request: req}, nil
	}
	digest := wire.AppNodePacketDigest(q.OriginalPacket)
	response := f.n.receipts[digest]
	if response == nil {
		var original clientwire.Packet
		if json.Unmarshal(q.OriginalPacket, &original) != nil {
			f.t.Fatal("invalid original confirmation")
		}
		b := clientwire.Binding{HubID: f.n.scope.HubID, OwnerID: f.n.scope.OwnerID, DeviceID: f.n.scope.DeviceID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
		if _, err := clientwire.OpenRequest(f.n.n2.hubKey, f.n.scope.DevicePublic, b, q.OriginalPacket); err != nil {
			f.t.Fatal(err)
		}
		payload, _ := json.Marshal(struct {
			Error       string `json:"error,omitempty"`
			OK          bool   `json:"ok"`
			OperationID string `json:"operation_id"`
			RequestID   string `json:"request_id"`
		}{"PAIRING_ENDED", false, original.Route.OperationID, "clientreq_synthetic_negative"})
		route := original.Route
		route.Direction = clientwire.DirectionResponse
		route.Sequence = f.n.nextResponse
		route.SenderKeyID, route.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
		route.SenderKeyVersion, route.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
		response, err = clientwire.SealResponse(f.n.n2.hubKey, f.n.scope.DevicePublic, b, route, payload)
		if err != nil {
			f.t.Fatal(err)
		}
		f.n.receipts[digest] = bytes.Clone(response)
		f.n.lastRequest++
		f.n.nextResponse++
	}
	var original clientwire.Packet
	_ = json.Unmarshal(q.OriginalPacket, &original)
	result := wire.AppNodeReconcileResult{Format: wire.AppNodeReconciledFormat, Origin: f.n.scope.Origin, HubID: f.n.scope.HubID, AccountID: f.n.scope.AccountID, OwnerID: f.n.scope.OwnerID, DeviceID: f.n.scope.DeviceID, RequestID: packet.Packet.Route.OperationID, RequestPacketDigest: wire.AppNodePacketDigest(raw), GrantID: q.GrantID, OriginalKind: q.OriginalKind, OriginalOperation: original.Route.Operation, OriginalRequestID: original.Route.OperationID, OriginalPacketDigest: digest, State: wire.AppNodeRejectedFenced, ReceiptPacket: response, AccountEpoch: 1, DeviceEpoch: 1, CurrentHeadVersion: f.n.head, CurrentGrantState: f.n.state, ObservedAt: f.n.stamp(f.n.n2.now)}
	sealed, err := wire.SealResponse(f.n.n2.hubKey, f.n.scope.DevicePublic, packet.Packet.Route, result)
	if err != nil {
		f.t.Fatal(err)
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(sealed)), Header: make(http.Header), Request: req}, nil
}
func TestNodePairingCancelRequiresOriginalNegativeReceiptAndReopenDoesNotRepeatSlot(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	if err := f.approve(); err != nil {
		t.Fatal(err)
	}
	c := f.n.c
	original := bytes.Clone(c.node.PairTrust.Confirmation.Request)
	// Stop at the durable side-cancellation receipt, before local cleanup, to
	// exercise the real cross-record crash boundary explicitly.
	q := wire.NodePairTrustOwnerCancel{Format: wire.NodePairTrustFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: c.node.PairTrust.Scope, Context: f.context, OOBCommitment: f.o, IssuedAt: f.n.stamp(f.n.n2.now)}
	if err := c.newNodePairTrustOperation(context.Background(), wire.OperationOwnerNodePairTrustCancel, q); err != nil {
		t.Fatal(err)
	}
	if c.node.PairTrust.Confirmation.Applied || c.node.Client.NextRequest != 1 || c.node.Client.NextResponse != 1 || c.nodeConfirmation != nil {
		t.Fatal("NPT cancellation settled the old slot without its receipt")
	}
	// Serialize and restore both copies to break their in-memory pointer alias.
	c.node.Pending = c.node.PairTrust.Confirmation
	if err := c.persistNode(); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	c = f.n.c
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	if !c.node.PairTrust.Confirmation.Applied || !bytes.Equal(c.node.PairTrust.Confirmation.Request, original) || c.node.Client.NextRequest != 2 || c.node.Client.NextResponse != 2 || c.nodeConfirmation != nil || f.n.binding != nil {
		t.Fatal("original negative receipt did not settle exactly once without a binding")
	}
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	if c.node.Client.NextRequest != 2 || c.node.Client.NextResponse != 2 {
		t.Fatal("negative replay advanced the slot twice")
	}
}
func TestNodePairingCounterObservationCannotAdvanceOrAdoptAnotherSlot(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	if err := f.approve(); err != nil {
		t.Fatal(err)
	}
	c := f.n.c
	before := c.node.Client
	good := wire.AppNodeClientCounters{SessionEpoch: before.Epoch, LastRequestSequence: before.NextRequest, NextResponseSequence: before.NextResponse + 1}
	if !c.observesReservedNodeConfirmation(good) || c.node.Client != before {
		t.Fatal("one reserved advance changed local counters")
	}
	for _, got := range []wire.AppNodeClientCounters{{SessionEpoch: before.Epoch + 1, LastRequestSequence: good.LastRequestSequence, NextResponseSequence: good.NextResponseSequence}, {SessionEpoch: before.Epoch, LastRequestSequence: good.LastRequestSequence + 1, NextResponseSequence: good.NextResponseSequence + 1}} {
		if c.observesReservedNodeConfirmation(got) {
			t.Fatal("another epoch or slot was mistaken for original ACK")
		}
	}
	c.node.PairTrust.Confirmation.ExpectedResponseSequence++
	if c.observesReservedNodeConfirmation(good) {
		t.Fatal("another original response slot matched ACK")
	}
}
func TestNodePairingExactSavedDescriptorMismatchNeverReplacesProfile(t *testing.T) {
	f := newNodePairingFixture(t)
	c := f.n.c
	original, _ := json.Marshal(c.state.Transport)
	f.context.DescriptorDigest = strings.Repeat("0", 64)
	var err error
	f.code, err = wire.EncodeNodePairTrustCode(f.context, f.n.code, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := wire.NodePairTrustContextDigest(f.context)
	f.o, _ = wire.NodePairTrustOOBCommitment(digest, f.secret)
	if c.Dispatch(context.Background(), Action{Kind: ActionReviewNodePairing, DevicePairingCode: f.code}) == nil {
		t.Fatal("same CC/NC with different CA/SPKI descriptor digest was accepted")
	}
	after, _ := json.Marshal(c.state.Transport)
	if !bytes.Equal(original, after) || c.node.Proposal != nil || c.nodeConfirmation != nil || len(f.requests[wire.OperationOwnerNodePairTrustPrepare]) != 0 {
		t.Fatal("new code changed trusted profile or started approval")
	}
}

func TestNodePairingExistingBindingAddsTrustWithoutNewInitialGrant(t *testing.T) {
	f := newNodePairingFixture(t)
	c := f.n.c
	ctx := context.Background()
	if err := c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.n.code}); err != nil {
		t.Fatal(err)
	}
	f.n.approve(t)
	binding := f.n.bindingDTO()
	confirmation := bytes.Clone(c.nodeConfirmation.Operation.Request)
	counters := c.node.Client
	initialGrants := len(f.n.posts[wire.OperationAppNodeComplete])
	f.context.Mode = wire.NodePairTrustExisting
	f.context.Candidate = nil
	f.context.Binding = &binding
	var err error
	f.code, err = wire.EncodeNodePairTrustCode(f.context, "", f.secret)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := wire.NodePairTrustContextDigest(f.context)
	f.o, _ = wire.NodePairTrustOOBCommitment(digest, f.secret)
	f.review()
	if err := f.approve(); err != nil {
		t.Fatal(err)
	}
	if len(f.confirm) != 0 || c.node.PairTrust.Confirmation != nil || len(f.n.posts[wire.OperationAppNodeComplete]) != initialGrants {
		t.Fatal("trust-only pairing started a new INITIAL admission")
	}
	f.ack()
	if err := c.Dispatch(ctx, Action{Kind: ActionRefreshNodePairing}); err != nil {
		t.Fatal(err)
	}
	if c.node.PairTrust.Stage != wire.NodePairTrustACKed || !reflect.DeepEqual(binding, f.n.bindingDTO()) || !bytes.Equal(confirmation, c.nodeConfirmation.Operation.Request) || c.node.Client != counters {
		t.Fatal("trust-only ACK changed original binding, credential or conversation")
	}
}

func TestNodePairingNewLoginObservesWithoutRenewingOriginalApproval(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	if err := f.approve(); err != nil {
		t.Fatal(err)
	}
	c := f.n.c
	approval := *c.node.PairTrust.Approval
	proof := bytes.Clone(c.node.PairTrust.OwnerProof)
	f.n.scope.AccountSessionID = "synthetic-new-current-session"
	f.n.scope.AccountSessionExpiresAt = f.n.stamp(f.n.n2.now.Add(12 * time.Minute))
	c.session.ExpiresAt = f.n.scope.AccountSessionExpiresAt
	f.state = wire.NodePairTrustRevoked
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRefreshNodePairing}); err != nil {
		t.Fatal(err)
	}
	p := c.node.PairTrust.Pending
	body, err := pairTrustBody(p)
	if err != nil {
		t.Fatal(err)
	}
	status := body.(*wire.NodePairTrustOwnerStatus)
	if status.Scope.AccountSessionID != f.n.scope.AccountSessionID || !reflect.DeepEqual(approval, *c.node.PairTrust.Approval) || !bytes.Equal(proof, c.node.PairTrust.OwnerProof) || c.node.PairTrust.Stage != wire.NodePairTrustRevoked || !c.node.PairTrust.Confirmation.Applied || c.node.Client.NextRequest != 2 {
		t.Fatal("current observation renewed the old approval or failed exact negative settlement")
	}
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	if !c.node.PairTrust.Confirmation.Applied || c.nodeConfirmation != nil || f.n.binding != nil || len(f.requests[wire.OperationOwnerNodePairTrustComplete]) != 1 {
		t.Fatal("revoked old session did not settle original negative outcome without reapproval")
	}
}
func TestNodePairingAvailabilityStartsUnknownAndDeadlineIsLocalOnly(t *testing.T) {
	f := newNodePairingFixture(t)
	c := f.n.c
	c.pairTrustDiscovery = false
	c.pairTrustAvailable = false
	c.pairTrustAvailability = ""
	c.publish()
	if c.Snapshot().Node.Pairing.Availability != "UNKNOWN" {
		t.Fatal("unqueried capability was shown as unsupported")
	}
	f.review()
	if err := f.approve(); err != nil {
		t.Fatal(err)
	}
	before := c.Snapshot().Node.Pairing
	if before.ExpiresAt != c.node.PairTrust.Approval.AcceptBefore {
		t.Fatal("UI used code lifetime instead of the earlier acceptance deadline")
	}
	f.n.n2.now = parseExpiry(before.ExpiresAt)
	after := c.Snapshot().Node.Pairing
	if !after.DeadlineReached || after.State != wire.NodePairTrustOwnerApproved || c.node.PairTrust.Stage != wire.NodePairTrustOwnerApproved {
		t.Fatal("local clock either stayed waiting or invented server expiry")
	}
}

func TestNodePairingCloseDoesNotCancelApprovalOrStopIndependentACK(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	if err := f.approve(); err != nil {
		t.Fatal(err)
	}
	owner := f.n.c.owner.Public().ID
	original := bytes.Clone(f.n.c.node.PairTrust.Confirmation.Request)
	if err := f.n.c.Close(); err != nil {
		t.Fatal(err)
	}
	if f.state != wire.NodePairTrustOwnerApproved || len(f.requests[wire.OperationOwnerNodePairTrustCancel]) != 0 {
		t.Fatal("App close implicitly cancelled remote approval")
	}
	f.ack()
	f.reopen()
	if err := f.n.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNodePairing}); err != nil {
		t.Fatal(err)
	}
	if f.n.c.nodeConfirmation == nil || !bytes.Equal(original, f.n.c.nodeConfirmation.Operation.Request) || f.n.c.owner.Public().ID != owner || f.n.c.node.PairTrust.Stage != wire.NodePairTrustACKed {
		t.Fatal("independent ACK did not survive App close/reopen")
	}
}
func TestNodePairingUncertainApprovalDoesNotBlockLogout(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	f.drop = wire.OperationOwnerNodePairTrustComplete
	if f.approve() == nil {
		t.Fatal("fixture did not leave an uncertain approval")
	}
	original := bytes.Clone(f.n.c.node.PairTrust.Pending.Request)
	if err := f.n.c.Dispatch(context.Background(), Action{Kind: ActionLogout}); err == nil {
		t.Fatal("fixture must keep the logout HTTP result uncertain")
	}
	if f.logoutPosts != 1 || !bytes.Equal(original, f.n.c.node.PairTrust.Pending.Request) || f.n.c.node.PairTrust.Pending.Applied {
		t.Fatal("pairing pending blocked logout or discarded original approval")
	}
}
