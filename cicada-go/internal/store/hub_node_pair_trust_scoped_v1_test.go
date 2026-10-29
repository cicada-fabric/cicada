package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func TestNodePairScopedStoreACKGatesGlobalCountersAndSurvivesReopen(t *testing.T) {
	p := newNPTScopedStoreFixture(t)
	f := p.f
	a, proof, capsule := p.approve(t)
	if _, err := f.db.ProcessHubAppNodeScopedClient(*p.confirmation); !errors.Is(err, ErrNodePairTrustACKRequired) {
		t.Fatal("scoped client bypassed private Node ACK", err)
	}
	var last, next uint64
	if f.db.db.QueryRow(`SELECT last_request_sequence,next_response_sequence FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, f.scope.OwnerID, f.scope.DeviceID).Scan(&last, &next) != nil || last != 0 || next != 1 {
		t.Fatal("reservation advanced global counters")
	}
	if _, err := f.db.db.Exec(`UPDATE client_devices_v2 SET last_request_sequence=last_request_sequence+1 WHERE owner_id=? AND device_id=?`, f.scope.OwnerID, f.scope.DeviceID); err == nil {
		t.Fatal("generic writer bypassed scoped RESERVED trigger")
	}
	ack := p.ack(t, proof, capsule, f.now.Add(4*time.Second))
	seal := ack.Seal
	ack.Seal = func(wire.NodePairTrustScopedResult) ([]byte, error) {
		return nil, errors.New("SYNTHETIC local seal failure")
	}
	if _, err := f.db.ProcessHubNodePairTrustScoped(ack); err == nil {
		t.Fatal("failed response seal committed ACK")
	}
	ack.Seal = seal
	if _, err := f.db.NodeControlKeyForCredential(confirmCredentialDigestForTest(t, f.db, p.context.Candidate.RequestID), p.context.AuthorityNodeID); err == nil {
		t.Fatal("failed ACK seal installed a binding")
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.db, err = New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	result, receipt := p.call(t, ack, f.node)
	if result.State != wire.NodePairTrustScopedACKed || result.Binding == nil || wire.ValidateNodePairTrustScopedAccepted(p.context, a, *result.Binding) != nil {
		t.Fatal("scoped ACK lost actual original Node binding")
	}
	retry, err := f.db.ProcessHubNodePairTrustScoped(ack)
	if err != nil || !bytes.Equal(retry, receipt) {
		t.Fatal("lost ACK response was not exact", err)
	}
	if f.db.db.QueryRow(`SELECT last_request_sequence,next_response_sequence FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, f.scope.OwnerID, f.scope.DeviceID).Scan(&last, &next) != nil || last != 1 || next != 2 {
		t.Fatal("ACK did not settle global counters once")
	}
	status := wire.NodePairTrustScopedOwnerStatus{Format: wire.NodePairTrustScopedFormat, SessionToken: f.session.Token, Scope: a.Scope, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(f.now.Add(5 * time.Second))}
	view, _ := p.call(t, p.input(t, wire.OperationOwnerNodePairTrustScopedStatus, status, f.device, f.now.Add(5*time.Second)), f.device)
	var grantRaw []byte
	if f.db.db.QueryRow(`SELECT owner_proof FROM hub_app_node_grants_v1 WHERE grant_id=?`, a.GrantID).Scan(&grantRaw) != nil {
		t.Fatal("retained scoped grant")
	}
	grant, err := e2ee.VerifyOwnerAppNodeScopedGrant(f.owner.Public(), grantRaw, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.OpenAppNodeScopedConfirmationResponse(f.device, f.hub, grant, p.confirmation.Packet, view.ConfirmationResponse, 1); err != nil {
		t.Fatal("App lost original confirmation response", err)
	}
}

func TestNodePairScopedStoreSecondNodePreservesLegacyAndGlobalCounters(t *testing.T) {
	f := n3Fixture(t, true)
	legacy := f.activate(t)
	original := f.client(t, legacy, 1, f.now.Add(2*time.Second))
	oldReceipt, err := f.db.ProcessHubAppNodeClient(original)
	if err != nil {
		t.Fatal(err)
	}
	before, err := wire.OpenAppNodeConfirmationResponse(f.device, f.hub, legacy, original.Packet, oldReceipt, 1)
	if err != nil || !before.OK {
		t.Fatal("legacy baseline", err)
	}
	legacyBundle := func() []byte {
		var head, claims, state, prov string
		var proof []byte
		var remaining uint64
		if f.db.db.QueryRow(`SELECT json_array(head_version,latest_grant_id,provenance_id) FROM hub_app_node_heads_v1 WHERE owner_id=? AND device_id=?`, f.scope.OwnerID, f.scope.DeviceID).Scan(&head) != nil {
			t.Fatal("legacy head")
		}
		if f.db.db.QueryRow(`SELECT claims_json,state,owner_proof,remaining,provenance_id FROM hub_app_node_grants_v1 WHERE grant_id=?`, legacy.GrantID).Scan(&claims, &state, &proof, &remaining, &prov) != nil {
			t.Fatal("legacy grant")
		}
		raw, err := json.Marshal([]any{head, claims, state, proof, remaining, prov})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	retained := legacyBundle()
	oldOwner, oldDevice := f.owner.Public(), f.device.Public()
	// Only the newly added second Node gets a new synthetic key. The original
	// Node binding, Owner/App/account and their epochs are retained unchanged.
	f.node, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if f.node.Public().ID == before.Binding.NodePublic.ID {
		t.Fatal("second Node did not have an independent identity")
	}
	f.now = f.now.Add(3 * time.Second)
	p := newNPTScopedStoreFixtureFor(t, f, true)
	a, proof, capsule := p.approve(t)
	retry := original
	retry.At = f.now.Add(3 * time.Second)
	if recovered, err := f.db.ProcessHubAppNodeClient(retry); err != nil || !bytes.Equal(recovered, oldReceipt) {
		t.Fatal("legacy original unavailable while scoped RESERVED", err)
	}
	acked, _ := p.call(t, p.ack(t, proof, capsule, f.now.Add(4*time.Second)), f.node)
	if acked.Binding == nil || acked.Binding.NodeID == before.Binding.NodeID {
		t.Fatal("second actual Node binding missing")
	}
	if !bytes.Equal(retained, legacyBundle()) || !reflect.DeepEqual(oldOwner, f.owner.Public()) || !reflect.DeepEqual(oldDevice, f.device.Public()) {
		t.Fatal("new Node replaced legacy authority or identities")
	}
	q, err := wire.NewAppNodeStatus(f.session, legacy.GrantID, f.now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, view, _ := f.call(t, q, f.now.Add(5*time.Second))
	if view.Result == nil || view.Result.Authority.State != wire.AppNodeActive || view.Result.Node == nil || view.Result.Node.NodeID != before.Binding.NodeID || view.Result.Authority.Counters.LastRequestSequence != 2 || view.Result.Authority.Counters.NextResponseSequence != 3 {
		t.Fatal("legacy READ or whole-App counters changed")
	}
	query := wire.NodePairTrustScopedOwnerStatus{Format: wire.NodePairTrustScopedFormat, SessionToken: f.session.Token, Scope: a.Scope, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(f.now.Add(5 * time.Second))}
	observed, _ := p.call(t, p.input(t, wire.OperationOwnerNodePairTrustScopedStatus, query, f.device, f.now.Add(5*time.Second)), f.device)
	var raw []byte
	if f.db.db.QueryRow(`SELECT owner_proof FROM hub_app_node_grants_v1 WHERE grant_id=?`, a.GrantID).Scan(&raw) != nil {
		t.Fatal("scoped grant")
	}
	g, err := e2ee.VerifyOwnerAppNodeScopedGrant(f.owner.Public(), raw, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.OpenAppNodeScopedConfirmationResponse(f.device, f.hub, g, p.confirmation.Packet, observed.ConfirmationResponse, 2); err != nil {
		t.Fatal("second Node borrowed first response sequence", err)
	}
	tx, err := f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	allowed, err := appNodeInitialNamespaceAllowed(tx, f.scope.OwnerID, f.scope.DeviceID, before.Binding.NodeID, "NODE_V1")
	if err != nil || allowed {
		t.Fatal("confirmed legacy Node could reopen INITIAL under Scope2", err)
	}
	allowed, err = appNodeInitialNamespaceAllowed(tx, f.scope.OwnerID, f.scope.DeviceID, acked.Binding.NodeID, "LEGACY_V1")
	if err != nil || allowed {
		t.Fatal("confirmed scoped Node could reopen legacy INITIAL", err)
	}
}

func TestNodePairScopedStorePreparedAndReservedBlockOtherNamespace(t *testing.T) {
	t.Run("legacy prepared", func(t *testing.T) {
		p := newNPTScopedStoreFixture(t)
		f := p.f
		legacyCode := "23456789ABCD"
		_, _, old := f.prepare(t, f.scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: legacyCode}, f.now)
		q, _ := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{NodeID: p.context.AuthorityNodeID}, "", f.now)
		_, status, _ := scopedStoreCall(t, f, q, f.now)
		prepare, err := wire.NewAppNodeScopedPrepare(f.session, status.Result.Authority.Scope, wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetInitial, Code: f.code}, f.owner, f.now)
		if err != nil {
			t.Fatal(err)
		}
		in, result, receipt := scopedStoreCall(t, f, prepare, f.now)
		if result.Result == nil || result.Result.ErrorCode != "AUTHORITY_CONFLICT" {
			t.Fatal("Scoped prepare ignored legacy PREPARED")
		}
		cancel, err := wire.NewAppNodeCancel(f.session, old.Claims.GrantID, 0, f.now.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		f.call(t, cancel, f.now.Add(time.Second))
		_, seal := scopedStoreInput(t, f, prepare, f.now)
		replayed, err := f.db.ProcessHubAppNodeScopedAuthority(in, seal)
		if err != nil || !bytes.Equal(replayed, receipt) {
			t.Fatal("settling other scope turned original rejection into fresh approval", err)
		}
	})
	t.Run("scoped reserved", func(t *testing.T) {
		p := newNPTScopedStoreFixture(t)
		f := p.f
		p.approve(t)
		prepare, err := wire.NewAppNodePrepare(f.session, f.scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: "23456789ABCD"}, f.owner, f.now.Add(4*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		_, result, _ := f.call(t, prepare, f.now.Add(4*time.Second))
		if result.Result == nil || result.Result.ErrorCode != "AUTHORITY_CONFLICT" {
			t.Fatal("legacy prepare ignored scoped RESERVED")
		}
		var n int
		if f.db.db.QueryRow(`SELECT count(*) FROM hub_node_pair_trust_slots_v1 WHERE state='RESERVED'`).Scan(&n) != nil || n != 1 {
			t.Fatal("other namespace changed original reservation")
		}
	})
}

func TestNodePairScopedStoreIndependentHeadsProvenanceAndCancel(t *testing.T) {
	f := n3Fixture(t, true)
	a := newNPTScopedStoreFixtureForNode(t, f, "SYNTHETIC-scoped-A", "456789ABCDEF", 0x41, true)
	aApproval, aProof, aCapsule := a.approve(t)
	a.call(t, a.ack(t, aProof, aCapsule, f.now.Add(4*time.Second)), f.node)
	readHead := func(node string) string {
		var raw string
		if f.db.db.QueryRow(`SELECT json_array(head_version,latest_grant_id,provenance_id) FROM hub_app_node_scoped_heads_v1 WHERE owner_id=? AND device_id=? AND authority_node_id=?`, f.scope.OwnerID, f.scope.DeviceID, node).Scan(&raw) != nil {
			t.Fatal("exact Node head")
		}
		return raw
	}
	aBefore := readHead(a.context.AuthorityNodeID)
	var err error
	f.node, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(6 * time.Second)
	b := newNPTScopedStoreFixtureForNode(t, f, "SYNTHETIC-scoped-B", "56789ABCDEFG", 0x42, true)
	bApproval, bProof, bCapsule := b.approve(t)
	b.call(t, b.ack(t, bProof, bCapsule, f.now.Add(4*time.Second)), f.node)
	if readHead(a.context.AuthorityNodeID) != aBefore {
		t.Fatal("B confirmation overwrote A head/provenance")
	}
	bBefore := readHead(b.context.AuthorityNodeID)
	q, err := wire.NewAppNodeScopedCancel(f.session, a.context.AuthorityNodeID, aApproval.GrantID, 1, f.now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, result, _ := scopedStoreCall(t, f, q, f.now.Add(5*time.Second))
	if result.Result == nil || result.Result.State != wire.AppNodeScopedCompleted {
		t.Fatal("A cancel refused")
	}
	if readHead(b.context.AuthorityNodeID) != bBefore {
		t.Fatal("A cancel advanced B head")
	}
	status, err := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{NodeID: b.context.AuthorityNodeID}, bApproval.GrantID, f.now.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, view, _ := scopedStoreCall(t, f, status, f.now.Add(6*time.Second))
	if view.Result == nil || view.Result.Authority.State != wire.AppNodeScopedActive || view.Result.Authority.CurrentHeadVersion != 1 || view.Result.Node == nil || view.Result.Node.NodeID != b.context.AuthorityNodeID {
		t.Fatal("A cancellation removed B live authority")
	}
}

func TestNodePairScopedStoreAppOriginalReconcileLossRestartAndPermanentFence(t *testing.T) {
	p := newNPTScopedStoreFixture(t)
	f := p.f
	body := p.prepareBody(t)
	original := p.input(t, wire.OperationOwnerNodePairTrustScopedPrepare, body, f.device, f.now.Add(2*time.Second))
	prepared, receipt := p.call(t, original, f.device)
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.db, err = New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	query := wire.NodePairTrustScopedReconcile{Format: wire.NodePairTrustScopedFormat, OriginalPacket: original.Packet, OriginalPacketDigest: wire.NodePairTrustScopedPacketDigest(original.Packet), IssuedAt: appNodeStamp(f.now.Add(3 * time.Second))}
	in := p.input(t, wire.OperationNodePairTrustScopedReconcile, query, f.device, f.now.Add(3*time.Second))
	in.Original = &original
	result, response := p.call(t, in, f.device)
	if result.State != wire.NodePairTrustScopedRecovered || !bytes.Equal(result.OriginalReceipt, receipt) {
		t.Fatal("App could not recover its exact original prepare")
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.db, err = New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.db.ProcessHubNodePairTrustScoped(in)
	if err != nil || !bytes.Equal(retry, response) {
		t.Fatal("lost reconcile response changed after restart", err)
	}
	proof, capsule, err := wire.SealNodePairTrustScopedApproval(f.owner, p.context, p.o, *prepared.Approval, p.s, p.x, f.now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	complete := wire.NodePairTrustScopedOwnerComplete{Format: wire.NodePairTrustScopedFormat, SessionToken: f.session.Token, Scope: body.Scope, Context: p.context, OOBCommitment: p.o, OwnerProof: proof, TrustCapsule: capsule, IssuedAt: appNodeStamp(f.now.Add(3 * time.Second))}
	unadmitted := p.input(t, wire.OperationOwnerNodePairTrustScopedComplete, complete, f.device, f.now.Add(3*time.Second))
	fenceQuery := wire.NodePairTrustScopedReconcile{Format: wire.NodePairTrustScopedFormat, OriginalPacket: unadmitted.Packet, OriginalPacketDigest: wire.NodePairTrustScopedPacketDigest(unadmitted.Packet), IssuedAt: appNodeStamp(f.now.Add(4 * time.Second))}
	fence := p.input(t, wire.OperationNodePairTrustScopedReconcile, fenceQuery, f.device, f.now.Add(4*time.Second))
	fence.Original = &unadmitted
	fenced, _ := p.call(t, fence, f.device)
	if fenced.State != wire.NodePairTrustScopedFenced {
		t.Fatal("unadmitted original was executed during recovery")
	}
	late, lateReceipt := p.call(t, unadmitted, f.device)
	if late.State != wire.NodePairTrustScopedFenced || len(lateReceipt) == 0 {
		t.Fatal("late original escaped permanent fence")
	}
	var count int
	if f.db.db.QueryRow(`SELECT count(*) FROM client_device_requests_v2`).Scan(&count) != nil || count != 0 {
		t.Fatal("historical recovery spent a Client sequence")
	}
}

type nptScopedStoreFixture struct {
	f            *n3StoreFixture
	context      wire.NodePairTrustScopedContext
	o            string
	s, x         []byte
	confirmation *HubAppNodeClientInput
}

func newNPTScopedStoreFixture(t *testing.T) *nptScopedStoreFixture {
	return newNPTScopedStoreFixtureMode(t, true)
}
func newNPTScopedStoreFixtureMode(t *testing.T, commitO bool) *nptScopedStoreFixture {
	t.Helper()
	return newNPTScopedStoreFixtureFor(t, n3Fixture(t, true), commitO)
}
func newNPTScopedStoreFixtureFor(t *testing.T, f *n3StoreFixture, commitO bool) *nptScopedStoreFixture {
	t.Helper()
	return newNPTScopedStoreFixtureForNode(t, f, "synthetic-NPT-scoped-node", "3456789ABCDE", 0x44, commitO)
}
func newNPTScopedStoreFixtureForNode(t *testing.T, f *n3StoreFixture, nodeID, code string, credentialTag byte, commitO bool) *nptScopedStoreFixture {
	t.Helper()
	p := &nptScopedStoreFixture{f: f, s: bytes.Repeat([]byte{0x53}, 32), x: bytes.Repeat([]byte{0x58}, 32)}
	f.code = code
	attempt, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	p.context.AttemptID = attempt
	b := wire.NodePairTrustScopedStart{ScopeVersion: 2, Format: wire.NodePairTrustScopedFormat, Hub: f.hub, Origin: f.scope.Origin, DescriptorDigest: strings.Repeat("ab", 32), NodeID: nodeID, NodeName: "Synthetic NPT Node", CredentialDigest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{credentialTag}, 32)), RequestNonce: bytes.Repeat([]byte{0x4c}, 32), HubNodeControlPublic: f.nodeControl.Public(), HubNodeControlKeyVersion: 1, IssuedAt: appNodeStamp(f.now), ExpiresAt: appNodeStamp(f.now.Add(10 * time.Minute))}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: f.hub.HubID, NodeID: b.NodeID, RequestNonce: b.RequestNonce, CredentialDigest: b.CredentialDigest, NodePublicIdentity: f.node.Public(), HubPublicIdentity: f.nodeControl.Public(), HubKeyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	b.PairingProof, err = e2ee.Seal(f.node, f.nodeControl.Public(), transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	in := p.input(t, wire.OperationNodePairTrustScopedStart, b, f.node, f.now)
	in.Start = &NodeControlKeyRequestInput{Mode: "INITIAL", NodeID: b.NodeID, NodeName: b.NodeName, CredentialDigest: b.CredentialDigest, CodeDigest: mustNPTScopedCodeDigest(t, f.hub.HubID, f.code), NodePublicIdentity: f.node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(f.node.Public()), ProofPacket: b.PairingProof, HubPublicIdentity: f.nodeControl.Public(), HubKeyVersion: 1, HubFingerprint: nodewire.IdentityFingerprint(f.nodeControl.Public()), ExpiresAt: f.now.Add(10 * time.Minute)}
	in.Selector = f.code
	result, receipt := p.call(t, in, f.node)
	p.context = *result.Context
	d, _ := wire.NodePairTrustScopedContextDigest(p.context)
	p.o, _ = wire.NodePairTrustScopedOOBCommitment(d, p.s)
	retry, e := f.db.ProcessHubNodePairTrustScoped(in)
	if e != nil || !bytes.Equal(retry, receipt) {
		t.Fatal("START lost response changed original", e)
	}
	commit := wire.NodePairTrustScopedCommit{Format: wire.NodePairTrustScopedFormat, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(f.now)}
	if commitO {
		p.call(t, p.input(t, wire.OperationNodePairTrustScopedCommit, commit, f.node, f.now), f.node)
	}
	return p
}
func mustNPTScopedCodeDigest(t *testing.T, hub, code string) string {
	t.Helper()
	d, e := wire.AppNodeCodeDigest(hub, code)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func (p *nptScopedStoreFixture) input(t *testing.T, op string, body any, key *e2ee.Identity, at time.Time) HubNodePairTrustScopedInput {
	t.Helper()
	id, e := wire.NewRequestID()
	if e != nil {
		t.Fatal(e)
	}
	attempt := p.context.AttemptID
	if attempt == "" {
		attempt = strings.Repeat("a3", 16)
	}
	h := wire.NodePairTrustScopedPacket{Operation: op, RequestID: id, AttemptID: attempt}
	raw, e := wire.SealNodePairTrustScopedRequest(key, p.f.hub, h, body, at)
	if e != nil {
		t.Fatal("seal new typed packet", op, e)
	}
	decoded := wire.NewNodePairTrustScopedRequestBody(op)
	header, e := wire.OpenNodePairTrustScopedRequest(p.f.hubPrivate, p.f.hub, raw, op, decoded, at)
	if e != nil {
		t.Fatal(e)
	}
	return HubNodePairTrustScopedInput{Hub: p.f.hub, NodeControlPublic: p.f.nodeControl.Public(), Header: header, Body: reflect.ValueOf(decoded).Elem().Interface(), Packet: raw, At: at,
		Seal: func(r wire.NodePairTrustScopedResult) ([]byte, error) {
			return wire.SealNodePairTrustScopedResponse(p.f.hubPrivate, p.f.hub, raw, body, r)
		},
		OpenConfirmation: func(raw []byte, public e2ee.PublicIdentity) (HubAppNodeClientInput, error) {
			if p.confirmation == nil || !bytes.Equal(raw, p.confirmation.Packet) || !reflect.DeepEqual(public, p.f.device.Public()) {
				return HubAppNodeClientInput{}, ErrNodePairTrustRejected
			}
			return *p.confirmation, nil
		},
	}
}
func (p *nptScopedStoreFixture) call(t *testing.T, in HubNodePairTrustScopedInput, key *e2ee.Identity) (wire.NodePairTrustScopedResult, []byte) {
	t.Helper()
	raw, e := p.f.db.ProcessHubNodePairTrustScoped(in)
	if e != nil {
		t.Fatal("Store pairing", in.Header.Operation, e)
	}
	out, e := wire.OpenNodePairTrustScopedResponse(key, p.f.hub, in.Packet, raw, in.Body)
	if e != nil {
		t.Fatal("Store sealed result", in.Header.Operation, e)
	}
	return out, raw
}
func (p *nptScopedStoreFixture) prepareBody(t *testing.T) wire.NodePairTrustScopedOwnerPrepare {
	t.Helper()
	f := p.f
	g := scopedStoreActivate(t, p)
	var last uint64
	if f.db.db.QueryRow(`SELECT last_request_sequence FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, f.scope.OwnerID, f.scope.DeviceID).Scan(&last) != nil {
		t.Fatal("global request sequence")
	}
	confirm := scopedStoreClient(t, f, g, last+1, f.now.Add(2*time.Second))
	p.confirmation = &confirm
	var grant []byte
	if e := f.db.db.QueryRow(`SELECT owner_proof FROM hub_app_node_grants_v1 WHERE grant_id=?`, g.GrantID).Scan(&grant); e != nil {
		t.Fatal(e)
	}
	return wire.NodePairTrustScopedOwnerPrepare{Format: wire.NodePairTrustScopedFormat, SessionToken: f.session.Token, Scope: g.Scope, Context: p.context, OOBCommitment: p.o, GrantProof: grant, ConfirmationPacket: confirm.Packet, IssuedAt: appNodeStamp(f.now.Add(2 * time.Second))}
}
func (p *nptScopedStoreFixture) approve(t *testing.T) (wire.NodePairTrustScopedApproval, []byte, []byte) {
	t.Helper()
	f := p.f
	b := p.prepareBody(t)
	r, _ := p.call(t, p.input(t, wire.OperationOwnerNodePairTrustScopedPrepare, b, f.device, f.now.Add(2*time.Second)), f.device)
	proof, capsule, e := wire.SealNodePairTrustScopedApproval(f.owner, p.context, p.o, *r.Approval, p.s, p.x, f.now.Add(3*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	complete := wire.NodePairTrustScopedOwnerComplete{Format: wire.NodePairTrustScopedFormat, SessionToken: f.session.Token, Scope: b.Scope, Context: p.context, OOBCommitment: p.o, OwnerProof: proof, TrustCapsule: capsule, IssuedAt: appNodeStamp(f.now.Add(3 * time.Second))}
	p.call(t, p.input(t, wire.OperationOwnerNodePairTrustScopedComplete, complete, f.device, f.now.Add(3*time.Second)), f.device)
	return *r.Approval, proof, capsule
}
func (p *nptScopedStoreFixture) ack(t *testing.T, proof, capsule []byte, at time.Time) HubNodePairTrustScopedInput {
	t.Helper()
	f := p.f
	poll := wire.NodePairTrustScopedPoll{Format: wire.NodePairTrustScopedFormat, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(at)}
	q := p.input(t, wire.OperationNodePairTrustScopedPoll, poll, f.node, at)
	r, receipt := p.call(t, q, f.node)
	if !bytes.Equal(r.OwnerProof, proof) || !bytes.Equal(r.TrustCapsule, capsule) {
		t.Fatal("exact Owner E changed")
	}
	opened, e := wire.OpenNodePairTrustScopedCapsule(f.node, p.context, p.o, r.OwnerProof, r.TrustCapsule, p.s, at)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(opened.OOBSecret)
	defer clear(opened.ACKNonce)
	b := wire.NodePairTrustScopedACK{Format: wire.NodePairTrustScopedFormat, Context: p.context, OOBCommitment: p.o, PollPacketDigest: wire.NodePairTrustScopedPacketDigest(q.Packet), PollReceiptDigest: wire.NodePairTrustScopedPacketDigest(receipt), OwnerProofDigest: wire.NodePairTrustScopedProofDigest(proof), CapsuleDigest: wire.NodePairTrustScopedCapsuleDigest(capsule), ACKNonce: append([]byte(nil), opened.ACKNonce...), IssuedAt: appNodeStamp(at)}
	return p.input(t, wire.OperationNodePairTrustScopedACK, b, f.node, at)
}

func scopedStoreInput(t *testing.T, f *n3StoreFixture, body any, at time.Time) (HubAppNodeScopedAuthorityInput, HubAppNodeScopedSeal) {
	t.Helper()
	raw, err := wire.SealClientRequest(f.device, f.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	binding, route, err := wire.NewClientRoute(f.hub, body, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var out any
	switch body.(type) {
	case wire.AppNodeScopedPrepare:
		out = new(wire.AppNodeScopedPrepare)
	case wire.AppNodeScopedComplete:
		out = new(wire.AppNodeScopedComplete)
	case wire.AppNodeScopedStatus:
		out = new(wire.AppNodeScopedStatus)
	case wire.AppNodeScopedCancel:
		out = new(wire.AppNodeScopedCancel)
	case wire.AppNodeScopedReconcile:
		out = new(wire.AppNodeScopedReconcile)
	default:
		t.Fatal("unknown scoped test body")
	}
	pub := f.device.Public()
	if err := wire.OpenRequestAt(f.hubPrivate, &pub, binding, route, raw, out, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reflect.ValueOf(out).Elem().Interface(), body) {
		t.Fatal("typed authenticated Store body changed")
	}
	return HubAppNodeScopedAuthorityInput{Hub: f.hub, NodeControlPublic: f.nodeControl.Public(), Device: pub, Packet: raw, Body: body, At: at}, func(v any) ([]byte, error) { return wire.SealResponse(f.hubPrivate, pub, route, v) }
}
func scopedStoreCall(t *testing.T, f *n3StoreFixture, body any, at time.Time) (HubAppNodeScopedAuthorityInput, wire.AppNodeScopedResponse, []byte) {
	t.Helper()
	in, seal := scopedStoreInput(t, f, body, at)
	raw, err := f.db.ProcessHubAppNodeScopedAuthority(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	result, err := wire.OpenAppNodeScopedResponse(f.device, f.hub, in.Packet, raw)
	if err != nil {
		t.Fatal("scoped Store response", err)
	}
	return in, result, raw
}
func scopedStoreActivate(t *testing.T, p *nptScopedStoreFixture) e2ee.OwnerAppNodeScopedGrantClaims {
	t.Helper()
	f := p.f
	status, err := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{NodeID: p.context.AuthorityNodeID}, "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	_, observed, _ := scopedStoreCall(t, f, status, f.now)
	if observed.Result == nil {
		t.Fatal("scoped status")
	}
	prepare, err := wire.NewAppNodeScopedPrepare(f.session, observed.Result.Authority.Scope, wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetInitial, Code: f.code}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	original, ch, _ := scopedStoreCall(t, f, prepare, f.now)
	if ch.Challenge == nil {
		t.Fatal("scoped prepare refused", ch.Result.ErrorCode)
	}
	complete, err := wire.NewAppNodeScopedComplete(f.session, prepare, original.Packet, *ch.Challenge, f.owner, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, result, _ := scopedStoreCall(t, f, complete, f.now.Add(time.Second))
	if result.Result == nil || result.Result.Authority.State != wire.AppNodeScopedActive {
		t.Fatal("scoped activation")
	}
	return ch.Challenge.Claims
}
func scopedStoreClient(t *testing.T, f *n3StoreFixture, g e2ee.OwnerAppNodeScopedGrantClaims, sequence uint64, at time.Time) HubAppNodeClientInput {
	t.Helper()
	raw, err := wire.SealAppNodeScopedConfirmation(f.device, f.hub, g, f.code, sequence, at)
	if err != nil {
		t.Fatal(err)
	}
	b := clientwire.Binding{HubID: f.hub.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, SessionEpoch: g.Scope.ClientSessionEpoch, HubKeyVersion: 1, DeviceKeyVersion: 1}
	opened, err := clientwire.OpenRequest(f.hubPrivate, f.device.Public(), b, raw)
	if err != nil {
		t.Fatal(err)
	}
	r := opened.Route
	return HubAppNodeClientInput{Hub: f.hub, NodeControlPublic: f.nodeControl.Public(), Device: f.device.Public(), Packet: raw, Route: r, Code: f.code, CandidateDigest: g.Candidate.CandidateDigest, CandidateVersion: g.Candidate.Version, At: at, Seal: func(seq uint64, id string, binding *NodeControlKeyBinding, code string) ([]byte, error) {
		body := struct {
			Error       string `json:"error,omitempty"`
			OK          bool   `json:"ok"`
			OperationID string `json:"operation_id"`
			RequestID   string `json:"request_id"`
			Result      any    `json:"result,omitempty"`
		}{Error: code, OK: code == "", OperationID: r.OperationID, RequestID: id}
		if binding != nil {
			body.Result = binding
		}
		plain, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reply := r
		reply.Direction = clientwire.DirectionResponse
		reply.Sequence = seq
		reply.SenderKeyID, reply.ReceiverKeyID = reply.ReceiverKeyID, reply.SenderKeyID
		reply.SenderKeyVersion, reply.ReceiverKeyVersion = reply.ReceiverKeyVersion, reply.SenderKeyVersion
		return clientwire.SealResponse(f.hubPrivate, f.device.Public(), b, reply, plain)
	}}
}
