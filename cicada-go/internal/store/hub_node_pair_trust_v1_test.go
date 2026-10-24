package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type nptStoreFixture struct {
	f            *n3StoreFixture
	context      wire.NodePairTrustContext
	o            string
	s, x         []byte
	confirmation *HubAppNodeClientInput
}

func newNPTStoreFixture(t *testing.T) *nptStoreFixture {
	t.Helper()
	p := &nptStoreFixture{f: n3Fixture(t, true), s: bytes.Repeat([]byte{0x53}, 32), x: bytes.Repeat([]byte{0x58}, 32)}
	f := p.f
	f.code = "3456789ABCDE"
	b := wire.NodePairTrustStart{Format: wire.NodePairTrustFormat, Hub: f.hub, Origin: f.scope.Origin, DescriptorDigest: strings.Repeat("ab", 32), NodeID: "synthetic-NPT-node", NodeName: "Synthetic NPT Node", CredentialDigest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32)), RequestNonce: bytes.Repeat([]byte{0x4c}, 32), HubNodeControlPublic: f.nodeControl.Public(), HubNodeControlKeyVersion: 1, IssuedAt: appNodeStamp(f.now), ExpiresAt: appNodeStamp(f.now.Add(10 * time.Minute))}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: f.hub.HubID, NodeID: b.NodeID, RequestNonce: b.RequestNonce, CredentialDigest: b.CredentialDigest, NodePublicIdentity: f.node.Public(), HubPublicIdentity: f.nodeControl.Public(), HubKeyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	b.PairingProof, err = e2ee.Seal(f.node, f.nodeControl.Public(), transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	in := p.input(t, wire.OperationNodePairTrustStart, b, f.node, f.now)
	in.Start = &NodeControlKeyRequestInput{Mode: "INITIAL", NodeID: b.NodeID, NodeName: b.NodeName, CredentialDigest: b.CredentialDigest, CodeDigest: mustNPTCodeDigest(t, f.hub.HubID, f.code), NodePublicIdentity: f.node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(f.node.Public()), ProofPacket: b.PairingProof, HubPublicIdentity: f.nodeControl.Public(), HubKeyVersion: 1, HubFingerprint: nodewire.IdentityFingerprint(f.nodeControl.Public()), ExpiresAt: f.now.Add(10 * time.Minute)}
	in.Selector = f.code
	result, receipt := p.call(t, in, f.node)
	p.context = *result.Context
	d, _ := wire.NodePairTrustContextDigest(p.context)
	p.o, _ = wire.NodePairTrustOOBCommitment(d, p.s)
	retry, e := f.db.ProcessHubNodePairTrust(in)
	if e != nil || !bytes.Equal(retry, receipt) {
		t.Fatal("START lost response changed original", e)
	}
	commit := wire.NodePairTrustCommit{Format: wire.NodePairTrustFormat, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(f.now)}
	p.call(t, p.input(t, wire.OperationNodePairTrustCommit, commit, f.node, f.now), f.node)
	return p
}
func mustNPTCodeDigest(t *testing.T, hub, code string) string {
	t.Helper()
	d, e := wire.AppNodeCodeDigest(hub, code)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func (p *nptStoreFixture) input(t *testing.T, op string, body any, key *e2ee.Identity, at time.Time) HubNodePairTrustInput {
	t.Helper()
	id, e := wire.NewRequestID()
	if e != nil {
		t.Fatal(e)
	}
	attempt := p.context.AttemptID
	if attempt == "" {
		attempt = strings.Repeat("a3", 16)
	}
	h := wire.NodePairTrustPacket{Operation: op, RequestID: id, AttemptID: attempt}
	raw, e := wire.SealNodePairTrustRequest(key, p.f.hub, h, body, at)
	if e != nil {
		t.Fatal("seal new typed packet", op, e)
	}
	decoded := wire.NewNodePairTrustRequestBody(op)
	header, e := wire.OpenNodePairTrustRequest(p.f.hubPrivate, p.f.hub, raw, op, decoded, at)
	if e != nil {
		t.Fatal(e)
	}
	return HubNodePairTrustInput{Hub: p.f.hub, NodeControlPublic: p.f.nodeControl.Public(), Header: header, Body: reflect.ValueOf(decoded).Elem().Interface(), Packet: raw, At: at,
		Seal: func(r wire.NodePairTrustResult) ([]byte, error) {
			return wire.SealNodePairTrustResponse(p.f.hubPrivate, p.f.hub, raw, body, r)
		},
		OpenConfirmation: func(raw []byte, public e2ee.PublicIdentity) (HubAppNodeClientInput, error) {
			if p.confirmation == nil || !bytes.Equal(raw, p.confirmation.Packet) || !reflect.DeepEqual(public, p.f.device.Public()) {
				return HubAppNodeClientInput{}, ErrNodePairTrustRejected
			}
			return *p.confirmation, nil
		},
	}
}
func (p *nptStoreFixture) call(t *testing.T, in HubNodePairTrustInput, key *e2ee.Identity) (wire.NodePairTrustResult, []byte) {
	t.Helper()
	raw, e := p.f.db.ProcessHubNodePairTrust(in)
	if e != nil {
		t.Fatal("Store pairing", in.Header.Operation, e)
	}
	out, e := wire.OpenNodePairTrustResponse(key, p.f.hub, in.Packet, raw, in.Body)
	if e != nil {
		t.Fatal("Store sealed result", in.Header.Operation, e)
	}
	return out, raw
}
func (p *nptStoreFixture) prepareBody(t *testing.T) wire.NodePairTrustOwnerPrepare {
	t.Helper()
	f := p.f
	g := f.activate(t)
	confirm := f.client(t, g, 1, f.now.Add(2*time.Second))
	p.confirmation = &confirm
	var grant []byte
	if e := f.db.db.QueryRow(`SELECT owner_proof FROM hub_app_node_grants_v1 WHERE grant_id=?`, g.GrantID).Scan(&grant); e != nil {
		t.Fatal(e)
	}
	return wire.NodePairTrustOwnerPrepare{Format: wire.NodePairTrustFormat, SessionToken: f.session.Token, Scope: g.Scope, Context: p.context, OOBCommitment: p.o, GrantProof: grant, ConfirmationPacket: confirm.Packet, IssuedAt: appNodeStamp(f.now.Add(2 * time.Second))}
}
func (p *nptStoreFixture) approve(t *testing.T) (wire.NodePairTrustApproval, []byte, []byte) {
	t.Helper()
	f := p.f
	b := p.prepareBody(t)
	r, _ := p.call(t, p.input(t, wire.OperationOwnerNodePairTrustPrepare, b, f.device, f.now.Add(2*time.Second)), f.device)
	proof, capsule, e := wire.SealNodePairTrustApproval(f.owner, p.context, p.o, *r.Approval, p.s, p.x, f.now.Add(3*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	complete := wire.NodePairTrustOwnerComplete{Format: wire.NodePairTrustFormat, SessionToken: f.session.Token, Scope: b.Scope, Context: p.context, OOBCommitment: p.o, OwnerProof: proof, TrustCapsule: capsule, IssuedAt: appNodeStamp(f.now.Add(3 * time.Second))}
	p.call(t, p.input(t, wire.OperationOwnerNodePairTrustComplete, complete, f.device, f.now.Add(3*time.Second)), f.device)
	return *r.Approval, proof, capsule
}
func (p *nptStoreFixture) ack(t *testing.T, proof, capsule []byte, at time.Time) HubNodePairTrustInput {
	t.Helper()
	f := p.f
	poll := wire.NodePairTrustPoll{Format: wire.NodePairTrustFormat, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(at)}
	q := p.input(t, wire.OperationNodePairTrustPoll, poll, f.node, at)
	r, receipt := p.call(t, q, f.node)
	if !bytes.Equal(r.OwnerProof, proof) || !bytes.Equal(r.TrustCapsule, capsule) {
		t.Fatal("exact Owner E changed")
	}
	opened, e := wire.OpenNodePairTrustCapsule(f.node, p.context, p.o, r.OwnerProof, r.TrustCapsule, p.s, at)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(opened.OOBSecret)
	defer clear(opened.ACKNonce)
	b := wire.NodePairTrustACK{Format: wire.NodePairTrustFormat, Context: p.context, OOBCommitment: p.o, PollPacketDigest: wire.NodePairTrustPacketDigest(q.Packet), PollReceiptDigest: wire.NodePairTrustPacketDigest(receipt), OwnerProofDigest: wire.NodePairTrustProofDigest(proof), CapsuleDigest: wire.NodePairTrustCapsuleDigest(capsule), ACKNonce: append([]byte(nil), opened.ACKNonce...), IssuedAt: appNodeStamp(at)}
	return p.input(t, wire.OperationNodePairTrustACK, b, f.node, at)
}

func TestNodePairStoreACKGatesOriginalCountersAndSurvivesReopen(t *testing.T) {
	p := newNPTStoreFixture(t)
	f := p.f
	code := mustNPTCodeDigest(t, f.hub.HubID, f.code)
	if _, e := f.db.ConfirmNodeControlKeyRequest(f.scope.OwnerID, f.scope.DeviceID, code, 1, p.context.Candidate.CandidateDigest, f.nodeControl.Public().ID, nodewire.IdentityFingerprint(f.nodeControl.Public())); !errors.Is(e, ErrNodePairTrustACKRequired) {
		t.Fatal("old direct writer bypassed ACK", e)
	}
	a, proof, capsule := p.approve(t)
	if _, e := f.db.ProcessHubAppNodeClient(*p.confirmation); !errors.Is(e, ErrNodePairTrustACKRequired) {
		t.Fatal("old N3 writer consumed reserved confirm", e)
	}
	var last, next uint64
	if e := f.db.db.QueryRow(`SELECT last_request_sequence,next_response_sequence FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, f.scope.OwnerID, f.scope.DeviceID).Scan(&last, &next); e != nil || last != 0 || next != 1 {
		t.Fatal("reservation advanced counters", e)
	}
	if _, e := f.db.db.Exec(`UPDATE client_devices_v2 SET last_request_sequence=last_request_sequence+1 WHERE owner_id=? AND device_id=?`, f.scope.OwnerID, f.scope.DeviceID); e == nil {
		t.Fatal("generic writer bypassed reserved slot trigger")
	}
	ack := p.ack(t, proof, capsule, f.now.Add(4*time.Second))
	seal := ack.Seal
	ack.Seal = func(wire.NodePairTrustResult) ([]byte, error) { return nil, errors.New("SYNTHETIC lost local seal") }
	if _, e := f.db.ProcessHubNodePairTrust(ack); e == nil {
		t.Fatal("failed ACK seal committed")
	}
	ack.Seal = seal
	if _, e := f.db.NodeControlKeyForCredential(confirmCredentialDigestForTest(t, f.db, p.context.Candidate.RequestID), p.context.Candidate.NodeID); e == nil {
		t.Fatal("failed seal activated binding")
	}
	if e := f.db.Close(); e != nil {
		t.Fatal(e)
	}
	db, e := New(f.path)
	if e != nil {
		t.Fatal(e)
	}
	f.db = db
	defer db.Close()
	r, receipt := p.call(t, ack, f.node)
	if r.State != wire.NodePairTrustACKed || r.Binding == nil || wire.ValidateNodePairTrustAccepted(p.context, a, *r.Binding) != nil {
		t.Fatal("ACK did not preserve original binding")
	}
	retry, e := f.db.ProcessHubNodePairTrust(ack)
	if e != nil || !bytes.Equal(retry, receipt) {
		t.Fatal("lost ACK response changed original", e)
	}
	if e := f.db.db.QueryRow(`SELECT last_request_sequence,next_response_sequence FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, f.scope.OwnerID, f.scope.DeviceID).Scan(&last, &next); e != nil || last != 1 || next != 2 {
		t.Fatal("ACK counters did not settle once", e)
	}
	q := wire.NodePairTrustOwnerStatus{Format: wire.NodePairTrustFormat, SessionToken: f.session.Token, Scope: a.Scope, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(f.now.Add(5 * time.Second))}
	status, _ := p.call(t, p.input(t, wire.OperationOwnerNodePairTrustStatus, q, f.device, f.now.Add(5*time.Second)), f.device)
	if _, e := wire.OpenAppNodeConfirmationResponse(f.device, f.hub, mustNPTGrant(t, p), p.confirmation.Packet, status.ConfirmationResponse, 1); e != nil {
		t.Fatal("App did not get original sealed Client response", e)
	}
}
func confirmCredentialDigestForTest(t *testing.T, db *Store, id string) string {
	t.Helper()
	var s string
	if e := db.db.QueryRow(`SELECT node_credential_digest FROM node_control_key_requests_v1 WHERE id=?`, id).Scan(&s); e != nil {
		t.Fatal(e)
	}
	return s
}
func mustNPTGrant(t *testing.T, p *nptStoreFixture) e2ee.OwnerAppNodeGrantClaims {
	t.Helper()
	r, e := nodePairLoadForTest(p.f.db, p.context.AttemptID)
	if e != nil {
		t.Fatal(e)
	}
	var g e2ee.OwnerAppNodeGrant
	if json.Unmarshal(r.Grant, &g) != nil {
		t.Fatal("grant")
	}
	return g.Claims
}
func nodePairLoadForTest(db *Store, id string) (*nodePairTrustRecord, error) {
	tx, e := db.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	return nodePairLoad(tx, id)
}

func (p *nptStoreFixture) reconcileConfirm(t *testing.T, at time.Time) ([]byte, error) {
	t.Helper()
	g := mustNPTGrant(t, p)
	q, err := wire.NewAppNodeReconcile(p.f.session, wire.AppNodeOriginalClient, g.GrantID, p.confirmation.Packet, at)
	if err != nil {
		return nil, err
	}
	in, seal := p.f.input(t, q, at)
	in.OriginalClient = p.confirmation
	raw, err := p.f.db.ProcessHubAppNodeAuthority(in, seal)
	if err != nil {
		return nil, err
	}
	r, err := wire.OpenAppNodeResponse(p.f.device, p.f.hub, in.Packet, raw)
	if err != nil {
		return nil, err
	}
	return r.Reconciled.ReceiptPacket, nil
}

func TestNodePairStoreTerminalUsesOnlyOriginalNegativeReceipt(t *testing.T) {
	for _, kind := range []string{"cancel", "expiry", "logout", "Owner-revoke", "App-epoch"} {
		t.Run(kind, func(t *testing.T) {
			p := newNPTStoreFixture(t)
			f := p.f
			a, proof, capsule := p.approve(t)
			validACK := p.ack(t, proof, capsule, f.now.Add(4*time.Second))
			if _, e := p.reconcileConfirm(t, f.now.Add(4*time.Second)); !errors.Is(e, ErrNodePairTrustACKRequired) {
				t.Fatal("pending old reconcile settled slot", e)
			}
			at := f.now.Add(5 * time.Second)
			switch kind {
			case "cancel":
				q := wire.NodePairTrustCancel{Format: wire.NodePairTrustFormat, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(at)}
				p.call(t, p.input(t, wire.OperationNodePairTrustCancel, q, f.node, at), f.node)
			case "expiry":
				at = f.now.Add(11 * time.Minute)
			case "logout":
				if _, e := f.db.db.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE session_id=?`, a.Scope.AccountSessionID); e != nil {
					t.Fatal(e)
				}
			case "Owner-revoke":
				if _, e := f.db.RevokeOwnerApprovalKeyLocal(a.Scope.OwnerID, a.Scope.OwnerPublic.ID, 1); e != nil {
					t.Fatal(e)
				}
			case "App-epoch":
				if _, e := f.db.AdvanceClientDeviceSessionEpoch(a.Scope.OwnerID, a.Scope.DeviceID, 1); e != nil {
					t.Fatal("slot blocked security epoch change", e)
				}
			}
			original := *p.confirmation
			original.At = at
			if _, e := f.db.ProcessHubAppNodeClient(original); e == nil {
				t.Fatal("terminal raw confirmation settled")
			}
			receipt, e := p.reconcileConfirm(t, at)
			// Preserve the signed original, X and authenticated poll while only
			// advancing the trusted writer clock, including an epoch replacement.
			validACK.At = at
			if _, ackErr := f.db.ProcessHubNodePairTrust(validACK); ackErr == nil {
				t.Fatal("terminal accepted an otherwise valid original ACK")
			}
			if kind == "App-epoch" {
				if e == nil {
					t.Fatal("old counter moved into new epoch")
				}
				return
			}
			if e != nil {
				t.Fatal("terminal original fence", e)
			}
			opened, e := wire.OpenAppNodeConfirmationResponse(f.device, f.hub, mustNPTGrant(t, p), p.confirmation.Packet, receipt, 1)
			if e != nil || opened.OK || opened.Binding != nil {
				t.Fatal("terminal did not return authentic negative old response", e)
			}
			exact, e := f.db.ProcessHubAppNodeClient(original)
			if e != nil || !bytes.Equal(exact, receipt) {
				t.Fatal("negative exact original changed", e)
			}
			var last, next int
			if e := f.db.db.QueryRow(`SELECT last_request_sequence,next_response_sequence FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, a.Scope.OwnerID, a.Scope.DeviceID).Scan(&last, &next); e != nil || last != 1 || next != 2 {
				t.Fatal("terminal fence counter did not settle once", e)
			}
		})
	}
}

func TestNodePairStoreMarkedCandidateMissingSideCannotFallBack(t *testing.T) {
	p := newNPTStoreFixture(t)
	f := p.f
	var required int
	if e := f.db.db.QueryRow(`SELECT require_pair_trust_ack FROM node_control_key_requests_v1 WHERE id=?`, p.context.Candidate.RequestID).Scan(&required); e != nil || required != 1 {
		t.Fatal("original candidate has no independent ACK marker", e)
	}
	if _, e := f.db.db.Exec(`UPDATE node_control_key_requests_v1 SET require_pair_trust_ack=0 WHERE id=?`, p.context.Candidate.RequestID); e == nil {
		t.Fatal("ACK marker could be cleared")
	}
	if _, e := f.db.db.Exec(`DELETE FROM hub_node_pair_trust_v1 WHERE attempt_id=?`, p.context.AttemptID); e == nil {
		t.Fatal("live side row could be discarded")
	}
	// Isolated corruption injection removes only the side-row deletion guard.
	if _, e := f.db.db.Exec(`DROP TRIGGER hub_node_pair_trust_v1_no_delete`); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.db.Exec(`DELETE FROM hub_node_pair_trust_v1 WHERE attempt_id=?`, p.context.AttemptID); e != nil {
		t.Fatal(e)
	}
	code := mustNPTCodeDigest(t, f.hub.HubID, f.code)
	if _, e := f.db.ConfirmNodeControlKeyRequest(f.scope.OwnerID, f.scope.DeviceID, code, 1, p.context.Candidate.CandidateDigest, f.nodeControl.Public().ID, nodewire.IdentityFingerprint(f.nodeControl.Public())); e == nil {
		t.Fatal("missing side silently became legacy")
	}
}

func TestNodePairStoreAnonymousExpiryGCAndBudgetDoNotBurnACKCapacity(t *testing.T) {
	p := newNPTStoreFixture(t)
	f := p.f
	tx, e := f.db.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if e = nodePairGC(tx, f.now.Add(21*time.Minute)); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	var n, rows, used int
	if e = f.db.db.QueryRow(`SELECT count(*) FROM hub_node_pair_trust_v1 WHERE attempt_id=?`, p.context.AttemptID).Scan(&n); e != nil || n != 0 {
		t.Fatal("anonymous attempt retained after recovery window", e)
	}
	if e = f.db.db.QueryRow(`SELECT count(*) FROM node_control_key_requests_v1 WHERE id=?`, p.context.Candidate.RequestID).Scan(&n); e != nil || n != 0 {
		t.Fatal("anonymous original candidate not reclaimed", e)
	}
	if e = f.db.db.QueryRow(`SELECT anonymous_rows,read_rows,read_bytes FROM hub_node_pair_trust_budget_v1 WHERE id=1`).Scan(&n, &rows, &used); e != nil || n != 0 || rows != 0 || used != 0 {
		t.Fatal("GC budget accounting", e, n, rows, used)
	}
	q := wire.NodePairTrustCommit{Format: wire.NodePairTrustFormat, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(f.now)}
	in := p.input(t, wire.OperationNodePairTrustCommit, q, f.node, f.now)
	in.At = f.now.Add(21 * time.Minute)
	if _, e := f.db.ProcessHubNodePairTrust(in); e == nil {
		t.Fatal("expired original reexecuted after GC")
	}
	// Read-cache exhaustion is separately charged; an authorized ACK can still
	// settle from its reserved critical allowance.
	p = newNPTStoreFixture(t)
	f = p.f
	_, proof, capsule := p.approve(t)
	ack := p.ack(t, proof, capsule, f.now.Add(4*time.Second))
	if e = f.db.db.QueryRow(`SELECT read_bytes FROM hub_node_pair_trust_budget_v1 WHERE id=1`).Scan(&used); e != nil {
		t.Fatal(e)
	}
	for i := 0; used < 16<<20; i++ {
		size := 1 << 20
		if 16<<20-used < size {
			size = 16<<20 - used
		}
		if _, e = f.db.db.Exec(`INSERT INTO hub_node_pair_trust_reads_v1 VALUES(?,?,?,?,?,?,?, ?,?)`, "SYNTHETIC-burn", string(rune('a'+i)), "SYNTHETIC-unapproved", "SYNTHETIC", strings.Repeat("ab", 32), "PENDING", bytes.Repeat([]byte{0x53}, size), appNodeStamp(f.now), appNodeStamp(f.now.Add(2*time.Minute))); e != nil {
			t.Fatal(e)
		}
		used += size
	}
	if _, e = f.db.ProcessHubNodePairTrust(ack); e != nil {
		t.Fatal("anonymous read cache blocked reserved ACK", e)
	}
	r, e := nodePairLoadForTest(f.db, p.context.AttemptID)
	if e != nil {
		t.Fatal(e)
	}
	status := wire.NodePairTrustOwnerStatus{Format: wire.NodePairTrustFormat, SessionToken: f.session.Token, Scope: r.Approval.Scope, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(f.now.Add(5 * time.Second))}
	if _, e = f.db.ProcessHubNodePairTrust(p.input(t, wire.OperationOwnerNodePairTrustStatus, status, f.device, f.now.Add(5*time.Second))); !errors.Is(e, ErrNodePairTrustCapacity) {
		t.Fatal("read exhaustion was not a sanitized retryable capacity result", e)
	}
	var retained int
	tx, e = f.db.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if e = nodePairGC(tx, f.now.Add(time.Hour)); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	if e = f.db.db.QueryRow(`SELECT count(*) FROM hub_node_pair_trust_v1 WHERE attempt_id=? AND authorized=1 AND state='ACKED'`, p.context.AttemptID).Scan(&retained); e != nil || retained != 1 {
		t.Fatal("GC removed Owner-authorized history", e)
	}
}

func TestNodePairStoreConcurrentPrepareHasOneWinnerAndACKIsExact(t *testing.T) {
	p := newNPTStoreFixture(t)
	f := p.f
	b := p.prepareBody(t)
	inputs := []HubNodePairTrustInput{
		p.input(t, wire.OperationOwnerNodePairTrustPrepare, b, f.device, f.now.Add(2*time.Second)),
		p.input(t, wire.OperationOwnerNodePairTrustPrepare, b, f.device, f.now.Add(2*time.Second)),
	}
	var wg sync.WaitGroup
	responses := make([][]byte, 2)
	errs := make([]error, 2)
	for i := range inputs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); responses[i], errs[i] = f.db.ProcessHubNodePairTrust(inputs[i]) }(i)
	}
	wg.Wait()
	winner := -1
	for i, e := range errs {
		if e == nil {
			if winner != -1 {
				t.Fatal("two Owner claims won")
			}
			winner = i
		}
	}
	if winner == -1 {
		t.Fatal("no concurrent claim won")
	}
	r, e := wire.OpenNodePairTrustResponse(f.device, f.hub, inputs[winner].Packet, responses[winner], b)
	if e != nil {
		t.Fatal(e)
	}
	proof, capsule, e := wire.SealNodePairTrustApproval(f.owner, p.context, p.o, *r.Approval, p.s, p.x, f.now.Add(3*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	c := wire.NodePairTrustOwnerComplete{Format: wire.NodePairTrustFormat, SessionToken: f.session.Token, Scope: b.Scope, Context: p.context, OOBCommitment: p.o, OwnerProof: proof, TrustCapsule: capsule, IssuedAt: appNodeStamp(f.now.Add(3 * time.Second))}
	p.call(t, p.input(t, wire.OperationOwnerNodePairTrustComplete, c, f.device, f.now.Add(3*time.Second)), f.device)
	ack := p.ack(t, proof, capsule, f.now.Add(4*time.Second))
	responses = make([][]byte, 8)
	errs = make([]error, 8)
	for i := range responses {
		wg.Add(1)
		go func(i int) { defer wg.Done(); responses[i], errs[i] = f.db.ProcessHubNodePairTrust(ack) }(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil || !bytes.Equal(responses[0], responses[i]) {
			t.Fatal("concurrent ACK did not recover one exact receipt", e)
		}
	}
	var last, next int
	if e := f.db.db.QueryRow(`SELECT last_request_sequence,next_response_sequence FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, b.Scope.OwnerID, b.Scope.DeviceID).Scan(&last, &next); e != nil || last != 1 || next != 2 {
		t.Fatal("concurrent ACK repeated original counter", e)
	}
}

func TestNodePairStoreReconcileCannotFenceFutureOriginalBeyondTTL(t *testing.T) {
	p := newNPTStoreFixture(t)
	f := p.f
	future := f.now.Add(time.Hour)
	b := wire.NodePairTrustPoll{Format: wire.NodePairTrustFormat, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(future)}
	original := p.input(t, wire.OperationNodePairTrustPoll, b, f.node, future)
	reconcile := wire.NodePairTrustReconcile{Format: wire.NodePairTrustFormat, OriginalPacket: original.Packet, OriginalPacketDigest: wire.NodePairTrustPacketDigest(original.Packet), IssuedAt: appNodeStamp(f.now)}
	in := p.input(t, wire.OperationNodePairTrustReconcile, reconcile, f.node, f.now)
	in.Original = &original
	if _, e := f.db.ProcessHubNodePairTrust(in); e == nil {
		t.Fatal("short TTL fence covered a future admissible original")
	}
	// A presently issued unknown read is fenced and its exact retry has no effect.
	b.IssuedAt = appNodeStamp(f.now)
	original = p.input(t, wire.OperationNodePairTrustPoll, b, f.node, f.now)
	reconcile.OriginalPacket = original.Packet
	reconcile.OriginalPacketDigest = wire.NodePairTrustPacketDigest(original.Packet)
	in = p.input(t, wire.OperationNodePairTrustReconcile, reconcile, f.node, f.now)
	in.Original = &original
	r, _ := p.call(t, in, f.node)
	if r.State != wire.NodePairTrustFenced {
		t.Fatal("unknown original not fenced")
	}
	r, _ = p.call(t, original, f.node)
	if r.State != wire.NodePairTrustFenced {
		t.Fatal("fenced original redispatched")
	}
	original.At = f.now.Add(3 * time.Minute)
	if _, e := f.db.ProcessHubNodePairTrust(original); e == nil {
		t.Fatal("formerly valid original poll redispatched after its fence expired")
	}
}

func TestNodePairStoreExistingBindingIsTrustOnlyAndExpiredReadsRemainFresh(t *testing.T) {
	p := newNPTStoreFixture(t)
	f := p.f
	a, proof, capsule := p.approve(t)
	first, _ := p.call(t, p.ack(t, proof, capsule, f.now.Add(4*time.Second)), f.node)
	id, e := wire.NewRequestID()
	if e != nil {
		t.Fatal(e)
	}
	p.context = wire.NodePairTrustContext{Format: wire.NodePairTrustFormat, AttemptID: id, Hub: f.hub, Origin: a.Scope.Origin, DescriptorDigest: p.context.DescriptorDigest, NodeNonce: strings.Repeat("ea", 32), Mode: wire.NodePairTrustExisting, Binding: first.Binding, IssuedAt: appNodeStamp(f.now.Add(5 * time.Second)), ExpiresAt: appNodeStamp(f.now.Add(9 * time.Minute))}
	d, _ := wire.NodePairTrustContextDigest(p.context)
	p.o, _ = wire.NodePairTrustOOBCommitment(d, p.s)
	start := wire.NodePairTrustExistingStart{Format: wire.NodePairTrustFormat, Context: p.context, IssuedAt: appNodeStamp(f.now.Add(5 * time.Second))}
	p.call(t, p.input(t, wire.OperationNodePairTrustExisting, start, f.node, f.now.Add(5*time.Second)), f.node)
	commit := wire.NodePairTrustCommit{Format: wire.NodePairTrustFormat, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(f.now.Add(5 * time.Second))}
	p.call(t, p.input(t, wire.OperationNodePairTrustCommit, commit, f.node, f.now.Add(5*time.Second)), f.node)
	b := wire.NodePairTrustOwnerPrepare{Format: wire.NodePairTrustFormat, SessionToken: f.session.Token, Scope: a.Scope, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(f.now.Add(6 * time.Second))}
	prepared, _ := p.call(t, p.input(t, wire.OperationOwnerNodePairTrustPrepare, b, f.device, f.now.Add(6*time.Second)), f.device)
	if prepared.Approval == nil || prepared.Approval.GrantID != "" || prepared.Approval.ConfirmationPacketDigest != "" {
		t.Fatal("trust-only preparation adopted INITIAL grant")
	}
	proof, capsule, e = wire.SealNodePairTrustApproval(f.owner, p.context, p.o, *prepared.Approval, p.s, p.x, f.now.Add(7*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	c := wire.NodePairTrustOwnerComplete{Format: wire.NodePairTrustFormat, SessionToken: f.session.Token, Scope: a.Scope, Context: p.context, OOBCommitment: p.o, OwnerProof: proof, TrustCapsule: capsule, IssuedAt: appNodeStamp(f.now.Add(7 * time.Second))}
	p.call(t, p.input(t, wire.OperationOwnerNodePairTrustComplete, c, f.device, f.now.Add(7*time.Second)), f.device)
	accepted, _ := p.call(t, p.ack(t, proof, capsule, f.now.Add(8*time.Second)), f.node)
	if accepted.Binding == nil || !reflect.DeepEqual(first.Binding, accepted.Binding) {
		t.Fatal("trust-only changed original binding")
	}
	var last, next, requests, slots int
	if e = f.db.db.QueryRow(`SELECT last_request_sequence,next_response_sequence FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, a.Scope.OwnerID, a.Scope.DeviceID).Scan(&last, &next); e != nil || last != 1 || next != 2 {
		t.Fatal("trust-only consumed Client sequence", e)
	}
	if e = f.db.db.QueryRow(`SELECT count(*) FROM node_control_key_requests_v1 WHERE node_id=?`, first.Binding.NodeID).Scan(&requests); e != nil || requests != 1 {
		t.Fatal("trust-only created another original candidate", e)
	}
	if e = f.db.db.QueryRow(`SELECT count(*) FROM hub_node_pair_trust_slots_v1 WHERE attempt_id=?`, id).Scan(&slots); e != nil || slots != 0 {
		t.Fatal("trust-only reserved Client slot", e)
	}
	// Fresh reads may observe the old ACKED context; they cannot install trust.
	at := f.now.Add(11 * time.Minute)
	q := wire.NodePairTrustOwnerStatus{Format: wire.NodePairTrustFormat, SessionToken: f.session.Token, Scope: a.Scope, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(at)}
	r, _ := p.call(t, p.input(t, wire.OperationOwnerNodePairTrustStatus, q, f.device, at), f.device)
	if r.State != wire.NodePairTrustACKed || len(r.ConfirmationResponse) != 0 {
		t.Fatal("historical trust-only status changed state")
	}
}

func TestNodePairStoreExpiredObservationDoesNotSettleOriginalClient(t *testing.T) {
	p := newNPTStoreFixture(t)
	f := p.f
	a, _, _ := p.approve(t)
	at := f.now.Add(11 * time.Minute)
	q := wire.NodePairTrustOwnerStatus{Format: wire.NodePairTrustFormat, SessionToken: f.session.Token, Scope: a.Scope, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(at)}
	r, _ := p.call(t, p.input(t, wire.OperationOwnerNodePairTrustStatus, q, f.device, at), f.device)
	if r.State != wire.NodePairTrustExpired || r.Binding != nil || len(r.ConfirmationResponse) != 0 {
		t.Fatal("expired observation forged settlement")
	}
	r, _ = p.call(t, p.input(t, wire.OperationOwnerNodePairTrustCancel, q, f.device, at), f.device)
	if r.State != wire.NodePairTrustExpired {
		t.Fatal("late cancel renewed terminal state")
	}
	var last, next int
	if e := f.db.db.QueryRow(`SELECT last_request_sequence,next_response_sequence FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, a.Scope.OwnerID, a.Scope.DeviceID).Scan(&last, &next); e != nil || last != 0 || next != 1 {
		t.Fatal("observation settled pending Client slot", e)
	}
}

func TestNodePairStoreNoEffectFencesAndTerminalCancelCannotBurnCriticalHistory(t *testing.T) {
	p := newNPTStoreFixture(t)
	f := p.f
	a, proof, capsule := p.approve(t)
	ack := p.ack(t, proof, capsule, f.now.Add(4*time.Second))
	p.call(t, ack, f.node)
	var before, after int
	if e := f.db.db.QueryRow(`SELECT critical_rows FROM hub_node_pair_trust_budget_v1 WHERE id=1`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	at := f.now.Add(11 * time.Minute)
	// A signed, historically valid-shaped but never admitted ACK is not another
	// Owner-authorized mutation. Its FENCED result belongs in the expiring cache.
	b := ack.Body.(wire.NodePairTrustACK)
	b.ACKNonce = bytes.Repeat([]byte{0x4a}, 32)
	old := p.input(t, wire.OperationNodePairTrustACK, b, f.node, f.now.Add(4*time.Second))
	q := wire.NodePairTrustReconcile{Format: wire.NodePairTrustFormat, OriginalPacket: old.Packet, OriginalPacketDigest: wire.NodePairTrustPacketDigest(old.Packet), IssuedAt: appNodeStamp(at)}
	in := p.input(t, wire.OperationNodePairTrustReconcile, q, f.node, at)
	in.Original = &old
	fenced, _ := p.call(t, in, f.node)
	if fenced.State != wire.NodePairTrustFenced {
		t.Fatal("missing original was not fenced")
	}
	nodeCancel := wire.NodePairTrustCancel{Format: wire.NodePairTrustFormat, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(at)}
	closed, _ := p.call(t, p.input(t, wire.OperationNodePairTrustCancel, nodeCancel, f.node, at), f.node)
	if closed.State != wire.NodePairTrustACKed {
		t.Fatal("late Node cancel changed terminal state")
	}
	ownerCancel := wire.NodePairTrustOwnerStatus{Format: wire.NodePairTrustFormat, SessionToken: f.session.Token, Scope: a.Scope, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(at)}
	closed, _ = p.call(t, p.input(t, wire.OperationOwnerNodePairTrustCancel, ownerCancel, f.device, at), f.device)
	if closed.State != wire.NodePairTrustACKed || len(closed.ConfirmationResponse) == 0 {
		t.Fatal("late Owner cancel lost original response")
	}
	if e := f.db.db.QueryRow(`SELECT critical_rows FROM hub_node_pair_trust_budget_v1 WHERE id=1`).Scan(&after); e != nil || after != before {
		t.Fatal("no-effect reads permanently burned critical budget", e, before, after)
	}
	var n int
	if e := f.db.db.QueryRow(`SELECT count(*) FROM hub_node_pair_trust_reads_v1 WHERE sender_key_id=? AND request_id=?`, old.Header.SenderPublic.ID, old.Header.RequestID).Scan(&n); e != nil || n != 1 {
		t.Fatal("no-effect fence not retained in bounded TTL cache", e)
	}
	// A real first cancellation retains one immutable transition receipt;
	// later cancellation observations do not create unbounded permanent rows.
	p = newNPTStoreFixture(t)
	f = p.f
	a, _, _ = p.approve(t)
	if e := f.db.db.QueryRow(`SELECT critical_rows FROM hub_node_pair_trust_budget_v1 WHERE id=1`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	nodeCancel = wire.NodePairTrustCancel{Format: wire.NodePairTrustFormat, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(f.now.Add(4 * time.Second))}
	closed, _ = p.call(t, p.input(t, wire.OperationNodePairTrustCancel, nodeCancel, f.node, f.now.Add(4*time.Second)), f.node)
	if closed.State != wire.NodePairTrustCancelled {
		t.Fatal("first cancel did not transition")
	}
	if e := f.db.db.QueryRow(`SELECT critical_rows FROM hub_node_pair_trust_budget_v1 WHERE id=1`).Scan(&after); e != nil || after != before+1 {
		t.Fatal("first cancel lost its permanent transition receipt", e)
	}
	ownerCancel = wire.NodePairTrustOwnerStatus{Format: wire.NodePairTrustFormat, SessionToken: f.session.Token, Scope: a.Scope, Context: p.context, OOBCommitment: p.o, IssuedAt: appNodeStamp(f.now.Add(5 * time.Second))}
	p.call(t, p.input(t, wire.OperationOwnerNodePairTrustCancel, ownerCancel, f.device, f.now.Add(5*time.Second)), f.device)
	if e := f.db.db.QueryRow(`SELECT critical_rows FROM hub_node_pair_trust_budget_v1 WHERE id=1`).Scan(&after); e != nil || after != before+1 {
		t.Fatal("repeat cancel burned another permanent receipt", e)
	}
}
