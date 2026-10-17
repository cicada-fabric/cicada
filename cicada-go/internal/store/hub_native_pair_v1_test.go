package store

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type nativePairStoreFixture struct {
	f     *n3StoreFixture
	scope e2ee.OwnerNativePairScope
	at    time.Time
}

func nativePairStore(t *testing.T) *nativePairStoreFixture {
	t.Helper()
	f := n3Fixture(t, true)
	grant := f.activate(t)
	if _, err := f.db.ProcessHubAppNodeClient(f.client(t, grant, 1, f.now.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	var b NodeControlKeyBinding
	var raw string
	if err := f.db.db.QueryRow(`SELECT binding_json FROM hub_app_node_provenance_v1 WHERE owner_id=? AND device_id=?`, f.scope.OwnerID, f.scope.DeviceID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal([]byte(raw), &b) != nil {
		t.Fatal("synthetic N3 provenance malformed")
	}
	return &nativePairStoreFixture{f: f, scope: e2ee.OwnerNativePairScope{Actor: f.scope, Node: appNodeBindingPublic(b)}, at: f.now.Add(3 * time.Second)}
}

func (f *nativePairStoreFixture) context(t *testing.T, at time.Time) wire.NativePairRequestContext {
	t.Helper()
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	s := f.scope.Actor
	return wire.NativePairRequestContext{Origin: s.Origin, HubID: s.HubID, AccountID: s.AccountID, OwnerID: s.OwnerID, DeviceID: s.DeviceID, AccountSessionID: s.AccountSessionID, AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch, ClientSessionEpoch: s.ClientSessionEpoch, RequestID: id, ClientNonce: nonce, IssuedAt: appNodeStamp(at)}
}

func (f *nativePairStoreFixture) claims(c wire.NativePairRequestContext, purpose string) e2ee.OwnerNativePairClaims {
	issued, _ := time.Parse(time.RFC3339Nano, c.IssuedAt)
	return e2ee.OwnerNativePairClaims{Version: 1, Purpose: purpose, Scope: f.scope, RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt, ExpiresAt: appNodeStamp(issued.Add(time.Minute))}
}

func (f *nativePairStoreFixture) input(t *testing.T, body any, at time.Time) (HubNativePairInput, HubNativePairSeal) {
	t.Helper()
	raw, err := wire.SealClientRequest(f.f.device, f.f.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err := wire.NewClientRoute(f.f.hub, body, f.f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var out any
	switch body.(type) {
	case wire.NativePairBootstrapPrepare:
		out = &wire.NativePairBootstrapPrepare{}
	case wire.NativePairBootstrapComplete:
		out = &wire.NativePairBootstrapComplete{}
	case wire.NativePairStatusRequest:
		out = &wire.NativePairStatusRequest{}
	case wire.NativePairReconcileRequest:
		out = &wire.NativePairReconcileRequest{}
	case wire.NativePairRevoke:
		out = &wire.NativePairRevoke{}
	default:
		t.Fatal("missing exact synthetic request type")
	}
	pub := f.f.device.Public()
	if wire.OpenRequestAt(f.f.hubPrivate, &pub, b, r, raw, out, time.Time{}) != nil {
		t.Fatal("synthetic authenticated input failed")
	}
	in := HubNativePairInput{Hub: f.f.hub, NodeControlPublic: f.f.nodeControl.Public(), Device: pub, Packet: raw, Body: reflect.ValueOf(out).Elem().Interface(), At: at}
	return in, func(body any) ([]byte, error) { return wire.SealResponse(f.f.hubPrivate, pub, r, body) }
}

func (f *nativePairStoreFixture) prepare(t *testing.T) (wire.NativePairBootstrapPrepare, HubNativePairInput, wire.NativePairBootstrapChallenge) {
	t.Helper()
	c := f.context(t, f.at)
	claims := f.claims(c, e2ee.OwnerNativePairBootstrapPreview)
	claims.Bootstrap = &e2ee.NativePairBootstrapClaims{GroupLabel: "Synthetic native pair", Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy()}
	proof, err := e2ee.SignOwnerNativePair(f.f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairBootstrapPrepare{Format: wire.NativePairFormat, Context: c, SessionToken: f.f.session.Token, OwnerProof: proof}
	in, seal := f.input(t, q, f.at)
	packet, err := f.f.db.ProcessHubNativePair(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	var ch wire.NativePairBootstrapChallenge
	if wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, packet, &ch) != nil {
		var fence wire.NativePairBootstrapFence
		_ = wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, packet, &fence)
		t.Fatal("prepare fenced", fence.ErrorCode)
	}
	if wire.ValidateNativePairBootstrapTarget(q, in.Packet, ch, f.f.hub, f.at) != nil {
		t.Fatal("Hub changed the exact Owner bootstrap target")
	}
	return q, in, ch
}

func (f *nativePairStoreFixture) complete(t *testing.T, ch wire.NativePairBootstrapChallenge) (wire.NativePairBootstrapComplete, HubNativePairInput, HubNativePairSeal) {
	t.Helper()
	at := f.at.Add(time.Second)
	c := f.context(t, at)
	claims := f.claims(c, e2ee.OwnerNativePairBootstrapCommit)
	claims.Scope = ch.Scope
	claims.Bootstrap = &ch.Bootstrap
	claims.ExpiresAt = ch.ProofExpiresAt
	proof, err := e2ee.SignOwnerNativePair(f.f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairBootstrapComplete{Format: wire.NativePairFormat, Context: c, SessionToken: f.f.session.Token, OwnerProof: proof}
	in, seal := f.input(t, q, at)
	return q, in, seal
}

func TestHubNativePairBootstrapAtomicReceiptAndStableIdentity(t *testing.T) {
	f := nativePairStore(t)
	_, prepared, ch := f.prepare(t)
	var domains int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM networks_v2 WHERE id=?`, ch.Bootstrap.NetworkID).Scan(&domains) != nil || domains != 0 {
		t.Fatal("preview created a Network")
	}
	_, in, seal := f.complete(t, ch)
	reply, err := f.f.db.ProcessHubNativePair(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	var result wire.NativePairResult
	if wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, reply, &result) != nil || result.State != wire.NativePairWaitingJoin || result.ControlRevision != 2 || result.SlotA != nil || result.SlotB != nil {
		t.Fatal("bootstrap did not reserve two empty slots")
	}
	if f.f.db.db.QueryRow(`SELECT count(*) FROM groups WHERE id=? AND network_id=? AND state='ACTIVE'`, ch.Bootstrap.GroupID, ch.Bootstrap.NetworkID).Scan(&domains) != nil || domains != 1 {
		t.Fatal("Network/Group did not commit together")
	}
	var peers int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM memberships WHERE group_id=? AND role='member'`, ch.Bootstrap.GroupID).Scan(&peers) != nil || peers != 0 {
		t.Fatal("bootstrap inferred a SID/peer grant")
	}
	if err = f.f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.f.db, err = New(f.f.path)
	if err != nil {
		t.Fatal(err)
	}
	// Expired login/Root still permits recovery of this exact original receipt.
	if _, err = f.f.db.db.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE session_id=?`, f.scope.Actor.AccountSessionID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.f.db.db.Exec(`UPDATE owner_approval_keys_v2 SET state='REVOKED',version=version+1 WHERE owner_id=? AND key_id=?`, f.scope.Actor.OwnerID, f.f.owner.Public().ID); err != nil {
		t.Fatal(err)
	}
	in.At = f.at.Add(20 * time.Minute)
	retry, err := f.f.db.ProcessHubNativePair(in, seal)
	if err != nil || !bytes.Equal(reply, retry) {
		t.Fatal("exact committed receipt did not survive reopen/revocation", err)
	}
	_, prepareSeal := f.input(t, prepared.Body, f.at)
	prepared.At = in.At
	old, err := f.f.db.ProcessHubNativePair(prepared, prepareSeal)
	if err != nil {
		t.Fatal(err)
	}
	var historical wire.NativePairBootstrapChallenge
	if wire.OpenClientResponse(f.f.device, f.f.hub, prepared.Packet, old, &historical) != nil || !reflect.DeepEqual(historical, ch) {
		t.Fatal("prepare exact retry refreshed identity/deadline")
	}
}

func TestHubNativePairUnadmittedCompletionFencedAfterSealFailure(t *testing.T) {
	f := nativePairStore(t)
	_, _, ch := f.prepare(t)
	q, in, seal := f.complete(t, ch)
	if _, err := f.f.db.ProcessHubNativePair(in, func(any) ([]byte, error) { return nil, errors.New("synthetic seal failure") }); err == nil {
		t.Fatal("seal failure committed")
	}
	var count int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM networks_v2 WHERE id=?`, ch.Bootstrap.NetworkID).Scan(&count) != nil || count != 0 {
		t.Fatal("seal failure left a partial Network")
	}
	c := f.context(t, f.at.Add(20*time.Minute))
	c.AccountSessionID = "synthetic-expired-login-history"
	rq := wire.NativePairReconcileRequest{Format: wire.NativePairFormat, Context: c, PairID: ch.Bootstrap.PairID, OriginalPacket: in.Packet}
	ri, rs := f.input(t, rq, f.at.Add(20*time.Minute))
	ri.Original = &in
	ri.OriginalSeal = seal
	if _, err := f.f.db.db.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE session_id=?`, f.scope.Actor.AccountSessionID); err != nil {
		t.Fatal(err)
	}
	packet, err := f.f.db.ProcessHubNativePair(ri, rs)
	if err != nil {
		t.Fatal(err)
	}
	var result wire.NativePairReconciled
	if wire.OpenClientResponse(f.f.device, f.f.hub, ri.Packet, packet, &result) != nil || result.State != "REJECTED_FENCED" || wire.ValidateNativePairReconcileTarget(result, ch.Bootstrap.PairID, in.Packet) != nil {
		t.Fatal("unadmitted original did not obtain permanent fence")
	}
	var fence wire.NativePairRejectionFence
	if wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, result.ReceiptPacket, &fence) != nil || wire.ValidateNativePairRejectionTarget(fence, q, in.Packet) != nil {
		t.Fatal("no-effect fence did not bind original Owner target")
	}
	in.At = ri.At
	late, err := f.f.db.ProcessHubNativePair(in, seal)
	if err != nil || !bytes.Equal(late, result.ReceiptPacket) {
		t.Fatal("late original was admitted after permanent fence")
	}
	if f.f.db.db.QueryRow(`SELECT count(*) FROM networks_v2 WHERE id=?`, ch.Bootstrap.NetworkID).Scan(&count) != nil || count != 0 {
		t.Fatal("reconcile executed old consent")
	}
}

func TestHubNativePairCompetingCompletionCommitsOneDomainEffect(t *testing.T) {
	f := nativePairStore(t)
	_, _, ch := f.prepare(t)
	_, first, fs := f.complete(t, ch)
	_, second, ss := f.complete(t, ch)
	other, err := New(f.f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	type answer struct {
		input  HubNativePairInput
		packet []byte
		err    error
	}
	start := make(chan struct{})
	done := make(chan answer, 2)
	for _, v := range []struct {
		db   *Store
		in   HubNativePairInput
		seal HubNativePairSeal
	}{{f.f.db, first, fs}, {other, second, ss}} {
		v := v
		go func() { <-start; p, e := v.db.ProcessHubNativePair(v.in, v.seal); done <- answer{v.in, p, e} }()
	}
	close(start)
	completed, fenced := 0, 0
	for n := 0; n < 2; n++ {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		var ok wire.NativePairResult
		if wire.OpenClientResponse(f.f.device, f.f.hub, r.input.Packet, r.packet, &ok) == nil {
			if ok.State != wire.NativePairWaitingJoin {
				t.Fatal("unexpected winner state")
			}
			completed++
			continue
		}
		var no wire.NativePairRejectionFence
		if wire.OpenClientResponse(f.f.device, f.f.hub, r.input.Packet, r.packet, &no) != nil || !no.NoEffect {
			t.Fatal("loser did not receive a permanent no-effect fence")
		}
		fenced++
	}
	if completed != 1 || fenced != 1 {
		t.Fatal("concurrent completion produced the wrong winner count")
	}
	var count int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM networks_v2 WHERE id=?`, ch.Bootstrap.NetworkID).Scan(&count) != nil || count != 1 {
		t.Fatal("concurrent claim duplicated a Network")
	}
	if f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pair_slots_v1 WHERE pair_id=?`, ch.Bootstrap.PairID).Scan(&count) != nil || count != 2 {
		t.Fatal("concurrent claim duplicated/resized slots")
	}
}

func TestHubNativePairProofExpiresWhileWaitingForWriter(t *testing.T) {
	f := nativePairStore(t)
	c := f.context(t, f.at)
	claims := f.claims(c, e2ee.OwnerNativePairBootstrapPreview)
	claims.Bootstrap = &e2ee.NativePairBootstrapClaims{GroupLabel: "Synthetic waiting preview", Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy()}
	proof, err := e2ee.SignOwnerNativePair(f.f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairBootstrapPrepare{Format: wire.NativePairFormat, Context: c, SessionToken: f.f.session.Token, OwnerProof: proof}
	in, seal := f.input(t, q, f.at)
	other, err := New(f.f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	tx, err := other.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE hub_native_pair_guard_v1 SET touched_at=touched_at WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var sampled atomic.Bool
	in.Now = func() time.Time { sampled.Store(true); return f.at.Add(2 * time.Minute) }
	type answer struct {
		packet []byte
		err    error
	}
	done := make(chan answer, 1)
	started := make(chan struct{})
	go func() { close(started); p, e := f.f.db.ProcessHubNativePair(in, seal); done <- answer{p, e} }()
	<-started
	select {
	case <-done:
		t.Fatal("request bypassed the held database writer")
	case <-time.After(40 * time.Millisecond):
	}
	if sampled.Load() {
		t.Fatal("trusted clock sampled before database writer acquisition")
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	var fence wire.NativePairBootstrapFence
	if !sampled.Load() || wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, r.packet, &fence) != nil || fence.ErrorCode != "PROOF_EXPIRED" || !fence.NoEffect {
		t.Fatal("old request was admitted with its pre-wait clock")
	}
	var count int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pairs_v1`).Scan(&count) != nil || count != 0 {
		t.Fatal("expired proof reserved a pair")
	}
}

func TestHubNativePairPrepareInsertFailurePublishesNoIDInFenceOrReconcile(t *testing.T) {
	f := nativePairStore(t)
	c := f.context(t, f.at)
	claims := f.claims(c, e2ee.OwnerNativePairBootstrapPreview)
	claims.Bootstrap = &e2ee.NativePairBootstrapClaims{GroupLabel: "Synthetic failed reservation", Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy()}
	proof, err := e2ee.SignOwnerNativePair(f.f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairBootstrapPrepare{Format: wire.NativePairFormat, Context: c, SessionToken: f.f.session.Token, OwnerProof: proof}
	in, seal := f.input(t, q, f.at)
	if _, err = f.f.db.db.Exec(`CREATE TRIGGER synthetic_reject_pair_insert BEFORE INSERT ON hub_native_pairs_v1 BEGIN SELECT RAISE(ABORT,'synthetic failed pair insert');END;`); err != nil {
		t.Fatal(err)
	}
	reply, err := f.f.db.ProcessHubNativePair(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	var fence wire.NativePairBootstrapFence
	if wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, reply, &fence) != nil || !fence.NoEffect {
		t.Fatal("failed reservation did not yield a typed no-effect fence")
	}
	var pair string
	if f.f.db.db.QueryRow(`SELECT pair_id FROM hub_native_pair_operations_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, c.OwnerID, c.DeviceID, c.RequestID).Scan(&pair) != nil || pair != "" {
		t.Fatal("uncommitted random PairID leaked into permanent fence history")
	}
	rq := wire.NativePairReconcileRequest{Format: wire.NativePairFormat, Context: f.context(t, f.at.Add(time.Second)), OriginalPacket: in.Packet}
	ri, rs := f.input(t, rq, f.at.Add(time.Second))
	ri.Original = &in
	ri.OriginalSeal = seal
	recovered, err := f.f.db.ProcessHubNativePair(ri, rs)
	if err != nil {
		t.Fatal(err)
	}
	var result wire.NativePairReconciled
	if wire.OpenClientResponse(f.f.device, f.f.hub, ri.Packet, recovered, &result) != nil || result.PairID != "" || !bytes.Equal(result.ReceiptPacket, reply) || wire.ValidateNativePairReconcileTarget(result, "", in.Packet) != nil {
		t.Fatal("outer recovery metadata disagreed with unknown-ID nested fence")
	}
	if _, err = f.f.db.db.Exec(`DROP TRIGGER synthetic_reject_pair_insert`); err != nil {
		t.Fatal(err)
	}
	late, err := f.f.db.ProcessHubNativePair(in, seal)
	if err != nil || !bytes.Equal(late, reply) {
		t.Fatal("failed original was admitted after database insertion recovered")
	}
}
