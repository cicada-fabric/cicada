package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"strings"
	"testing"
	"time"
)

// Only zero-Join fixture setup calls an internal Tx helper. Every Owner intent,
// candidate publication, consent and activation below uses production admission.
func nativePairConsentFixture(t *testing.T) (*nativePairStoreFixture, wire.NativePairBootstrapChallenge, wire.NativePairResult) {
	t.Helper()
	f := nativePairStore(t)
	f.at = time.Now().UTC().Add(-10 * time.Second)
	f.pairKeys = make(map[string]*e2ee.Identity)
	_, _, ch := f.prepare(t)
	_, in, seal := f.complete(t, ch)
	if _, err := f.f.db.ProcessHubNativePair(in, seal); err != nil {
		t.Fatal(err)
	}
	tx, err := f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, letter := range []string{"A", "B"} {
		p, e := readNativePair(tx, ch.Bootstrap.PairID)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = nativePairZeroJoinTx(tx, p, wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision, PairID: p.id, Slot: letter, ExpectedGeneration: 1, Runtime: "codex", NativeSessionID: "synthetic-consent-original-" + letter, Workspace: "/synthetic/consent/" + letter}, "synthetic-consent-token-"+letter, f.at); e != nil {
			t.Fatal(e)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, letter := range []string{"A", "B"} {
		var scope NativeActorScope
		if err = f.f.db.db.QueryRow(`SELECT s.principal_id,s.endpoint_id,p.group_id,p.network_id,m.id,m.revision,s.binding_id,b.epoch,s.lease_owner FROM hub_native_pair_slots_v1 s JOIN hub_native_pairs_v1 p ON p.pair_id=s.pair_id JOIN session_bindings b ON b.id=s.binding_id JOIN memberships m ON m.principal_id=s.principal_id AND m.group_id=p.group_id WHERE s.pair_id=? AND s.slot=? AND s.state='JOINED_ZERO'`, ch.Bootstrap.PairID, letter).Scan(&scope.PrincipalID, &scope.EndpointID, &scope.GroupID, &scope.NetworkID, &scope.MembershipID, &scope.MembershipRevision, &scope.BindingID, &scope.BindingEpoch, &scope.LeaseOwner); err != nil {
			t.Fatal(err)
		}
		key, e := e2ee.NewIdentity()
		if e != nil {
			t.Fatal(e)
		}
		f.pairKeys[letter] = key
		proof, e := key.SignEndpointKeyAttestation(scope.EndpointID, scope.PrincipalID, f.scope.Node.NodeID, scope.BindingID, scope.BindingEpoch)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.f.db.RegisterEndpointKeyCandidateForActor(scope, proof); e != nil {
			t.Fatal(e)
		}
	}
	tx, err = f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	p, err := readNativePair(tx, ch.Bootstrap.PairID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := nativePairResultTx(tx, p, f.context(t, f.at), wire.OperationNativePairStatus, "synthetic-only-not-wire", "COMPLETED", "", true, f.at)
	tx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	f.scope = ch.Scope
	return f, ch, result
}

func (f *nativePairStoreFixture) consentPlan(t *testing.T, r wire.NativePairResult) (HubNativePairInput, wire.NativePairPlanChallenge) {
	t.Helper()
	at := f.at.Add(2 * time.Second)
	c := f.context(t, at)
	claims := f.claims(c, e2ee.OwnerNativePairConsentPreview)
	ad, _ := wire.NativePairSlotDigest(*r.SlotA)
	bd, _ := wire.NativePairSlotDigest(*r.SlotB)
	claims.Consent = &e2ee.NativePairConsentClaims{PairID: r.PairID, ExpectedRevision: r.ControlRevision, SlotADigest: ad, SlotBDigest: bd, PeerExpiresAt: r.PeerExpiresAt}
	proof, err := e2ee.SignOwnerNativePair(f.f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairConsentPrepare{Format: wire.NativePairFormat, Context: c, SessionToken: f.f.session.Token, OwnerProof: proof}
	in, seal := f.input(t, q, at)
	packet, err := f.f.db.ProcessHubNativePair(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	var ch wire.NativePairPlanChallenge
	if e := wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, packet, &ch); e != nil {
		var fence wire.NativePairRejectionFence
		_ = wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, packet, &fence)
		t.Fatal("plan fenced", fence.ErrorCode, e)
	}
	var bootstrap []byte
	if f.f.db.db.QueryRow(`SELECT bootstrap_owner_proof FROM hub_native_pairs_v1 WHERE pair_id=?`, r.PairID).Scan(&bootstrap) != nil || wire.ValidateNativePairPlanTarget(q, in.Packet, ch, bootstrap, f.f.hub, at) != nil {
		t.Fatal("actual Plan target invalid")
	}
	return in, ch
}

func (f *nativePairStoreFixture) consent(t *testing.T, plan wire.NativePairConsentPlan, letter string) (HubNativePairInput, HubNativePairSeal) {
	t.Helper()
	at := f.at.Add(3 * time.Second)
	c := f.context(t, at)
	claims := f.claims(c, e2ee.OwnerNativePairSlotConsent)
	claims.Scope = plan.Scope
	s, other, m := plan.SlotA, plan.SlotB, plan.SlotAKeyManifest
	if letter == "B" {
		s, other, m = plan.SlotB, plan.SlotA, plan.SlotBKeyManifest
	}
	ad, _ := wire.NativePairSlotDigest(plan.SlotA)
	bd, _ := wire.NativePairSlotDigest(plan.SlotB)
	claims.Consent = &e2ee.NativePairConsentClaims{PairID: plan.PairID, ExpectedRevision: plan.ExpectedRevision, PlanID: plan.PlanID, PlanDigest: plan.Digest, SlotADigest: ad, SlotBDigest: bd, Slot: letter, SlotGeneration: s.Generation, SlotAttemptID: s.AttemptID, NativeSessionID: s.NativeSessionID, PeerNativeSessionID: other.NativeSessionID, ActivateWhenBoth: true, PlanExpiresAt: plan.ExpiresAt, PeerExpiresAt: plan.PeerExpiresAt}
	proof, err := e2ee.SignOwnerNativePair(f.f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	issued, _ := time.Parse(time.RFC3339Nano, m.IssuedAt)
	end, _ := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	group, err := f.f.owner.SignOwnerLinkKeyGrant(m.OwnerID, m.Operation, m.Digest, m.CandidateBindingDigest, uint64(m.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issued, end)
	if err != nil {
		t.Fatal(err)
	}
	return f.input(t, wire.NativePairConsentComplete{Format: wire.NativePairFormat, Context: c, SessionToken: f.f.session.Token, OwnerProof: proof, GroupKeyProof: group}, at)
}

func (f *nativePairStoreFixture) result(t *testing.T, in HubNativePairInput, seal HubNativePairSeal) ([]byte, wire.NativePairResult) {
	t.Helper()
	raw, err := f.f.db.ProcessHubNativePair(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	var r wire.NativePairResult
	if e := wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, raw, &r); e != nil {
		var fence wire.NativePairRejectionFence
		_ = wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, raw, &fence)
		t.Fatal("mutation fenced", fence.ErrorCode, e)
	}
	return raw, r
}

func TestHubNativePairConsentActivatesBothCurrentMembershipsAtomically(t *testing.T) {
	f, _, status := nativePairConsentFixture(t)
	_, ch := f.consentPlan(t, status)
	a, sa := f.consent(t, ch.Plan, "A")
	b, sb := f.consent(t, ch.Plan, "B")
	raw, r := f.result(t, a, sa)
	if r.State != wire.NativePairWaitingConsent || r.ControlRevision != ch.Plan.ExpectedRevision || r.SlotAState != wire.NativePairSlotConsentRecorded {
		t.Fatal("first consent published authority")
	}
	var n int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM group_endpoint_key_grants_v2 WHERE group_id=?`, ch.Plan.GroupID).Scan(&n) != nil || n != 0 {
		t.Fatal("partial key grant")
	}
	for _, s := range []wire.NativePairSlot{ch.Plan.SlotA, ch.Plan.SlotB} {
		var grants string
		if f.f.db.db.QueryRow(`SELECT grants_json FROM memberships WHERE group_id=? AND principal_id=?`, ch.Plan.GroupID, s.PrincipalID).Scan(&grants) != nil || grants != "[]" {
			t.Fatal("partial membership")
		}
	}
	// Reopen proves the first consent is durable, with no SQL-made ACTIVE state.
	if err := f.f.db.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.f.db, err = New(f.f.path)
	if err != nil {
		t.Fatal(err)
	}
	retry, _ := f.result(t, a, sa)
	if !bytes.Equal(raw, retry) {
		t.Fatal("lost response changed receipt")
	}
	_, r = f.result(t, b, sb)
	if r.State != wire.NativePairActive || r.ControlRevision != ch.Plan.ExpectedRevision+1 || r.SlotAState != wire.NativePairSlotActive || r.SlotBState != wire.NativePairSlotActive {
		t.Fatal("two consents did not activate atomically")
	}
	for _, s := range []wire.NativePairSlot{ch.Plan.SlotA, ch.Plan.SlotB} {
		var grants string
		var revision uint64
		if f.f.db.db.QueryRow(`SELECT grants_json,revision FROM memberships WHERE group_id=? AND principal_id=?`, ch.Plan.GroupID, s.PrincipalID).Scan(&grants, &revision) != nil || revision != s.MembershipRevision+1 {
			t.Fatal("wrong final membership revision")
		}
		var got []string
		if json.Unmarshal([]byte(grants), &got) != nil || len(got) != 4 {
			t.Fatal("wrong final grants")
		}
		tx, e := f.f.db.db.Begin()
		if e != nil {
			t.Fatal(e)
		}
		grant, e := readLatestGroupEndpointKeyGrant(tx, f.scope.Actor.OwnerID, ch.Plan.GroupID, s.EndpointID)
		if e != nil || evaluateGroupEndpointKeyGrant(tx, grant, b.At) != GroupEndpointKeyGrantCurrent {
			tx.Rollback()
			t.Fatal("projected proof is immediately stale", e)
		}
		tx.Rollback()
	}
}

func TestHubNativePairConsentSecondFailureRollsBackBothMemberships(t *testing.T) {
	f, _, status := nativePairConsentFixture(t)
	_, ch := f.consentPlan(t, status)
	a, sa := f.consent(t, ch.Plan, "A")
	b, sb := f.consent(t, ch.Plan, "B")
	f.result(t, a, sa)
	if _, err := f.f.db.db.Exec(`CREATE TRIGGER synthetic_second_grant_abort BEFORE INSERT ON group_endpoint_key_grants_v2 WHEN NEW.endpoint_id='` + ch.Plan.SlotB.EndpointID + `' BEGIN SELECT RAISE(ABORT,'synthetic second grant failure'); END`); err != nil {
		t.Fatal(err)
	}
	raw, err := f.f.db.ProcessHubNativePair(b, sb)
	if err != nil {
		t.Fatal(err)
	}
	var fence wire.NativePairRejectionFence
	if wire.OpenClientResponse(f.f.device, f.f.hub, b.Packet, raw, &fence) != nil || !fence.NoEffect {
		t.Fatal("missing atomic rejection fence")
	}
	var n int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM memberships WHERE group_id=? AND role='member' AND grants_json='[]' AND revision=1`, ch.Plan.GroupID).Scan(&n) != nil || n != 2 {
		t.Fatal("partial membership survived rollback")
	}
	if f.f.db.db.QueryRow(`SELECT count(*) FROM group_endpoint_key_grants_v2 WHERE group_id=?`, ch.Plan.GroupID).Scan(&n) != nil || n != 0 {
		t.Fatal("partial grant survived rollback")
	}
	if f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pair_consents_v1 WHERE plan_id=?`, ch.Plan.PlanID).Scan(&n) != nil || n != 1 {
		t.Fatal("rejected consent survived")
	}
}

func TestHubNativePairConsentRejectsStaleBasisAndExpiredPlan(t *testing.T) {
	for _, name := range []string{"candidate", "membership", "expiry", "replaced_plan"} {
		t.Run(name, func(t *testing.T) {
			f, _, r := nativePairConsentFixture(t)
			_, ch := f.consentPlan(t, r)
			a, sa := f.consent(t, ch.Plan, "A")
			b, sb := f.consent(t, ch.Plan, "B")
			f.result(t, a, sa)
			switch name {
			case "candidate":
				if _, err := f.f.db.db.Exec(`UPDATE endpoint_key_candidates_v2 SET version=version+1 WHERE endpoint_id=?`, ch.Plan.SlotB.EndpointID); err != nil {
					t.Fatal(err)
				}
			case "membership":
				if _, err := f.f.db.db.Exec(`UPDATE memberships SET revision=revision+1 WHERE group_id=? AND principal_id=?`, ch.Plan.GroupID, ch.Plan.SlotB.PrincipalID); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				end, _ := time.Parse(time.RFC3339Nano, ch.Plan.ExpiresAt)
				b.At = end // exact Plan boundary, while the existing receipt remains recoverable
			case "replaced_plan":
				f.consentPlan(t, r)
			}
			raw, err := f.f.db.ProcessHubNativePair(b, sb)
			if err != nil {
				t.Fatal(err)
			}
			var fence wire.NativePairRejectionFence
			if wire.OpenClientResponse(f.f.device, f.f.hub, b.Packet, raw, &fence) != nil || !fence.NoEffect {
				t.Fatal("stale/expired consent was not fenced")
			}
			retry, err := f.f.db.ProcessHubNativePair(b, sb)
			if err != nil || !bytes.Equal(raw, retry) {
				t.Fatal("stale consent fence changed", err)
			}
			var n int
			if f.f.db.db.QueryRow(`SELECT count(*) FROM group_endpoint_key_grants_v2 WHERE group_id=?`, ch.Plan.GroupID).Scan(&n) != nil || n != 0 {
				t.Fatal("stale plan activated key grants")
			}
		})
	}
}

func TestHubNativePairConsentConcurrentAcrossStoreHandles(t *testing.T) {
	f, _, r := nativePairConsentFixture(t)
	_, ch := f.consentPlan(t, r)
	a, sa := f.consent(t, ch.Plan, "A")
	b, sb := f.consent(t, ch.Plan, "B")
	other, err := New(f.f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	type outcome struct {
		raw []byte
		err error
		in  HubNativePairInput
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	go func() { <-start; raw, e := f.f.db.ProcessHubNativePair(a, sa); results <- outcome{raw, e, a} }()
	go func() { <-start; raw, e := other.ProcessHubNativePair(b, sb); results <- outcome{raw, e, b} }()
	close(start)
	active, recorded := 0, 0
	for i := 0; i < 2; i++ {
		out := <-results
		if out.err != nil {
			t.Fatal(out.err)
		}
		var result wire.NativePairResult
		if wire.OpenClientResponse(f.f.device, f.f.hub, out.in.Packet, out.raw, &result) != nil {
			t.Fatal("concurrent consent fenced")
		}
		if result.State == wire.NativePairActive {
			active++
		} else if result.State == wire.NativePairWaitingConsent {
			recorded++
		}
	}
	if active != 1 || recorded != 1 {
		t.Fatal("concurrent consents did not serialize once", active, recorded)
	}
	var n int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM group_endpoint_key_grants_v2 WHERE group_id=?`, ch.Plan.GroupID).Scan(&n) != nil || n != 2 {
		t.Fatal("concurrent activation duplicated or lost grants")
	}
}

func TestHubNativePairSlotRejectRetainsOtherIdentityAndFencesOldConsent(t *testing.T) {
	f, _, r := nativePairConsentFixture(t)
	_, ch := f.consentPlan(t, r)
	a, sa := f.consent(t, ch.Plan, "A")
	oldB, sb := f.consent(t, ch.Plan, "B")
	f.result(t, a, sa)
	at := f.at.Add(4 * time.Second)
	c := f.context(t, at)
	claims := f.claims(c, e2ee.OwnerNativePairSlotReject)
	digest, _ := wire.NativePairSlotDigest(ch.Plan.SlotA)
	claims.Reject = &e2ee.NativePairRejectClaims{PairID: r.PairID, ExpectedRevision: r.ControlRevision, Slot: "A", SlotGeneration: ch.Plan.SlotA.Generation, SlotAttemptID: ch.Plan.SlotA.AttemptID, SlotDigest: digest}
	proof, err := e2ee.SignOwnerNativePair(f.f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	in, seal := f.input(t, wire.NativePairSlotReject{Format: wire.NativePairFormat, Context: c, SessionToken: f.f.session.Token, OwnerProof: proof}, at)
	raw, rejected := f.result(t, in, seal)
	if rejected.State != wire.NativePairWaitingJoin || rejected.SlotA != nil || rejected.SlotB.NativeSessionID != ch.Plan.SlotB.NativeSessionID || rejected.ControlRevision != ch.Plan.ExpectedRevision+1 {
		t.Fatal("reject replaced unrelated identity")
	}
	retry, _ := f.result(t, in, seal)
	if !bytes.Equal(raw, retry) {
		t.Fatal("reject exact receipt changed")
	}
	packet, err := f.f.db.ProcessHubNativePair(oldB, sb)
	if err != nil {
		t.Fatal(err)
	}
	var fence wire.NativePairRejectionFence
	if wire.OpenClientResponse(f.f.device, f.f.hub, oldB.Packet, packet, &fence) != nil || !fence.NoEffect {
		t.Fatal("old consent survived slot generation rejection")
	}
	var sid, state string
	var generation uint64
	if f.f.db.db.QueryRow(`SELECT native_session_id,status FROM session_bindings WHERE id=?`, ch.Plan.SlotA.BindingID).Scan(&sid, &state) != nil || sid != ch.Plan.SlotA.NativeSessionID || state != "revoked" {
		t.Fatal("original Thread identity was removed or left effective")
	}
	if f.f.db.db.QueryRow(`SELECT generation FROM hub_native_pair_slots_v1 WHERE pair_id=? AND slot='A' AND state='RESERVED'`, r.PairID).Scan(&generation) != nil || generation != 2 {
		t.Fatal("slot did not advance generation")
	}
	tx, err := f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	p, err := readNativePair(tx, r.PairID)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision, PairID: p.id, Slot: "A", ExpectedGeneration: 2, Runtime: "codex", NativeSessionID: sid, Workspace: "/synthetic/rejected"}
	if _, err = nativePairZeroJoinTx(tx, p, q, "synthetic-old-sid-retry-token", at); err == nil {
		t.Fatal("retained SID silently re-enrolled")
	}
	q.NativeSessionID = "synthetic-new-explicit-slot-attempt"
	if _, err = nativePairZeroJoinTx(tx, p, q, "synthetic-new-slot-token", at); err != nil {
		t.Fatal("explicit new generation rejected", err)
	}
}

func TestHubNativePairActivationRejectsPeerFitDeliveryOverflowWithoutPartialGrants(t *testing.T) {
	f, _, r := nativePairConsentFixture(t)
	_, ch := f.consentPlan(t, r)
	a, sa := f.consent(t, ch.Plan, "A")
	b, sb := f.consent(t, ch.Plan, "B")
	f.result(t, a, sa)
	// Measure the genuine production activation in an unpublished transaction,
	// then roll it back. No SQL fixture creates ACTIVE/membership/key grants.
	tx, err := f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	q := b.Body.(wire.NativePairConsentComplete)
	actor, err := appNodeActor(tx, b.Hub, q.Context.DeviceID, b.Device, q.SessionToken, b.At)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err = nativePairProcessTx(tx, actor, b, sb, false); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	pair, err := readSameGroupSealedV1PairTx(tx, ch.Plan.GroupID, ch.Plan.SlotA.EndpointID, ch.Plan.SlotB.EndpointID, b.At)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	peer, err := sameGroupSealedV1PeerCarrierTx(tx, pair)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	encoded, err := json.Marshal(peer)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	padding := wire.MaxNativePairCarrierBytes - len(encoded) - 64
	tx.Rollback()
	if padding <= 0 {
		t.Fatal("fixture lacks a near-boundary peer carrier")
	}
	// Actual persisted Grant ID fault: signatures/tuples remain genuine. The
	// peer still fits, while the full future delivery reservation cannot fit.
	endpoint := strings.ReplaceAll(ch.Plan.SlotB.EndpointID, "'", "''")
	if _, err = f.f.db.db.Exec(`CREATE TRIGGER synthetic_activation_carrier_overflow AFTER INSERT ON group_endpoint_key_grants_v2 WHEN NEW.endpoint_id='` + endpoint + `' BEGIN UPDATE group_endpoint_key_grants_v2 SET id=NEW.id||'` + strings.Repeat("s", padding) + `' WHERE id=NEW.id; END`); err != nil {
		t.Fatal(err)
	}
	packet, err := f.f.db.ProcessHubNativePair(b, sb)
	if err != nil {
		t.Fatal(err)
	}
	var fence wire.NativePairRejectionFence
	if wire.OpenClientResponse(f.f.device, f.f.hub, b.Packet, packet, &fence) != nil || !fence.NoEffect {
		t.Fatal("delivery overflow activation was not fenced")
	}
	var n int
	for _, query := range []struct {
		sql  string
		want int
	}{
		{`SELECT count(*) FROM hub_native_pairs_v1 WHERE pair_id=? AND state='WAITING_CONSENT'`, 1},
		{`SELECT count(*) FROM memberships WHERE group_id=(SELECT group_id FROM hub_native_pairs_v1 WHERE pair_id=?) AND role='member' AND grants_json='[]' AND revision=1`, 2},
		{`SELECT count(*) FROM group_endpoint_key_grants_v2 WHERE group_id=(SELECT group_id FROM hub_native_pairs_v1 WHERE pair_id=?)`, 0},
		{`SELECT count(*) FROM hub_native_pair_consents_v1 WHERE plan_id=(SELECT plan_id FROM hub_native_pairs_v1 WHERE pair_id=?)`, 1},
	} {
		if f.f.db.db.QueryRow(query.sql, ch.Plan.PairID).Scan(&n) != nil || n != query.want {
			t.Fatal("overflow partially published authority", query.sql, n)
		}
	}
	// Directly observe the exact rollback cause without interpreting TARGET_
	// UNAVAILABLE as proof of overflow: rerun with a fresh Owner intent in an
	// unpublished transaction and check the typed internal preflight error.
	fresh, _ := f.consent(t, ch.Plan, "B")
	q = fresh.Body.(wire.NativePairConsentComplete)
	tx, err = f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	actor, err = appNodeActor(tx, fresh.Hub, q.Context.DeviceID, fresh.Device, q.SessionToken, fresh.At)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := e2ee.VerifyOwnerNativePair(actor.scope.OwnerPublic, q.OwnerProof, e2ee.OwnerNativePairSlotConsent, fresh.At)
	if err != nil {
		t.Fatal(err)
	}
	_, err = nativePairConsentCompleteTx(tx, actor, claims, q.OwnerProof, q.GroupKeyProof, q.Context, wire.NativePairPacketDigest(fresh.Packet), fresh.At)
	if !errors.Is(err, errNativePairCarrierTooLarge) {
		t.Fatal("fixture did not exercise complete delivery size", err)
	}
	var p *hubNativePair
	p, err = readNativePair(tx, ch.Plan.PairID)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := readSameGroupSealedV1PairTx(tx, p.group, ch.Plan.SlotA.EndpointID, ch.Plan.SlotB.EndpointID, fresh.At)
	if err != nil {
		t.Fatal("peer itself must still fit", err)
	}
	carrier, err := sameGroupSealedV1PeerCarrierTx(tx, actual)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(carrier)
	if len(encoded) > wire.MaxNativePairCarrierBytes || len(encoded) < wire.MaxNativePairCarrierBytes-128 {
		t.Fatal("peer-fit negative fixture boundary missing", len(encoded))
	}
	t.Logf("synthetic actual peer=%d limit=%d; full delivery reservation rejected before publication", len(encoded), wire.MaxNativePairCarrierBytes)
}

func TestHubNativePairConsentRetainedFirstProofSurvivesItsShortWindow(t *testing.T) {
	f, _, r := nativePairConsentFixture(t)
	_, ch := f.consentPlan(t, r)
	a, sa := f.consent(t, ch.Plan, "A")
	f.result(t, a, sa)
	f.at = f.at.Add(90 * time.Second)
	b, sb := f.consent(t, ch.Plan, "B")
	_, active := f.result(t, b, sb)
	if active.State != wire.NativePairActive {
		t.Fatal("durable historical first consent was treated as a new expired request")
	}
}
