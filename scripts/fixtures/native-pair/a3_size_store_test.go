package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Separate from the HTTP formatter test: an actual original second consent
// must fail atomically when genuine persisted carrier data makes only the full
// future delivery overflow. Reused producer setup uses its zero-Join Tx helper;
// this is Store/PQ evidence, not a Node RPC/TCP/Runtime gate. No SQL creates
// ACTIVE/memberships/grants. The only SQL mutation is a private size-fault trigger.
func TestQANativePairA3DeliveryOverflowCannotPublishAuthority(t *testing.T) {
	f, _, status := nativePairConsentFixture(t)
	_, challenge := f.consentPlan(t, status)
	first, firstSeal := f.consent(t, challenge.Plan, "A")
	f.result(t, first, firstSeal)
	assertZero := func() {
		t.Helper()
		for _, slot := range []wire.NativePairSlot{challenge.Plan.SlotA, challenge.Plan.SlotB} {
			membership, err := f.f.db.GetMembershipByPrincipalGroup(slot.PrincipalID, challenge.Plan.GroupID)
			if err != nil || len(membership.Grants) != 0 || uint64(membership.Revision) != slot.MembershipRevision {
				t.Fatal("oversize consent published partial membership")
			}
			grant, err := f.f.db.GetGroupEndpointKeyGrant(f.scope.Actor.OwnerID, challenge.Plan.GroupID, slot.EndpointID)
			if !errors.Is(err, ErrGroupEndpointKeyGrantNotFound) || grant != nil {
				t.Fatal("oversize consent published a partial legacy key grant")
			}
		}
		var state wire.NativePairState
		var revision uint64
		var consents int
		if f.f.db.db.QueryRow(`SELECT state,control_revision FROM hub_native_pairs_v1 WHERE pair_id=?`, challenge.Plan.PairID).Scan(&state, &revision) != nil ||
			state != wire.NativePairWaitingConsent || revision != challenge.Plan.ExpectedRevision ||
			f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pair_consents_v1 WHERE plan_id=?`, challenge.Plan.PlanID).Scan(&consents) != nil || consents != 1 {
			t.Fatal("oversize consent changed activation revision or retained a second consent")
		}
	}
	assertZero()
	second, secondSeal := f.consent(t, challenge.Plan, "B")
	// Invoke the genuine production activation in a transaction which is always
	// rolled back. This measures actual tuple/proofs, never an SQL-made ACTIVE.
	tx, err := f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	actorFor := func(tx *sql.Tx, in HubNativePairInput) *hubAppNodeActor {
		t.Helper()
		q := in.Body.(wire.NativePairConsentComplete)
		actor, err := appNodeActor(tx, in.Hub, q.Context.DeviceID, in.Device, q.SessionToken, in.At)
		if err != nil {
			tx.Rollback()
			t.Fatal("actual original account/device was not current", err)
		}
		return actor
	}
	if _, err = nativePairProcessTx(tx, actorFor(tx, second), second, secondSeal, false); err != nil {
		tx.Rollback()
		t.Fatal("unfaulted original activation did not fit", err)
	}
	pair, err := readSameGroupSealedV1PairTx(tx, challenge.Plan.GroupID, challenge.Plan.SlotA.EndpointID, challenge.Plan.SlotB.EndpointID, second.At)
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
	padding := wire.MaxNativePairCarrierBytes - len(encoded) - 32
	// Legal maximum future route/attempt values are internal size reservations,
	// not published actual message identities or evidence. '&' expands in JSON.
	id := strings.Repeat("&", sameGroupSealedV1MaxTokenBytes)
	record := &RelaySealedV1Record{Route: RelaySealedV1Route{MessageID: id, RequestID: id,
		SenderEndpointID: pair.sender.EndpointID, ReceiverEndpointID: pair.receiver.EndpointID,
		Kind: "reply", ReplyTo: id}, Security: RelayMessageSecurity{Digest: strings.Repeat("0", 64),
		VisibilityPolicyRef: SameGroupSealedV1DataScope, ReceiverGroupID: pair.groupID}}
	scope, err := readNativeContextScopeForEndpointTx(tx, pair.receiver.EndpointID, pair.groupID)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	full, err := sameGroupSealedV1DeliveryCarrier(pair, record, id, "", scope, nil)
	if err != nil || padding <= 0 {
		tx.Rollback()
		t.Fatal("unfaulted complete delivery did not fit", err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertZero()
	endpoint := strings.ReplaceAll(challenge.Plan.SlotB.EndpointID, "'", "''")
	if _, err = f.f.db.db.Exec(`CREATE TRIGGER synthetic_qa_a3_delivery_overflow AFTER INSERT ON group_endpoint_key_grants_v2
WHEN NEW.endpoint_id='` + endpoint + `' BEGIN UPDATE group_endpoint_key_grants_v2 SET id=NEW.id||'` + strings.Repeat("s", padding) + `' WHERE id=NEW.id; END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.f.db.db.Exec(`DROP TRIGGER IF EXISTS synthetic_qa_a3_delivery_overflow`) })
	packet, err := f.f.db.ProcessHubNativePair(second, secondSeal)
	var fence wire.NativePairRejectionFence
	q := second.Body.(wire.NativePairConsentComplete)
	if err != nil || wire.OpenClientResponse(f.f.device, f.f.hub, second.Packet, packet, &fence) != nil ||
		wire.ValidateNativePairRejectionTarget(fence, q, second.Packet) != nil || !fence.NoEffect {
		t.Fatal("actual original oversize activation did not yield its exact authenticated no-effect fence", err)
	}
	assertZero()
	// A generic denial is insufficient evidence of size causality. A new valid
	// original in an unpublished production transaction must hit the typed size
	// error, while the genuine peer carrier still fits and verifies its proofs.
	fresh, _ := f.consent(t, challenge.Plan, "B")
	tx, err = f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	actor := actorFor(tx, fresh)
	freshQ := fresh.Body.(wire.NativePairConsentComplete)
	claims, err := e2ee.VerifyOwnerNativePair(actor.scope.OwnerPublic, freshQ.OwnerProof, e2ee.OwnerNativePairSlotConsent, fresh.At)
	if err != nil {
		t.Fatal(err)
	}
	_, err = nativePairConsentCompleteTx(tx, actor, claims, freshQ.OwnerProof, freshQ.GroupKeyProof,
		freshQ.Context, wire.NativePairPacketDigest(fresh.Packet), fresh.At)
	if !errors.Is(err, errNativePairCarrierTooLarge) {
		t.Fatal("actual complete delivery preflight was not the rejection cause", err)
	}
	pair, err = readSameGroupSealedV1PairTx(tx, challenge.Plan.GroupID, challenge.Plan.SlotA.EndpointID, challenge.Plan.SlotB.EndpointID, fresh.At)
	if err != nil {
		t.Fatal(err)
	}
	peer, err = sameGroupSealedV1PeerCarrierTx(tx, pair)
	if err != nil {
		t.Fatal("negative fixture peer itself did not fit", err)
	}
	encoded, _ = json.Marshal(peer)
	if len(encoded) > wire.MaxNativePairCarrierBytes || len(encoded) < wire.MaxNativePairCarrierBytes-96 ||
		wire.VerifyNativePairPeerAuthorization(true, peer.NativePairEvidence, peer.NativePairCurrent,
			f.f.hub, f.f.owner.Public(), challenge.Plan.Scope.NodeTupleDigest, pair.sender.EndpointID, pair.receiver.EndpointID, fresh.At) != nil {
		t.Fatal("near-boundary peer lacks the genuine original signed tuple", len(encoded))
	}
	// Reuse the previously genuine complete typed reservation, replacing only
	// its freshly produced actual evidence. Compute full bytes independently of
	// the Store's size helper, without publishing a fake route/attempt.
	full.Sender, full.Receiver = pair.sender, pair.receiver
	full.Sender.NativeSessionID = ""
	full.NativePairEvidence, full.NativePairCurrent = pair.nativeEvidence, pair.nativeCurrent
	fullEncoded, err := json.Marshal(full)
	if err != nil || len(fullEncoded) <= wire.MaxNativePairCarrierBytes || !errors.Is(nativePairAdmissionPreflightTx(tx, pair, record), errNativePairCarrierTooLarge) {
		t.Fatal("independent full delivery byte oracle did not overflow", len(fullEncoded), err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertZero()
	if _, err = f.f.db.db.Exec(`DROP TRIGGER synthetic_qa_a3_delivery_overflow`); err != nil {
		t.Fatal(err)
	}
	retry, err := f.f.db.ProcessHubNativePair(second, secondSeal)
	if err != nil || !bytes.Equal(retry, packet) {
		t.Fatal("fault removal revived or changed the permanently fenced original")
	}
	assertZero()
	t.Logf("QA_NATIVE_PAIR_A3_SIZE actual_signed_peer_bytes=%d fits=true full_internal_delivery_bytes=%d overflows=true second_consent_rollback_both_memberships_and_grants=true first_consent_only=true original_fence_permanent=true no_SQL_activation=true TCP_and_Runtime_NOT_RUN=true", len(encoded), len(fullEncoded))
}
