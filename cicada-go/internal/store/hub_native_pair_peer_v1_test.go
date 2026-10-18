package store

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nativePairActiveFixture(t *testing.T) (*nativePairStoreFixture, wire.NativePairConsentPlan, string) {
	t.Helper()
	f, _, r := nativePairConsentFixture(t)
	_, ch := f.consentPlan(t, r)
	a, sa := f.consent(t, ch.Plan, "A")
	b, sb := f.consent(t, ch.Plan, "B")
	f.result(t, a, sa)
	_, active := f.result(t, b, sb)
	if active.State != wire.NativePairActive {
		t.Fatal("production consents did not activate")
	}
	raw, err := hex.DecodeString(ch.Plan.Scope.CredentialCommitment)
	if err != nil {
		t.Fatal(err)
	}
	return f, ch.Plan, base64.RawURLEncoding.EncodeToString(raw)
}

func nativePairSeal(t *testing.T, f *nativePairStoreFixture, p wire.NativePairConsentPlan, credential, letter, msg, kind, request, reply, parent string, size int) []byte {
	t.Helper()
	sender, receiver := p.SlotA, p.SlotB
	senderKey, receiverKey := f.pairKeys["A"], f.pairKeys["B"]
	if letter == "B" {
		sender, receiver = receiver, sender
		senderKey, receiverKey = receiverKey, senderKey
	}
	peer, err := f.f.db.GetSameGroupSealedV1PeerKey(credential, p.GroupID, sender.EndpointID, receiver.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	pair := sameGroupEndpointPair{hubID: peer.HubID, groupID: peer.GroupID, sender: peer.Sender, receiver: peer.Receiver}
	context := sameGroupSealedV1Context(pair, msg, kind, request, reply, parent)
	raw, err := e2ee.SealEndpointMessage(senderKey, receiverKey.Public(), context, bytes.Repeat([]byte("s"), size), 1)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestHubNativePairPeerActualCurrentAndFourBoundedExchanges(t *testing.T) {
	f, p, credential := nativePairActiveFixture(t)
	// Administrative login ends without revoking the separately Owner-signed
	// peer lease. Neither another login nor Control inference supplies authority.
	if _, err := f.f.db.db.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE session_id=?`, f.scope.Actor.AccountSessionID); err != nil {
		t.Fatal(err)
	}

	peer, err := f.f.db.GetSameGroupSealedV1PeerKey(credential, p.GroupID, p.SlotA.EndpointID, p.SlotB.EndpointID)
	if err != nil || peer.NativePairEvidence == nil || peer.NativePairCurrent == nil {
		t.Fatal("missing real Store evidence", err)
	}
	if peer.Receiver.NativeSessionID != "" || peer.NativePairCurrent.Receiver.NativeSessionID != p.SlotB.NativeSessionID || wire.VerifyNativePairPeerAuthorization(true, peer.NativePairEvidence, peer.NativePairCurrent, f.f.hub, f.f.owner.Public(), p.Scope.NodeTupleDigest, p.SlotA.EndpointID, p.SlotB.EndpointID, time.Now().UTC()) != nil {
		t.Fatal("actual Current/signatures or old redaction wrong")
	}
	overPlain := SameGroupSealedV1Ask{NodeCredentialDigest: credential, GroupID: p.GroupID, SourceEndpointID: p.SlotA.EndpointID, TargetEndpointID: p.SlotB.EndpointID, MessageID: "synthetic-too-large-plaintext", RequestID: "synthetic-too-large-plaintext-request", IdempotencyKey: "synthetic-too-large-plaintext", DataScope: SameGroupSealedV1DataScope, ExpiresAt: appNodeStamp(time.Now().UTC().Add(time.Minute))}
	overPlain.Ciphertext = nativePairSeal(t, f, p, credential, "A", overPlain.MessageID, "REQUEST", overPlain.RequestID, "", "", 8193)
	if _, err = f.f.db.EnqueueSameGroupSealedV1Ask(overPlain); err == nil {
		t.Fatal("8KiB plaintext policy was bypassed through a larger valid old envelope")
	}

	// SEND and causal ASK remain unavailable even with ordinary live Group grants.
	send := nativePairSeal(t, f, p, credential, "A", "synthetic-pair-send", "SEND", "", "", "", 1)
	if _, err = f.f.db.EnqueueSameGroupSealedV1Send(SameGroupSealedV1Send{NodeCredentialDigest: credential, GroupID: p.GroupID, SourceEndpointID: p.SlotA.EndpointID, TargetEndpointID: p.SlotB.EndpointID, MessageID: "synthetic-pair-send", IdempotencyKey: "synthetic-pair-send", DataScope: SameGroupSealedV1DataScope, Ciphertext: send}); err == nil {
		t.Fatal("pair acquired generic SEND")
	}
	for i := 0; i < 4; i++ {
		msg, req, reply := fmt.Sprintf("synthetic-pair-ask-%d", i), fmt.Sprintf("synthetic-pair-request-%d", i), fmt.Sprintf("synthetic-pair-reply-%d", i)
		ask := SameGroupSealedV1Ask{NodeCredentialDigest: credential, GroupID: p.GroupID, SourceEndpointID: p.SlotA.EndpointID, TargetEndpointID: p.SlotB.EndpointID, MessageID: msg, RequestID: req, IdempotencyKey: msg, DataScope: SameGroupSealedV1DataScope, ExpiresAt: appNodeStamp(time.Now().UTC().Add(time.Minute))}
		ask.Ciphertext = nativePairSeal(t, f, p, credential, "A", msg, "REQUEST", req, "", "", 8192)
		first, e := f.f.db.EnqueueSameGroupSealedV1Ask(ask)
		if e != nil {
			t.Fatal("bounded ASK denied", i, e)
		}
		retry, e := f.f.db.EnqueueSameGroupSealedV1Ask(ask)
		if e != nil || retry.MessageID != first.MessageID {
			t.Fatal("exact ASK retry charged twice", e)
		}
		if i == 0 {
			extra := ask
			extra.RequestID = "synthetic-extra-request"
			extra.MessageID = "synthetic-extra-ask"
			extra.IdempotencyKey = extra.MessageID
			extra.Ciphertext = nativePairSeal(t, f, p, credential, "A", extra.MessageID, "REQUEST", extra.RequestID, "", "", 1)
			if _, e = f.f.db.EnqueueSameGroupSealedV1Ask(extra); e == nil {
				t.Fatal("second outstanding root ASK admitted")
			}
			child := extra
			child.ParentRequestID = req
			child.Ciphertext = nativePairSeal(t, f, p, credential, "A", child.MessageID, "REQUEST", child.RequestID, "", req, 1)
			if _, e = f.f.db.EnqueueSameGroupSealedV1Ask(child); e == nil {
				t.Fatal("causal ASK admitted")
			}
		}
		attempts, e := f.f.db.ClaimSameGroupSealedV1Inbox(credential, RelayClaimInput{RecipientEndpointID: p.SlotB.EndpointID, ConsumerID: "synthetic-pair-receiver", BindingID: p.SlotB.BindingID, BindingEpoch: p.SlotB.BindingEpoch, Limit: 1})
		if e != nil || len(attempts) != 1 {
			t.Fatal("bounded claim", i, e, len(attempts))
		}
		auth, e := f.f.db.AuthorizeClaimedSameGroupSealedV1Delivery(credential, msg, attempts[0].AttemptID)
		if e != nil || auth.NativePairEvidence == nil || auth.NativePairCurrent == nil || auth.NativeSessionID != p.SlotB.NativeSessionID || auth.Sender.NativeSessionID != "" || wire.ValidateNativePairCarrierSize(auth) != nil {
			t.Fatal("current exact delivery carrier", e)
		}
		response := SameGroupSealedV1Reply{NodeCredentialDigest: credential, RequestID: req, MessageID: reply, IdempotencyKey: reply, Ciphertext: nativePairSeal(t, f, p, credential, "B", reply, "REPLY", req, msg, "", 8192)}
		if _, e = f.f.db.EnqueueSameGroupSealedV1Reply(response); e != nil {
			t.Fatal("bounded reply denied", i, e)
		}
		if _, e = f.f.db.EnqueueSameGroupSealedV1Reply(response); e != nil {
			t.Fatal("exact reply retry denied", i, e)
		}
	}
	var asks, replies, total int
	if f.f.db.db.QueryRow(`SELECT sum(kind='ASK'),sum(kind='REPLY'),count(*) FROM hub_native_pair_messages_v1 WHERE pair_id=?`, p.PairID).Scan(&asks, &replies, &total) != nil || asks != 4 || replies != 4 || total != 8 {
		t.Fatal("durable exact budget wrong", asks, replies, total)
	}
	overflow := SameGroupSealedV1Ask{NodeCredentialDigest: credential, GroupID: p.GroupID, SourceEndpointID: p.SlotA.EndpointID, TargetEndpointID: p.SlotB.EndpointID, MessageID: "synthetic-overflow-ask", RequestID: "synthetic-overflow-request", IdempotencyKey: "synthetic-overflow-ask", DataScope: SameGroupSealedV1DataScope, ExpiresAt: appNodeStamp(time.Now().UTC().Add(time.Minute))}
	overflow.Ciphertext = nativePairSeal(t, f, p, credential, "A", overflow.MessageID, "REQUEST", overflow.RequestID, "", "", 1)
	if _, err = f.f.db.EnqueueSameGroupSealedV1Ask(overflow); err == nil {
		t.Fatal("fifth ASK admitted")
	}
	var n int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM fabric_messages WHERE id=?`, overflow.MessageID).Scan(&n) != nil || n != 0 {
		t.Fatal("budget rejection partially published")
	}
}

func TestHubNativePairPeerDeniesIndependentActualAccessChange(t *testing.T) {
	f, p, credential := nativePairActiveFixture(t)
	if _, err := f.f.db.db.Exec(`UPDATE network_access_sessions_v2 SET epoch=epoch+1 WHERE id=?`, p.SlotB.NetworkAccessBindingID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.f.db.GetSameGroupSealedV1PeerKey(credential, p.GroupID, p.SlotA.EndpointID, p.SlotB.EndpointID); err == nil {
		t.Fatal("Plan copied into Current after actual access epoch change")
	}
}

func TestHubNativePairPeerCancellationStopsFinalAuthorizationAndLateReply(t *testing.T) {
	f, p, credential := nativePairActiveFixture(t)
	msg, req := "synthetic-cancel-ask", "synthetic-cancel-request"
	ask := SameGroupSealedV1Ask{NodeCredentialDigest: credential, GroupID: p.GroupID, SourceEndpointID: p.SlotA.EndpointID, TargetEndpointID: p.SlotB.EndpointID, MessageID: msg, RequestID: req, IdempotencyKey: msg, DataScope: SameGroupSealedV1DataScope, ExpiresAt: appNodeStamp(time.Now().UTC().Add(time.Minute)), Ciphertext: nativePairSeal(t, f, p, credential, "A", msg, "REQUEST", req, "", "", 1)}
	if _, err := f.f.db.EnqueueSameGroupSealedV1Ask(ask); err != nil {
		t.Fatal(err)
	}
	attempts, err := f.f.db.ClaimSameGroupSealedV1Inbox(credential, RelayClaimInput{RecipientEndpointID: p.SlotB.EndpointID, ConsumerID: "synthetic-cancel-receiver", BindingID: p.SlotB.BindingID, BindingEpoch: p.SlotB.BindingEpoch, Limit: 1})
	if err != nil || len(attempts) != 1 {
		t.Fatal(err)
	}
	if _, err = f.f.db.CancelSameGroupSealedV1Request(credential, req); err != nil {
		t.Fatal(err)
	}
	if _, err = f.f.db.AuthorizeClaimedSameGroupSealedV1Delivery(credential, msg, attempts[0].AttemptID); err == nil {
		t.Fatal("cancelled ASK authorized native injection")
	}
	reply := "synthetic-cancel-reply"
	cipher := nativePairSeal(t, f, p, credential, "B", reply, "REPLY", req, msg, "", 1)
	if _, err = f.f.db.EnqueueSameGroupSealedV1Reply(SameGroupSealedV1Reply{NodeCredentialDigest: credential, RequestID: req, MessageID: reply, IdempotencyKey: reply, Ciphertext: cipher}); err == nil {
		t.Fatal("cancelled ASK gained new reply authority")
	}
	var n int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pair_messages_v1 WHERE pair_id=?`, p.PairID).Scan(&n) != nil || n != 1 {
		t.Fatal("cancellation refunded reservation or charged rejected reply")
	}
}

func TestHubNativePairActualOversizePreflightRollsBackClaimAndAuthorization(t *testing.T) {
	f, p, credential := nativePairActiveFixture(t)
	msg, req := "synthetic-size-ask", "synthetic-size-request"
	ask := SameGroupSealedV1Ask{NodeCredentialDigest: credential, GroupID: p.GroupID, SourceEndpointID: p.SlotA.EndpointID, TargetEndpointID: p.SlotB.EndpointID, MessageID: msg, RequestID: req, IdempotencyKey: msg, DataScope: SameGroupSealedV1DataScope, ExpiresAt: appNodeStamp(time.Now().UTC().Add(time.Minute)), Ciphertext: nativePairSeal(t, f, p, credential, "A", msg, "REQUEST", req, "", "", 1)}
	if _, err := f.f.db.EnqueueSameGroupSealedV1Ask(ask); err != nil {
		t.Fatal(err)
	}
	var originalID string
	if f.f.db.db.QueryRow(`SELECT id FROM group_endpoint_key_grants_v2 WHERE group_id=? AND endpoint_id=?`, p.GroupID, p.SlotB.EndpointID).Scan(&originalID) != nil {
		t.Fatal("actual Owner grant missing")
	}
	// Storage-fault fixture only: preserve real Owner signatures/ACTIVE rows but
	// expand an actual old carrier ID. This exercises the production writer's
	// complete encoding, with neither a smaller test bound nor an injected DTO.
	peer, err := f.f.db.GetSameGroupSealedV1PeerKey(credential, p.GroupID, p.SlotA.EndpointID, p.SlotB.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(peer)
	if err != nil || len(encoded) >= wire.MaxNativePairCarrierBytes-64 {
		t.Fatal("unexpected fixture carrier size")
	}
	oversized := originalID + strings.Repeat("s", wire.MaxNativePairCarrierBytes-len(encoded)-64)
	if _, err := f.f.db.db.Exec(`UPDATE group_endpoint_key_grants_v2 SET id=? WHERE id=?`, oversized, originalID); err != nil {
		t.Fatal(err)
	}
	nearLimit, err := f.f.db.GetSameGroupSealedV1PeerKey(credential, p.GroupID, p.SlotA.EndpointID, p.SlotB.EndpointID)
	if err != nil {
		t.Fatal("near-limit peer must remain valid", err)
	}
	encoded, _ = json.Marshal(nearLimit)
	if len(encoded) > wire.MaxNativePairCarrierBytes-32 || len(encoded) < wire.MaxNativePairCarrierBytes-96 {
		t.Fatal("actual peer boundary not exercised", len(encoded))
	}
	t.Logf("synthetic actual Store peer carrier=%d limit=%d; exact delivery adds actual route/attempt", len(encoded), wire.MaxNativePairCarrierBytes)

	overflow := ask
	overflow.MessageID = "synthetic-size-admission"
	overflow.RequestID = "synthetic-size-admission-request"
	overflow.IdempotencyKey = overflow.MessageID
	overflow.Ciphertext = nativePairSeal(t, f, p, credential, "A", overflow.MessageID, "REQUEST", overflow.RequestID, "", "", 1)
	if _, e := f.f.db.EnqueueSameGroupSealedV1Ask(overflow); !errors.Is(e, errNativePairCarrierTooLarge) {
		t.Fatal("actual message admission did not preflight complete delivery", e)
	}
	var published int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM fabric_messages WHERE id=?`, overflow.MessageID).Scan(&published) != nil || published != 0 {
		t.Fatal("oversize admission partially published a message")
	}

	claim := RelayClaimInput{RecipientEndpointID: p.SlotB.EndpointID, ConsumerID: "synthetic-size-receiver", BindingID: p.SlotB.BindingID, BindingEpoch: p.SlotB.BindingEpoch, Limit: 1}
	if _, err := f.f.db.ClaimSameGroupSealedV1Inbox(credential, claim); !errors.Is(err, errNativePairCarrierTooLarge) {
		t.Fatal("complete actual oversize was not rejected", err)
	}
	var state string
	var n int
	if f.f.db.db.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=?`, msg).Scan(&state) != nil || state != RelayInboxReady || f.f.db.db.QueryRow(`SELECT count(*) FROM relay_v2_delivery_attempts WHERE message_id=?`, msg).Scan(&n) != nil || n != 0 {
		t.Fatal("size preflight partially committed claim")
	}
	if _, err := f.f.db.db.Exec(`UPDATE group_endpoint_key_grants_v2 SET id=? WHERE id=?`, originalID, oversized); err != nil {
		t.Fatal(err)
	}
	attempts, err := f.f.db.ClaimSameGroupSealedV1Inbox(credential, claim)
	if err != nil || len(attempts) != 1 {
		t.Fatal("restored original carrier claim failed", err)
	}
	if _, err = f.f.db.db.Exec(`UPDATE group_endpoint_key_grants_v2 SET id=? WHERE id=?`, oversized, originalID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.f.db.AuthorizeClaimedSameGroupSealedV1Delivery(credential, msg, attempts[0].AttemptID); !errors.Is(err, errNativePairCarrierTooLarge) {
		t.Fatal("actual authorization writer bypassed size preflight", err)
	}
	if f.f.db.db.QueryRow(`SELECT state FROM relay_v2_delivery_attempts WHERE attempt_id=?`, attempts[0].AttemptID).Scan(&state) != nil || state != RelayAttemptClaimed {
		t.Fatal("size rejection committed a terminal failure")
	}
}

func TestHubNativePairPeerActiveHeartbeatRemainsCurrentBeyondJoinUntil(t *testing.T) {
	f, p, _ := nativePairActiveFixture(t)
	if _, err := f.f.db.db.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE session_id=?`, f.scope.Actor.AccountSessionID); err != nil {
		t.Fatal(err)
	}
	for _, elapsed := range []time.Duration{4 * time.Minute, 8 * time.Minute, 12 * time.Minute} {
		at := f.at.Add(elapsed)
		for _, slot := range []wire.NativePairSlot{p.SlotA, p.SlotB} {
			binding, err := f.f.db.renewSessionBindingLease(slot.BindingID, slot.LeaseOwner, slot.BindingEpoch, appNodeStamp(at.Add(5*time.Minute)), func() time.Time { return at })
			if err != nil || binding.Epoch != slot.BindingEpoch || binding.NativeSessionID != slot.NativeSessionID {
				t.Fatal("ACTIVE heartbeat rotated or lost original identity", err)
			}
		}
	}
	tx, err := f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	evidence, current, err := nativePairPeerTx(tx, p.GroupID, p.SlotA.EndpointID, p.SlotB.EndpointID, f.at.Add(12*time.Minute))
	if err != nil || evidence == nil || current == nil || current.Sender.NetworkAccessEpoch != p.SlotA.NetworkAccessEpoch || current.Receiver.NativeSessionID != p.SlotB.NativeSessionID {
		t.Fatal("same-identity heartbeat staled signed Plan or required an administrative login", err)
	}
	end, _ := time.Parse(time.RFC3339Nano, p.PeerExpiresAt)
	if _, _, err = nativePairPeerTx(tx, p.GroupID, p.SlotA.EndpointID, p.SlotB.EndpointID, end); err == nil {
		t.Fatal("signed peer deadline is not exclusive")
	}
}
