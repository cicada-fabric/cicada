package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

var errNativePairCarrierTooLarge = errors.New("native pair complete carrier exceeds bound")

// Pair policy is selected by this persisted Group marker, never a peer payload.
func nativePairForGroupTx(tx *sql.Tx, group string) (*hubNativePair, error) {
	exists, err := nativePairScopeExists(tx, "", group, "")
	if err != nil || !exists {
		return nil, err
	}
	var id string
	if err = tx.QueryRow(`SELECT pair_id FROM hub_native_pairs_v1 WHERE group_id=?`, group).Scan(&id); err != nil {
		return nil, err
	}
	return readNativePair(tx, id)
}

func nativePairCurrentSlot(s wire.NativePairSlot) wire.NativePairCurrentSlot {
	return wire.NativePairCurrentSlot{Slot: s.Slot, Generation: s.Generation, AttemptID: s.AttemptID, NativeSessionID: s.NativeSessionID, NetworkAccessBindingID: s.NetworkAccessBindingID, NetworkAccessEpoch: s.NetworkAccessEpoch, NetworkMembershipRevision: s.NetworkMembershipRevision, EndpointNetworkRevision: s.EndpointNetworkRevision, LeaseOwner: s.LeaseOwner, LeaseCeiling: s.LeaseCeiling}
}

func nativePairPeerTx(tx *sql.Tx, group, sender, receiver string, at time.Time) (*wire.NativePairPeerEvidence, *wire.NativePairPeerCurrent, error) {
	p, err := nativePairForGroupTx(tx, group)
	if err != nil {
		return nil, nil, ErrSameGroupSealedV1Denied
	}
	if p == nil {
		return nil, nil, nil
	}
	if p.state != wire.NativePairActive || !appNodeBefore(at, p.peerExpires) {
		return nil, nil, ErrSameGroupSealedV1Denied
	}
	plan, err := nativePairReadPlanTx(tx, p, "ACTIVE")
	if err != nil {
		return nil, nil, ErrSameGroupSealedV1Denied
	}
	actualA, actualB, err := nativePairPlanCurrentTx(tx, p, plan, true, at)
	if err != nil {
		return nil, nil, ErrSameGroupSealedV1Denied
	}
	currentSender, currentReceiver := actualA, actualB
	if sender == actualB.EndpointID && receiver == actualA.EndpointID {
		currentSender, currentReceiver = actualB, actualA
	} else if sender != actualA.EndpointID || receiver != actualB.EndpointID {
		return nil, nil, ErrSameGroupSealedV1Denied
	}
	grants, _ := json.Marshal(wire.NativePairGroupGrants())
	for _, s := range []*wire.NativePairSlot{actualA, actualB} {
		var count int
		if tx.QueryRow(`SELECT count(*) FROM hub_native_pair_slots_v1 s JOIN memberships m ON m.principal_id=s.principal_id AND m.group_id=? JOIN network_memberships_v2 n ON n.network_id=? AND n.principal_id=s.principal_id JOIN endpoint_network_memberships_v2 e ON e.network_id=n.network_id AND e.endpoint_id=s.endpoint_id WHERE s.pair_id=? AND s.slot=? AND s.generation=? AND s.state='ACTIVE' AND m.status='active' AND m.role='member' AND m.grants_json=? AND m.authorization_json='{}' AND m.expires_at=? AND n.status='active' AND n.grants_json='[]' AND e.status='active' AND e.discoverable=0`, p.group, p.network, p.id, s.Slot, s.Generation, string(grants), p.peerExpires).Scan(&count) != nil || count != 1 {
			return nil, nil, ErrSameGroupSealedV1Denied
		}
	}
	evidence := &wire.NativePairPeerEvidence{ContractRevision: wire.NativePairContractRevision, Plan: plan, BootstrapOwnerProof: append([]byte(nil), p.bootstrapProof...)}
	if tx.QueryRow(`SELECT owner_proof,group_key_proof FROM hub_native_pair_consents_v1 WHERE plan_id=? AND slot='A'`, p.planID).Scan(&evidence.SlotAOwnerConsent, &evidence.SlotAGroupKeyProof) != nil || tx.QueryRow(`SELECT owner_proof,group_key_proof FROM hub_native_pair_consents_v1 WHERE plan_id=? AND slot='B'`, p.planID).Scan(&evidence.SlotBOwnerConsent, &evidence.SlotBGroupKeyProof) != nil {
		return nil, nil, ErrSameGroupSealedV1Denied
	}
	// These are observations of independently read rows. Never substitute a
	// signed Plan coordinate for a missing or mismatched actual coordinate.
	current := &wire.NativePairPeerCurrent{State: "CURRENT", ControlRevision: p.revision, ObservedAt: appNodeStamp(at), Sender: nativePairCurrentSlot(*currentSender), Receiver: nativePairCurrentSlot(*currentReceiver)}
	if wire.VerifyNativePairPeerAuthorization(true, evidence, current, p.accountHub, p.scope.Actor.OwnerPublic, p.scope.NodeTupleDigest, sender, receiver, at) != nil {
		return nil, nil, ErrSameGroupSealedV1Denied
	}
	return evidence, current, nil
}

// Count authenticated AEAD ciphertext bytes, rather than a caller's plaintext
// assertion. The existing fixed suite is AES-GCM with a 16-byte tag. No content
// is opened or logged; padding counts against the same budget.
func nativePairPlaintextSize(ciphertext []byte) (uint64, error) {
	var outer e2ee.EndpointMessageEnvelope
	var inner e2ee.Envelope
	if json.Unmarshal(ciphertext, &outer) != nil || json.Unmarshal(outer.Sealed, &inner) != nil || inner.Algorithm != e2ee.Algorithm || len(inner.Ciphertext) <= 16 {
		return 0, ErrSameGroupSealedV1Denied
	}
	return uint64(len(inner.Ciphertext) - 16), nil
}

// The existing Relay admission writer holds the transaction. Exact immutable
// retries reuse the ledger row; a rejected/cancelled/UNKNOWN delivery never
// refunds its reservation, including across reopen or restart.
func nativePairReserveMessageTx(tx *sql.Tx, pair sameGroupEndpointPair, record *RelaySealedV1Record, parent string, at time.Time) error {
	if pair.nativeEvidence == nil {
		return nil
	}
	plan := pair.nativeEvidence.Plan
	kind := "ASK"
	if record.Route.Kind == "reply" {
		kind = "REPLY"
	} else if record.Route.Kind != "ask" {
		return ErrSameGroupSealedV1Denied
	}
	if parent != "" || record.Route.RequestID == "" || len(record.Ciphertext) > int(plan.Policy.MaxCiphertextBytes) {
		return ErrSameGroupSealedV1Denied
	}
	plain, err := nativePairPlaintextSize(record.Ciphertext)
	if err != nil || plain > plan.Policy.MaxPlaintextBytes {
		return ErrSameGroupSealedV1Denied
	}
	var savedDigest, request, sender, receiver, savedKind string
	var size int
	err = tx.QueryRow(`SELECT ciphertext_digest,ciphertext_bytes,request_id,kind,sender_endpoint_id,receiver_endpoint_id FROM hub_native_pair_messages_v1 WHERE pair_id=? AND message_id=?`, plan.PairID, record.Route.MessageID).Scan(&savedDigest, &size, &request, &savedKind, &sender, &receiver)
	if err == nil {
		if savedDigest != record.Security.Digest || size != len(record.Ciphertext) || request != record.Route.RequestID || savedKind != kind || sender != record.Route.SenderEndpointID || receiver != record.Route.ReceiverEndpointID {
			return ErrRelayIdempotencyConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	b, err := nativePairBudget(tx, plan.PairID)
	if err != nil {
		return err
	}
	if b.MessagesUsed >= plan.Policy.MaxMessages || b.CiphertextBytesUsed+uint64(len(record.Ciphertext)) > plan.Policy.MaxTotalCiphertext || (kind == "ASK" && b.RootAsksUsed >= plan.Policy.MaxRootAsks) || (kind == "REPLY" && b.RepliesUsed >= plan.Policy.MaxReplies) {
		return ErrSameGroupSealedV1Denied
	}
	var total uint64
	var counted uint64
	rows, err := tx.Query(`SELECT p.ciphertext FROM hub_native_pair_messages_v1 m JOIN relay_v2_message_payloads p ON p.message_id=m.message_id WHERE m.pair_id=?`, plan.PairID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			break
		}
		var n uint64
		n, err = nativePairPlaintextSize(raw)
		if err != nil {
			break
		}
		total += n
		counted++
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if re != nil {
		return re
	}
	if counted != b.MessagesUsed || total+plain > plan.Policy.MaxTotalPlaintext {
		return ErrSameGroupSealedV1Denied
	}
	var n int
	if kind == "ASK" {
		if tx.QueryRow(`SELECT count(*) FROM hub_native_pair_messages_v1 m JOIN relay_v2_requests r ON r.request_id=m.request_id WHERE m.pair_id=? AND m.kind='ASK' AND r.state IN('OPEN','CANCEL_REQUESTED') AND cicada_network_expiry_allows(r.expires_at,?)`, plan.PairID, appNodeStamp(at)).Scan(&n) != nil || uint64(n) >= plan.Policy.MaxOutstandingAsks {
			return ErrSameGroupSealedV1Denied
		}
	} else {
		if tx.QueryRow(`SELECT count(*) FROM hub_native_pair_messages_v1 m JOIN relay_v2_requests r ON r.request_id=m.request_id WHERE m.pair_id=? AND m.request_id=? AND m.kind='ASK' AND r.state='OPEN' AND cicada_network_expiry_allows(r.expires_at,?)`, plan.PairID, record.Route.RequestID, appNodeStamp(at)).Scan(&n) != nil || n != 1 {
			return ErrSameGroupSealedV1Denied
		}
		if tx.QueryRow(`SELECT count(*) FROM hub_native_pair_messages_v1 WHERE pair_id=? AND request_id=? AND kind='REPLY'`, plan.PairID, record.Route.RequestID).Scan(&n) != nil || uint64(n) >= plan.Policy.MaxRepliesPerAsk {
			return ErrSameGroupSealedV1Denied
		}
	}
	_, err = tx.Exec(`INSERT INTO hub_native_pair_messages_v1(pair_id,message_id,request_id,kind,ciphertext_digest,ciphertext_bytes,sender_endpoint_id,receiver_endpoint_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, plan.PairID, record.Route.MessageID, record.Route.RequestID, kind, record.Security.Digest, len(record.Ciphertext), record.Route.SenderEndpointID, record.Route.ReceiverEndpointID, appNodeStamp(at))
	return err
}

func nativePairQueuedMessageTx(tx *sql.Tx, pair sameGroupEndpointPair, record *RelaySealedV1Record) error {
	if pair.nativeEvidence == nil {
		return nil
	}
	kind := "ASK"
	if record.Route.Kind == "reply" {
		kind = "REPLY"
	} else if record.Route.Kind != "ask" {
		return ErrSameGroupSealedV1Denied
	}
	var count int
	if tx.QueryRow(`SELECT count(*) FROM hub_native_pair_messages_v1 WHERE pair_id=? AND message_id=? AND request_id=? AND kind=? AND ciphertext_digest=? AND ciphertext_bytes=? AND sender_endpoint_id=? AND receiver_endpoint_id=?`, pair.nativeEvidence.Plan.PairID, record.Route.MessageID, record.Route.RequestID, kind, record.Security.Digest, len(record.Ciphertext), pair.sender.EndpointID, pair.receiver.EndpointID).Scan(&count) != nil || count != 1 {
		return ErrSameGroupSealedV1Denied
	}
	return nil
}

func nativePairClaimBudgetTx(tx *sql.Tx, pair sameGroupEndpointPair, message string) error {
	if pair.nativeEvidence == nil {
		return nil
	}
	var n uint64
	var charged int
	if tx.QueryRow(`SELECT count(*) FROM relay_v2_delivery_attempts WHERE message_id=?`, message).Scan(&charged) != nil {
		return ErrSameGroupSealedV1Denied
	}
	if charged > 0 {
		return nil
	}
	if tx.QueryRow(`SELECT count(DISTINCT a.message_id) FROM relay_v2_delivery_attempts a JOIN hub_native_pair_messages_v1 m ON m.message_id=a.message_id WHERE m.pair_id=?`, pair.nativeEvidence.Plan.PairID).Scan(&n) != nil || n >= pair.nativeEvidence.Plan.Policy.MaxNativeDeliveries {
		return ErrSameGroupSealedV1Denied
	}
	return nil
}

func nativePairCarrierTx(result any, evidence *wire.NativePairPeerEvidence) error {
	if evidence != nil && wire.ValidateNativePairCarrierSize(result) != nil {
		return errors.Join(ErrSameGroupSealedV1Denied, errNativePairCarrierTooLarge)
	}
	return nil
}

// Activation preflights both actual peer carriers AND complete delivery shapes
// in both directions before publishing permissions. Size-only future fields
// stay internal and are never returned or stored as an authorization.
func nativePairActivationPreflightTx(tx *sql.Tx, p *hubNativePair, at time.Time) error {
	plan, err := nativePairReadPlanTx(tx, p, "ACTIVE")
	if err != nil {
		return err
	}
	for _, ids := range [][2]string{{plan.SlotA.EndpointID, plan.SlotB.EndpointID}, {plan.SlotB.EndpointID, plan.SlotA.EndpointID}} {
		pair, e := readSameGroupSealedV1PairTx(tx, p.group, ids[0], ids[1], at)
		if e != nil {
			return e
		}
		if pair.nativeEvidence == nil {
			return ErrSameGroupSealedV1Denied
		}
		// Existing Relay token grammar allows 256 bytes and HTML-sensitive ASCII.
		// '&' attains its maximum six-byte JSON expansion for every such byte.
		id := strings.Repeat("&", sameGroupSealedV1MaxTokenBytes)
		for _, kind := range []string{"ask", "reply"} {
			route := RelaySealedV1Route{MessageID: id, RequestID: id, SenderEndpointID: pair.sender.EndpointID, ReceiverEndpointID: pair.receiver.EndpointID, Kind: kind}
			if kind == "reply" {
				route.ReplyTo = id
			}
			record := &RelaySealedV1Record{Route: route, Security: RelayMessageSecurity{Digest: strings.Repeat("0", 64), VisibilityPolicyRef: SameGroupSealedV1DataScope, ReceiverGroupID: pair.groupID}}
			if e = nativePairAdmissionPreflightTx(tx, pair, record); e != nil {
				return e
			}
		}
	}
	return nil
}

// Reserve only unknown future fields. Actual endpoint/key/proof/Current tuple
// and actual message route remain intact. Attempt IDs use the unchanged Relay
// token upper bound (also covering NewID's random/fallback forms), and future
// RFC3339Nano observations need at most 30 ASCII bytes. ParentRequestID is empty
// under the fixed depth-zero policy; task/SEND carriers are unavailable. These
// placeholders are size-only, never authorization data and never published.
func nativePairAdmissionPreflightTx(tx *sql.Tx, pair sameGroupEndpointPair, record *RelaySealedV1Record) error {
	if pair.nativeEvidence == nil {
		return nil
	}
	scope, err := readNativeContextScopeForEndpointTx(tx, pair.receiver.EndpointID, pair.groupID)
	if err != nil {
		return err
	}
	reserved := pair
	current := *pair.nativeCurrent
	current.ObservedAt = "2099-12-31T23:59:59.123456789Z"
	reserved.nativeCurrent = &current
	_, err = sameGroupSealedV1DeliveryCarrier(reserved, record, strings.Repeat("&", sameGroupSealedV1MaxTokenBytes), "", scope, nil)
	return err
}

// Keep proof bytes exactly as consented and verify the actual old carrier's
// projected manifest matches that evidence; no alternative legacy grant may
// silently stand in for the two explicit consents.
func nativePairMatchEndpointEvidence(pair sameGroupEndpointPair) error {
	if pair.nativeEvidence == nil {
		return nil
	}
	p := pair.nativeEvidence
	for _, actual := range []SameGroupSealedV1EndpointEvidence{pair.sender, pair.receiver} {
		m, proof := p.Plan.SlotAKeyManifest, p.SlotAGroupKeyProof
		if actual.EndpointID == p.Plan.SlotB.EndpointID {
			m, proof = p.Plan.SlotBKeyManifest, p.SlotBGroupKeyProof
		}
		raw, _ := json.Marshal(actual.Grant.Manifest)
		var projected wire.NativePairGroupKeyManifest
		if json.Unmarshal(raw, &projected) != nil || !reflect.DeepEqual(projected, m) || !bytes.Equal(actual.Grant.SignedProof, proof) {
			return ErrSameGroupSealedV1Denied
		}
	}
	return nil
}
