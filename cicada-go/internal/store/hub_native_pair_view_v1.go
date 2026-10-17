package store

import (
	"database/sql"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nativePairSlotTx(tx *sql.Tx, p *hubNativePair, letter string, at time.Time, requireCurrent bool) (*wire.NativePairSlot, wire.NativePairSlotState, error) {
	s := wire.NativePairSlot{Slot: letter, Runtime: "codex", NodeID: p.node, LeaseCeiling: p.peerExpires}
	var state wire.NativePairSlotState
	err := tx.QueryRow(`SELECT generation,state,attempt_id,native_session_id,endpoint_id,principal_id,network_access_binding_id,binding_id,lease_owner FROM hub_native_pair_slots_v1 WHERE pair_id=? AND slot=? AND state!='REJECTED'`, p.id, letter).Scan(&s.Generation, &state, &s.AttemptID, &s.NativeSessionID, &s.EndpointID, &s.PrincipalID, &s.NetworkAccessBindingID, &s.BindingID, &s.LeaseOwner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, wire.NativePairSlotReserved, nil
	}
	if err != nil {
		return nil, "", err
	}
	if state == wire.NativePairSlotReserved {
		return nil, state, nil
	}
	err = tx.QueryRow(`SELECT a.epoch,n.revision,en.revision,b.epoch,m.revision,eg.revision FROM network_access_sessions_v2 a JOIN network_memberships_v2 n ON n.network_id=a.network_id AND n.principal_id=a.principal_id JOIN endpoint_network_memberships_v2 en ON en.network_id=a.network_id AND en.endpoint_id=a.endpoint_id JOIN session_bindings b ON b.id=? JOIN memberships m ON m.principal_id=b.principal_id AND m.group_id=b.group_id JOIN endpoint_group_memberships eg ON eg.endpoint_id=b.endpoint_id AND eg.group_id=b.group_id WHERE a.id=? AND a.network_id=? AND a.endpoint_id=? AND b.endpoint_id=? AND b.native_session_id=? AND b.node_id=? AND b.group_id=? AND b.lease_owner=?`, s.BindingID, s.NetworkAccessBindingID, p.network, s.EndpointID, s.EndpointID, s.NativeSessionID, p.node, p.group, s.LeaseOwner).Scan(&s.NetworkAccessEpoch, &s.NetworkMembershipRevision, &s.EndpointNetworkRevision, &s.BindingEpoch, &s.MembershipRevision, &s.EndpointJoinRevision)
	if err != nil {
		return nil, "", err
	}
	manifest, err := readGroupEndpointKeyGrantManifest(tx, p.owner, p.group, s.EndpointID, p.scope.Actor.OwnerPublic.ID, appNodeStamp(at), p.peerExpires, at)
	if err != nil {
		if requireCurrent {
			return nil, "", err
		}
		return &s, state, nil
	}
	s.CandidateVersion = uint64(manifest.CandidateVersion)
	s.CandidatePublic = manifest.CandidatePublicIdentity
	s.CandidateFingerprint = manifest.CandidateFingerprint
	s.CandidateProofDigest = manifest.CandidateProofDigest
	s.CandidateAttestation = append([]byte(nil), manifest.CandidateAttestation...)
	if wire.ValidateNativePairSlot(s, p.scope, p.peerExpires) != nil {
		return nil, "", ErrHubAccountRejected
	}
	if state != wire.NativePairSlotActive {
		state = wire.NativePairSlotCandidateReady
		if p.planID != "" {
			var count int
			if err = tx.QueryRow(`SELECT count(*) FROM hub_native_pair_consents_v1 c JOIN hub_native_pair_plans_v1 plan ON plan.plan_id=c.plan_id AND plan.state='PREPARED' WHERE c.plan_id=? AND c.slot=?`, p.planID, letter).Scan(&count); err != nil {
				return nil, "", err
			}
			if count > 0 {
				state = wire.NativePairSlotConsentRecorded
			}
		}
	}
	return &s, state, nil
}

func nativePairBudget(tx *sql.Tx, pair string) (wire.NativePairBudgetObservation, error) {
	var b wire.NativePairBudgetObservation
	err := tx.QueryRow(`SELECT coalesce(sum(CASE WHEN kind='ASK' THEN 1 ELSE 0 END),0),coalesce(sum(CASE WHEN kind='REPLY' THEN 1 ELSE 0 END),0),count(*),coalesce(sum(ciphertext_bytes),0) FROM hub_native_pair_messages_v1 WHERE pair_id=?`, pair).Scan(&b.RootAsksUsed, &b.RepliesUsed, &b.MessagesUsed, &b.CiphertextBytesUsed)
	return b, err
}

func nativePairResultTx(tx *sql.Tx, p *hubNativePair, c wire.NativePairRequestContext, op, digest, outcome, code string, administrative bool, at time.Time) (wire.NativePairResult, error) {
	r := wire.NativePairResult{Format: wire.NativePairFormat, Operation: op, RequestID: c.RequestID, RequestPacketDigest: digest, PairID: p.id, State: p.state, Outcome: outcome, ErrorCode: code, ControlRevision: p.revision, AdministrativePermission: administrative, PeerExpiresAt: p.peerExpires, ObservedAt: appNodeStamp(at)}
	var err error
	r.SlotA, r.SlotAState, err = nativePairSlotTx(tx, p, "A", at, false)
	if err != nil {
		return r, err
	}
	r.SlotB, r.SlotBState, err = nativePairSlotTx(tx, p, "B", at, false)
	if err != nil {
		return r, err
	}
	r.Budget, err = nativePairBudget(tx, p.id)
	return r, err
}
