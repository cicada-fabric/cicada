package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Called only inside the ordinary native heartbeat's writer transaction.
// A pair's directory access credential keeps its original epoch/identity;
// network_renew deliberately has different rotation semantics and is not used.
func renewNativePairAccessLeaseTx(tx *sql.Tx, binding *SessionBinding, wanted string, at time.Time) (string, error) {
	var pair string
	err := tx.QueryRow(`SELECT pair_id FROM hub_native_pairs_v1 WHERE group_id=?`, binding.GroupID).Scan(&pair)
	if errors.Is(err, sql.ErrNoRows) {
		return wanted, nil
	}
	if err != nil {
		return "", err
	}
	p, err := readNativePair(tx, pair)
	if err != nil || p == nil {
		return "", ErrNetworkPermission
	}
	scope := NativeActorScope{PrincipalID: binding.PrincipalID, EndpointID: binding.EndpointID,
		GroupID: p.group, NetworkID: p.network, BindingID: binding.ID,
		BindingEpoch: binding.Epoch, LeaseOwner: binding.LeaseOwner}
	if err = tx.QueryRow(`SELECT id,revision FROM memberships WHERE group_id=? AND principal_id=?`,
		p.group, binding.PrincipalID).Scan(&scope.MembershipID, &scope.MembershipRevision); err != nil || guardNativeSelfTx(tx, scope, at) != nil {
		return "", ErrNetworkPermission
	}
	var slot wire.NativePairCurrentSlot
	var accessID string
	err = tx.QueryRow(`SELECT slot,generation,attempt_id,native_session_id,network_access_binding_id,lease_owner
FROM hub_native_pair_slots_v1 WHERE pair_id=? AND endpoint_id=? AND principal_id=? AND binding_id=? AND state IN('JOINED_ZERO','ACTIVE')`,
		p.id, binding.EndpointID, binding.PrincipalID, binding.ID).Scan(&slot.Slot, &slot.Generation,
		&slot.AttemptID, &slot.NativeSessionID, &accessID, &slot.LeaseOwner)
	if err != nil || slot.NativeSessionID != binding.NativeSessionID || slot.LeaseOwner != binding.LeaseOwner || binding.NodeID != p.node {
		return "", ErrNetworkPermission
	}
	var accessEpoch uint64
	var accessExpiry string
	err = tx.QueryRow(`SELECT epoch,lease_expires_at FROM network_access_sessions_v2
WHERE id=? AND network_id=? AND endpoint_id=? AND principal_id=? AND native_session_id=? AND node_id=?
AND lease_owner=? AND credential_hash=? AND owner_key_id=? AND status='active'`, accessID,
		p.network, binding.EndpointID, binding.PrincipalID, binding.NativeSessionID, p.node,
		binding.LeaseOwner, binding.CredentialHash, p.scope.Actor.OwnerPublic.ID).Scan(&accessEpoch, &accessExpiry)
	if err != nil {
		return "", ErrNetworkPermission
	}
	// Every accepted zero Join starts these two immutable lease epochs at one.
	// Once active, additionally compare their exact signed Plan basis.
	if accessEpoch != 1 || binding.Epoch != 1 {
		return "", ErrNetworkPermission
	}
	if p.state == wire.NativePairActive {
		var raw string
		var plan wire.NativePairConsentPlan
		if tx.QueryRow(`SELECT plan_json FROM hub_native_pair_plans_v1 WHERE plan_id=? AND pair_id=? AND state='ACTIVE'`,
			p.planID, p.id).Scan(&raw) != nil || json.Unmarshal([]byte(raw), &plan) != nil || wire.ValidateNativePairPlan(plan, p.accountHub) != nil {
			return "", ErrNetworkPermission
		}
		var exactResources int
		if plan.PairID != p.id || plan.PlanID != p.planID || plan.GroupID != p.group || plan.NetworkID != p.network ||
			tx.QueryRow(`SELECT count(*) FROM networks_v2 n JOIN groups g ON g.network_id=n.id
WHERE n.id=? AND n.hub_id=? AND n.owner_id=? AND n.state='ACTIVE' AND n.version=?
AND g.id=? AND g.owner_principal_id=? AND g.state='ACTIVE' AND g.version=? AND g.revision=?`,
				p.network, p.hub, p.owner, plan.NetworkVersion, p.group, p.owner, plan.GroupVersion, plan.GroupRevision).Scan(&exactResources) != nil || exactResources != 1 {
			return "", ErrNetworkPermission
		}
		approved, projected := plan.SlotA, plan.ProjectedSlotAMembership
		if slot.Slot == "B" {
			approved, projected = plan.SlotB, plan.ProjectedSlotBMembership
		}
		if approved.Slot != slot.Slot || approved.Generation != slot.Generation || approved.AttemptID != slot.AttemptID ||
			approved.EndpointID != binding.EndpointID || approved.PrincipalID != binding.PrincipalID || approved.NodeID != binding.NodeID ||
			approved.NativeSessionID != binding.NativeSessionID || approved.BindingID != binding.ID || approved.BindingEpoch != binding.Epoch ||
			approved.NetworkAccessBindingID != accessID || approved.NetworkAccessEpoch != accessEpoch ||
			approved.LeaseOwner != binding.LeaseOwner || approved.LeaseCeiling != p.peerExpires ||
			uint64(scope.MembershipRevision) != projected {
			return "", ErrNetworkPermission
		}
		actual, _, err := nativePairSlotTx(tx, p, slot.Slot, at, true)
		if err != nil || actual == nil || actual.NetworkMembershipRevision != approved.NetworkMembershipRevision ||
			actual.EndpointNetworkRevision != approved.EndpointNetworkRevision || actual.EndpointJoinRevision != approved.EndpointJoinRevision ||
			actual.CandidateVersion != approved.CandidateVersion || actual.CandidateFingerprint != approved.CandidateFingerprint ||
			actual.CandidateProofDigest != approved.CandidateProofDigest {
			return "", ErrNetworkPermission
		}
	}
	ceiling, ce := time.Parse(time.RFC3339Nano, p.peerExpires)
	nativeEnd, ne := parseSessionBindingLeaseExpiry(binding.LeaseExpiresAt)
	accessEnd, ae := time.Parse(time.RFC3339Nano, accessExpiry)
	end, ee := time.Parse(time.RFC3339Nano, wanted)
	if ce != nil || ne != nil || ae != nil || ee != nil || !at.Before(ceiling) ||
		!at.Before(nativeEnd) || !at.Before(accessEnd) || nativeEnd.After(ceiling) || accessEnd.After(ceiling) {
		return "", ErrSessionBindingLeaseExpired
	}
	if nativeEnd.After(end) {
		end = nativeEnd
	}
	if accessEnd.After(end) {
		end = accessEnd
	}
	if end.After(ceiling) {
		end = ceiling
	}
	stamp := appNodeStamp(end)
	updated, err := tx.Exec(`UPDATE network_access_sessions_v2 SET lease_expires_at=?,updated_at=?
WHERE id=? AND epoch=? AND lease_owner=? AND credential_hash=? AND lease_expires_at=? AND status='active'`,
		stamp, at.Format(time.RFC3339), accessID, accessEpoch, binding.LeaseOwner, binding.CredentialHash, accessExpiry)
	if err != nil {
		return "", err
	}
	if n, err := updated.RowsAffected(); err != nil || n != 1 {
		return "", ErrSessionBindingStaleEpoch
	}
	return stamp, nil
}
