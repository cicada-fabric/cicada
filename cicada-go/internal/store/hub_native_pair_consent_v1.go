package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nativePairStableScope(a, b e2ee.OwnerNativePairScope) bool {
	a.Actor.AccountSessionID, b.Actor.AccountSessionID = "", ""
	a.Actor.AccountSessionExpiresAt, b.Actor.AccountSessionExpiresAt = "", ""
	return reflect.DeepEqual(a, b)
}

// Read both live identities independently of the signed Plan. Lease expiry and
// heartbeat version may change; identity, epochs, membership and candidate may not.
func nativePairLiveSlotTx(tx *sql.Tx, p *hubNativePair, letter string, at time.Time) (*wire.NativePairSlot, error) {
	s, _, err := nativePairSlotTx(tx, p, letter, at, true)
	if err != nil || s == nil {
		return nil, ErrHubAccountRejected
	}
	var membership string
	if tx.QueryRow(`SELECT id FROM memberships WHERE group_id=? AND principal_id=?`, p.group, s.PrincipalID).Scan(&membership) != nil {
		return nil, ErrHubAccountRejected
	}
	scope := NativeActorScope{NetworkID: p.network, GroupID: p.group, PrincipalID: s.PrincipalID, EndpointID: s.EndpointID, BindingID: s.BindingID, BindingEpoch: s.BindingEpoch, LeaseOwner: s.LeaseOwner, MembershipID: membership, MembershipRevision: int64(s.MembershipRevision)}
	if guardNativeSelfTx(tx, scope, at) != nil {
		return nil, ErrHubAccountRejected
	}
	var count int
	if tx.QueryRow(`SELECT count(*) FROM network_access_sessions_v2 a JOIN session_bindings b ON b.id=?
 WHERE a.id=? AND a.network_id=? AND a.endpoint_id=? AND a.principal_id=? AND a.native_session_id=? AND a.node_id=?
 AND a.status='active' AND a.epoch=? AND a.lease_owner=? AND a.owner_key_id=? AND a.credential_hash=b.credential_hash
 AND b.epoch=? AND b.status='leased' AND b.lease_owner=a.lease_owner`, s.BindingID, s.NetworkAccessBindingID, p.network, s.EndpointID, s.PrincipalID, s.NativeSessionID, p.node, s.NetworkAccessEpoch, s.LeaseOwner, p.scope.Actor.OwnerPublic.ID, s.BindingEpoch).Scan(&count) != nil || count != 1 {
		return nil, ErrHubAccountRejected
	}
	var accessEnd, nativeEnd string
	if tx.QueryRow(`SELECT a.lease_expires_at,b.lease_expires_at FROM network_access_sessions_v2 a JOIN session_bindings b ON b.id=? WHERE a.id=?`, s.BindingID, s.NetworkAccessBindingID).Scan(&accessEnd, &nativeEnd) != nil {
		return nil, ErrHubAccountRejected
	}
	ceiling, ce := time.Parse(time.RFC3339Nano, p.peerExpires)
	for _, stamp := range []string{accessEnd, nativeEnd} {
		end, e := time.Parse(time.RFC3339Nano, stamp)
		if ce != nil || e != nil || !at.Before(end) || end.After(ceiling) {
			return nil, ErrHubAccountRejected
		}
	}
	if s.NetworkAccessEpoch != 1 || s.BindingEpoch != 1 {
		return nil, ErrHubAccountRejected
	}
	return s, nil
}

func nativePairResourcesTx(tx *sql.Tx, p *hubNativePair) (uint64, uint64, uint64, error) {
	var n, g, r uint64
	err := tx.QueryRow(`SELECT n.version,g.version,g.revision FROM networks_v2 n JOIN groups g ON g.network_id=n.id WHERE n.id=? AND n.hub_id=? AND n.owner_id=? AND n.state='ACTIVE' AND g.id=? AND g.owner_principal_id=? AND g.state='ACTIVE' AND g.context_policy='group_scoped'`, p.network, p.hub, p.owner, p.group, p.owner).Scan(&n, &g, &r)
	return n, g, r, err
}

func nativePairProjectedManifestTx(tx *sql.Tx, p *hubNativePair, s wire.NativePairSlot, issued string, at time.Time) (wire.NativePairGroupKeyManifest, error) {
	var m wire.NativePairGroupKeyManifest
	old, err := readGroupEndpointKeyGrantManifest(tx, p.owner, p.group, s.EndpointID, p.scope.Actor.OwnerPublic.ID, issued, p.peerExpires, at)
	if err != nil {
		return m, err
	}
	raw, err := json.Marshal(old)
	if err != nil {
		return m, err
	}
	if err = json.Unmarshal(raw, &m); err != nil {
		return m, err
	}
	m.MembershipRevision++
	m.CandidateBindingDigest, err = wire.NativePairGroupBindingDigest(m)
	if err != nil {
		return m, err
	}
	m.Digest, err = wire.NativePairGroupManifestDigest(m)
	return m, err
}

func nativePairRequireZeroTx(tx *sql.Tx, p *hubNativePair, s wire.NativePairSlot) error {
	var grants, auth string
	var count int
	if tx.QueryRow(`SELECT grants_json,authorization_json FROM memberships WHERE group_id=? AND principal_id=? AND status='active' AND revision=? AND role='member' AND expires_at=?`, p.group, s.PrincipalID, s.MembershipRevision, p.peerExpires).Scan(&grants, &auth) != nil || grants != "[]" {
		return ErrHubAccountRejected
	}
	// Zero membership has no key grants, extra peers, or inherited roles. Network
	// remains undiscoverable with no grants even after pair activation.
	if tx.QueryRow(`SELECT count(*) FROM network_memberships_v2 n JOIN endpoint_network_memberships_v2 e ON e.network_id=n.network_id WHERE n.network_id=? AND n.principal_id=? AND n.status='active' AND n.grants_json='[]' AND n.revision=? AND e.endpoint_id=? AND e.status='active' AND e.revision=? AND e.discoverable=0`, p.network, s.PrincipalID, s.NetworkMembershipRevision, s.EndpointID, s.EndpointNetworkRevision).Scan(&count) != nil || count != 1 {
		return ErrHubAccountRejected
	}
	if tx.QueryRow(`SELECT count(*) FROM group_endpoint_key_grants_v2 WHERE group_id=? AND endpoint_id=?`, p.group, s.EndpointID).Scan(&count) != nil || count != 0 {
		return ErrHubAccountRejected
	}
	member, err := scanMembership(tx.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE group_id=? AND principal_id=?`, p.group, s.PrincipalID))
	if err != nil || !reflect.DeepEqual(member.Roles, []string{"member"}) || len(member.Authorization) != 0 {
		return ErrHubAccountRejected
	}
	return nil
}

func nativePairConsentPrepareTx(tx *sql.Tx, a *hubAppNodeActor, claims e2ee.OwnerNativePairClaims, c wire.NativePairRequestContext, digest string, at time.Time) (any, error) {
	p, err := nativePairOwned(tx, a, claims.Consent.PairID, at)
	if err != nil || p.state != wire.NativePairWaitingConsent || p.revision != claims.Consent.ExpectedRevision || !nativePairStableScope(p.scope, claims.Scope) {
		return nil, ErrHubAccountRejected
	}
	sa, err := nativePairLiveSlotTx(tx, p, "A", at)
	if err != nil {
		return nil, err
	}
	sb, err := nativePairLiveSlotTx(tx, p, "B", at)
	if err != nil {
		return nil, err
	}
	ad, _ := wire.NativePairSlotDigest(*sa)
	bd, _ := wire.NativePairSlotDigest(*sb)
	if ad != claims.Consent.SlotADigest || bd != claims.Consent.SlotBDigest || claims.Consent.PeerExpiresAt != p.peerExpires {
		return nil, ErrHubAccountRejected
	}
	for _, s := range []wire.NativePairSlot{*sa, *sb} {
		if err = nativePairRequireZeroTx(tx, p, s); err != nil {
			return nil, err
		}
	}
	n, g, r, err := nativePairResourcesTx(tx, p)
	if err != nil {
		return nil, err
	}
	id, err := wire.NewRequestID()
	if err != nil {
		return nil, err
	}
	end := at.Add(5 * time.Minute)
	for _, stamp := range []string{p.peerExpires, claims.Scope.Actor.AccountSessionExpiresAt} {
		bound, e := time.Parse(time.RFC3339Nano, stamp)
		if e != nil {
			return nil, ErrHubAccountRejected
		}
		if bound.Before(end) {
			end = bound
		}
	}
	plan := wire.NativePairConsentPlan{Format: wire.NativePairFormat, PairID: p.id, ExpectedRevision: p.revision, PlanID: id, Scope: claims.Scope, BootstrapProofDigest: wire.NativePairProofDigest(p.bootstrapProof), NetworkID: p.network, NetworkVersion: n, GroupID: p.group, GroupVersion: g, GroupRevision: r, SlotA: *sa, SlotB: *sb, ProjectedSlotAMembership: sa.MembershipRevision + 1, ProjectedSlotBMembership: sb.MembershipRevision + 1, GroupGrants: wire.NativePairGroupGrants(), Policy: e2ee.NativePairFixedPeerPolicy(), PreparedAt: appNodeStamp(at), ExpiresAt: appNodeStamp(end), PeerExpiresAt: p.peerExpires}
	plan.SlotAKeyManifest, err = nativePairProjectedManifestTx(tx, p, *sa, plan.PreparedAt, at)
	if err != nil {
		return nil, err
	}
	plan.SlotBKeyManifest, err = nativePairProjectedManifestTx(tx, p, *sb, plan.PreparedAt, at)
	if err != nil {
		return nil, err
	}
	plan.Digest, err = wire.NativePairPlanDigest(plan)
	if err != nil || wire.ValidateNativePairPlanForConsent(plan, p.accountHub, at) != nil {
		return nil, ErrHubAccountRejected
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`UPDATE hub_native_pair_plans_v1 SET state='INVALIDATED' WHERE pair_id=? AND state='PREPARED'`, p.id); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`INSERT INTO hub_native_pair_plans_v1(plan_id,pair_id,plan_json,state,created_at) VALUES(?,?,?,'PREPARED',?)`, id, p.id, string(raw), plan.PreparedAt); err != nil {
		return nil, err
	}
	res, err := tx.Exec(`UPDATE hub_native_pairs_v1 SET plan_id=? WHERE pair_id=? AND control_revision=? AND state='WAITING_CONSENT'`, id, p.id, p.revision)
	if err = nativePairOneRow(res, err); err != nil {
		return nil, err
	}
	return wire.NativePairPlanChallenge{Format: wire.NativePairFormat, RequestID: c.RequestID, RequestPacketDigest: digest, Plan: plan, ObservedAt: appNodeStamp(at)}, nil
}

func nativePairOneRow(r sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrHubAccountRejected
	}
	return nil
}

func nativePairReadPlanTx(tx *sql.Tx, p *hubNativePair, state string) (wire.NativePairConsentPlan, error) {
	var plan wire.NativePairConsentPlan
	var raw string
	if tx.QueryRow(`SELECT plan_json FROM hub_native_pair_plans_v1 WHERE plan_id=? AND pair_id=? AND state=?`, p.planID, p.id, state).Scan(&raw) != nil || json.Unmarshal([]byte(raw), &plan) != nil || wire.ValidateNativePairPlan(plan, p.accountHub) != nil || plan.PairID != p.id || plan.PlanID != p.planID || plan.GroupID != p.group || plan.NetworkID != p.network || !nativePairStableScope(plan.Scope, p.scope) {
		return plan, ErrHubAccountRejected
	}
	return plan, nil
}

func nativePairPlanCurrentTx(tx *sql.Tx, p *hubNativePair, plan wire.NativePairConsentPlan, active bool, at time.Time) (*wire.NativePairSlot, *wire.NativePairSlot, error) {
	n, g, r, err := nativePairResourcesTx(tx, p)
	if err != nil || n != plan.NetworkVersion || g != plan.GroupVersion || r != plan.GroupRevision || (active && p.revision != plan.ExpectedRevision+1) || (!active && p.revision != plan.ExpectedRevision) {
		return nil, nil, ErrHubAccountRejected
	}
	actual := make([]*wire.NativePairSlot, 2)
	for i, wanted := range []wire.NativePairSlot{plan.SlotA, plan.SlotB} {
		actual[i], err = nativePairLiveSlotTx(tx, p, wanted.Slot, at)
		if err != nil {
			return nil, nil, err
		}
		comparison := *actual[i]
		if active {
			if comparison.MembershipRevision != wanted.MembershipRevision+1 {
				return nil, nil, ErrHubAccountRejected
			}
			comparison.MembershipRevision = wanted.MembershipRevision
		}
		if !reflect.DeepEqual(comparison, wanted) {
			return nil, nil, ErrHubAccountRejected
		}
		if !active {
			if err = nativePairRequireZeroTx(tx, p, *actual[i]); err != nil {
				return nil, nil, err
			}
		}
	}
	return actual[0], actual[1], nil
}

func nativePairConsentCompleteTx(tx *sql.Tx, a *hubAppNodeActor, claims e2ee.OwnerNativePairClaims, proof, groupProof []byte, c wire.NativePairRequestContext, digest string, at time.Time) (any, error) {
	p, err := nativePairOwned(tx, a, claims.Consent.PairID, at)
	if err != nil || p.state != wire.NativePairWaitingConsent || p.planID != claims.Consent.PlanID {
		return nil, ErrHubAccountRejected
	}
	plan, err := nativePairReadPlanTx(tx, p, "PREPARED")
	if err != nil || wire.ValidateNativePairPlanForConsent(plan, p.accountHub, at) != nil || wire.ValidateNativePairConsentTarget(claims, plan) != nil {
		return nil, ErrHubAccountRejected
	}
	if _, _, err = nativePairPlanCurrentTx(tx, p, plan, false, at); err != nil {
		return nil, err
	}
	m := plan.SlotAKeyManifest
	if claims.Consent.Slot == "B" {
		m = plan.SlotBKeyManifest
	}
	if len(groupProof) == 0 || len(groupProof) > 16*1024 {
		return nil, ErrHubAccountRejected
	}
	verified, err := e2ee.VerifyOwnerLinkKeyGrant(groupProof, a.scope.OwnerPublic, p.owner, GroupEndpointKeyGrantOperation, m.Digest, m.CandidateBindingDigest, uint64(m.CandidateVersion), e2ee.OwnerLinkGrantSideSource, at)
	if err != nil || verified.IssuedAt != plan.PreparedAt || verified.ExpiresAt != p.peerExpires {
		return nil, ErrHubAccountRejected
	}
	var oldProof, oldGroup []byte
	err = tx.QueryRow(`SELECT owner_proof,group_key_proof FROM hub_native_pair_consents_v1 WHERE plan_id=? AND slot=?`, p.planID, claims.Consent.Slot).Scan(&oldProof, &oldGroup)
	if err == nil {
		if !bytes.Equal(oldProof, proof) || !bytes.Equal(oldGroup, groupProof) {
			return nil, ErrHubAccountRejected
		}
	} else if err == sql.ErrNoRows {
		if _, err = tx.Exec(`INSERT INTO hub_native_pair_consents_v1(plan_id,slot,owner_proof,group_key_proof,created_at) VALUES(?,?,?,?,?)`, p.planID, claims.Consent.Slot, proof, groupProof, appNodeStamp(at)); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM hub_native_pair_consents_v1 WHERE plan_id=?`, p.planID).Scan(&count); err != nil {
		return nil, err
	}
	if count == 2 {
		for _, s := range []wire.NativePairSlot{plan.SlotA, plan.SlotB} {
			var consent, key []byte
			if tx.QueryRow(`SELECT owner_proof,group_key_proof FROM hub_native_pair_consents_v1 WHERE plan_id=? AND slot=?`, p.planID, s.Slot).Scan(&consent, &key) != nil {
				return nil, ErrHubAccountRejected
			}
			// Historical first consent remains valid until the Plan expires, even if its
			// individual short proof window has elapsed. Current source is checked above.
			prior, e := e2ee.VerifyOwnerNativePair(a.scope.OwnerPublic, consent, e2ee.OwnerNativePairSlotConsent, time.Time{})
			if e != nil || wire.ValidateNativePairConsentTarget(prior, plan) != nil || prior.Consent.Slot != s.Slot {
				return nil, ErrHubAccountRejected
			}
			grants, _ := json.Marshal(wire.NativePairGroupGrants())
			res, e := tx.Exec(`UPDATE memberships SET grants_json=?,revision=revision+1,version=version+1,updated_at=? WHERE group_id=? AND principal_id=? AND status='active' AND grants_json='[]' AND revision=?`, string(grants), appNodeStamp(at), p.group, s.PrincipalID, s.MembershipRevision)
			if e = nativePairOneRow(res, e); e != nil {
				return nil, e
			}
			accepted, e := acceptGroupEndpointKeyGrantTx(tx, p.owner, p.group, s.EndpointID, a.scope.OwnerPublic.ID, key, at)
			wanted := plan.SlotAKeyManifest
			if s.Slot == "B" {
				wanted = plan.SlotBKeyManifest
			}
			if e != nil || accepted.Manifest.Digest != wanted.Digest {
				return nil, ErrHubAccountRejected
			}
		}
		res, e := tx.Exec(`UPDATE hub_native_pair_slots_v1 SET state='ACTIVE' WHERE pair_id=? AND state='JOINED_ZERO'`, p.id)
		if e != nil {
			return nil, e
		}
		if n, e := res.RowsAffected(); e != nil || n != 2 {
			return nil, ErrHubAccountRejected
		}
		res, e = tx.Exec(`UPDATE hub_native_pair_plans_v1 SET state='ACTIVE' WHERE plan_id=? AND state='PREPARED'`, p.planID)
		if e = nativePairOneRow(res, e); e != nil {
			return nil, e
		}
		res, e = tx.Exec(`UPDATE hub_native_pairs_v1 SET state='ACTIVE',control_revision=control_revision+1 WHERE pair_id=? AND state='WAITING_CONSENT' AND control_revision=? AND plan_id=?`, p.id, p.revision, p.planID)
		if e = nativePairOneRow(res, e); e != nil {
			return nil, e
		}
		p.state = wire.NativePairActive
		p.revision++
		if err = nativePairActivationPreflightTx(tx, p, at); err != nil {
			return nil, err
		}
	}
	return nativePairResultTx(tx, p, c, wire.OperationNativePairConsentComplete, digest, "COMPLETED", "", true, at)
}
