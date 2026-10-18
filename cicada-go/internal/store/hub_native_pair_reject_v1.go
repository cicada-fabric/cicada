package store

import (
	"database/sql"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"time"
)

func nativePairSlotRejectTx(tx *sql.Tx, a *hubAppNodeActor, claims e2ee.OwnerNativePairClaims, c wire.NativePairRequestContext, digest string, at time.Time) (any, error) {
	r := claims.Reject
	p, err := nativePairOwned(tx, a, r.PairID, at)
	if err != nil || (p.state != wire.NativePairWaitingJoin && p.state != wire.NativePairWaitingConsent) || p.revision != r.ExpectedRevision || !nativePairStableScope(p.scope, claims.Scope) {
		return nil, ErrHubAccountRejected
	}
	s, _, err := nativePairSlotTx(tx, p, r.Slot, at, false)
	if err != nil || s == nil || s.Generation != r.SlotGeneration || s.AttemptID != r.SlotAttemptID || s.Generation >= wire.MaxNativePairSlotGenerations {
		return nil, ErrHubAccountRejected
	}
	actual, err := wire.NativePairSlotDigest(*s)
	if err != nil || actual != r.SlotDigest {
		return nil, ErrHubAccountRejected
	}
	stamp := appNodeStamp(at)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE memberships SET status='revoked',revoked_at=?,revocation_reason='NATIVE_PAIR_SLOT_REJECTED',revision=revision+1,version=version+1,updated_at=? WHERE group_id=? AND principal_id=? AND status='active' AND grants_json='[]' AND revision=?`, []any{stamp, stamp, p.group, s.PrincipalID, s.MembershipRevision}},
		{`UPDATE network_memberships_v2 SET status='revoked',revision=revision+1,updated_at=? WHERE network_id=? AND principal_id=? AND status='active'`, []any{stamp, p.network, s.PrincipalID}},
		{`UPDATE network_access_sessions_v2 SET status='revoked',updated_at=? WHERE id=? AND network_id=? AND endpoint_id=? AND epoch=? AND lease_owner=? AND status='active'`, []any{stamp, s.NetworkAccessBindingID, p.network, s.EndpointID, s.NetworkAccessEpoch, s.LeaseOwner}},
		{`UPDATE session_bindings SET status='revoked',revocation_reason='NATIVE_PAIR_SLOT_REJECTED',version=version+1,updated_at=? WHERE id=? AND endpoint_id=? AND epoch=? AND lease_owner=? AND status='leased'`, []any{stamp, s.BindingID, s.EndpointID, s.BindingEpoch, s.LeaseOwner}},
		{`UPDATE hub_native_pair_slots_v1 SET state='REJECTED' WHERE pair_id=? AND slot=? AND generation=? AND state='JOINED_ZERO'`, []any{p.id, s.Slot, s.Generation}},
	} {
		result, e := tx.Exec(q.sql, q.args...)
		if e = nativePairOneRow(result, e); e != nil {
			return nil, e
		}
	}
	if _, err = tx.Exec(`UPDATE hub_native_pair_plans_v1 SET state='INVALIDATED' WHERE pair_id=? AND state='PREPARED'`, p.id); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`INSERT INTO hub_native_pair_slots_v1(pair_id,slot,generation,state,created_at) VALUES(?,?,?,'RESERVED',?)`, p.id, s.Slot, s.Generation+1, stamp); err != nil {
		return nil, err
	}
	res, err := tx.Exec(`UPDATE hub_native_pairs_v1 SET state='WAITING_JOIN',plan_id='',control_revision=control_revision+1 WHERE pair_id=? AND control_revision=? AND state IN('WAITING_JOIN','WAITING_CONSENT')`, p.id, p.revision)
	if err = nativePairOneRow(res, err); err != nil {
		return nil, err
	}
	p.state = wire.NativePairWaitingJoin
	p.planID = ""
	p.revision++
	if err = nativePairExpireTx(tx, p, at); err != nil {
		return nil, err
	}
	return nativePairResultTx(tx, p, c, wire.OperationNativePairSlotReject, digest, "COMPLETED", "", true, at)
}
