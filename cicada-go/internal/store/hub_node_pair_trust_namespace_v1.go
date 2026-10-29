package store

import (
	"database/sql"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Global anonymous budgets cover both namespaces. Dispatch only from immutable
// stored metadata, never by attempting one authority parser and then another.
func nodePairExpireAnonymousNamespace(tx *sql.Tx, id string, at time.Time) error {
	var kind string
	if err := tx.QueryRow(`SELECT authority_kind FROM hub_node_pair_trust_v1 WHERE attempt_id=? AND authorized=0`, id).Scan(&kind); err != nil {
		return err
	}
	switch kind {
	case "LEGACY_V1":
		r, err := nodePairLoad(tx, id)
		if err != nil {
			return err
		}
		if r.Approval != nil {
			return ErrNodePairTrustRejected
		}
		return nodePairExpire(tx, r, wire.NodePairTrustExpired, at)
	case "NODE_V1":
		r, err := nodePairScopedLoad(tx, id)
		if err != nil {
			return err
		}
		if r.Approval != nil {
			return ErrNodePairTrustRejected
		}
		return nodePairScopedExpire(tx, r, wire.NodePairTrustScopedExpired, at)
	default:
		return ErrNodePairTrustRejected
	}
}

func nodePairScopedOriginalClientGuardTx(tx *sql.Tx, in HubAppNodeClientInput, fence bool) error {
	var request string
	var required int
	err := tx.QueryRow(`SELECT id,require_pair_trust_ack FROM node_control_key_requests_v1 WHERE candidate_digest=?`, in.CandidateDigest).Scan(&request, &required)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if required != 1 {
		return ErrNodePairTrustRejected
	}
	var state, attempt string
	if err := tx.QueryRow(`SELECT state,attempt_id FROM hub_node_pair_trust_v1 WHERE authority_kind='NODE_V1' AND candidate_request_id=?`, request).Scan(&state, &attempt); err != nil {
		return ErrNodePairTrustRejected
	}
	if fence && state != "ACKING" {
		r, err := nodePairScopedLoad(tx, attempt)
		if err != nil {
			return err
		}
		if err := nodePairScopedRefresh(tx, HubNodePairTrustScopedInput{Hub: in.Hub, At: in.At}, r); err != nil {
			return err
		}
		state = r.State
	}
	if state == "ACKING" {
		return nil
	}
	if state == wire.NodePairTrustScopedPending || state == wire.NodePairTrustScopedOwnerApproved || !fence {
		return ErrNodePairTrustACKRequired
	}
	return nil // Authenticated original reconciliation may only seal no effect.
}
