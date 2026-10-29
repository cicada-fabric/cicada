package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// An INITIAL cannot reset another namespace's history for the same actual
// Node. Same-namespace pre-provenance expiry/session-end/self-cancel continues
// through the existing head/state checks; it is not a permanent first-failure
// lock. Confirmed or irreversibly revoked history always remains a fence.
func appNodeInitialNamespaceAllowed(tx *sql.Tx, owner, device, node, kind string) (bool, error) {
	var blocked int
	err := tx.QueryRow(`SELECT count(*) FROM hub_app_node_grants_v1 WHERE owner_id=? AND coalesce(json_extract(claims_json,'$.candidate.node_id'),json_extract(claims_json,'$.binding.node_id'),'')=? AND (provenance_id!='' OR state='REVOKED' OR authority_kind!=? OR device_id!=?)`, owner, node, kind, device).Scan(&blocked)
	return blocked == 0, err
}

// The original Node selected its explicit NPT version before the App saw the
// code. An App proof cannot transplant a candidate between those versions.
func appNodeCandidateNamespaceAllowed(tx *sql.Tx, c *e2ee.OwnerAppNodeCandidate, kind string) (bool, error) {
	var required int
	if err := tx.QueryRow(`SELECT require_pair_trust_ack FROM node_control_key_requests_v1 WHERE id=? AND node_id=?`, c.RequestID, c.NodeID).Scan(&required); err != nil {
		return false, err
	}
	var actual string
	err := tx.QueryRow(`SELECT authority_kind FROM hub_node_pair_trust_v1 WHERE candidate_request_id=? AND node_id=?`, c.RequestID, c.NodeID).Scan(&actual)
	if required == 0 && errors.Is(err, sql.ErrNoRows) {
		return kind == "LEGACY_V1", nil
	}
	if err != nil {
		return false, err
	}
	return required == 1 && actual == kind, nil
}

// Release only logically expired scoped proposals; do not let another route
// revive them or decode Scope2 as v1. Both families use the original App actor.
func appNodeScopedRefreshAll(tx *sql.Tx, a *hubAppNodeActor, at time.Time) error {
	rows, err := tx.Query(`SELECT DISTINCT authority_node_id FROM hub_app_node_grants_v1 WHERE authority_kind='NODE_V1' AND owner_id=? AND device_id=? AND state IN('PREPARED','ACTIVE')`, a.scope.OwnerID, a.scope.DeviceID)
	if err != nil {
		return err
	}
	var nodes []string
	for rows.Next() {
		var node string
		if err = rows.Scan(&node); err != nil {
			break
		}
		nodes = append(nodes, node)
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if re != nil {
		return re
	}
	for _, node := range nodes {
		if err := appNodeScopedRefresh(tx, appNodeScopedActorFromBase(a, node), at); err != nil {
			return err
		}
	}
	return nil
}
