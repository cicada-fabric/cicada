package store

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nativePairPrepareTx(tx *sql.Tx, a *hubAppNodeActor, scope e2ee.OwnerNativePairScope, claims e2ee.OwnerNativePairClaims, c wire.NativePairRequestContext, digest string, at time.Time, hub wire.HubIdentity) (any, string, error) {
	rows, err := tx.Query(`SELECT pair_id FROM hub_native_pairs_v1 WHERE owner_id=? AND hub_id=? AND node_id=? AND state IN('PREPARED','WAITING_JOIN','WAITING_CONSENT','ACTIVE')`, a.scope.OwnerID, a.scope.HubID, scope.Node.NodeID)
	if err != nil {
		return nil, "", err
	}
	var previous []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		previous = append(previous, id)
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	if re != nil {
		return nil, "", re
	}
	for _, id := range previous {
		p, err := readNativePair(tx, id)
		if err != nil {
			return nil, "", err
		}
		if err = nativePairExpireTx(tx, p, at); err != nil {
			return nil, "", err
		}
		if p.state != wire.NativePairExpired && p.state != wire.NativePairRevoked {
			return nil, "", ErrHubAccountRejected
		}
	}
	id, err := wire.NewRequestID()
	if err != nil {
		return nil, "", err
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		return nil, "", err
	}
	b := *claims.Bootstrap
	b.PairID = id
	b.NetworkID = NewID("net")
	b.GroupID = NewID("grp")
	b.PreparedAt = appNodeStamp(at)
	b.JoinUntil = appNodeStamp(at.Add(10 * time.Minute))
	b.PeerExpiresAt = appNodeStamp(at.Add(time.Hour))
	b.PrepareRequestID = c.RequestID
	b.PreparePacketDigest = digest
	b.ServerNonce = nativePairProofNonce(nonce)
	end := at.Add(5 * time.Minute)
	sessionEnd, _ := time.Parse(time.RFC3339Nano, scope.Actor.AccountSessionExpiresAt)
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	challenge := wire.NativePairBootstrapChallenge{Format: wire.NativePairFormat, RequestID: c.RequestID, RequestPacketDigest: digest, Scope: scope, Bootstrap: b, ProofExpiresAt: appNodeStamp(end), ObservedAt: appNodeStamp(at)}
	// The complete target is validated now, before reserving any permanent ID.
	// The App separately compares the known local preview before human signing.
	probe := e2ee.OwnerNativePairClaims{Version: 1, Purpose: e2ee.OwnerNativePairBootstrapCommit, Scope: scope, RequestID: id, Nonce: b.ServerNonce, IssuedAt: appNodeStamp(at), ExpiresAt: challenge.ProofExpiresAt, Bootstrap: &b}
	if e2ee.ValidateOwnerNativePairClaims(probe, at) != nil {
		return nil, "", ErrHubAccountRejected
	}
	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		return nil, "", err
	}
	bootstrapJSON, err := json.Marshal(b)
	if err != nil {
		return nil, "", err
	}
	hubJSON, err := json.Marshal(hub)
	if err != nil {
		return nil, "", err
	}
	_, err = tx.Exec(`INSERT INTO hub_native_pairs_v1(pair_id,hub_id,account_id,owner_id,device_id,node_id,network_id,group_id,scope_json,bootstrap_json,state,control_revision,prepare_operation_id,proof_expires_at,join_until,peer_expires_at,created_at,account_hub_identity_json) VALUES(?,?,?,?,?,?,?,?,?,?,'PREPARED',1,?,?,?,?,?,?)`, id, a.scope.HubID, a.scope.AccountID, a.scope.OwnerID, a.scope.DeviceID, scope.Node.NodeID, b.NetworkID, b.GroupID, string(scopeJSON), string(bootstrapJSON), c.RequestID, challenge.ProofExpiresAt, b.JoinUntil, b.PeerExpiresAt, b.PreparedAt, string(hubJSON))
	return challenge, id, err
}

func nativePairCompleteTx(tx *sql.Tx, a *hubAppNodeActor, claims e2ee.OwnerNativePairClaims, proof []byte, c wire.NativePairRequestContext, digest string, at time.Time) (any, error) {
	p, err := nativePairOwned(tx, a, claims.Bootstrap.PairID, at)
	if err != nil {
		return nil, err
	}
	if p.state != wire.NativePairPrepared || p.revision != 1 || !appNodeBefore(at, p.proofExpires) || !reflect.DeepEqual(claims.Scope, p.scope) || !reflect.DeepEqual(*claims.Bootstrap, p.bootstrap) {
		return nil, ErrHubAccountRejected
	}
	var trust string
	if tx.QueryRow(`SELECT trust_domain_id FROM principals WHERE id=? AND owner_id=id AND kind='human' AND status='active'`, p.owner).Scan(&trust) != nil || trust == "" {
		return nil, ErrHubAccountRejected
	}
	if _, err = createNetworkTx(tx, Network{ID: p.network, HubID: p.hub, OwnerID: p.owner, Name: p.bootstrap.GroupLabel, State: NetworkStateActive}, at); err != nil {
		return nil, err
	}
	if _, err = insertGroupWithOwnerMembershipTx(tx, Group{ID: p.group, NetworkID: p.network, OwnerPrincipalID: p.owner, TrustDomainID: trust, Name: p.bootstrap.GroupLabel, State: GroupStateActive, ContextPolicy: "group_scoped", Purpose: "Explicit bounded native Thread pair", Revision: 1, Version: 1}, at, p.peerExpires); err != nil {
		return nil, err
	}
	for _, letter := range []string{"A", "B"} {
		if _, err = tx.Exec(`INSERT INTO hub_native_pair_slots_v1(pair_id,slot,generation,state,created_at) VALUES(?,?,1,'RESERVED',?)`, p.id, letter, appNodeStamp(at)); err != nil {
			return nil, err
		}
	}
	result, err := tx.Exec(`UPDATE hub_native_pairs_v1 SET state='WAITING_JOIN',control_revision=2,bootstrap_owner_proof=? WHERE pair_id=? AND state='PREPARED' AND control_revision=1 AND bootstrap_owner_proof IS NULL`, proof, p.id)
	if err != nil {
		return nil, err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return nil, ErrHubAccountRejected
	}
	p.state = wire.NativePairWaitingJoin
	p.revision = 2
	p.bootstrapProof = append([]byte(nil), proof...)
	return nativePairResultTx(tx, p, c, wire.OperationNativePairBootstrapComplete, digest, "COMPLETED", "", true, at)
}

func nativePairRevokeTx(tx *sql.Tx, a *hubAppNodeActor, claims e2ee.OwnerNativePairClaims, c wire.NativePairRequestContext, digest string, at time.Time) (any, error) {
	if wire.ValidateNativePairRevokeTarget(claims) != nil {
		return nil, ErrHubAccountRejected
	}
	p, err := nativePairOwned(tx, a, claims.Revoke.PairID, at)
	if err != nil {
		return nil, err
	}
	if p.revision != claims.Revoke.ExpectedRevision {
		return nil, ErrHubAccountRejected
	}
	if p.state != wire.NativePairRevoked && p.state != wire.NativePairExpired {
		if _, err = tx.Exec(`UPDATE memberships SET status='revoked',revoked_at=?,revocation_reason='NATIVE_PAIR_REVOKED',revision=revision+1,version=version+1,updated_at=? WHERE group_id=? AND principal_id IN(SELECT principal_id FROM hub_native_pair_slots_v1 WHERE pair_id=? AND principal_id!='') AND status='active'`, appNodeStamp(at), appNodeStamp(at), p.group, p.id); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`UPDATE network_memberships_v2 SET status='revoked',revision=revision+1,updated_at=? WHERE network_id=? AND principal_id IN(SELECT principal_id FROM hub_native_pair_slots_v1 WHERE pair_id=? AND principal_id!='') AND status='active'`, appNodeStamp(at), p.network, p.id); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`UPDATE network_access_sessions_v2 SET status='revoked',updated_at=? WHERE network_id=? AND endpoint_id IN(SELECT endpoint_id FROM hub_native_pair_slots_v1 WHERE pair_id=? AND endpoint_id!='')`, appNodeStamp(at), p.network, p.id); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`UPDATE session_bindings SET status='revoked',revocation_reason='NATIVE_PAIR_REVOKED',version=version+1,updated_at=? WHERE id IN(SELECT binding_id FROM hub_native_pair_slots_v1 WHERE pair_id=? AND binding_id!='')`, appNodeStamp(at), p.id); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`UPDATE hub_native_pair_plans_v1 SET state='INVALIDATED' WHERE pair_id=? AND state='PREPARED'`, p.id); err != nil {
			return nil, err
		}
		result, err := tx.Exec(`UPDATE hub_native_pairs_v1 SET state='REVOKED',control_revision=control_revision+1,terminal_reason='OWNER_REVOKED' WHERE pair_id=? AND control_revision=?`, p.id, p.revision)
		if err != nil {
			return nil, err
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return nil, ErrHubAccountRejected
		}
		p.state = wire.NativePairRevoked
		p.revision++
	}
	return nativePairResultTx(tx, p, c, wire.OperationNativePairRevoke, digest, "COMPLETED", "", false, at)
}
