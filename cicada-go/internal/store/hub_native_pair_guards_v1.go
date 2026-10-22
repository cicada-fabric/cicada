package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

type nativePairReader interface{ QueryRow(string, ...any) *sql.Row }

func nativePairScopeExists(q nativePairReader, network, group, binding string) (bool, error) {
	var exists int
	if err := q.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='hub_native_pairs_v1'`).Scan(&exists); err != nil {
		return false, err
	}
	if exists == 0 {
		// Initial schema builders can run before v64. An already-applied v64
		// database missing this critical table must fail closed instead.
		if err := q.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations_v2'`).Scan(&exists); err != nil {
			return false, err
		}
		if exists == 0 {
			return false, nil
		}
		var high int
		if err := q.QueryRow(`SELECT coalesce(max(version),0) FROM schema_migrations_v2 WHERE state='applied'`).Scan(&high); err != nil {
			return false, err
		}
		if high >= 64 {
			return false, ErrNetworkPermission
		}
		return false, nil
	}
	err := q.QueryRow(`SELECT EXISTS(SELECT 1 FROM hub_native_pairs_v1 p WHERE (? != '' AND p.network_id=?) OR (? != '' AND p.group_id=?) OR (? != '' AND EXISTS(SELECT 1 FROM hub_native_pair_slots_v1 s WHERE s.pair_id=p.pair_id AND s.binding_id=?)))`, network, network, group, group, binding, binding).Scan(&exists)
	return exists != 0, err
}
func nativePairLegacyAllowed(q nativePairReader, network, group, binding string) error {
	found, err := nativePairScopeExists(q, network, group, binding)
	if err != nil {
		return err
	}
	if found {
		return ErrNetworkPermission
	}
	domain, err := localDomainScopeExists(q, group, binding)
	if err != nil {
		return err
	}
	if domain {
		return ErrNetworkPermission
	}
	return nil
}
func (s *Store) CheckLegacyGroupEnrollment(group string) error {
	return nativePairLegacyAllowed(s.db, "", group, "")
}

// The native Session is already authenticated by the ordinary current actor
// guard. This adds its immutable pair slot and original N2/N3 coordinates in
// the same read/write snapshot, without supplying peer actions or a login.
func nativePairSelfTx(tx *sql.Tx, scope NativeActorScope, at time.Time) error {
	var pair string
	err := tx.QueryRow(`SELECT pair_id FROM hub_native_pairs_v1 WHERE group_id=?`, scope.GroupID).Scan(&pair)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	p, err := readNativePair(tx, pair)
	if err != nil || p == nil || p.accountHub.HubID == "" || !appNodeBefore(at, p.peerExpires) {
		return ErrNetworkPermission
	}
	if p.state != "WAITING_JOIN" && p.state != "WAITING_CONSENT" && p.state != "ACTIVE" {
		return ErrNetworkPermission
	}
	if p.state == "WAITING_JOIN" && !appNodeBefore(at, p.joinUntil) {
		return ErrNetworkPermission
	}
	var sid string
	err = tx.QueryRow(`SELECT native_session_id FROM hub_native_pair_slots_v1 WHERE pair_id=? AND endpoint_id=? AND principal_id=? AND binding_id=? AND lease_owner=? AND state IN('JOINED_ZERO','ACTIVE')`, p.id, scope.EndpointID, scope.PrincipalID, scope.BindingID, scope.LeaseOwner).Scan(&sid)
	if err != nil || sid == "" || scope.NetworkID != p.network {
		return ErrNetworkPermission
	}
	binding, err := getSessionBindingLeaseTx(tx, scope.BindingID)
	if err != nil || binding.NativeSessionID != sid || binding.NodeID != p.node || binding.Epoch != scope.BindingEpoch {
		return ErrNetworkPermission
	}
	digest, err := hex.DecodeString(p.scope.CredentialCommitment)
	if err != nil || len(digest) != 32 {
		return ErrNetworkPermission
	}
	route := NodeControlRPCInput{CredentialDigest: base64.RawURLEncoding.EncodeToString(digest), NodeID: p.node, BindingID: p.scope.Node.OwnerBindingID, BindingVersion: p.scope.Node.BindingVersion, NodeKeyID: p.scope.Node.NodePublic.ID, NodeKeyEpoch: p.scope.Node.NodeKeyEpoch}
	return nativePairNodeCurrentTx(tx, p, HubNativePairNodeInput{Hub: p.accountHub, NodeControlPublic: p.scope.Node.HubNodeControlPublic, At: at}, route)
}
func (s *Store) RequireHubNativePairSelf(scope NativeActorScope) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	yes, err := nativePairScopeExists(tx, "", scope.GroupID, "")
	if err != nil || !yes {
		return ErrNetworkPermission
	}
	if err = guardNativeSelfTx(tx, scope, time.Now().UTC()); err != nil {
		return err
	}
	return nil
}
