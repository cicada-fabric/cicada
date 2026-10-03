package store

import (
	"database/sql"
	"errors"
	"time"
)

// guardNativeSelfTx checks identity and current selected Group membership without
// granting an operation on peers. Keep this separate from named action checks.
func guardNativeSelfTx(tx *sql.Tx, scope NativeActorScope, at time.Time) error {
	if err := guardNativeActorTx(tx, scope, "", at); err != nil {
		return err
	}
	var effective int
	if err := tx.QueryRow(`SELECT cicada_network_effective_allows(effective_at,?)
FROM memberships WHERE id=? AND revision=?`, at.Format(time.RFC3339Nano),
		scope.MembershipID, scope.MembershipRevision).Scan(&effective); err != nil || effective != 1 {
		return ErrNetworkPermission
	}
	return nil
}

// GetNativeSelfForActor exposes only this actor's current Endpoint and native
// binding. It needs active membership, not permission to enumerate Group peers.
func (s *Store) GetNativeSelfForActor(scope NativeActorScope) (*Endpoint, *SessionBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	if err := guardNativeSelfTx(tx, scope, time.Now().UTC()); err != nil {
		return nil, nil, err
	}
	endpoint, err := scanEndpoint(tx.QueryRow(`SELECT `+endpointColumns+
		` FROM fabric_endpoints WHERE id=?`, scope.EndpointID))
	if err != nil {
		return nil, nil, err
	}
	if err := tx.QueryRow(`SELECT principal_id,group_id,binding_id,migration_state
FROM fabric_endpoints WHERE id=?`, scope.EndpointID).Scan(&endpoint.PrincipalID,
		&endpoint.GroupID, &endpoint.BindingID, &endpoint.MigrationState); err != nil {
		return nil, nil, err
	}
	endpoint.MigrationStatus = endpoint.MigrationState
	binding, err := scanSessionBinding(tx.QueryRow(`SELECT `+sessionBindingColumns+
		` FROM session_bindings WHERE id=?`, scope.BindingID))
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return endpoint, binding, nil
}

// GetOwnEndpointKeyCandidateForActor is an exact self read. Peer candidate reads
// still require Directory authorization at Fabric's Resolve boundary.
func (s *Store) GetOwnEndpointKeyCandidateForActor(scope NativeActorScope) (*EndpointKeyCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := guardNativeSelfTx(tx, scope, time.Now().UTC()); err != nil {
		return nil, err
	}
	candidate, err := scanEndpointKeyCandidate(tx.QueryRow(`SELECT `+endpointKeyCandidateColumns+
		` FROM endpoint_key_candidates_v2 WHERE endpoint_id=? AND principal_id=?
AND binding_id=? AND binding_epoch=? AND node_id=(SELECT node_id FROM session_bindings WHERE id=?)
AND owner_id=(SELECT owner FROM fabric_endpoints WHERE id=?)`, scope.EndpointID,
		scope.PrincipalID, scope.BindingID, scope.BindingEpoch, scope.BindingID, scope.EndpointID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEndpointKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return candidate, nil
}
