package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// Missing current schema must never turn an Owner-controlled Endpoint back
// into a legacy actor. Pre-migration disposable fixtures retain their profile.
func endpointGroupsSchemaPresent(q nativePairReader) (bool, error) {
	var count int
	if err := q.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='hub_endpoint_groups_registrations_v1'`).Scan(&count); err != nil {
		return false, err
	}
	if count != 0 {
		return true, nil
	}
	if err := q.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations_v2'`).Scan(&count); err != nil || count == 0 {
		return false, err
	}
	var high int
	if err := q.QueryRow(`SELECT coalesce(max(version),0) FROM schema_migrations_v2 WHERE state='applied'`).Scan(&high); err != nil {
		return false, err
	}
	if high >= 69 {
		return false, ErrNetworkPermission
	}
	return false, nil
}

func endpointGroupsManagedTx(tx *sql.Tx, endpoint string) (*hubEndpointGroupsRegistration, error) {
	yes, err := endpointGroupsSchemaPresent(tx)
	if err != nil || !yes {
		return nil, err
	}
	return endpointGroupsRegistrationTx(tx, endpoint)
}

func endpointGroupsRegistrationLeaseTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, at time.Time) error {
	if endpointGroupsRegistrationCurrentTx(tx, r, at) != nil {
		return ErrNetworkPermission
	}
	var nativeEnd, accessEnd, nmExpiry string
	var nmRevision, enRevision uint64
	a := r.anchor
	err := tx.QueryRow(`SELECT b.lease_expires_at,a.lease_expires_at,nm.expires_at,nm.revision,en.revision FROM session_bindings b JOIN network_access_sessions_v2 a ON a.id=? AND a.endpoint_id=b.endpoint_id AND a.principal_id=b.principal_id AND a.node_id=b.node_id AND a.native_session_id=b.native_session_id AND a.credential_hash=b.credential_hash AND a.lease_owner=b.lease_owner AND a.epoch=? AND a.status='active' JOIN network_memberships_v2 nm ON nm.network_id=? AND nm.principal_id=b.principal_id AND nm.status='active' JOIN endpoint_network_memberships_v2 en ON en.network_id=nm.network_id AND en.endpoint_id=b.endpoint_id AND en.status='active' WHERE b.id=? AND b.endpoint_id=? AND b.epoch=? AND b.lease_owner=? AND b.status IN('active','leased','online','ready','acquired')`, a.NetworkAccessBindingID, a.NetworkAccessEpoch, a.NetworkID, a.BindingID, a.Registration.EndpointID, a.BindingEpoch, a.LeaseOwner).Scan(&nativeEnd, &accessEnd, &nmExpiry, &nmRevision, &enRevision)
	if err != nil || nmRevision != a.NetworkMembershipRevision || enRevision != a.EndpointNetworkRevision || !appNodeBefore(at, nativeEnd) || !appNodeBefore(at, accessEnd) {
		return ErrNetworkPermission
	}
	if !networkExpiryAllows(nmExpiry, at) {
		p, e := readLocalDomain(tx, r.originPolicy)
		if e != nil || p == nil || p.policy.ExpiresAt != nmExpiry {
			return ErrNetworkPermission
		}
	}
	return nil
}

// Every action is capped at the selected Endpoint source. Shared Principal
// grants cannot supply an additional role or borrow another Group's source.
func endpointGroupsGuardTx(tx *sql.Tx, endpoint, group, action string, at time.Time) (bool, error) {
	r, err := endpointGroupsManagedTx(tx, endpoint)
	if err != nil || r == nil {
		return r != nil, err
	}
	if action != "" {
		allowed := false
		for _, v := range e2ee.EndpointGroupRights() {
			if action == v {
				allowed = true
			}
		}
		if !allowed {
			return true, ErrNetworkPermission
		}
	}
	if endpointGroupsRegistrationLeaseTx(tx, r, at) != nil {
		return true, ErrNetworkPermission
	}
	_, authority, _, err := endpointGroupsResolveTx(tx, r, group, at, false)
	if err != nil || authority == nil {
		return true, ErrNetworkPermission
	}
	return true, nil
}

func (s *Store) AuthorizeEndpointGroupSource(scope NativeActorScope, action string, at time.Time) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	managed, err := endpointGroupsGuardTx(tx, scope.EndpointID, scope.GroupID, action, at)
	if err != nil || !managed {
		return managed, err
	}
	r, err := endpointGroupsRegistrationTx(tx, scope.EndpointID)
	if err != nil || r == nil {
		return true, ErrNetworkPermission
	}
	if scope.PrincipalID != r.anchor.Registration.PrincipalID || scope.NetworkID != r.anchor.NetworkID || scope.BindingID != r.anchor.BindingID || scope.BindingEpoch != r.anchor.BindingEpoch || scope.LeaseOwner != r.anchor.LeaseOwner {
		return true, ErrNetworkPermission
	}
	m, err := endpointGroupsMemberTx(tx, scope.PrincipalID, scope.GroupID)
	if err != nil || m == nil || scope.MembershipID != m.ID || scope.MembershipRevision != m.Revision {
		return true, ErrNetworkPermission
	}
	return true, nil
}

func endpointGroupsBindingTx(tx *sql.Tx, binding string) (*hubEndpointGroupsRegistration, error) {
	yes, err := endpointGroupsSchemaPresent(tx)
	if err != nil || !yes {
		return nil, err
	}
	var endpoint string
	err = tx.QueryRow(`SELECT endpoint_id FROM hub_endpoint_groups_registrations_v1 WHERE binding_id=?`, binding).Scan(&endpoint)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return endpointGroupsRegistrationTx(tx, endpoint)
}

// No legacy proof can complete or rejoin an Owner-controlled native/Group
// tuple. Pending manual contribution leaves an untouched DEFAULT source live.
func endpointGroupsDefaultAdmissionTx(tx *sql.Tx, endpoint, group string) error {
	r, err := endpointGroupsManagedTx(tx, endpoint)
	if err != nil || r == nil {
		return err
	}
	h, err := endpointGroupsHeadTx(tx, r, group)
	if err != nil || h.Mode == "OWNER" {
		return ErrNetworkPermission
	}
	row, err := endpointGroupsRelationRowTx(tx, r, group)
	if err != nil || row.defaultWithdrawn {
		return ErrNetworkPermission
	}
	return nil
}

func endpointGroupsLeaseCeilingTx(tx *sql.Tx, binding string, at time.Time) (bool, error) {
	r, err := endpointGroupsBindingTx(tx, binding)
	if err != nil || r == nil {
		return r != nil, err
	}
	return true, endpointGroupsRegistrationCurrentTx(tx, r, at)
}

// Directory targets carry their own current source. Registration liveness and
// a retained static join alone never make an expired relation discoverable.
func endpointGroupsFilterDirectoryTx(tx *sql.Tx, group string, endpoints []Endpoint, at time.Time) ([]Endpoint, error) {
	if len(endpoints) == 0 {
		return endpoints, nil
	}
	present, err := endpointGroupsSchemaPresent(tx)
	if err != nil || !present {
		return endpoints, err
	}
	marks := ""
	args := make([]any, 0, len(endpoints))
	for _, e := range endpoints {
		if marks != "" {
			marks += ","
		}
		marks += "?"
		args = append(args, e.ID)
	}
	rows, err := tx.Query(`SELECT endpoint_id FROM hub_endpoint_groups_registrations_v1 WHERE endpoint_id IN (`+marks+`)`, args...)
	if err != nil {
		return nil, err
	}
	managed := map[string]bool{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		managed[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := make([]Endpoint, 0, len(endpoints))
	for _, e := range endpoints {
		if managed[e.ID] {
			if _, err = endpointGroupsGuardTx(tx, e.ID, group, "", at); err != nil {
				if errors.Is(err, ErrNetworkPermission) {
					continue
				}
				return nil, err
			}
		}
		result = append(result, e)
	}
	return result, nil
}

func (s *Store) FilterEndpointGroupDirectory(group string, endpoints []Endpoint, at time.Time) ([]Endpoint, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return endpointGroupsFilterDirectoryTx(tx, group, endpoints, at)
}
