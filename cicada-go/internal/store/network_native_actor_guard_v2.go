package store

import (
	"database/sql"
	"time"
)

// NativeActorScope is the native SessionBinding and Group membership already
// authenticated by Fabric. Store repeats the current checks in the transaction
// that exposes a scoped read or changes an operation's state.
type NativeActorScope struct {
	PrincipalID        string
	EndpointID         string
	GroupID            string
	NetworkID          string
	MembershipID       string
	MembershipRevision int64
	BindingID          string
	BindingEpoch       uint64
	LeaseOwner         string
}

func guardNativeActorTx(tx *sql.Tx, scope NativeActorScope, action string, at time.Time) error {
	if scope.PrincipalID == "" || scope.EndpointID == "" || scope.GroupID == "" ||
		scope.MembershipID == "" || scope.MembershipRevision <= 0 ||
		scope.BindingID == "" || scope.BindingEpoch == 0 || scope.LeaseOwner == "" {
		return ErrNetworkPermission
	}
	var bindingStatus, leaseExpiry, memberExpiry, mappedNetwork, ownerID, nodeID string
	query := `SELECT b.status,b.lease_expires_at,m.expires_at,g.network_id,e.owner,e.machine_id
FROM session_bindings b
JOIN fabric_endpoints e ON e.id=b.endpoint_id AND e.principal_id=b.principal_id
  AND e.binding_id=b.id AND e.native_session_id=b.native_session_id
  AND e.machine_id=b.node_id AND e.migration_state='READY' AND e.status!='left'
JOIN principals p ON p.id=e.principal_id AND p.owner_id=e.owner AND p.status='active'
JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=? AND eg.status='active'
JOIN memberships m ON m.group_id=eg.group_id AND m.principal_id=p.id AND m.status='active'
JOIN groups g ON g.id=m.group_id AND g.state='ACTIVE'
WHERE b.id=? AND b.endpoint_id=? AND b.principal_id=? AND b.epoch=?
  AND b.lease_owner=? AND m.id=? AND m.revision=?`
	args := []any{scope.GroupID, scope.BindingID, scope.EndpointID, scope.PrincipalID,
		scope.BindingEpoch, scope.LeaseOwner, scope.MembershipID, scope.MembershipRevision}
	if action != "" {
		query += ` AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value IN ('*',?))`
		args = append(args, action)
	}
	if err := tx.QueryRow(query, args...).Scan(&bindingStatus, &leaseExpiry, &memberExpiry, &mappedNetwork, &ownerID, &nodeID); err != nil {
		return ErrNetworkPermission
	}
	if !isActiveBindingStatus(bindingStatus) || mappedNetwork != scope.NetworkID {
		return ErrNetworkPermission
	}
	leaseDeadline, err := time.Parse(time.RFC3339Nano, leaseExpiry)
	if err != nil || !leaseDeadline.After(at) {
		return ErrNetworkPermission
	}
	if memberExpiry != "" {
		memberDeadline, err := time.Parse(time.RFC3339Nano, memberExpiry)
		if err != nil || !memberDeadline.After(at) {
			return ErrNetworkPermission
		}
	}
	if err := networkGuardGroupEndpointTx(tx, scope.PrincipalID, scope.EndpointID, scope.GroupID, at); err != nil {
		return err
	}
	if mappedNetwork != "" {
		var hubID string
		if err := tx.QueryRow(`SELECT hub_id FROM networks_v2 WHERE id=? AND state='ACTIVE'`, mappedNetwork).Scan(&hubID); err != nil {
			return ErrNetworkPermission
		}
		if err := requireCurrentOwnerBoundGroupNodeTx(tx, nodeID, ownerID, hubID); err != nil {
			return ErrNetworkPermission
		}
	}
	return nil
}
