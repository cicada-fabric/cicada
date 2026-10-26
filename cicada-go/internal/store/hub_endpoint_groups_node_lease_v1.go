package store

import (
	"database/sql"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"time"
)

// Registration renewal grants no Group/business rights. A currently signed Node
// may resume its original cold native lease, retaining credential, IDs and epochs.
func endpointGroupsRenewRegistrationTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, at time.Time) error {
	if endpointGroupsRegistrationCurrentTx(tx, r, at) != nil {
		return ErrNetworkPermission
	}
	a := r.anchor
	var nativeEnd, accessEnd, credential, nmExpiry string
	var nmRevision, enRevision uint64
	err := tx.QueryRow(`SELECT b.lease_expires_at,a.lease_expires_at,b.credential_hash,nm.expires_at,nm.revision,en.revision FROM session_bindings b JOIN fabric_endpoints e ON e.binding_id=b.id AND e.id=b.endpoint_id AND e.status!='left' JOIN network_access_sessions_v2 a ON a.id=? AND a.endpoint_id=b.endpoint_id AND a.principal_id=b.principal_id AND a.node_id=b.node_id AND a.native_session_id=b.native_session_id AND a.credential_hash=b.credential_hash AND a.lease_owner=b.lease_owner AND a.epoch=? AND a.status='active' JOIN network_memberships_v2 nm ON nm.network_id=? AND nm.principal_id=b.principal_id AND nm.status='active' JOIN endpoint_network_memberships_v2 en ON en.network_id=nm.network_id AND en.endpoint_id=b.endpoint_id AND en.status='active' WHERE b.id=? AND b.endpoint_id=? AND b.principal_id=? AND b.node_id=? AND b.native_session_id=? AND b.epoch=? AND b.lease_owner=? AND b.status IN('active','leased','online','ready','acquired')`, a.NetworkAccessBindingID, a.NetworkAccessEpoch, a.NetworkID, a.BindingID, a.Registration.EndpointID, a.Registration.PrincipalID, a.Registration.NodeID, a.Registration.NativeSessionID, a.BindingEpoch, a.LeaseOwner).Scan(&nativeEnd, &accessEnd, &credential, &nmExpiry, &nmRevision, &enRevision)
	if err != nil || credential == "" || nmRevision != a.NetworkMembershipRevision || enRevision != a.EndpointNetworkRevision {
		return ErrNetworkPermission
	}
	if !networkExpiryAllows(nmExpiry, at) {
		origin, e := readLocalDomain(tx, r.originPolicy)
		if e != nil || origin == nil || nmExpiry != origin.policy.ExpiresAt {
			return ErrNetworkPermission
		}
	}
	end := at.Add(5 * time.Minute)
	for _, stamp := range []string{nativeEnd, accessEnd} {
		t, e := time.Parse(time.RFC3339Nano, stamp)
		if e != nil {
			return ErrNetworkPermission
		}
		if t.After(end) {
			end = t
		}
	}
	stamp := appNodeStamp(end)
	res, err := tx.Exec(`UPDATE network_access_sessions_v2 SET lease_expires_at=?,updated_at=? WHERE id=? AND epoch=? AND endpoint_id=? AND credential_hash=? AND lease_owner=? AND lease_expires_at=? AND status='active'`, stamp, appNodeStamp(at), a.NetworkAccessBindingID, a.NetworkAccessEpoch, a.Registration.EndpointID, credential, a.LeaseOwner, accessEnd)
	if err != nil {
		return err
	}
	if n, e := res.RowsAffected(); e != nil || n != 1 {
		return ErrNetworkPermission
	}
	res, err = tx.Exec(`UPDATE session_bindings SET lease_expires_at=?,version=version+1,updated_at=? WHERE id=? AND endpoint_id=? AND epoch=? AND credential_hash=? AND lease_owner=? AND lease_expires_at=? AND status IN('active','leased','online','ready','acquired')`, stamp, appNodeStamp(at), a.BindingID, a.Registration.EndpointID, a.BindingEpoch, credential, a.LeaseOwner, nativeEnd)
	if err != nil {
		return err
	}
	if n, e := res.RowsAffected(); e != nil || n != 1 {
		return ErrNetworkPermission
	}
	r.anchor.LeaseExpiresAt = stamp
	r.anchor.State = "REGISTERED"
	return nil
}

func endpointGroupsNodeRenewTx(tx *sql.Tx, in HubEndpointGroupsNodeInput, r *hubEndpointGroupsRegistration, q wire.EndpointGroupsNodeRenew) (any, error) {
	if q.RegistrationDigest != r.anchor.RegistrationDigest || q.ExpectedBindingID != r.anchor.BindingID || q.ExpectedBindingEpoch != r.anchor.BindingEpoch {
		return nil, ErrNetworkPermission
	}
	if err := endpointGroupsRenewRegistrationTx(tx, r, in.At); err != nil {
		return nil, err
	}
	return wire.EndpointGroupsNodeRenewResult{ContractRevision: wire.OwnerEndpointGroupsContractRevision, Registration: r.anchor, ObservedAt: appNodeStamp(in.At)}, nil
}
