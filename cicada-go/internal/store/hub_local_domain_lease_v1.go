package store

import (
	"database/sql"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func renewLocalDomainAccessLeaseTx(tx *sql.Tx, binding *SessionBinding, wanted string, at time.Time) (string, error) {
	yes, err := localDomainScopeExists(tx, "", binding.ID)
	if err != nil || !yes {
		return wanted, err
	}
	ceiling, err := localDomainBindingLeaseCeilingTx(tx, binding.ID, at)
	if err != nil {
		return "", err
	}
	var id, owner, end string
	var epoch uint64
	err = tx.QueryRow(`SELECT a.id,a.lease_owner,a.lease_expires_at,a.epoch FROM network_access_sessions_v2 a JOIN hub_local_domain_members_v1 m ON m.access_id=a.id WHERE m.binding_id=? AND m.state IN('JOINED_ZERO','ACTIVE') AND a.endpoint_id=? AND a.principal_id=? AND a.node_id=? AND a.native_session_id=? AND a.credential_hash=? AND a.status='active'`, binding.ID, binding.EndpointID, binding.PrincipalID, binding.NodeID, binding.NativeSessionID, binding.CredentialHash).Scan(&id, &owner, &end, &epoch)
	if err != nil || owner != binding.LeaseOwner || !appNodeBefore(at, end) {
		return "", ErrSessionBindingLeaseExpired
	}
	deadline, e := time.Parse(time.RFC3339Nano, wanted)
	accessEnd, ae := time.Parse(time.RFC3339Nano, end)
	nativeEnd, ne := time.Parse(time.RFC3339Nano, binding.LeaseExpiresAt)
	if e != nil || ae != nil || ne != nil {
		return "", ErrSessionBindingLeaseExpired
	}
	if accessEnd.After(deadline) {
		deadline = accessEnd
	}
	if nativeEnd.After(deadline) {
		deadline = nativeEnd
	}
	if limit := at.Add(5 * time.Minute); deadline.After(limit) {
		deadline = limit
	}
	if ceiling != "" {
		bound, ce := time.Parse(time.RFC3339Nano, ceiling)
		if ce != nil || !at.Before(bound) {
			return "", ErrSessionBindingLeaseExpired
		}
		if deadline.After(bound) {
			deadline = bound
		}
	}
	stamp := appNodeStamp(deadline)
	r, err := tx.Exec(`UPDATE network_access_sessions_v2 SET lease_expires_at=?,updated_at=? WHERE id=? AND epoch=? AND lease_owner=? AND lease_expires_at=? AND credential_hash=? AND status='active'`, stamp, appNodeStamp(at), id, epoch, owner, end, binding.CredentialHash)
	if err != nil {
		return "", err
	}
	if n, e := r.RowsAffected(); e != nil || n != 1 {
		return "", ErrSessionBindingStaleEpoch
	}
	return stamp, nil
}

// A fresh signed Node Join can resume its already-current member after a cold
// lease lapse. It retains the original writer/token/epochs and cannot revive
// terminal membership, adopt a new policy, or replace a newer binding owner.
func resumeLocalDomainMemberLeaseTx(tx *sql.Tx, p *hubLocalDomain, m wire.LocalDomainMember, at time.Time) error {
	if _, err := localDomainBindingLeaseCeilingTx(tx, m.BindingID, at); err != nil {
		return err
	}
	end := at.Add(5 * time.Minute)
	if p.policy.ExpiresAt != "" {
		expiry, e := time.Parse(time.RFC3339Nano, p.policy.ExpiresAt)
		if e != nil || !at.Before(expiry) {
			return ErrNetworkPermission
		}
		if expiry.Before(end) {
			end = expiry
		}
	}
	var nativeEnd, accessEnd, credential string
	err := tx.QueryRow(`SELECT b.lease_expires_at,a.lease_expires_at,b.credential_hash FROM session_bindings b JOIN fabric_endpoints e ON e.binding_id=b.id AND e.id=b.endpoint_id AND e.status!='left' JOIN network_access_sessions_v2 a ON a.id=? AND a.endpoint_id=b.endpoint_id AND a.principal_id=b.principal_id AND a.node_id=b.node_id AND a.native_session_id=b.native_session_id AND a.credential_hash=b.credential_hash AND a.lease_owner=b.lease_owner AND a.epoch=? AND a.status='active' WHERE b.id=? AND b.endpoint_id=? AND b.principal_id=? AND b.epoch=? AND b.lease_owner=? AND b.status IN('active','leased','online','ready','acquired')`, m.NetworkAccessBindingID, m.NetworkAccessEpoch, m.BindingID, m.EndpointID, m.PrincipalID, m.BindingEpoch, m.LeaseOwner).Scan(&nativeEnd, &accessEnd, &credential)
	if err != nil {
		return ErrNetworkPermission
	}
	for _, stamp := range []string{nativeEnd, accessEnd} {
		e, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			return ErrNetworkPermission
		}
		if e.After(end) {
			end = e
		}
	}
	if p.policy.ExpiresAt != "" {
		expiry, _ := time.Parse(time.RFC3339Nano, p.policy.ExpiresAt)
		if end.After(expiry) {
			return ErrNetworkPermission
		}
	}
	stamp := appNodeStamp(end)
	if _, err = tx.Exec(`UPDATE network_access_sessions_v2 SET lease_expires_at=?,updated_at=? WHERE id=? AND epoch=? AND credential_hash=? AND lease_owner=? AND status='active'`, stamp, appNodeStamp(at), m.NetworkAccessBindingID, m.NetworkAccessEpoch, credential, m.LeaseOwner); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE session_bindings SET lease_expires_at=?,version=version+1,updated_at=? WHERE id=? AND epoch=? AND credential_hash=? AND lease_owner=? AND status IN('active','leased','online','ready','acquired')`, stamp, appNodeStamp(at), m.BindingID, m.BindingEpoch, credential, m.LeaseOwner); err != nil {
		return err
	}
	return nil
}
