package store

import (
	"database/sql"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"time"
)

// Self identity and attestation are required before a classification anchor can
// exist. This exact zero member admits no directory, relay or Group action.
func threadCollaborationZeroSelfTx(tx *sql.Tx, scope NativeActorScope, at time.Time) (bool, error) {
	p, err := localDomainForGroupTx(tx, scope.GroupID)
	if err != nil || p == nil {
		return false, err
	}
	m, err := localDomainEndpointCurrentTx(tx, p, scope.EndpointID, at)
	if err != nil {
		return false, err
	}
	if m.member.State != wire.LocalDomainMemberJoinedZero {
		return false, nil
	}
	var membership string
	if tx.QueryRow(`SELECT id FROM memberships WHERE group_id=? AND principal_id=? AND revision=? AND status='active' AND grants_json='[]'`, scope.GroupID, scope.PrincipalID, scope.MembershipRevision).Scan(&membership) != nil || membership != scope.MembershipID || scope.PrincipalID != m.member.PrincipalID || scope.NetworkID != p.policy.NetworkID || scope.BindingID != m.member.BindingID || scope.BindingEpoch != m.member.BindingEpoch || scope.LeaseOwner != m.member.LeaseOwner || scope.MembershipRevision != int64(m.member.MembershipRevision) {
		return true, ErrNetworkPermission
	}
	return true, nil
}

func (s *Store) AuthenticateLocalDomainZeroSelf(credential, group string) (NativeActorScope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return NativeActorScope{}, err
	}
	defer tx.Rollback()
	b, err := scanSessionBinding(tx.QueryRow(`SELECT `+sessionBindingColumns+` FROM session_bindings WHERE credential_hash=?`, credential))
	if err != nil {
		return NativeActorScope{}, ErrNetworkPermission
	}
	if group == "" {
		group = b.GroupID
	}
	var network, membership string
	var revision int64
	if tx.QueryRow(`SELECT g.network_id,m.id,m.revision FROM groups g JOIN memberships m ON m.group_id=g.id AND m.principal_id=? WHERE g.id=? AND g.state='ACTIVE'`, b.PrincipalID, group).Scan(&network, &membership, &revision) != nil {
		return NativeActorScope{}, ErrNetworkPermission
	}
	scope := NativeActorScope{PrincipalID: b.PrincipalID, EndpointID: b.EndpointID, GroupID: group, NetworkID: network, MembershipID: membership, MembershipRevision: revision, BindingID: b.ID, BindingEpoch: b.Epoch, LeaseOwner: b.LeaseOwner}
	if zero, err := threadCollaborationZeroSelfTx(tx, scope, time.Now().UTC()); err != nil || !zero {
		return NativeActorScope{}, ErrNetworkPermission
	}
	return scope, nil
}
