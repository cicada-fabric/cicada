package store

import (
	"database/sql"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func rejectLocalDomainNetworkRenewalTx(tx *sql.Tx, access string) error {
	var shared int
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM network_access_sessions_v2 a JOIN session_bindings b ON b.endpoint_id=a.endpoint_id AND b.principal_id=a.principal_id AND b.node_id=a.node_id AND b.native_session_id=a.native_session_id AND (b.credential_hash=a.credential_hash OR b.lease_owner=a.lease_owner) WHERE a.id=?)`, access).Scan(&shared); err != nil {
		return err
	}
	if shared != 0 {
		return ErrNetworkPermission
	}
	if _, err := localDomainScopeExists(tx, "", ""); err != nil {
		return err
	}
	var exists int
	if err := tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='hub_local_domain_members_v1'`).Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM hub_local_domain_members_v1 WHERE access_id=?)`, access).Scan(&exists); err != nil {
			return err
		}
		if exists != 0 {
			return ErrNetworkPermission
		}
	}
	if err := tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='hub_native_pair_slots_v1'`).Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM hub_native_pair_slots_v1 WHERE network_access_binding_id=?)`, access).Scan(&exists); err != nil {
			return err
		}
		if exists != 0 {
			return ErrNetworkPermission
		}
	}
	return nil
}

func localDomainScopeExists(q nativePairReader, group, binding string) (bool, error) {
	var exists int
	if err := q.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='hub_local_domains_v1'`).Scan(&exists); err != nil {
		return false, err
	}
	if exists == 0 {
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
		if high >= 66 {
			return false, ErrNetworkPermission
		}
		return false, nil
	}
	err := q.QueryRow(`SELECT EXISTS(SELECT 1 FROM hub_local_domains_v1 p WHERE (?!='' AND p.group_id=?) OR (?!='' AND EXISTS(SELECT 1 FROM hub_local_domain_members_v1 m WHERE m.policy_id=p.policy_id AND m.binding_id=?)))`, group, group, binding, binding).Scan(&exists)
	return exists != 0, err
}

func localDomainForGroupTx(tx *sql.Tx, group string) (*hubLocalDomain, error) {
	yes, err := localDomainScopeExists(tx, group, "")
	if err != nil || !yes {
		return nil, err
	}
	var id string
	if tx.QueryRow(`SELECT policy_id FROM hub_local_domains_v1 WHERE group_id=?`, group).Scan(&id) != nil {
		return nil, ErrNetworkPermission
	}
	return readLocalDomain(tx, id)
}

// A minimal Hub route selector; the actual send repeats bilateral Guard under
// its admission writer. Historical Group markers never disappear or downgrade.
func (s *Store) RequireHubLocalDomainRelay(credential, group string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	node, owner, hub, err := readActiveOwnerBoundNodeTx(tx, credential)
	if err != nil {
		return ErrNetworkPermission
	}
	if present, e := endpointGroupsSchemaPresent(tx); e != nil {
		return e
	} else if present {
		rows, e := tx.Query(`SELECT r.endpoint_id FROM hub_endpoint_groups_registrations_v1 r JOIN hub_endpoint_groups_relations_v1 x ON x.endpoint_id=r.endpoint_id AND x.group_id=? WHERE r.owner_id=? AND r.node_id=? ORDER BY r.endpoint_id`, group, owner, node)
		if e != nil {
			return e
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, id := range ids {
			r, e := endpointGroupsRegistrationTx(tx, id)
			if e == nil && r != nil && r.anchor.Registration.HubID == hub {
				if managed, e := endpointGroupsGuardTx(tx, id, group, "message.send", time.Now().UTC()); managed && e == nil {
					return nil
				}
			}
		}
	}
	p, err := localDomainForGroupTx(tx, group)
	if err != nil || p == nil || p.policy.Node.NodeID != node || p.policy.OwnerID != owner || p.policy.HubID != hub {
		return ErrNetworkPermission
	}
	return localDomainPolicyAuthorityTx(tx, p, p.accountHub, p.policy.Node.HubNodeControlPublic, time.Now().UTC())
}

func localDomainEndpointCurrentTx(tx *sql.Tx, p *hubLocalDomain, endpoint string, at time.Time) (*hubLocalDomainMember, error) {
	if p == nil || p.state != wire.LocalDomainActive || len(p.proof) == 0 || localDomainRootNodeAuthorityTx(tx, p.policy, wire.HubIdentity{}, p.policy.Node.HubNodeControlPublic, at) != nil {
		return nil, ErrNetworkPermission
	}
	var count int
	if tx.QueryRow(`SELECT count(*) FROM groups g JOIN networks_v2 n ON n.id=g.network_id WHERE g.id=? AND g.state='ACTIVE' AND g.owner_principal_id=? AND g.network_id=? AND n.hub_id=? AND n.owner_id=? AND n.state='ACTIVE'`, p.policy.GroupID, p.policy.OwnerID, p.policy.NetworkID, p.policy.HubID, p.policy.OwnerID).Scan(&count) != nil || count != 1 {
		return nil, ErrNetworkPermission
	}
	var id string
	if tx.QueryRow(`SELECT member_id FROM hub_local_domain_members_v1 WHERE policy_id=? AND endpoint_id=? AND state IN('JOINED_ZERO','ACTIVE')`, p.policy.PolicyID, endpoint).Scan(&id) != nil {
		return nil, ErrNetworkPermission
	}
	m, err := readLocalDomainMember(tx, id)
	if err != nil || m == nil {
		return nil, ErrNetworkPermission
	}
	if _, err = localDomainMemberSnapshotTx(tx, p, m.member, at); err != nil {
		return nil, err
	}
	return m, nil
}

func localDomainSelfTx(tx *sql.Tx, scope NativeActorScope, at time.Time) error {
	if managed, err := endpointGroupsGuardTx(tx, scope.EndpointID, scope.GroupID, "", at); err != nil || managed {
		return err
	}
	p, err := localDomainForGroupTx(tx, scope.GroupID)
	if err != nil || p == nil {
		return err
	}
	m, err := localDomainEndpointCurrentTx(tx, p, scope.EndpointID, at)
	if err != nil || scope.PrincipalID != m.member.PrincipalID || scope.NetworkID != p.policy.NetworkID || scope.BindingID != m.member.BindingID || scope.BindingEpoch != m.member.BindingEpoch || scope.LeaseOwner != m.member.LeaseOwner || scope.MembershipRevision != int64(m.member.MembershipRevision) {
		return ErrNetworkPermission
	}
	return nil
}

func (s *Store) RequireHubNativeCollaborationSelf(scope NativeActorScope) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if managed, err := endpointGroupsGuardTx(tx, scope.EndpointID, scope.GroupID, "", time.Now().UTC()); err != nil {
		return err
	} else if managed {
		return guardNativeSelfTx(tx, scope, time.Now().UTC())
	}
	domain, err := localDomainScopeExists(tx, scope.GroupID, "")
	if err != nil {
		return err
	}
	if !domain {
		pair, e := nativePairScopeExists(tx, "", scope.GroupID, "")
		if e != nil {
			return e
		}
		if !pair {
			return ErrNetworkPermission
		}
	}
	return guardNativeSelfTx(tx, scope, time.Now().UTC())
}

func localDomainLeaveEndpointTx(tx *sql.Tx, endpoint, stamp string) error {
	var exists int
	if err := tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='hub_local_domain_members_v1'`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	if _, err := tx.Exec(`UPDATE memberships SET status='revoked',revision=revision+1,version=version+1,revoked_at=?,revocation_reason='LOCAL_DOMAIN_LEFT',updated_at=? WHERE (principal_id,group_id) IN(SELECT principal_id,p.group_id FROM hub_local_domain_members_v1 m JOIN hub_local_domains_v1 p ON p.policy_id=m.policy_id WHERE m.endpoint_id=? AND m.state IN('JOINED_ZERO','ACTIVE')) AND status='active' AND NOT EXISTS(SELECT 1 FROM fabric_endpoints other JOIN endpoint_group_memberships eg ON eg.endpoint_id=other.id AND eg.group_id=memberships.group_id AND eg.status='active' WHERE other.principal_id=memberships.principal_id AND other.id!=?)`, stamp, stamp, endpoint, endpoint); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE network_memberships_v2 SET status='revoked',revision=revision+1,updated_at=? WHERE (principal_id,network_id) IN(SELECT m.principal_id,p.network_id FROM hub_local_domain_members_v1 m JOIN hub_local_domains_v1 p ON p.policy_id=m.policy_id WHERE m.endpoint_id=? AND m.state IN('JOINED_ZERO','ACTIVE')) AND status='active' AND NOT EXISTS(SELECT 1 FROM fabric_endpoints other JOIN endpoint_network_memberships_v2 en ON en.endpoint_id=other.id AND en.network_id=network_memberships_v2.network_id AND en.status='active' WHERE other.principal_id=network_memberships_v2.principal_id AND other.id!=?)`, stamp, endpoint, endpoint); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE hub_local_domain_challenges_v1 SET state='INVALIDATED' WHERE member_id IN(SELECT member_id FROM hub_local_domain_members_v1 WHERE endpoint_id=?) AND state='PREPARED'`, endpoint); err != nil {
		return err
	}
	_, err := tx.Exec(`UPDATE hub_local_domain_members_v1 SET state='LEFT',revision=revision+1,member_json=json_set(member_json,'$.state','LEFT','$.revision',revision+1) WHERE endpoint_id=? AND state IN('JOINED_ZERO','ACTIVE')`, endpoint)
	return err
}

func localDomainBindingLeaseCeilingTx(tx *sql.Tx, binding string, at time.Time) (string, error) {
	if managed, err := endpointGroupsLeaseCeilingTx(tx, binding, at); err != nil || managed {
		return "", err
	}
	yes, err := localDomainScopeExists(tx, "", binding)
	if err != nil || !yes {
		return "", err
	}
	var policy, member string
	if err = tx.QueryRow(`SELECT policy_id,member_id FROM hub_local_domain_members_v1 WHERE binding_id=?`, binding).Scan(&policy, &member); err != nil {
		return "", err
	}
	p, err := readLocalDomain(tx, policy)
	if err != nil || p == nil || p.state != wire.LocalDomainActive {
		return "", ErrNetworkPermission
	}
	m, err := readLocalDomainMember(tx, member)
	if err != nil || m == nil || (m.member.State != wire.LocalDomainMemberJoinedZero && m.member.State != wire.LocalDomainMemberActive) {
		return "", ErrNetworkPermission
	}
	if err = localDomainPolicyAuthorityTx(tx, p, p.accountHub, p.policy.Node.HubNodeControlPublic, at); err != nil {
		return "", err
	}
	if _, err = localDomainMemberStateTx(tx, p, m.member, at, false); err != nil {
		return "", err
	}
	return p.policy.ExpiresAt, nil
}
