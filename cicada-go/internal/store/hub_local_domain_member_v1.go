package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type hubLocalDomainMember struct {
	member                 wire.LocalDomainMember
	attempt, joinOperation string
	joinSequence           uint64
	grant                  string
}

func readLocalDomainMember(tx *sql.Tx, id string) (*hubLocalDomainMember, error) {
	var m hubLocalDomainMember
	var raw, policy, owner, node, sid, endpoint, principal, binding, access, runtime, workspace, state string
	var revision uint64
	err := tx.QueryRow(`SELECT member_json,policy_id,owner_id,node_id,native_session_id,endpoint_id,principal_id,binding_id,access_id,runtime,workspace,state,revision,attempt_id,join_operation_id,join_sequence,key_grant_json FROM hub_local_domain_members_v1 WHERE member_id=?`, id).Scan(&raw, &policy, &owner, &node, &sid, &endpoint, &principal, &binding, &access, &runtime, &workspace, &state, &revision, &m.attempt, &m.joinOperation, &m.joinSequence, &m.grant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(raw), &m.member) != nil {
		return nil, ErrNetworkPermission
	}
	s := m.member
	if s.MemberID != id || s.Selection.PolicyID != policy || s.NodeID != node || s.NativeSessionID != sid || s.EndpointID != endpoint || s.PrincipalID != principal || s.BindingID != binding || s.NetworkAccessBindingID != access || s.Runtime != runtime || s.Workspace != workspace || s.State != state || s.Revision != revision || revision == 0 || wire.ValidateLocalDomainSelection(s.Selection) != nil {
		return nil, ErrNetworkPermission
	}
	p, err := readLocalDomain(tx, policy)
	if err != nil || p == nil || p.policy.OwnerID != owner || p.policy.Node.NodeID != node || p.policy.LocalUserScope != s.LocalUserScope || p.policy.Epoch != s.Selection.PolicyEpoch {
		return nil, ErrNetworkPermission
	}
	selection, err := wire.LocalDomainSelectionForPolicy(p.policy)
	if err != nil || selection != s.Selection {
		return nil, ErrNetworkPermission
	}
	return &m, nil
}

func localDomainMemberSnapshotTx(tx *sql.Tx, p *hubLocalDomain, m wire.LocalDomainMember, at time.Time) (wire.LocalDomainMember, error) {
	return localDomainMemberStateTx(tx, p, m, at, true)
}

func localDomainMemberStateTx(tx *sql.Tx, p *hubLocalDomain, m wire.LocalDomainMember, at time.Time, requireLease bool) (wire.LocalDomainMember, error) {
	if m.Selection.PolicyID != p.policy.PolicyID || m.Selection.PolicyEpoch != p.policy.Epoch || m.NodeID != p.policy.Node.NodeID || m.LocalUserScope != p.policy.LocalUserScope || (m.State != wire.LocalDomainMemberJoinedZero && m.State != wire.LocalDomainMemberActive) {
		return wire.LocalDomainMember{}, ErrNetworkPermission
	}
	var runtime, sid, workspace, nativeEnd, accessEnd, ns, bs, ms, egs, enms, nms, expiry string
	var epoch, accessEpoch, nmr, enr, mr, egr uint64
	err := tx.QueryRow(`SELECT e.harness,e.native_session_id,e.workspace,b.lease_expires_at,a.lease_expires_at,e.status,b.status,gm.status,eg.status,en.status,nm.status,gm.expires_at,b.epoch,a.epoch,nm.revision,en.revision,gm.revision,eg.revision
FROM fabric_endpoints e JOIN principals pr ON pr.id=e.principal_id AND pr.owner_id=e.owner AND pr.status='active'
JOIN session_bindings b ON b.id=e.binding_id AND b.endpoint_id=e.id AND b.principal_id=e.principal_id AND b.native_session_id=e.native_session_id AND b.node_id=e.machine_id
JOIN network_access_sessions_v2 a ON a.id=? AND a.endpoint_id=e.id AND a.principal_id=e.principal_id AND a.node_id=e.machine_id AND a.native_session_id=e.native_session_id AND a.network_id=? AND a.status='active' AND a.credential_hash=b.credential_hash AND a.lease_owner=b.lease_owner AND a.owner_key_id=?
JOIN memberships gm ON gm.principal_id=e.principal_id AND gm.group_id=?
JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=gm.group_id
JOIN network_memberships_v2 nm ON nm.principal_id=e.principal_id AND nm.network_id=a.network_id
JOIN endpoint_network_memberships_v2 en ON en.endpoint_id=e.id AND en.network_id=a.network_id
WHERE e.id=? AND e.principal_id=? AND e.owner=? AND e.machine_id=? AND e.migration_state='READY' AND b.id=? AND b.lease_owner=?`, m.NetworkAccessBindingID, p.policy.NetworkID, p.policy.OwnerPublic.ID, p.policy.GroupID, m.EndpointID, m.PrincipalID, p.policy.OwnerID, m.NodeID, m.BindingID, m.LeaseOwner).Scan(&runtime, &sid, &workspace, &nativeEnd, &accessEnd, &ns, &bs, &ms, &egs, &enms, &nms, &expiry, &epoch, &accessEpoch, &nmr, &enr, &mr, &egr)
	if err != nil || runtime != m.Runtime || sid != m.NativeSessionID || workspace != m.Workspace || ns == "left" || !isActiveBindingStatus(bs) || ms != "active" || egs != "active" || enms != "active" || nms != "active" || epoch != m.BindingEpoch || accessEpoch != m.NetworkAccessEpoch || (requireLease && (!appNodeBefore(at, nativeEnd) || !appNodeBefore(at, accessEnd))) || (expiry != "" && !appNodeBefore(at, expiry)) {
		return wire.LocalDomainMember{}, ErrNetworkPermission
	}
	if m.NetworkMembershipRevision != nmr || m.EndpointNetworkRevision != enr || m.MembershipRevision != mr || m.EndpointJoinRevision != egr {
		return wire.LocalDomainMember{}, ErrNetworkPermission
	}
	return m, nil
}

func localDomainJoinResultTx(tx *sql.Tx, p *hubLocalDomain, m wire.LocalDomainMember, token string, reused bool, at time.Time) (wire.LocalDomainNodeJoinResult, error) {
	d, err := localDomainDescriptionTx(tx, p, at)
	if err != nil {
		return wire.LocalDomainNodeJoinResult{}, err
	}
	e, err := scanEndpointV2(tx.QueryRow(`SELECT `+endpointV2Columns+` FROM fabric_endpoints WHERE id=?`, m.EndpointID))
	if err != nil {
		return wire.LocalDomainNodeJoinResult{}, err
	}
	r, err := nodeEndpointResultTx(tx, e, reused)
	if err != nil {
		return wire.LocalDomainNodeJoinResult{}, err
	}
	var lease string
	if tx.QueryRow(`SELECT lease_expires_at FROM session_bindings WHERE id=? AND epoch=?`, m.BindingID, m.BindingEpoch).Scan(&lease) != nil {
		return wire.LocalDomainNodeJoinResult{}, ErrNetworkPermission
	}
	scope, err := readNativeContextScopeForGroupTx(tx, p.policy.GroupID)
	if err != nil {
		return wire.LocalDomainNodeJoinResult{}, err
	}
	return wire.LocalDomainNodeJoinResult{ContractRevision: wire.LocalDomainContractRevision, Description: d, Member: m, Endpoint: *r, NativeContextScope: wire.LocalDomainContextScope{HubID: scope.HubID, NetworkID: scope.NetworkID, GroupID: scope.GroupID, GroupContextPolicy: scope.GroupContextPolicy, NetworkContextPolicy: scope.NetworkContextPolicy}, SessionToken: token, LeaseExpiresAt: lease, Reused: reused}, nil
}

func localDomainJoinTx(tx *sql.Tx, in HubLocalDomainNodeInput, rpc NodeControlRPCInput, p *hubLocalDomain, q wire.LocalDomainNodeJoin) (any, error) {
	var previous string
	err := tx.QueryRow(`SELECT member_id FROM hub_local_domain_members_v1 WHERE policy_id=? AND native_session_id=? AND state IN('JOINED_ZERO','ACTIVE')`, p.policy.PolicyID, q.NativeSessionID).Scan(&previous)
	if err == nil {
		m, e := readLocalDomainMember(tx, previous)
		if e != nil || m == nil || m.member.Workspace != q.Workspace || m.member.Runtime != q.Runtime {
			return nil, ErrNetworkPermission
		}
		if e = resumeLocalDomainMemberLeaseTx(tx, p, m.member, in.At); e != nil {
			return nil, e
		}
		// A distinct operation can recover public identity, not mint a second
		// token. The original exact encrypted receipt retains the original token.
		return localDomainJoinResultTx(tx, p, m.member, "", true, in.At)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var attempts int
	if tx.QueryRow(`SELECT count(*) FROM hub_local_domain_members_v1 WHERE policy_id=? AND attempt_id=?`, p.policy.PolicyID, q.AttemptID).Scan(&attempts) != nil || attempts != 0 {
		return nil, ErrSessionBindingConflict
	}
	registered, err := nodeEndpointForSessionTx(tx, p.policy.OwnerID, p.policy.Node.NodeID, q.Runtime, q.NativeSessionID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var endpoint, principal, name, replace string
	epoch, accessEpoch := uint64(1), uint64(1)
	name = q.EndpointName
	if name == "" {
		name = "Thread"
	}
	if registered != nil {
		if registered.Workspace != q.Workspace || registered.Visibility != "private" {
			return nil, ErrSessionBindingConflict
		}
		var live int
		if tx.QueryRow(`SELECT (SELECT count(*) FROM session_bindings WHERE endpoint_id=? AND status IN('pending','active','leased'))+(SELECT count(*) FROM memberships WHERE principal_id=? AND status='active')+(SELECT count(*) FROM network_memberships_v2 WHERE principal_id=? AND status='active')`, registered.ID, registered.PrincipalID, registered.PrincipalID).Scan(&live) != nil || live != 0 {
			return nil, ErrSessionBindingConflict
		}
		endpoint, principal, name = registered.ID, registered.PrincipalID, registered.Name
		var oldEpoch uint64
		if err = tx.QueryRow(`SELECT coalesce(max(epoch),0) FROM session_bindings WHERE endpoint_id=?`, endpoint).Scan(&oldEpoch); err != nil || oldEpoch >= 1<<63-2 {
			return nil, ErrSessionBindingConflict
		}
		epoch = oldEpoch + 1
		if oldEpoch > 0 {
			if tx.QueryRow(`SELECT id FROM session_bindings WHERE endpoint_id=? AND epoch=? ORDER BY rowid DESC LIMIT 1`, endpoint, oldEpoch).Scan(&replace) != nil {
				return nil, ErrSessionBindingConflict
			}
		}
		if err = tx.QueryRow(`SELECT coalesce(max(epoch),0)+1 FROM network_access_sessions_v2 WHERE endpoint_id=? AND network_id=?`, endpoint, p.policy.NetworkID).Scan(&accessEpoch); err != nil || accessEpoch >= 1<<63-1 {
			return nil, ErrSessionBindingConflict
		}
	} else {
		var trust string
		if tx.QueryRow(`SELECT trust_domain_id FROM principals WHERE id=? AND kind='human' AND status='active'`, p.policy.OwnerID).Scan(&trust) != nil {
			return nil, ErrNetworkPermission
		}
		endpoint, principal, err = insertNetworkNativeEndpointTx(tx, p.policy.OwnerID, trust, name, q.Runtime, q.NativeSessionID, p.policy.Node.NodeID, q.Workspace, in.At)
		if err != nil {
			return nil, err
		}
	}
	if in.SessionToken == "" {
		return nil, ErrSessionBindingConflict
	}
	stamp := appNodeStamp(in.At)
	hash := sha256.Sum256([]byte(in.SessionToken))
	credential := base64.RawURLEncoding.EncodeToString(hash[:])
	lease := NewID("adapter")
	end := in.At.Add(5 * time.Minute)
	if p.policy.ExpiresAt != "" {
		ce, _ := time.Parse(time.RFC3339Nano, p.policy.ExpiresAt)
		if ce.Before(end) {
			end = ce
		}
	}
	leaseEnd := appNodeStamp(end)
	if _, err = tx.Exec(`INSERT INTO network_memberships_v2(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at) VALUES(?,?,?,'[]','active',?,1,?,?) ON CONFLICT(network_id,principal_id) DO UPDATE SET grants_json='[]',status='active',expires_at=excluded.expires_at,revision=network_memberships_v2.revision+1,updated_at=excluded.updated_at`, NewID("netmem"), p.policy.NetworkID, principal, p.policy.ExpiresAt, stamp, stamp); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`INSERT INTO endpoint_network_memberships_v2(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at) VALUES(?,?,'active',1,?,0,?,?) ON CONFLICT(network_id,endpoint_id) DO UPDATE SET status='active',revision=endpoint_network_memberships_v2.revision+1,discoverable=0,updated_at=excluded.updated_at`, p.policy.NetworkID, endpoint, name, stamp, stamp); err != nil {
		return nil, err
	}
	var membershipID string
	err = tx.QueryRow(`SELECT id FROM memberships WHERE group_id=? AND principal_id=?`, p.policy.GroupID, principal).Scan(&membershipID)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err = insertZeroGroupAdmissionTx(tx, principal, p.policy.GroupID, endpoint, p.policy.ExpiresAt, in.At); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		if _, err = tx.Exec(`UPDATE memberships SET role='member',roles_json='["member"]',grants_json='[]',authorization_json='{}',status='active',effective_at=?,expires_at=?,revoked_at='',revocation_reason='',revision=revision+1,version=version+1,updated_at=? WHERE id=? AND status!='active'`, stamp, p.policy.ExpiresAt, stamp, membershipID); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`UPDATE endpoint_group_memberships SET status='active',revision=revision+1,updated_at=? WHERE endpoint_id=? AND group_id=? AND status!='active'`, stamp, endpoint, p.policy.GroupID); err != nil {
			return nil, err
		}
	}
	access := NewID("netaccess")
	// The established Network session is unique per Network/Endpoint. Preserve
	// that identity while fencing its old credential by a strictly newer epoch;
	// the terminal member retains its original immutable (id,epoch) tuple.
	var oldAccess string
	accessErr := tx.QueryRow(`SELECT id FROM network_access_sessions_v2 WHERE network_id=? AND endpoint_id=? AND status!='active'`, p.policy.NetworkID, endpoint).Scan(&oldAccess)
	if accessErr == nil {
		access = oldAccess
	} else if !errors.Is(accessErr, sql.ErrNoRows) {
		return nil, accessErr
	}
	if _, err = tx.Exec(`INSERT INTO network_access_sessions_v2(id,network_id,endpoint_id,principal_id,native_session_id,node_id,epoch,lease_owner,lease_expires_at,status,credential_hash,owner_key_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,'active',?,?,?,?) ON CONFLICT(network_id,endpoint_id) DO UPDATE SET epoch=excluded.epoch,lease_owner=excluded.lease_owner,lease_expires_at=excluded.lease_expires_at,status='active',credential_hash=excluded.credential_hash,owner_key_id=excluded.owner_key_id,updated_at=excluded.updated_at WHERE network_access_sessions_v2.status!='active' AND network_access_sessions_v2.id=excluded.id AND network_access_sessions_v2.principal_id=excluded.principal_id AND network_access_sessions_v2.node_id=excluded.node_id AND network_access_sessions_v2.native_session_id=excluded.native_session_id AND network_access_sessions_v2.epoch<excluded.epoch`, access, p.policy.NetworkID, endpoint, principal, q.NativeSessionID, p.policy.Node.NodeID, accessEpoch, lease, leaseEnd, credential, p.policy.OwnerPublic.ID, stamp, stamp); err != nil {
		return nil, err
	}
	binding, capabilities, err := normalizeBinding(SessionBinding{EndpointID: endpoint, PrincipalID: principal, GroupID: p.policy.GroupID, NativeSessionID: q.NativeSessionID, NodeID: p.policy.Node.NodeID, WorkspaceID: q.Workspace, Epoch: epoch, LeaseOwner: lease, LeaseExpiresAt: leaseEnd, Status: SessionBindingStatusLeased, CredentialHash: credential, Mode: "adopted", ContextContinuity: "NATIVE_RESUME", ReplacesBindingID: replace})
	if err != nil {
		return nil, err
	}
	binding.WorkspaceID, binding.Workspace = q.Workspace, q.Workspace
	if err = insertSessionBindingRowTx(tx, binding, capabilities, stamp); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`UPDATE fabric_endpoints SET group_id=?,binding_id=?,status='online',migration_state='READY',capabilities_json='{"local_peer_delivery":"sealed_v1"}',updated_at=? WHERE id=? AND principal_id=?`, p.policy.GroupID, binding.ID, stamp, endpoint, principal); err != nil {
		return nil, err
	}
	m := wire.LocalDomainMember{MemberID: NewID("ldmember"), Selection: q.Selection, Revision: 1, State: wire.LocalDomainMemberJoinedZero, NodeID: p.policy.Node.NodeID, LocalUserScope: p.policy.LocalUserScope, NativeSessionID: q.NativeSessionID, Runtime: q.Runtime, Workspace: q.Workspace, EndpointID: endpoint, PrincipalID: principal, BindingID: binding.ID, BindingEpoch: epoch, NetworkAccessBindingID: access, NetworkAccessEpoch: accessEpoch, LeaseOwner: lease}
	if tx.QueryRow(`SELECT nm.revision,en.revision,gm.revision,eg.revision FROM network_memberships_v2 nm JOIN endpoint_network_memberships_v2 en ON en.network_id=nm.network_id AND en.endpoint_id=? JOIN memberships gm ON gm.principal_id=nm.principal_id AND gm.group_id=? JOIN endpoint_group_memberships eg ON eg.endpoint_id=en.endpoint_id AND eg.group_id=gm.group_id WHERE nm.network_id=? AND nm.principal_id=?`, endpoint, p.policy.GroupID, p.policy.NetworkID, principal).Scan(&m.NetworkMembershipRevision, &m.EndpointNetworkRevision, &m.MembershipRevision, &m.EndpointJoinRevision) != nil {
		return nil, ErrNetworkPermission
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO hub_local_domain_members_v1(member_id,policy_id,owner_id,node_id,native_session_id,endpoint_id,principal_id,binding_id,access_id,runtime,workspace,member_json,state,revision,attempt_id,join_operation_id,join_sequence,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'JOINED_ZERO',1,?,?,?,?)`, m.MemberID, p.policy.PolicyID, p.policy.OwnerID, m.NodeID, m.NativeSessionID, endpoint, principal, binding.ID, access, q.Runtime, q.Workspace, string(raw), q.AttemptID, rpc.OperationID, rpc.Sequence, stamp)
	if err != nil {
		return nil, err
	}
	return localDomainJoinResultTx(tx, p, m, in.SessionToken, registered != nil, in.At)
}
