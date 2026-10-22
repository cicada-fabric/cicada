package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type HubLocalDomainInput struct {
	Hub               wire.HubIdentity
	NodeControlPublic e2ee.PublicIdentity
	Device            e2ee.PublicIdentity
	Packet            []byte
	Body              any
	At                time.Time
	Now               func() time.Time
	Original          *HubLocalDomainInput
	OriginalSeal      HubLocalDomainSeal
}
type HubLocalDomainSeal func(any) ([]byte, error)

type hubLocalDomain struct {
	accountHub                                                   wire.HubIdentity
	policy                                                       e2ee.LocalDomainPolicy
	proof, prepareProof, report                                  []byte
	state                                                        string
	revision                                                     uint64
	proofExpires, created, reason, creatorAccount, creatorDevice string
}

type localDomainReceipt struct {
	packet        []byte
	state, policy string
}

func localDomainOwnerFields(body any) (op string, c wire.AppNodeRequestContext, token, proof []byte, err error) {
	var q wire.LocalDomainPrepare
	switch v := body.(type) {
	case wire.LocalDomainPrepare:
		q = v
		op = wire.OperationLocalDomainPrepare
	case wire.LocalDomainActivate:
		q = wire.LocalDomainPrepare{Format: v.Format, Context: v.Context, SessionToken: v.SessionToken, OwnerProof: v.OwnerProof}
		op = wire.OperationLocalDomainActivate
	case wire.LocalDomainStatusRequest:
		q = wire.LocalDomainPrepare(v)
		op = wire.OperationLocalDomainStatus
	case wire.LocalDomainRevoke:
		q = wire.LocalDomainPrepare(v)
		op = wire.OperationLocalDomainRevoke
	case wire.LocalDomainReconcileRequest:
		return wire.OperationLocalDomainReconcile, v.Context, nil, nil, nil
	default:
		return "", c, nil, nil, ErrHubAccountRejected
	}
	return op, q.Context, q.SessionToken, q.OwnerProof, nil
}

func localDomainInput(in HubLocalDomainInput) (string, wire.AppNodeRequestContext, []byte, []byte, error) {
	op, c, token, proof, err := localDomainOwnerFields(in.Body)
	if err != nil || in.At.IsZero() {
		return "", c, nil, nil, ErrHubAccountRejected
	}
	p, err := wire.PreflightRequest(in.Packet, op)
	_, route, re := wire.RequestRoute(in.Hub, c.OwnerID, c.DeviceID, c.RequestID, op, wire.HandshakeEpoch, in.Device)
	if err != nil || re != nil || p.Packet.Route != route || !reflect.DeepEqual(p.SenderPublicIdentity, in.Device) || c.HubID != in.Hub.HubID {
		return "", c, nil, nil, ErrHubAccountRejected
	}
	return op, c, token, proof, nil
}

func readLocalDomain(tx *sql.Tx, id string) (*hubLocalDomain, error) {
	var p hubLocalDomain
	var raw, hub, owner, node, user, network, group, hubJSON string
	var epoch uint64
	err := tx.QueryRow(`SELECT policy_json,hub_identity_json,hub_id,owner_id,node_id,local_user_scope,network_id,group_id,epoch,policy_proof,state,revision,prepare_proof,user_report,proof_expires_at,created_at,terminal_reason,creator_account_id,creator_device_id FROM hub_local_domains_v1 WHERE policy_id=?`, id).Scan(&raw, &hubJSON, &hub, &owner, &node, &user, &network, &group, &epoch, &p.proof, &p.state, &p.revision, &p.prepareProof, &p.report, &p.proofExpires, &p.created, &p.reason, &p.creatorAccount, &p.creatorDevice)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(hubJSON), &p.accountHub) != nil || json.Unmarshal([]byte(raw), &p.policy) != nil || wire.ValidateLocalDomainPolicy(p.policy, p.accountHub, time.Time{}) != nil || p.policy.PolicyID != id || p.policy.HubID != hub || p.policy.OwnerID != owner || p.policy.Node.NodeID != node || p.policy.LocalUserScope != user || p.policy.NetworkID != network || p.policy.GroupID != group || p.policy.Epoch != epoch || p.revision == 0 {
		return nil, ErrHubAccountRejected
	}
	if len(p.proof) > 0 {
		policy, err := e2ee.VerifyOwnerLocalDomainPolicy(p.policy.OwnerPublic, p.proof, time.Time{})
		if err != nil || !reflect.DeepEqual(policy, p.policy) {
			return nil, ErrHubAccountRejected
		}
	} else if p.state == wire.LocalDomainActive || p.state == wire.LocalDomainRevoked {
		return nil, ErrHubAccountRejected
	}
	return &p, nil
}

func localDomainDescriptionTx(tx *sql.Tx, p *hubLocalDomain, at time.Time) (wire.LocalDomainDescription, error) {
	var count uint64
	if err := tx.QueryRow(`SELECT count(*) FROM hub_local_domain_members_v1 WHERE policy_id=?`, p.policy.PolicyID).Scan(&count); err != nil {
		return wire.LocalDomainDescription{}, err
	}
	return wire.LocalDomainDescription{ContractRevision: wire.LocalDomainContractRevision, Policy: p.policy, PolicyProof: append([]byte(nil), p.proof...), State: p.state, Revision: p.revision, MemberCount: count, ObservedAt: appNodeStamp(at)}, nil
}

// Retained lookup authenticates exact historical envelopes. Current lookup
// adds Owner/Node/credential/key authority, independently of creator App state.
func localDomainNodeBindingTx(tx *sql.Tx, node, credential string, epoch uint64, current bool) (*NodeControlKeyBinding, error) {
	query := `SELECT b.id,b.owner_id,b.hub_id,b.node_id,b.node_name,k.client_device_id,k.owner_key_id,
k.node_credential_version,b.version,k.node_credential_digest,k.node_key_id,k.node_public_identity_json,k.node_fingerprint,k.node_key_version,k.node_key_epoch,
k.hub_key_id,k.hub_public_identity_json,k.hub_fingerprint,k.hub_key_version,k.approved_request_id,k.approved_request_version,k.approved_candidate_digest,
k.approved_owner_device_id,k.approved_owner_key_id,k.approved_at,k.state,k.version,k.revoked_at
FROM node_control_key_bindings_v1 k JOIN node_owner_bindings_v2 b ON b.id=k.owner_binding_id`
	if current {
		query += ` JOIN fabric_node_credentials c ON c.node_id=b.node_id AND c.status='active' AND c.version=b.node_credential_version AND c.credential_hash=b.node_credential_digest
JOIN principals p ON p.id=b.owner_id AND p.kind='human' AND p.status='active'
JOIN owner_approval_keys_v2 o ON o.owner_id=b.owner_id AND o.key_id=b.owner_key_id AND o.state='ACTIVE'
JOIN client_device_hub_config_v2 h ON h.id=1 AND h.hub_id=b.hub_id
JOIN machines m ON m.id=b.node_id AND m.owner_id=b.owner_id`
	}
	query += ` WHERE b.node_id=?`
	args := []any{node}
	if current {
		query += ` AND b.state='ACTIVE' AND k.state='ACTIVE' AND k.node_credential_digest=b.node_credential_digest AND k.node_credential_version=b.node_credential_version AND k.owner_id=b.owner_id AND k.owner_key_id=b.owner_key_id AND k.hub_id=b.hub_id`
	}
	if credential != "" {
		query += ` AND k.node_credential_digest=?`
		args = append(args, credential)
	}
	if epoch != 0 {
		query += ` AND k.node_key_epoch=?`
		args = append(args, epoch)
	}
	query += ` ORDER BY k.node_key_epoch DESC LIMIT 1`
	var b NodeControlKeyBinding
	var np, hp string
	err := tx.QueryRow(query, args...).Scan(&b.OwnerBindingID, &b.OwnerID, &b.HubID, &b.NodeID, &b.NodeName, &b.ClientDeviceID, &b.OwnerKeyID, &b.NodeCredentialVersion, &b.BindingVersion, &b.CredentialDigest, &b.NodeKeyID, &np, &b.NodeKeyFingerprint, &b.NodeKeyVersion, &b.NodeKeyEpoch, &b.HubKeyID, &hp, &b.HubKeyFingerprint, &b.HubKeyVersion, &b.ApprovedRequestID, &b.ApprovedRequestVersion, &b.ApprovedCandidateDigest, &b.ApprovedOwnerDeviceID, &b.ApprovedOwnerKeyID, &b.ApprovedAt, &b.State, &b.Version, &b.RevokedAt)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(np), &b.NodePublicIdentity) != nil || json.Unmarshal([]byte(hp), &b.HubPublicIdentity) != nil || e2ee.ValidatePublicIdentity(b.NodePublicIdentity) != nil || e2ee.ValidatePublicIdentity(b.HubPublicIdentity) != nil || b.NodeKeyID != b.NodePublicIdentity.ID || b.HubKeyID != b.HubPublicIdentity.ID || b.NodeKeyFingerprint != nodewire.IdentityFingerprint(b.NodePublicIdentity) || b.HubKeyFingerprint != nodewire.IdentityFingerprint(b.HubPublicIdentity) || b.NodeKeyVersion == 0 || b.NodeKeyEpoch == 0 || b.HubKeyVersion == 0 {
		return nil, ErrNodeControlKeyUnauthorized
	}
	return &b, nil
}

func localDomainPolicyAuthorityTx(tx *sql.Tx, p *hubLocalDomain, hub wire.HubIdentity, control e2ee.PublicIdentity, at time.Time) error {
	if p == nil || p.state != wire.LocalDomainActive || len(p.proof) == 0 || wire.ValidateLocalDomainPolicy(p.policy, hub, at) != nil {
		return ErrNetworkPermission
	}
	policy := p.policy
	if err := localDomainRootNodeAuthorityTx(tx, policy, hub, control, at); err != nil {
		return err
	}
	var count int
	err := tx.QueryRow(`SELECT count(*) FROM groups g JOIN networks_v2 n ON n.id=g.network_id WHERE g.id=? AND g.network_id=? AND g.owner_principal_id=? AND g.state='ACTIVE' AND g.context_policy='group_scoped' AND n.hub_id=? AND n.owner_id=? AND n.state='ACTIVE'`, policy.GroupID, policy.NetworkID, policy.OwnerID, policy.HubID, policy.OwnerID).Scan(&count)
	if err != nil || count != 1 {
		return ErrNetworkPermission
	}
	return nil
}

func localDomainRootNodeAuthorityTx(tx *sql.Tx, policy e2ee.LocalDomainPolicy, hub wire.HubIdentity, control e2ee.PublicIdentity, at time.Time) error {
	if e2ee.ValidateLocalDomainPolicy(policy, at) != nil || (hub.HubID != "" && wire.ValidateLocalDomainPolicy(policy, hub, at) != nil) {
		return ErrNetworkPermission
	}
	key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, policy.OwnerID, policy.OwnerPublic.ID))
	if err != nil || key.State != OwnerApprovalKeyActive || uint64(key.Version) != policy.OwnerKeyVersion || !reflect.DeepEqual(key.Public, policy.OwnerPublic) || !activeSelfOwnedHuman(tx, policy.OwnerID) {
		return ErrNetworkPermission
	}
	decoded, err := hex.DecodeString(policy.CredentialCommitment)
	if err != nil {
		return ErrNetworkPermission
	}
	b, err := localDomainNodeBindingTx(tx, policy.Node.NodeID, base64.RawURLEncoding.EncodeToString(decoded), policy.Node.NodeKeyEpoch, true)
	if err != nil || b.Version != policy.NodeControlBindingVersion || !reflect.DeepEqual(b.HubPublicIdentity, control) {
		return ErrNetworkPermission
	}
	current, expected := appNodeBindingPublic(*b), policy.Node
	current.NodeName, expected.NodeName = "", ""
	if !reflect.DeepEqual(current, expected) {
		return ErrNetworkPermission
	}
	return nil
}

func localDomainExpireTx(tx *sql.Tx, p *hubLocalDomain, at time.Time) error {
	if p == nil || p.state == wire.LocalDomainRevoked || p.state == wire.LocalDomainExpired {
		return nil
	}
	expired := p.state == wire.LocalDomainPrepared && !appNodeBefore(at, p.proofExpires)
	if p.policy.ExpiresAt != "" && !appNodeBefore(at, p.policy.ExpiresAt) {
		expired = true
	}
	if !expired {
		return nil
	}
	return localDomainTerminateTx(tx, p, wire.LocalDomainExpired, "EXPIRED", at)
}

func localDomainTerminateTx(tx *sql.Tx, p *hubLocalDomain, state, reason string, at time.Time) error {
	if p.state == wire.LocalDomainRevoked || p.state == wire.LocalDomainExpired {
		return nil
	}
	stamp := appNodeStamp(at)
	queries := []string{
		`UPDATE memberships SET status='revoked',revision=revision+1,version=version+1,revoked_at=?,revocation_reason='LOCAL_DOMAIN_TERMINAL',updated_at=? WHERE group_id=? AND principal_id IN(SELECT principal_id FROM hub_local_domain_members_v1 WHERE policy_id=?) AND status='active'`,
		`UPDATE network_memberships_v2 SET status='revoked',revision=revision+1,updated_at=? WHERE network_id=? AND principal_id IN(SELECT principal_id FROM hub_local_domain_members_v1 WHERE policy_id=?) AND status='active'`,
	}
	if _, err := tx.Exec(queries[0], stamp, stamp, p.policy.GroupID, p.policy.PolicyID); err != nil {
		return err
	}
	if _, err := tx.Exec(queries[1], stamp, p.policy.NetworkID, p.policy.PolicyID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE network_access_sessions_v2 SET status='revoked',updated_at=? WHERE id IN(SELECT access_id FROM hub_local_domain_members_v1 WHERE policy_id=?)`, stamp, p.policy.PolicyID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE session_bindings SET status='revoked',revocation_reason='LOCAL_DOMAIN_TERMINAL',version=version+1,updated_at=? WHERE id IN(SELECT binding_id FROM hub_local_domain_members_v1 WHERE policy_id=?) AND status!='revoked'`, stamp, p.policy.PolicyID); err != nil {
		return err
	}
	memberState := wire.LocalDomainMemberRevoked
	if state == wire.LocalDomainExpired {
		memberState = wire.LocalDomainMemberExpired
	}
	if _, err := tx.Exec(`UPDATE hub_local_domain_members_v1 SET state=?,revision=revision+1,member_json=json_set(member_json,'$.state',?,'$.revision',revision+1) WHERE policy_id=? AND state IN('JOINED_ZERO','ACTIVE')`, memberState, memberState, p.policy.PolicyID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE hub_local_domain_challenges_v1 SET state='INVALIDATED' WHERE policy_id=? AND state='PREPARED'`, p.policy.PolicyID); err != nil {
		return err
	}
	r, err := tx.Exec(`UPDATE hub_local_domains_v1 SET state=?,revision=revision+1,terminal_reason=? WHERE policy_id=? AND revision=? AND state IN('PREPARED','ACTIVE')`, state, reason, p.policy.PolicyID, p.revision)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil || n != 1 {
		return ErrHubAccountRejected
	}
	p.state = state
	p.reason = reason
	p.revision++
	return nil
}
