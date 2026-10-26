package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type hubEndpointGroupsRegistration struct {
	anchor                                   wire.EndpointGroupsRegistrationAnchor
	nativeDigest, originPolicy, originMember string
	hub                                      wire.HubIdentity
	listing                                  uint64
}

type hubEndpointGroupsPolicy struct {
	policy   e2ee.EndpointGroupPolicy
	proof    []byte
	state    string
	revision uint64
	grant    *wire.EndpointGroupDelegatedGrant
}

type hubEndpointGroupsRelation struct {
	revision         uint64
	defaultStamp     string
	defaultWithdrawn bool
}

func endpointGroupsNodeTx(tx *sql.Tx, owner, node string, hub wire.HubIdentity, control e2ee.PublicIdentity) (*NodeControlKeyBinding, error) {
	b, err := localDomainNodeBindingTx(tx, node, "", 0, true)
	if err != nil || b.OwnerID != owner || b.HubID != hub.HubID || !reflect.DeepEqual(b.HubPublicIdentity, control) {
		return nil, ErrNetworkPermission
	}
	return b, nil
}

func endpointGroupsRegistrationTx(tx *sql.Tx, endpoint string) (*hubEndpointGroupsRegistration, error) {
	var a, hub string
	r := &hubEndpointGroupsRegistration{}
	err := tx.QueryRow(`SELECT anchor_json,hub_identity_json,native_digest,origin_policy_id,origin_member_id,relations_revision FROM hub_endpoint_groups_registrations_v1 WHERE endpoint_id=?`, endpoint).Scan(&a, &hub, &r.nativeDigest, &r.originPolicy, &r.originMember, &r.listing)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(a), &r.anchor) != nil || json.Unmarshal([]byte(hub), &r.hub) != nil || wire.ValidateEndpointGroupsRegistrationAnchor(r.anchor, r.hub) != nil {
		return nil, ErrNetworkPermission
	}
	digest, err := e2ee.EndpointGroupNativeIdentityDigest(wire.EndpointGroupsNativeIdentity(r.anchor))
	if err != nil || digest != r.nativeDigest {
		return nil, ErrNetworkPermission
	}
	var lease, status, endpointStatus string
	var epoch uint64
	err = tx.QueryRow(`SELECT b.lease_expires_at,b.status,b.epoch,e.status FROM session_bindings b JOIN fabric_endpoints e ON e.id=b.endpoint_id AND e.binding_id=b.id WHERE b.id=? AND b.endpoint_id=? AND b.principal_id=? AND b.node_id=? AND b.native_session_id=? AND b.lease_owner=?`, r.anchor.BindingID, endpoint, r.anchor.Registration.PrincipalID, r.anchor.Registration.NodeID, r.anchor.Registration.NativeSessionID, r.anchor.LeaseOwner).Scan(&lease, &status, &epoch, &endpointStatus)
	if err != nil || epoch != r.anchor.BindingEpoch || endpointStatus == "left" || status == "revoked" {
		r.anchor.State = "REVOKED"
		return r, nil
	}
	r.anchor.LeaseExpiresAt = lease
	r.anchor.State = "REGISTERED"
	return r, nil
}

func endpointGroupsRegistrationCurrentTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, at time.Time) error {
	if r == nil || r.anchor.State == "REVOKED" || at.IsZero() {
		return ErrNetworkPermission
	}
	a := r.anchor
	p, err := readLocalDomain(tx, r.originPolicy)
	if err != nil || p == nil {
		return ErrNetworkPermission
	}
	// Historical origin proves only how this exact native identity was admitted.
	// Its default-policy state/expiry is not a continuing registration authority.
	origin, err := e2ee.VerifyOwnerLocalDomainPolicy(p.policy.OwnerPublic, p.proof, time.Time{})
	if err != nil || !reflect.DeepEqual(origin, p.policy) || origin.OwnerID != a.Registration.OwnerID || origin.Node.NodeID != a.Registration.NodeID || origin.LocalUserScope != a.LocalUserScope || origin.NetworkID != a.NetworkID {
		return ErrNetworkPermission
	}
	b, err := endpointGroupsNodeTx(tx, origin.OwnerID, origin.Node.NodeID, r.hub, origin.Node.HubNodeControlPublic)
	if err != nil || b.NodeKeyEpoch != a.NodeKeyEpoch {
		return ErrNetworkPermission
	}
	expected, current := origin.Node, appNodeBindingPublic(*b)
	expected.NodeName, current.NodeName = "", ""
	if !reflect.DeepEqual(expected, current) {
		return ErrNetworkPermission
	}
	key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, origin.OwnerID, origin.OwnerPublic.ID))
	if err != nil || key.State != OwnerApprovalKeyActive || uint64(key.Version) != origin.OwnerKeyVersion || !reflect.DeepEqual(key.Public, origin.OwnerPublic) || !activeSelfOwnedHuman(tx, origin.OwnerID) {
		return ErrNetworkPermission
	}
	side, err := readCommunicationLinkKeySide(tx, a.Registration.EndpointID, "", a.Registration.PrincipalID, a.Registration.OwnerID, a.Registration.NodeID, a.BindingID, a.BindingEpoch)
	if err != nil || side.CandidateVersion != int64(a.CandidateVersion) || side.KeyID != a.CandidateKeyID || side.KeyFingerprint != a.CandidateFingerprint || side.ProofDigest != a.CandidateProofDigest || !reflect.DeepEqual(side.PublicIdentity, a.CandidatePublic) {
		return ErrNetworkPermission
	}
	var count int
	if tx.QueryRow(`SELECT count(*) FROM fabric_endpoints e JOIN principals p ON p.id=e.principal_id JOIN networks_v2 n ON n.id=? WHERE e.id=? AND e.principal_id=? AND e.machine_id=? AND e.harness=? AND e.native_session_id=? AND e.workspace=? AND e.binding_id=? AND e.migration_state='READY' AND e.status!='left' AND p.kind='agent' AND p.owner_id=? AND p.status='active' AND n.hub_id=? AND n.owner_id=? AND n.state='ACTIVE'`, a.NetworkID, a.Registration.EndpointID, a.Registration.PrincipalID, a.Registration.NodeID, a.Registration.Harness, a.Registration.NativeSessionID, a.Registration.Workspace, a.BindingID, a.Registration.OwnerID, a.Registration.HubID, a.Registration.OwnerID).Scan(&count) != nil || count != 1 {
		return ErrNetworkPermission
	}
	return nil
}

func endpointGroupsEnsureRegistrationTx(tx *sql.Tx, owner, node, network, endpoint string, hub wire.HubIdentity, control e2ee.PublicIdentity, at time.Time) (*hubEndpointGroupsRegistration, error) {
	old, err := endpointGroupsRegistrationTx(tx, endpoint)
	if err != nil {
		return nil, err
	}
	if old != nil {
		if old.anchor.Registration.OwnerID != owner || old.anchor.Registration.NodeID != node || old.anchor.NetworkID != network || old.hub.HubID != hub.HubID || !reflect.DeepEqual(old.hub, hub) || endpointGroupsRegistrationCurrentTx(tx, old, at) != nil {
			return nil, ErrNetworkPermission
		}
		return old, nil
	}
	var memberID string
	if tx.QueryRow(`SELECT m.member_id FROM hub_local_domain_members_v1 m JOIN hub_local_domains_v1 p ON p.policy_id=m.policy_id WHERE m.endpoint_id=? AND m.owner_id=? AND m.node_id=? AND p.network_id=? AND p.hub_id=? AND m.state IN('JOINED_ZERO','ACTIVE') ORDER BY m.created_at DESC LIMIT 1`, endpoint, owner, node, network, hub.HubID).Scan(&memberID) != nil {
		return nil, ErrNetworkPermission
	}
	m, err := readLocalDomainMember(tx, memberID)
	if err != nil || m == nil {
		return nil, ErrNetworkPermission
	}
	p, err := readLocalDomain(tx, m.member.Selection.PolicyID)
	if err != nil || p == nil || p.state != wire.LocalDomainActive || localDomainPolicyAuthorityTx(tx, p, hub, control, at) != nil {
		return nil, ErrNetworkPermission
	}
	b, err := endpointGroupsNodeTx(tx, owner, node, hub, control)
	if err != nil {
		return nil, err
	}
	v := m.member
	side, err := readCommunicationLinkKeySide(tx, endpoint, "", v.PrincipalID, owner, node, v.BindingID, v.BindingEpoch)
	if err != nil {
		return nil, err
	}
	var lease string
	if tx.QueryRow(`SELECT lease_expires_at FROM session_bindings WHERE id=? AND epoch=? AND endpoint_id=? AND lease_owner=? AND status IN('active','leased','online','ready','acquired')`, v.BindingID, v.BindingEpoch, endpoint, v.LeaseOwner).Scan(&lease) != nil {
		return nil, ErrNetworkPermission
	}
	reg := e2ee.EndpointGroupRegistration{HubID: hub.HubID, OwnerID: owner, NodeID: node, Harness: v.Runtime, NativeSessionID: v.NativeSessionID, Workspace: v.Workspace, EndpointID: endpoint, PrincipalID: v.PrincipalID}
	digest, err := e2ee.EndpointGroupRegistrationDigest(reg)
	if err != nil {
		return nil, err
	}
	a := wire.EndpointGroupsRegistrationAnchor{Profile: wire.EndpointGroupsNativeProfile, RegistrationSource: wire.EndpointGroupsRegistrationSource, Registration: reg, RegistrationDigest: digest, RegistrationRevision: 1, LocalUserScope: p.policy.LocalUserScope, NetworkID: network, BindingID: v.BindingID, BindingEpoch: v.BindingEpoch, NodeKeyEpoch: b.NodeKeyEpoch, LeaseOwner: v.LeaseOwner, NetworkAccessBindingID: v.NetworkAccessBindingID, NetworkAccessEpoch: v.NetworkAccessEpoch, NetworkMembershipRevision: v.NetworkMembershipRevision, EndpointNetworkRevision: v.EndpointNetworkRevision, CandidateVersion: uint64(side.CandidateVersion), CandidateKeyID: side.KeyID, CandidatePublic: side.PublicIdentity, CandidateFingerprint: side.KeyFingerprint, CandidateProofDigest: side.ProofDigest, State: "REGISTERED", LeaseExpiresAt: lease}
	if wire.ValidateEndpointGroupsRegistrationAnchor(a, hub) != nil {
		return nil, ErrNetworkPermission
	}
	nativeDigest, err := e2ee.EndpointGroupNativeIdentityDigest(wire.EndpointGroupsNativeIdentity(a))
	if err != nil {
		return nil, err
	}
	anchorRaw, _ := json.Marshal(a)
	hubRaw, _ := json.Marshal(hub)
	_, err = tx.Exec(`INSERT INTO hub_endpoint_groups_registrations_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)`, endpoint, owner, node, network, nativeDigest, digest, 1, a.BindingID, a.BindingEpoch, p.policy.PolicyID, memberID, string(anchorRaw), string(hubRaw), appNodeStamp(at))
	if err != nil {
		return nil, err
	}
	r := &hubEndpointGroupsRegistration{anchor: a, nativeDigest: nativeDigest, originPolicy: p.policy.PolicyID, originMember: memberID, hub: hub}
	if err = endpointGroupsTouchTx(tx, r); err != nil {
		return nil, err
	}
	if _, err = endpointGroupsEnsureRelationTx(tx, r, p.policy.GroupID, at); err != nil {
		return nil, err
	}
	return r, nil
}

func endpointGroupsTouchTx(tx *sql.Tx, r *hubEndpointGroupsRegistration) error {
	if _, err := tx.Exec(`UPDATE hub_endpoint_groups_registrations_v1 SET relations_revision=relations_revision+1 WHERE endpoint_id=? AND relations_revision<9223372036854775806`, r.anchor.Registration.EndpointID); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT INTO hub_endpoint_groups_listings_v1 VALUES(?,?,?,1) ON CONFLICT(owner_id,node_id,network_id) DO UPDATE SET revision=revision+1`, r.anchor.Registration.OwnerID, r.anchor.Registration.NodeID, r.anchor.NetworkID)
	if err == nil {
		r.listing++
	}
	return err
}

func endpointGroupsHeadTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string) (e2ee.EndpointGroupOwnerControl, error) {
	h := e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
	err := tx.QueryRow(`SELECT mode,revision,deny_reason,policy_id,policy_epoch FROM hub_endpoint_groups_heads_v1 WHERE native_digest=? AND group_id=?`, r.nativeDigest, group).Scan(&h.Mode, &h.Revision, &h.DenyReason, &h.PolicyID, &h.PolicyEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return h, nil
	}
	if err != nil || e2ee.ValidateEndpointGroupOwnerControl(h) != nil {
		return h, ErrNetworkPermission
	}
	return h, nil
}

func endpointGroupsSetHeadTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, old, next e2ee.EndpointGroupOwnerControl, at time.Time) error {
	if e2ee.ValidateEndpointGroupOwnerControl(old) != nil || e2ee.ValidateEndpointGroupOwnerControl(next) != nil || next.Revision != old.Revision+1 || old.Mode == "OWNER" && next.Mode != "OWNER" {
		return ErrNetworkPermission
	}
	current, err := endpointGroupsHeadTx(tx, r, group)
	if err != nil || current != old {
		return ErrNetworkPermission
	}
	if _, err = tx.Exec(`INSERT INTO hub_endpoint_groups_heads_v1 VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(native_digest,group_id) DO UPDATE SET mode=excluded.mode,revision=excluded.revision,deny_reason=excluded.deny_reason,policy_id=excluded.policy_id,policy_epoch=excluded.policy_epoch,updated_at=excluded.updated_at`, r.nativeDigest, group, next.Mode, next.Revision, next.DenyReason, next.PolicyID, next.PolicyEpoch, appNodeStamp(at)); err != nil {
		return err
	}
	return nil
}

func endpointGroupsEnsureRelationTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, at time.Time) (hubEndpointGroupsRelation, error) {
	var row hubEndpointGroupsRelation
	err := tx.QueryRow(`SELECT revision,default_stamp,default_withdrawn FROM hub_endpoint_groups_relations_v1 WHERE endpoint_id=? AND group_id=?`, r.anchor.Registration.EndpointID, group).Scan(&row.revision, &row.defaultStamp, &row.defaultWithdrawn)
	if err == nil {
		return row, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return row, err
	}
	_, err = tx.Exec(`INSERT INTO hub_endpoint_groups_relations_v1 VALUES(?,?,?,1,'',0,?,?)`, r.anchor.Registration.EndpointID, group, r.nativeDigest, appNodeStamp(at), appNodeStamp(at))
	if err != nil {
		return row, err
	}
	row.revision = 1
	return row, endpointGroupsTouchTx(tx, r)
}

func endpointGroupsPolicyTx(tx *sql.Tx, id string) (*hubEndpointGroupsPolicy, error) {
	var raw, grant string
	p := &hubEndpointGroupsPolicy{}
	err := tx.QueryRow(`SELECT policy_json,policy_proof,state,contribution_revision,grant_json FROM hub_endpoint_groups_policies_v1 WHERE policy_id=?`, id).Scan(&raw, &p.proof, &p.state, &p.revision, &grant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(raw), &p.policy) != nil || e2ee.ValidateEndpointGroupPolicy(p.policy, time.Time{}) != nil {
		return nil, ErrNetworkPermission
	}
	verified, err := e2ee.VerifyOwnerEndpointGroupPolicy(p.policy.OwnerPublic, p.proof, time.Time{})
	if err != nil || !reflect.DeepEqual(verified, p.policy) {
		return nil, ErrNetworkPermission
	}
	if grant != "" {
		p.grant = &wire.EndpointGroupDelegatedGrant{}
		if json.Unmarshal([]byte(grant), p.grant) != nil {
			return nil, ErrNetworkPermission
		}
	}
	return p, nil
}

func endpointGroupsPolicyForRelationTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string) (*hubEndpointGroupsPolicy, error) {
	var id string
	err := tx.QueryRow(`SELECT policy_id FROM hub_endpoint_groups_policies_v1 WHERE native_digest=? AND group_id=? ORDER BY epoch DESC LIMIT 1`, r.nativeDigest, group).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return endpointGroupsPolicyTx(tx, id)
}

func endpointGroupsPolicyCurrentTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, p *hubEndpointGroupsPolicy, at time.Time) error {
	if p == nil || p.state != "ACTIVE" || e2ee.ValidateEndpointGroupPolicy(p.policy, at) != nil || endpointGroupsRegistrationCurrentTx(tx, r, at) != nil {
		return ErrNetworkPermission
	}
	b, err := endpointGroupsNodeTx(tx, p.policy.OwnerID, p.policy.Node.NodeID, r.hub, p.policy.Node.HubNodeControlPublic)
	if err != nil {
		return err
	}
	expected, current := p.policy.Node, appNodeBindingPublic(*b)
	expected.NodeName, current.NodeName = "", ""
	if !reflect.DeepEqual(expected, current) || p.policy.OwnerID != r.anchor.Registration.OwnerID || p.policy.EndpointID != r.anchor.Registration.EndpointID || p.policy.RegistrationDigest != r.anchor.RegistrationDigest || p.policy.BindingID != r.anchor.BindingID || p.policy.BindingEpoch != r.anchor.BindingEpoch {
		return ErrNetworkPermission
	}
	return nil
}

func endpointGroupsAdvanceRelationTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group, stamp string, withdraw bool, at time.Time) error {
	row, err := endpointGroupsEnsureRelationTx(tx, r, group, at)
	if err != nil {
		return err
	}
	withdraw = withdraw || row.defaultWithdrawn
	_, err = tx.Exec(`UPDATE hub_endpoint_groups_relations_v1 SET revision=revision+1,default_stamp=?,default_withdrawn=?,updated_at=? WHERE endpoint_id=? AND group_id=? AND revision=?`, stamp, withdraw, appNodeStamp(at), r.anchor.Registration.EndpointID, group, row.revision)
	if err != nil {
		return err
	}
	return endpointGroupsTouchTx(tx, r)
}

func endpointGroupsExpireTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, at time.Time) error {
	p, err := endpointGroupsPolicyForRelationTx(tx, r, group)
	if err != nil || p == nil || p.state == "REVOKED" || p.state == "EXPIRED" || p.policy.ExpiresAt == "" || appNodeBefore(at, p.policy.ExpiresAt) {
		return err
	}
	_, err = tx.Exec(`UPDATE hub_endpoint_groups_policies_v1 SET state='EXPIRED',contribution_revision=contribution_revision+1,updated_at=? WHERE policy_id=? AND state IN('PENDING_KEY','ACTIVE')`, appNodeStamp(at), p.policy.PolicyID)
	if err != nil {
		return err
	}
	h, err := endpointGroupsHeadTx(tx, r, group)
	if err != nil {
		return err
	}
	// A never-completed pending policy cannot clear or replace an older head.
	if p.state == "ACTIVE" && h.Mode == "OWNER" && h.PolicyID == p.policy.PolicyID && h.PolicyEpoch == p.policy.Epoch && h.DenyReason == "NONE" {
		next := h
		next.Revision++
		next.DenyReason = "EXPIRED"
		if err = endpointGroupsSetHeadTx(tx, r, group, h, next, at); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`UPDATE hub_endpoint_groups_key_challenges_v1 SET state='EXPIRED' WHERE policy_id=? AND state='PREPARED'`, p.policy.PolicyID); err != nil {
		return err
	}
	row, err := endpointGroupsEnsureRelationTx(tx, r, group, at)
	if err != nil {
		return err
	}
	return endpointGroupsAdvanceRelationTx(tx, r, group, row.defaultStamp, false, at)
}

func endpointGroupsOriginCredential(p e2ee.LocalDomainPolicy) string {
	raw, err := hex.DecodeString(p.CredentialCommitment)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
func endpointGroupsDigest(v any) string {
	raw, _ := json.Marshal(v)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
