package store

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func endpointGroupsNodePolicyTx(tx *sql.Tx, in HubEndpointGroupsNodeInput, r *hubEndpointGroupsRegistration, id, group string, epoch uint64) (*hubEndpointGroupsPolicy, error) {
	p, err := endpointGroupsPolicyTx(tx, id)
	if err != nil || p == nil || p.policy.Epoch != epoch || p.policy.GroupID != group || p.policy.EndpointID != r.anchor.Registration.EndpointID || p.policy.OwnerID != r.anchor.Registration.OwnerID || p.policy.Node.NodeID != r.anchor.Registration.NodeID || p.policy.RegistrationDigest != r.anchor.RegistrationDigest || p.policy.RegistrationRevision != r.anchor.RegistrationRevision || p.policy.BindingID != r.anchor.BindingID || p.policy.BindingEpoch != r.anchor.BindingEpoch || p.policy.CandidateVersion != r.anchor.CandidateVersion || p.policy.CandidateProofDigest != r.anchor.CandidateProofDigest || p.policy.EndpointFingerprint != r.anchor.CandidateFingerprint || !reflect.DeepEqual(p.policy.EndpointPublic, r.anchor.CandidatePublic) || p.policy.LocalUserScope != r.anchor.LocalUserScope || p.policy.NetworkID != r.anchor.NetworkID {
		return nil, ErrNetworkPermission
	}
	if p.state != "PENDING_KEY" && p.state != "ACTIVE" {
		return nil, ErrNetworkPermission
	}
	verified, err := e2ee.VerifyOwnerEndpointGroupPolicy(p.policy.OwnerPublic, p.proof, in.At)
	if err != nil || !reflect.DeepEqual(verified, p.policy) || wire.ValidateOwnerEndpointGroupsPolicy(p.policy, in.Hub, in.At) != nil {
		return nil, ErrNetworkPermission
	}
	key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, p.policy.OwnerID, p.policy.OwnerPublic.ID))
	if err != nil || key.State != OwnerApprovalKeyActive || uint64(key.Version) != p.policy.OwnerKeyVersion || !reflect.DeepEqual(key.Public, p.policy.OwnerPublic) || !activeSelfOwnedHuman(tx, p.policy.OwnerID) {
		return nil, ErrNetworkPermission
	}
	b, err := endpointGroupsNodeTx(tx, p.policy.OwnerID, p.policy.Node.NodeID, in.Hub, in.NodeControlPublic)
	if err != nil {
		return nil, err
	}
	expected, current := p.policy.Node, appNodeBindingPublic(*b)
	expected.NodeName = ""
	current.NodeName = ""
	if !reflect.DeepEqual(expected, current) || endpointGroupsRegistrationLeaseTx(tx, r, in.At) != nil {
		return nil, ErrNetworkPermission
	}
	latest, err := endpointGroupsPolicyForRelationTx(tx, r, group)
	if err != nil || latest == nil || latest.policy.PolicyID != id {
		return nil, ErrNetworkPermission
	}
	return p, nil
}

func endpointGroupsNodeCASTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, p *hubEndpointGroupsPolicy, at time.Time) (wire.OwnerEndpointGroupsCAS, wire.OwnerEndpointGroupsRelationCard, error) {
	var c wire.OwnerEndpointGroupsCAS
	card, _, _, err := endpointGroupsResolveTx(tx, r, p.policy.GroupID, at, true)
	if err != nil {
		return c, card, err
	}
	g, err := endpointGroupsGroupTx(tx, p.policy.OwnerID, p.policy.NetworkID, p.policy.GroupID)
	if err != nil {
		return c, card, err
	}
	var nv uint64
	if tx.QueryRow(`SELECT version FROM networks_v2 WHERE id=? AND hub_id=? AND owner_id=? AND state='ACTIVE' AND context_policy=''`, p.policy.NetworkID, p.policy.HubID, p.policy.OwnerID).Scan(&nv) != nil || nv == 0 {
		return c, card, ErrNetworkPermission
	}
	digest, err := e2ee.EndpointGroupOwnerControlDigest(r.nativeDigest, p.policy.GroupID, card.OwnerControl)
	if err != nil {
		return c, card, err
	}
	c = wire.OwnerEndpointGroupsCAS{OwnerKeyVersion: p.policy.OwnerKeyVersion, NodeOwnerBindingID: p.policy.Node.OwnerBindingID, NodeOwnerBindingVersion: p.policy.Node.BindingVersion, NodeKeyEpoch: p.policy.Node.NodeKeyEpoch, NetworkVersion: nv, GroupVersion: uint64(g.Version), RegistrationDigest: r.anchor.RegistrationDigest, RegistrationRevision: r.anchor.RegistrationRevision, BindingID: r.anchor.BindingID, BindingEpoch: r.anchor.BindingEpoch, CandidateVersion: r.anchor.CandidateVersion, CandidateProofDigest: r.anchor.CandidateProofDigest, CandidateFingerprint: r.anchor.CandidateFingerprint, RelationRevision: card.RelationRevision, DecisionRevision: card.OwnerControl.Revision, OwnerControlDigest: digest, PolicyEpoch: p.policy.Epoch}
	m, err := endpointGroupsMemberTx(tx, p.policy.PrincipalID, p.policy.GroupID)
	if err != nil {
		return c, card, err
	}
	if m != nil {
		c.MembershipRevision = uint64(m.Revision)
	}
	_, c.EndpointJoinRevision, err = endpointGroupsJoinTx(tx, p.policy.EndpointID, p.policy.GroupID)
	return c, card, err
}

// The projection names the existing Principal and Endpoint, never a fresh key.
// Shared rows already supplying the minimal rights are retained unchanged.
func endpointGroupsNodeMembershipProjectionTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, c wire.OwnerEndpointGroupsCAS, at time.Time) (uint64, uint64, bool, bool, error) {
	if err := endpointGroupsAdmissionSafeTx(tx, r, group, at); err != nil {
		return 0, 0, false, false, err
	}
	m, err := endpointGroupsMemberTx(tx, r.anchor.Registration.PrincipalID, group)
	if err != nil {
		return 0, 0, false, false, err
	}
	changeMember := m == nil || !endpointGroupsMemberGrants(m)
	if m != nil && (!networkEffectiveAllows(m.EffectiveAt, at) || !networkExpiryAllows(m.ExpiresAt, at)) {
		origin, e := readLocalDomain(tx, r.originPolicy)
		if e != nil || origin == nil || origin.policy.GroupID != group || m.ExpiresAt != origin.policy.ExpiresAt || !endpointGroupsMemberGrants(m) {
			return 0, 0, false, false, ErrNetworkPermission
		}
	}
	if changeMember {
		var others int
		if tx.QueryRow(`SELECT count(*) FROM endpoint_group_memberships j JOIN fabric_endpoints e ON e.id=j.endpoint_id WHERE j.group_id=? AND e.principal_id=? AND e.id!=? AND j.status='active'`, group, r.anchor.Registration.PrincipalID, r.anchor.Registration.EndpointID).Scan(&others) != nil || others != 0 {
			return 0, 0, false, false, ErrNetworkPermission
		}
		if m != nil && (m.Role != "member" || len(m.Authorization) != 0 || len(m.Grants) != 0 || len(m.Roles) != 0) {
			return 0, 0, false, false, ErrNetworkPermission
		}
	}
	status, jr, err := endpointGroupsJoinTx(tx, r.anchor.Registration.EndpointID, group)
	if err != nil || jr != c.EndpointJoinRevision {
		return 0, 0, false, false, ErrNetworkPermission
	}
	mr := c.MembershipRevision
	if changeMember {
		mr++
	}
	changeJoin := status != "active"
	if changeJoin {
		jr++
	}
	if mr == 0 || jr == 0 || mr >= 1<<63 || jr >= 1<<63 {
		return 0, 0, false, false, ErrNetworkPermission
	}
	return mr, jr, changeMember, changeJoin, nil
}

func endpointGroupsNodeChallengeTx(tx *sql.Tx, in HubEndpointGroupsNodeInput, r *hubEndpointGroupsRegistration, p *hubEndpointGroupsPolicy, id, observed, expires string) (wire.EndpointGroupKeyPrepareResult, e2ee.EndpointGroupOwnerControl, error) {
	var out wire.EndpointGroupKeyPrepareResult
	c, card, err := endpointGroupsNodeCASTx(tx, r, p, in.At)
	if err != nil || p.state != "PENDING_KEY" || c.DecisionRevision != p.policy.ExpectedDecisionRevision || c.OwnerControlDigest != p.policy.ExpectedOwnerControlDigest {
		return out, card.OwnerControl, ErrNetworkPermission
	}
	mr, jr, _, _, err := endpointGroupsNodeMembershipProjectionTx(tx, r, p.policy.GroupID, c, in.At)
	if err != nil {
		return out, card.OwnerControl, err
	}
	projected := c
	projected.MembershipRevision = mr
	projected.EndpointJoinRevision = jr
	manifest, err := endpointGroupsManifestTx(tx, r, p.policy, projected)
	if err != nil {
		return out, card.OwnerControl, err
	}
	manifest.IssuedAt = observed
	manifest.CandidateBindingDigest, err = wire.LocalDomainGroupBindingDigest(manifest)
	if err != nil {
		return out, card.OwnerControl, err
	}
	manifest.Digest, err = wire.LocalDomainGroupManifestDigest(manifest)
	if err != nil {
		return out, card.OwnerControl, err
	}
	head := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: card.OwnerControl.Revision + 1, DenyReason: "NONE", PolicyID: p.policy.PolicyID, PolicyEpoch: p.policy.Epoch}
	hd, err := e2ee.EndpointGroupOwnerControlDigest(r.nativeDigest, p.policy.GroupID, head)
	if err != nil {
		return out, card.OwnerControl, err
	}
	v := p.policy
	relation := wire.EndpointGroupRelation{HubID: v.HubID, OwnerID: v.OwnerID, NodeID: v.Node.NodeID, LocalUserScope: v.LocalUserScope, NetworkID: v.NetworkID, GroupID: v.GroupID, EndpointID: v.EndpointID, PrincipalID: v.PrincipalID, RegistrationDigest: v.RegistrationDigest, RegistrationRevision: v.RegistrationRevision, Source: "OWNER_EXPLICIT", AuthorityID: v.PolicyID, AuthorityEpoch: v.Epoch, ContributionRevision: p.revision + 1, State: "ACTIVE", DecisionRevision: head.Revision, OwnerControlDigest: hd, PolicyID: v.PolicyID, PolicyEpoch: v.Epoch, BindingID: v.BindingID, BindingEpoch: v.BindingEpoch, MembershipRevision: mr, EndpointJoinRevision: jr, CandidateVersion: v.CandidateVersion, CandidateKeyID: v.EndpointKeyID, CandidateFingerprint: v.EndpointFingerprint, CandidateProofDigest: v.CandidateProofDigest, ExpiresAt: v.ExpiresAt}
	out = wire.EndpointGroupKeyPrepareResult{ChallengeID: id, PolicyID: v.PolicyID, PolicyEpoch: v.Epoch, Expected: c, ProjectedOwnerControl: head, ProjectedRelation: relation, ProjectedKeyManifest: manifest, ObservedAt: observed, ExpiresAt: expires}
	out.ChallengeDigest, err = wire.EndpointGroupKeyChallengeDigest(out)
	return out, card.OwnerControl, err
}

func endpointGroupsNodeKeyPrepareTx(tx *sql.Tx, in HubEndpointGroupsNodeInput, r *hubEndpointGroupsRegistration, q wire.EndpointGroupsNodeKeyPrepare) (any, error) {
	p, err := endpointGroupsNodePolicyTx(tx, in, r, q.PolicyID, q.GroupID, q.PolicyEpoch)
	if err != nil {
		return nil, err
	}
	c, card, err := endpointGroupsNodeCASTx(tx, r, p, in.At)
	if err != nil || c.RelationRevision != q.ExpectedRelationRevision {
		return nil, ErrNetworkPermission
	}
	result := wire.EndpointGroupsNodeKeyResult{ContractRevision: wire.OwnerEndpointGroupsContractRevision, Registration: r.anchor, PolicyProof: append([]byte(nil), p.proof...), OwnerControl: card.OwnerControl, ObservedAt: appNodeStamp(in.At)}
	if p.state == "ACTIVE" {
		_, authority, _, e := endpointGroupsResolveTx(tx, r, q.GroupID, in.At, false)
		if e != nil || authority == nil || p.grant == nil || !reflect.DeepEqual(authority.Relation, p.grant.Relation) {
			return nil, ErrNetworkPermission
		}
		result.Grant = p.grant
	} else {
		id, e := wire.NewRequestID()
		if e != nil {
			return nil, e
		}
		end := in.At.Add(5 * time.Minute)
		for _, stamp := range []string{r.anchor.LeaseExpiresAt, p.policy.ExpiresAt} {
			if stamp != "" {
				t, e := time.Parse(time.RFC3339Nano, stamp)
				if e != nil {
					return nil, ErrNetworkPermission
				}
				if t.Before(end) {
					end = t
				}
			}
		}
		if !in.At.Before(end) {
			return nil, ErrNetworkPermission
		}
		challenge, head, e := endpointGroupsNodeChallengeTx(tx, in, r, p, id, result.ObservedAt, appNodeStamp(end))
		if e != nil {
			return nil, e
		}
		result.Challenge = &challenge
		result.OwnerControl = head
		if _, e = tx.Exec(`UPDATE hub_endpoint_groups_key_challenges_v1 SET state='EXPIRED' WHERE endpoint_id=? AND state='PREPARED' AND julianday(expires_at)<=julianday(?)`, q.EndpointID, result.ObservedAt); e != nil {
			return nil, e
		}
		var count int
		if e = tx.QueryRow(`SELECT count(*) FROM hub_endpoint_groups_key_challenges_v1 WHERE endpoint_id=? AND state='PREPARED'`, q.EndpointID).Scan(&count); e != nil {
			return nil, e
		}
		if count >= 128 {
			return nil, ErrHubOwnerDiagnosticsFull
		}
		raw, e := json.Marshal(challenge)
		if e != nil {
			return nil, e
		}
		if _, e = tx.Exec(`INSERT INTO hub_endpoint_groups_key_challenges_v1 VALUES(?,?,?,?,?,?,'PREPARED',?,?)`, id, q.PolicyID, q.EndpointID, q.GroupID, q.ExpectedRelationRevision, string(raw), challenge.ExpiresAt, result.ObservedAt); e != nil {
			return nil, e
		}
	}
	if _, err = wire.ValidateEndpointGroupsNodeKeyResult(result, in.Hub, p.policy.OwnerID, p.policy.OwnerPublic, in.At); err != nil {
		return nil, ErrNetworkPermission
	}
	return result, nil
}

func endpointGroupsNodeInstallMembershipTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, c wire.OwnerEndpointGroupsCAS, at time.Time) error {
	_, _, member, join, err := endpointGroupsNodeMembershipProjectionTx(tx, r, group, c, at)
	if err != nil {
		return err
	}
	stamp := appNodeStamp(at)
	rights, _ := json.Marshal(e2ee.EndpointGroupRights())
	if member {
		var res sql.Result
		if c.MembershipRevision == 0 {
			res, err = tx.Exec(`INSERT INTO memberships(id,principal_id,group_id,role,roles_json,grants_json,status,effective_at,expires_at,revoked_at,revocation_reason,revision,authorization_json,version,created_at,updated_at) VALUES(?,?,?,'member','[]',?,'active','','','','',1,'{}',1,?,?)`, NewID("mem"), r.anchor.Registration.PrincipalID, group, string(rights), stamp, stamp)
		} else {
			res, err = tx.Exec(`UPDATE memberships SET grants_json=?,status='active',effective_at='',expires_at='',revoked_at='',revocation_reason='',revision=revision+1,version=version+1,updated_at=? WHERE principal_id=? AND group_id=? AND revision=?`, string(rights), stamp, r.anchor.Registration.PrincipalID, group, c.MembershipRevision)
		}
		if err != nil {
			return err
		}
		if n, e := res.RowsAffected(); e != nil || n != 1 {
			return ErrNetworkPermission
		}
	}
	if join {
		var res sql.Result
		if c.EndpointJoinRevision == 0 {
			res, err = tx.Exec(`INSERT INTO endpoint_group_memberships(endpoint_id,group_id,status,revision,created_at,updated_at) VALUES(?,?,'active',1,?,?)`, r.anchor.Registration.EndpointID, group, stamp, stamp)
		} else {
			res, err = tx.Exec(`UPDATE endpoint_group_memberships SET status='active',revision=revision+1,updated_at=? WHERE endpoint_id=? AND group_id=? AND revision=?`, stamp, r.anchor.Registration.EndpointID, group, c.EndpointJoinRevision)
		}
		if err != nil {
			return err
		}
		if n, e := res.RowsAffected(); e != nil || n != 1 {
			return ErrNetworkPermission
		}
	}
	return nil
}

func endpointGroupsNodeKeyCompleteTx(tx *sql.Tx, in HubEndpointGroupsNodeInput, r *hubEndpointGroupsRegistration, q wire.EndpointGroupsNodeKeyComplete) (any, error) {
	p, err := endpointGroupsNodePolicyTx(tx, in, r, q.PolicyID, q.GroupID, q.PolicyEpoch)
	if err != nil || p.state != "PENDING_KEY" {
		return nil, ErrNetworkPermission
	}
	var raw, state, expires, policy, endpoint, group string
	var revision uint64
	err = tx.QueryRow(`SELECT challenge_json,state,expires_at,policy_id,endpoint_id,group_id,expected_relation_revision FROM hub_endpoint_groups_key_challenges_v1 WHERE challenge_id=?`, q.ChallengeID).Scan(&raw, &state, &expires, &policy, &endpoint, &group, &revision)
	if err != nil || state != "PREPARED" || !appNodeBefore(in.At, expires) || policy != q.PolicyID || endpoint != q.EndpointID || group != q.GroupID || revision != q.ExpectedRelationRevision {
		return nil, ErrNetworkPermission
	}
	var challenge wire.EndpointGroupKeyPrepareResult
	if json.Unmarshal([]byte(raw), &challenge) != nil || challenge.ChallengeID != q.ChallengeID || challenge.ExpiresAt != expires || challenge.Expected.RelationRevision != revision {
		return nil, ErrNetworkPermission
	}
	current, old, err := endpointGroupsNodeChallengeTx(tx, in, r, p, q.ChallengeID, challenge.ObservedAt, challenge.ExpiresAt)
	if err != nil || !reflect.DeepEqual(current, challenge) {
		return nil, ErrNetworkPermission
	}
	claims, err := wire.EndpointGroupKeyClaimsForChallenge(challenge, p.policy)
	if err != nil {
		return nil, err
	}
	signed, err := e2ee.VerifyEndpointGroupKey(p.policy, q.NodeProof, in.At)
	if err != nil || !reflect.DeepEqual(claims, signed) {
		return nil, ErrNetworkPermission
	}
	card, _, _, err := endpointGroupsResolveTx(tx, r, q.GroupID, in.At, false)
	if err != nil {
		return nil, err
	}
	allowed, err := endpointGroupsAddWithinLimitTx(tx, r, card, in.At)
	if err != nil || !allowed {
		return nil, ErrNetworkPermission
	}
	grant := wire.EndpointGroupDelegatedGrant{Relation: challenge.ProjectedRelation, Manifest: challenge.ProjectedKeyManifest, PolicyProof: append([]byte(nil), p.proof...), NodeProof: append([]byte(nil), q.NodeProof...)}
	if _, err = wire.VerifyEndpointGroupDelegatedGrant(grant, in.Hub, p.policy.OwnerID, p.policy.OwnerPublic, in.At); err != nil {
		return nil, ErrNetworkPermission
	}
	if err = endpointGroupsNodeInstallMembershipTx(tx, r, q.GroupID, challenge.Expected, in.At); err != nil {
		return nil, err
	}
	grantRaw, err := json.Marshal(grant)
	if err != nil {
		return nil, err
	}
	changed, err := tx.Exec(`UPDATE hub_endpoint_groups_policies_v1 SET state='ACTIVE',contribution_revision=contribution_revision+1,grant_json=?,updated_at=? WHERE policy_id=? AND state='PENDING_KEY' AND contribution_revision=?`, string(grantRaw), appNodeStamp(in.At), q.PolicyID, p.revision)
	if err != nil {
		return nil, err
	}
	if n, e := changed.RowsAffected(); e != nil || n != 1 {
		return nil, ErrNetworkPermission
	}
	if err = endpointGroupsSetHeadTx(tx, r, q.GroupID, old, challenge.ProjectedOwnerControl, in.At); err != nil {
		return nil, err
	}
	row, err := endpointGroupsRelationRowTx(tx, r, q.GroupID)
	if err != nil {
		return nil, err
	}
	if err = endpointGroupsAdvanceRelationTx(tx, r, q.GroupID, row.defaultStamp, false, in.At); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`UPDATE hub_endpoint_groups_key_challenges_v1 SET state=CASE WHEN challenge_id=? THEN 'COMPLETED' ELSE 'INVALIDATED' END WHERE policy_id=? AND state='PREPARED'`, q.ChallengeID, q.PolicyID); err != nil {
		return nil, err
	}
	result := wire.EndpointGroupsNodeKeyResult{ContractRevision: wire.OwnerEndpointGroupsContractRevision, Registration: r.anchor, PolicyProof: append([]byte(nil), p.proof...), Grant: &grant, OwnerControl: challenge.ProjectedOwnerControl, ObservedAt: appNodeStamp(in.At)}
	if _, err = wire.ValidateEndpointGroupsNodeKeyResult(result, in.Hub, p.policy.OwnerID, p.policy.OwnerPublic, in.At); err != nil {
		return nil, ErrNetworkPermission
	}
	return result, nil
}
