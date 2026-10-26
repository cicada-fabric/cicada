package store

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func endpointGroupsScopeTx(tx *sql.Tx, in HubEndpointGroupsInput, a *hubAppNodeActor, node, network string) (*NodeControlKeyBinding, uint64, error) {
	if a == nil || a.root != wire.RootActiveState || !a.source {
		return nil, 0, ErrNetworkPermission
	}
	b, err := endpointGroupsNodeTx(tx, a.scope.OwnerID, node, in.Hub, in.NodeControlPublic)
	if err != nil {
		return nil, 0, err
	}
	var version uint64
	if tx.QueryRow(`SELECT version FROM networks_v2 WHERE id=? AND hub_id=? AND owner_id=? AND state='ACTIVE' AND context_policy=''`, network, in.Hub.HubID, a.scope.OwnerID).Scan(&version) != nil || version == 0 {
		return nil, 0, ErrNetworkPermission
	}
	return b, version, nil
}

func endpointGroupsCASTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, g *Group, a *hubAppNodeActor, b *NodeControlKeyBinding, networkVersion uint64, at time.Time) (wire.OwnerEndpointGroupsCAS, wire.OwnerEndpointGroupsRelationCard, error) {
	card, _, _, err := endpointGroupsResolveTx(tx, r, g.ID, at, true)
	if err != nil {
		return wire.OwnerEndpointGroupsCAS{}, card, err
	}
	h := card.OwnerControl
	digest, err := e2ee.EndpointGroupOwnerControlDigest(r.nativeDigest, g.ID, h)
	if err != nil {
		return wire.OwnerEndpointGroupsCAS{}, card, err
	}
	c := wire.OwnerEndpointGroupsCAS{OwnerKeyVersion: a.scope.OwnerKeyVersion, NodeOwnerBindingID: b.OwnerBindingID, NodeOwnerBindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, NetworkVersion: networkVersion, GroupVersion: uint64(g.Version), RegistrationDigest: r.anchor.RegistrationDigest, RegistrationRevision: r.anchor.RegistrationRevision, BindingID: r.anchor.BindingID, BindingEpoch: r.anchor.BindingEpoch, CandidateVersion: r.anchor.CandidateVersion, CandidateProofDigest: r.anchor.CandidateProofDigest, CandidateFingerprint: r.anchor.CandidateFingerprint, RelationRevision: card.RelationRevision, DecisionRevision: h.Revision, OwnerControlDigest: digest}
	m, err := endpointGroupsMemberTx(tx, r.anchor.Registration.PrincipalID, g.ID)
	if err != nil {
		return c, card, err
	}
	if m != nil {
		c.MembershipRevision = uint64(m.Revision)
	}
	_, c.EndpointJoinRevision, err = endpointGroupsJoinTx(tx, r.anchor.Registration.EndpointID, g.ID)
	if err != nil {
		return c, card, err
	}
	p, err := endpointGroupsPolicyForRelationTx(tx, r, g.ID)
	if err != nil {
		return c, card, err
	}
	if p != nil {
		c.PolicyEpoch = p.policy.Epoch
	}
	return c, card, nil
}

func endpointGroupsManifestTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, p e2ee.EndpointGroupPolicy, c wire.OwnerEndpointGroupsCAS) (wire.LocalDomainKeyManifest, error) {
	side, err := readCommunicationLinkKeySide(tx, r.anchor.Registration.EndpointID, p.GroupID, r.anchor.Registration.PrincipalID, r.anchor.Registration.OwnerID, r.anchor.Registration.NodeID, r.anchor.BindingID, r.anchor.BindingEpoch)
	if err != nil {
		return wire.LocalDomainKeyManifest{}, err
	}
	m := wire.LocalDomainKeyManifest{Version: 1, Operation: "group-endpoint-key-grant:v1", HubID: p.HubID, OwnerID: p.OwnerID, PrincipalID: p.PrincipalID, GroupID: p.GroupID, GroupRevision: int64(c.GroupVersion), EndpointID: p.EndpointID, NodeID: p.Node.NodeID, BindingID: p.BindingID, BindingEpoch: p.BindingEpoch, MembershipRevision: int64(c.MembershipRevision), EndpointJoinRevision: int64(c.EndpointJoinRevision), CandidateVersion: int64(p.CandidateVersion), CandidateKeyID: p.EndpointKeyID, CandidateFingerprint: p.EndpointFingerprint, CandidateProofDigest: p.CandidateProofDigest, CandidatePublicIdentity: p.EndpointPublic, CandidateAttestation: side.Attestation, OwnerKeyID: p.OwnerPublic.ID, IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt}
	m.CandidateBindingDigest, err = wire.LocalDomainGroupBindingDigest(m)
	if err != nil {
		return m, err
	}
	m.Digest, err = wire.LocalDomainGroupManifestDigest(m)
	return m, err
}

// Review creation snapshots only existing original identity. No business
// membership or Group authority is installed until its exact approved apply.
func endpointGroupsPrepareTx(tx *sql.Tx, in HubEndpointGroupsInput, a *hubAppNodeActor, q wire.OwnerEndpointGroupsPrepareRequest) (wire.OwnerEndpointGroupsReview, string, error) {
	var review wire.OwnerEndpointGroupsReview
	b, nv, err := endpointGroupsScopeTx(tx, in, a, q.Body.NodeID, q.Body.NetworkID)
	if err != nil {
		return review, "TARGET_NOT_AUTHORIZED", nil
	}
	id, err := wire.NewRequestID()
	if err != nil {
		return review, "", err
	}
	var proof e2ee.OwnerEndpointGroupsRequestProof
	if json.Unmarshal(q.OwnerProof, &proof) != nil {
		return review, "TARGET_NOT_AUTHORIZED", nil
	}
	end, err := time.Parse(time.RFC3339Nano, proof.Claims.ExpiresAt)
	if err != nil || !in.At.Before(end) {
		return review, "REVIEW_EXPIRED", nil
	}
	review = wire.OwnerEndpointGroupsReview{ReviewID: id, RequestID: q.Context.RequestID, RequestPacketDigest: wire.OwnerEndpointGroupsPacketDigest(in.Packet), Action: q.Body.Action, ObservedAt: appNodeStamp(in.At), ExpiresAt: appNodeStamp(end), Target: wire.OwnerEndpointGroupsTarget{HubID: in.Hub.HubID, OwnerID: a.scope.OwnerID, NodeID: b.NodeID, NetworkID: q.Body.NetworkID, GroupID: q.Body.GroupID}}
	review.Expected = wire.OwnerEndpointGroupsCAS{OwnerKeyVersion: a.scope.OwnerKeyVersion, NodeOwnerBindingID: b.OwnerBindingID, NodeOwnerBindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, NetworkVersion: nv}
	if q.Body.Action == wire.OwnerEndpointGroupsCreateGroup {
		yes := true
		review.Target.GroupID = NewID("grp")
		review.Target.Name = q.Body.Name
		review.Target.ContextPolicy = "group_scoped"
		review.Projection = wire.OwnerEndpointGroupsProjection{GroupID: review.Target.GroupID, Name: q.Body.Name, ContextPolicy: "group_scoped", OwnerManagementOnly: &yes}
	} else {
		r, e := endpointGroupsEnsureRegistrationTx(tx, a.scope.OwnerID, b.NodeID, q.Body.NetworkID, q.Body.EndpointID, in.Hub, in.NodeControlPublic, in.At)
		if e != nil {
			return review, "UNSUPPORTED_PROFILE", nil
		}
		g, e := endpointGroupsGroupTx(tx, a.scope.OwnerID, q.Body.NetworkID, q.Body.GroupID)
		if e != nil {
			return review, "TARGET_NOT_AUTHORIZED", nil
		}
		if g.Revision != g.Version {
			return review, "UNSUPPORTED_PROFILE", nil
		}
		if err = guardDedicatedThreadGroupEndpointTx(tx, r.anchor.Registration.EndpointID, g.ID, in.At); err != nil {
			return review, "TARGET_NOT_AUTHORIZED", nil
		}
		c, card, e := endpointGroupsCASTx(tx, r, g, a, b, nv, in.At)
		if e != nil {
			return review, "", e
		}
		review.Expected = c
		review.Target.LocalUserScope = r.anchor.LocalUserScope
		review.Target.EndpointID = r.anchor.Registration.EndpointID
		review.Target.PrincipalID = r.anchor.Registration.PrincipalID
		review.Target.RegistrationDigest = r.anchor.RegistrationDigest
		if q.Body.Action == wire.OwnerEndpointGroupsRemoveEndpoint {
			yes := true
			review.Projection = wire.OwnerEndpointGroupsProjection{Source: "OWNER_EXPLICIT", RelationState: "REMOVED", ManualDeny: &yes, WithdrawScope: "EXACT_ENDPOINT_GROUP"}
		} else {
			old, e := endpointGroupsPolicyForRelationTx(tx, r, g.ID)
			if e != nil {
				return review, "", e
			}
			if old != nil && old.state == "ACTIVE" {
				return review, "MANUAL_SOURCE_ALREADY_ACTIVE", nil
			}
			if old != nil && old.state == "PENDING_KEY" {
				return review, "RELATION_PENDING", nil
			}
			withinLimit, e := endpointGroupsAddWithinLimitTx(tx, r, card, in.At)
			if e != nil {
				return review, "", e
			}
			if !withinLimit {
				return review, "GROUP_RELATION_LIMIT", nil
			}
			if e = endpointGroupsAdmissionSafeTx(tx, r, g.ID, in.At); e != nil {
				return review, "SHARED_MEMBERSHIP_CONFLICT", nil
			}
			policyID, e := wire.NewRequestID()
			if e != nil {
				return review, "", e
			}
			nonce, e := wire.NewNonce()
			if e != nil {
				return review, "", e
			}
			expiry, e := wire.EndpointGroupDurationExpiry(q.Body.Duration, in.At)
			if e != nil {
				return review, "TARGET_NOT_AUTHORIZED", nil
			}
			p := e2ee.EndpointGroupPolicy{Version: 1, Purpose: e2ee.OwnerEndpointGroupsPolicyPurpose, PolicyID: policyID, Epoch: c.PolicyEpoch + 1, Origin: a.scope.Origin, HubID: in.Hub.HubID, HubFingerprint: a.scope.HubFingerprint, OwnerID: a.scope.OwnerID, OwnerPublic: a.scope.OwnerPublic, OwnerKeyVersion: a.scope.OwnerKeyVersion, Node: appNodeBindingPublic(*b), LocalUserScope: r.anchor.LocalUserScope, NetworkID: r.anchor.NetworkID, GroupID: g.ID, EndpointID: r.anchor.Registration.EndpointID, PrincipalID: r.anchor.Registration.PrincipalID, RegistrationDigest: r.anchor.RegistrationDigest, RegistrationRevision: r.anchor.RegistrationRevision, BindingID: r.anchor.BindingID, BindingEpoch: r.anchor.BindingEpoch, EndpointKeyID: r.anchor.CandidateKeyID, EndpointPublic: r.anchor.CandidatePublic, EndpointFingerprint: r.anchor.CandidateFingerprint, CandidateVersion: r.anchor.CandidateVersion, CandidateProofDigest: r.anchor.CandidateProofDigest, ExpectedOwnerControlDigest: c.OwnerControlDigest, ExpectedDecisionRevision: c.DecisionRevision, Rights: e2ee.EndpointGroupRights(), IssuedAt: review.ObservedAt, ExpiresAt: expiry, ReviewID: id, ServerNonce: hex.EncodeToString(nonce)}
			core := p.Core()
			grants := []string{}
			head := card.OwnerControl
			next := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: head.Revision + 1, DenyReason: "NONE", PolicyID: policyID, PolicyEpoch: p.Epoch}
			state := card.State
			if state == "NONE" {
				state = "PENDING_KEY"
			}
			review.Projection = wire.OwnerEndpointGroupsProjection{Source: "OWNER_EXPLICIT", ContributionState: "PENDING_KEY", EffectiveRelationState: state, Grants: &grants, ProjectedRights: e2ee.EndpointGroupRights(), Duration: q.Body.Duration, ExpectedOwnerControl: &head, CompletionOwnerControl: &next, PolicyCore: &core}
			manifest, e := endpointGroupsManifestTx(tx, r, p, c)
			if e != nil {
				return review, "", e
			}
			review.KeyManifest = &manifest
			review.Policy = &p
		}
	}
	review.ReviewDigest, err = wire.OwnerEndpointGroupsReviewDigest(review)
	if err != nil {
		return review, "", err
	}
	if review.Policy != nil {
		review.Policy.ReviewDigest = review.ReviewDigest
	}
	return review, "", nil
}

// Shared Principal rows are only reused when they already contain the exact
// minimal rights and remain current. Activation never widens another Endpoint.
func endpointGroupsAdmissionSafeTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, at time.Time) error {
	m, err := endpointGroupsMemberTx(tx, r.anchor.Registration.PrincipalID, group)
	if err != nil || m == nil {
		return err
	}
	var others int
	if err = tx.QueryRow(`SELECT count(*) FROM endpoint_group_memberships j JOIN fabric_endpoints e ON e.id=j.endpoint_id WHERE j.group_id=? AND e.principal_id=? AND e.id!=? AND j.status='active'`, group, r.anchor.Registration.PrincipalID, r.anchor.Registration.EndpointID).Scan(&others); err != nil {
		return err
	}
	if others > 0 && (!endpointGroupsMemberGrants(m) || !networkExpiryAllows(m.ExpiresAt, at) || !networkEffectiveAllows(m.EffectiveAt, at)) {
		return ErrNetworkPermission
	}
	// Reusing a finite unrelated shared membership would promise rights that
	// this per-source delegation cannot deliver without altering its owner.
	if others > 0 && m.ExpiresAt != "" {
		return ErrNetworkPermission
	}
	return nil
}

// The limit counts effective Group relations, including default sources;
// terminal history and a second source for the same active Group do not count.
func endpointGroupsAddWithinLimitTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, target wire.OwnerEndpointGroupsRelationCard, at time.Time) (bool, error) {
	if target.State == "ACTIVE" {
		return true, nil
	}
	cards, err := endpointGroupsRelationCardsTx(tx, r, at)
	if err != nil {
		return false, err
	}
	active := 0
	for _, card := range cards {
		if card.State == "ACTIVE" {
			active++
		}
	}
	return active < 32, nil
}

func endpointGroupsApplyTx(tx *sql.Tx, in HubEndpointGroupsInput, a *hubAppNodeActor, q wire.OwnerEndpointGroupsApplyRequest, review wire.OwnerEndpointGroupsReview) (wire.OwnerEndpointGroupsOperation, string, error) {
	op := wire.OwnerEndpointGroupsOperation{OperationID: q.Context.RequestID, OriginalPacketDigest: wire.OwnerEndpointGroupsPacketDigest(in.Packet), Action: review.Action, State: "COMPLETED", ReviewID: review.ReviewID, Target: review.Target, CommittedAt: appNodeStamp(in.At)}
	b, nv, err := endpointGroupsScopeTx(tx, in, a, review.Target.NodeID, review.Target.NetworkID)
	if err != nil {
		return op, "TARGET_NOT_AUTHORIZED", nil
	}
	base := wire.OwnerEndpointGroupsCAS{OwnerKeyVersion: a.scope.OwnerKeyVersion, NodeOwnerBindingID: b.OwnerBindingID, NodeOwnerBindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, NetworkVersion: nv}
	if review.Action == wire.OwnerEndpointGroupsCreateGroup {
		if base != review.Expected {
			return op, "CAS_CONFLICT", nil
		}
		var trust string
		if tx.QueryRow(`SELECT trust_domain_id FROM principals WHERE id=? AND kind='human' AND status='active'`, a.scope.OwnerID).Scan(&trust) != nil {
			return op, "TARGET_NOT_AUTHORIZED", nil
		}
		_, err = insertGroupWithOwnerMembershipTx(tx, Group{ID: review.Target.GroupID, NetworkID: review.Target.NetworkID, OwnerPrincipalID: a.scope.OwnerID, TrustDomainID: trust, Name: review.Target.Name, State: GroupStateActive, Revision: 1, ContextPolicy: "group_scoped", Version: 1}, in.At, "")
		if err != nil {
			return op, "", err
		}
		if _, err = tx.Exec(`INSERT INTO hub_endpoint_groups_listings_v1 VALUES(?,?,?,1) ON CONFLICT(owner_id,node_id,network_id) DO UPDATE SET revision=revision+1`, a.scope.OwnerID, b.NodeID, review.Target.NetworkID); err != nil {
			return op, "", err
		}
		yes := true
		op.Effect = &wire.OwnerEndpointGroupsEffect{GroupID: review.Target.GroupID, Created: &yes}
		return op, "", nil
	}
	r, err := endpointGroupsRegistrationTx(tx, review.Target.EndpointID)
	if err != nil {
		return op, "", err
	}
	if r == nil || r.anchor.Registration.OwnerID != a.scope.OwnerID || r.anchor.Registration.NodeID != b.NodeID || r.anchor.NetworkID != review.Target.NetworkID || endpointGroupsRegistrationCurrentTx(tx, r, in.At) != nil {
		return op, "TARGET_NOT_AUTHORIZED", nil
	}
	g, err := endpointGroupsGroupTx(tx, a.scope.OwnerID, r.anchor.NetworkID, review.Target.GroupID)
	if err != nil {
		return op, "TARGET_NOT_AUTHORIZED", nil
	}
	c, card, err := endpointGroupsCASTx(tx, r, g, a, b, nv, in.At)
	if err != nil {
		return op, "", err
	}
	if c != review.Expected || g.Revision != g.Version {
		return op, "CAS_CONFLICT", nil
	}
	if err = guardDedicatedThreadGroupEndpointTx(tx, r.anchor.Registration.EndpointID, g.ID, in.At); err != nil {
		return op, "TARGET_NOT_AUTHORIZED", nil
	}
	row, err := endpointGroupsRelationRowTx(tx, r, g.ID)
	if err != nil {
		return op, "", err
	}
	head := card.OwnerControl
	if review.Action == wire.OwnerEndpointGroupsAddEndpoint {
		if review.Policy == nil || review.Projection.ExpectedOwnerControl == nil || *review.Projection.ExpectedOwnerControl != head {
			return op, "CAS_CONFLICT", nil
		}
		p, err := e2ee.VerifyOwnerEndpointGroupPolicy(a.scope.OwnerPublic, q.Body.PolicyProof, in.At)
		if err != nil || !reflect.DeepEqual(p, *review.Policy) {
			return op, "TARGET_NOT_AUTHORIZED", nil
		}
		if err = endpointGroupsAdmissionSafeTx(tx, r, g.ID, in.At); err != nil {
			return op, "SHARED_MEMBERSHIP_CONFLICT", nil
		}
		withinLimit, err := endpointGroupsAddWithinLimitTx(tx, r, card, in.At)
		if err != nil {
			return op, "", err
		}
		if !withinLimit {
			return op, "GROUP_RELATION_LIMIT", nil
		}
		old, err := endpointGroupsPolicyForRelationTx(tx, r, g.ID)
		if err != nil {
			return op, "", err
		}
		if old != nil && (old.state == "ACTIVE" || old.state == "PENDING_KEY") {
			return op, "CAS_CONFLICT", nil
		}
		raw, _ := json.Marshal(p)
		_, err = tx.Exec(`INSERT INTO hub_endpoint_groups_policies_v1 VALUES(?,?,?,?,?,?,?,'PENDING_KEY',1,'',?,?)`, p.PolicyID, r.nativeDigest, p.EndpointID, p.GroupID, p.Epoch, string(raw), q.Body.PolicyProof, appNodeStamp(in.At), appNodeStamp(in.At))
		if err != nil {
			return op, "", err
		}
		if row.revision == 0 { // First admitted source owns aggregate revision one.
			if _, err = endpointGroupsEnsureRelationTx(tx, r, g.ID, in.At); err != nil {
				return op, "", err
			}
		} else if err = endpointGroupsAdvanceRelationTx(tx, r, g.ID, row.defaultStamp, false, in.At); err != nil {
			return op, "", err
		}
		revision := c.RelationRevision + 1
		decision := head.Revision
		state := card.State
		if state == "NONE" {
			state = "PENDING_KEY"
		}
		op.Effect = &wire.OwnerEndpointGroupsEffect{GroupID: g.ID, EndpointID: p.EndpointID, RelationRevision: &revision, DecisionRevision: &decision, PolicyID: p.PolicyID, PolicyEpoch: p.Epoch, ContributionRevision: 1, ContributionState: "PENDING_KEY", EffectiveRelationState: state, OwnerControl: &head}
	} else {
		withdrawn := []wire.EndpointGroupSourceReference{}
		for _, v := range card.Contributions {
			if v.State == "ACTIVE" || v.State == "PENDING_KEY" {
				withdrawn = append(withdrawn, wire.EndpointGroupSourceReference{Source: v.Source, AuthorityID: v.AuthorityID, AuthorityEpoch: v.AuthorityEpoch, ContributionRevision: v.ContributionRevision})
			}
		}
		if _, err = tx.Exec(`UPDATE hub_endpoint_groups_policies_v1 SET state='REVOKED',contribution_revision=contribution_revision+1,updated_at=? WHERE native_digest=? AND group_id=? AND state IN('ACTIVE','PENDING_KEY')`, appNodeStamp(in.At), r.nativeDigest, g.ID); err != nil {
			return op, "", err
		}
		next := head
		next.Mode = "OWNER"
		next.Revision++
		next.DenyReason = "REMOVED"
		if err = endpointGroupsSetHeadTx(tx, r, g.ID, head, next, in.At); err != nil {
			return op, "", err
		}
		if row.revision == 0 {
			// The reviewed aggregate was zero. Its first removal is exactly
			// revision one, with the permanent withdrawal already set at insert.
			if _, err = tx.Exec(`INSERT INTO hub_endpoint_groups_relations_v1 VALUES(?,?,?,1,'',1,?,?)`, r.anchor.Registration.EndpointID, g.ID, r.nativeDigest, appNodeStamp(in.At), appNodeStamp(in.At)); err != nil {
				return op, "", err
			}
			if err = endpointGroupsTouchTx(tx, r); err != nil {
				return op, "", err
			}
		} else if err = endpointGroupsAdvanceRelationTx(tx, r, g.ID, row.defaultStamp, true, in.At); err != nil {
			return op, "", err
		}
		if _, err = tx.Exec(`UPDATE endpoint_group_memberships SET status='revoked',revision=revision+1,updated_at=? WHERE endpoint_id=? AND group_id=? AND status!='revoked'`, appNodeStamp(in.At), r.anchor.Registration.EndpointID, g.ID); err != nil {
			return op, "", err
		}
		if _, err = tx.Exec(`UPDATE hub_endpoint_groups_key_challenges_v1 SET state='INVALIDATED' WHERE endpoint_id=? AND group_id=? AND state='PREPARED'`, r.anchor.Registration.EndpointID, g.ID); err != nil {
			return op, "", err
		}
		revision := c.RelationRevision + 1
		decision := next.Revision
		yes := true
		op.Effect = &wire.OwnerEndpointGroupsEffect{GroupID: g.ID, EndpointID: r.anchor.Registration.EndpointID, RelationRevision: &revision, DecisionRevision: &decision, WithdrawnContributions: &withdrawn, ManualDeny: &yes, RelationState: "REMOVED", OwnerControl: &next}
	}
	return op, "", nil
}

func endpointGroupsCurrentTx(tx *sql.Tx, in HubEndpointGroupsInput, a *hubAppNodeActor, op *wire.OwnerEndpointGroupsOperation) (*wire.OwnerEndpointGroupsRelationCard, *wire.OwnerEndpointGroupsGroupCard, error) {
	if op == nil {
		return nil, nil, nil
	}
	if _, _, err := endpointGroupsScopeTx(tx, in, a, op.Target.NodeID, op.Target.NetworkID); err != nil {
		return nil, nil, nil
	}
	g, err := endpointGroupsGroupTx(tx, a.scope.OwnerID, op.Target.NetworkID, op.Target.GroupID)
	if err != nil {
		if errors.Is(err, ErrNetworkPermission) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	group := endpointGroupsGroupCard(g)
	if op.Action == wire.OwnerEndpointGroupsCreateGroup {
		return nil, &group, nil
	}
	r, err := endpointGroupsRegistrationTx(tx, op.Target.EndpointID)
	if err != nil {
		return nil, nil, err
	}
	if r == nil || r.anchor.Registration.OwnerID != a.scope.OwnerID || r.anchor.Registration.NodeID != op.Target.NodeID || r.anchor.NetworkID != op.Target.NetworkID || endpointGroupsRegistrationCurrentTx(tx, r, in.At) != nil {
		return nil, nil, nil
	}
	card, _, _, err := endpointGroupsResolveTx(tx, r, g.ID, in.At, true)
	if err != nil {
		return nil, nil, err
	}
	return &card, &group, nil
}

func endpointGroupsGroupCard(g *Group) wire.OwnerEndpointGroupsGroupCard {
	return wire.OwnerEndpointGroupsGroupCard{GroupID: g.ID, Name: g.Name, NetworkID: g.NetworkID, GroupVersion: uint64(g.Version), ContextPolicy: g.ContextPolicy, AllowedActions: []string{wire.OwnerEndpointGroupsAddEndpoint}}
}
