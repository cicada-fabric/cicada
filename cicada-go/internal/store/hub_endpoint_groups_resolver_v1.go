package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func endpointGroupsGroupTx(tx *sql.Tx, owner, network, group string) (*Group, error) {
	g, err := scanGroup(tx.QueryRow(`SELECT `+groupColumns+` FROM groups WHERE id=?`, group))
	if err != nil || g.OwnerPrincipalID != owner || g.NetworkID != network || g.State != GroupStateActive || g.ContextPolicy != "group_scoped" || g.Version <= 0 || g.Revision <= 0 {
		return nil, ErrNetworkPermission
	}
	var count int
	if tx.QueryRow(`SELECT count(*) FROM hub_native_pairs_v1 WHERE group_id=?`, group).Scan(&count) != nil || count != 0 {
		return nil, ErrNetworkPermission
	}
	if tx.QueryRow(`SELECT count(*) FROM networks_v2 WHERE id=? AND owner_id=? AND state='ACTIVE'`, network, owner).Scan(&count) != nil || count != 1 {
		return nil, ErrNetworkPermission
	}
	return g, nil
}

func endpointGroupsMemberTx(tx *sql.Tx, principal, group string) (*Membership, error) {
	m, err := scanMembership(tx.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE principal_id=? AND group_id=?`, principal, group))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return m, err
}

func endpointGroupsJoinTx(tx *sql.Tx, endpoint, group string) (string, uint64, error) {
	var status string
	var revision uint64
	err := tx.QueryRow(`SELECT status,revision FROM endpoint_group_memberships WHERE endpoint_id=? AND group_id=?`, endpoint, group).Scan(&status, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	return status, revision, err
}

func endpointGroupsMemberGrants(m *Membership) bool {
	if m == nil || m.Status != MembershipStatusActive {
		return false
	}
	for _, right := range e2ee.EndpointGroupRights() {
		found := false
		for _, g := range m.Grants {
			if g == right {
				found = true
			}
		}
		if m.Authorization[right] == true {
			found = true
		}
		if !found {
			return false
		}
	}
	return true
}

func endpointGroupsStaticMemberTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, manual bool, at time.Time) (*Membership, uint64, error) {
	m, err := endpointGroupsMemberTx(tx, r.anchor.Registration.PrincipalID, group)
	if err != nil || !endpointGroupsMemberGrants(m) || !networkEffectiveAllows(m.EffectiveAt, at) {
		return nil, 0, ErrNetworkPermission
	}
	if !networkExpiryAllows(m.ExpiresAt, at) {
		// Only the reviewed manual source can outlive its original default
		// policy dependency. The shared row is never widened for other Endpoints.
		p, e := readLocalDomain(tx, r.originPolicy)
		if !manual || e != nil || p == nil || p.policy.GroupID != group || m.ExpiresAt != p.policy.ExpiresAt {
			return nil, 0, ErrNetworkPermission
		}
	}
	status, revision, err := endpointGroupsJoinTx(tx, r.anchor.Registration.EndpointID, group)
	if err != nil || status != "active" || revision == 0 {
		return nil, 0, ErrNetworkPermission
	}
	return m, revision, nil
}

func endpointGroupsDefaultTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, at time.Time) (*wire.OwnerEndpointGroupsContributionCard, *wire.LocalDomainEndpointKeyGrant, error) {
	p, err := readLocalDomain(tx, r.originPolicy)
	if err != nil || p == nil {
		return nil, nil, ErrNetworkPermission
	}
	if p.policy.GroupID != group {
		return nil, nil, nil
	}
	m, err := readLocalDomainMember(tx, r.originMember)
	if err != nil || m == nil {
		return nil, nil, ErrNetworkPermission
	}
	if p.revision >= 1<<62 || m.member.Revision >= 1<<62 {
		return nil, nil, ErrNetworkPermission
	}
	card := &wire.OwnerEndpointGroupsContributionCard{Source: "DEFAULT_POLICY", AuthorityID: p.policy.PolicyID, AuthorityEpoch: p.policy.Epoch, ContributionRevision: p.revision + m.member.Revision, State: "REVOKED", ExpiresAt: p.policy.ExpiresAt, KeyState: "REVOKED", UnavailableReason: "DEFAULT_POLICY_UNAVAILABLE"}
	if p.state == wire.LocalDomainExpired || m.member.State == wire.LocalDomainMemberExpired || p.policy.ExpiresAt != "" && !appNodeBefore(at, p.policy.ExpiresAt) {
		card.State = "EXPIRED"
		card.KeyState = "EXPIRED"
		return card, nil, nil
	}
	if p.state != wire.LocalDomainActive || m.member.State == wire.LocalDomainMemberRevoked || m.member.State == wire.LocalDomainMemberLeft {
		return card, nil, nil
	}
	card.State = "PENDING_KEY"
	card.KeyState = "PENDING"
	card.UnavailableReason = "KEY_NOT_READY"
	if m.member.State != wire.LocalDomainMemberActive || m.grant == "" {
		return card, nil, nil
	}
	var grant wire.LocalDomainEndpointKeyGrant
	if json.Unmarshal([]byte(m.grant), &grant) != nil {
		return nil, nil, ErrNetworkPermission
	}
	if _, err := wire.VerifyLocalDomainEndpointKeyGrant(grant, r.hub, r.anchor.Registration.OwnerID, p.policy.OwnerPublic, at); err != nil {
		return card, nil, nil
	}
	member, join, err := endpointGroupsStaticMemberTx(tx, r, group, false, at)
	if err != nil || uint64(member.Revision) != grant.Member.MembershipRevision || join != grant.Member.EndpointJoinRevision || !reflect.DeepEqual(grant.Member, m.member) {
		return card, nil, nil
	}
	card.State = "ACTIVE"
	card.KeyState = "CURRENT"
	card.UnavailableReason = ""
	return card, &grant, nil
}

func endpointGroupsRelationRowTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string) (hubEndpointGroupsRelation, error) {
	var row hubEndpointGroupsRelation
	err := tx.QueryRow(`SELECT revision,default_stamp,default_withdrawn FROM hub_endpoint_groups_relations_v1 WHERE endpoint_id=? AND group_id=?`, r.anchor.Registration.EndpointID, group).Scan(&row.revision, &row.defaultStamp, &row.defaultWithdrawn)
	if errors.Is(err, sql.ErrNoRows) {
		return row, nil
	}
	return row, err
}

func endpointGroupsResolveTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, at time.Time, materialize bool) (wire.OwnerEndpointGroupsRelationCard, *wire.EndpointGroupCurrentEndpoint, *wire.EndpointGroupPeerSource, error) {
	var empty wire.OwnerEndpointGroupsRelationCard
	g, err := endpointGroupsGroupTx(tx, r.anchor.Registration.OwnerID, r.anchor.NetworkID, group)
	if err != nil {
		return empty, nil, nil, err
	}
	if materialize {
		if err = endpointGroupsExpireTx(tx, r, group, at); err != nil {
			return empty, nil, nil, err
		}
	}
	head, err := endpointGroupsHeadTx(tx, r, group)
	if err != nil {
		return empty, nil, nil, err
	}
	row, err := endpointGroupsRelationRowTx(tx, r, group)
	if err != nil {
		return empty, nil, nil, err
	}
	def, defaultGrant, err := endpointGroupsDefaultTx(tx, r, group, at)
	if err != nil {
		return empty, nil, nil, err
	}
	if row.defaultWithdrawn && def != nil {
		def.State = "REVOKED"
		def.KeyState = "REVOKED"
		def.UnavailableReason = "OWNER_REMOVED"
		defaultGrant = nil
	}
	if materialize && def != nil {
		stamp := endpointGroupsDigest(*def)
		if row.revision == 0 {
			row, err = endpointGroupsEnsureRelationTx(tx, r, group, at)
			if err != nil {
				return empty, nil, nil, err
			}
		}
		if stamp != row.defaultStamp {
			if err = endpointGroupsAdvanceRelationTx(tx, r, group, stamp, false, at); err != nil {
				return empty, nil, nil, err
			}
			row, err = endpointGroupsRelationRowTx(tx, r, group)
			if err != nil {
				return empty, nil, nil, err
			}
		}
	}
	card := wire.OwnerEndpointGroupsRelationCard{GroupID: group, GroupName: g.Name, NetworkID: g.NetworkID, State: "NONE", RelationRevision: row.revision, DecisionRevision: head.Revision, ManualDeny: head.DenyReason != "NONE", OwnerControl: head, Contributions: []wire.OwnerEndpointGroupsContributionCard{}, KeyState: "NOT_READY", AllowedActions: []string{}, UnavailableReason: "TARGET_NOT_AUTHORIZED"}
	if def != nil {
		card.Contributions = append(card.Contributions, *def)
	}
	p, err := endpointGroupsPolicyForRelationTx(tx, r, group)
	if err != nil {
		return empty, nil, nil, err
	}
	var manual *wire.OwnerEndpointGroupsContributionCard
	if p != nil {
		manual = &wire.OwnerEndpointGroupsContributionCard{Source: "OWNER_EXPLICIT", AuthorityID: p.policy.PolicyID, AuthorityEpoch: p.policy.Epoch, ContributionRevision: p.revision, State: p.state, ExpiresAt: p.policy.ExpiresAt, KeyState: "PENDING", UnavailableReason: "KEY_NOT_READY"}
		if p.state == "REVOKED" {
			manual.KeyState = "REVOKED"
			manual.UnavailableReason = "OWNER_REMOVED"
		}
		if p.state == "EXPIRED" || p.policy.ExpiresAt != "" && !appNodeBefore(at, p.policy.ExpiresAt) {
			manual.State = "EXPIRED"
			manual.KeyState = "EXPIRED"
			manual.UnavailableReason = "POLICY_EXPIRED"
		}
		if p.state == "ACTIVE" && p.grant != nil {
			if _, e := wire.VerifyEndpointGroupDelegatedGrant(*p.grant, r.hub, r.anchor.Registration.OwnerID, p.policy.OwnerPublic, at); e == nil {
				manual.KeyState = "CURRENT"
				manual.UnavailableReason = ""
			}
		}
		card.Contributions = append(card.Contributions, *manual)
	}
	var relation *wire.EndpointGroupRelation
	var source *wire.EndpointGroupPeerSource
	if head.DenyReason == "REMOVED" {
		card.State = "REMOVED"
		card.KeyState = "REVOKED"
		card.UnavailableReason = "OWNER_READD_REQUIRED"
	} else if head.DenyReason == "EXPIRED" {
		card.State = "EXPIRED"
		card.KeyState = "EXPIRED"
		card.UnavailableReason = "OWNER_READD_REQUIRED"
	} else if head.Mode == "DEFAULT" && def != nil && def.State == "ACTIVE" && defaultGrant != nil {
		m, k := defaultGrant.Member, defaultGrant.Manifest
		digest, e := e2ee.EndpointGroupOwnerControlDigest(r.nativeDigest, group, head)
		if e != nil {
			return empty, nil, nil, e
		}
		relation = &wire.EndpointGroupRelation{HubID: r.anchor.Registration.HubID, OwnerID: r.anchor.Registration.OwnerID, NodeID: m.NodeID, LocalUserScope: m.LocalUserScope, NetworkID: r.anchor.NetworkID, GroupID: group, EndpointID: m.EndpointID, PrincipalID: m.PrincipalID, RegistrationDigest: r.anchor.RegistrationDigest, RegistrationRevision: r.anchor.RegistrationRevision, Source: "DEFAULT_POLICY", AuthorityID: def.AuthorityID, AuthorityEpoch: def.AuthorityEpoch, ContributionRevision: def.ContributionRevision, State: "ACTIVE", DecisionRevision: head.Revision, OwnerControlDigest: digest, PolicyID: def.AuthorityID, PolicyEpoch: def.AuthorityEpoch, BindingID: m.BindingID, BindingEpoch: m.BindingEpoch, MembershipRevision: m.MembershipRevision, EndpointJoinRevision: m.EndpointJoinRevision, CandidateVersion: m.CandidateVersion, CandidateKeyID: k.CandidateKeyID, CandidateFingerprint: k.CandidateFingerprint, CandidateProofDigest: k.CandidateProofDigest, ExpiresAt: def.ExpiresAt}
		source = &wire.EndpointGroupPeerSource{LocalDomainGrant: defaultGrant}
	} else if head.Mode == "OWNER" && p != nil && p.policy.PolicyID == head.PolicyID && p.policy.Epoch == head.PolicyEpoch && p.state == "ACTIVE" && manual.KeyState == "CURRENT" && p.grant != nil && endpointGroupsPolicyCurrentTx(tx, r, p, at) == nil {
		member, join, e := endpointGroupsStaticMemberTx(tx, r, group, true, at)
		if e == nil && uint64(member.Revision) == p.grant.Relation.MembershipRevision && join == p.grant.Relation.EndpointJoinRevision {
			copy := p.grant.Relation
			relation = &copy
			source = &wire.EndpointGroupPeerSource{EndpointGroupGrant: p.grant}
		}
	}
	if relation != nil && source != nil {
		var revision int64
		if source.LocalDomainGrant != nil {
			revision = source.LocalDomainGrant.Manifest.GroupRevision
		} else if source.EndpointGroupGrant != nil {
			revision = source.EndpointGroupGrant.Manifest.GroupRevision
		}
		if revision != g.Revision {
			relation = nil
			source = nil
		}
	}
	if relation != nil && endpointGroupsRegistrationCurrentTx(tx, r, at) == nil {
		card.State = "ACTIVE"
		card.KeyState = "CURRENT"
		card.ExpiresAt = relation.ExpiresAt
		card.UnavailableReason = ""
		ref := wire.EndpointGroupSourceReference{Source: relation.Source, AuthorityID: relation.AuthorityID, AuthorityEpoch: relation.AuthorityEpoch, ContributionRevision: relation.ContributionRevision}
		card.SelectedSource = &ref
		for i := range card.Contributions {
			v := &card.Contributions[i]
			v.Effective = v.Source == relation.Source
			if !v.Effective && v.UnavailableReason == "" {
				v.UnavailableReason = "OWNER_CONTROLLED"
			}
		}
		card.AllowedActions = []string{wire.OwnerEndpointGroupsRemoveEndpoint}
		if p == nil || p.state == "REVOKED" || p.state == "EXPIRED" {
			card.AllowedActions = append([]string{wire.OwnerEndpointGroupsAddEndpoint}, card.AllowedActions...)
		}
		authority := &wire.EndpointGroupCurrentEndpoint{OwnerControl: head, Relation: *relation}
		return card, authority, source, nil
	}
	if card.State == "NONE" {
		if manual != nil && manual.State == "PENDING_KEY" || def != nil && def.State == "PENDING_KEY" {
			card.State = "PENDING_KEY"
			card.KeyState = "PENDING"
			card.UnavailableReason = "KEY_NOT_READY"
		} else if manual != nil && manual.State == "EXPIRED" || def != nil && def.State == "EXPIRED" {
			card.State = "EXPIRED"
			card.KeyState = "EXPIRED"
		} else if row.revision > 0 {
			card.State = "REMOVED"
			card.KeyState = "REVOKED"
		}
	}
	for i := range card.Contributions {
		v := &card.Contributions[i]
		if head.Mode == "OWNER" && v.Source == "DEFAULT_POLICY" && v.UnavailableReason == "" {
			v.UnavailableReason = "OWNER_CONTROLLED"
		}
	}
	if p == nil || p.state == "REVOKED" || p.state == "EXPIRED" {
		card.AllowedActions = append(card.AllowedActions, wire.OwnerEndpointGroupsAddEndpoint)
	}
	if row.revision > 0 {
		card.AllowedActions = append(card.AllowedActions, wire.OwnerEndpointGroupsRemoveEndpoint)
	}
	return card, nil, nil, nil
}
