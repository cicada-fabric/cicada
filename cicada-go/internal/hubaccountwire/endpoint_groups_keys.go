package hubaccountwire

import (
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func endpointGroupRelationShape(r EndpointGroupRelation) error {
	for _, id := range []string{r.HubID, r.OwnerID, r.NodeID, r.NetworkID, r.GroupID, r.EndpointID, r.PrincipalID, r.AuthorityID, r.BindingID, r.CandidateKeyID} {
		if !validID(id) {
			return ErrInvalid
		}
	}
	for _, n := range []uint64{r.RegistrationRevision, r.AuthorityEpoch, r.ContributionRevision, r.PolicyEpoch, r.BindingEpoch, r.CandidateVersion} {
		if !nativePairPositive(n) {
			return ErrInvalid
		}
	}
	for _, n := range []uint64{r.DecisionRevision, r.MembershipRevision, r.EndpointJoinRevision} {
		if n >= 1<<63 {
			return ErrInvalid
		}
	}
	if !e2ee.ValidLocalDomainUserScope(r.LocalUserScope) || !endpointGroupsSource(r.Source) || !endpointGroupsState(r.State) || !isHex(r.PolicyID, 16) || r.PolicyID != r.AuthorityID || r.PolicyEpoch != r.AuthorityEpoch ||
		!isHex(r.RegistrationDigest, 32) || !isHex(r.OwnerControlDigest, 32) || !isHex(r.CandidateProofDigest, 32) || !strings.HasPrefix(r.CandidateFingerprint, "sha256:") || !isHex(strings.TrimPrefix(r.CandidateFingerprint, "sha256:"), 32) ||
		r.ExpiresAt != "" && validateCanonicalTime(r.ExpiresAt) != nil {
		return ErrInvalid
	}
	if r.State == "ACTIVE" && (!nativePairPositive(r.MembershipRevision) || !nativePairPositive(r.EndpointJoinRevision)) {
		return ErrInvalid
	}
	return nil
}

func EndpointGroupRelationDigest(r EndpointGroupRelation) (string, error) {
	if endpointGroupRelationShape(r) != nil {
		return "", ErrInvalid
	}
	return ownerEndpointGroupsDigest("cicada/owner/endpoint-groups/relation/v1\x00", r)
}

func validateEndpointGroupCurrentEndpoint(c EndpointGroupCurrentEndpoint, now time.Time) error {
	r, h := c.Relation, c.OwnerControl
	if now.IsZero() || endpointGroupRelationShape(r) != nil || e2ee.ValidateEndpointGroupOwnerControl(h) != nil || r.State != "ACTIVE" || h.Revision != r.DecisionRevision || h.DenyReason != "NONE" ||
		r.ExpiresAt != "" && !beforeText(now, r.ExpiresAt) {
		return ErrInvalid
	}
	if h.Mode == "OWNER" {
		if r.Source != "OWNER_EXPLICIT" || r.PolicyID != h.PolicyID || r.PolicyEpoch != h.PolicyEpoch {
			return ErrInvalid
		}
	} else if r.Source != "DEFAULT_POLICY" {
		return ErrInvalid
	}
	return nil
}

func beforeText(now time.Time, stamp string) bool {
	end, err := parseCanonicalUTC(stamp)
	return err == nil && now.Before(end)
}

func ValidateEndpointGroupCurrent(c EndpointGroupCurrent, operation, attempt string, now time.Time) error {
	if now.IsZero() || c.Format != EndpointGroupCurrentFormat || !validID(c.HubID) || !validID(c.GroupID) || !endpointGroupsContains([]string{"peer_key", "native_delivery"}, operation) || attempt == "" || len(attempt) > 257 || c.Operation != operation || c.AttemptID != attempt ||
		validateTimeWindowNow(c.ObservedAt, c.ExpiresAt, 30*time.Second, now) != nil || validateEndpointGroupCurrentEndpoint(c.Sender, now) != nil || validateEndpointGroupCurrentEndpoint(c.Receiver, now) != nil ||
		c.Sender.Relation.EndpointID == c.Receiver.Relation.EndpointID || c.Sender.Relation.HubID != c.HubID || c.Receiver.Relation.HubID != c.HubID || c.Sender.Relation.GroupID != c.GroupID || c.Receiver.Relation.GroupID != c.GroupID ||
		c.Sender.Relation.NetworkID != c.Receiver.Relation.NetworkID {
		return ErrInvalid
	}
	end, _ := parseCanonicalUTC(c.ExpiresAt)
	for _, r := range []EndpointGroupRelation{c.Sender.Relation, c.Receiver.Relation} {
		if r.ExpiresAt != "" {
			policyEnd, _ := parseCanonicalUTC(r.ExpiresAt)
			if end.After(policyEnd) {
				return ErrInvalid
			}
		}
	}
	return nil
}

func endpointGroupRelationForPolicy(r EndpointGroupRelation, p e2ee.EndpointGroupPolicy) bool {
	return r.Source == "OWNER_EXPLICIT" && r.HubID == p.HubID && r.OwnerID == p.OwnerID && r.NodeID == p.Node.NodeID && r.LocalUserScope == p.LocalUserScope && r.NetworkID == p.NetworkID && r.GroupID == p.GroupID && r.EndpointID == p.EndpointID && r.PrincipalID == p.PrincipalID &&
		r.RegistrationDigest == p.RegistrationDigest && r.RegistrationRevision == p.RegistrationRevision && r.AuthorityID == p.PolicyID && r.AuthorityEpoch == p.Epoch && r.PolicyID == p.PolicyID && r.PolicyEpoch == p.Epoch &&
		r.DecisionRevision == p.ExpectedDecisionRevision+1 && r.BindingID == p.BindingID && r.BindingEpoch == p.BindingEpoch && r.CandidateVersion == p.CandidateVersion && r.CandidateKeyID == p.EndpointKeyID &&
		r.CandidateFingerprint == p.EndpointFingerprint && r.CandidateProofDigest == p.CandidateProofDigest && r.ExpiresAt == p.ExpiresAt
}

// Only verifies the exact Owner-approved public projection. Before signing a
// challenge a Node must also compare its private original registration anchor.
func ValidateEndpointGroupKeyProjection(g EndpointGroupDelegatedGrant, hub HubIdentity, expectedOwnerID string, trustedOwner e2ee.PublicIdentity, now time.Time) (e2ee.EndpointGroupPolicy, error) {
	p, err := e2ee.VerifyOwnerEndpointGroupPolicy(trustedOwner, g.PolicyProof, now)
	r, k := g.Relation, g.Manifest
	if err != nil || ValidateOwnerEndpointGroupsPolicy(p, hub, now) != nil || p.OwnerID != expectedOwnerID || endpointGroupRelationShape(r) != nil || r.State != "ACTIVE" || !endpointGroupRelationForPolicy(r, p) || k.GroupRevision <= 0 ||
		validateEndpointGroupManifest(k, p, uint64(k.GroupRevision), r.MembershipRevision, r.EndpointJoinRevision) != nil {
		return e2ee.EndpointGroupPolicy{}, ErrInvalid
	}
	issued, err := parseCanonicalUTC(k.IssuedAt)
	policyIssued, _ := parseCanonicalUTC(p.IssuedAt)
	if err != nil || issued.Before(policyIssued) || !now.IsZero() && issued.After(now.Add(30*time.Second)) {
		return e2ee.EndpointGroupPolicy{}, ErrInvalid
	}
	return p, nil
}

func VerifyEndpointGroupDelegatedGrant(g EndpointGroupDelegatedGrant, hub HubIdentity, expectedOwnerID string, trustedOwner e2ee.PublicIdentity, now time.Time) (e2ee.EndpointGroupPolicy, error) {
	p, err := ValidateEndpointGroupKeyProjection(g, hub, expectedOwnerID, trustedOwner, now)
	if err != nil {
		return e2ee.EndpointGroupPolicy{}, ErrInvalid
	}
	c, err := e2ee.VerifyEndpointGroupKey(p, g.NodeProof, now)
	relationDigest, re := EndpointGroupRelationDigest(g.Relation)
	manifestDigest, me := LocalDomainGroupManifestDigest(g.Manifest)
	if err != nil || re != nil || me != nil || c.OwnerControlDigest != g.Relation.OwnerControlDigest || c.RelationDigest != relationDigest || c.ManifestDigest != manifestDigest || c.CandidateBindingDigest != g.Manifest.CandidateBindingDigest || c.IssuedAt != g.Manifest.IssuedAt {
		return e2ee.EndpointGroupPolicy{}, ErrInvalid
	}
	return p, nil
}

func EndpointGroupKeyChallengeDigest(c EndpointGroupKeyPrepareResult) (string, error) {
	return ownerEndpointGroupsDigest("cicada/owner/endpoint-groups/key-challenge/v1\x00", struct {
		ChallengeID           string                         `json:"challenge_id"`
		PolicyID              string                         `json:"policy_id"`
		PolicyEpoch           uint64                         `json:"policy_epoch"`
		Expected              OwnerEndpointGroupsCAS         `json:"expected"`
		ProjectedOwnerControl e2ee.EndpointGroupOwnerControl `json:"projected_owner_control"`
		ProjectedRelation     EndpointGroupRelation          `json:"projected_relation"`
		ProjectedKeyManifest  LocalDomainKeyManifest         `json:"projected_key_manifest"`
		ObservedAt            string                         `json:"observed_at"`
		ExpiresAt             string                         `json:"expires_at"`
	}{c.ChallengeID, c.PolicyID, c.PolicyEpoch, c.Expected, c.ProjectedOwnerControl, c.ProjectedRelation, c.ProjectedKeyManifest, c.ObservedAt, c.ExpiresAt})
}

func EndpointGroupKeyClaimsForChallenge(c EndpointGroupKeyPrepareResult, p e2ee.EndpointGroupPolicy) (e2ee.EndpointGroupKeyClaims, error) {
	digest, err := EndpointGroupKeyChallengeDigest(c)
	policyDigest, pe := e2ee.EndpointGroupPolicyDigest(p)
	relationDigest, re := EndpointGroupRelationDigest(c.ProjectedRelation)
	manifestDigest, me := LocalDomainGroupManifestDigest(c.ProjectedKeyManifest)
	if err != nil || pe != nil || re != nil || me != nil || digest != c.ChallengeDigest || !isHex(c.ChallengeID, 16) || c.PolicyID != p.PolicyID || c.PolicyEpoch != p.Epoch || c.ProjectedKeyManifest.IssuedAt != c.ObservedAt {
		return e2ee.EndpointGroupKeyClaims{}, ErrInvalid
	}
	claims := e2ee.EndpointGroupKeyClaims{Version: 1, Purpose: e2ee.EndpointGroupKeyPurpose, HubID: p.HubID, NodeID: p.Node.NodeID, NodeKeyEpoch: p.Node.NodeKeyEpoch, PolicyID: p.PolicyID, PolicyEpoch: p.Epoch, PolicyDigest: policyDigest, RegistrationDigest: p.RegistrationDigest, OwnerControlDigest: c.ProjectedRelation.OwnerControlDigest, RelationDigest: relationDigest, ManifestDigest: manifestDigest, CandidateBindingDigest: c.ProjectedKeyManifest.CandidateBindingDigest, ChallengeID: c.ChallengeID, ChallengeDigest: c.ChallengeDigest, IssuedAt: c.ObservedAt, ExpiresAt: p.ExpiresAt}
	if e2ee.ValidateEndpointGroupKeyClaims(claims, p, time.Time{}) != nil {
		return e2ee.EndpointGroupKeyClaims{}, ErrInvalid
	}
	return claims, nil
}

func ValidateEndpointGroupsNodeKeyResult(r EndpointGroupsNodeKeyResult, hub HubIdentity, expectedOwnerID string, trustedOwner e2ee.PublicIdentity, now time.Time) (e2ee.EndpointGroupPolicy, error) {
	invalid := func() (e2ee.EndpointGroupPolicy, error) { return e2ee.EndpointGroupPolicy{}, ErrInvalid }
	if now.IsZero() || r.ContractRevision != OwnerEndpointGroupsContractRevision || ValidateEndpointGroupsRegistrationAnchor(r.Registration, hub) != nil || r.Registration.State == "REVOKED" || validateRecent(r.ObservedAt, now, 30*time.Second) != nil || (r.Challenge == nil) == (r.Grant == nil) {
		return invalid()
	}
	p, err := e2ee.VerifyOwnerEndpointGroupPolicy(trustedOwner, r.PolicyProof, now)
	if err != nil || p.OwnerID != expectedOwnerID || ValidateOwnerEndpointGroupsPolicy(p, hub, now) != nil || !endpointGroupsPolicyForAnchor(p, r.Registration) {
		return invalid()
	}
	nativeDigest, err := e2ee.EndpointGroupNativeIdentityDigest(EndpointGroupsNativeIdentity(r.Registration))
	if err != nil {
		return invalid()
	}
	if r.Grant != nil {
		if !reflect.DeepEqual(r.PolicyProof, r.Grant.PolicyProof) {
			return invalid()
		}
		if _, err := VerifyEndpointGroupDelegatedGrant(*r.Grant, hub, expectedOwnerID, trustedOwner, now); err != nil {
			return invalid()
		}
		digest, err := e2ee.EndpointGroupOwnerControlDigest(nativeDigest, p.GroupID, r.OwnerControl)
		if err != nil || digest != r.Grant.Relation.OwnerControlDigest || validateEndpointGroupCurrentEndpoint(EndpointGroupCurrentEndpoint{r.OwnerControl, r.Grant.Relation}, now) != nil {
			return invalid()
		}
		return p, nil
	}
	c := *r.Challenge
	projected := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: p.ExpectedDecisionRevision + 1, DenyReason: "NONE", PolicyID: p.PolicyID, PolicyEpoch: p.Epoch}
	headDigest, err := e2ee.EndpointGroupOwnerControlDigest(nativeDigest, p.GroupID, projected)
	if err != nil || !ownerEndpointGroupsCASValid(c.Expected, false) || c.Expected.OwnerKeyVersion != p.OwnerKeyVersion || c.Expected.NodeOwnerBindingID != p.Node.OwnerBindingID || c.Expected.NodeOwnerBindingVersion != p.Node.BindingVersion || c.Expected.NodeKeyEpoch != p.Node.NodeKeyEpoch ||
		c.Expected.RegistrationDigest != p.RegistrationDigest || c.Expected.RegistrationRevision != p.RegistrationRevision || c.Expected.BindingID != p.BindingID || c.Expected.BindingEpoch != p.BindingEpoch || c.Expected.CandidateVersion != p.CandidateVersion || c.Expected.CandidateProofDigest != p.CandidateProofDigest || c.Expected.CandidateFingerprint != p.EndpointFingerprint ||
		c.Expected.DecisionRevision != p.ExpectedDecisionRevision || c.Expected.OwnerControlDigest != p.ExpectedOwnerControlDigest || r.OwnerControl.Revision != p.ExpectedDecisionRevision || c.ProjectedOwnerControl != projected || c.ProjectedRelation.OwnerControlDigest != headDigest ||
		c.ObservedAt != r.ObservedAt || c.ProjectedKeyManifest.IssuedAt != c.ObservedAt || uint64(c.ProjectedKeyManifest.GroupRevision) != c.Expected.GroupVersion || c.Expected.PolicyEpoch != p.Epoch ||
		(c.ProjectedRelation.MembershipRevision != c.Expected.MembershipRevision && c.ProjectedRelation.MembershipRevision != c.Expected.MembershipRevision+1) ||
		(c.ProjectedRelation.EndpointJoinRevision != c.Expected.EndpointJoinRevision && c.ProjectedRelation.EndpointJoinRevision != c.Expected.EndpointJoinRevision+1) || validateTimeWindowNow(c.ObservedAt, c.ExpiresAt, 5*time.Minute, now) != nil {
		return invalid()
	}
	oldHeadDigest, err := e2ee.EndpointGroupOwnerControlDigest(nativeDigest, p.GroupID, r.OwnerControl)
	if err != nil || oldHeadDigest != p.ExpectedOwnerControlDigest {
		return invalid()
	}
	if p.ExpiresAt != "" {
		end, _ := parseCanonicalUTC(c.ExpiresAt)
		policyEnd, _ := parseCanonicalUTC(p.ExpiresAt)
		if end.After(policyEnd) {
			return invalid()
		}
	}
	projection := EndpointGroupDelegatedGrant{Manifest: c.ProjectedKeyManifest, Relation: c.ProjectedRelation, PolicyProof: r.PolicyProof}
	if _, err := ValidateEndpointGroupKeyProjection(projection, hub, expectedOwnerID, trustedOwner, now); err != nil {
		return invalid()
	}
	if _, err := EndpointGroupKeyClaimsForChallenge(c, p); err != nil {
		return invalid()
	}
	return p, nil
}

// Each side selects exactly one independently verified Owner chain. This
// authenticates evidence; current Store Guard and original native context still
// authorize each actual operation. Arriving policies cannot bootstrap trust.
func VerifyEndpointGroupPeerSource(source EndpointGroupPeerSource, snapshot EndpointGroupCurrentEndpoint, hub HubIdentity, expectedOwnerID string, trustedOwner e2ee.PublicIdentity, now time.Time) (e2ee.PublicIdentity, error) {
	if now.IsZero() || validateEndpointGroupCurrentEndpoint(snapshot, now) != nil || (source.LocalDomainGrant == nil) == (source.EndpointGroupGrant == nil) || snapshot.Relation.OwnerID != expectedOwnerID {
		return e2ee.PublicIdentity{}, ErrInvalid
	}
	if source.EndpointGroupGrant != nil {
		g := *source.EndpointGroupGrant
		p, err := VerifyEndpointGroupDelegatedGrant(g, hub, expectedOwnerID, trustedOwner, now)
		if err != nil || !reflect.DeepEqual(snapshot.Relation, g.Relation) || snapshot.OwnerControl.Mode != "OWNER" || snapshot.OwnerControl.PolicyID != p.PolicyID || snapshot.OwnerControl.PolicyEpoch != p.Epoch {
			return e2ee.PublicIdentity{}, ErrInvalid
		}
		return g.Manifest.CandidatePublicIdentity, nil
	}
	g := *source.LocalDomainGrant
	p, err := VerifyLocalDomainEndpointKeyGrant(g, hub, expectedOwnerID, trustedOwner, now)
	m, r := g.Member, snapshot.Relation
	if err != nil || snapshot.OwnerControl.Mode != "DEFAULT" || r.Source != "DEFAULT_POLICY" || r.HubID != p.HubID || r.NodeID != m.NodeID || r.LocalUserScope != m.LocalUserScope || r.NetworkID != p.NetworkID || r.GroupID != p.GroupID || r.EndpointID != m.EndpointID || r.PrincipalID != m.PrincipalID ||
		r.AuthorityID != p.PolicyID || r.AuthorityEpoch != p.Epoch || r.BindingID != m.BindingID || r.BindingEpoch != m.BindingEpoch || r.MembershipRevision != m.MembershipRevision || r.EndpointJoinRevision != m.EndpointJoinRevision || r.CandidateVersion != m.CandidateVersion || r.CandidateKeyID != m.CandidateKeyID || r.CandidateFingerprint != m.CandidateFingerprint || r.CandidateProofDigest != m.CandidateProofDigest || r.ExpiresAt != p.ExpiresAt {
		return e2ee.PublicIdentity{}, ErrInvalid
	}
	registration := e2ee.EndpointGroupRegistration{HubID: p.HubID, OwnerID: p.OwnerID, NodeID: p.Node.NodeID, Harness: m.Runtime, NativeSessionID: m.NativeSessionID, Workspace: m.Workspace, EndpointID: m.EndpointID, PrincipalID: m.PrincipalID}
	regDigest, err := e2ee.EndpointGroupRegistrationDigest(registration)
	nativeDigest, ne := e2ee.EndpointGroupNativeIdentityDigest(e2ee.EndpointGroupNativeIdentity{HubID: p.HubID, OwnerID: p.OwnerID, NodeID: p.Node.NodeID, LocalUserScope: p.LocalUserScope, Harness: m.Runtime, NativeSessionID: m.NativeSessionID, Workspace: m.Workspace})
	headDigest, he := e2ee.EndpointGroupOwnerControlDigest(nativeDigest, p.GroupID, snapshot.OwnerControl)
	if err != nil || ne != nil || he != nil || regDigest != r.RegistrationDigest || headDigest != r.OwnerControlDigest {
		return e2ee.PublicIdentity{}, ErrInvalid
	}
	return g.Manifest.CandidatePublicIdentity, nil
}
