package nodekeys

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type endpointGroupsKeyFixture struct {
	x        *localDomainKeyFixture
	anchors  [2]wire.EndpointGroupsRegistrationAnchor
	grants   [2]wire.EndpointGroupDelegatedGrant
	policies [2]e2ee.EndpointGroupPolicy
	heads    [2]e2ee.EndpointGroupOwnerControl
}

func syntheticEndpointGroupsKeys(t *testing.T, trust, finiteDefault bool) *endpointGroupsKeyFixture {
	t.Helper()
	x := localDomainKeys(t, trust)
	if finiteDefault {
		x.policy.ExpiresAt = x.f.now.Add(time.Minute).Format(time.RFC3339Nano)
		var err error
		x.proof, err = e2ee.SignOwnerLocalDomainPolicy(x.f.owner, x.policy)
		if err != nil {
			t.Fatal(err)
		}
		selection, err := wire.LocalDomainSelectionForPolicy(x.policy)
		if err != nil {
			t.Fatal(err)
		}
		for i := range x.grants {
			g := &x.grants[i]
			g.PolicyProof = x.proof
			g.Member.Selection = selection
			g.Manifest.ExpiresAt = x.policy.ExpiresAt
			g.Manifest.CandidateBindingDigest, _ = wire.LocalDomainGroupBindingDigest(g.Manifest)
			g.Manifest.Digest, _ = wire.LocalDomainGroupManifestDigest(g.Manifest)
			digest, _ := wire.LocalDomainMemberDigest(g.Member)
			g.NodeProof, err = e2ee.SignLocalDomainEndpointKey(x.node, x.policy, e2ee.LocalDomainEndpointKeyClaims{Version: 1, Purpose: e2ee.LocalDomainEndpointKeyPurpose, PolicyID: x.policy.PolicyID, PolicyEpoch: x.policy.Epoch, PolicyDigest: selection.PolicyDigest, MemberID: g.Member.MemberID, MemberRevision: g.Member.Revision, MemberDigest: digest, ManifestDigest: g.Manifest.Digest, CandidateBindingDigest: g.Manifest.CandidateBindingDigest, IssuedAt: g.Manifest.IssuedAt, ExpiresAt: x.policy.ExpiresAt})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	f := &endpointGroupsKeyFixture{x: x}
	ctx := context.Background()
	if trust {
		x.require(t)
	}
	for i, g := range x.grants {
		m, k := g.Member, g.Manifest
		r := e2ee.EndpointGroupRegistration{HubID: x.policy.HubID, OwnerID: x.policy.OwnerID, NodeID: m.NodeID, Harness: m.Runtime, NativeSessionID: m.NativeSessionID, Workspace: m.Workspace, EndpointID: m.EndpointID, PrincipalID: m.PrincipalID}
		digest, err := e2ee.EndpointGroupRegistrationDigest(r)
		if err != nil {
			t.Fatal(err)
		}
		a := wire.EndpointGroupsRegistrationAnchor{Profile: wire.EndpointGroupsNativeProfile, RegistrationSource: wire.EndpointGroupsRegistrationSource, Registration: r, RegistrationDigest: digest, RegistrationRevision: 1, LocalUserScope: m.LocalUserScope, NetworkID: x.policy.NetworkID, BindingID: m.BindingID, BindingEpoch: m.BindingEpoch, NodeKeyEpoch: x.policy.Node.NodeKeyEpoch, LeaseOwner: m.LeaseOwner, NetworkAccessBindingID: m.NetworkAccessBindingID, NetworkAccessEpoch: m.NetworkAccessEpoch, NetworkMembershipRevision: m.NetworkMembershipRevision, EndpointNetworkRevision: m.EndpointNetworkRevision, CandidateVersion: m.CandidateVersion, CandidateKeyID: m.CandidateKeyID, CandidatePublic: k.CandidatePublicIdentity, CandidateFingerprint: m.CandidateFingerprint, CandidateProofDigest: m.CandidateProofDigest, State: "REGISTERED", LeaseExpiresAt: x.f.now.Add(5 * time.Minute).Format(time.RFC3339Nano)}
		if wire.ValidateEndpointGroupsRegistrationAnchor(a, x.f.hub) != nil {
			t.Fatal("synthetic anchor shape")
		}
		f.anchors[i] = a
		if trust {
			c := GroupEndpointKeyCandidate{EndpointID: m.EndpointID, GroupID: x.policy.GroupID, PrincipalID: m.PrincipalID, OwnerID: x.policy.OwnerID, NodeID: m.NodeID, BindingID: m.BindingID, BindingEpoch: m.BindingEpoch, KeyID: m.CandidateKeyID, KeyFingerprint: m.CandidateFingerprint, ProofDigest: m.CandidateProofDigest, PublicIdentity: k.CandidatePublicIdentity, Attestation: k.CandidateAttestation}
			if err := x.f.state.RememberLocalDomainLocalAttestation(ctx, x.policy.PolicyID, c, x.f.now); err != nil {
				t.Fatal("origin attestation", err)
			}
			if err := x.f.state.RememberLocalDomainGrant(ctx, g, x.f.now); err != nil {
				t.Fatal("origin member", err)
			}
			if err := x.f.state.CheckEndpointGroupsRegistration(ctx, x.f.hub, a, x.f.now); err != nil {
				t.Fatal("original registration", err)
			}
		}
		// Hub Apply installs pending contribution 1; Complete advances it to 2.
		f.grants[i], f.policies[i], f.heads[i] = f.manual(t, i, "synthetic-manual-G2", 1, 2, e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}, "")
	}
	return f
}

func (f *endpointGroupsKeyFixture) manual(t *testing.T, index int, group string, epoch, revision uint64, expected e2ee.EndpointGroupOwnerControl, expires string) (wire.EndpointGroupDelegatedGrant, e2ee.EndpointGroupPolicy, e2ee.EndpointGroupOwnerControl) {
	t.Helper()
	a := f.anchors[index]
	r := a.Registration
	native, err := endpointGroupsNativeDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest, err := e2ee.EndpointGroupOwnerControlDigest(native, group, expected)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat(string(rune('a'+index)), 30) + string(rune('a'+epoch)) + string(rune('a'+revision))
	p := e2ee.EndpointGroupPolicy{Version: 1, Purpose: e2ee.OwnerEndpointGroupsPolicyPurpose, PolicyID: id, Epoch: epoch, Origin: f.x.policy.Origin, HubID: r.HubID, HubFingerprint: f.x.policy.HubFingerprint, OwnerID: r.OwnerID, OwnerPublic: f.x.f.owner.Public(), OwnerKeyVersion: f.x.policy.OwnerKeyVersion, Node: f.x.policy.Node, LocalUserScope: a.LocalUserScope, NetworkID: a.NetworkID, GroupID: group, EndpointID: r.EndpointID, PrincipalID: r.PrincipalID, RegistrationDigest: a.RegistrationDigest, RegistrationRevision: a.RegistrationRevision, BindingID: a.BindingID, BindingEpoch: a.BindingEpoch, EndpointKeyID: a.CandidateKeyID, EndpointPublic: a.CandidatePublic, EndpointFingerprint: a.CandidateFingerprint, CandidateVersion: a.CandidateVersion, CandidateProofDigest: a.CandidateProofDigest, ExpectedOwnerControlDigest: expectedDigest, ExpectedDecisionRevision: expected.Revision, Rights: e2ee.EndpointGroupRights(), IssuedAt: f.x.f.now.Format(time.RFC3339Nano), ExpiresAt: expires, ReviewID: strings.Repeat("7", 32), ReviewDigest: strings.Repeat("8", 64), ServerNonce: strings.Repeat("9", 64)}
	proof, err := e2ee.SignOwnerEndpointGroupPolicy(f.x.f.owner, p)
	if err != nil {
		t.Fatal("manual Owner policy", err)
	}
	head := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: expected.Revision + 1, DenyReason: "NONE", PolicyID: p.PolicyID, PolicyEpoch: p.Epoch}
	headDigest, err := e2ee.EndpointGroupOwnerControlDigest(native, group, head)
	if err != nil {
		t.Fatal(err)
	}
	old := f.x.grants[index].Manifest
	k := old
	k.GroupID = group
	k.ExpiresAt = expires
	k.CandidateBindingDigest, _ = wire.LocalDomainGroupBindingDigest(k)
	k.Digest, _ = wire.LocalDomainGroupManifestDigest(k)
	relation := wire.EndpointGroupRelation{HubID: r.HubID, OwnerID: r.OwnerID, NodeID: r.NodeID, LocalUserScope: a.LocalUserScope, NetworkID: a.NetworkID, GroupID: group, EndpointID: r.EndpointID, PrincipalID: r.PrincipalID, RegistrationDigest: a.RegistrationDigest, RegistrationRevision: a.RegistrationRevision, Source: "OWNER_EXPLICIT", AuthorityID: p.PolicyID, AuthorityEpoch: epoch, ContributionRevision: revision, State: "ACTIVE", DecisionRevision: head.Revision, OwnerControlDigest: headDigest, PolicyID: p.PolicyID, PolicyEpoch: epoch, BindingID: a.BindingID, BindingEpoch: a.BindingEpoch, MembershipRevision: uint64(k.MembershipRevision), EndpointJoinRevision: uint64(k.EndpointJoinRevision), CandidateVersion: a.CandidateVersion, CandidateKeyID: a.CandidateKeyID, CandidateFingerprint: a.CandidateFingerprint, CandidateProofDigest: a.CandidateProofDigest, ExpiresAt: expires}
	digest, err := wire.EndpointGroupRelationDigest(relation)
	if err != nil {
		t.Fatal(err)
	}
	pd, _ := e2ee.EndpointGroupPolicyDigest(p)
	claims := e2ee.EndpointGroupKeyClaims{Version: 1, Purpose: e2ee.EndpointGroupKeyPurpose, HubID: p.HubID, NodeID: p.Node.NodeID, NodeKeyEpoch: p.Node.NodeKeyEpoch, PolicyID: p.PolicyID, PolicyEpoch: epoch, PolicyDigest: pd, RegistrationDigest: a.RegistrationDigest, OwnerControlDigest: headDigest, RelationDigest: digest, ManifestDigest: k.Digest, CandidateBindingDigest: k.CandidateBindingDigest, ChallengeID: strings.Repeat("6", 32), ChallengeDigest: strings.Repeat("5", 64), IssuedAt: k.IssuedAt, ExpiresAt: p.ExpiresAt}
	np, err := e2ee.SignEndpointGroupKey(f.x.node, p, claims)
	if err != nil {
		t.Fatal("manual Node certification", err)
	}
	g := wire.EndpointGroupDelegatedGrant{Manifest: k, Relation: relation, PolicyProof: proof, NodeProof: np}
	if _, err := wire.VerifyEndpointGroupDelegatedGrant(g, f.x.f.hub, p.OwnerID, f.x.f.owner.Public(), f.x.f.now); err != nil {
		t.Fatal("synthetic actual delegated chain", err)
	}
	return g, p, head
}

func (f *endpointGroupsKeyFixture) current(group string, sender, receiver wire.EndpointGroupCurrentEndpoint, now time.Time) wire.EndpointGroupCurrent {
	end := now.Add(30 * time.Second)
	for _, r := range []wire.EndpointGroupRelation{sender.Relation, receiver.Relation} {
		if r.ExpiresAt != "" {
			e, _ := time.Parse(time.RFC3339Nano, r.ExpiresAt)
			if e.Before(end) {
				end = e
			}
		}
	}
	return wire.EndpointGroupCurrent{Format: wire.EndpointGroupCurrentFormat, HubID: f.x.f.hub.HubID, GroupID: group, Sender: sender, Receiver: receiver, Operation: "peer_key", AttemptID: "synthetic-exact-attempt", ObservedAt: now.Format(time.RFC3339Nano), ExpiresAt: end.Format(time.RFC3339Nano)}
}

func (f *endpointGroupsKeyFixture) manualCurrent(now time.Time) wire.EndpointGroupCurrent {
	return f.current(f.grants[0].Relation.GroupID, wire.EndpointGroupCurrentEndpoint{OwnerControl: f.heads[0], Relation: f.grants[0].Relation}, wire.EndpointGroupCurrentEndpoint{OwnerControl: f.heads[1], Relation: f.grants[1].Relation}, now)
}

func TestEndpointGroupsIndependentOriginalOwnerPinAndZeroRightsRegistration(t *testing.T) {
	f := syntheticEndpointGroupsKeys(t, false, false)
	ctx := context.Background()
	s := f.x.f.state
	if err := s.RequireEndpointGroupPolicy(ctx, f.x.f.hub, f.policies[0], f.grants[0].PolicyProof, f.x.f.now); !errors.Is(err, ErrEndpointGroupsPolicy) {
		t.Fatal("policy installed its own Owner trust", err)
	}
	if err := s.CheckEndpointGroupsRegistration(ctx, f.x.f.hub, f.anchors[0], f.x.f.now); err == nil {
		t.Fatal("registration learned source from arriving anchor")
	}
	if yes, err := s.EndpointGroupsRequired(ctx, f.anchors[0].Registration.EndpointID, f.grants[0].Relation.GroupID); err != nil || yes {
		t.Fatal("refusal installed permission marker", err)
	}
	var n int
	if s.db.QueryRow(`SELECT count(*) FROM node_crypto_owner_key_trust`).Scan(&n) != nil || n != 0 {
		t.Fatal("Owner pin manufactured")
	}
}

func TestEndpointGroupsManualAuthorityOutlivesDefaultAndPreservesOriginalKey(t *testing.T) {
	f := syntheticEndpointGroupsKeys(t, true, true)
	ctx := context.Background()
	s := f.x.f.state
	now := f.x.f.now.Add(2 * time.Minute)
	for i := range f.grants {
		if err := s.CheckEndpointGroupsRegistration(ctx, f.x.f.hub, f.anchors[i], now); err != nil {
			t.Fatal("registration depended on expired default", err)
		}
		if err := s.RequireEndpointGroupPolicy(ctx, f.x.f.hub, f.policies[i], f.grants[i].PolicyProof, now); err != nil {
			t.Fatal(err)
		}
		if yes, _ := s.EndpointGroupsRequired(ctx, f.anchors[i].Registration.EndpointID, f.grants[i].Relation.GroupID); yes {
			t.Fatal("pending policy took over before key Complete")
		}
		if err := s.RememberEndpointGroupGrant(ctx, f.x.f.hub, f.anchors[i], f.grants[i], f.heads[i], now); err != nil {
			t.Fatal("manual certificate depended on default permission", err)
		}
	}
	c := f.manualCurrent(now)
	sources := [2]wire.EndpointGroupPeerSource{{EndpointGroupGrant: &f.grants[0]}, {EndpointGroupGrant: &f.grants[1]}}
	pin, err := s.PinEndpointGroupsPeer(ctx, f.anchors[0].Registration.EndpointID, sources[0], sources[1], c, c.Operation, c.AttemptID, now)
	if err != nil {
		t.Fatal(err)
	}
	if pin.KeyID != f.anchors[1].CandidateKeyID || pin.BindingID != f.anchors[1].BindingID || pin.BindingEpoch != f.anchors[1].BindingEpoch || !samePublicIdentity(pin.Public, f.anchors[1].CandidatePublic) {
		t.Fatal("pin replaced original identity or epoch")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenCryptoState(f.x.f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	f.x.f.state = reopened
	if required, err := reopened.VerifyEndpointGroupsGroupAuthorization(ctx, f.anchors[0].Registration.EndpointID, c.GroupID, sources[0], sources[1], &c, c.Operation, c.AttemptID, now); err != nil || !required {
		t.Fatal("retained manual source did not recover", err)
	}
	bad := f.anchors[0]
	bad.BindingEpoch++
	if err := reopened.CheckEndpointGroupsRegistration(ctx, f.x.f.hub, bad, now); err == nil {
		t.Fatal("cold recovery silently changed original binding epoch")
	}
}

func TestEndpointGroupsOwnerDenyIsPermanentUntilNewExactGrant(t *testing.T) {
	f := syntheticEndpointGroupsKeys(t, true, false)
	s := f.x.f.state
	ctx := context.Background()
	a, g := f.anchors[0], f.grants[0]
	now := f.x.f.now
	if err := s.RememberEndpointGroupGrant(ctx, f.x.f.hub, a, g, f.heads[0], now); err != nil {
		t.Fatal(err)
	}
	current := f.manualCurrent(now)
	pin, err := s.PinEndpointGroupsPeer(ctx, a.Registration.EndpointID, wire.EndpointGroupPeerSource{EndpointGroupGrant: &g}, wire.EndpointGroupPeerSource{EndpointGroupGrant: &f.grants[1]}, current, current.Operation, current.AttemptID, now)
	if err != nil || s.CheckPeerPinAdmission(ctx, *pin) != nil {
		t.Fatal("initial managed pin admission", err)
	}
	removed := f.heads[0]
	removed.Revision++
	removed.DenyReason = "REMOVED"
	if err := s.ObserveEndpointGroupOwnerControl(ctx, a, g.Relation.GroupID, removed, now); err != nil {
		t.Fatal(err)
	}
	if s.CheckPeerPinAdmission(ctx, *pin) == nil {
		t.Fatal("cached pin ignored known Owner removal")
	}
	if err := s.RememberEndpointGroupGrant(ctx, f.x.f.hub, a, g, f.heads[0], now); err == nil {
		t.Fatal("old exact certificate resurrected removed authority")
	}
	if err := s.ObserveEndpointGroupOwnerControl(ctx, a, g.Relation.GroupID, f.heads[0], now); err == nil {
		t.Fatal("Observe cleared deny")
	}
	if err := s.ObserveEndpointGroupOwnerControl(ctx, a, g.Relation.GroupID, e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}, now); err == nil {
		t.Fatal("Observe returned to default")
	}
	newGrant, p, head := f.manual(t, 0, g.Relation.GroupID, 2, 2, removed, "")
	if err := s.RequireEndpointGroupPolicy(ctx, f.x.f.hub, p, newGrant.PolicyProof, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RememberEndpointGroupGrant(ctx, f.x.f.hub, a, newGrant, head, now); err != nil {
		t.Fatal("new exact Owner authorization could not clear deny", err)
	}
	if s.CheckPeerPinAdmission(ctx, *pin) == nil {
		t.Fatal("old cached pin borrowed re-added authority before fresh pin")
	}
	fresh := f.current(g.Relation.GroupID, wire.EndpointGroupCurrentEndpoint{OwnerControl: head, Relation: newGrant.Relation}, current.Receiver, now)
	newPin, err := s.PinEndpointGroupsPeer(ctx, a.Registration.EndpointID, wire.EndpointGroupPeerSource{EndpointGroupGrant: &newGrant}, wire.EndpointGroupPeerSource{EndpointGroupGrant: &f.grants[1]}, fresh, fresh.Operation, fresh.AttemptID, now)
	if err != nil || newPin.Version <= pin.Version || newPin.KeyID != pin.KeyID || newPin.BindingEpoch != pin.BindingEpoch || s.CheckPeerPinAdmission(ctx, *pin) == nil || s.CheckPeerPinAdmission(ctx, *newPin) != nil {
		t.Fatal("new authority did not invalidate only cached admission metadata", err)
	}
	if yes, err := s.EndpointGroupsRequired(ctx, a.Registration.EndpointID, g.Relation.GroupID); err != nil || !yes {
		t.Fatal("new manual grant cleared permanent Owner-control marker", err)
	}
	never := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: 1, DenyReason: "REMOVED"}
	if err := s.ObserveEndpointGroupOwnerControl(ctx, a, "synthetic-never-completed", never, now); err != nil {
		t.Fatal("removal before first Complete was lost", err)
	}
	if err := endpointGroupsLegacyAllowed(ctx, s.db, "synthetic-never-completed", a.Registration.EndpointID); err == nil {
		t.Fatal("no-policy Owner deny fell back to legacy")
	}
}

func TestEndpointGroupsMixedDefaultAndManualSourcesDoNotBlendPolicies(t *testing.T) {
	f := syntheticEndpointGroupsKeys(t, true, false)
	s := f.x.f.state
	ctx := context.Background()
	now := f.x.f.now
	group := f.x.policy.GroupID
	manual, _, head := f.manual(t, 1, group, 1, 1, e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}, "")
	if err := s.RememberEndpointGroupGrant(ctx, f.x.f.hub, f.anchors[1], manual, head, now); err != nil {
		t.Fatal(err)
	}
	m := f.x.grants[0].Member
	a := f.anchors[0]
	native, _ := endpointGroupsNativeDigest(a)
	defaultHead := e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
	digest, _ := e2ee.EndpointGroupOwnerControlDigest(native, group, defaultHead)
	r := wire.EndpointGroupRelation{HubID: f.x.policy.HubID, OwnerID: f.x.policy.OwnerID, NodeID: m.NodeID, LocalUserScope: m.LocalUserScope, NetworkID: a.NetworkID, GroupID: group, EndpointID: m.EndpointID, PrincipalID: m.PrincipalID, RegistrationDigest: a.RegistrationDigest, RegistrationRevision: a.RegistrationRevision, Source: "DEFAULT_POLICY", AuthorityID: f.x.policy.PolicyID, AuthorityEpoch: f.x.policy.Epoch, ContributionRevision: 1, State: "ACTIVE", OwnerControlDigest: digest, PolicyID: f.x.policy.PolicyID, PolicyEpoch: f.x.policy.Epoch, BindingID: m.BindingID, BindingEpoch: m.BindingEpoch, MembershipRevision: m.MembershipRevision, EndpointJoinRevision: m.EndpointJoinRevision, CandidateVersion: m.CandidateVersion, CandidateKeyID: m.CandidateKeyID, CandidateFingerprint: m.CandidateFingerprint, CandidateProofDigest: m.CandidateProofDigest}
	c := f.current(group, wire.EndpointGroupCurrentEndpoint{OwnerControl: defaultHead, Relation: r}, wire.EndpointGroupCurrentEndpoint{OwnerControl: head, Relation: manual.Relation}, now)
	sender := wire.EndpointGroupPeerSource{LocalDomainGrant: &f.x.grants[0]}
	receiver := wire.EndpointGroupPeerSource{EndpointGroupGrant: &manual}
	pin, err := s.PinEndpointGroupsPeer(ctx, a.Registration.EndpointID, sender, receiver, c, c.Operation, c.AttemptID, now)
	if err != nil {
		t.Fatal("independent default/manual chain refused", err)
	}
	pending, policy, _ := f.manual(t, 0, group, 1, 1, defaultHead, "")
	if err := s.RequireEndpointGroupPolicy(ctx, f.x.f.hub, policy, pending.PolicyProof, now); err != nil {
		t.Fatal(err)
	}
	again, err := s.PinEndpointGroupsPeer(ctx, a.Registration.EndpointID, sender, receiver, c, c.Operation, c.AttemptID, now)
	if err != nil || again.Version != pin.Version || s.CheckPeerPinAdmission(ctx, *pin) != nil {
		t.Fatal("unrelated pending source invalidated controlling default evidence", err)
	}
	if yes, _ := s.EndpointGroupsRequired(ctx, a.Registration.EndpointID, group); yes {
		t.Fatal("remote Owner policy took over default sender")
	}
	if _, err := s.PinLocalDomainPeer(ctx, a.Registration.EndpointID, f.x.grants[0], f.x.grants[1], f.x.current, f.x.current.Operation, f.x.current.AttemptID, now); err == nil {
		t.Fatal("legacy default proof bypassed known manual receiver head")
	}
	bad := receiver
	bad.LocalDomainGrant = &f.x.grants[1]
	if _, err := s.VerifyEndpointGroupsGroupAuthorization(ctx, a.Registration.EndpointID, group, sender, bad, &c, c.Operation, c.AttemptID, now); err == nil {
		t.Fatal("one Endpoint blended proof sources")
	}
}

func TestEndpointGroupsFreshCurrentAndWriterOwnerRevocationFence(t *testing.T) {
	f := syntheticEndpointGroupsKeys(t, true, false)
	s := f.x.f.state
	ctx := context.Background()
	now := f.x.f.now
	c := f.manualCurrent(now)
	a := f.anchors[0]
	sources := [2]wire.EndpointGroupPeerSource{{EndpointGroupGrant: &f.grants[0]}, {EndpointGroupGrant: &f.grants[1]}}
	if required, err := s.VerifyEndpointGroupsGroupAuthorization(ctx, a.Registration.EndpointID, c.GroupID, sources[0], sources[1], &c, c.Operation, c.AttemptID, now); err != nil || !required {
		t.Fatal(err)
	}
	for _, test := range []struct {
		operation, attempt string
		at                 time.Time
	}{{c.Operation, "synthetic-other-attempt", now}, {"send", c.AttemptID, now}, {c.Operation, c.AttemptID, now.Add(30 * time.Second)}} {
		if _, err := s.VerifyEndpointGroupsGroupAuthorization(ctx, a.Registration.EndpointID, c.GroupID, sources[0], sources[1], &c, test.operation, test.attempt, test.at); err == nil {
			t.Fatal("stale/different operation Current admitted")
		}
	}
	other, err := OpenCryptoState(f.x.f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	trust, err := other.GetNodeOwnerKeyTrustLocal(f.x.policy.OwnerID, f.x.f.owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.RevokeNodeOwnerKeyTrustLocal(trust.OwnerID, trust.KeyID, trust.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PinEndpointGroupsPeer(ctx, a.Registration.EndpointID, sources[0], sources[1], c, c.Operation, c.AttemptID, now); err == nil {
		t.Fatal("Owner revoked after preliminary verification still pinned")
	}
	var n int
	if s.db.QueryRow(`SELECT count(*) FROM node_crypto_peer_pins`).Scan(&n) != nil || n != 0 {
		t.Fatal("revoked writer partially installed pin")
	}
	// Existing cached admission also rechecks the independent Owner pin rather
	// than borrowing a still-equal Endpoint key after local Owner revocation.
	freshFixture := syntheticEndpointGroupsKeys(t, true, false)
	state := freshFixture.x.f.state
	current := freshFixture.manualCurrent(freshFixture.x.f.now)
	pin, err := state.PinEndpointGroupsPeer(ctx, freshFixture.anchors[0].Registration.EndpointID, wire.EndpointGroupPeerSource{EndpointGroupGrant: &freshFixture.grants[0]}, wire.EndpointGroupPeerSource{EndpointGroupGrant: &freshFixture.grants[1]}, current, current.Operation, current.AttemptID, freshFixture.x.f.now)
	if err != nil {
		t.Fatal(err)
	}
	root, err := state.GetNodeOwnerKeyTrustLocal(freshFixture.x.policy.OwnerID, freshFixture.x.f.owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.RevokeNodeOwnerKeyTrustLocal(root.OwnerID, root.KeyID, root.Version); err != nil {
		t.Fatal(err)
	}
	if state.CheckPeerPinAdmission(ctx, *pin) == nil {
		t.Fatal("cached managed pin ignored independent Owner revocation")
	}
}

func TestEndpointGroupsPrivateRegistrationRejectsScopeAndIdentityReplacement(t *testing.T) {
	f := syntheticEndpointGroupsKeys(t, true, false)
	s := f.x.f.state
	ctx := context.Background()
	a := f.anchors[0]
	for i, change := range []func(*wire.EndpointGroupsRegistrationAnchor){func(a *wire.EndpointGroupsRegistrationAnchor) {
		a.Registration.NativeSessionID = "synthetic-other-session"
	}, func(a *wire.EndpointGroupsRegistrationAnchor) { a.Registration.Workspace += "/other" }, func(a *wire.EndpointGroupsRegistrationAnchor) { a.Registration.EndpointID = "synthetic-alias" }, func(a *wire.EndpointGroupsRegistrationAnchor) { a.LocalUserScope = "uid:1001" }, func(a *wire.EndpointGroupsRegistrationAnchor) {
		a.NetworkAccessBindingID = "synthetic-replacement-access"
	}, func(a *wire.EndpointGroupsRegistrationAnchor) { a.BindingEpoch++ }, func(a *wire.EndpointGroupsRegistrationAnchor) { a.NodeKeyEpoch++ }, func(a *wire.EndpointGroupsRegistrationAnchor) { a.Profile = "LEGACY_STRICT" }} {
		bad := a
		change(&bad)
		bad.RegistrationDigest, _ = e2ee.EndpointGroupRegistrationDigest(bad.Registration)
		if err := s.CheckEndpointGroupsRegistration(ctx, f.x.f.hub, bad, f.x.f.now); err == nil {
			t.Fatalf("registration replacement %d accepted", i)
		}
	}
	if required, err := s.EndpointGroupsRequired(ctx, a.Registration.EndpointID, f.x.policy.GroupID); err != nil || required {
		t.Fatal("zero-right registration granted a Group marker", err)
	}
	before, err := s.LocalDomainOriginalLocalKey(ctx, a.Registration.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, a.CandidatePublic) {
		t.Fatal("original key replaced")
	}
	var old int
	if err := s.db.QueryRow(`SELECT version FROM node_crypto_schema`).Scan(&old); err != nil || old != 8 {
		t.Fatal("schema mismatch", err)
	}
}

func TestEndpointGroupsTrustedForeignOwnerCannotBorrowSameNetworkGroup(t *testing.T) {
	f := syntheticEndpointGroupsKeys(t, true, false)
	ctx := context.Background()
	s := f.x.f.state
	now := f.x.f.now
	foreignOwner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := PeerKeyFingerprint(foreignOwner.Public())
	if err != nil {
		t.Fatal(err)
	}
	const otherOwner = "synthetic-foreign-owner"
	if _, err := s.TrustOwnerApprovalKeyLocal(otherOwner, foreignOwner.Public().ID, foreignOwner.Public(), fingerprint); err != nil {
		t.Fatal(err)
	}
	// A second complete valid Owner/Node chain is trusted locally. Its proof
	// remains ineligible for this same-Owner profile even in the same Group.
	other := *f
	otherX := *f.x
	otherBase := *f.x.f
	otherBase.owner = foreignOwner
	otherX.f = &otherBase
	otherX.policy.OwnerID = otherOwner
	otherX.policy.OwnerPublic = foreignOwner.Public()
	otherX.policy.Node.OwnerID = otherOwner
	otherX.policy.Node.OwnerKeyID = foreignOwner.Public().ID
	otherX.policy.Node.OwnerBindingID = "synthetic-foreign-owner-binding"
	otherX.grants[1].Manifest.OwnerID = otherOwner
	otherX.grants[1].Manifest.OwnerKeyID = foreignOwner.Public().ID
	other.x = &otherX
	other.anchors[1].Registration.OwnerID = otherOwner
	other.anchors[1].RegistrationDigest, _ = e2ee.EndpointGroupRegistrationDigest(other.anchors[1].Registration)
	for _, kind := range []string{"manual-manual", "default-manual"} {
		t.Run(kind, func(t *testing.T) {
			group := f.grants[0].Relation.GroupID
			sender := wire.EndpointGroupPeerSource{EndpointGroupGrant: &f.grants[0]}
			senderSnapshot := wire.EndpointGroupCurrentEndpoint{OwnerControl: f.heads[0], Relation: f.grants[0].Relation}
			if kind == "default-manual" {
				group = f.x.policy.GroupID
				sender = wire.EndpointGroupPeerSource{LocalDomainGrant: &f.x.grants[0]}
				a := f.anchors[0]
				m := f.x.grants[0].Member
				head := e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
				native, _ := endpointGroupsNativeDigest(a)
				digest, _ := e2ee.EndpointGroupOwnerControlDigest(native, group, head)
				senderSnapshot = wire.EndpointGroupCurrentEndpoint{OwnerControl: head, Relation: wire.EndpointGroupRelation{HubID: f.x.policy.HubID, OwnerID: f.x.policy.OwnerID, NodeID: m.NodeID, LocalUserScope: m.LocalUserScope, NetworkID: a.NetworkID, GroupID: group, EndpointID: m.EndpointID, PrincipalID: m.PrincipalID, RegistrationDigest: a.RegistrationDigest, RegistrationRevision: a.RegistrationRevision, Source: "DEFAULT_POLICY", AuthorityID: f.x.policy.PolicyID, AuthorityEpoch: f.x.policy.Epoch, ContributionRevision: 1, State: "ACTIVE", OwnerControlDigest: digest, PolicyID: f.x.policy.PolicyID, PolicyEpoch: f.x.policy.Epoch, BindingID: m.BindingID, BindingEpoch: m.BindingEpoch, MembershipRevision: m.MembershipRevision, EndpointJoinRevision: m.EndpointJoinRevision, CandidateVersion: m.CandidateVersion, CandidateKeyID: m.CandidateKeyID, CandidateFingerprint: m.CandidateFingerprint, CandidateProofDigest: m.CandidateProofDigest}}
			}
			foreign, _, head := other.manual(t, 1, group, 1, 1, e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}, "")
			receiver := wire.EndpointGroupPeerSource{EndpointGroupGrant: &foreign}
			receiverSnapshot := wire.EndpointGroupCurrentEndpoint{OwnerControl: head, Relation: foreign.Relation}
			if _, err := wire.VerifyEndpointGroupPeerSource(sender, senderSnapshot, f.x.f.hub, f.x.policy.OwnerID, f.x.f.owner.Public(), now); err != nil {
				t.Fatal("local positive proof invalid", err)
			}
			if _, err := wire.VerifyEndpointGroupPeerSource(receiver, receiverSnapshot, f.x.f.hub, otherOwner, foreignOwner.Public(), now); err != nil {
				t.Fatal("foreign positive proof invalid", err)
			}
			current := f.current(group, senderSnapshot, receiverSnapshot, now)
			if _, err := s.VerifyEndpointGroupsGroupAuthorization(ctx, f.anchors[0].Registration.EndpointID, group, sender, receiver, &current, current.Operation, current.AttemptID, now); err == nil {
				t.Fatal("read verifier mixed trusted Owners")
			}
			if _, err := s.PinEndpointGroupsPeer(ctx, f.anchors[0].Registration.EndpointID, sender, receiver, current, current.Operation, current.AttemptID, now); err == nil {
				t.Fatal("writer pin mixed trusted Owners")
			}
		})
	}
	var count int
	if s.db.QueryRow(`SELECT count(*) FROM node_crypto_peer_pins`).Scan(&count) != nil || count != 0 {
		t.Fatal("foreign Owner refusal partially installed a pin")
	}
}

// A peer can miss removal while retaining the old ACTIVE source. The first
// subsequent ASK must accept the new signed authority, in either direction,
// even though both Hub Complete results have contribution revision two.
func TestEndpointGroupsReaddedPeerAuthorityKeepsIndependentContributionCounter(t *testing.T) {
	f := syntheticEndpointGroupsKeys(t, true, false)
	ctx := context.Background()
	s := f.x.f.state
	now := f.x.f.now
	oldGrant := f.grants[0]
	otherGrant := f.grants[1]
	local := f.anchors[1].Registration.EndpointID
	oldCurrent := f.manualCurrent(now)
	oldSource := wire.EndpointGroupPeerSource{EndpointGroupGrant: &oldGrant}
	otherSource := wire.EndpointGroupPeerSource{EndpointGroupGrant: &otherGrant}
	pin, err := s.PinEndpointGroupsPeer(ctx, local, oldSource, otherSource, oldCurrent, oldCurrent.Operation, oldCurrent.AttemptID, now)
	if err != nil {
		t.Fatal("initial remote source", err)
	}
	removed := f.heads[0]
	removed.Revision++
	removed.DenyReason = "REMOVED"
	readded, _, head := f.manual(t, 0, oldGrant.Relation.GroupID, 2, 2, removed, "")
	if oldGrant.Relation.ContributionRevision != 2 || readded.Relation.ContributionRevision != 2 {
		t.Fatal("fixture differs from actual Hub Complete counters")
	}
	source := wire.EndpointGroupPeerSource{EndpointGroupGrant: &readded}
	current := f.current(readded.Relation.GroupID, wire.EndpointGroupCurrentEndpoint{OwnerControl: head, Relation: readded.Relation}, oldCurrent.Receiver, now)
	if required, err := s.VerifyEndpointGroupsGroupAuthorization(ctx, local, current.GroupID, source, otherSource, &current, current.Operation, current.AttemptID, now); err != nil || !required {
		t.Fatal("first ASK rejected higher remote authority with the same contribution counter", err)
	}
	fresh, err := s.PinEndpointGroupsPeer(ctx, local, source, otherSource, current, current.Operation, current.AttemptID, now)
	if err != nil {
		t.Fatal("new remote authority pin", err)
	}
	if fresh.Version <= pin.Version || fresh.KeyID != pin.KeyID || fresh.BindingID != pin.BindingID || fresh.BindingEpoch != pin.BindingEpoch || !samePublicIdentity(fresh.Public, pin.Public) {
		t.Fatal("readd replaced original identity instead of advancing admission metadata")
	}
	if s.CheckPeerPinAdmission(ctx, *pin) == nil {
		t.Fatal("old cached pin borrowed new authority")
	}
	// The opposite direction reuses each Endpoint's own source/head. A shared
	// Group counter or sender-only comparison would reject or mutate this pin.
	reverse := f.current(current.GroupID, current.Receiver, current.Sender, now)
	reversePin, err := s.PinEndpointGroupsPeer(ctx, local, otherSource, source, reverse, reverse.Operation, reverse.AttemptID, now)
	if err != nil || reversePin.Version != fresh.Version {
		t.Fatal("ASK direction changed authority admission", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenCryptoState(f.x.f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	f.x.f.state = reopened
	s = reopened
	if required, err := s.VerifyEndpointGroupsGroupAuthorization(ctx, local, reverse.GroupID, otherSource, source, &reverse, reverse.Operation, reverse.AttemptID, now); err != nil || !required {
		t.Fatal("new authority failed persisted restart", err)
	}
	if err := s.CheckPeerPinAdmission(ctx, *fresh); err != nil {
		t.Fatal("fresh persisted pin rejected", err)
	}
	if required, err := s.VerifyEndpointGroupsGroupAuthorization(ctx, local, oldCurrent.GroupID, oldSource, otherSource, &oldCurrent, oldCurrent.Operation, oldCurrent.AttemptID, now); !required || !errors.Is(err, ErrEndpointGroupsConflict) {
		t.Fatal("old authority epoch replay accepted", err)
	}
	if _, err := s.PinEndpointGroupsPeer(ctx, local, oldSource, otherSource, current, current.Operation, current.AttemptID, now); err == nil {
		t.Fatal("old source blended with higher current head")
	}
	// Neither replay attempt may roll back the accepted source or cached pin.
	if err := s.CheckPeerPinAdmission(ctx, *fresh); err != nil {
		t.Fatal("rejected replay damaged current admission", err)
	}
}
