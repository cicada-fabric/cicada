package hubaccountwire

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func syntheticEndpointGroupsNode(t *testing.T) (*e2ee.Identity, endpointGroupsFixture, EndpointGroupsNodeKeyResult) {
	t.Helper()
	g := syntheticEndpointGroupsReview(t, OwnerEndpointGroupsAddEndpoint)
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p := g.review.Policy
	p.Node.NodePublic = node.Public()
	p.Node.NodeKeyFingerprint = nodewire.IdentityFingerprint(node.Public())
	reg := e2ee.EndpointGroupRegistration{HubID: p.HubID, OwnerID: p.OwnerID, NodeID: p.Node.NodeID, Harness: "codex", NativeSessionID: "synthetic-original-D", Workspace: "/synthetic/D", EndpointID: p.EndpointID, PrincipalID: p.PrincipalID}
	a := EndpointGroupsRegistrationAnchor{Profile: EndpointGroupsNativeProfile, RegistrationSource: EndpointGroupsRegistrationSource, Registration: reg, RegistrationRevision: 1, LocalUserScope: p.LocalUserScope, NetworkID: p.NetworkID, BindingID: p.BindingID, BindingEpoch: p.BindingEpoch, NodeKeyEpoch: p.Node.NodeKeyEpoch, LeaseOwner: "synthetic-writer", NetworkAccessBindingID: "synthetic-original-access", NetworkAccessEpoch: 1, NetworkMembershipRevision: 1, EndpointNetworkRevision: 1, CandidateVersion: p.CandidateVersion, CandidateKeyID: p.EndpointKeyID, CandidatePublic: p.EndpointPublic, CandidateFingerprint: p.EndpointFingerprint, CandidateProofDigest: p.CandidateProofDigest, State: "REGISTERED", LeaseExpiresAt: formatUTC(g.f.now.Add(5 * time.Minute))}
	a.RegistrationDigest, _ = e2ee.EndpointGroupRegistrationDigest(reg)
	old := e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
	nativeDigest, _ := e2ee.EndpointGroupNativeIdentityDigest(EndpointGroupsNativeIdentity(a))
	oldDigest, _ := e2ee.EndpointGroupOwnerControlDigest(nativeDigest, p.GroupID, old)
	p.RegistrationDigest = a.RegistrationDigest
	p.ExpectedOwnerControlDigest = oldDigest
	g.review.Target.RegistrationDigest = a.RegistrationDigest
	g.review.Expected.RegistrationDigest = a.RegistrationDigest
	g.review.Expected.OwnerControlDigest = oldDigest
	core := p.Core()
	g.review.Projection.PolicyCore = &core
	g.review.ReviewDigest, _ = OwnerEndpointGroupsReviewDigest(g.review)
	p.ReviewDigest = g.review.ReviewDigest
	proof, err := e2ee.SignOwnerEndpointGroupPolicy(g.f.owner, *p)
	if err != nil {
		t.Fatal(err)
	}
	head := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: 1, DenyReason: "NONE", PolicyID: p.PolicyID, PolicyEpoch: p.Epoch}
	headDigest, _ := e2ee.EndpointGroupOwnerControlDigest(nativeDigest, p.GroupID, head)
	relation := EndpointGroupRelation{HubID: p.HubID, OwnerID: p.OwnerID, NodeID: p.Node.NodeID, LocalUserScope: p.LocalUserScope, NetworkID: p.NetworkID, GroupID: p.GroupID, EndpointID: p.EndpointID, PrincipalID: p.PrincipalID, RegistrationDigest: p.RegistrationDigest, RegistrationRevision: p.RegistrationRevision, Source: "OWNER_EXPLICIT", AuthorityID: p.PolicyID, AuthorityEpoch: p.Epoch, ContributionRevision: 2, State: "ACTIVE", DecisionRevision: 1, OwnerControlDigest: headDigest, PolicyID: p.PolicyID, PolicyEpoch: p.Epoch, BindingID: p.BindingID, BindingEpoch: p.BindingEpoch, MembershipRevision: 1, EndpointJoinRevision: 1, CandidateVersion: p.CandidateVersion, CandidateKeyID: p.EndpointKeyID, CandidateFingerprint: p.EndpointFingerprint, CandidateProofDigest: p.CandidateProofDigest, ExpiresAt: p.ExpiresAt}
	manifest := *g.review.KeyManifest
	manifest.MembershipRevision = 1
	manifest.EndpointJoinRevision = 1
	manifest.IssuedAt = formatUTC(g.f.now.Add(2 * time.Second))
	manifest.CandidateBindingDigest, _ = LocalDomainGroupBindingDigest(manifest)
	manifest.Digest, _ = LocalDomainGroupManifestDigest(manifest)
	expected := g.review.Expected
	expected.PolicyEpoch = p.Epoch
	expected.RelationRevision = 1
	c := EndpointGroupKeyPrepareResult{ChallengeID: strings.Repeat("e", 32), PolicyID: p.PolicyID, PolicyEpoch: p.Epoch, Expected: expected, ProjectedOwnerControl: head, ProjectedRelation: relation, ProjectedKeyManifest: manifest, ObservedAt: manifest.IssuedAt, ExpiresAt: formatUTC(g.f.now.Add(5 * time.Minute))}
	c.ChallengeDigest, _ = EndpointGroupKeyChallengeDigest(c)
	r := EndpointGroupsNodeKeyResult{ContractRevision: OwnerEndpointGroupsContractRevision, Registration: a, PolicyProof: proof, Challenge: &c, OwnerControl: old, ObservedAt: c.ObservedAt}
	if _, err := ValidateEndpointGroupsNodeKeyResult(r, g.f.hub, p.OwnerID, g.f.owner.Public(), g.f.now.Add(3*time.Second)); err != nil {
		t.Fatal("synthetic Node challenge", err)
	}
	return node, g, r
}

func TestEndpointGroupsNodeProjectedGrantAndChallengeNegatives(t *testing.T) {
	node, g, r := syntheticEndpointGroupsNode(t)
	p := *g.review.Policy
	now := g.f.now.Add(3 * time.Second)
	claims, err := EndpointGroupKeyClaimsForChallenge(*r.Challenge, p)
	if err != nil {
		t.Fatal(err)
	}
	nodeProof, err := e2ee.SignEndpointGroupKey(node, p, claims)
	if err != nil {
		t.Fatal(err)
	}
	grant := EndpointGroupDelegatedGrant{Manifest: r.Challenge.ProjectedKeyManifest, Relation: r.Challenge.ProjectedRelation, PolicyProof: r.PolicyProof, NodeProof: nodeProof}
	if _, err := VerifyEndpointGroupDelegatedGrant(grant, g.f.hub, p.OwnerID, g.f.owner.Public(), now); err != nil {
		t.Fatal(err)
	}
	complete := r
	complete.Challenge = nil
	complete.Grant = &grant
	complete.OwnerControl = r.Challenge.ProjectedOwnerControl
	if _, err := ValidateEndpointGroupsNodeKeyResult(complete, g.f.hub, p.OwnerID, g.f.owner.Public(), now); err != nil {
		t.Fatal("completed exact projection", err)
	}
	for i, change := range []func(*EndpointGroupsNodeKeyResult){
		func(r *EndpointGroupsNodeKeyResult) {
			r.Challenge.ProjectedKeyManifest.IssuedAt = formatUTC(g.f.now.Add(1500 * time.Millisecond))
			r.Challenge.ProjectedKeyManifest.Digest, _ = LocalDomainGroupManifestDigest(r.Challenge.ProjectedKeyManifest)
		},
		func(r *EndpointGroupsNodeKeyResult) { r.Challenge.Expected.GroupVersion++ },
		func(r *EndpointGroupsNodeKeyResult) {
			r.Challenge.ProjectedRelation.MembershipRevision += 2
			r.Challenge.ProjectedKeyManifest.MembershipRevision += 2
			r.Challenge.ProjectedKeyManifest.CandidateBindingDigest, _ = LocalDomainGroupBindingDigest(r.Challenge.ProjectedKeyManifest)
			r.Challenge.ProjectedKeyManifest.Digest, _ = LocalDomainGroupManifestDigest(r.Challenge.ProjectedKeyManifest)
		},
		func(r *EndpointGroupsNodeKeyResult) { r.Challenge.ProjectedOwnerControl.Revision++ },
		func(r *EndpointGroupsNodeKeyResult) { r.Registration.BindingEpoch++ },
	} {
		var bad EndpointGroupsNodeKeyResult
		json.Unmarshal(mustEndpointGroupsJSON(t, r), &bad)
		change(&bad)
		bad.Challenge.ChallengeDigest, _ = EndpointGroupKeyChallengeDigest(*bad.Challenge)
		if _, err := ValidateEndpointGroupsNodeKeyResult(bad, g.f.hub, p.OwnerID, g.f.owner.Public(), now); err == nil {
			t.Fatalf("altered projected challenge %d accepted", i)
		}
	}
	snapshot := EndpointGroupCurrentEndpoint{complete.OwnerControl, grant.Relation}
	if _, err := VerifyEndpointGroupPeerSource(EndpointGroupPeerSource{EndpointGroupGrant: &grant}, snapshot, g.f.hub, p.OwnerID, g.f.owner.Public(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEndpointGroupPeerSource(EndpointGroupPeerSource{EndpointGroupGrant: &grant, LocalDomainGrant: &LocalDomainEndpointKeyGrant{}}, snapshot, g.f.hub, p.OwnerID, g.f.owner.Public(), now); err == nil {
		t.Fatal("multiple authority sources accepted")
	}
	if _, err := VerifyEndpointGroupPeerSource(EndpointGroupPeerSource{EndpointGroupGrant: &grant}, snapshot, g.f.hub, p.OwnerID, node.Public(), now); err == nil {
		t.Fatal("arriving grant replaced original Owner pin")
	}
}

func TestEndpointGroupsNodeDescribeAuthoritiesAreExactBijection(t *testing.T) {
	_, g, key := syntheticEndpointGroupsNode(t)
	c := key.Challenge
	ref := EndpointGroupSourceReference{Source: "OWNER_EXPLICIT", AuthorityID: c.PolicyID, AuthorityEpoch: c.PolicyEpoch, ContributionRevision: c.ProjectedRelation.ContributionRevision}
	card := OwnerEndpointGroupsRelationCard{GroupID: c.ProjectedRelation.GroupID, GroupName: "Synthetic G2", NetworkID: c.ProjectedRelation.NetworkID, State: "ACTIVE", RelationRevision: 2, DecisionRevision: 1, OwnerControl: c.ProjectedOwnerControl, Contributions: []OwnerEndpointGroupsContributionCard{{Source: ref.Source, AuthorityID: ref.AuthorityID, AuthorityEpoch: ref.AuthorityEpoch, ContributionRevision: ref.ContributionRevision, State: "ACTIVE", KeyState: "CURRENT", Effective: true}}, SelectedSource: &ref, KeyState: "CURRENT"}
	r := EndpointGroupsNodeDescribeResult{ContractRevision: OwnerEndpointGroupsContractRevision, Registration: key.Registration, Relations: []OwnerEndpointGroupsRelationCard{card}, Authorities: []EndpointGroupCurrentEndpoint{{c.ProjectedOwnerControl, c.ProjectedRelation}}, RelationsRevision: 2, Complete: true, ObservedAt: c.ObservedAt}
	now := g.f.now.Add(3 * time.Second)
	if ValidateEndpointGroupsNodeDescribeResult(r, g.f.hub, now) != nil {
		t.Fatal("exact active page rejected")
	}
	orphan := r
	orphan.Relations = []OwnerEndpointGroupsRelationCard{{GroupID: "synthetic-G1", GroupName: "Synthetic G1", NetworkID: r.Registration.NetworkID, State: "NONE", OwnerControl: e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}, KeyState: "NOT_READY"}}
	if ValidateEndpointGroupsNodeDescribeResult(orphan, g.f.hub, now) == nil {
		t.Fatal("orphan G2 authority outside relation page accepted")
	}
	missing := r
	missing.Authorities = nil
	if ValidateEndpointGroupsNodeDescribeResult(missing, g.f.hub, now) == nil {
		t.Fatal("active card missing exact authority accepted")
	}
	r.Registration.Profile = "LOCAL_DOMAIN_V1"
	if ValidateEndpointGroupsNodeDescribeResult(r, g.f.hub, now) == nil {
		t.Fatal("capability silently upgraded legacy registration")
	}
}

func TestEndpointGroupsNodeClosedRequestAndRawDigestRecovery(t *testing.T) {
	q := EndpointGroupsNodeRenew{EndpointID: "synthetic-D", RegistrationDigest: strings.Repeat("a", 64), ExpectedBindingID: "synthetic-original-binding", ExpectedBindingEpoch: 1}
	plain, err := CanonicalEndpointGroupsNodeRequest(OperationEndpointGroupsNodeRenew, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEndpointGroupsNodeRequest(OperationEndpointGroupsNodeRenew, []byte(strings.Replace(string(plain), `"endpoint_id":`, `"native_session_id":"invented","endpoint_id":`, 1))); err == nil {
		t.Fatal("caller-supplied identity accepted")
	}
	route := nodewire.Route{Version: 1, Direction: nodewire.DirectionRequest, HubID: "synthetic-hub", NodeID: "synthetic-node", BindingID: "synthetic-binding", BindingVersion: 1, NodeKeyEpoch: 1, Sequence: 1, OperationID: "synthetic-operation", Operation: OperationEndpointGroupsNodeRenew, SenderKeyID: "synthetic-node-key", SenderKeyVersion: 1, ReceiverKeyID: "synthetic-hub-key", ReceiverKeyVersion: 1}
	original := mustEndpointGroupsJSON(t, nodewire.Packet{Route: route, Envelope: []byte("SYNTHETIC_NOT_A_REAL_ENVELOPE")})
	response := route
	response.Direction = nodewire.DirectionResponse
	response.SenderKeyID, response.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
	response.SenderKeyVersion, response.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
	receipt := mustEndpointGroupsJSON(t, nodewire.Packet{Route: response, Envelope: []byte("SYNTHETIC_NOT_A_REAL_ENVELOPE")})
	r := EndpointGroupsNodeReconciled{ContractRevision: OwnerEndpointGroupsContractRevision, OriginalOperation: route.Operation, OriginalOperationID: route.OperationID, OriginalSequence: route.Sequence, OriginalPacketDigest: nodewire.RecoveryDigest(original), State: "COMPLETED", ReceiptPacket: receipt, ObservedAt: "2026-10-26T12:00:00Z"}
	if ValidateEndpointGroupsNodeReconcileTarget(r, original) != nil {
		t.Fatal("raw Node carrier digest rejected")
	}
	r.OriginalPacketDigest = OwnerEndpointGroupsPacketDigest(original)
	if ValidateEndpointGroupsNodeReconcileTarget(r, original) == nil {
		t.Fatal("Owner digest substituted for raw Node ledger digest")
	}
}

func TestOwnerEndpointGroupsTargetlessFenceIsOnlyExactOriginalApply(t *testing.T) {
	g := syntheticEndpointGroupsReview(t, OwnerEndpointGroupsCreateGroup)
	f := g.f
	q, err := NewOwnerEndpointGroupsApply(f.session, f.scope, g.prepare, g.original, g.review, f.owner, f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	original, err := SealClientRequest(f.device, f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	r := OwnerEndpointGroupsResult{Format: OwnerEndpointGroupsResultFormat, ContractRevision: OwnerEndpointGroupsContractRevision, RequestID: q.Context.RequestID, RequestPacketDigest: OwnerEndpointGroupsPacketDigest(original), HubID: f.hub.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, State: "REJECTED_FENCED", ErrorCode: OwnerEndpointGroupsOriginalNotAdmitted, CapturedAt: formatUTC(f.now.Add(3 * time.Second)), Freshness: "SNAPSHOT_ONLY"}
	_, route, _ := NewClientRoute(f.hub, q, f.device.Public())
	sealed, err := SealResponse(f.hubPrivate, f.device.Public(), route, r)
	if err != nil {
		t.Fatal(err)
	}
	var opened OwnerEndpointGroupsResult
	if OpenOwnerEndpointGroupsResponse(f.device, f.hub, original, sealed, &opened) != nil || VerifyOwnerEndpointGroupsOriginalFence(q, original, opened, f.hub) != nil {
		t.Fatal("authenticated original no-effect fence rejected")
	}
	for _, change := range []func(*OwnerEndpointGroupsResult){func(r *OwnerEndpointGroupsResult) { r.ErrorCode = "REVIEW_EXPIRED" }, func(r *OwnerEndpointGroupsResult) { r.ErrorCode = "OUTCOME_UNCERTAIN" }, func(r *OwnerEndpointGroupsResult) { r.NodeID = g.review.Target.NodeID }, func(r *OwnerEndpointGroupsResult) {
		r.RequestPacketDigest = OwnerEndpointGroupsPacketDigest(g.original)
	}} {
		bad := r
		change(&bad)
		if VerifyOwnerEndpointGroupsOriginalFence(q, original, bad, f.hub) == nil {
			t.Fatal("wrapper/uncertainty/untargeted state became original fence")
		}
	}
}
