package main

import (
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

// Isolated public-field mapping, not a signature or authorization acceptance
// fixture. Full evidence verification has separate real-signature SQLite tests.
func TestNativePairCurrentEndpointUsesProjectedMembershipAndExactOtherFields(t *testing.T) {
	key, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	s := wire.NativePairSlot{Slot: "A", EndpointID: "synthetic-endpoint-a", PrincipalID: "synthetic-principal-a", NodeID: "synthetic-node", BindingID: "synthetic-binding-a", BindingEpoch: 3, NativeSessionID: "synthetic-native-a", MembershipRevision: 4, EndpointJoinRevision: 6, CandidateVersion: 2, CandidatePublic: key.Public(), CandidateProofDigest: "synthetic-map-only", CandidateAttestation: []byte("synthetic-map-only-not-a-signature")}
	p := wire.NativePairConsentPlan{GroupID: "synthetic-group", GroupRevision: 7, ProjectedSlotAMembership: 5, SlotA: s, Scope: e2ee.OwnerNativePairScope{Actor: e2ee.OwnerAppNodeScope{OwnerID: "synthetic-owner", OwnerPublic: key.Public()}}, SlotAKeyManifest: wire.NativePairGroupKeyManifest{NativePairGroupKeyClaims: wire.NativePairGroupKeyClaims{CandidateBindingDigest: "synthetic-binding-map"}, Digest: "synthetic-manifest-map"}}
	a := crossNodeGroupEndpointEvidence{EndpointID: s.EndpointID, PrincipalID: s.PrincipalID, OwnerID: p.Scope.Actor.OwnerID, NodeID: s.NodeID, GroupID: p.GroupID, BindingID: s.BindingID, BindingEpoch: s.BindingEpoch, NativeSessionID: s.NativeSessionID, GroupRevision: 7, MembershipRevision: 5, EndpointJoinRevision: 6,
		Candidate: store.EndpointKeyCandidate{EndpointID: s.EndpointID, PrincipalID: s.PrincipalID, OwnerID: p.Scope.Actor.OwnerID, NodeID: s.NodeID, BindingID: s.BindingID, BindingEpoch: s.BindingEpoch, KeyID: s.CandidatePublic.ID, Public: s.CandidatePublic, Version: 2, State: store.EndpointKeyCandidateStateCandidate, Proof: s.CandidateAttestation, ProofDigest: s.CandidateProofDigest},
		Grant:     &store.OwnerGroupEndpointKeyGrant{OwnerID: p.Scope.Actor.OwnerID, GroupID: p.GroupID, EndpointID: s.EndpointID, OwnerKeyID: p.Scope.Actor.OwnerPublic.ID, CurrentStatus: store.GroupEndpointKeyGrantCurrent, Manifest: store.GroupEndpointKeyGrantManifest{Digest: p.SlotAKeyManifest.Digest, CandidateBindingDigest: p.SlotAKeyManifest.CandidateBindingDigest}}}
	if err := matchNativePairEndpoint(a, s, p); err != nil {
		t.Fatal("projected membership rejected", err)
	}
	redacted := a
	redacted.NativeSessionID = ""
	if err := matchNativePairEndpoint(redacted, s, p); err != nil {
		t.Fatal("legacy receiver SID redaction rejected; Current verifies the actual SID separately", err)
	}
	for _, edit := range []func(*crossNodeGroupEndpointEvidence){func(a *crossNodeGroupEndpointEvidence) { a.MembershipRevision = 4 }, func(a *crossNodeGroupEndpointEvidence) { a.NativeSessionID = "synthetic-other" }, func(a *crossNodeGroupEndpointEvidence) { a.EndpointJoinRevision++ }, func(a *crossNodeGroupEndpointEvidence) { a.BindingEpoch++ }, func(a *crossNodeGroupEndpointEvidence) { a.Candidate.Version++ }, func(a *crossNodeGroupEndpointEvidence) { a.Grant = nil }} {
		bad := a
		edit(&bad)
		if matchNativePairEndpoint(bad, s, p) == nil {
			t.Fatal("unreviewed Endpoint field accepted")
		}
	}
}
