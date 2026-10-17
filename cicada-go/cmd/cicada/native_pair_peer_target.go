package main

import (
	"bytes"
	"errors"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

// Compare the existing endpoint/candidate/grant carrier fields after verifying
// the complete Owner evidence. The separate current Network/lease projection
// must also match before a Pair operation is admitted. Plan slots retain their
// pre-activation memberships; current carriers use the signed projections.
func matchNativePairEndpoint(actual crossNodeGroupEndpointEvidence, slot wire.NativePairSlot, p wire.NativePairConsentPlan) error {
	manifest, proofMembership := p.SlotAKeyManifest, p.ProjectedSlotAMembership
	if slot.Slot == "B" {
		manifest, proofMembership = p.SlotBKeyManifest, p.ProjectedSlotBMembership
	} else if slot.Slot != "A" {
		return errors.New("invalid Pair slot")
	}
	if actual.EndpointID != slot.EndpointID || actual.PrincipalID != slot.PrincipalID || actual.OwnerID != p.Scope.Actor.OwnerID || actual.NodeID != slot.NodeID || actual.GroupID != p.GroupID || actual.BindingID != slot.BindingID || actual.BindingEpoch != slot.BindingEpoch || actual.NativeSessionID != slot.NativeSessionID || actual.GroupRevision != int64(p.GroupRevision) || actual.MembershipRevision != int64(proofMembership) || actual.EndpointJoinRevision != int64(slot.EndpointJoinRevision) {
		return errors.New("current Pair Endpoint differs from the reviewed slot")
	}
	c := actual.Candidate
	if c.EndpointID != slot.EndpointID || c.PrincipalID != slot.PrincipalID || c.OwnerID != actual.OwnerID || c.NodeID != slot.NodeID || c.BindingID != slot.BindingID || c.BindingEpoch != slot.BindingEpoch || c.Version != int64(slot.CandidateVersion) || c.State != store.EndpointKeyCandidateStateCandidate || c.KeyID != slot.CandidatePublic.ID || !sameMCPKeyPublic(c.Public, slot.CandidatePublic) || c.ProofDigest != slot.CandidateProofDigest || !bytes.Equal(c.Proof, slot.CandidateAttestation) {
		return errors.New("current Pair candidate differs from the reviewed key")
	}
	g := actual.Grant
	if g == nil || g.OwnerID != actual.OwnerID || g.GroupID != p.GroupID || g.EndpointID != slot.EndpointID || g.OwnerKeyID != p.Scope.Actor.OwnerPublic.ID || g.CurrentStatus != store.GroupEndpointKeyGrantCurrent || g.Manifest.Digest != manifest.Digest || g.Manifest.CandidateBindingDigest != manifest.CandidateBindingDigest {
		return errors.New("current Pair grant differs from the activation manifest")
	}
	return nil
}
