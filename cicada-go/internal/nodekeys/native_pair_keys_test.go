package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestNativePairCandidateAckLossRetainsExactKeyAndAttestation(t *testing.T) {
	f := newNativePairStateFixture(t, true)
	f.require(t)
	ctx := context.Background()
	slot := f.evidence.Plan.SlotA
	c := GroupEndpointKeyCandidate{EndpointID: slot.EndpointID, GroupID: f.evidence.Plan.GroupID, PrincipalID: slot.PrincipalID, OwnerID: f.scope.Actor.OwnerID, NodeID: slot.NodeID, BindingID: slot.BindingID, BindingEpoch: slot.BindingEpoch, KeyID: slot.CandidatePublic.ID, KeyFingerprint: slot.CandidateFingerprint, ProofDigest: slot.CandidateProofDigest, PublicIdentity: slot.CandidatePublic, Attestation: slot.CandidateAttestation}
	if err := f.state.RememberNativePairLocalAttestation(ctx, f.evidence.Plan.PairID, c); err != nil {
		t.Fatal(err)
	}
	if err := f.state.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.state, err = OpenCryptoState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	original, err := f.state.NativePairOriginalLocalKey(ctx, c.EndpointID)
	if err != nil || !samePublicIdentity(original, c.PublicIdentity) {
		t.Fatal("restart lost original local public key", err)
	}
	retained, err := f.state.NativePairLocalAttestation(ctx, f.evidence.Plan.PairID, c.EndpointID, c.BindingID, c.BindingEpoch)
	if err != nil || retained.CandidateVersion != 0 || !bytes.Equal(retained.Attestation, c.Attestation) {
		t.Fatal("lost Ack became CandidateReady or regenerated attestation", err)
	}
	changed := c
	replacement, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	changed.PublicIdentity = replacement.Public()
	changed.KeyID = changed.PublicIdentity.ID
	changed.KeyFingerprint, _ = PeerKeyFingerprint(changed.PublicIdentity)
	changed.Attestation, err = replacement.SignEndpointKeyAttestation(c.EndpointID, c.PrincipalID, c.NodeID, c.BindingID, c.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(changed.Attestation)
	changed.ProofDigest = hex.EncodeToString(h[:])
	if err := f.state.RememberNativePairLocalAttestation(ctx, f.evidence.Plan.PairID, changed); !errors.Is(err, ErrNativePairConflict) {
		t.Fatal("known Endpoint silently changed key", err)
	}
	c.CandidateVersion = 2
	if err := f.state.ConfirmNativePairLocalCandidate(ctx, f.evidence.Plan.PairID, c); err != nil {
		t.Fatal(err)
	}
	retained, err = f.state.NativePairLocalAttestation(ctx, f.evidence.Plan.PairID, c.EndpointID, c.BindingID, c.BindingEpoch)
	if err != nil || retained.CandidateVersion != 2 || !bytes.Equal(retained.Attestation, c.Attestation) {
		t.Fatal("actual accepted candidate was not durably applied", err)
	}
	c.CandidateVersion = 3
	if err := f.state.ConfirmNativePairLocalCandidate(ctx, f.evidence.Plan.PairID, c); !errors.Is(err, ErrNativePairConflict) {
		t.Fatal("ack changed the original accepted version", err)
	}
}
