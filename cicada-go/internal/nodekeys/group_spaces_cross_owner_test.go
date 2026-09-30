package nodekeys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestCrossOwnerGroupSpaceKeyRequiresBothIndependentLocalOwnerPinsAndProofs(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	endpointOwner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	groupOwner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := candidate.SignEndpointKeyAttestation("endpoint_a", "principal_a", "node_a", "binding_a", 7)
	if err != nil {
		t.Fatal(err)
	}
	proofDigest := sha256.Sum256(attestation)
	fingerprint, err := PeerKeyFingerprint(candidate.Public())
	if err != nil {
		t.Fatal(err)
	}
	manifest := CrossOwnerGroupKeyManifest{
		Version: 2, Operation: crossOwnerGroupKeyOperation, HubID: "hub_a", NetworkID: "network_a",
		GroupID: "group_a", GroupRevision: 9, EndpointID: "endpoint_a", PrincipalID: "principal_a",
		EndpointOwnerID: "owner_endpoint_a", GroupOwnerID: "owner_group_a", NodeID: "node_a",
		BindingID: "binding_a", BindingEpoch: 7, MembershipRevision: 3, EndpointJoinRevision: 5,
		CandidateVersion: 2, CandidateKeyID: candidate.Public().ID, CandidateFingerprint: fingerprint,
		CandidateProofDigest: hex.EncodeToString(proofDigest[:]), CandidatePublicIdentity: candidate.Public(),
		CandidateAttestation: attestation, Capabilities: []string{"space.read"},
		CrossOwnerContextShared: true, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	manifest.CandidateBindingDigest = crossOwnerGroupBindingDigest(manifest)
	manifest.Digest = crossOwnerGroupManifestDigest(manifest)
	makeProof := func(owner *e2ee.Identity, ownerID, side string, wireSide e2ee.OwnerLinkGrantSide) *CrossOwnerGroupKeyProof {
		t.Helper()
		wire, err := owner.SignOwnerLinkKeyGrant(ownerID, crossOwnerGroupKeyOperation,
			manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
			wireSide, now.Add(-time.Minute), now.Add(30*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		return &CrossOwnerGroupKeyProof{ID: "proof_" + side, GroupID: manifest.GroupID,
			EndpointID: manifest.EndpointID, SignerOwnerID: ownerID, SignerSide: side,
			OwnerKeyID: owner.Public().ID, ManifestDigest: manifest.Digest,
			CurrentStatus: "CURRENT", SignedProof: wire}
	}
	evidence := GroupSpaceEndpointEvidence{
		EndpointID: manifest.EndpointID, PrincipalID: manifest.PrincipalID,
		OwnerID: manifest.EndpointOwnerID, NodeID: manifest.NodeID, BindingID: manifest.BindingID,
		BindingEpoch: manifest.BindingEpoch, MembershipRevision: manifest.MembershipRevision,
		JoinRevision: manifest.EndpointJoinRevision, KeyID: manifest.CandidateKeyID,
		PublicIdentity: candidate.Public(), EvidenceProtocol: crossOwnerGroupSpaceEvidenceProtocol,
		CrossOwnerKeyStatus: &CrossOwnerGroupKeyStatus{Manifest: manifest, Current: true,
			EndpointConsent: makeProof(endpointOwner, manifest.EndpointOwnerID, "ENDPOINT", e2ee.OwnerLinkGrantSideSource),
			GroupAdmission:  makeProof(groupOwner, manifest.GroupOwnerID, "GROUP", e2ee.OwnerLinkGrantSideTarget)},
		Candidate: GroupSpaceKeyCandidate{EndpointID: manifest.EndpointID, PrincipalID: manifest.PrincipalID,
			OwnerID: manifest.EndpointOwnerID, NodeID: manifest.NodeID, Public: candidate.Public(),
			KeyID: manifest.CandidateKeyID, BindingID: manifest.BindingID, BindingEpoch: manifest.BindingEpoch,
			Proof: attestation, ProofDigest: manifest.CandidateProofDigest, State: "CANDIDATE",
			Version: manifest.CandidateVersion},
	}
	verify := func() error {
		_, err := state.VerifyGroupSpaceEndpointKey(context.Background(), "hub_a", "group_a", evidence, now)
		return err
	}
	if err := verify(); err == nil {
		t.Fatal("Hub evidence established Owner trust without local pins")
	}
	trust := func(ownerID string, owner *e2ee.Identity) {
		t.Helper()
		fp, err := PeerKeyFingerprint(owner.Public())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.TrustOwnerApprovalKeyLocal(ownerID, owner.Public().ID, owner.Public(), fp); err != nil {
			t.Fatal(err)
		}
	}
	trust(manifest.EndpointOwnerID, endpointOwner)
	if err := verify(); err == nil {
		t.Fatal("Endpoint Owner pin alone authorized the foreign Group")
	}
	trust(manifest.GroupOwnerID, groupOwner)
	if err := verify(); err != nil {
		t.Fatalf("two independently pinned Owner proofs were rejected: %v", err)
	}
	evidence.CrossOwnerKeyStatus.GroupAdmission.SignedProof = append([]byte(nil), evidence.CrossOwnerKeyStatus.EndpointConsent.SignedProof...)
	if err := verify(); err == nil {
		t.Fatal("Endpoint Owner signature was accepted as Group Owner approval")
	}
	evidence.CrossOwnerKeyStatus.GroupAdmission = nil
	if err := verify(); err == nil {
		t.Fatal("missing Group Owner approval was accepted")
	}
}
