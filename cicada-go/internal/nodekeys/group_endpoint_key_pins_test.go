package nodekeys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type groupEndpointKeyPinFixture struct {
	state    *CryptoState
	evidence GroupEndpointKeyPinEvidence
	owner    *e2ee.Identity
}

func newGroupEndpointKeyPinFixture(t *testing.T, issuedAt, expiresAt time.Time) *groupEndpointKeyPinFixture {
	t.Helper()
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	localIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	const (
		ownerID     = "owner_group_a"
		groupID     = "group_shared_a"
		localEP     = "ep_local_a"
		peerEP      = "ep_peer_a"
		peerNode    = "node_peer_a"
		peerBinding = "binding_peer_a"
	)
	const peerEpoch = uint64(7)
	const candidateVersion = int64(3)

	attestation, err := peerIdentity.SignEndpointKeyAttestation(peerEP,
		"principal_peer_a", peerNode, peerBinding, peerEpoch)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := PeerKeyFingerprint(peerIdentity.Public())
	if err != nil {
		t.Fatal(err)
	}
	proofSum := sha256.Sum256(attestation)
	proofDigest := hex.EncodeToString(proofSum[:])

	manifest := GroupEndpointKeyGrantManifest{
		Version: groupEndpointKeyGrantVersion, Operation: groupEndpointKeyGrantOperation,
		HubID: "hub_primary_a", OwnerID: ownerID, PrincipalID: "principal_peer_a",
		GroupID: groupID, GroupRevision: 9, EndpointID: peerEP,
		NodeID: peerNode, BindingID: peerBinding, BindingEpoch: peerEpoch,
		MembershipRevision: 11, EndpointJoinRevision: 13,
		CandidateVersion: candidateVersion, CandidateKeyID: peerIdentity.Public().ID,
		CandidateFingerprint: fingerprint, CandidateProofDigest: proofDigest,
		CandidatePublicIdentity: peerIdentity.Public(), OwnerKeyID: owner.Public().ID,
		IssuedAt:  issuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano),
	}
	manifest.CandidateBindingDigest = groupEndpointKeyBindingDigest(manifest)
	manifest.Digest = groupEndpointKeyManifestDigest(manifest)
	signedProof, err := owner.SignOwnerLinkKeyGrant(ownerID,
		groupEndpointKeyGrantOperation, manifest.Digest, manifest.CandidateBindingDigest,
		uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	evidence := GroupEndpointKeyPinEvidence{
		Scope: PeerPinScope{LocalEndpointID: localEP, LocalGroupID: groupID,
			PeerEndpointID: peerEP, PeerGroupID: groupID},
		Local: PeerPinLocalEndpoint{EndpointID: localEP, GroupID: groupID,
			PrincipalID: "principal_local_a", OwnerID: ownerID, NodeID: "node_local_a",
			BindingID: "binding_local_a", BindingEpoch: 5,
			KeyID: localIdentity.Public().ID, Public: localIdentity.Public()},
		Peer: PeerPinIdentity{EndpointID: peerEP, GroupID: groupID,
			PrincipalID: "principal_peer_a", OwnerID: ownerID},
		Route: GroupEndpointKeyRouteSnapshot{
			HubID: "hub_primary_a", GroupID: groupID, GroupRevision: manifest.GroupRevision,
			MembershipRevision:   manifest.MembershipRevision,
			EndpointJoinRevision: manifest.EndpointJoinRevision,
			ExpectedOwnerKeyID:   owner.Public().ID,
			PeerNodeID:           peerNode, PeerBindingID: peerBinding,
			PeerBindingEpoch: peerEpoch, CandidateVersion: candidateVersion,
			CandidateKeyID:       peerIdentity.Public().ID,
			CandidateFingerprint: fingerprint, CandidateProofDigest: proofDigest,
		},
		Grant: GroupEndpointKeyGrant{ID: "gkg_node_test_a", OwnerID: ownerID,
			GroupID: groupID, EndpointID: peerEP, OwnerKeyID: owner.Public().ID,
			Manifest: manifest, SignedProof: signedProof,
			AcceptedAt:    issuedAt.UTC().Format(time.RFC3339Nano),
			CurrentStatus: groupEndpointKeyGrantCurrent},
		Candidate: GroupEndpointKeyCandidate{
			EndpointID: peerEP, GroupID: groupID, PrincipalID: "principal_peer_a",
			OwnerID: ownerID, NodeID: peerNode, BindingID: peerBinding,
			BindingEpoch: peerEpoch, CandidateVersion: candidateVersion,
			KeyID: peerIdentity.Public().ID, KeyFingerprint: fingerprint,
			ProofDigest: proofDigest, PublicIdentity: peerIdentity.Public(),
			Attestation: attestation,
		},
	}
	return &groupEndpointKeyPinFixture{state: state, evidence: evidence, owner: owner}
}

func trustGroupEndpointKeyPinFixtureOwner(t *testing.T, fixture *groupEndpointKeyPinFixture) {
	t.Helper()
	fingerprint, err := PeerKeyFingerprint(fixture.owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.state.TrustOwnerApprovalKeyLocal(fixture.evidence.Peer.OwnerID,
		fixture.owner.Public().ID, fixture.owner.Public(), fingerprint); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerGrantedGroupEndpointPeerPinVerifiesAndUsesExistingSameGroupPin(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newGroupEndpointKeyPinFixture(t, now.Add(-time.Minute), now.Add(20*time.Minute))
	trustGroupEndpointKeyPinFixtureOwner(t, fixture)
	candidate, err := fixture.state.VerifyGroupEndpointKeyGrant(context.Background(), fixture.evidence)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.EndpointID != fixture.evidence.Peer.EndpointID ||
		candidate.OwnerID != fixture.evidence.Peer.OwnerID ||
		candidate.Public.ID != fixture.evidence.Route.CandidateKeyID {
		t.Fatalf("verified candidate differs from current peer route: %+v", candidate)
	}
	first, err := fixture.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), fixture.evidence)
	if err != nil {
		t.Fatal(err)
	}
	if first.Scope != fixture.evidence.Scope || first.Version != 1 ||
		first.KeyID != fixture.evidence.Route.CandidateKeyID || first.ManifestDigest != "" ||
		first.LinkVersion != 0 {
		t.Fatalf("same-Group pin did not use existing local pin state: %+v", first)
	}
	second, err := fixture.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), fixture.evidence)
	if err != nil || second.Version != first.Version || second.CreatedAt != first.CreatedAt {
		t.Fatalf("replaying the same grant reset or changed the existing pin: first=%+v second=%+v err=%v", first, second, err)
	}
}

func TestOwnerGrantedGroupEndpointPeerPinRequiresIndependentNodeOwnerTrust(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newGroupEndpointKeyPinFixture(t, now.Add(-time.Minute), now.Add(20*time.Minute))
	ownerFingerprint, err := PeerKeyFingerprint(fixture.owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	trust, err := fixture.state.GetNodeOwnerKeyTrustLocal(fixture.evidence.Grant.OwnerID,
		fixture.evidence.Grant.OwnerKeyID)
	if !errors.Is(err, ErrNodeOwnerKeyTrustNotFound) || trust != nil {
		t.Fatalf("fixture unexpectedly trusts a Hub-provided Owner key: trust=%+v err=%v", trust, err)
	}
	if _, err := fixture.state.VerifyGroupEndpointKeyGrant(context.Background(), fixture.evidence); !errors.Is(err, ErrPeerPinOwnerTrustRequired) {
		t.Fatalf("grant established trust from its own record: %v", err)
	}
	if _, err := fixture.state.TrustOwnerApprovalKeyLocal(fixture.evidence.Peer.OwnerID,
		fixture.owner.Public().ID, fixture.owner.Public(), ownerFingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.state.RevokeNodeOwnerKeyTrustLocal(fixture.evidence.Peer.OwnerID,
		fixture.owner.Public().ID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), fixture.evidence); !errors.Is(err, ErrNodeOwnerKeyTrustRevoked) {
		t.Fatalf("locally revoked Owner key trust still authorized a pin: %v", err)
	}
}

func TestOwnerGrantedGroupEndpointPeerPinRejectsTrustRevokedAfterVerification(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newGroupEndpointKeyPinFixture(t, now.Add(-time.Minute), now.Add(20*time.Minute))
	trustGroupEndpointKeyPinFixtureOwner(t, fixture)
	candidate, err := fixture.state.VerifyGroupEndpointKeyGrant(context.Background(), fixture.evidence)
	if err != nil {
		t.Fatal(err)
	}
	verifiedTrust, err := fixture.state.GetNodeOwnerKeyTrustLocal(fixture.evidence.Peer.OwnerID,
		fixture.evidence.Route.ExpectedOwnerKeyID)
	if err != nil {
		t.Fatal(err)
	}
	grantExpiry, err := time.Parse(time.RFC3339Nano, fixture.evidence.Grant.Manifest.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.state.RevokeNodeOwnerKeyTrustLocal(fixture.evidence.Peer.OwnerID,
		fixture.evidence.Route.ExpectedOwnerKeyID, verifiedTrust.Version); err != nil {
		t.Fatal(err)
	}
	_, err = fixture.state.pinGroupEndpointPeerKeyWithOwnerTrust(context.Background(),
		fixture.evidence.Scope, fixture.evidence.Peer, candidate.Public.ID,
		fixture.evidence.Route.CandidateFingerprint, candidate, *verifiedTrust, grantExpiry)
	if !errors.Is(err, ErrNodeOwnerKeyTrustRevoked) {
		t.Fatalf("pin transaction accepted a trust snapshot revoked after proof verification: %v", err)
	}
	if _, err := fixture.state.GetPeerPin(context.Background(), fixture.evidence.Scope,
		fixture.evidence.Peer); !errors.Is(err, ErrPeerPinNotFound) {
		t.Fatalf("concurrent revocation race persisted a peer pin: %v", err)
	}
}

func TestOwnerGrantedGroupEndpointPeerPinRejectsHubForgedCandidate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newGroupEndpointKeyPinFixture(t, now.Add(-time.Minute), now.Add(20*time.Minute))
	trustGroupEndpointKeyPinFixtureOwner(t, fixture)
	fakeEndpoint, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fakeAttestation, err := fakeEndpoint.SignEndpointKeyAttestation(
		fixture.evidence.Candidate.EndpointID, fixture.evidence.Candidate.PrincipalID,
		fixture.evidence.Candidate.NodeID, fixture.evidence.Candidate.BindingID,
		fixture.evidence.Candidate.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := PeerKeyFingerprint(fakeEndpoint.Public())
	if err != nil {
		t.Fatal(err)
	}
	proofSum := sha256.Sum256(fakeAttestation)
	proofDigest := hex.EncodeToString(proofSum[:])
	fixture.evidence.Candidate.PublicIdentity = fakeEndpoint.Public()
	fixture.evidence.Candidate.KeyID = fakeEndpoint.Public().ID
	fixture.evidence.Candidate.KeyFingerprint = fingerprint
	fixture.evidence.Candidate.ProofDigest = proofDigest
	fixture.evidence.Candidate.Attestation = fakeAttestation
	fixture.evidence.Route.CandidateKeyID = fakeEndpoint.Public().ID
	fixture.evidence.Route.CandidateFingerprint = fingerprint
	fixture.evidence.Route.CandidateProofDigest = proofDigest
	manifest := &fixture.evidence.Grant.Manifest
	manifest.CandidateKeyID = fakeEndpoint.Public().ID
	manifest.CandidateFingerprint = fingerprint
	manifest.CandidateProofDigest = proofDigest
	manifest.CandidatePublicIdentity = fakeEndpoint.Public()
	manifest.CandidateBindingDigest = groupEndpointKeyBindingDigest(*manifest)
	manifest.Digest = groupEndpointKeyManifestDigest(*manifest)
	fixture.evidence.Grant.Manifest = *manifest
	if _, err := fixture.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), fixture.evidence); !errors.Is(err, ErrGroupEndpointKeyGrantInvalid) {
		t.Fatalf("Hub-replaced candidate without a new Owner signature was accepted: %v", err)
	}
	if _, err := fixture.state.GetPeerPin(context.Background(), fixture.evidence.Scope,
		fixture.evidence.Peer); !errors.Is(err, ErrPeerPinNotFound) {
		t.Fatalf("rejected candidate changed Node pin state: %v", err)
	}
}

func TestOwnerGrantedGroupEndpointPeerPinRejectsStaleIdentityHubAndVersion(t *testing.T) {
	mutations := []struct {
		name   string
		change func(*GroupEndpointKeyPinEvidence)
	}{
		{name: "old binding", change: func(e *GroupEndpointKeyPinEvidence) {
			e.Route.PeerBindingEpoch++
		}},
		{name: "wrong owner", change: func(e *GroupEndpointKeyPinEvidence) {
			e.Peer.OwnerID = "owner_wrong"
		}},
		{name: "wrong group", change: func(e *GroupEndpointKeyPinEvidence) {
			e.Route.GroupID = "group_wrong"
		}},
		{name: "wrong Hub", change: func(e *GroupEndpointKeyPinEvidence) {
			e.Route.HubID = "hub_wrong"
		}},
		{name: "wrong candidate version", change: func(e *GroupEndpointKeyPinEvidence) {
			e.Route.CandidateVersion++
		}},
		{name: "wrong owner key ID", change: func(e *GroupEndpointKeyPinEvidence) {
			e.Route.ExpectedOwnerKeyID = "owner_key_wrong"
		}},
		{name: "bad complete manifest digest", change: func(e *GroupEndpointKeyPinEvidence) {
			e.Grant.Manifest.Digest = hex.EncodeToString(make([]byte, sha256.Size))
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			fixture := newGroupEndpointKeyPinFixture(t, now.Add(-time.Minute), now.Add(20*time.Minute))
			trustGroupEndpointKeyPinFixtureOwner(t, fixture)
			test.change(&fixture.evidence)
			if _, err := fixture.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), fixture.evidence); err == nil {
				t.Fatal("mismatched grant evidence established a same-Group pin")
			}
			if _, err := fixture.state.GetPeerPin(context.Background(), fixture.evidence.Scope,
				fixture.evidence.Peer); !errors.Is(err, ErrPeerPinNotFound) {
				t.Fatalf("rejected evidence changed Node pin state: %v", err)
			}
		})
	}
}

func TestOwnerGrantedGroupEndpointPeerPinRejectsExpiryStatusAndCrossProtocolGrant(t *testing.T) {
	t.Run("expired manifest", func(t *testing.T) {
		base := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
		fixture := newGroupEndpointKeyPinFixture(t, base.Add(-time.Minute), base.Add(5*time.Minute))
		trustGroupEndpointKeyPinFixtureOwner(t, fixture)
		if _, err := fixture.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), fixture.evidence); !errors.Is(err, ErrGroupEndpointKeyGrantExpired) {
			t.Fatalf("expired Owner grant was accepted: %v", err)
		}
	})
	t.Run("revoked status", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		fixture := newGroupEndpointKeyPinFixture(t, now.Add(-time.Minute), now.Add(20*time.Minute))
		trustGroupEndpointKeyPinFixtureOwner(t, fixture)
		fixture.evidence.Grant.CurrentStatus = groupEndpointKeyGrantRevoked
		if _, err := fixture.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), fixture.evidence); !errors.Is(err, ErrGroupEndpointKeyGrantRevoked) {
			t.Fatalf("revoked grant status was accepted: %v", err)
		}
	})
	t.Run("ordinary Link operation", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		fixture := newGroupEndpointKeyPinFixture(t, now.Add(-time.Minute), now.Add(20*time.Minute))
		trustGroupEndpointKeyPinFixtureOwner(t, fixture)
		issuedAt, err := time.Parse(time.RFC3339Nano, fixture.evidence.Grant.Manifest.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, fixture.evidence.Grant.Manifest.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		ordinaryLinkProof, err := fixture.owner.SignOwnerLinkKeyGrant(
			fixture.evidence.Grant.OwnerID, "link_ordinary_a",
			fixture.evidence.Grant.Manifest.Digest,
			fixture.evidence.Grant.Manifest.CandidateBindingDigest,
			uint64(fixture.evidence.Grant.Manifest.CandidateVersion),
			e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
		if err != nil {
			t.Fatal(err)
		}
		fixture.evidence.Grant.SignedProof = ordinaryLinkProof
		if _, err := fixture.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), fixture.evidence); !errors.Is(err, ErrGroupEndpointKeyGrantInvalid) {
			t.Fatalf("ordinary Link grant crossed into Group operation: %v", err)
		}
	})
}

func TestOwnerGrantedGroupEndpointPeerPinRejectsTamperedOwnerSignature(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newGroupEndpointKeyPinFixture(t, now.Add(-time.Minute), now.Add(20*time.Minute))
	trustGroupEndpointKeyPinFixtureOwner(t, fixture)
	var proof e2ee.OwnerLinkKeyGrant
	if err := json.Unmarshal(fixture.evidence.Grant.SignedProof, &proof); err != nil {
		t.Fatal(err)
	}
	proof.Signature[len(proof.Signature)-1] ^= 1
	fixture.evidence.Grant.SignedProof, _ = json.Marshal(proof)
	if _, err := fixture.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), fixture.evidence); !errors.Is(err, ErrGroupEndpointKeyGrantInvalid) {
		t.Fatalf("tampered Owner proof was accepted: %v", err)
	}
}
