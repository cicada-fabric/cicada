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

type crossGroupPinFixture struct {
	now         time.Time
	localKey    *e2ee.Identity
	peerKey     *e2ee.Identity
	scope       PeerPinScope
	local       PeerPinLocalEndpoint
	peer        PeerPinIdentity
	bundle      PeerKeyAuthorizationBundle
	sourceTrust OwnerKeyTrust
	targetTrust OwnerKeyTrust
}

func TestOwnerGrantedCrossGroupPeerPinRequiresBilateralLocalTrust(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	fixture := newCrossGroupPinFixture(t, "owner_same", "owner_same")
	installFixtureOwnerTrust(t, state, fixture)

	pin, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), fixture.scope,
		fixture.local, fixture.peer, fixture.bundle)
	if err != nil {
		t.Fatal(err)
	}
	if pin.LinkVersion != fixture.bundle.Manifest.LinkVersion ||
		pin.ManifestDigest != fixture.bundle.Manifest.Digest || pin.LinkExpiresAt == "" ||
		pin.SourceGrantExpiry == "" || pin.TargetGrantExpiry == "" || pin.KeyID != fixture.bundle.Manifest.Target.KeyID {
		t.Fatalf("owner-granted pin did not persist exact link binding: %+v", pin)
	}
	if _, err := state.GetPeerPin(context.Background(), fixture.scope, fixture.peer); !errors.Is(err, ErrPeerPinCrossGroupGrantRequired) {
		t.Fatalf("legacy pin lookup exposed a cross-Group pin: %v", err)
	}
	verified, err := state.GetOwnerGrantedCrossGroupPeerPin(context.Background(), fixture.scope,
		fixture.local, fixture.peer, fixture.bundle)
	if err != nil || verified.ManifestDigest != pin.ManifestDigest {
		t.Fatalf("fresh bilateral Bundle did not verify pinned key: pin=%+v err=%v", verified, err)
	}
	if fixture.sourceTrust.KeyID == fixture.targetTrust.KeyID {
		t.Fatal("fixture must exercise two keys for the same Owner")
	}
}

func TestOwnerGrantedCrossGroupPeerPinRejectsHubForgedCandidate(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	fixture := newCrossGroupPinFixture(t, "owner_a", "owner_b")
	installFixtureOwnerTrust(t, state, fixture)

	forgedBundle := fixture.bundle
	fakeEndpoint, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fakeAttestation, err := fakeEndpoint.SignEndpointKeyAttestation(forgedBundle.Manifest.Target.EndpointID,
		forgedBundle.Manifest.Target.PrincipalID, forgedBundle.Manifest.Target.NodeID,
		forgedBundle.Manifest.Target.BindingID, forgedBundle.Manifest.Target.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	forgedBundle.Manifest.Target.PublicIdentity = fakeEndpoint.Public()
	forgedBundle.Manifest.Target.KeyID = fakeEndpoint.Public().ID
	forgedBundle.Manifest.Target.KeyFingerprint, err = PeerKeyFingerprint(fakeEndpoint.Public())
	if err != nil {
		t.Fatal(err)
	}
	forgedBundle.Manifest.Target.Attestation = fakeAttestation
	proofDigest := sha256.Sum256(fakeAttestation)
	forgedBundle.Manifest.Target.ProofDigest = hex.EncodeToString(proofDigest[:])
	refreshPeerManifestDigest(t, &forgedBundle.Manifest)

	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), fixture.scope,
		fixture.local, fixture.peer, forgedBundle); !errors.Is(err, ErrPeerPinGrantInvalid) {
		t.Fatalf("Hub-invented Endpoint key accepted without owner signatures: %v", err)
	}
	if _, err := state.GetPeerPin(context.Background(), fixture.scope, fixture.peer); !errors.Is(err, ErrPeerPinCrossGroupGrantRequired) {
		t.Fatalf("forged response changed the legacy pin API: %v", err)
	}
}

func TestOwnerGrantedCrossGroupPeerPinRejectsSingleSideGrant(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	fixture := newCrossGroupPinFixture(t, "owner_a", "owner_b")
	installFixtureOwnerTrust(t, state, fixture)

	fixture.bundle.TargetGrant.SignedProof = nil
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), fixture.scope,
		fixture.local, fixture.peer, fixture.bundle); !errors.Is(err, ErrPeerPinGrantInvalid) {
		t.Fatalf("single-side grant established a pin: %v", err)
	}
}

func TestOwnerGrantedCrossGroupPeerPinRejectsUntrustedHubOwnerKey(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	fixture := newCrossGroupPinFixture(t, "owner_a", "owner_b")
	installFixtureOwnerTrust(t, state, fixture)

	fakeOwner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fakeBundle := fixture.bundle
	fakeBundle.TargetGrant.OwnerKeyID = fakeOwner.Public().ID
	fakeBundle.TargetGrant.OwnerPublicIdentity = fakeOwner.Public()
	fakeBundle.TargetGrant.OwnerKeyState = NodeOwnerKeyTrustActive
	fakeBundle.TargetGrant.OwnerKeyVersion = 1
	fakeBundle.TargetGrant.CurrentStatus = "ACCEPTED"
	fakeBundle.TargetGrant.SignedProof, err = fakeOwner.SignOwnerLinkKeyGrant(
		fixture.bundle.TargetGrant.OwnerID, fixture.bundle.Manifest.LinkID,
		fixture.bundle.Manifest.ContractDigest, fixture.bundle.Manifest.Digest,
		uint64(fixture.bundle.Manifest.LinkVersion), e2ee.OwnerLinkGrantSideTarget,
		fixture.now.Add(-time.Minute), fixture.now.Add(20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), fixture.scope,
		fixture.local, fixture.peer, fakeBundle); !errors.Is(err, ErrPeerPinOwnerTrustRequired) {
		t.Fatalf("same-response Hub Owner key became trusted: %v", err)
	}
}

func TestOwnerGrantedCrossGroupPeerPinRejectsExpiryRevocationAndStaleVersion(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	expiredFixture := newCrossGroupPinFixtureAt(t, "owner_exp_source", "owner_exp_target",
		time.Now().UTC().Add(-40*time.Minute).Truncate(time.Second))
	installFixtureOwnerTrust(t, state, expiredFixture)
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), expiredFixture.scope,
		expiredFixture.local, expiredFixture.peer, expiredFixture.bundle); !errors.Is(err, ErrPeerPinGrantExpired) {
		t.Fatalf("expired Owner grant accepted: %v", err)
	}
	fixture := newCrossGroupPinFixture(t, "owner_a", "owner_b")
	installFixtureOwnerTrust(t, state, fixture)

	revokedBundle := fixture.bundle
	revokedBundle.LinkState = "REVOKED"
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), fixture.scope,
		fixture.local, fixture.peer, revokedBundle); !errors.Is(err, ErrPeerPinGrantInvalid) {
		t.Fatalf("revoked Link bundle accepted: %v", err)
	}
	revokedOwnerBundle := fixture.bundle
	revokedOwnerBundle.TargetGrant.OwnerKeyState = "REVOKED"
	revokedOwnerBundle.TargetGrant.CurrentStatus = "OWNER_KEY_REVOKED"
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), fixture.scope,
		fixture.local, fixture.peer, revokedOwnerBundle); !errors.Is(err, ErrPeerPinOwnerTrustRequired) {
		t.Fatalf("revoked Store Owner key accepted: %v", err)
	}

	versionExpired := fixture.bundle
	versionExpired.Manifest.LinkVersion++
	refreshPeerManifestDigest(t, &versionExpired.Manifest)
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), fixture.scope,
		fixture.local, fixture.peer, versionExpired); !errors.Is(err, ErrPeerPinGrantInvalid) {
		t.Fatalf("grant for an expired Link version accepted: %v", err)
	}

	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), fixture.scope,
		fixture.local, fixture.peer, fixture.bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := state.RevokeNodeOwnerKeyTrustLocal(fixture.sourceTrust.OwnerID,
		fixture.sourceTrust.KeyID, fixture.sourceTrust.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), fixture.scope,
		fixture.local, fixture.peer, fixture.bundle); !errors.Is(err, ErrPeerPinOwnerTrustRequired) {
		t.Fatalf("revoked Node-local Owner trust accepted: %v", err)
	}
	if _, err := state.GetOwnerGrantedCrossGroupPeerPin(context.Background(), fixture.scope,
		fixture.local, fixture.peer, fixture.bundle); !errors.Is(err, ErrPeerPinOwnerTrustRequired) {
		t.Fatalf("revoked Node-local Owner trust did not fence a prior pin: %v", err)
	}
}

func TestNodeLocalOwnerKeyTrustRequiresExpectedKeyAndRevocationIsTerminal(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()

	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := PeerKeyFingerprint(owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.TrustOwnerApprovalKeyLocal("owner_a", owner.Public().ID,
		owner.Public(), changedFingerprint(fingerprint)); !errors.Is(err, ErrPeerPinOwnerTrustRequired) {
		t.Fatalf("mismatched expected fingerprint was installed: %v", err)
	}
	trust, err := state.TrustOwnerApprovalKeyLocal("owner_a", owner.Public().ID,
		owner.Public(), fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if trust.State != NodeOwnerKeyTrustActive || trust.Version != 1 {
		t.Fatalf("Node-local Owner trust = %+v", trust)
	}
	if _, err := state.RevokeNodeOwnerKeyTrustLocal("owner_a", owner.Public().ID, trust.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := state.TrustOwnerApprovalKeyLocal("owner_a", owner.Public().ID,
		owner.Public(), fingerprint); !errors.Is(err, ErrNodeOwnerKeyTrustRevoked) {
		t.Fatalf("revoked Owner trust was silently restored: %v", err)
	}
}

func TestNodeLocalOwnerKeyTrustSurvivesRestart(t *testing.T) {
	stateDir := t.TempDir()
	state, err := OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := PeerKeyFingerprint(owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.TrustOwnerApprovalKeyLocal("owner_persist", owner.Public().ID,
		owner.Public(), fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	state, err = OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	loaded, err := state.GetNodeOwnerKeyTrustLocal("owner_persist", owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != NodeOwnerKeyTrustActive || loaded.Version != 1 ||
		loaded.ExpectedFingerprint != fingerprint || !samePublicIdentity(loaded.PublicIdentity, owner.Public()) {
		t.Fatalf("Node-local Owner trust changed across restart: %+v", loaded)
	}
}

func newCrossGroupPinFixture(t *testing.T, sourceOwnerID, targetOwnerID string) crossGroupPinFixture {
	t.Helper()
	return newCrossGroupPinFixtureAt(t, sourceOwnerID, targetOwnerID, time.Now().UTC().Truncate(time.Second))
}

func newCrossGroupPinFixtureAt(t *testing.T, sourceOwnerID, targetOwnerID string, now time.Time) crossGroupPinFixture {
	t.Helper()
	now = now.UTC().Truncate(time.Second)
	linkExpiry := now.Add(90 * time.Minute).UTC().Format(time.RFC3339)
	localIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sourceOwnerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	targetOwnerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	local := PeerPinLocalEndpoint{EndpointID: "ep_local", GroupID: "group_a",
		PrincipalID: "pr_local", OwnerID: sourceOwnerID, NodeID: "node_local",
		BindingID: "binding_local", BindingEpoch: 5,
		KeyID: localIdentity.Public().ID, Public: localIdentity.Public()}
	peer := PeerPinIdentity{EndpointID: "ep_peer", GroupID: "group_b",
		PrincipalID: "pr_peer", OwnerID: targetOwnerID}
	scope := PeerPinScope{LocalEndpointID: local.EndpointID, LocalGroupID: local.GroupID,
		PeerEndpointID: peer.EndpointID, PeerGroupID: peer.GroupID, CommunicationLinkID: "link_1"}
	sourceSide := signedManifestSide(t, local, localIdentity)
	peerNode := PeerPinLocalEndpoint{EndpointID: peer.EndpointID, GroupID: peer.GroupID,
		PrincipalID: peer.PrincipalID, OwnerID: peer.OwnerID, NodeID: "node_peer",
		BindingID: "binding_peer", BindingEpoch: 8}
	targetSide := signedManifestSide(t, peerNode, peerIdentity)
	contract := peerLinkContract{
		LinkID: "link_1", SourceEndpointID: local.EndpointID, SourcePrincipalID: local.PrincipalID,
		SourceGroupID: local.GroupID, SourceOwnerID: local.OwnerID, SourceNodeID: local.NodeID,
		TargetEndpointID: peer.EndpointID, TargetPrincipalID: peer.PrincipalID,
		TargetGroupID: peer.GroupID, TargetOwnerID: peer.OwnerID, TargetNodeID: peerNode.NodeID,
		Direction: "bidirectional", Actions: []string{"ask", "reply", "send"},
		DataScopes: []string{"benchmark.public_result"}, ExpiresAt: linkExpiry,
		ScopeSnapshot: peerLinkScopeSnapshot{SourceMembershipRevision: 2, SourceJoinRevision: 3,
			SourceGroupVersion: 4, TargetMembershipRevision: 5, TargetJoinRevision: 6, TargetGroupVersion: 7},
	}
	contractCanonical, err := json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	contractDigest := sha256.Sum256(append([]byte(peerLinkContractDomain), contractCanonical...))
	manifest := PeerKeyAuthorizationManifest{
		Version: peerKeyManifestVersion, LinkID: contract.LinkID, LinkVersion: 12,
		ContractDigest: hex.EncodeToString(contractDigest[:]), ContractCanonical: contractCanonical,
		Source: sourceSide, Target: targetSide,
	}
	refreshPeerManifestDigest(t, &manifest)
	sourceProof, err := sourceOwnerKey.SignOwnerLinkKeyGrant(sourceOwnerID,
		manifest.LinkID, manifest.ContractDigest, manifest.Digest, uint64(manifest.LinkVersion),
		e2ee.OwnerLinkGrantSideSource, now.Add(-time.Minute), now.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	targetProof, err := targetOwnerKey.SignOwnerLinkKeyGrant(targetOwnerID,
		manifest.LinkID, manifest.ContractDigest, manifest.Digest, uint64(manifest.LinkVersion),
		e2ee.OwnerLinkGrantSideTarget, now.Add(-time.Minute), now.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	sourceOwnerFingerprint, err := PeerKeyFingerprint(sourceOwnerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	targetOwnerFingerprint, err := PeerKeyFingerprint(targetOwnerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	return crossGroupPinFixture{now: now, localKey: localIdentity, peerKey: peerIdentity,
		scope: scope, local: local, peer: peer,
		bundle: PeerKeyAuthorizationBundle{Manifest: manifest, LinkState: "PROPOSED",
			SourceGrant: PeerOwnerKeyGrantEvidence{Side: "SOURCE", OwnerID: sourceOwnerID,
				OwnerKeyID: sourceOwnerKey.Public().ID, OwnerPublicIdentity: sourceOwnerKey.Public(),
				OwnerKeyState: NodeOwnerKeyTrustActive, OwnerKeyVersion: 1,
				CurrentStatus: "ACCEPTED", SignedProof: sourceProof},
			TargetGrant: PeerOwnerKeyGrantEvidence{Side: "TARGET", OwnerID: targetOwnerID,
				OwnerKeyID: targetOwnerKey.Public().ID, OwnerPublicIdentity: targetOwnerKey.Public(),
				OwnerKeyState: NodeOwnerKeyTrustActive, OwnerKeyVersion: 1,
				CurrentStatus: "ACCEPTED", SignedProof: targetProof}},
		sourceTrust: OwnerKeyTrust{OwnerID: sourceOwnerID, KeyID: sourceOwnerKey.Public().ID,
			PublicIdentity: sourceOwnerKey.Public(), ExpectedFingerprint: sourceOwnerFingerprint,
			State: NodeOwnerKeyTrustActive, Version: 1},
		targetTrust: OwnerKeyTrust{OwnerID: targetOwnerID, KeyID: targetOwnerKey.Public().ID,
			PublicIdentity: targetOwnerKey.Public(), ExpectedFingerprint: targetOwnerFingerprint,
			State: NodeOwnerKeyTrustActive, Version: 1}}
}

func signedManifestSide(t *testing.T, endpoint PeerPinLocalEndpoint,
	identity *e2ee.Identity) PeerKeyManifestSide {
	t.Helper()
	attestation, err := identity.SignEndpointKeyAttestation(endpoint.EndpointID,
		endpoint.PrincipalID, endpoint.NodeID, endpoint.BindingID, endpoint.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := PeerKeyFingerprint(identity.Public())
	if err != nil {
		t.Fatal(err)
	}
	proofDigest := sha256.Sum256(attestation)
	return PeerKeyManifestSide{EndpointID: endpoint.EndpointID, GroupID: endpoint.GroupID,
		PrincipalID: endpoint.PrincipalID, OwnerID: endpoint.OwnerID, NodeID: endpoint.NodeID,
		BindingID: endpoint.BindingID, BindingEpoch: endpoint.BindingEpoch, CandidateVersion: 1,
		KeyID: identity.Public().ID, KeyFingerprint: fingerprint,
		ProofDigest: hex.EncodeToString(proofDigest[:]), PublicIdentity: identity.Public(), Attestation: attestation}
}

func refreshPeerManifestDigest(t *testing.T, manifest *PeerKeyAuthorizationManifest) {
	t.Helper()
	claims := peerKeyManifestClaims{Version: manifest.Version, LinkID: manifest.LinkID,
		LinkVersion: manifest.LinkVersion, ContractDigest: manifest.ContractDigest,
		ContractCanonical: manifest.ContractCanonical, Source: manifest.Source, Target: manifest.Target}
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte(peerKeyManifestDomain), encoded...))
	manifest.Digest = hex.EncodeToString(sum[:])
}

func installFixtureOwnerTrust(t *testing.T, state *CryptoState, fixture crossGroupPinFixture) {
	t.Helper()
	if _, err := state.TrustOwnerApprovalKeyLocal(fixture.sourceTrust.OwnerID,
		fixture.sourceTrust.KeyID, fixture.sourceTrust.PublicIdentity,
		fixture.sourceTrust.ExpectedFingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := state.TrustOwnerApprovalKeyLocal(fixture.targetTrust.OwnerID,
		fixture.targetTrust.KeyID, fixture.targetTrust.PublicIdentity,
		fixture.targetTrust.ExpectedFingerprint); err != nil {
		t.Fatal(err)
	}
}
