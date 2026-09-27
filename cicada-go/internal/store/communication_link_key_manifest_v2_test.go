package store

import (
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

func registerLinkEndpointKey(t *testing.T, s *Store, endpointID string) {
	t.Helper()
	binding, err := s.GetSessionBindingForEndpoint(endpointID)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignEndpointKeyAttestation(endpointID, binding.PrincipalID,
		binding.NodeID, binding.ID, binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterEndpointKeyCandidate(endpointID, binding.PrincipalID,
		binding.ID, binding.Epoch, proof); err != nil {
		t.Fatal(err)
	}
}

func TestCommunicationLinkKeyManifestRequiresBothCurrentCandidates(t *testing.T) {
	f := newCommunicationLinkGrantFixture(t)
	if _, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "stranger"); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("unrelated owner saw link manifest: %v", err)
	}
	if _, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a"); !errors.Is(err, ErrCommunicationLinkKeyCandidate) {
		t.Fatalf("missing candidates produced manifest: %v", err)
	}
	registerLinkEndpointKey(t, f.store, "ep_source")
	if _, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a"); !errors.Is(err, ErrCommunicationLinkKeyCandidate) {
		t.Fatalf("one candidate produced manifest: %v", err)
	}
	registerLinkEndpointKey(t, f.store, "ep_target")
	manifest, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a")
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a")
	if err != nil || manifest.Digest != retry.Digest || manifest.Digest == "" {
		t.Fatalf("manifest digest not stable: first=%#v second=%#v err=%v", manifest, retry, err)
	}
	if manifest.Source.BindingID != f.sourceBindingID || manifest.Source.BindingEpoch == 0 ||
		manifest.Source.KeyID == manifest.Target.KeyID || manifest.Source.ProofDigest == "" ||
		manifest.Target.ProofDigest == "" {
		t.Fatalf("manifest did not bind both distinct native sessions: %#v", manifest)
	}
	if len(manifest.ContractCanonical) == 0 ||
		digestCommunicationLinkContract(manifest.ContractCanonical) != manifest.ContractDigest {
		t.Fatal("manifest omitted the independently reviewable canonical Link contract")
	}
	want, err := nodekeys.PeerKeyFingerprint(manifest.Source.PublicIdentity)
	if err != nil || manifest.Source.KeyFingerprint != want {
		t.Fatalf("source fingerprint mismatch: got %q want %q err=%v", manifest.Source.KeyFingerprint, want, err)
	}
	released, err := f.store.ReleaseSessionBindingLease(f.sourceBindingID, f.sourceLeaseOwner,
		manifest.Source.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a"); err == nil {
		t.Fatal("released native binding still produced a current manifest")
	}
	if _, err := f.store.AcquireSessionBindingLease(f.sourceBindingID, f.sourceLeaseOwner,
		released.Epoch, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a"); !errors.Is(err, ErrCommunicationLinkKeyCandidate) {
		t.Fatalf("stale candidate survived binding epoch change: %v", err)
	}
}
