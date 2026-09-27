package store

import (
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func signLinkKeyGrant(t *testing.T, identity *e2ee.Identity, link *CommunicationLink,
	manifest *CommunicationLinkKeyManifest, side e2ee.OwnerLinkGrantSide) []byte {
	t.Helper()
	proof, err := identity.SignOwnerLinkKeyGrant("owner_a", link.ID,
		link.ContractDigest, manifest.Digest, uint64(link.Version), side,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestCommunicationLinkKeyGrantsBindOwnerAndBothEndpointKeys(t *testing.T) {
	f := newCommunicationLinkGrantFixture(t)
	registerLinkEndpointKey(t, f.store, "ep_source")
	registerLinkEndpointKey(t, f.store, "ep_target")
	manifest, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a")
	if err != nil {
		t.Fatal(err)
	}
	legacyProof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
		e2ee.OwnerLinkGrantSideSource, time.Now().UTC().Add(-time.Minute),
		time.Now().UTC().Add(time.Hour))
	if _, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, legacyProof); err == nil {
		t.Fatal("v1 grant was accepted as key-bound consent")
	}
	sourceProof := signLinkKeyGrant(t, f.sourceKey, f.link, manifest, e2ee.OwnerLinkGrantSideSource)
	if _, err := f.store.RecordCommunicationLinkKeyGrant("stranger", f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, sourceProof); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("foreign owner accepted source consent: %v", err)
	}
	if _, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID,
		CommunicationLinkGrantTarget, f.sourceKeyID, sourceProof); err == nil {
		t.Fatal("source proof accepted for target side")
	}
	first, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, sourceProof)
	if err != nil || !first.Accepted || first.ManifestDigest != manifest.Digest {
		t.Fatalf("source key grant rejected: status=%#v err=%v", first, err)
	}
	retry, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, sourceProof)
	if err != nil || retry.AcceptedAt != first.AcceptedAt {
		t.Fatalf("exact retry not idempotent: status=%#v err=%v", retry, err)
	}
	other := signLinkKeyGrant(t, f.sourceKey, f.link, manifest, e2ee.OwnerLinkGrantSideSource)
	if _, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, other); !errors.Is(err, ErrCommunicationLinkGrantConflict) {
		t.Fatalf("different proof replaced accepted side: %v", err)
	}
	targetProof := signLinkKeyGrant(t, f.targetKey, f.link, manifest, e2ee.OwnerLinkGrantSideTarget)
	if _, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID,
		CommunicationLinkGrantTarget, f.targetKeyID, targetProof); err != nil {
		t.Fatal(err)
	}
	statuses, err := f.store.GetCommunicationLinkKeyGrantStatuses(f.link.ID, "owner_a")
	if err != nil || len(statuses) != 2 || statuses[0].CurrentStatus != CommunicationLinkKeyGrantAccepted ||
		statuses[1].CurrentStatus != CommunicationLinkKeyGrantAccepted {
		t.Fatalf("bilateral key grants missing: statuses=%#v err=%v", statuses, err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.store, err = New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	statuses, err = f.store.GetCommunicationLinkKeyGrantStatuses(f.link.ID, "owner_a")
	if err != nil || statuses[0].CurrentStatus != CommunicationLinkKeyGrantAccepted ||
		statuses[1].CurrentStatus != CommunicationLinkKeyGrantAccepted {
		t.Fatalf("key grants did not survive restart: statuses=%#v err=%v", statuses, err)
	}
	link, err := f.store.GetCommunicationLinkForOwner(f.link.ID, "owner_a")
	if err != nil || link.State != CommunicationLinkProposed {
		t.Fatalf("key grants activated route: link=%#v err=%v", link, err)
	}
	released, err := f.store.ReleaseSessionBindingLease(f.sourceBindingID, f.sourceLeaseOwner,
		manifest.Source.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcquireSessionBindingLease(f.sourceBindingID, f.sourceLeaseOwner,
		released.Epoch, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	statuses, err = f.store.GetCommunicationLinkKeyGrantStatuses(f.link.ID, "owner_a")
	if err != nil || statuses[0].CurrentStatus != CommunicationLinkKeyGrantBindingStale ||
		statuses[1].CurrentStatus != CommunicationLinkKeyGrantBindingStale {
		t.Fatalf("binding epoch did not stale both grants: %#v err=%v", statuses, err)
	}
}

func TestCommunicationLinkKeyGrantOwnerKeyRevocationFencesConsent(t *testing.T) {
	f := newCommunicationLinkGrantFixture(t)
	registerLinkEndpointKey(t, f.store, "ep_source")
	registerLinkEndpointKey(t, f.store, "ep_target")
	manifest, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a")
	if err != nil {
		t.Fatal(err)
	}
	proof := signLinkKeyGrant(t, f.sourceKey, f.link, manifest, e2ee.OwnerLinkGrantSideSource)
	if _, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevokeOwnerApprovalKeyLocal("owner_a", f.sourceKeyID, 1); err != nil {
		t.Fatal(err)
	}
	statuses, err := f.store.GetCommunicationLinkKeyGrantStatuses(f.link.ID, "owner_a")
	if err != nil || statuses[0].CurrentStatus != CommunicationLinkKeyGrantOwnerKeyRevoked {
		t.Fatalf("revoked owner key still authorized consent: statuses=%#v err=%v", statuses, err)
	}
}

func TestLegacyLinkGrantsAreNotKeyConsent(t *testing.T) {
	f := newCommunicationLinkGrantFixture(t)
	proof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
		e2ee.OwnerLinkGrantSideSource, time.Now().UTC().Add(-time.Minute),
		time.Now().UTC().Add(time.Hour))
	if _, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, proof); err != nil {
		t.Fatal(err)
	}
	statuses, err := f.store.GetCommunicationLinkKeyGrantStatuses(f.link.ID, "owner_a")
	if err != nil || len(statuses) != 2 || statuses[0].CurrentStatus != CommunicationLinkKeyGrantLegacyUnbound ||
		statuses[0].Accepted || statuses[1].CurrentStatus != CommunicationLinkKeyGrantMissing {
		t.Fatalf("legacy consent treated as key-bound: statuses=%#v err=%v", statuses, err)
	}
}
