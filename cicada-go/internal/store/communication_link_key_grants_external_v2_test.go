package store

import (
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func signExternalThreadLinkKeyGrant(t *testing.T, identity *e2ee.Identity,
	ownerID string, link *CommunicationLink, manifest *CommunicationLinkKeyManifest,
	side e2ee.OwnerLinkGrantSide, expiresAt time.Time,
) []byte {
	t.Helper()
	proof, err := identity.SignOwnerLinkKeyGrant(ownerID, link.ID,
		link.ContractDigest, manifest.Digest, uint64(link.Version), side,
		time.Now().UTC().Add(-time.Minute), expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// External invitation acceptance creates cross-owner proposals. This test
// proves that each independent owner can consent only for their own side of
// the same Hub-derived manifest, and that the result remains non-routable.
func TestExternalInviteLinkRequiresIndependentOwnerKeyBoundConsent(t *testing.T) {
	f := newExternalThreadInviteTestFixture(t)
	invite := f.createInvite(t)
	accepted, err := f.store.AcceptExternalThreadInvite(invite.Token,
		f.target.ownerID, f.target.endpointID, f.target.groupID)
	if err != nil {
		t.Fatal(err)
	}
	link, err := f.store.GetCommunicationLinkForOwner(accepted.LinkID, f.source.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	registerLinkEndpointKey(t, f.store, f.source.endpointID)
	registerLinkEndpointKey(t, f.store, f.target.endpointID)

	sourceManifest, err := f.store.GetCommunicationLinkKeyManifest(link.ID, f.source.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	targetManifest, err := f.store.GetCommunicationLinkKeyManifest(link.ID, f.target.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if sourceManifest.Digest == "" || sourceManifest.Digest != targetManifest.Digest ||
		sourceManifest.Source.OwnerID != f.source.ownerID ||
		sourceManifest.Source.EndpointID != f.source.endpointID ||
		sourceManifest.Target.OwnerID != f.target.ownerID ||
		sourceManifest.Target.EndpointID != f.target.endpointID {
		t.Fatalf("owners did not receive the same server-derived cross-owner manifest: source=%#v target=%#v",
			sourceManifest, targetManifest)
	}

	sourceOwnerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	targetOwnerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sourceKeyRecord, err := f.store.RegisterOwnerApprovalKeyLocal(f.source.ownerID, sourceOwnerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	targetKeyRecord, err := f.store.RegisterOwnerApprovalKeyLocal(f.target.ownerID, targetOwnerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	linkExpiry, err := time.Parse(time.RFC3339, link.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}

	// Neither caller-selected side nor the other owner's signature grants
	// authority over a side bound to a different Principal.
	targetSideSignedBySource := signExternalThreadLinkKeyGrant(t, sourceOwnerKey,
		f.source.ownerID, link, sourceManifest, e2ee.OwnerLinkGrantSideTarget, linkExpiry)
	if _, err := f.store.RecordCommunicationLinkKeyGrant(f.source.ownerID, link.ID,
		CommunicationLinkGrantTarget, sourceKeyRecord.KeyID, targetSideSignedBySource); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("source owner signed for target side: %v", err)
	}
	if _, err := f.store.RecordCommunicationLinkKeyGrant(f.target.ownerID, link.ID,
		CommunicationLinkGrantSource, targetKeyRecord.KeyID, targetSideSignedBySource); !errors.Is(err, ErrOwnerApprovalKeyNotFound) && !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("source proof was accepted for target owner's source-side request: %v", err)
	}

	sourceProof := signExternalThreadLinkKeyGrant(t, sourceOwnerKey,
		f.source.ownerID, link, sourceManifest, e2ee.OwnerLinkGrantSideSource, linkExpiry)
	if _, err := f.store.RecordCommunicationLinkKeyGrant(f.source.ownerID, link.ID,
		CommunicationLinkGrantTarget, sourceKeyRecord.KeyID, sourceProof); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("source owner wrote consent into target side: %v", err)
	}
	if _, err := f.store.RecordCommunicationLinkKeyGrant(f.source.ownerID, link.ID,
		CommunicationLinkGrantSource, sourceKeyRecord.KeyID, sourceProof); err != nil {
		t.Fatalf("source owner's valid source-side consent failed: %v", err)
	}
	statuses, err := f.store.GetCommunicationLinkKeyGrantStatuses(link.ID, f.target.ownerID)
	if err != nil || len(statuses) != 2 ||
		statuses[0].CurrentStatus != CommunicationLinkKeyGrantAccepted ||
		statuses[1].CurrentStatus != CommunicationLinkKeyGrantMissing {
		t.Fatalf("one owner alone produced bilateral consent: statuses=%#v err=%v", statuses, err)
	}

	targetProof := signExternalThreadLinkKeyGrant(t, targetOwnerKey,
		f.target.ownerID, link, targetManifest, e2ee.OwnerLinkGrantSideTarget, linkExpiry)
	if _, err := f.store.RecordCommunicationLinkKeyGrant(f.target.ownerID, link.ID,
		CommunicationLinkGrantSource, targetKeyRecord.KeyID, targetProof); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("target owner wrote consent into source side: %v", err)
	}
	if _, err := f.store.RecordCommunicationLinkKeyGrant(f.target.ownerID, link.ID,
		CommunicationLinkGrantTarget, targetKeyRecord.KeyID, targetProof); err != nil {
		t.Fatalf("target owner's valid target-side consent failed: %v", err)
	}

	bundle, err := f.store.getCommunicationLinkAuthorizationBundleForNodeScope(
		"node_target", f.target.ownerID, link.ID)
	if err != nil {
		t.Fatalf("target Node could not verify bilateral consent evidence: %v", err)
	}
	if bundle.SourceGrant.OwnerID != f.source.ownerID || bundle.TargetGrant.OwnerID != f.target.ownerID ||
		bundle.SourceGrant.OwnerKeyID != sourceKeyRecord.KeyID ||
		bundle.TargetGrant.OwnerKeyID != targetKeyRecord.KeyID ||
		bundle.SourceGrant.CurrentStatus != CommunicationLinkKeyGrantAccepted ||
		bundle.TargetGrant.CurrentStatus != CommunicationLinkKeyGrantAccepted ||
		bundle.LinkState != CommunicationLinkProposed {
		t.Fatalf("authorization bundle lost independent owners or activated routing: %#v", bundle)
	}

	if _, err := f.store.RevokeOwnerApprovalKeyLocal(f.target.ownerID, targetKeyRecord.KeyID, 1); err != nil {
		t.Fatal(err)
	}
	statuses, err = f.store.GetCommunicationLinkKeyGrantStatuses(link.ID, f.source.ownerID)
	if err != nil || statuses[1].CurrentStatus != CommunicationLinkKeyGrantOwnerKeyRevoked {
		t.Fatalf("target key revocation did not fence target consent: statuses=%#v err=%v", statuses, err)
	}
	if _, err := f.store.getCommunicationLinkAuthorizationBundleForNodeScope(
		"node_source", f.source.ownerID, link.ID); !errors.Is(err, ErrOwnerApprovalKeyConflict) {
		t.Fatalf("revoked target owner key remained trusted by the Link bundle: %v", err)
	}
}

func TestExternalInviteLinkKeyProofExpiryIsReportedPerOwner(t *testing.T) {
	f := newExternalThreadInviteTestFixture(t)
	invite := f.createInvite(t)
	accepted, err := f.store.AcceptExternalThreadInvite(invite.Token,
		f.target.ownerID, f.target.endpointID, f.target.groupID)
	if err != nil {
		t.Fatal(err)
	}
	link, err := f.store.GetCommunicationLinkForOwner(accepted.LinkID, f.source.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	registerLinkEndpointKey(t, f.store, f.source.endpointID)
	registerLinkEndpointKey(t, f.store, f.target.endpointID)
	manifest, err := f.store.GetCommunicationLinkKeyManifest(link.ID, f.source.ownerID)
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
	sourceRecord, err := f.store.RegisterOwnerApprovalKeyLocal(f.source.ownerID, sourceOwnerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	targetRecord, err := f.store.RegisterOwnerApprovalKeyLocal(f.target.ownerID, targetOwnerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	shortExpiry := time.Now().UTC().Add(2 * time.Second)
	linkExpiry, err := time.Parse(time.RFC3339, link.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	sourceProof := signExternalThreadLinkKeyGrant(t, sourceOwnerKey,
		f.source.ownerID, link, manifest, e2ee.OwnerLinkGrantSideSource, shortExpiry)
	targetProof := signExternalThreadLinkKeyGrant(t, targetOwnerKey,
		f.target.ownerID, link, manifest, e2ee.OwnerLinkGrantSideTarget, linkExpiry)
	if _, err := f.store.RecordCommunicationLinkKeyGrant(f.source.ownerID, link.ID,
		CommunicationLinkGrantSource, sourceRecord.KeyID, sourceProof); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RecordCommunicationLinkKeyGrant(f.target.ownerID, link.ID,
		CommunicationLinkGrantTarget, targetRecord.KeyID, targetProof); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(shortExpiry) + 20*time.Millisecond)
	statuses, err := f.store.GetCommunicationLinkKeyGrantStatuses(link.ID, f.target.ownerID)
	if err != nil || len(statuses) != 2 ||
		statuses[0].CurrentStatus != CommunicationLinkKeyGrantProofExpired ||
		statuses[1].CurrentStatus != CommunicationLinkKeyGrantAccepted {
		t.Fatalf("expired source proof status was not isolated: statuses=%#v err=%v", statuses, err)
	}
	if _, err := f.store.getCommunicationLinkAuthorizationBundleForNodeScope(
		"node_target", f.target.ownerID, link.ID); !errors.Is(err, ErrCommunicationLinkGrantConflict) {
		t.Fatalf("expired bilateral consent still produced trusted Node evidence: %v", err)
	}
}
