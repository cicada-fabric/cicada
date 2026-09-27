package store

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestCommunicationLinkAuthorizationBundleRequiresCurrentBilateralConsent(t *testing.T) {
	f := newCommunicationLinkGrantFixture(t)
	registerLinkEndpointKey(t, f.store, "ep_source")
	registerLinkEndpointKey(t, f.store, "ep_target")
	manifest, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a")
	if err != nil {
		t.Fatal(err)
	}
	read := func(nodeID string) (*CommunicationLinkAuthorizationBundle, error) {
		return f.store.getCommunicationLinkAuthorizationBundleForNodeScope(nodeID, "owner_a", f.link.ID)
	}
	if _, err := read("node_source"); !errors.Is(err, ErrCommunicationLinkGrantConflict) {
		t.Fatalf("unsigned Link yielded a bundle: %v", err)
	}
	if _, err := read("other_node"); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("foreign Node learned Link authorization: %v", err)
	}
	if _, err := f.store.getCommunicationLinkAuthorizationBundleForNodeScope("node_source", "wrong_owner", f.link.ID); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("rebound Node owner learned Link authorization: %v", err)
	}
	sourceProof := signLinkKeyGrant(t, f.sourceKey, f.link, manifest, e2ee.OwnerLinkGrantSideSource)
	if _, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, sourceProof); err != nil {
		t.Fatal(err)
	}
	if _, err := read("node_source"); !errors.Is(err, ErrCommunicationLinkGrantConflict) {
		t.Fatalf("one-sided Link yielded a bundle: %v", err)
	}
	targetProof := signLinkKeyGrant(t, f.targetKey, f.link, manifest, e2ee.OwnerLinkGrantSideTarget)
	if _, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID,
		CommunicationLinkGrantTarget, f.targetKeyID, targetProof); err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range []string{"node_source", "node_target"} {
		bundle, err := read(nodeID)
		if err != nil {
			t.Fatalf("authorized Node %s cannot read bundle: %v", nodeID, err)
		}
		if bundle.Manifest.Digest != manifest.Digest || bundle.SourceGrant.OwnerKeyID != f.sourceKeyID ||
			bundle.TargetGrant.OwnerKeyID != f.targetKeyID ||
			string(bundle.SourceGrant.SignedProof) != string(sourceProof) ||
			string(bundle.TargetGrant.SignedProof) != string(targetProof) ||
			bundle.LinkState != CommunicationLinkProposed ||
			bundle.SourceGrant.CurrentStatus != CommunicationLinkKeyGrantAccepted ||
			bundle.TargetGrant.CurrentStatus != CommunicationLinkKeyGrantAccepted {
			t.Fatalf("bundle omitted or altered bilateral evidence for %s", nodeID)
		}
		if bundle.SourceGrant.OwnerPublicIdentity.ID != f.sourceKeyID || bundle.TargetGrant.OwnerPublicIdentity.ID != f.targetKeyID {
			t.Fatalf("bundle owner public identities do not match signed keys for %s", nodeID)
		}
	}
	if _, err := f.store.RevokeOwnerApprovalKeyLocal("owner_a", f.targetKeyID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := read("node_source"); !errors.Is(err, ErrOwnerApprovalKeyConflict) {
		t.Fatalf("revoked owner key still yielded authorization: %v", err)
	}
}

func TestCommunicationLinkAuthorizationBundleNodeCredentialRevocation(t *testing.T) {
	f := newCommunicationLinkGrantFixture(t)
	registerLinkEndpointKey(t, f.store, "ep_source")
	registerLinkEndpointKey(t, f.store, "ep_target")
	manifest, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a")
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct {
		name string
		key  *e2ee.Identity
		id   string
		role e2ee.OwnerLinkGrantSide
	}{
		{CommunicationLinkGrantSource, f.sourceKey, f.sourceKeyID, e2ee.OwnerLinkGrantSideSource},
		{CommunicationLinkGrantTarget, f.targetKey, f.targetKeyID, e2ee.OwnerLinkGrantSideTarget},
	} {
		proof := signLinkKeyGrant(t, side.key, f.link, manifest, side.role)
		if _, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID,
			side.name, side.id, proof); err != nil {
			t.Fatal(err)
		}
	}
	hubID, err := f.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceGrant, err := f.sourceKey.SignOwnerDeviceGrant("owner_a", "client-node-test", device.Public(),
		hubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: "owner_a", OwnerKeyID: f.sourceKeyID, DeviceID: "client-node-test",
		DevicePublic: device.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		t.Fatal(err)
	}
	nodeTokenHash := sha256.Sum256([]byte("independent node bearer"))
	credentialDigest := base64.RawURLEncoding.EncodeToString(nodeTokenHash[:])
	codeHash := sha256.Sum256([]byte("independent short code"))
	codeDigest := hex.EncodeToString(codeHash[:])
	if _, err := f.store.CreatePendingNodeDeviceBinding("node_source", "Source Node",
		credentialDigest, codeDigest, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	binding, err := f.store.ConfirmPendingNodeDeviceBinding("owner_a", "client-node-test", codeDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.GetCommunicationLinkAuthorizationBundleForNodeCredential(credentialDigest, f.link.ID); err != nil {
		t.Fatalf("current bound Node credential could not read Link evidence: %v", err)
	}
	if _, err := f.store.GetCommunicationLinkAuthorizationBundleForNodeCredential(
		base64.RawURLEncoding.EncodeToString(codeHash[:]), f.link.ID); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("wrong Node credential read Link evidence: %v", err)
	}
	if _, err := f.store.RevokeNodeDeviceBinding("owner_a", binding.ID, binding.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.GetCommunicationLinkAuthorizationBundleForNodeCredential(credentialDigest, f.link.ID); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("revoked Node credential read Link evidence: %v", err)
	}
}

func TestCommunicationLinkAuthorizationBundleFencesBindingAndLinkRevocation(t *testing.T) {
	f := newCommunicationLinkGrantFixture(t)
	registerLinkEndpointKey(t, f.store, "ep_source")
	registerLinkEndpointKey(t, f.store, "ep_target")
	manifest, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a")
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct {
		name string
		key  *e2ee.Identity
		id   string
		role e2ee.OwnerLinkGrantSide
	}{
		{CommunicationLinkGrantSource, f.sourceKey, f.sourceKeyID, e2ee.OwnerLinkGrantSideSource},
		{CommunicationLinkGrantTarget, f.targetKey, f.targetKeyID, e2ee.OwnerLinkGrantSideTarget},
	} {
		proof := signLinkKeyGrant(t, side.key, f.link, manifest, side.role)
		if _, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID,
			side.name, side.id, proof); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.getCommunicationLinkAuthorizationBundleForNodeScope("node_source", "owner_a", f.link.ID); err != nil {
		t.Fatal(err)
	}
	released, err := f.store.ReleaseSessionBindingLease(f.sourceBindingID,
		f.sourceLeaseOwner, manifest.Source.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcquireSessionBindingLease(f.sourceBindingID, f.sourceLeaseOwner,
		released.Epoch, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.getCommunicationLinkAuthorizationBundleForNodeScope("node_source", "owner_a", f.link.ID); err == nil {
		t.Fatal("stale native binding yielded authorization")
	}
	if _, err := f.store.RevokeCommunicationLink(f.link.ID, "owner_a", f.link.Version, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.getCommunicationLinkAuthorizationBundleForNodeScope("node_target", "owner_a", f.link.ID); err == nil {
		t.Fatal("revoked Link yielded authorization")
	}
}
