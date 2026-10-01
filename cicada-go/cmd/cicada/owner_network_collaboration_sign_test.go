package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestOwnerNetworkCollaborationSignVerifiesExactPurposeManifest(t *testing.T) {
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	const hubID, networkID, endpointID, ownerID = "hub_collab_cli", "net_collab_cli", "ep_collab_cli", "owner_collab_cli"
	const nativeID = "synthetic-collaboration-thread"
	attestation, err := endpoint.SignNetworkDirectKeyAttestation(hubID, networkID,
		endpointID, "principal_collab_cli", "node_collab_cli", "binding_collab_cli", 2)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(endpoint.Public())
	if err != nil {
		t.Fatal(err)
	}
	key := store.NetworkDirectKeyManifest{Version: 1, HubID: hubID, NetworkID: networkID,
		EndpointID: endpointID, PrincipalID: "principal_collab_cli", OwnerID: ownerID,
		NodeID: "node_collab_cli", NativeSessionID: nativeID,
		NativeSessionDigest: e2ee.NetworkDirectNativeSessionDigest(nativeID),
		BindingID:           "binding_collab_cli", BindingEpoch: 2, MembershipRevision: 3,
		EndpointEnrollmentRevision: 4,
		Candidate: store.NetworkDirectKeyCandidate{NetworkID: networkID, EndpointID: endpointID,
			PrincipalID: "principal_collab_cli", OwnerID: ownerID, NodeID: "node_collab_cli",
			BindingID: "binding_collab_cli", BindingEpoch: 2, Public: endpoint.Public(),
			Fingerprint: fingerprint, Attestation: attestation, Version: 1}}
	key.Digest, err = key.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := key.CanonicalClaims()
	if err != nil {
		t.Fatal(err)
	}
	manifest := store.NetworkCollaborationKeyManifest{Purpose: e2ee.NetworkCollaborationPurposeTask,
		Key: key, Digest: e2ee.NetworkCollaborationManifestDigest(e2ee.NetworkCollaborationPurposeTask, claims)}

	dir := t.TempDir()
	private, err := owner.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(dir, "owner.key")
	if err := os.WriteFile(privatePath, private, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	proofPath := filepath.Join(dir, "proof.json")
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	args := []string{"--private", privatePath, "--manifest", manifestPath, "--output", proofPath,
		"--expect-owner-id", ownerID, "--expect-owner-key-id", owner.Public().ID,
		"--expect-hub-id", hubID, "--expect-network-id", networkID,
		"--expect-endpoint-id", endpointID, "--expect-native-session-digest", key.NativeSessionDigest,
		"--purpose", e2ee.NetworkCollaborationPurposeTask, "--expires-at", expires}
	var summary bytes.Buffer
	if err := ownerNetworkCollaborationKeySignCommand(args, &summary); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(proofPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("proof file mode: %v %v", info, err)
	}
	var wrapper struct {
		SignedProof string `json:"signed_proof"`
	}
	wrapperBytes, err := os.ReadFile(proofPath)
	if err != nil || json.Unmarshal(wrapperBytes, &wrapper) != nil {
		t.Fatal("proof wrapper is unreadable")
	}
	proof, err := base64.StdEncoding.DecodeString(wrapper.SignedProof)
	if err != nil {
		t.Fatal("proof is not standard base64")
	}
	verified, err := e2ee.VerifyOwnerNetworkCollaborationKeyGrant(proof, owner.Public(),
		e2ee.OwnerNetworkCollaborationKeyGrant{Purpose: manifest.Purpose, HubID: hubID,
			NetworkID: networkID, EndpointID: endpointID, OwnerID: ownerID,
			ManifestDigest: manifest.Digest}, time.Now().UTC())
	if err != nil || verified.OwnerKeyID != owner.Public().ID {
		t.Fatalf("purpose proof did not verify: %v", err)
	}
	if !bytes.Contains(summary.Bytes(), []byte(`"purpose":"TASK"`)) ||
		!bytes.Contains(summary.Bytes(), []byte(manifest.Digest)) {
		t.Fatal("signing summary omitted the reviewed purpose or digest")
	}
	if err := ownerNetworkCollaborationKeySignCommand(args, &summary); err == nil {
		t.Fatal("existing proof path was overwritten")
	}

	manifest.Purpose = e2ee.NetworkCollaborationPurposeBroadcast
	changed, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	args[5] = filepath.Join(dir, "wrong-purpose-proof.json")
	if err := ownerNetworkCollaborationKeySignCommand(args, &summary); err == nil {
		t.Fatal("mismatched purpose manifest was signed")
	}
}
