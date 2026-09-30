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

func TestOwnerNetworkKeySignVerifiesFullSyntheticManifest(t *testing.T) {
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	const hubID, networkID, endpointID, ownerID = "hub_cli", "net_cli", "ep_cli", "owner_cli"
	const nativeID = "synthetic-native-thread"
	attestation, err := endpoint.SignNetworkDirectKeyAttestation(hubID, networkID, endpointID, "principal_cli", "node_cli", "binding_cli", 1)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(endpoint.Public())
	if err != nil {
		t.Fatal(err)
	}
	manifest := store.NetworkDirectKeyManifest{Version: 1, HubID: hubID, NetworkID: networkID,
		EndpointID: endpointID, PrincipalID: "principal_cli", OwnerID: ownerID, NodeID: "node_cli",
		NativeSessionID: nativeID, NativeSessionDigest: e2ee.NetworkDirectNativeSessionDigest(nativeID),
		BindingID: "binding_cli", BindingEpoch: 1, MembershipRevision: 1, EndpointEnrollmentRevision: 1,
		Candidate: store.NetworkDirectKeyCandidate{NetworkID: networkID, EndpointID: endpointID,
			PrincipalID: "principal_cli", OwnerID: ownerID, NodeID: "node_cli", BindingID: "binding_cli",
			BindingEpoch: 1, Public: endpoint.Public(), Fingerprint: fingerprint, Attestation: attestation, Version: 1}}
	manifest.Digest, err = manifest.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
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
	writeManifest := func() {
		t.Helper()
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeManifest()
	proofPath := filepath.Join(dir, "proof.json")
	args := []string{"--private", privatePath, "--manifest", manifestPath, "--output", proofPath,
		"--expect-owner-id", ownerID, "--expect-hub-id", hubID, "--expect-network-id", networkID,
		"--expect-endpoint-id", endpointID, "--expect-native-session-digest", manifest.NativeSessionDigest,
		"--expires-at", time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)}
	var summary bytes.Buffer
	if err := ownerNetworkKeySignCommand(args, &summary); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(proofPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("proof file mode: %v %v", info, err)
	}
	var result struct {
		SignedProof string `json:"signed_proof"`
	}
	data, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	proof, err := base64.StdEncoding.DecodeString(result.SignedProof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2ee.VerifyOwnerNetworkDirectKeyGrant(proof, owner.Public(), e2ee.OwnerNetworkDirectKeyGrant{
		Version: 1, HubID: hubID, NetworkID: networkID, EndpointID: endpointID, OwnerID: ownerID,
		OwnerKeyID: owner.Public().ID, ManifestDigest: manifest.Digest}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(summary.Bytes(), []byte(`"manifest_digest":"`+manifest.Digest+`"`)) {
		t.Fatal("summary omitted reviewed digest")
	}
	// A stale or substituted manifest cannot be signed, and a proof path is
	// never overwritten even for a valid exact retry.
	if err := ownerNetworkKeySignCommand(args, &summary); err == nil {
		t.Fatal("proof was overwritten")
	}
	manifest.Candidate.Fingerprint = "sha256:wrong"
	manifest.Digest, err = manifest.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	writeManifest()
	args[5] = filepath.Join(dir, "tampered-proof.json")
	if err := ownerNetworkKeySignCommand(args, &summary); err == nil {
		t.Fatal("tampered candidate was signed")
	}
}
