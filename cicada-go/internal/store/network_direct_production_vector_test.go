package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

func TestNetworkDirectProductionShapeSyntheticVector(t *testing.T) {
	data, err := os.ReadFile("testdata/network-direct-key-production-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		SyntheticOnly     bool                     `json:"synthetic_only"`
		Warning           string                   `json:"warning"`
		Manifest          NetworkDirectKeyManifest `json:"manifest"`
		CanonicalClaims   string                   `json:"canonical_claims"`
		ManifestDigest    string                   `json:"manifest_digest"`
		OwnerPublic       e2ee.PublicIdentity      `json:"owner_public_identity"`
		OwnerProof        string                   `json:"owner_proof"`
		AttestationSigned string                   `json:"attestation_signed_input_base64"`
		AttestationSHA    string                   `json:"attestation_signed_sha256"`
		GrantSigned       string                   `json:"owner_grant_signed_input_base64"`
		GrantSHA          string                   `json:"owner_grant_signed_sha256"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if !vector.SyntheticOnly || !strings.Contains(vector.Warning, "Never initialize") ||
		strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatal("public fixture lacks synthetic deployment warning or contains private material")
	}
	m := vector.Manifest
	if m.NativeSessionID != "native_synthetic_private_locator" ||
		m.NativeSessionDigest != e2ee.NetworkDirectNativeSessionDigest(m.NativeSessionID) ||
		m.Candidate.Fingerprint == "" || len(m.Candidate.Attestation) == 0 ||
		m.Candidate.Version <= 0 || m.BindingEpoch <= 0 || m.MembershipRevision <= 0 ||
		m.EndpointEnrollmentRevision <= 0 {
		t.Fatal("production-shape fixture omitted current native, revision or candidate evidence")
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(m.Candidate.Public)
	if err != nil || fingerprint != m.Candidate.Fingerprint {
		t.Fatalf("candidate fingerprint differs from production calculation: %v", err)
	}
	claims, err := m.CanonicalClaims()
	if err != nil || !bytes.Equal(claims, []byte(vector.CanonicalClaims)) ||
		strings.Contains(string(claims), "native_synthetic_private_locator") ||
		!strings.Contains(string(claims), `"digest":""`) {
		t.Fatalf("Store canonical claims differ from published production shape: %v", err)
	}
	digest, err := m.CanonicalDigest()
	if err != nil || digest != m.Digest || digest != vector.ManifestDigest ||
		digest != e2ee.NetworkDirectManifestDigest(claims) {
		t.Fatalf("manifest digest mismatch: %v", err)
	}
	attExpected := e2ee.NetworkDirectKeyAttestation{Version: 1, HubID: m.HubID,
		NetworkID: m.NetworkID, EndpointID: m.EndpointID, PrincipalID: m.PrincipalID,
		NodeID: m.NodeID, BindingID: m.BindingID, BindingEpoch: m.BindingEpoch,
		Public: m.Candidate.Public}
	if _, err := e2ee.VerifyNetworkDirectKeyAttestation(m.Candidate.Attestation, attExpected); err != nil {
		t.Fatalf("candidate self-attestation: %v", err)
	}
	var att e2ee.NetworkDirectKeyAttestation
	if err := json.Unmarshal(m.Candidate.Attestation, &att); err != nil {
		t.Fatal(err)
	}
	att.Signature = nil
	attClaims, _ := json.Marshal(att)
	checkNetworkProductionSignedInput(t, vector.AttestationSigned, vector.AttestationSHA,
		append([]byte("cicada/network/direct-key-attestation/v1\x00"), attClaims...))
	verifyAt := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	grant, err := e2ee.VerifyOwnerNetworkDirectKeyGrant([]byte(vector.OwnerProof), vector.OwnerPublic,
		e2ee.OwnerNetworkDirectKeyGrant{HubID: m.HubID, NetworkID: m.NetworkID,
			EndpointID: m.EndpointID, OwnerID: m.OwnerID, ManifestDigest: m.Digest}, verifyAt)
	if err != nil {
		t.Fatalf("Owner proof: %v", err)
	}
	grant.Signature = nil
	grantClaims, _ := json.Marshal(grant)
	checkNetworkProductionSignedInput(t, vector.GrantSigned, vector.GrantSHA,
		append([]byte("cicada/network/direct-key-grant/v1\x00"), grantClaims...))
	changed := m
	changed.Candidate.Fingerprint = strings.Repeat("0", len(changed.Candidate.Fingerprint))
	if got, err := changed.CanonicalDigest(); err != nil || got == m.Digest {
		t.Fatalf("fingerprint tampering did not alter consent digest: %v", err)
	}
	changed = m
	changed.BindingEpoch++
	if got, err := changed.CanonicalDigest(); err != nil || got == m.Digest {
		t.Fatalf("binding tampering did not alter consent digest: %v", err)
	}
	changed = m
	changed.NativeSessionID = "native_synthetic_other_locator"
	changed.NativeSessionDigest = e2ee.NetworkDirectNativeSessionDigest(changed.NativeSessionID)
	if got, err := changed.CanonicalDigest(); err != nil || got == m.Digest {
		t.Fatalf("native locator commitment tampering did not alter consent digest: %v", err)
	}
}

func checkNetworkProductionSignedInput(t *testing.T, encoded, digest string, expected []byte) {
	t.Helper()
	actual, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("signed bytes differ from published fixture: %v", err)
	}
	sum := sha256.Sum256(actual)
	if hex.EncodeToString(sum[:]) != digest {
		t.Fatal("signed input SHA-256 differs")
	}
}
