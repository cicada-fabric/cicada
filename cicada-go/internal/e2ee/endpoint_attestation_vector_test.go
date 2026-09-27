package e2ee

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	endpointAttestationVectorPath = "testdata/endpoint-key-attestation-v1.json"
	endpointAttestationWarning    = "PUBLIC SYNTHETIC TEST KEY — NEVER USE IN A DEPLOYMENT"
)

type endpointAttestationVector struct {
	FixtureVersion int            `json:"fixture_version"`
	Warning        string         `json:"warning"`
	Attestation    string         `json:"attestation_utf8"`
	Public         PublicIdentity `json:"public_identity"`
	SignedInputHex string         `json:"signed_input_hex"`
	ProofSHA256    string         `json:"proof_sha256"`
}

// The fixture pins the exact v1 signing bytes independently of the Go
// Sign/Verify round trip, so a Kotlin implementation need not infer them.
func TestPublishedEndpointAttestationVector(t *testing.T) {
	if os.Getenv("CICADA_UPDATE_ENDPOINT_ATTESTATION_VECTOR") == "1" {
		writeEndpointAttestationVector(t)
	}
	data, err := os.ReadFile(endpointAttestationVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var vector endpointAttestationVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.FixtureVersion != 1 || vector.Warning != endpointAttestationWarning {
		t.Fatal("unsupported or unlabelled Endpoint attestation fixture")
	}
	proof := []byte(vector.Attestation)
	digest := sha256.Sum256(proof)
	if hex.EncodeToString(digest[:]) != vector.ProofSHA256 {
		t.Fatal("published attestation proof digest changed")
	}
	var attestation EndpointKeyAttestation
	if err := json.Unmarshal(proof, &attestation); err != nil {
		t.Fatal(err)
	}
	publicJSON, _ := json.Marshal(vector.Public)
	proofPublicJSON, _ := json.Marshal(attestation.Public)
	if !bytes.Equal(publicJSON, proofPublicJSON) {
		t.Fatal("published public key differs from attestation")
	}
	signed, err := endpointAttestationSignedBytes(attestation)
	if err != nil || hex.EncodeToString(signed) != vector.SignedInputHex {
		t.Fatal("published Endpoint attestation signed bytes changed")
	}
	if !bytes.HasSuffix(signed, []byte(`,"signature":null}`)) {
		t.Fatal("v1 signature input must end with signature:null")
	}
	_, signingKey, err := validatePublic(vector.Public)
	if err != nil || !mldsa65.Verify(signingKey, signed, nil, attestation.Signature) {
		t.Fatal("published ML-DSA-65 signature did not independently verify")
	}
	withoutSignature := append(bytes.TrimSuffix(bytes.Clone(signed), []byte(`,"signature":null}`)), '}')
	if mldsa65.Verify(signingKey, withoutSignature, nil, attestation.Signature) {
		t.Fatal("signature unexpectedly verifies under the obsolete omitted-field contract")
	}
	if _, err := VerifyEndpointKeyAttestation(proof, attestation.EndpointID,
		attestation.PrincipalID, attestation.NodeID, attestation.BindingID,
		attestation.BindingEpoch); err != nil {
		t.Fatalf("published attestation failed production verification: %v", err)
	}
}

func writeEndpointAttestationVector(t *testing.T) {
	t.Helper()
	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignEndpointKeyAttestation("ep_synthetic_vector",
		"pr_synthetic_vector", "node_synthetic_vector", "bind_synthetic_vector", 7)
	if err != nil {
		t.Fatal(err)
	}
	var attestation EndpointKeyAttestation
	if err := json.Unmarshal(proof, &attestation); err != nil {
		t.Fatal(err)
	}
	signed, err := endpointAttestationSignedBytes(attestation)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(proof)
	vector := endpointAttestationVector{
		FixtureVersion: 1, Warning: endpointAttestationWarning,
		Attestation: string(proof), Public: identity.Public(),
		SignedInputHex: hex.EncodeToString(signed), ProofSHA256: hex.EncodeToString(digest[:]),
	}
	encoded, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(endpointAttestationVectorPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(endpointAttestationVectorPath, append(encoded, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
