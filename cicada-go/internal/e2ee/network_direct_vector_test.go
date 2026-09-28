package e2ee

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNetworkDirectPublicSyntheticVector(t *testing.T) {
	data, err := os.ReadFile("testdata/network-direct-key-consent-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		SyntheticOnly            bool                 `json:"synthetic_only"`
		Warning                  string               `json:"warning"`
		Owner                    PublicIdentity       `json:"owner_public_identity"`
		Sender                   PublicIdentity       `json:"sender_public_identity"`
		Attestation              string               `json:"attestation"`
		AttestationSigned        string               `json:"attestation_signed_input_base64"`
		AttestationSHA           string               `json:"attestation_signed_sha256"`
		Manifest                 string               `json:"manifest_canonical_json"`
		ManifestDigest           string               `json:"manifest_digest"`
		SyntheticNativeSessionID string               `json:"synthetic_native_session_id"`
		NativeSessionDigest      string               `json:"native_session_digest"`
		Grant                    string               `json:"owner_grant"`
		GrantSigned              string               `json:"owner_grant_signed_input_base64"`
		GrantSHA                 string               `json:"owner_grant_signed_sha256"`
		Context                  NetworkDirectContext `json:"network_context"`
		Envelope                 string               `json:"network_envelope"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if !vector.SyntheticOnly || !strings.Contains(vector.Warning, "Never initialize") {
		t.Fatal("public vector lacks deployment prohibition")
	}
	if strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatal("public vector contains private-key material")
	}
	var attestation NetworkDirectKeyAttestation
	if err := json.Unmarshal([]byte(vector.Attestation), &attestation); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNetworkDirectKeyAttestation([]byte(vector.Attestation), attestation); err != nil {
		t.Fatalf("attestation: %v", err)
	}
	if attestation.Public.ID != vector.Sender.ID {
		t.Fatal("sender key mismatch")
	}
	attestation.Signature = nil
	attestClaims, err := json.Marshal(attestation)
	if err != nil {
		t.Fatal(err)
	}
	checkSignedVector(t, vector.AttestationSigned, vector.AttestationSHA,
		append([]byte(networkDirectAttestationDomain), attestClaims...))
	if got := NetworkDirectManifestDigest([]byte(vector.Manifest)); got != vector.ManifestDigest {
		t.Fatalf("manifest digest: %s", got)
	}
	if vector.SyntheticNativeSessionID != "native_synthetic_private_locator" ||
		NetworkDirectNativeSessionDigest(vector.SyntheticNativeSessionID) != vector.NativeSessionDigest {
		t.Fatal("synthetic native-session commitment differs")
	}
	var signedManifest struct {
		NativeSessionDigest string `json:"native_session_digest"`
	}
	if err := json.Unmarshal([]byte(vector.Manifest), &signedManifest); err != nil ||
		signedManifest.NativeSessionDigest != vector.NativeSessionDigest {
		t.Fatal("Owner-signed manifest omits synthetic native-session commitment")
	}
	var grant OwnerNetworkDirectKeyGrant
	if err := json.Unmarshal([]byte(vector.Grant), &grant); err != nil {
		t.Fatal(err)
	}
	acceptedAt := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if _, err := VerifyOwnerNetworkDirectKeyGrant([]byte(vector.Grant), vector.Owner,
		OwnerNetworkDirectKeyGrant{HubID: vector.Context.HubID,
			NetworkID: vector.Context.NetworkID, EndpointID: vector.Context.SenderEndpointID,
			OwnerID: vector.Context.SenderOwnerID, ManifestDigest: vector.ManifestDigest}, acceptedAt); err != nil {
		t.Fatalf("Owner proof: %v", err)
	}
	grant.Signature = nil
	grantClaims, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	checkSignedVector(t, vector.GrantSigned, vector.GrantSHA,
		append([]byte(networkDirectGrantDomain), grantClaims...))
	if err := VerifyNetworkDirectMessage(vector.Sender, vector.Context, []byte(vector.Envelope)); err != nil {
		t.Fatalf("network envelope: %v", err)
	}
	changed := vector.Context
	changed.NetworkID = "net_synthetic_other"
	if err := VerifyNetworkDirectMessage(vector.Sender, changed, []byte(vector.Envelope)); err == nil {
		t.Fatal("network scope tampering passed")
	}
	changed = vector.Context
	changed.SenderEnrollmentRevision++
	if err := VerifyNetworkDirectMessage(vector.Sender, changed, []byte(vector.Envelope)); err == nil {
		t.Fatal("enrollment generation tampering passed")
	}
}

func checkSignedVector(t *testing.T, encoded, digest string, expected []byte) {
	t.Helper()
	actual, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(expected) {
		t.Fatal("signed input bytes differ")
	}
	hash := sha256.Sum256(actual)
	if hex.EncodeToString(hash[:]) != digest {
		t.Fatal("signed input digest differs")
	}
}
