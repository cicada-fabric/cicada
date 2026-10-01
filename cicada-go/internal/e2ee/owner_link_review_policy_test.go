package e2ee

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPublishedOwnerLinkReviewPolicyProofVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "owner-link-review-policy-proof-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		FixtureVersion        int            `json:"fixture_version"`
		SyntheticOnly         bool           `json:"synthetic_only"`
		Warning               string         `json:"warning"`
		Algorithm             string         `json:"algorithm"`
		SigningDomain         string         `json:"signing_domain"`
		SigningDomainHex      string         `json:"signing_domain_hex"`
		ClaimsFieldOrder      []string       `json:"claims_field_order"`
		OwnerPublicIdentity   PublicIdentity `json:"owner_public_identity"`
		MLDSAPublicKeyBase64  string         `json:"mldsa_public_key_base64"`
		CanonicalUnsignedJSON string         `json:"canonical_unsigned_json"`
		SignedBytesBase64     string         `json:"signed_bytes_base64"`
		SignedBytesHex        string         `json:"signed_bytes_hex"`
		SignedBytesSHA256     string         `json:"signed_bytes_sha256"`
		SignatureBase64       string         `json:"signature_base64"`
		ProofJSON             string         `json:"proof_json"`
		ProofSHA256           string         `json:"proof_sha256"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.FixtureVersion != 1 || !vector.SyntheticOnly ||
		vector.Warning != "PUBLIC SYNTHETIC TEST KEY — NEVER USE IN A DEPLOYMENT" ||
		vector.Algorithm != "ML-DSA-65" ||
		vector.SigningDomain != `cicada/communication-link/review-policy-owner-approval/v1\x00` {
		t.Fatal("Owner review-policy vector is not clearly synthetic or names the wrong purpose domain")
	}
	if err := ValidatePublicIdentity(vector.OwnerPublicIdentity); err != nil {
		t.Fatalf("published synthetic Owner public identity is invalid: %v", err)
	}
	mldsaPublic, err := base64.StdEncoding.DecodeString(vector.MLDSAPublicKeyBase64)
	if err != nil || !bytes.Equal(mldsaPublic, vector.OwnerPublicIdentity.SigningPublic) {
		t.Fatal("published ML-DSA public key differs from the trusted Owner identity")
	}
	var proof OwnerLinkReviewPolicyProof
	proofWire := []byte(vector.ProofJSON)
	if err := json.Unmarshal(proofWire, &proof); err != nil {
		t.Fatal(err)
	}
	canonicalProof, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(canonicalProof, proofWire) {
		t.Fatal("published Owner review-policy proof is not canonical wire JSON")
	}
	wantOrder := []string{
		"version", "owner_id", "link_id", "contract_digest", "policy_digest",
		"expected_link_version", "policy_version", "side", "issued_at", "expires_at", "nonce",
	}
	if len(vector.ClaimsFieldOrder) != len(wantOrder) {
		t.Fatalf("claims field count=%d, want %d", len(vector.ClaimsFieldOrder), len(wantOrder))
	}
	for i := range wantOrder {
		if vector.ClaimsFieldOrder[i] != wantOrder[i] {
			t.Fatalf("claims field order[%d]=%q, want %q", i, vector.ClaimsFieldOrder[i], wantOrder[i])
		}
	}
	claims, err := json.Marshal(proof.claims())
	if err != nil || string(claims) != vector.CanonicalUnsignedJSON {
		t.Fatal("published unsigned JSON differs from the production 11-field ordered claims")
	}
	signed, err := ownerLinkReviewPolicySignedBytes(proof)
	if err != nil {
		t.Fatal(err)
	}
	base64Bytes, err := base64.StdEncoding.DecodeString(vector.SignedBytesBase64)
	if err != nil {
		t.Fatal(err)
	}
	hexBytes, err := hex.DecodeString(vector.SignedBytesHex)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(signed)
	proofSum := sha256.Sum256(proofWire)
	if !bytes.Equal(signed, base64Bytes) || !bytes.Equal(signed, hexBytes) ||
		hex.EncodeToString(sum[:]) != vector.SignedBytesSHA256 ||
		hex.EncodeToString(proofSum[:]) != vector.ProofSHA256 ||
		!bytes.Equal(proof.Signature, mustDecodeVectorBase64(t, vector.SignatureBase64)) {
		t.Fatal("published Owner review-policy signing bytes, digest, proof hash, or signature differs")
	}
	if !bytes.HasPrefix(signed, []byte(ownerLinkReviewPolicyDomain)) ||
		vector.SigningDomainHex != hex.EncodeToString([]byte(ownerLinkReviewPolicyDomain)) {
		t.Fatal("Owner review-policy signature domain differs")
	}
	now := time.Date(2026, 10, 1, 13, 0, 0, 0, time.UTC)
	if _, err := VerifyOwnerLinkReviewPolicy(proofWire, vector.OwnerPublicIdentity,
		proof.OwnerID, proof.LinkID, proof.ContractDigest, proof.PolicyDigest,
		proof.ExpectedLinkVersion, proof.PolicyVersion, proof.Side, now); err != nil {
		t.Fatalf("published synthetic Owner review-policy proof was rejected: %v", err)
	}
	if _, err := VerifyOwnerLinkGrant(proofWire, vector.OwnerPublicIdentity,
		proof.OwnerID, proof.LinkID, proof.ContractDigest, proof.ExpectedLinkVersion, proof.Side, now); err == nil {
		t.Fatal("review-policy proof was accepted under the ordinary Link-grant purpose")
	}
	otherOwner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnerLinkReviewPolicy(proofWire, otherOwner.Public(),
		proof.OwnerID, proof.LinkID, proof.ContractDigest, proof.PolicyDigest,
		proof.ExpectedLinkVersion, proof.PolicyVersion, proof.Side, now); err == nil {
		t.Fatal("proof verified under a different trusted Owner key")
	}

	for _, test := range []struct {
		name                       string
		ownerID, linkID            string
		contract, policy           string
		linkVersion, policyVersion uint64
		side                       OwnerLinkGrantSide
	}{
		{name: "owner", ownerID: "owner_synthetic_other"},
		{name: "link", linkID: "link_synthetic_other"},
		{name: "contract", contract: vectorDigest("different contract")},
		{name: "policy", policy: vectorDigest("different policy")},
		{name: "link-version", linkVersion: proof.ExpectedLinkVersion + 1},
		{name: "policy-version", policyVersion: proof.PolicyVersion + 1},
		{name: "side", side: OwnerLinkGrantSideTarget},
	} {
		t.Run(test.name, func(t *testing.T) {
			ownerID, linkID := proof.OwnerID, proof.LinkID
			contractDigest, policyDigest := proof.ContractDigest, proof.PolicyDigest
			linkVersion, policyVersion, side := proof.ExpectedLinkVersion, proof.PolicyVersion, proof.Side
			if test.ownerID != "" {
				ownerID = test.ownerID
			}
			if test.linkID != "" {
				linkID = test.linkID
			}
			if test.contract != "" {
				contractDigest = test.contract
			}
			if test.policy != "" {
				policyDigest = test.policy
			}
			if test.linkVersion != 0 {
				linkVersion = test.linkVersion
			}
			if test.policyVersion != 0 {
				policyVersion = test.policyVersion
			}
			if test.side != "" {
				side = test.side
			}
			if _, err := VerifyOwnerLinkReviewPolicy(proofWire, vector.OwnerPublicIdentity,
				ownerID, linkID, contractDigest, policyDigest, linkVersion, policyVersion, side, now); err == nil {
				t.Fatal("proof verified with a changed Owner/Link/contract/policy/version/side scope")
			}
		})
	}

	var wireObject map[string]json.RawMessage
	if err := json.Unmarshal(proofWire, &wireObject); err != nil {
		t.Fatal(err)
	}
	reordered, err := json.Marshal(wireObject)
	if err != nil || bytes.Equal(reordered, proofWire) {
		t.Fatal("negative ordering fixture did not change canonical field order")
	}
	if _, err := VerifyOwnerLinkReviewPolicy(reordered, vector.OwnerPublicIdentity,
		proof.OwnerID, proof.LinkID, proof.ContractDigest, proof.PolicyDigest,
		proof.ExpectedLinkVersion, proof.PolicyVersion, proof.Side, now); err == nil {
		t.Fatal("reordered Owner review-policy proof JSON was accepted")
	}

	tampered := proof
	tampered.PolicyDigest = vectorDigest("tampered policy")
	tamperedWire, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnerLinkReviewPolicy(tamperedWire, vector.OwnerPublicIdentity,
		proof.OwnerID, proof.LinkID, proof.ContractDigest, tampered.PolicyDigest,
		proof.ExpectedLinkVersion, proof.PolicyVersion, proof.Side, now); err == nil {
		t.Fatal("tampered signed policy claim was accepted")
	}
	tampered = proof
	tampered.Signature = append([]byte(nil), proof.Signature...)
	tampered.Signature[0] ^= 1
	tamperedWire, err = json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnerLinkReviewPolicy(tamperedWire, vector.OwnerPublicIdentity,
		proof.OwnerID, proof.LinkID, proof.ContractDigest, proof.PolicyDigest,
		proof.ExpectedLinkVersion, proof.PolicyVersion, proof.Side, now); err == nil {
		t.Fatal("tampered ML-DSA signature was accepted")
	}
}

func mustDecodeVectorBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func vectorDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func TestOwnerLinkReviewPolicyProofIsPurposeSeparatedAndExact(t *testing.T) {
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	digest := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
	contractDigest, policyDigest := digest("contract"), digest("review-policy")
	now := time.Now().UTC().Truncate(time.Second)
	proof, err := owner.SignOwnerLinkReviewPolicy("owner_a", "link_a", contractDigest,
		policyDigest, 3, 2, OwnerLinkGrantSideSource, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnerLinkReviewPolicy(proof, owner.Public(), "owner_a", "link_a",
		contractDigest, policyDigest, 3, 2, OwnerLinkGrantSideSource, now.Add(time.Minute)); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	if _, err := VerifyOwnerLinkGrant(proof, owner.Public(), "owner_a", "link_a",
		contractDigest, 3, OwnerLinkGrantSideSource, now.Add(time.Minute)); err == nil {
		t.Fatal("review-policy proof was accepted as a normal Link grant")
	}
	if _, err := VerifyOwnerLinkReviewPolicy(proof, other.Public(), "owner_a", "link_a",
		contractDigest, policyDigest, 3, 2, OwnerLinkGrantSideSource, now.Add(time.Minute)); err == nil {
		t.Fatal("proof verified under a different trusted owner key")
	}
	if _, err := VerifyOwnerLinkReviewPolicy(proof, owner.Public(), "owner_a", "link_a",
		contractDigest, digest("different policy"), 3, 2, OwnerLinkGrantSideSource, now.Add(time.Minute)); err == nil {
		t.Fatal("proof verified for a different policy digest")
	}

	var envelope map[string]any
	if err := json.Unmarshal(proof, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["policy_digest"] = digest("modified")
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnerLinkReviewPolicy(tampered, owner.Public(), "owner_a", "link_a",
		contractDigest, digest("modified"), 3, 2, OwnerLinkGrantSideSource, now.Add(time.Minute)); err == nil {
		t.Fatal("tampered policy digest verified")
	}
}
