package nodekeys

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const crossOwnerGroupKeyVectorPath = "../e2ee/testdata/cross-owner-group-key-v2.json"

type crossOwnerGroupKeyPublicVector struct {
	FixtureVersion                   int                        `json:"fixture_version"`
	Warning                          string                     `json:"warning"`
	Manifest                         CrossOwnerGroupKeyManifest `json:"manifest"`
	EndpointOwnerPublic              e2ee.PublicIdentity        `json:"endpoint_owner_public_identity"`
	GroupOwnerPublic                 e2ee.PublicIdentity        `json:"group_owner_public_identity"`
	EndpointConsent                  CrossOwnerGroupKeyProof    `json:"endpoint_consent"`
	GroupAdmission                   CrossOwnerGroupKeyProof    `json:"group_admission"`
	EndpointConsentSignedInputBase64 string                     `json:"endpoint_consent_signed_input_base64"`
	EndpointConsentSignedInputSHA256 string                     `json:"endpoint_consent_signed_input_sha256"`
	GroupAdmissionSignedInputBase64  string                     `json:"group_admission_signed_input_base64"`
	GroupAdmissionSignedInputSHA256  string                     `json:"group_admission_signed_input_sha256"`
}

func TestPublishedCrossOwnerGroupKeyVectorVerifiesBothOwnerSides(t *testing.T) {
	data, err := os.ReadFile(crossOwnerGroupKeyVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var vector crossOwnerGroupKeyPublicVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	manifest := vector.Manifest
	if vector.FixtureVersion != 1 || vector.Warning != "PUBLIC SYNTHETIC TEST KEYS — NEVER USE IN A DEPLOYMENT" ||
		manifest.Operation != crossOwnerGroupKeyOperation || manifest.EndpointOwnerID == manifest.GroupOwnerID ||
		!manifest.CrossOwnerContextShared || manifest.HistoryIncluded || manifest.Digest != crossOwnerGroupManifestDigest(manifest) ||
		manifest.CandidateBindingDigest != crossOwnerGroupBindingDigest(manifest) {
		t.Fatal("published cross-owner manifest is unlabelled, malformed, or digest-mismatched")
	}
	proofDigest := sha256.Sum256(manifest.CandidateAttestation)
	if hex.EncodeToString(proofDigest[:]) != manifest.CandidateProofDigest {
		t.Fatal("Endpoint attestation digest differs from cross-owner manifest")
	}
	if _, err := e2ee.VerifyEndpointKeyAttestation(manifest.CandidateAttestation,
		manifest.EndpointID, manifest.PrincipalID, manifest.NodeID, manifest.BindingID,
		manifest.BindingEpoch); err != nil {
		t.Fatalf("synthetic Endpoint candidate attestation is invalid: %v", err)
	}
	at := time.Date(2026, 9, 30, 12, 5, 0, 0, time.UTC)
	for _, item := range []struct {
		name              string
		proof             CrossOwnerGroupKeyProof
		owner             e2ee.PublicIdentity
		ownerID           string
		label             string
		side              e2ee.OwnerLinkGrantSide
		signedInput       string
		signedInputSHA256 string
	}{{"endpoint-owner", vector.EndpointConsent, vector.EndpointOwnerPublic,
		manifest.EndpointOwnerID, "ENDPOINT", e2ee.OwnerLinkGrantSideSource,
		vector.EndpointConsentSignedInputBase64, vector.EndpointConsentSignedInputSHA256},
		{"group-owner", vector.GroupAdmission, vector.GroupOwnerPublic,
			manifest.GroupOwnerID, "GROUP", e2ee.OwnerLinkGrantSideTarget,
			vector.GroupAdmissionSignedInputBase64, vector.GroupAdmissionSignedInputSHA256}} {
		t.Run(item.name, func(t *testing.T) {
			if item.proof.GroupID != manifest.GroupID || item.proof.EndpointID != manifest.EndpointID ||
				item.proof.SignerOwnerID != item.ownerID || item.proof.SignerSide != item.label ||
				item.proof.OwnerKeyID != item.owner.ID || item.proof.ManifestDigest != manifest.Digest ||
				item.proof.CurrentStatus != "CURRENT" || len(item.proof.SignedProof) == 0 {
				t.Fatal("Owner proof is not bound to its exact source/target manifest side")
			}
			verifyPublicOwnerGrantVector(t, item.proof.SignedProof, item.signedInput, item.signedInputSHA256)
			if _, err := e2ee.VerifyOwnerLinkKeyGrant(item.proof.SignedProof, item.owner,
				item.ownerID, crossOwnerGroupKeyOperation, manifest.Digest,
				manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion), item.side, at); err != nil {
				t.Fatalf("synthetic Owner key proof did not verify: %v", err)
			}
		})
	}
	if vector.EndpointConsent.OwnerKeyID == vector.GroupAdmission.OwnerKeyID ||
		vector.EndpointConsent.SignedProof == nil || vector.GroupAdmission.SignedProof == nil {
		t.Fatal("the two Owner approvals must be distinct public signatures")
	}
	if _, err := e2ee.VerifyOwnerLinkKeyGrant(vector.EndpointConsent.SignedProof,
		vector.GroupOwnerPublic, manifest.EndpointOwnerID, crossOwnerGroupKeyOperation,
		manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, at); err == nil {
		t.Fatal("the Group Owner public key verified the Endpoint Owner signature")
	}
}

func verifyPublicOwnerGrantVector(t *testing.T, wire []byte, signedInputBase64, signedInputSHA256 string) {
	t.Helper()
	var grant e2ee.OwnerLinkKeyGrant
	if err := json.Unmarshal(wire, &grant); err != nil {
		t.Fatal("could not decode public Owner grant")
	}
	claims, err := json.Marshal(struct {
		Version             int                     `json:"version"`
		OwnerID             string                  `json:"owner_id"`
		LinkID              string                  `json:"link_id"`
		ContractDigest      string                  `json:"contract_digest"`
		KeyBindingDigest    string                  `json:"key_binding_digest"`
		ExpectedLinkVersion uint64                  `json:"expected_link_version"`
		Side                e2ee.OwnerLinkGrantSide `json:"side"`
		IssuedAt            string                  `json:"issued_at"`
		ExpiresAt           string                  `json:"expires_at"`
		Nonce               string                  `json:"nonce"`
	}{grant.Version, grant.OwnerID, grant.LinkID, grant.ContractDigest,
		grant.KeyBindingDigest, grant.ExpectedLinkVersion, grant.Side,
		grant.IssuedAt, grant.ExpiresAt, grant.Nonce})
	if err != nil {
		t.Fatal("could not encode public Owner grant claims")
	}
	signed := append([]byte("cicada/communication-link/owner-key-grant/v2\x00"), claims...)
	provided, err := base64.StdEncoding.DecodeString(signedInputBase64)
	digest := sha256.Sum256(signed)
	if err != nil || !bytes.Equal(provided, signed) || hex.EncodeToString(digest[:]) != signedInputSHA256 {
		t.Fatal("published Owner key-grant signed bytes or digest changed")
	}
}
