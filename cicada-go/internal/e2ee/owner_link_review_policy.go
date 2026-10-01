package e2ee

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	OwnerLinkReviewPolicyProofVersion = 1
	ownerLinkReviewPolicyDomain       = "cicada/communication-link/review-policy-owner-approval/v1\x00"
	ownerLinkReviewNonceBytes         = 32
	maxOwnerLinkReviewProofBytes      = 16 * 1024
)

// OwnerLinkReviewPolicyProof is a purpose-separated Owner signature for an
// exact metadata-review policy. It deliberately does not alter the existing
// communication-link grant canonical bytes or authorize message contents.
type OwnerLinkReviewPolicyProof struct {
	Version             int                `json:"version"`
	OwnerID             string             `json:"owner_id"`
	LinkID              string             `json:"link_id"`
	ContractDigest      string             `json:"contract_digest"`
	PolicyDigest        string             `json:"policy_digest"`
	ExpectedLinkVersion uint64             `json:"expected_link_version"`
	PolicyVersion       uint64             `json:"policy_version"`
	Side                OwnerLinkGrantSide `json:"side"`
	IssuedAt            string             `json:"issued_at"`
	ExpiresAt           string             `json:"expires_at"`
	Nonce               string             `json:"nonce"`
	Signature           []byte             `json:"signature"`
}

type ownerLinkReviewPolicyClaims struct {
	Version             int                `json:"version"`
	OwnerID             string             `json:"owner_id"`
	LinkID              string             `json:"link_id"`
	ContractDigest      string             `json:"contract_digest"`
	PolicyDigest        string             `json:"policy_digest"`
	ExpectedLinkVersion uint64             `json:"expected_link_version"`
	PolicyVersion       uint64             `json:"policy_version"`
	Side                OwnerLinkGrantSide `json:"side"`
	IssuedAt            string             `json:"issued_at"`
	ExpiresAt           string             `json:"expires_at"`
	Nonce               string             `json:"nonce"`
}

func (proof OwnerLinkReviewPolicyProof) claims() ownerLinkReviewPolicyClaims {
	return ownerLinkReviewPolicyClaims{
		Version: proof.Version, OwnerID: proof.OwnerID, LinkID: proof.LinkID,
		ContractDigest: proof.ContractDigest, PolicyDigest: proof.PolicyDigest,
		ExpectedLinkVersion: proof.ExpectedLinkVersion, PolicyVersion: proof.PolicyVersion,
		Side: proof.Side, IssuedAt: proof.IssuedAt, ExpiresAt: proof.ExpiresAt,
		Nonce: proof.Nonce,
	}
}

func (proof OwnerLinkReviewPolicyProof) validateClaims() error {
	if proof.Version != OwnerLinkReviewPolicyProofVersion ||
		!canonicalEndpointToken(proof.OwnerID, true) || !canonicalEndpointToken(proof.LinkID, true) ||
		!canonicalSHA256Hex(proof.ContractDigest) || !canonicalSHA256Hex(proof.PolicyDigest) ||
		proof.ExpectedLinkVersion == 0 || proof.PolicyVersion == 0 ||
		!validOwnerLinkGrantSide(proof.Side) || !canonicalSHA256Hex(proof.Nonce) {
		return ErrInvalidEnvelope
	}
	issued, err := parseCanonicalUTC(proof.IssuedAt)
	if err != nil {
		return ErrInvalidEnvelope
	}
	expires, err := parseCanonicalUTC(proof.ExpiresAt)
	if err != nil || !expires.After(issued) {
		return ErrInvalidEnvelope
	}
	return nil
}

func ownerLinkReviewPolicySignedBytes(proof OwnerLinkReviewPolicyProof) ([]byte, error) {
	encoded, err := json.Marshal(proof.claims())
	if err != nil {
		return nil, err
	}
	return append([]byte(ownerLinkReviewPolicyDomain), encoded...), nil
}

// SignOwnerLinkReviewPolicy creates one side's approval for a canonical
// server-computed policy digest. The distinct signing domain preserves every
// existing v1 Owner Link grant byte and meaning.
func (identity *Identity) SignOwnerLinkReviewPolicy(
	ownerID, linkID, contractDigest, policyDigest string,
	expectedLinkVersion, policyVersion uint64,
	side OwnerLinkGrantSide, issuedAt, expiresAt time.Time,
) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil {
		return nil, errors.New("owner review-policy signing identity is unavailable")
	}
	if err := ValidatePublicIdentity(identity.Public()); err != nil {
		return nil, fmt.Errorf("validate owner review-policy signing identity: %w", err)
	}
	proof := OwnerLinkReviewPolicyProof{
		Version: OwnerLinkReviewPolicyProofVersion, OwnerID: ownerID, LinkID: linkID,
		ContractDigest: contractDigest, PolicyDigest: policyDigest,
		ExpectedLinkVersion: expectedLinkVersion, PolicyVersion: policyVersion,
		Side: side, IssuedAt: issuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano),
	}
	nonce := make([]byte, ownerLinkReviewNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate owner review-policy nonce: %w", err)
	}
	proof.Nonce = hex.EncodeToString(nonce)
	if err := proof.validateClaims(); err != nil {
		return nil, fmt.Errorf("invalid owner review-policy proof claims: %w", err)
	}
	signed, err := ownerLinkReviewPolicySignedBytes(proof)
	if err != nil {
		return nil, fmt.Errorf("encode owner review-policy proof claims: %w", err)
	}
	proof.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(identity.signingPrivate, signed, nil, true, proof.Signature); err != nil {
		return nil, fmt.Errorf("sign owner review-policy proof: %w", err)
	}
	wire, err := json.Marshal(proof)
	if err != nil || len(wire) > maxOwnerLinkReviewProofBytes {
		return nil, ErrInvalidEnvelope
	}
	return wire, nil
}

// VerifyOwnerLinkReviewPolicy verifies the exact Link, policy digest, side,
// owner, and version tuple using a separately trusted owner key.
func VerifyOwnerLinkReviewPolicy(
	data []byte, trustedOwner PublicIdentity,
	expectedOwnerID, expectedLinkID, expectedContractDigest, expectedPolicyDigest string,
	expectedLinkVersion, expectedPolicyVersion uint64,
	expectedSide OwnerLinkGrantSide, now time.Time,
) (OwnerLinkReviewPolicyProof, error) {
	if len(data) == 0 || len(data) > maxOwnerLinkReviewProofBytes || now.IsZero() ||
		!canonicalEndpointToken(expectedOwnerID, true) || !canonicalEndpointToken(expectedLinkID, true) ||
		!canonicalSHA256Hex(expectedContractDigest) || !canonicalSHA256Hex(expectedPolicyDigest) ||
		expectedLinkVersion == 0 || expectedPolicyVersion == 0 || !validOwnerLinkGrantSide(expectedSide) {
		return OwnerLinkReviewPolicyProof{}, ErrInvalidEnvelope
	}
	if err := ValidatePublicIdentity(trustedOwner); err != nil {
		return OwnerLinkReviewPolicyProof{}, fmt.Errorf("validate trusted owner review-policy identity: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var proof OwnerLinkReviewPolicyProof
	if err := decoder.Decode(&proof); err != nil {
		return OwnerLinkReviewPolicyProof{}, fmt.Errorf("decode owner review-policy proof: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return OwnerLinkReviewPolicyProof{}, ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(data, canonical) {
		return OwnerLinkReviewPolicyProof{}, errors.New("owner review-policy proof is not canonical JSON")
	}
	if err := proof.validateClaims(); err != nil || len(proof.Signature) != mldsa65.SignatureSize {
		return OwnerLinkReviewPolicyProof{}, ErrInvalidEnvelope
	}
	if proof.OwnerID != expectedOwnerID || proof.LinkID != expectedLinkID ||
		proof.ContractDigest != expectedContractDigest || proof.PolicyDigest != expectedPolicyDigest ||
		proof.ExpectedLinkVersion != expectedLinkVersion || proof.PolicyVersion != expectedPolicyVersion ||
		proof.Side != expectedSide {
		return OwnerLinkReviewPolicyProof{}, errors.New("owner review-policy proof does not match expected contract")
	}
	issuedAt, _ := parseCanonicalUTC(proof.IssuedAt)
	expiresAt, _ := parseCanonicalUTC(proof.ExpiresAt)
	if issuedAt.After(now) || !now.Before(expiresAt) {
		return OwnerLinkReviewPolicyProof{}, errors.New("owner review-policy proof is not currently valid")
	}
	_, signingPublic, err := validatePublic(trustedOwner)
	if err != nil {
		return OwnerLinkReviewPolicyProof{}, err
	}
	signed, err := ownerLinkReviewPolicySignedBytes(proof)
	if err != nil || !mldsa65.Verify(signingPublic, signed, nil, proof.Signature) {
		return OwnerLinkReviewPolicyProof{}, errors.New("owner review-policy signature is invalid")
	}
	return proof, nil
}
