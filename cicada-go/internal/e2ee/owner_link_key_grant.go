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
	OwnerLinkKeyGrantVersion = 2
	ownerLinkKeyGrantDomain  = "cicada/communication-link/owner-key-grant/v2\x00"
)

// OwnerLinkKeyGrant approves one current Link contract AND the exact pair of
// Endpoint public-key candidates. Version 1 grants cannot establish key trust.
// The manifest digest must be computed from trusted current Store records;
// the caller cannot supply candidate fingerprints as authority.
type OwnerLinkKeyGrant struct {
	Version             int                `json:"version"`
	OwnerID             string             `json:"owner_id"`
	LinkID              string             `json:"link_id"`
	ContractDigest      string             `json:"contract_digest"`
	KeyBindingDigest    string             `json:"key_binding_digest"`
	ExpectedLinkVersion uint64             `json:"expected_link_version"`
	Side                OwnerLinkGrantSide `json:"side"`
	IssuedAt            string             `json:"issued_at"`
	ExpiresAt           string             `json:"expires_at"`
	Nonce               string             `json:"nonce"`
	Signature           []byte             `json:"signature"`
}

type ownerLinkKeyGrantClaims struct {
	Version             int                `json:"version"`
	OwnerID             string             `json:"owner_id"`
	LinkID              string             `json:"link_id"`
	ContractDigest      string             `json:"contract_digest"`
	KeyBindingDigest    string             `json:"key_binding_digest"`
	ExpectedLinkVersion uint64             `json:"expected_link_version"`
	Side                OwnerLinkGrantSide `json:"side"`
	IssuedAt            string             `json:"issued_at"`
	ExpiresAt           string             `json:"expires_at"`
	Nonce               string             `json:"nonce"`
}

func (grant OwnerLinkKeyGrant) claims() ownerLinkKeyGrantClaims {
	return ownerLinkKeyGrantClaims{
		Version: grant.Version, OwnerID: grant.OwnerID, LinkID: grant.LinkID,
		ContractDigest: grant.ContractDigest, KeyBindingDigest: grant.KeyBindingDigest,
		ExpectedLinkVersion: grant.ExpectedLinkVersion, Side: grant.Side,
		IssuedAt: grant.IssuedAt, ExpiresAt: grant.ExpiresAt, Nonce: grant.Nonce,
	}
}

func (grant OwnerLinkKeyGrant) validateClaims() (time.Time, time.Time, error) {
	if grant.Version != OwnerLinkKeyGrantVersion ||
		!canonicalEndpointToken(grant.OwnerID, true) ||
		!canonicalEndpointToken(grant.LinkID, true) ||
		!canonicalSHA256Hex(grant.ContractDigest) ||
		!canonicalSHA256Hex(grant.KeyBindingDigest) ||
		grant.ExpectedLinkVersion == 0 || !validOwnerLinkGrantSide(grant.Side) ||
		!canonicalSHA256Hex(grant.Nonce) {
		return time.Time{}, time.Time{}, ErrInvalidEnvelope
	}
	issued, err := parseCanonicalUTC(grant.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, ErrInvalidEnvelope
	}
	expires, err := parseCanonicalUTC(grant.ExpiresAt)
	if err != nil || !expires.After(issued) {
		return time.Time{}, time.Time{}, ErrInvalidEnvelope
	}
	return issued, expires, nil
}

func ownerLinkKeyGrantSignedBytes(grant OwnerLinkKeyGrant) ([]byte, error) {
	encoded, err := json.Marshal(grant.claims())
	if err != nil {
		return nil, err
	}
	return append([]byte(ownerLinkKeyGrantDomain), encoded...), nil
}

// SignOwnerLinkKeyGrant signs one side's key-bound consent with an independently
// trusted owner signing identity. The owner must inspect the trusted manifest
// before signing its digest.
func (identity *Identity) SignOwnerLinkKeyGrant(ownerID, linkID, contractDigest,
	keyBindingDigest string, linkVersion uint64, side OwnerLinkGrantSide,
	issuedAt, expiresAt time.Time) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil {
		return nil, errors.New("owner key-grant signing identity is unavailable")
	}
	if err := ValidatePublicIdentity(identity.Public()); err != nil {
		return nil, fmt.Errorf("validate owner signing identity: %w", err)
	}
	grant := OwnerLinkKeyGrant{
		Version: OwnerLinkKeyGrantVersion, OwnerID: ownerID, LinkID: linkID,
		ContractDigest: contractDigest, KeyBindingDigest: keyBindingDigest,
		ExpectedLinkVersion: linkVersion, Side: side,
		IssuedAt:  issuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano),
	}
	nonce := make([]byte, ownerLinkGrantNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate owner key-grant nonce: %w", err)
	}
	grant.Nonce = hex.EncodeToString(nonce)
	if _, _, err := grant.validateClaims(); err != nil {
		return nil, fmt.Errorf("invalid owner key-grant claims: %w", err)
	}
	signed, err := ownerLinkKeyGrantSignedBytes(grant)
	if err != nil {
		return nil, err
	}
	grant.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(identity.signingPrivate, signed, nil, true, grant.Signature); err != nil {
		return nil, fmt.Errorf("sign owner key grant: %w", err)
	}
	wire, err := json.Marshal(grant)
	if err != nil || len(wire) > maxOwnerLinkGrantBytes {
		return nil, ErrInvalidEnvelope
	}
	return wire, nil
}

// VerifyOwnerLinkKeyGrant binds a trusted owner signature to a server-derived
// current contract and key manifest. Nonce replay prevention remains a Store
// transaction responsibility.
func VerifyOwnerLinkKeyGrant(data []byte, trustedOwner PublicIdentity,
	expectedOwnerID, expectedLinkID, expectedContractDigest,
	expectedKeyBindingDigest string, expectedLinkVersion uint64,
	expectedSide OwnerLinkGrantSide, now time.Time) (OwnerLinkKeyGrant, error) {
	if len(data) == 0 || len(data) > maxOwnerLinkGrantBytes || now.IsZero() ||
		!canonicalEndpointToken(expectedOwnerID, true) ||
		!canonicalEndpointToken(expectedLinkID, true) ||
		!canonicalSHA256Hex(expectedContractDigest) ||
		!canonicalSHA256Hex(expectedKeyBindingDigest) || expectedLinkVersion == 0 ||
		!validOwnerLinkGrantSide(expectedSide) {
		return OwnerLinkKeyGrant{}, ErrInvalidEnvelope
	}
	if err := ValidatePublicIdentity(trustedOwner); err != nil {
		return OwnerLinkKeyGrant{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var grant OwnerLinkKeyGrant
	if err := decoder.Decode(&grant); err != nil {
		return OwnerLinkKeyGrant{}, fmt.Errorf("decode owner key grant: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return OwnerLinkKeyGrant{}, ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(grant)
	if err != nil || !bytes.Equal(data, canonical) {
		return OwnerLinkKeyGrant{}, errors.New("owner key grant is not canonical JSON")
	}
	issued, expires, err := grant.validateClaims()
	if err != nil || len(grant.Signature) != mldsa65.SignatureSize {
		return OwnerLinkKeyGrant{}, ErrInvalidEnvelope
	}
	if grant.OwnerID != expectedOwnerID || grant.LinkID != expectedLinkID ||
		grant.ContractDigest != expectedContractDigest ||
		grant.KeyBindingDigest != expectedKeyBindingDigest ||
		grant.ExpectedLinkVersion != expectedLinkVersion || grant.Side != expectedSide {
		return OwnerLinkKeyGrant{}, errors.New("owner key grant does not match current link and key manifest")
	}
	if issued.After(now) || !now.Before(expires) {
		return OwnerLinkKeyGrant{}, errors.New("owner key grant is outside its validity period")
	}
	_, signingPublic, err := validatePublic(trustedOwner)
	if err != nil {
		return OwnerLinkKeyGrant{}, err
	}
	signed, err := ownerLinkKeyGrantSignedBytes(grant)
	if err != nil || !mldsa65.Verify(signingPublic, signed, nil, grant.Signature) {
		return OwnerLinkKeyGrant{}, errors.New("owner key grant signature verification failed")
	}
	return grant, nil
}
