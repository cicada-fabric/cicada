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
	OwnerLinkGrantVersion    = 1
	ownerLinkGrantDomain     = "cicada/communication-link/owner-grant/v1\x00"
	ownerLinkGrantNonceBytes = 32
	maxOwnerLinkGrantBytes   = 16 * 1024
)

// OwnerLinkGrantSide names the one CommunicationLink side authorized by a
// grant. SOURCE and TARGET approvals are separate signatures.
type OwnerLinkGrantSide string

const (
	OwnerLinkGrantSideSource OwnerLinkGrantSide = "SOURCE"
	OwnerLinkGrantSideTarget OwnerLinkGrantSide = "TARGET"
)

// OwnerLinkGrant is a signed approval for one precise, versioned link contract.
// It intentionally has no actions or data-scope fields: those are committed by
// ContractDigest, which the Hub derives from the canonical trusted contract.
// The request body must never supply the contract fields used to derive it.
// Nonce is 32 bytes of CSPRNG output encoded as lower-case hex; stores should
// atomically record it as the replay identifier when accepting the grant.
type OwnerLinkGrant struct {
	Version             int                `json:"version"`
	OwnerID             string             `json:"owner_id"`
	LinkID              string             `json:"link_id"`
	ContractDigest      string             `json:"contract_digest"`
	ExpectedLinkVersion uint64             `json:"expected_link_version"`
	Side                OwnerLinkGrantSide `json:"side"`
	IssuedAt            string             `json:"issued_at"`
	ExpiresAt           string             `json:"expires_at"`
	Nonce               string             `json:"nonce"`
	Signature           []byte             `json:"signature"`
}

type ownerLinkGrantClaims struct {
	Version             int                `json:"version"`
	OwnerID             string             `json:"owner_id"`
	LinkID              string             `json:"link_id"`
	ContractDigest      string             `json:"contract_digest"`
	ExpectedLinkVersion uint64             `json:"expected_link_version"`
	Side                OwnerLinkGrantSide `json:"side"`
	IssuedAt            string             `json:"issued_at"`
	ExpiresAt           string             `json:"expires_at"`
	Nonce               string             `json:"nonce"`
}

func (grant OwnerLinkGrant) claims() ownerLinkGrantClaims {
	return ownerLinkGrantClaims{
		Version: grant.Version, OwnerID: grant.OwnerID, LinkID: grant.LinkID,
		ContractDigest: grant.ContractDigest, ExpectedLinkVersion: grant.ExpectedLinkVersion,
		Side: grant.Side, IssuedAt: grant.IssuedAt, ExpiresAt: grant.ExpiresAt, Nonce: grant.Nonce,
	}
}

func (grant OwnerLinkGrant) validateClaims() (time.Time, time.Time, error) {
	if grant.Version != OwnerLinkGrantVersion ||
		!canonicalEndpointToken(grant.OwnerID, true) ||
		!canonicalEndpointToken(grant.LinkID, true) ||
		!canonicalSHA256Hex(grant.ContractDigest) || grant.ExpectedLinkVersion == 0 ||
		!validOwnerLinkGrantSide(grant.Side) || !canonicalSHA256Hex(grant.Nonce) {
		return time.Time{}, time.Time{}, ErrInvalidEnvelope
	}
	issuedAt, err := parseCanonicalUTC(grant.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, ErrInvalidEnvelope
	}
	expiresAt, err := parseCanonicalUTC(grant.ExpiresAt)
	if err != nil || !expiresAt.After(issuedAt) {
		return time.Time{}, time.Time{}, ErrInvalidEnvelope
	}
	return issuedAt, expiresAt, nil
}

func validOwnerLinkGrantSide(side OwnerLinkGrantSide) bool {
	return side == OwnerLinkGrantSideSource || side == OwnerLinkGrantSideTarget
}

func canonicalSHA256Hex(value string) bool {
	if len(value) != 2*32 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func parseCanonicalUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("timestamp is not canonical UTC RFC3339")
	}
	return parsed, nil
}

func ownerLinkGrantSignedBytes(grant OwnerLinkGrant) ([]byte, error) {
	encoded, err := json.Marshal(grant.claims())
	if err != nil {
		return nil, err
	}
	return append([]byte(ownerLinkGrantDomain), encoded...), nil
}

// SignOwnerLinkGrant creates one side's approval. The Client must use a
// separately provisioned owner-grant Identity that it independently holds;
// never reuse or implicitly fall back to an Endpoint Identity. Before accepting
// grants, the Hub must authenticate enrollment and register the corresponding
// public identity as trusted for ownerID. issuedAt and expiresAt are serialized
// as canonical UTC RFC3339Nano timestamps. contractDigest must be computed by
// trusted code from the exact canonical link contract, including its actions
// and scope, rather than copied from an untrusted request body.
func (identity *Identity) SignOwnerLinkGrant(
	ownerID, linkID, contractDigest string,
	expectedLinkVersion uint64,
	side OwnerLinkGrantSide,
	issuedAt, expiresAt time.Time,
) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil {
		return nil, errors.New("owner-grant signing identity is unavailable")
	}
	if _, _, err := validatePublic(identity.Public()); err != nil {
		return nil, fmt.Errorf("validate owner-grant signing identity: %w", err)
	}
	grant := OwnerLinkGrant{
		Version: OwnerLinkGrantVersion, OwnerID: ownerID, LinkID: linkID,
		ContractDigest: contractDigest, ExpectedLinkVersion: expectedLinkVersion,
		Side: side, IssuedAt: issuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano),
	}
	nonce := make([]byte, ownerLinkGrantNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate owner-grant nonce: %w", err)
	}
	grant.Nonce = hex.EncodeToString(nonce)
	if _, _, err := grant.validateClaims(); err != nil {
		return nil, fmt.Errorf("invalid owner-link grant claims: %w", err)
	}
	signed, err := ownerLinkGrantSignedBytes(grant)
	if err != nil {
		return nil, fmt.Errorf("encode owner-link grant claims: %w", err)
	}
	grant.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(identity.signingPrivate, signed, nil, true, grant.Signature); err != nil {
		return nil, fmt.Errorf("sign owner-link grant: %w", err)
	}
	wire, err := json.Marshal(grant)
	if err != nil {
		return nil, fmt.Errorf("encode owner-link grant: %w", err)
	}
	if len(wire) > maxOwnerLinkGrantBytes {
		return nil, ErrInvalidEnvelope
	}
	return wire, nil
}

// VerifyOwnerLinkGrant verifies against the caller's trusted owner public
// identity and server-derived expected contract claims. expectedContractDigest
// must come from the canonical current contract, not the grant request body.
// now must come from a trusted clock. A successful result exposes Nonce so the
// caller can atomically reject its reuse in durable storage; this function is
// intentionally stateless and does not claim to prevent replay on its own.
func VerifyOwnerLinkGrant(
	data []byte,
	trustedOwner PublicIdentity,
	expectedOwnerID, expectedLinkID, expectedContractDigest string,
	expectedLinkVersion uint64,
	expectedSide OwnerLinkGrantSide,
	now time.Time,
) (OwnerLinkGrant, error) {
	if len(data) == 0 || len(data) > maxOwnerLinkGrantBytes || now.IsZero() ||
		!canonicalEndpointToken(expectedOwnerID, true) ||
		!canonicalEndpointToken(expectedLinkID, true) ||
		!canonicalSHA256Hex(expectedContractDigest) || expectedLinkVersion == 0 ||
		!validOwnerLinkGrantSide(expectedSide) {
		return OwnerLinkGrant{}, ErrInvalidEnvelope
	}
	if err := ValidatePublicIdentity(trustedOwner); err != nil {
		return OwnerLinkGrant{}, fmt.Errorf("validate trusted owner identity: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var grant OwnerLinkGrant
	if err := decoder.Decode(&grant); err != nil {
		return OwnerLinkGrant{}, fmt.Errorf("decode owner-link grant: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return OwnerLinkGrant{}, ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(grant)
	if err != nil || !bytes.Equal(data, canonical) {
		return OwnerLinkGrant{}, errors.New("owner-link grant is not canonical JSON")
	}
	issuedAt, expiresAt, err := grant.validateClaims()
	if err != nil || len(grant.Signature) != mldsa65.SignatureSize {
		return OwnerLinkGrant{}, ErrInvalidEnvelope
	}
	if grant.OwnerID != expectedOwnerID || grant.LinkID != expectedLinkID ||
		grant.ContractDigest != expectedContractDigest ||
		grant.ExpectedLinkVersion != expectedLinkVersion || grant.Side != expectedSide {
		return OwnerLinkGrant{}, errors.New("owner-link grant does not match expected contract side")
	}
	if issuedAt.After(now) {
		return OwnerLinkGrant{}, errors.New("owner-link grant issuance is in the future")
	}
	if !now.Before(expiresAt) {
		return OwnerLinkGrant{}, errors.New("owner-link grant has expired")
	}
	_, signingPublic, err := validatePublic(trustedOwner)
	if err != nil {
		return OwnerLinkGrant{}, fmt.Errorf("validate trusted owner signing key: %w", err)
	}
	signed, err := ownerLinkGrantSignedBytes(grant)
	if err != nil || !mldsa65.Verify(signingPublic, signed, nil, grant.Signature) {
		return OwnerLinkGrant{}, errors.New("owner-link grant signature verification failed")
	}
	return grant, nil
}
