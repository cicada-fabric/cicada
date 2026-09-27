package e2ee

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	OwnerDeviceGrantVersion    = 1
	OwnerDevicePurposeControl  = "CLIENT_CONTROL"
	ownerDeviceGrantDomain     = "cicada/client/owner-device-grant/v1\x00"
	ownerDeviceGrantNonceBytes = 32
	maxOwnerDeviceGrantBytes   = 16 * 1024
)

// OwnerDeviceGrant is an owner's approval of one exact Client device key at
// one Hub. The device's self-signature is not part of the trust decision.
// Nonce must be consumed by durable storage when the grant is accepted.
type OwnerDeviceGrant struct {
	Version              int    `json:"version"`
	OwnerID              string `json:"owner_id"`
	OwnerKeyID           string `json:"owner_key_id"`
	DeviceID             string `json:"device_id"`
	DeviceKeyID          string `json:"device_key_id"`
	DeviceKeyFingerprint string `json:"device_key_fingerprint"`
	HubID                string `json:"hub_id"`
	Purpose              string `json:"purpose"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
	Nonce                string `json:"nonce"`
	Signature            []byte `json:"signature"`
}

type ownerDeviceGrantClaims struct {
	Version              int    `json:"version"`
	OwnerID              string `json:"owner_id"`
	OwnerKeyID           string `json:"owner_key_id"`
	DeviceID             string `json:"device_id"`
	DeviceKeyID          string `json:"device_key_id"`
	DeviceKeyFingerprint string `json:"device_key_fingerprint"`
	HubID                string `json:"hub_id"`
	Purpose              string `json:"purpose"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
	Nonce                string `json:"nonce"`
}

func (grant OwnerDeviceGrant) claims() ownerDeviceGrantClaims {
	return ownerDeviceGrantClaims{
		Version: grant.Version, OwnerID: grant.OwnerID, OwnerKeyID: grant.OwnerKeyID,
		DeviceID: grant.DeviceID, DeviceKeyID: grant.DeviceKeyID,
		DeviceKeyFingerprint: grant.DeviceKeyFingerprint, HubID: grant.HubID,
		Purpose: grant.Purpose, IssuedAt: grant.IssuedAt, ExpiresAt: grant.ExpiresAt,
		Nonce: grant.Nonce,
	}
}

// OwnerDevicePublicKeyFingerprint returns a full SHA-256 fingerprint over the
// canonical public identity, including its KEM and signing key bytes.
func OwnerDevicePublicKeyFingerprint(public PublicIdentity) (string, error) {
	if err := ValidatePublicIdentity(public); err != nil {
		return "", fmt.Errorf("validate device public identity: %w", err)
	}
	canonical, err := json.Marshal(public)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(append([]byte("cicada/client/device-public-key/v1\x00"), canonical...))
	return hex.EncodeToString(hash[:]), nil
}

func (grant OwnerDeviceGrant) validateClaims() (time.Time, time.Time, error) {
	if grant.Version != OwnerDeviceGrantVersion ||
		!canonicalEndpointToken(grant.OwnerID, true) ||
		!canonicalEndpointToken(grant.OwnerKeyID, true) ||
		!canonicalEndpointToken(grant.DeviceID, true) ||
		!canonicalEndpointToken(grant.DeviceKeyID, true) ||
		!canonicalSHA256Hex(grant.DeviceKeyFingerprint) ||
		!canonicalEndpointToken(grant.HubID, true) ||
		grant.Purpose != OwnerDevicePurposeControl || !canonicalSHA256Hex(grant.Nonce) {
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

func ownerDeviceGrantSignedBytes(grant OwnerDeviceGrant) ([]byte, error) {
	encoded, err := json.Marshal(grant.claims())
	if err != nil {
		return nil, err
	}
	return append([]byte(ownerDeviceGrantDomain), encoded...), nil
}

// SignOwnerDeviceGrant creates a precise device enrollment proof using this
// owner's ML-DSA key. Hub ID must be obtained from the Hub's trusted local
// configuration and passed to the signer out of band; it must not come from a
// packet being authorized.
func (identity *Identity) SignOwnerDeviceGrant(
	ownerID, deviceID string,
	devicePublic PublicIdentity,
	hubID, purpose string,
	issuedAt, expiresAt time.Time,
) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil {
		return nil, errors.New("owner device-grant signing identity is unavailable")
	}
	if err := ValidatePublicIdentity(identity.Public()); err != nil {
		return nil, fmt.Errorf("validate owner device-grant signer: %w", err)
	}
	fingerprint, err := OwnerDevicePublicKeyFingerprint(devicePublic)
	if err != nil {
		return nil, err
	}
	grant := OwnerDeviceGrant{
		Version:              OwnerDeviceGrantVersion,
		OwnerID:              ownerID,
		OwnerKeyID:           identity.Public().ID,
		DeviceID:             deviceID,
		DeviceKeyID:          devicePublic.ID,
		DeviceKeyFingerprint: fingerprint,
		HubID:                hubID,
		Purpose:              purpose,
		IssuedAt:             issuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:            expiresAt.UTC().Format(time.RFC3339Nano),
	}
	nonce := make([]byte, ownerDeviceGrantNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate owner device-grant nonce: %w", err)
	}
	grant.Nonce = hex.EncodeToString(nonce)
	if _, _, err := grant.validateClaims(); err != nil {
		return nil, fmt.Errorf("invalid owner device-grant claims: %w", err)
	}
	signed, err := ownerDeviceGrantSignedBytes(grant)
	if err != nil {
		return nil, fmt.Errorf("encode owner device-grant claims: %w", err)
	}
	grant.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(identity.signingPrivate, signed, nil, true, grant.Signature); err != nil {
		return nil, fmt.Errorf("sign owner device grant: %w", err)
	}
	wire, err := json.Marshal(grant)
	if err != nil {
		return nil, fmt.Errorf("encode owner device grant: %w", err)
	}
	if len(wire) > maxOwnerDeviceGrantBytes {
		return nil, ErrInvalidEnvelope
	}
	return wire, nil
}

// VerifyOwnerDeviceGrant verifies a canonical grant against a locally trusted
// owner key and caller-supplied trusted scope. The caller must consume Nonce in
// durable state; this function alone does not prevent replay.
func VerifyOwnerDeviceGrant(
	data []byte,
	trustedOwner PublicIdentity,
	devicePublic PublicIdentity,
	expectedOwnerID, expectedOwnerKeyID, expectedDeviceID, expectedHubID, expectedPurpose string,
	now time.Time,
) (OwnerDeviceGrant, error) {
	if len(data) == 0 || len(data) > maxOwnerDeviceGrantBytes || now.IsZero() ||
		!canonicalEndpointToken(expectedOwnerID, true) ||
		!canonicalEndpointToken(expectedOwnerKeyID, true) ||
		!canonicalEndpointToken(expectedDeviceID, true) ||
		!canonicalEndpointToken(expectedHubID, true) ||
		expectedPurpose != OwnerDevicePurposeControl {
		return OwnerDeviceGrant{}, ErrInvalidEnvelope
	}
	if err := ValidatePublicIdentity(trustedOwner); err != nil {
		return OwnerDeviceGrant{}, fmt.Errorf("validate trusted owner identity: %w", err)
	}
	fingerprint, err := OwnerDevicePublicKeyFingerprint(devicePublic)
	if err != nil {
		return OwnerDeviceGrant{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var grant OwnerDeviceGrant
	if err := decoder.Decode(&grant); err != nil {
		return OwnerDeviceGrant{}, fmt.Errorf("decode owner device grant: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return OwnerDeviceGrant{}, ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(grant)
	if err != nil || !bytes.Equal(data, canonical) {
		return OwnerDeviceGrant{}, errors.New("owner device grant is not canonical JSON")
	}
	issuedAt, expiresAt, err := grant.validateClaims()
	if err != nil || len(grant.Signature) != mldsa65.SignatureSize {
		return OwnerDeviceGrant{}, ErrInvalidEnvelope
	}
	if grant.OwnerID != expectedOwnerID || grant.OwnerKeyID != expectedOwnerKeyID ||
		grant.DeviceID != expectedDeviceID || grant.DeviceKeyID != devicePublic.ID ||
		grant.DeviceKeyFingerprint != fingerprint || grant.HubID != expectedHubID ||
		grant.Purpose != expectedPurpose {
		return OwnerDeviceGrant{}, errors.New("owner device grant does not match expected enrollment")
	}
	if issuedAt.After(now) {
		return OwnerDeviceGrant{}, errors.New("owner device grant issuance is in the future")
	}
	if !now.Before(expiresAt) {
		return OwnerDeviceGrant{}, errors.New("owner device grant has expired")
	}
	_, signingPublic, err := validatePublic(trustedOwner)
	if err != nil {
		return OwnerDeviceGrant{}, fmt.Errorf("validate trusted owner signing key: %w", err)
	}
	if expectedOwnerKeyID != trustedOwner.ID {
		return OwnerDeviceGrant{}, errors.New("owner device grant key ID does not match trusted key")
	}
	signed, err := ownerDeviceGrantSignedBytes(grant)
	if err != nil || !mldsa65.Verify(signingPublic, signed, nil, grant.Signature) {
		return OwnerDeviceGrant{}, errors.New("owner device grant signature verification failed")
	}
	return grant, nil
}
