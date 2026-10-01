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
	networkCollaborationKeyGrantDomain   = "cicada/network/collaboration-key-grant/v1\x00"
	networkCollaborationManifestDomain   = "cicada/network/collaboration-key-manifest/v1\x00"
	NetworkCollaborationPurposeTask      = "TASK"
	NetworkCollaborationPurposeBroadcast = "BROADCAST"
	networkCollaborationAADDomain        = "cicada/network/collaboration-aad/v1\x00"
	networkCollaborationEnvelopeDomain   = "cicada/network/collaboration-envelope/v1\x00"
)

// NetworkCollaborationManifestDigest purpose-binds the canonical current key
// manifest while leaving NetworkDirectManifestDigest and its v1 bytes intact.
func NetworkCollaborationManifestDigest(purpose string, canonicalKeyManifest []byte) string {
	sum := sha256.Sum256(append([]byte(networkCollaborationManifestDomain+purpose+"\x00"), canonicalKeyManifest...))
	return hex.EncodeToString(sum[:])
}

// OwnerNetworkCollaborationKeyGrant is a new, purpose-specific Owner consent.
// It deliberately does not alias or extend NetworkDirect's v1 signature.
type OwnerNetworkCollaborationKeyGrant struct {
	Version        int    `json:"version"`
	Purpose        string `json:"purpose"`
	HubID          string `json:"hub_id"`
	NetworkID      string `json:"network_id"`
	EndpointID     string `json:"endpoint_id"`
	OwnerID        string `json:"owner_id"`
	OwnerKeyID     string `json:"owner_key_id"`
	ManifestDigest string `json:"manifest_digest"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at"`
	Nonce          string `json:"nonce"`
	Signature      []byte `json:"signature"`
}

func (grant OwnerNetworkCollaborationKeyGrant) claims() OwnerNetworkCollaborationKeyGrant {
	grant.Signature = nil
	return grant
}

func (grant OwnerNetworkCollaborationKeyGrant) signedBytes() ([]byte, error) {
	encoded, err := json.Marshal(grant.claims())
	if err != nil {
		return nil, err
	}
	return append([]byte(networkCollaborationKeyGrantDomain), encoded...), nil
}

func (grant OwnerNetworkCollaborationKeyGrant) valid() bool {
	if grant.Version != 1 || (grant.Purpose != NetworkCollaborationPurposeTask &&
		grant.Purpose != NetworkCollaborationPurposeBroadcast) ||
		!canonicalSHA256Hex(grant.ManifestDigest) || !canonicalSHA256Hex(grant.Nonce) {
		return false
	}
	for _, value := range []string{grant.HubID, grant.NetworkID, grant.EndpointID,
		grant.OwnerID, grant.OwnerKeyID} {
		if !canonicalEndpointToken(value, true) {
			return false
		}
	}
	return true
}

func (identity *Identity) SignOwnerNetworkCollaborationKeyGrant(purpose, hubID, networkID,
	endpointID, ownerID, manifestDigest string, issuedAt, expiresAt time.Time) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil || !expiresAt.After(issuedAt) {
		return nil, ErrInvalidEnvelope
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	grant := OwnerNetworkCollaborationKeyGrant{Version: 1, Purpose: purpose,
		HubID: hubID, NetworkID: networkID, EndpointID: endpointID, OwnerID: ownerID,
		OwnerKeyID: identity.Public().ID, ManifestDigest: manifestDigest,
		IssuedAt:  issuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano), Nonce: hex.EncodeToString(nonce)}
	if !grant.valid() {
		return nil, ErrInvalidEnvelope
	}
	signed, err := grant.signedBytes()
	if err != nil {
		return nil, err
	}
	grant.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(identity.signingPrivate, signed, nil, true, grant.Signature); err != nil {
		return nil, err
	}
	return json.Marshal(grant)
}

func VerifyOwnerNetworkCollaborationKeyGrant(data []byte, trustedOwner PublicIdentity,
	expected OwnerNetworkCollaborationKeyGrant, at time.Time) (OwnerNetworkCollaborationKeyGrant, error) {
	if len(data) == 0 || len(data) > maxNetworkDirectProofBytes || at.IsZero() {
		return OwnerNetworkCollaborationKeyGrant{}, ErrInvalidEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var grant OwnerNetworkCollaborationKeyGrant
	if err := decoder.Decode(&grant); err != nil {
		return OwnerNetworkCollaborationKeyGrant{}, err
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || !grant.valid() ||
		len(grant.Signature) != mldsa65.SignatureSize || grant.Purpose != expected.Purpose ||
		grant.HubID != expected.HubID || grant.NetworkID != expected.NetworkID ||
		grant.EndpointID != expected.EndpointID || grant.OwnerID != expected.OwnerID ||
		grant.OwnerKeyID != trustedOwner.ID || grant.ManifestDigest != expected.ManifestDigest {
		return OwnerNetworkCollaborationKeyGrant{}, ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(grant)
	if err != nil || !bytes.Equal(data, canonical) {
		return OwnerNetworkCollaborationKeyGrant{}, ErrInvalidEnvelope
	}
	issued, err := parseCanonicalUTC(grant.IssuedAt)
	if err != nil || issued.After(at) {
		return OwnerNetworkCollaborationKeyGrant{}, ErrInvalidEnvelope
	}
	expires, err := parseCanonicalUTC(grant.ExpiresAt)
	if err != nil || !at.Before(expires) || !expires.After(issued) {
		return OwnerNetworkCollaborationKeyGrant{}, ErrInvalidEnvelope
	}
	_, public, err := validatePublic(trustedOwner)
	if err != nil {
		return OwnerNetworkCollaborationKeyGrant{}, err
	}
	signed, err := grant.signedBytes()
	if err != nil || !mldsa65.Verify(public, signed, nil, grant.Signature) {
		return OwnerNetworkCollaborationKeyGrant{}, ErrInvalidEnvelope
	}
	return grant, nil
}

// NetworkCollaborationMessageContext is separate from NetworkDirectContext so
// direct v1 canonical envelope/AAD bytes remain unchanged. Collaboration
// ciphertexts sign and seal the exact TASK or BROADCAST purpose.
type NetworkCollaborationMessageContext struct {
	Purpose string               `json:"purpose"`
	Route   NetworkDirectContext `json:"route"`
}

func (context NetworkCollaborationMessageContext) validate() error {
	if context.Purpose != NetworkCollaborationPurposeTask && context.Purpose != NetworkCollaborationPurposeBroadcast {
		return ErrInvalidEnvelope
	}
	if context.Route.Kind != "SEND" || context.Route.RequestID != "" || context.Route.ReplyTo != "" {
		return ErrInvalidEnvelope
	}
	return context.Route.validate()
}

type NetworkCollaborationEnvelope struct {
	Version   int                                `json:"version"`
	Suite     string                             `json:"suite"`
	Context   NetworkCollaborationMessageContext `json:"context"`
	Sealed    json.RawMessage                    `json:"sealed"`
	Signature []byte                             `json:"signature"`
}

func networkCollaborationAAD(context NetworkCollaborationMessageContext) ([]byte, error) {
	if err := context.validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(context)
	if err != nil {
		return nil, err
	}
	return append([]byte(networkCollaborationAADDomain), encoded...), nil
}

func networkCollaborationSignedBytes(envelope NetworkCollaborationEnvelope) ([]byte, error) {
	envelope.Signature = nil
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return append([]byte(networkCollaborationEnvelopeDomain), encoded...), nil
}

func SealNetworkCollaborationMessage(sender *Identity, receiver PublicIdentity,
	context NetworkCollaborationMessageContext, plaintext []byte, sequence uint64) ([]byte, error) {
	if sender == nil || sequence == 0 || len(plaintext) == 0 || len(plaintext) > maxEndpointPlaintext ||
		context.Route.SenderKeyID != sender.Public().ID || context.Route.ReceiverKeyID != receiver.ID {
		return nil, ErrInvalidEnvelope
	}
	aad, err := networkCollaborationAAD(context)
	if err != nil {
		return nil, err
	}
	sealed, err := Seal(sender, receiver, plaintext, aad, sequence)
	if err != nil {
		return nil, err
	}
	envelope := NetworkCollaborationEnvelope{Version: 1, Suite: Algorithm, Context: context, Sealed: json.RawMessage(sealed)}
	signed, err := networkCollaborationSignedBytes(envelope)
	if err != nil {
		return nil, err
	}
	envelope.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sender.signingPrivate, signed, nil, true, envelope.Signature); err != nil {
		return nil, fmt.Errorf("sign Network collaboration ciphertext: %w", err)
	}
	wire, err := json.Marshal(envelope)
	if err != nil || len(wire) > maxEndpointWire {
		return nil, ErrInvalidEnvelope
	}
	return wire, nil
}

func VerifyNetworkCollaborationMessage(expectedSender PublicIdentity,
	context NetworkCollaborationMessageContext, wire []byte) error {
	_, _, err := openNetworkCollaborationMessage(nil, expectedSender, context, wire, false)
	return err
}

func OpenNetworkCollaborationMessage(receiver *Identity, expectedSender PublicIdentity,
	context NetworkCollaborationMessageContext, wire []byte) ([]byte, uint64, error) {
	return openNetworkCollaborationMessage(receiver, expectedSender, context, wire, true)
}

func openNetworkCollaborationMessage(receiver *Identity, expectedSender PublicIdentity,
	context NetworkCollaborationMessageContext, wire []byte, openBody bool) ([]byte, uint64, error) {
	if len(wire) == 0 || len(wire) > maxEndpointWire || context.Route.SenderKeyID != expectedSender.ID ||
		(openBody && (receiver == nil || context.Route.ReceiverKeyID != receiver.Public().ID)) {
		return nil, 0, ErrInvalidEnvelope
	}
	aad, err := networkCollaborationAAD(context)
	if err != nil {
		return nil, 0, err
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var envelope NetworkCollaborationEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, 0, err
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || envelope.Version != 1 ||
		envelope.Suite != Algorithm || envelope.Context != context || len(envelope.Sealed) == 0 ||
		len(envelope.Signature) != mldsa65.SignatureSize {
		return nil, 0, ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(wire, canonical) {
		return nil, 0, ErrInvalidEnvelope
	}
	_, senderPublic, err := validatePublic(expectedSender)
	if err != nil {
		return nil, 0, err
	}
	signature := envelope.Signature
	signed, err := networkCollaborationSignedBytes(envelope)
	if err != nil || !mldsa65.Verify(senderPublic, signed, nil, signature) {
		return nil, 0, ErrInvalidEnvelope
	}
	if !openBody {
		return nil, 0, nil
	}
	return Open(receiver, expectedSender, envelope.Sealed, aad)
}
