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
	networkDirectAttestationDomain = "cicada/network/direct-key-attestation/v1\x00"
	networkDirectGrantDomain       = "cicada/network/direct-key-grant/v1\x00"
	networkDirectAADDomain         = "cicada/network/direct-envelope/v1\x00"
	NetworkDirectManifestDomain    = "cicada/network/direct-key-manifest/v1\x00"
	maxNetworkDirectProofBytes     = 32 * 1024
)

// NetworkDirectManifestDigest hashes the canonical public manifest bytes
// shared by Hub persistence and independent Node proof verification.
func NetworkDirectManifestDigest(canonical []byte) string {
	sum := sha256.Sum256(append([]byte(NetworkDirectManifestDomain), canonical...))
	return hex.EncodeToString(sum[:])
}

// NetworkDirectNativeSessionDigest commits to the local native destination
// without disclosing its locator in the public Owner-signed manifest.
func NetworkDirectNativeSessionDigest(nativeSessionID string) string {
	sum := sha256.Sum256([]byte("cicada/network/native-session/v1\x00" + nativeSessionID))
	return hex.EncodeToString(sum[:])
}

// NetworkDirectKeyAttestation proves possession of a key for one real native
// delivery binding. An owner signature over the current Store manifest is
// required separately before this candidate can be used by a peer.
type NetworkDirectKeyAttestation struct {
	Version      int            `json:"version"`
	HubID        string         `json:"hub_id"`
	NetworkID    string         `json:"network_id"`
	EndpointID   string         `json:"endpoint_id"`
	PrincipalID  string         `json:"principal_id"`
	NodeID       string         `json:"node_id"`
	BindingID    string         `json:"binding_id"`
	BindingEpoch uint64         `json:"binding_epoch"`
	Public       PublicIdentity `json:"public_identity"`
	Signature    []byte         `json:"signature"`
}

func (proof NetworkDirectKeyAttestation) valid() bool {
	if proof.Version != 1 || proof.BindingEpoch == 0 {
		return false
	}
	for _, value := range []string{proof.HubID, proof.NetworkID, proof.EndpointID,
		proof.PrincipalID, proof.NodeID, proof.BindingID} {
		if !canonicalEndpointToken(value, true) {
			return false
		}
	}
	return ValidatePublicIdentity(proof.Public) == nil
}

func networkDirectAttestationBytes(proof NetworkDirectKeyAttestation) ([]byte, error) {
	proof.Signature = nil
	encoded, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	return append([]byte(networkDirectAttestationDomain), encoded...), nil
}

func (identity *Identity) SignNetworkDirectKeyAttestation(hubID, networkID,
	endpointID, principalID, nodeID, bindingID string, bindingEpoch uint64) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil {
		return nil, ErrInvalidEnvelope
	}
	proof := NetworkDirectKeyAttestation{Version: 1, HubID: hubID, NetworkID: networkID,
		EndpointID: endpointID, PrincipalID: principalID, NodeID: nodeID,
		BindingID: bindingID, BindingEpoch: bindingEpoch, Public: identity.Public()}
	if !proof.valid() {
		return nil, ErrInvalidEnvelope
	}
	signed, err := networkDirectAttestationBytes(proof)
	if err != nil {
		return nil, err
	}
	proof.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(identity.signingPrivate, signed, nil, true, proof.Signature); err != nil {
		return nil, err
	}
	return json.Marshal(proof)
}

func VerifyNetworkDirectKeyAttestation(data []byte, expected NetworkDirectKeyAttestation) (PublicIdentity, error) {
	if len(data) == 0 || len(data) > maxNetworkDirectProofBytes {
		return PublicIdentity{}, ErrInvalidEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var proof NetworkDirectKeyAttestation
	if err := decoder.Decode(&proof); err != nil {
		return PublicIdentity{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || !proof.valid() ||
		proof.HubID != expected.HubID || proof.NetworkID != expected.NetworkID ||
		proof.EndpointID != expected.EndpointID || proof.PrincipalID != expected.PrincipalID ||
		proof.NodeID != expected.NodeID || proof.BindingID != expected.BindingID ||
		proof.BindingEpoch != expected.BindingEpoch || len(proof.Signature) != mldsa65.SignatureSize {
		return PublicIdentity{}, ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(data, canonical) {
		return PublicIdentity{}, ErrInvalidEnvelope
	}
	_, public, err := validatePublic(proof.Public)
	if err != nil {
		return PublicIdentity{}, err
	}
	signed, err := networkDirectAttestationBytes(proof)
	if err != nil || !mldsa65.Verify(public, signed, nil, proof.Signature) {
		return PublicIdentity{}, ErrInvalidEnvelope
	}
	return proof.Public, nil
}

// OwnerNetworkDirectKeyGrant is signed by the Endpoint owner over a trusted,
// current manifest. Its proof expiry bounds acceptance, not Network membership.
type OwnerNetworkDirectKeyGrant struct {
	Version        int    `json:"version"`
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

func (grant OwnerNetworkDirectKeyGrant) claims() OwnerNetworkDirectKeyGrant {
	grant.Signature = nil
	return grant
}

func (grant OwnerNetworkDirectKeyGrant) signedBytes() ([]byte, error) {
	encoded, err := json.Marshal(grant.claims())
	if err != nil {
		return nil, err
	}
	return append([]byte(networkDirectGrantDomain), encoded...), nil
}

func (grant OwnerNetworkDirectKeyGrant) valid() bool {
	if grant.Version != 1 || !canonicalSHA256Hex(grant.ManifestDigest) || !canonicalSHA256Hex(grant.Nonce) {
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

func (identity *Identity) SignOwnerNetworkDirectKeyGrant(hubID, networkID, endpointID,
	ownerID, manifestDigest string, issuedAt, expiresAt time.Time) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil || !expiresAt.After(issuedAt) {
		return nil, ErrInvalidEnvelope
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	grant := OwnerNetworkDirectKeyGrant{Version: 1, HubID: hubID, NetworkID: networkID,
		EndpointID: endpointID, OwnerID: ownerID, OwnerKeyID: identity.Public().ID,
		ManifestDigest: manifestDigest, IssuedAt: issuedAt.UTC().Format(time.RFC3339Nano),
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

func VerifyOwnerNetworkDirectKeyGrant(data []byte, trustedOwner PublicIdentity,
	expected OwnerNetworkDirectKeyGrant, at time.Time) (OwnerNetworkDirectKeyGrant, error) {
	if len(data) == 0 || len(data) > maxNetworkDirectProofBytes || at.IsZero() {
		return OwnerNetworkDirectKeyGrant{}, ErrInvalidEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var grant OwnerNetworkDirectKeyGrant
	if err := decoder.Decode(&grant); err != nil {
		return OwnerNetworkDirectKeyGrant{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || !grant.valid() ||
		len(grant.Signature) != mldsa65.SignatureSize ||
		grant.HubID != expected.HubID || grant.NetworkID != expected.NetworkID ||
		grant.EndpointID != expected.EndpointID || grant.OwnerID != expected.OwnerID ||
		grant.OwnerKeyID != trustedOwner.ID || grant.ManifestDigest != expected.ManifestDigest {
		return OwnerNetworkDirectKeyGrant{}, ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(grant)
	if err != nil || !bytes.Equal(data, canonical) {
		return OwnerNetworkDirectKeyGrant{}, ErrInvalidEnvelope
	}
	issued, err := parseCanonicalUTC(grant.IssuedAt)
	if err != nil || issued.After(at) {
		return OwnerNetworkDirectKeyGrant{}, ErrInvalidEnvelope
	}
	expires, err := parseCanonicalUTC(grant.ExpiresAt)
	if err != nil || !at.Before(expires) || !expires.After(issued) {
		return OwnerNetworkDirectKeyGrant{}, ErrInvalidEnvelope
	}
	_, public, err := validatePublic(trustedOwner)
	if err != nil {
		return OwnerNetworkDirectKeyGrant{}, err
	}
	signed, err := grant.signedBytes()
	if err != nil || !mldsa65.Verify(public, signed, nil, grant.Signature) {
		return OwnerNetworkDirectKeyGrant{}, ErrInvalidEnvelope
	}
	return grant, nil
}

// NetworkDirectContext is authenticated as AEAD associated data and as part
// of the outer ML-DSA signature. Expected values must come from current
// trusted route/enrollment records, never from the received header alone.
type NetworkDirectContext struct {
	HubID                      string `json:"hub_id"`
	NetworkID                  string `json:"network_id"`
	MessageID                  string `json:"message_id"`
	Kind                       string `json:"kind"`
	RequestID                  string `json:"request_id,omitempty"`
	ReplyTo                    string `json:"reply_to,omitempty"`
	SenderEndpointID           string `json:"sender_endpoint_id"`
	SenderPrincipalID          string `json:"sender_principal_id"`
	SenderOwnerID              string `json:"sender_owner_id"`
	SenderMembershipRevision   int64  `json:"sender_membership_revision"`
	SenderEnrollmentRevision   int64  `json:"sender_enrollment_revision"`
	SenderBindingEpoch         uint64 `json:"sender_binding_epoch"`
	SenderKeyID                string `json:"sender_key_id"`
	ReceiverEndpointID         string `json:"receiver_endpoint_id"`
	ReceiverPrincipalID        string `json:"receiver_principal_id"`
	ReceiverOwnerID            string `json:"receiver_owner_id"`
	ReceiverMembershipRevision int64  `json:"receiver_membership_revision"`
	ReceiverEnrollmentRevision int64  `json:"receiver_enrollment_revision"`
	ReceiverBindingEpoch       uint64 `json:"receiver_binding_epoch"`
	ReceiverKeyID              string `json:"receiver_key_id"`
}

func (context NetworkDirectContext) validate() error {
	for _, value := range []string{context.HubID, context.NetworkID, context.MessageID,
		context.SenderEndpointID, context.SenderPrincipalID, context.SenderOwnerID,
		context.SenderKeyID, context.ReceiverEndpointID, context.ReceiverPrincipalID,
		context.ReceiverOwnerID, context.ReceiverKeyID} {
		if !canonicalEndpointToken(value, true) {
			return ErrInvalidEnvelope
		}
	}
	for _, value := range []string{context.RequestID, context.ReplyTo} {
		if !canonicalEndpointToken(value, false) {
			return ErrInvalidEnvelope
		}
	}
	if context.SenderEndpointID == context.ReceiverEndpointID ||
		context.SenderMembershipRevision <= 0 || context.SenderEnrollmentRevision <= 0 ||
		context.ReceiverMembershipRevision <= 0 || context.ReceiverEnrollmentRevision <= 0 ||
		context.SenderBindingEpoch == 0 || context.ReceiverBindingEpoch == 0 {
		return ErrInvalidEnvelope
	}
	switch context.Kind {
	case "SEND":
		if context.RequestID != "" || context.ReplyTo != "" {
			return ErrInvalidEnvelope
		}
	case "REQUEST":
		if context.RequestID == "" || context.ReplyTo != "" {
			return ErrInvalidEnvelope
		}
	case "REPLY":
		if context.RequestID == "" || context.ReplyTo == "" {
			return ErrInvalidEnvelope
		}
	default:
		return ErrInvalidEnvelope
	}
	return nil
}

type NetworkDirectEnvelope struct {
	Version   int                  `json:"version"`
	Suite     string               `json:"suite"`
	Context   NetworkDirectContext `json:"context"`
	Sealed    json.RawMessage      `json:"sealed"`
	Signature []byte               `json:"signature"`
}

func networkDirectAAD(context NetworkDirectContext) ([]byte, error) {
	if err := context.validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(context)
	if err != nil {
		return nil, err
	}
	return append([]byte(networkDirectAADDomain), encoded...), nil
}

func SealNetworkDirectMessage(sender *Identity, receiver PublicIdentity,
	context NetworkDirectContext, plaintext []byte, sequence uint64) ([]byte, error) {
	if sender == nil || sequence == 0 || len(plaintext) == 0 || len(plaintext) > maxEndpointPlaintext ||
		context.SenderKeyID != sender.Public().ID || context.ReceiverKeyID != receiver.ID {
		return nil, ErrInvalidEnvelope
	}
	aad, err := networkDirectAAD(context)
	if err != nil {
		return nil, err
	}
	sealed, err := Seal(sender, receiver, plaintext, aad, sequence)
	if err != nil {
		return nil, err
	}
	envelope := NetworkDirectEnvelope{Version: 1, Suite: Algorithm, Context: context,
		Sealed: json.RawMessage(sealed)}
	unsigned, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	envelope.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sender.signingPrivate, unsigned, nil, true, envelope.Signature); err != nil {
		return nil, fmt.Errorf("sign Network direct ciphertext: %w", err)
	}
	wire, err := json.Marshal(envelope)
	if err != nil || len(wire) > maxEndpointWire {
		return nil, ErrInvalidEnvelope
	}
	return wire, nil
}

func OpenNetworkDirectMessage(receiver *Identity, expectedSender PublicIdentity,
	expected NetworkDirectContext, wire []byte) ([]byte, uint64, error) {
	if receiver == nil || len(wire) == 0 || len(wire) > maxEndpointWire ||
		expected.SenderKeyID != expectedSender.ID || expected.ReceiverKeyID != receiver.Public().ID {
		return nil, 0, ErrInvalidEnvelope
	}
	aad, err := networkDirectAAD(expected)
	if err != nil {
		return nil, 0, err
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var envelope NetworkDirectEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, 0, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) ||
		envelope.Version != 1 || envelope.Suite != Algorithm || envelope.Context != expected ||
		len(envelope.Sealed) == 0 || len(envelope.Signature) != mldsa65.SignatureSize {
		return nil, 0, ErrInvalidEnvelope
	}
	_, senderKey, err := validatePublic(expectedSender)
	if err != nil {
		return nil, 0, err
	}
	signature := envelope.Signature
	envelope.Signature = nil
	unsigned, err := json.Marshal(envelope)
	if err != nil || !mldsa65.Verify(senderKey, unsigned, nil, signature) {
		return nil, 0, ErrInvalidEnvelope
	}
	plaintext, sequence, err := Open(receiver, expectedSender, envelope.Sealed, aad)
	if err != nil || sequence == 0 || len(plaintext) == 0 || len(plaintext) > maxEndpointPlaintext {
		return nil, 0, ErrInvalidEnvelope
	}
	return plaintext, sequence, nil
}

// VerifyNetworkDirectMessage allows the Hub to verify the signed clear route
// and ciphertext without learning or decrypting the Endpoint plaintext.
func VerifyNetworkDirectMessage(expectedSender PublicIdentity,
	expected NetworkDirectContext, wire []byte) error {
	if len(wire) == 0 || len(wire) > maxEndpointWire ||
		expected.SenderKeyID != expectedSender.ID {
		return ErrInvalidEnvelope
	}
	if _, err := networkDirectAAD(expected); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var envelope NetworkDirectEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) ||
		envelope.Version != 1 || envelope.Suite != Algorithm || envelope.Context != expected ||
		len(envelope.Sealed) == 0 || len(envelope.Signature) != mldsa65.SignatureSize {
		return ErrInvalidEnvelope
	}
	_, senderKey, err := validatePublic(expectedSender)
	if err != nil {
		return err
	}
	signature := envelope.Signature
	envelope.Signature = nil
	unsigned, err := json.Marshal(envelope)
	if err != nil || !mldsa65.Verify(senderKey, unsigned, nil, signature) {
		return ErrInvalidEnvelope
	}
	return nil
}
