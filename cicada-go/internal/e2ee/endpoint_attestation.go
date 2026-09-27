package e2ee

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	EndpointKeyAttestationVersion = 1
	endpointAttestationDomain     = "cicada/fabric/endpoint-key-attestation/v1\x00"
	maxEndpointAttestationBytes   = 32 * 1024
)

// EndpointKeyAttestation proves local possession of a public Endpoint key for
// one currently leased native SessionBinding. A Hub may publish this as a
// candidate, but another Node must independently pin it before encryption:
// a self-signature alone does not establish the owner user's approval.
type EndpointKeyAttestation struct {
	Version      int            `json:"version"`
	EndpointID   string         `json:"endpoint_id"`
	PrincipalID  string         `json:"principal_id"`
	NodeID       string         `json:"node_id"`
	BindingID    string         `json:"binding_id"`
	BindingEpoch uint64         `json:"binding_epoch"`
	Public       PublicIdentity `json:"public_identity"`
	Signature    []byte         `json:"signature"`
}

func (attestation EndpointKeyAttestation) validateClaims() error {
	if attestation.Version != EndpointKeyAttestationVersion ||
		!canonicalEndpointToken(attestation.EndpointID, true) ||
		!canonicalEndpointToken(attestation.PrincipalID, true) ||
		!canonicalEndpointToken(attestation.NodeID, true) ||
		!canonicalEndpointToken(attestation.BindingID, true) || attestation.BindingEpoch == 0 {
		return ErrInvalidEnvelope
	}
	return ValidatePublicIdentity(attestation.Public)
}

func endpointAttestationSignedBytes(attestation EndpointKeyAttestation) ([]byte, error) {
	attestation.Signature = nil
	encoded, err := json.Marshal(attestation)
	if err != nil {
		return nil, err
	}
	return append([]byte(endpointAttestationDomain), encoded...), nil
}

func (identity *Identity) SignEndpointKeyAttestation(endpointID, principalID, nodeID, bindingID string, epoch uint64) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil {
		return nil, errors.New("Endpoint signing identity is unavailable")
	}
	attestation := EndpointKeyAttestation{Version: EndpointKeyAttestationVersion,
		EndpointID: endpointID, PrincipalID: principalID, NodeID: nodeID,
		BindingID: bindingID, BindingEpoch: epoch, Public: identity.Public()}
	if err := attestation.validateClaims(); err != nil {
		return nil, err
	}
	unsigned, err := endpointAttestationSignedBytes(attestation)
	if err != nil {
		return nil, err
	}
	attestation.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(identity.signingPrivate, unsigned, nil, true, attestation.Signature); err != nil {
		return nil, fmt.Errorf("sign Endpoint key attestation: %w", err)
	}
	return json.Marshal(attestation)
}

// VerifyEndpointKeyAttestation checks claims against server-derived actor and
// current binding values, not values copied from an untrusted request body.
func VerifyEndpointKeyAttestation(data []byte, endpointID, principalID, nodeID, bindingID string, epoch uint64) (PublicIdentity, error) {
	if len(data) == 0 || len(data) > maxEndpointAttestationBytes {
		return PublicIdentity{}, ErrInvalidEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var attestation EndpointKeyAttestation
	if err := decoder.Decode(&attestation); err != nil {
		return PublicIdentity{}, fmt.Errorf("decode Endpoint key attestation: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PublicIdentity{}, ErrInvalidEnvelope
	}
	if err := attestation.validateClaims(); err != nil {
		return PublicIdentity{}, err
	}
	if attestation.EndpointID != endpointID || attestation.PrincipalID != principalID ||
		attestation.NodeID != nodeID || attestation.BindingID != bindingID ||
		attestation.BindingEpoch != epoch || len(attestation.Signature) != mldsa65.SignatureSize {
		return PublicIdentity{}, ErrInvalidEnvelope
	}
	_, publicKey, err := validatePublic(attestation.Public)
	if err != nil {
		return PublicIdentity{}, err
	}
	signed, err := endpointAttestationSignedBytes(attestation)
	if err != nil || !mldsa65.Verify(publicKey, signed, nil, attestation.Signature) {
		return PublicIdentity{}, errors.New("Endpoint key attestation signature verification failed")
	}
	return attestation.Public, nil
}
