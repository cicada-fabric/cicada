package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const networkDirectOperationDomain = "cicada/nodekeys/network-direct-operation/v1\x00"

// NetworkDirectEvidence is derived from a fresh Hub peer-key Bundle. The
// caller must compute ManifestDigest with store.NetworkDirectKeyManifest's
// canonical digest and supply its exact self-attestation and accepted proof.
// The Owner public key is compared with independent Node-local trust.
type NetworkDirectEvidence struct {
	ManifestCanonical   []byte
	ExpectedAttestation e2ee.NetworkDirectKeyAttestation
	Attestation         []byte
	ExpectedGrant       e2ee.OwnerNetworkDirectKeyGrant
	GrantProof          []byte
	AcceptedAt          time.Time
	OwnerPublic         e2ee.PublicIdentity
}

func (s *CryptoState) verifyNetworkDirectEvidence(evidence NetworkDirectEvidence,
	route e2ee.NetworkDirectContext, sender bool) (e2ee.PublicIdentity, error) {
	attestation := evidence.ExpectedAttestation
	grant := evidence.ExpectedGrant
	var manifest struct {
		HubID                      string `json:"hub_id"`
		NetworkID                  string `json:"network_id"`
		EndpointID                 string `json:"endpoint_id"`
		PrincipalID                string `json:"principal_id"`
		OwnerID                    string `json:"owner_id"`
		NodeID                     string `json:"node_id"`
		BindingID                  string `json:"binding_id"`
		BindingEpoch               uint64 `json:"binding_epoch"`
		MembershipRevision         int64  `json:"membership_revision"`
		EndpointEnrollmentRevision int64  `json:"endpoint_enrollment_revision"`
		Candidate                  struct {
			BindingID    string              `json:"binding_id"`
			BindingEpoch uint64              `json:"binding_epoch"`
			Public       e2ee.PublicIdentity `json:"public_identity"`
			Attestation  []byte              `json:"attestation"`
		} `json:"candidate"`
	}
	if len(evidence.ManifestCanonical) == 0 ||
		json.Unmarshal(evidence.ManifestCanonical, &manifest) != nil ||
		grant.ManifestDigest != e2ee.NetworkDirectManifestDigest(evidence.ManifestCanonical) ||
		manifest.HubID != route.HubID || manifest.NetworkID != route.NetworkID ||
		manifest.EndpointID != attestation.EndpointID ||
		manifest.PrincipalID != attestation.PrincipalID ||
		manifest.OwnerID != grant.OwnerID || manifest.NodeID != attestation.NodeID ||
		manifest.BindingID != attestation.BindingID ||
		manifest.BindingEpoch != attestation.BindingEpoch ||
		manifest.Candidate.BindingID != attestation.BindingID ||
		manifest.Candidate.BindingEpoch != attestation.BindingEpoch ||
		!samePublicIdentity(manifest.Candidate.Public, attestation.Public) ||
		!bytes.Equal(manifest.Candidate.Attestation, evidence.Attestation) ||
		grant.NetworkID != route.NetworkID || grant.HubID != route.HubID ||
		attestation.NetworkID != route.NetworkID || attestation.HubID != route.HubID ||
		grant.EndpointID != attestation.EndpointID || grant.OwnerID == "" ||
		evidence.AcceptedAt.IsZero() {
		return e2ee.PublicIdentity{}, ErrEndpointContextScope
	}
	if sender {
		if attestation.EndpointID != route.SenderEndpointID ||
			attestation.PrincipalID != route.SenderPrincipalID ||
			grant.OwnerID != route.SenderOwnerID ||
			manifest.MembershipRevision != route.SenderMembershipRevision ||
			manifest.EndpointEnrollmentRevision != route.SenderEnrollmentRevision ||
			attestation.BindingEpoch != route.SenderBindingEpoch ||
			attestation.Public.ID != route.SenderKeyID {
			return e2ee.PublicIdentity{}, ErrEndpointContextScope
		}
	} else if attestation.EndpointID != route.ReceiverEndpointID ||
		attestation.PrincipalID != route.ReceiverPrincipalID ||
		grant.OwnerID != route.ReceiverOwnerID ||
		manifest.MembershipRevision != route.ReceiverMembershipRevision ||
		manifest.EndpointEnrollmentRevision != route.ReceiverEnrollmentRevision ||
		attestation.BindingEpoch != route.ReceiverBindingEpoch ||
		attestation.Public.ID != route.ReceiverKeyID {
		return e2ee.PublicIdentity{}, ErrEndpointContextScope
	}
	trusted, err := s.GetNodeOwnerKeyTrustLocal(grant.OwnerID, grant.OwnerKeyID)
	if err != nil || trusted.State != NodeOwnerKeyTrustActive ||
		!samePublicIdentity(trusted.PublicIdentity, evidence.OwnerPublic) {
		return e2ee.PublicIdentity{}, ErrPeerPinOwnerTrustRequired
	}
	public, err := e2ee.VerifyNetworkDirectKeyAttestation(evidence.Attestation, attestation)
	if err != nil || !samePublicIdentity(public, attestation.Public) {
		return e2ee.PublicIdentity{}, ErrPeerPinGrantInvalid
	}
	if _, err := e2ee.VerifyOwnerNetworkDirectKeyGrant(evidence.GrantProof,
		trusted.PublicIdentity, grant, evidence.AcceptedAt); err != nil {
		return e2ee.PublicIdentity{}, ErrPeerPinGrantInvalid
	}
	return public, nil
}

// NetworkDirectOperationID binds a durable retry to one exact Network route
// and body, including enrollment generations and request correlation.
func NetworkDirectOperationID(route e2ee.NetworkDirectContext,
	plaintext []byte) (string, error) {
	encoded, err := json.Marshal(route)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(networkDirectOperationDomain))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(encoded)
	binary.BigEndian.PutUint64(length[:], uint64(len(plaintext)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(plaintext)
	return "netmsg_" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *CryptoState) SealOutboundNetworkDirectMessage(ctx context.Context,
	local *e2ee.Identity, route e2ee.NetworkDirectContext,
	sender, receiver NetworkDirectEvidence, operationID string,
	plaintext []byte) (OutboundEndpointMessage, error) {
	if ctx == nil || local == nil || operationID == "" {
		return OutboundEndpointMessage{}, ErrEndpointContextScope
	}
	senderPublic, err := s.verifyNetworkDirectEvidence(sender, route, true)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	receiverPublic, err := s.verifyNetworkDirectEvidence(receiver, route, false)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	if !samePublicIdentity(senderPublic, local.Public()) {
		return OutboundEndpointMessage{}, ErrEndpointKeyIdentity
	}
	expectedOperation, err := NetworkDirectOperationID(route, plaintext)
	if err != nil || expectedOperation != operationID {
		return OutboundEndpointMessage{}, ErrOutboundConflict
	}
	if saved, err := s.GetOutbound(ctx, operationID, senderPublic.ID); err == nil {
		if saved.SourceEndpointID != route.SenderEndpointID ||
			e2ee.VerifyNetworkDirectMessage(senderPublic, route, saved.Envelope) != nil {
			return OutboundEndpointMessage{}, ErrOutboundConflict
		}
		sequence, err := networkDirectEnvelopeSequence(saved.Envelope)
		if err != nil {
			return OutboundEndpointMessage{}, ErrOutboundConflict
		}
		return OutboundEndpointMessage{Envelope: saved.Envelope,
			Sequence: sequence, Reused: true}, nil
	} else if !errors.Is(err, ErrCryptoStateNotFound) {
		return OutboundEndpointMessage{}, err
	}
	sequence, err := s.ReserveOutboundSequence(ctx, route.SenderEndpointID, senderPublic.ID)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	wire, err := e2ee.SealNetworkDirectMessage(local, receiverPublic, route, plaintext, sequence)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	saved, _, err := s.StoreOutbound(ctx, operationID, route.SenderEndpointID,
		senderPublic.ID, wire)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	return OutboundEndpointMessage{Envelope: saved.Envelope,
		Sequence: sequence}, nil
}

func (s *CryptoState) OpenInboundNetworkDirectMessage(ctx context.Context,
	local *e2ee.Identity, route e2ee.NetworkDirectContext,
	sender, receiver NetworkDirectEvidence, wire []byte) (InboundEndpointMessage, error) {
	if ctx == nil || local == nil {
		return InboundEndpointMessage{}, ErrEndpointContextScope
	}
	senderPublic, err := s.verifyNetworkDirectEvidence(sender, route, true)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	receiverPublic, err := s.verifyNetworkDirectEvidence(receiver, route, false)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	if !samePublicIdentity(receiverPublic, local.Public()) {
		return InboundEndpointMessage{}, ErrEndpointKeyIdentity
	}
	plaintext, sequence, err := e2ee.OpenNetworkDirectMessage(local, senderPublic, route, wire)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	duplicate, err := s.AcceptInbound(ctx, route.ReceiverEndpointID, senderPublic.ID,
		route.MessageID, sequence, wire)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	return InboundEndpointMessage{Plaintext: plaintext,
		Sequence: sequence, Duplicate: duplicate}, nil
}

func networkDirectEnvelopeSequence(wire []byte) (uint64, error) {
	var outer e2ee.NetworkDirectEnvelope
	if err := json.Unmarshal(wire, &outer); err != nil {
		return 0, err
	}
	var sealed e2ee.Envelope
	decoder := json.NewDecoder(bytes.NewReader(outer.Sealed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sealed); err != nil || sealed.Sequence == 0 {
		return 0, ErrOutboundConflict
	}
	return sealed.Sequence, nil
}
