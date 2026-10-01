package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const networkCollaborationOperationDomain = "cicada/nodekeys/network-collaboration-operation/v1\x00"

// NetworkCollaborationEvidence is the public, Owner-approved key evidence
// needed by a Node to send or receive one purpose-bound Network message. The
// Owner key is accepted only when it already exists in this Node's local trust
// store; Hub-supplied public keys never establish trust on their own.
type NetworkCollaborationEvidence struct {
	ManifestCanonical   []byte
	Purpose             string
	ExpectedAttestation e2ee.NetworkDirectKeyAttestation
	Attestation         []byte
	ExpectedGrant       e2ee.OwnerNetworkCollaborationKeyGrant
	GrantProof          []byte
	OwnerPublic         e2ee.PublicIdentity
}

type networkCollaborationManifestCandidate struct {
	NetworkID    string              `json:"network_id"`
	EndpointID   string              `json:"endpoint_id"`
	PrincipalID  string              `json:"principal_id"`
	OwnerID      string              `json:"owner_id"`
	NodeID       string              `json:"node_id"`
	BindingID    string              `json:"binding_id"`
	BindingEpoch uint64              `json:"binding_epoch"`
	Public       e2ee.PublicIdentity `json:"public_identity"`
	Fingerprint  string              `json:"fingerprint"`
	Attestation  []byte              `json:"attestation"`
	Version      int64               `json:"version"`
}

type networkCollaborationManifest struct {
	Version                    int                                   `json:"version"`
	HubID                      string                                `json:"hub_id"`
	NetworkID                  string                                `json:"network_id"`
	EndpointID                 string                                `json:"endpoint_id"`
	PrincipalID                string                                `json:"principal_id"`
	OwnerID                    string                                `json:"owner_id"`
	NodeID                     string                                `json:"node_id"`
	NativeSessionID            string                                `json:"native_session_id,omitempty"`
	NativeSessionDigest        string                                `json:"native_session_digest"`
	BindingID                  string                                `json:"binding_id"`
	BindingEpoch               uint64                                `json:"binding_epoch"`
	MembershipRevision         int64                                 `json:"membership_revision"`
	EndpointEnrollmentRevision int64                                 `json:"endpoint_enrollment_revision"`
	Candidate                  networkCollaborationManifestCandidate `json:"candidate"`
	Digest                     string                                `json:"digest"`
}

func NetworkCollaborationOperationID(context e2ee.NetworkCollaborationMessageContext,
	plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", ErrEndpointContextScope
	}
	encoded, err := json.Marshal(context)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(networkCollaborationOperationDomain))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(encoded)
	binary.BigEndian.PutUint64(length[:], uint64(len(plaintext)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(plaintext)
	return "netcollab_" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *CryptoState) verifyNetworkCollaborationEvidence(evidence NetworkCollaborationEvidence,
	route e2ee.NetworkDirectContext, sender bool) (e2ee.PublicIdentity, error) {
	if evidence.Purpose != e2ee.NetworkCollaborationPurposeTask &&
		evidence.Purpose != e2ee.NetworkCollaborationPurposeBroadcast {
		return e2ee.PublicIdentity{}, ErrEndpointContextScope
	}
	decoder := json.NewDecoder(bytes.NewReader(evidence.ManifestCanonical))
	decoder.DisallowUnknownFields()
	var manifest networkCollaborationManifest
	if len(evidence.ManifestCanonical) == 0 || len(evidence.ManifestCanonical) > 32*1024 ||
		decoder.Decode(&manifest) != nil {
		return e2ee.PublicIdentity{}, ErrEndpointContextScope
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || manifest.Version != 1 ||
		manifest.NativeSessionID != "" || manifest.Digest != "" || manifest.HubID != route.HubID ||
		manifest.NetworkID != route.NetworkID || manifest.BindingID == "" || manifest.BindingEpoch == 0 ||
		manifest.MembershipRevision <= 0 || manifest.EndpointEnrollmentRevision <= 0 ||
		manifest.Candidate.NetworkID != manifest.NetworkID ||
		manifest.Candidate.EndpointID != manifest.EndpointID ||
		manifest.Candidate.PrincipalID != manifest.PrincipalID ||
		manifest.Candidate.OwnerID != manifest.OwnerID || manifest.Candidate.NodeID != manifest.NodeID ||
		manifest.Candidate.BindingID != manifest.BindingID ||
		manifest.Candidate.BindingEpoch != manifest.BindingEpoch || manifest.Candidate.Version <= 0 ||
		manifest.NativeSessionDigest == "" || manifest.Candidate.Fingerprint == "" ||
		len(manifest.Candidate.Attestation) == 0 {
		return e2ee.PublicIdentity{}, ErrEndpointContextScope
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, evidence.ManifestCanonical) ||
		!samePublicIdentity(manifest.Candidate.Public, evidence.ExpectedAttestation.Public) ||
		!bytes.Equal(manifest.Candidate.Attestation, evidence.Attestation) {
		return e2ee.PublicIdentity{}, ErrEndpointContextScope
	}
	grant := evidence.ExpectedGrant
	if grant.Version != 1 || grant.Purpose != evidence.Purpose || grant.HubID != route.HubID ||
		grant.NetworkID != route.NetworkID || grant.EndpointID != manifest.EndpointID ||
		grant.OwnerID != manifest.OwnerID || grant.OwnerKeyID != evidence.OwnerPublic.ID ||
		grant.ManifestDigest != e2ee.NetworkCollaborationManifestDigest(evidence.Purpose, evidence.ManifestCanonical) {
		return e2ee.PublicIdentity{}, ErrPeerPinGrantInvalid
	}
	attestation := evidence.ExpectedAttestation
	if attestation.Version != 1 || attestation.HubID != manifest.HubID ||
		attestation.NetworkID != manifest.NetworkID || attestation.EndpointID != manifest.EndpointID ||
		attestation.PrincipalID != manifest.PrincipalID || attestation.NodeID != manifest.NodeID ||
		attestation.BindingID != manifest.BindingID || attestation.BindingEpoch != manifest.BindingEpoch ||
		manifest.Candidate.Public.ID != attestation.Public.ID {
		return e2ee.PublicIdentity{}, ErrEndpointContextScope
	}
	if sender {
		if manifest.EndpointID != route.SenderEndpointID || manifest.PrincipalID != route.SenderPrincipalID ||
			manifest.OwnerID != route.SenderOwnerID || manifest.MembershipRevision != route.SenderMembershipRevision ||
			manifest.EndpointEnrollmentRevision != route.SenderEnrollmentRevision ||
			manifest.BindingEpoch != route.SenderBindingEpoch || attestation.Public.ID != route.SenderKeyID {
			return e2ee.PublicIdentity{}, ErrEndpointContextScope
		}
	} else if manifest.EndpointID != route.ReceiverEndpointID || manifest.PrincipalID != route.ReceiverPrincipalID ||
		manifest.OwnerID != route.ReceiverOwnerID || manifest.MembershipRevision != route.ReceiverMembershipRevision ||
		manifest.EndpointEnrollmentRevision != route.ReceiverEnrollmentRevision ||
		manifest.BindingEpoch != route.ReceiverBindingEpoch || attestation.Public.ID != route.ReceiverKeyID {
		return e2ee.PublicIdentity{}, ErrEndpointContextScope
	}
	trusted, err := s.GetNodeOwnerKeyTrustLocal(grant.OwnerID, grant.OwnerKeyID)
	if err != nil || trusted.State != NodeOwnerKeyTrustActive ||
		!samePublicIdentity(trusted.PublicIdentity, evidence.OwnerPublic) {
		return e2ee.PublicIdentity{}, ErrPeerPinOwnerTrustRequired
	}
	public, err := e2ee.VerifyNetworkDirectKeyAttestation(evidence.Attestation, attestation)
	fingerprint, fingerprintErr := PeerKeyFingerprint(manifest.Candidate.Public)
	if err != nil || fingerprintErr != nil || fingerprint != manifest.Candidate.Fingerprint ||
		!samePublicIdentity(public, manifest.Candidate.Public) {
		return e2ee.PublicIdentity{}, ErrPeerPinGrantInvalid
	}
	if _, err := e2ee.VerifyOwnerNetworkCollaborationKeyGrant(evidence.GrantProof,
		trusted.PublicIdentity, grant, time.Now().UTC()); err != nil {
		return e2ee.PublicIdentity{}, ErrPeerPinGrantInvalid
	}
	return public, nil
}

func (s *CryptoState) SealOutboundNetworkCollaborationMessage(ctx context.Context,
	local *e2ee.Identity, messageContext e2ee.NetworkCollaborationMessageContext,
	sender, receiver NetworkCollaborationEvidence, operationID string,
	plaintext []byte) (OutboundEndpointMessage, error) {
	if ctx == nil || local == nil || operationID == "" {
		return OutboundEndpointMessage{}, ErrEndpointContextScope
	}
	senderPublic, err := s.verifyNetworkCollaborationEvidence(sender, messageContext.Route, true)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	receiverPublic, err := s.verifyNetworkCollaborationEvidence(receiver, messageContext.Route, false)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	if !samePublicIdentity(senderPublic, local.Public()) {
		return OutboundEndpointMessage{}, ErrEndpointKeyIdentity
	}
	expectedOperation, err := NetworkCollaborationOperationID(messageContext, plaintext)
	if err != nil || expectedOperation != operationID {
		return OutboundEndpointMessage{}, ErrOutboundConflict
	}
	if saved, err := s.GetOutbound(ctx, operationID, senderPublic.ID); err == nil {
		if saved.SourceEndpointID != messageContext.Route.SenderEndpointID ||
			e2ee.VerifyNetworkCollaborationMessage(senderPublic, messageContext, saved.Envelope) != nil {
			return OutboundEndpointMessage{}, ErrOutboundConflict
		}
		sequence, err := collaborationEnvelopeSequence(saved.Envelope)
		if err != nil {
			return OutboundEndpointMessage{}, ErrOutboundConflict
		}
		return OutboundEndpointMessage{Envelope: saved.Envelope, Sequence: sequence, Reused: true}, nil
	} else if !errors.Is(err, ErrCryptoStateNotFound) {
		return OutboundEndpointMessage{}, err
	}
	sequence, err := s.ReserveOutboundSequence(ctx, messageContext.Route.SenderEndpointID, senderPublic.ID)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	wire, err := e2ee.SealNetworkCollaborationMessage(local, receiverPublic, messageContext, plaintext, sequence)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	saved, _, err := s.StoreOutbound(ctx, operationID, messageContext.Route.SenderEndpointID, senderPublic.ID, wire)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	return OutboundEndpointMessage{Envelope: saved.Envelope, Sequence: sequence}, nil
}

func (s *CryptoState) OpenInboundNetworkCollaborationMessage(ctx context.Context,
	local *e2ee.Identity, messageContext e2ee.NetworkCollaborationMessageContext,
	sender, receiver NetworkCollaborationEvidence, wire []byte) (InboundEndpointMessage, error) {
	if ctx == nil || local == nil {
		return InboundEndpointMessage{}, ErrEndpointContextScope
	}
	senderPublic, err := s.verifyNetworkCollaborationEvidence(sender, messageContext.Route, true)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	receiverPublic, err := s.verifyNetworkCollaborationEvidence(receiver, messageContext.Route, false)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	if !samePublicIdentity(receiverPublic, local.Public()) {
		return InboundEndpointMessage{}, ErrEndpointKeyIdentity
	}
	plaintext, sequence, err := e2ee.OpenNetworkCollaborationMessage(local, senderPublic, messageContext, wire)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	duplicate, err := s.AcceptInbound(ctx, messageContext.Route.ReceiverEndpointID,
		senderPublic.ID, messageContext.Route.MessageID, sequence, wire)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	return InboundEndpointMessage{Plaintext: plaintext, Sequence: sequence, Duplicate: duplicate}, nil
}

func collaborationEnvelopeSequence(wire []byte) (uint64, error) {
	var outer e2ee.NetworkCollaborationEnvelope
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
