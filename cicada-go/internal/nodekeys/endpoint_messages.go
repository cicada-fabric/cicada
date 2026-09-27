package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

var (
	// ErrEndpointContextScope means the trusted endpoint context does not
	// describe the local and peer identities in the supplied pin scope.
	ErrEndpointContextScope = errors.New("endpoint message context does not match peer pin scope")
	// ErrEndpointBindingEpoch means the context's peer binding epoch differs
	// from the epoch covered by the active verified pin.
	ErrEndpointBindingEpoch = errors.New("endpoint message binding epoch does not match verified peer pin")
	// ErrEndpointKeyIdentity means the local or peer key ID in the context does
	// not match the local identity or active verified pin.
	ErrEndpointKeyIdentity = errors.New("endpoint message key identity does not match local identity or verified peer pin")
)

const endpointOperationIDDomain = "cicada/nodekeys/endpoint-operation/v1\x00"

// OutboundEndpointMessage is an encrypted envelope ready for transport.
// Envelope is always the exact byte sequence stored in the durable outbox.
// Reused is true when the operation ID already had a matching stored envelope.
type OutboundEndpointMessage struct {
	Envelope []byte
	Sequence uint64
	Reused   bool
}

// InboundEndpointMessage is plaintext opened from an authenticated envelope
// after its ciphertext and replay identity have been committed atomically.
// Duplicate means only that this exact ciphertext was already persisted; it
// does not mean an application or model consumed the plaintext.
type InboundEndpointMessage struct {
	Plaintext []byte
	Sequence  uint64
	Duplicate bool
}

// SealOutboundEndpointMessage checks the caller's trusted route against the
// exact active peer pin, then durably stores one endpoint envelope before
// returning bytes that may be sent to transport. Callers must build route from
// trusted Guard state; envelope fields or peer candidates are never trust
// inputs here.
//
// operationID must be the value returned by EndpointMessageOperationID for
// this exact route and plaintext. A retry with the same operationID returns
// the exact saved bytes without resealing. Reusing an ID with a different
// context or body fails before transport.
func (s *CryptoState) SealOutboundEndpointMessage(ctx context.Context, local *e2ee.Identity,
	scope PeerPinScope, expectedPeer PeerPinIdentity, operationID string,
	route e2ee.EndpointMessageContext, plaintext []byte) (OutboundEndpointMessage, error) {
	if ctx == nil {
		return OutboundEndpointMessage{}, errors.New("context is required")
	}
	if local == nil {
		return OutboundEndpointMessage{}, errors.New("local Endpoint identity is required")
	}
	if err := validateCryptoToken("operation ID", operationID); err != nil {
		return OutboundEndpointMessage{}, err
	}
	if err := validatePeerPinRequest(scope, expectedPeer); err != nil {
		return OutboundEndpointMessage{}, err
	}
	localPublic := local.Public()
	if err := e2ee.ValidatePublicIdentity(localPublic); err != nil {
		return OutboundEndpointMessage{}, fmt.Errorf("validate local Endpoint identity: %w", err)
	}
	if err := validateEndpointRouteScope(route, scope, expectedPeer, true); err != nil {
		return OutboundEndpointMessage{}, err
	}
	derivedOperationID, err := EndpointMessageOperationID(route, plaintext)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	if operationID != derivedOperationID {
		return OutboundEndpointMessage{}, ErrOutboundConflict
	}
	if route.SenderKeyID != localPublic.ID {
		return OutboundEndpointMessage{}, ErrEndpointKeyIdentity
	}

	pin, err := s.GetPeerPin(ctx, scope, expectedPeer)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	if route.ReceiverKeyID != pin.KeyID {
		return OutboundEndpointMessage{}, ErrEndpointKeyIdentity
	}
	if route.ReceiverBindingEpoch != pin.BindingEpoch {
		return OutboundEndpointMessage{}, ErrEndpointBindingEpoch
	}

	// Fetch first so retries preserve the exact ciphertext, nonce, signature and
	// reserved sequence from the original operation.
	record, err := s.GetOutbound(ctx, operationID, localPublic.ID)
	if err == nil {
		if record.SourceEndpointID != scope.LocalEndpointID || record.SourceKeyID != localPublic.ID {
			return OutboundEndpointMessage{}, ErrOutboundConflict
		}
		return outboundFromRecord(record, route, localPublic, true)
	}
	if !errors.Is(err, ErrCryptoStateNotFound) {
		return OutboundEndpointMessage{}, err
	}

	sequence, err := s.ReserveOutboundSequence(ctx, scope.LocalEndpointID, localPublic.ID)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	wire, err := e2ee.SealEndpointMessage(local, pin.Public, route, plaintext, sequence)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	stored, _, err := s.StoreOutbound(ctx, operationID, scope.LocalEndpointID, localPublic.ID, wire)
	if errors.Is(err, ErrOutboundConflict) {
		// Concurrent retries may both observe a missing row. Adopt the winner's
		// immutable envelope only if it is for this exact trusted route.
		record, getErr := s.GetOutbound(ctx, operationID, localPublic.ID)
		if getErr != nil {
			return OutboundEndpointMessage{}, err
		}
		if record.SourceEndpointID != scope.LocalEndpointID || record.SourceKeyID != localPublic.ID {
			return OutboundEndpointMessage{}, ErrOutboundConflict
		}
		return outboundFromRecord(record, route, localPublic, true)
	}
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	if stored.SourceEndpointID != scope.LocalEndpointID || stored.SourceKeyID != localPublic.ID {
		return OutboundEndpointMessage{}, ErrOutboundConflict
	}
	return outboundFromRecord(stored, route, localPublic, false)
}

// SealOwnerGrantedCrossGroupOutboundEndpointMessage encrypts one SEND,
// REQUEST, or correlated REPLY for an explicitly owner-granted cross-Group Link. The current bilateral Bundle is
// verified against independent Node-local Owner trust and the existing exact
// peer pin; the route is checked against its signed contract before the same
// durable sequence/outbox protocol used by same-Group messages. Callers must
// still obtain a fresh production route Guard decision before transport.
func (s *CryptoState) SealOwnerGrantedCrossGroupOutboundEndpointMessage(ctx context.Context,
	local *e2ee.Identity, scope PeerPinScope, localEndpoint PeerPinLocalEndpoint,
	expectedPeer PeerPinIdentity, bundle PeerKeyAuthorizationBundle, dataScope,
	operationID string, route e2ee.EndpointMessageContext,
	plaintext []byte) (OutboundEndpointMessage, error) {
	if ctx == nil || local == nil {
		return OutboundEndpointMessage{}, errors.New("context and local Endpoint identity are required")
	}
	localPublic := local.Public()
	if localEndpoint.KeyID != localPublic.ID || !samePublicIdentity(localEndpoint.Public, localPublic) {
		return OutboundEndpointMessage{}, ErrEndpointKeyIdentity
	}
	if err := validateCryptoToken("operation ID", operationID); err != nil {
		return OutboundEndpointMessage{}, err
	}
	if err := validateEndpointRouteScope(route, scope, expectedPeer, true); err != nil {
		return OutboundEndpointMessage{}, err
	}
	if err := validateOwnerGrantedMessageRoute(bundle, dataScope, route); err != nil {
		return OutboundEndpointMessage{}, err
	}
	if route.SenderKeyID != localPublic.ID || route.SenderBindingEpoch != localEndpoint.BindingEpoch {
		return OutboundEndpointMessage{}, ErrEndpointKeyIdentity
	}
	pin, err := s.GetOwnerGrantedCrossGroupPeerPin(ctx, scope, localEndpoint,
		expectedPeer, bundle)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	if route.ReceiverKeyID != pin.KeyID || route.ReceiverBindingEpoch != pin.BindingEpoch {
		return OutboundEndpointMessage{}, ErrEndpointKeyIdentity
	}
	derivedOperationID, err := EndpointMessageOperationID(route, plaintext)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	if operationID != derivedOperationID {
		return OutboundEndpointMessage{}, ErrOutboundConflict
	}
	// A retry adopts the original immutable ciphertext and sequence, never a
	// newly sealed payload with the same operation identity.
	record, err := s.GetOutbound(ctx, operationID, localPublic.ID)
	if err == nil {
		if record.SourceEndpointID != scope.LocalEndpointID || record.SourceKeyID != localPublic.ID {
			return OutboundEndpointMessage{}, ErrOutboundConflict
		}
		return outboundFromRecord(record, route, localPublic, true)
	}
	if !errors.Is(err, ErrCryptoStateNotFound) {
		return OutboundEndpointMessage{}, err
	}
	sequence, err := s.ReserveOutboundSequence(ctx, scope.LocalEndpointID, localPublic.ID)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	wire, err := e2ee.SealEndpointMessage(local, pin.Public, route, plaintext, sequence)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	stored, _, err := s.StoreOutbound(ctx, operationID, scope.LocalEndpointID, localPublic.ID, wire)
	if errors.Is(err, ErrOutboundConflict) {
		record, getErr := s.GetOutbound(ctx, operationID, localPublic.ID)
		if getErr != nil || record.SourceEndpointID != scope.LocalEndpointID ||
			record.SourceKeyID != localPublic.ID {
			return OutboundEndpointMessage{}, ErrOutboundConflict
		}
		return outboundFromRecord(record, route, localPublic, true)
	}
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	return outboundFromRecord(stored, route, localPublic, false)
}

// EndpointMessageOperationID returns a stable operation key for the exact
// trusted route and plaintext. Pass this value to SealOutboundEndpointMessage
// so retries with a changed route or body cannot silently reuse old ciphertext.
func EndpointMessageOperationID(route e2ee.EndpointMessageContext, plaintext []byte) (string, error) {
	encodedRoute, err := json.Marshal(route)
	if err != nil {
		return "", fmt.Errorf("encode endpoint operation context: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(endpointOperationIDDomain))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(encodedRoute)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(encodedRoute)
	binary.BigEndian.PutUint64(size[:], uint64(len(plaintext)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(plaintext)
	return "epmsg_" + hex.EncodeToString(hash.Sum(nil)), nil
}

// OpenInboundEndpointMessage checks the caller's trusted route and the active
// peer pin before opening an envelope. It commits the exact ciphertext and
// replay identity atomically before returning plaintext. Callers must build
// expectedRoute from trusted Guard state; the untrusted envelope cannot supply
// that context or create a pin.
//
// Duplicate reports that the ciphertext was already persisted. Applications
// must track their own consumption state and must never treat Duplicate as
// evidence that model processing completed.
func (s *CryptoState) OpenInboundEndpointMessage(ctx context.Context, local *e2ee.Identity,
	scope PeerPinScope, expectedPeer PeerPinIdentity, expectedRoute e2ee.EndpointMessageContext,
	wire []byte) (InboundEndpointMessage, error) {
	if ctx == nil {
		return InboundEndpointMessage{}, errors.New("context is required")
	}
	if local == nil {
		return InboundEndpointMessage{}, errors.New("local Endpoint identity is required")
	}
	if err := validatePeerPinRequest(scope, expectedPeer); err != nil {
		return InboundEndpointMessage{}, err
	}
	localPublic := local.Public()
	if err := e2ee.ValidatePublicIdentity(localPublic); err != nil {
		return InboundEndpointMessage{}, fmt.Errorf("validate local Endpoint identity: %w", err)
	}
	if err := validateEndpointRouteScope(expectedRoute, scope, expectedPeer, false); err != nil {
		return InboundEndpointMessage{}, err
	}
	if expectedRoute.ReceiverKeyID != localPublic.ID {
		return InboundEndpointMessage{}, ErrEndpointKeyIdentity
	}

	pin, err := s.GetPeerPin(ctx, scope, expectedPeer)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	if expectedRoute.SenderKeyID != pin.KeyID {
		return InboundEndpointMessage{}, ErrEndpointKeyIdentity
	}
	if expectedRoute.SenderBindingEpoch != pin.BindingEpoch {
		return InboundEndpointMessage{}, ErrEndpointBindingEpoch
	}

	plaintext, sequence, err := e2ee.OpenEndpointMessage(local, pin.Public, expectedRoute, wire)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	duplicate, err := s.AcceptInbound(ctx, scope.LocalEndpointID, pin.KeyID,
		expectedRoute.MessageID, sequence, wire)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	return InboundEndpointMessage{Plaintext: plaintext, Sequence: sequence, Duplicate: duplicate}, nil
}

// OpenOwnerGrantedCrossGroupInboundEndpointMessage is the receiving Endpoint
// cryptographic boundary for a cross-Group SEND, REQUEST, or correlated REPLY. The caller must first obtain
// a fresh, exact-attempt authorization from the authenticated Node Relay API;
// this method independently verifies its bilateral Owner proof, local trust,
// pinned peer key, signed route and replay state. The encrypted bytes are
// durable before plaintext is returned. This method does not claim that a
// native runtime consumed the result.
func (s *CryptoState) OpenOwnerGrantedCrossGroupInboundEndpointMessage(ctx context.Context,
	local *e2ee.Identity, scope PeerPinScope, localEndpoint PeerPinLocalEndpoint,
	expectedPeer PeerPinIdentity, bundle PeerKeyAuthorizationBundle, dataScope string,
	expectedRoute e2ee.EndpointMessageContext, wire []byte) (InboundEndpointMessage, error) {
	if ctx == nil || local == nil {
		return InboundEndpointMessage{}, errors.New("context and local Endpoint identity are required")
	}
	localPublic := local.Public()
	if localEndpoint.KeyID != localPublic.ID || !samePublicIdentity(localEndpoint.Public, localPublic) {
		return InboundEndpointMessage{}, ErrEndpointKeyIdentity
	}
	if err := validateEndpointRouteScope(expectedRoute, scope, expectedPeer, false); err != nil {
		return InboundEndpointMessage{}, err
	}
	if (expectedRoute.Kind != "SEND" && expectedRoute.Kind != "REQUEST" && expectedRoute.Kind != "REPLY") || expectedRoute.MessageID == "" ||
		expectedRoute.ReceiverKeyID != localPublic.ID ||
		expectedRoute.ReceiverBindingEpoch != localEndpoint.BindingEpoch {
		return InboundEndpointMessage{}, ErrEndpointContextScope
	}
	// GetOwnerGrantedCrossGroupPeerPin rejects revoked local trust, changed
	// grants, stale candidate/binding and a mismatched manifest. Legacy
	// GetPeerPin intentionally cannot return this cross-Group pin.
	pin, err := s.GetOwnerGrantedCrossGroupPeerPin(ctx, scope, localEndpoint,
		expectedPeer, bundle)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	if expectedRoute.SenderKeyID != pin.KeyID || expectedRoute.SenderBindingEpoch != pin.BindingEpoch {
		return InboundEndpointMessage{}, ErrEndpointKeyIdentity
	}
	if err := validateOwnerGrantedMessageRoute(bundle, dataScope, expectedRoute); err != nil {
		return InboundEndpointMessage{}, err
	}
	plaintext, sequence, err := e2ee.OpenEndpointMessage(local, pin.Public, expectedRoute, wire)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	duplicate, err := s.AcceptInbound(ctx, scope.LocalEndpointID, pin.KeyID,
		expectedRoute.MessageID, sequence, wire)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	return InboundEndpointMessage{Plaintext: plaintext, Sequence: sequence, Duplicate: duplicate}, nil
}

func validateOwnerGrantedMessageRoute(bundle PeerKeyAuthorizationBundle, dataScope string,
	route e2ee.EndpointMessageContext) error {
	var contract peerLinkContract
	if err := json.Unmarshal(bundle.Manifest.ContractCanonical, &contract); err != nil {
		return ErrEndpointContextScope
	}
	requiredAction := ""
	reverse := false
	switch route.Kind {
	case "SEND":
		if route.RequestID != "" || route.ReplyTo != "" {
			return ErrEndpointContextScope
		}
		requiredAction = "send"
	case "REQUEST":
		if route.RequestID == "" || route.ReplyTo != "" {
			return ErrEndpointContextScope
		}
		requiredAction = "ask"
	case "REPLY":
		if route.RequestID == "" || route.ReplyTo == "" {
			return ErrEndpointContextScope
		}
		requiredAction, reverse = "reply", true
	default:
		return ErrEndpointContextScope
	}
	allowedAction, allowedScope := false, false
	for _, action := range contract.Actions {
		allowedAction = allowedAction || action == requiredAction
	}
	for _, allowed := range contract.DataScopes {
		allowedScope = allowedScope || allowed == dataScope
	}
	senderManifest, receiverManifest := bundle.Manifest.Source, bundle.Manifest.Target
	expectedSenderEndpointID, expectedSenderPrincipalID, expectedSenderGroupID :=
		contract.SourceEndpointID, contract.SourcePrincipalID, contract.SourceGroupID
	expectedReceiverEndpointID, expectedReceiverPrincipalID, expectedReceiverGroupID :=
		contract.TargetEndpointID, contract.TargetPrincipalID, contract.TargetGroupID
	expectedSenderOwnerID, expectedReceiverOwnerID := contract.SourceOwnerID, contract.TargetOwnerID
	expectedSenderMembershipRevision := contract.ScopeSnapshot.SourceMembershipRevision
	expectedReceiverMembershipRevision := contract.ScopeSnapshot.TargetMembershipRevision
	if reverse {
		// A forward-only Link may carry the reverse answer to its exact
		// REQUEST when both Owners granted the separate reply action. The
		// Hub must additionally prove request_id/reply_to correlation.
		senderManifest, receiverManifest = receiverManifest, senderManifest
		expectedSenderEndpointID, expectedReceiverEndpointID = expectedReceiverEndpointID, expectedSenderEndpointID
		expectedSenderPrincipalID, expectedReceiverPrincipalID = expectedReceiverPrincipalID, expectedSenderPrincipalID
		expectedSenderGroupID, expectedReceiverGroupID = expectedReceiverGroupID, expectedSenderGroupID
		expectedSenderOwnerID, expectedReceiverOwnerID = expectedReceiverOwnerID, expectedSenderOwnerID
		expectedSenderMembershipRevision, expectedReceiverMembershipRevision =
			expectedReceiverMembershipRevision, expectedSenderMembershipRevision
	}
	if !allowedAction || !allowedScope || dataScope == "" || route.MessageID == "" ||
		expectedSenderEndpointID != route.SenderEndpointID ||
		expectedSenderPrincipalID != route.SenderPrincipalID ||
		expectedSenderGroupID != route.SenderGroupID ||
		expectedReceiverEndpointID != route.ReceiverEndpointID ||
		expectedReceiverPrincipalID != route.ReceiverPrincipalID ||
		expectedReceiverGroupID != route.ReceiverGroupID ||
		contract.Direction != "forward" && contract.Direction != "bidirectional" ||
		route.SenderOwnerID != expectedSenderOwnerID ||
		route.ReceiverOwnerID != expectedReceiverOwnerID ||
		route.SenderMembershipRevision != expectedSenderMembershipRevision ||
		route.ReceiverMembershipRevision != expectedReceiverMembershipRevision ||
		route.LinkID != bundle.Manifest.LinkID || route.LinkRevision != bundle.Manifest.LinkVersion ||
		route.TransportHubID != contract.TransportHubID ||
		route.SenderKeyID != senderManifest.KeyID ||
		route.ReceiverKeyID != receiverManifest.KeyID ||
		route.SenderBindingEpoch != senderManifest.BindingEpoch ||
		route.ReceiverBindingEpoch != receiverManifest.BindingEpoch {
		return ErrEndpointContextScope
	}
	return nil
}

func validateEndpointRouteScope(route e2ee.EndpointMessageContext, scope PeerPinScope,
	peer PeerPinIdentity, outbound bool) error {
	if route.SenderBindingEpoch == 0 || route.ReceiverBindingEpoch == 0 {
		return ErrEndpointContextScope
	}
	if outbound {
		if route.SenderEndpointID != scope.LocalEndpointID || route.SenderGroupID != scope.LocalGroupID ||
			route.ReceiverEndpointID != scope.PeerEndpointID || route.ReceiverGroupID != scope.PeerGroupID ||
			route.ReceiverPrincipalID != peer.PrincipalID || route.ReceiverOwnerID != peer.OwnerID {
			return ErrEndpointContextScope
		}
	} else if route.ReceiverEndpointID != scope.LocalEndpointID || route.ReceiverGroupID != scope.LocalGroupID ||
		route.SenderEndpointID != scope.PeerEndpointID || route.SenderGroupID != scope.PeerGroupID ||
		route.SenderPrincipalID != peer.PrincipalID || route.SenderOwnerID != peer.OwnerID {
		return ErrEndpointContextScope
	}
	if route.LinkID != scope.CommunicationLinkID {
		return ErrEndpointContextScope
	}
	return nil
}

func outboundFromRecord(record OutboundRecord, expected e2ee.EndpointMessageContext,
	localPublic e2ee.PublicIdentity, reused bool) (OutboundEndpointMessage, error) {
	parsed, err := decodeEndpointEnvelope(record.Envelope)
	if err != nil || parsed.Context != expected || parsed.Version != e2ee.EndpointEnvelopeVersion ||
		parsed.Suite != e2ee.EndpointEnvelopeSuite || len(parsed.Sealed) == 0 || len(parsed.Signature) == 0 {
		return OutboundEndpointMessage{}, ErrOutboundConflict
	}
	if err := verifyEndpointEnvelopeSignature(parsed, localPublic); err != nil {
		return OutboundEndpointMessage{}, ErrOutboundConflict
	}
	sequence, err := endpointEnvelopeSequence(parsed)
	if err != nil {
		return OutboundEndpointMessage{}, ErrOutboundConflict
	}
	return OutboundEndpointMessage{Envelope: append([]byte(nil), record.Envelope...), Sequence: sequence, Reused: reused}, nil
}

func verifyEndpointEnvelopeSignature(envelope e2ee.EndpointMessageEnvelope,
	localPublic e2ee.PublicIdentity) error {
	if envelope.Context.SenderKeyID != localPublic.ID {
		return ErrEndpointKeyIdentity
	}
	var senderKey mldsa65.PublicKey
	if err := senderKey.UnmarshalBinary(localPublic.SigningPublic); err != nil {
		return err
	}
	signature := envelope.Signature
	envelope.Signature = nil
	unsigned, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if !mldsa65.Verify(&senderKey, unsigned, nil, signature) {
		return errors.New("Endpoint route signature verification failed")
	}
	return nil
}

func endpointEnvelopeSequence(envelope e2ee.EndpointMessageEnvelope) (uint64, error) {
	var sealed e2ee.Envelope
	decoder := json.NewDecoder(bytes.NewReader(envelope.Sealed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sealed); err != nil {
		return 0, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return 0, errors.New("endpoint sealed envelope has trailing data")
	}
	if sealed.Sequence == 0 {
		return 0, errors.New("endpoint sealed envelope has zero sequence")
	}
	return sealed.Sequence, nil
}

func decodeEndpointEnvelope(wire []byte) (e2ee.EndpointMessageEnvelope, error) {
	var envelope e2ee.EndpointMessageEnvelope
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return e2ee.EndpointMessageEnvelope{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return e2ee.EndpointMessageEnvelope{}, errors.New("endpoint envelope has trailing data")
	}
	return envelope, nil
}
