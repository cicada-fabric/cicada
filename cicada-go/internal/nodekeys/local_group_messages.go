package nodekeys

import (
	"context"
	"errors"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// SealLocalSameGroupMessage persists an Endpoint envelope before local delivery.
// The caller must build route and expected identities from a fresh, authenticated
// local-delivery Guard result. Requiring both private identities to be present
// on this Node prevents a remote candidate from being treated as a local peer.
// This method is a cryptographic and durability boundary, not an authorization
// substitute: Guard must be rechecked again before native injection.
func (s *CryptoState) SealLocalSameGroupMessage(ctx context.Context,
	sender, receiver *e2ee.Identity, expectedSender, expectedReceiver e2ee.PublicIdentity,
	route e2ee.EndpointMessageContext, plaintext []byte) (OutboundEndpointMessage, error) {
	if ctx == nil || sender == nil || receiver == nil {
		return OutboundEndpointMessage{}, errors.New("local Endpoint identities and context are required")
	}
	if err := validateLocalSameGroupRoute(sender, receiver, expectedSender, expectedReceiver, route); err != nil {
		return OutboundEndpointMessage{}, err
	}
	operationID, err := EndpointMessageOperationID(route, plaintext)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	record, err := s.GetOutbound(ctx, operationID, expectedSender.ID)
	if err == nil {
		if record.SourceEndpointID != route.SenderEndpointID {
			return OutboundEndpointMessage{}, ErrOutboundConflict
		}
		return outboundFromRecord(record, route, expectedSender, true)
	}
	if !errors.Is(err, ErrCryptoStateNotFound) {
		return OutboundEndpointMessage{}, err
	}
	sequence, err := s.ReserveOutboundSequence(ctx, route.SenderEndpointID, expectedSender.ID)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	wire, err := e2ee.SealEndpointMessage(sender, expectedReceiver, route, plaintext, sequence)
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	stored, _, err := s.StoreOutbound(ctx, operationID, route.SenderEndpointID, expectedSender.ID, wire)
	if errors.Is(err, ErrOutboundConflict) {
		// A competing retry may have persisted the same operation first. Use
		// its exact bytes and sequence; never reseal an accepted operation.
		record, getErr := s.GetOutbound(ctx, operationID, expectedSender.ID)
		if getErr != nil || record.SourceEndpointID != route.SenderEndpointID {
			return OutboundEndpointMessage{}, ErrOutboundConflict
		}
		return outboundFromRecord(record, route, expectedSender, true)
	}
	if err != nil {
		return OutboundEndpointMessage{}, err
	}
	return outboundFromRecord(stored, route, expectedSender, false)
}

// OpenLocalSameGroupMessage authenticates the exact Guard-derived route and
// atomically stores the ciphertext with its replay identity before exposing
// plaintext to the Node's native-session inbox. Duplicate does not mean that
// the model consumed or even received the message.
func (s *CryptoState) OpenLocalSameGroupMessage(ctx context.Context,
	receiver, sender *e2ee.Identity, expectedReceiver, expectedSender e2ee.PublicIdentity,
	route e2ee.EndpointMessageContext, wire []byte) (InboundEndpointMessage, error) {
	if ctx == nil || sender == nil || receiver == nil {
		return InboundEndpointMessage{}, errors.New("local Endpoint identities and context are required")
	}
	if err := validateLocalSameGroupRoute(sender, receiver, expectedSender, expectedReceiver, route); err != nil {
		return InboundEndpointMessage{}, err
	}
	plaintext, sequence, err := e2ee.OpenEndpointMessage(receiver, expectedSender, route, wire)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	duplicate, err := s.AcceptInbound(ctx, route.ReceiverEndpointID, expectedSender.ID,
		route.MessageID, sequence, wire)
	if err != nil {
		return InboundEndpointMessage{}, err
	}
	return InboundEndpointMessage{Plaintext: plaintext, Sequence: sequence, Duplicate: duplicate}, nil
}

func validateLocalSameGroupRoute(sender, receiver *e2ee.Identity,
	expectedSender, expectedReceiver e2ee.PublicIdentity, route e2ee.EndpointMessageContext) error {
	if err := e2ee.ValidatePublicIdentity(expectedSender); err != nil {
		return ErrEndpointKeyIdentity
	}
	if err := e2ee.ValidatePublicIdentity(expectedReceiver); err != nil {
		return ErrEndpointKeyIdentity
	}
	if !samePublicIdentity(sender.Public(), expectedSender) ||
		!samePublicIdentity(receiver.Public(), expectedReceiver) ||
		route.SenderKeyID != expectedSender.ID || route.ReceiverKeyID != expectedReceiver.ID {
		return ErrEndpointKeyIdentity
	}
	if route.SenderEndpointID == route.ReceiverEndpointID ||
		route.SenderGroupID == "" || route.SenderGroupID != route.ReceiverGroupID ||
		route.SenderOwnerID == "" || route.SenderOwnerID != route.ReceiverOwnerID ||
		route.SenderMembershipRevision <= 0 || route.ReceiverMembershipRevision <= 0 ||
		route.SenderBindingEpoch == 0 || route.ReceiverBindingEpoch == 0 ||
		route.LinkID != "" || route.LinkRevision != 0 || route.TransportHubID != "" {
		return ErrEndpointContextScope
	}
	return nil
}
