package fabric

import (
	"errors"

	"github.com/cicada-ai/cicada/internal/store"
)

// Network direct inputs carry only selector IDs and opaque Endpoint-produced
// ciphertext. Sender identity comes from the authenticated Network access
// session and the current owner-bound Node credential, never from these DTOs.
type NetworkDirectSendInput struct {
	NetworkID           string `json:"network_id"`
	NetworkSessionToken string `json:"network_session_token"`
	TargetEndpointID    string `json:"target_endpoint_id"`
	MessageID           string `json:"message_id"`
	IdempotencyKey      string `json:"idempotency_key,omitempty"`
	Ciphertext          []byte `json:"ciphertext"`
}

type NetworkDirectAskInput struct {
	NetworkID           string `json:"network_id"`
	NetworkSessionToken string `json:"network_session_token"`
	TargetEndpointID    string `json:"target_endpoint_id"`
	MessageID           string `json:"message_id"`
	RequestID           string `json:"request_id"`
	ParentRequestID     string `json:"parent_request_id,omitempty"`
	IdempotencyKey      string `json:"idempotency_key,omitempty"`
	ExpiresAt           string `json:"expires_at"`
	Ciphertext          []byte `json:"ciphertext"`
}

type NetworkDirectReplyInput struct {
	NetworkID           string `json:"network_id"`
	NetworkSessionToken string `json:"network_session_token"`
	RequestID           string `json:"request_id"`
	MessageID           string `json:"message_id"`
	IdempotencyKey      string `json:"idempotency_key,omitempty"`
	Ciphertext          []byte `json:"ciphertext"`
}

type NetworkCollaborationSendInput struct {
	NetworkID           string `json:"network_id"`
	NetworkSessionToken string `json:"network_session_token"`
	Purpose             string `json:"purpose"`
	TargetEndpointID    string `json:"target_endpoint_id"`
	MessageID           string `json:"message_id"`
	IdempotencyKey      string `json:"idempotency_key,omitempty"`
	Ciphertext          []byte `json:"ciphertext"`
}

type NetworkDirectDelivery struct {
	store.RelaySealedV1DeliveryAttempt
	NetworkID       string `json:"network_id"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	NodeID          string `json:"node_id"`
}

func (s *Service) NetworkDirectNativeBinding(actor NetworkActor) (*store.NetworkDirectNativeBinding, error) {
	binding, err := s.store.EnsureNetworkDirectNativeBinding(networkDirectoryScope(actor))
	if err == store.ErrNetworkPermission {
		return nil, ErrPermissionDenied
	}
	return binding, err
}

func (s *Service) PublishNetworkDirectKeyCandidate(actor NetworkActor,
	attestation []byte) (*store.NetworkDirectKeyCandidate, error) {
	candidate, err := s.store.RegisterNetworkDirectKeyCandidate(networkDirectoryScope(actor), attestation)
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrPermissionDenied
	}
	return candidate, err
}

func (s *Service) NetworkDirectPeerKey(actor NetworkActor,
	targetEndpointID string) (*store.NetworkDirectPeerBundle, error) {
	bundle, err := s.store.NetworkDirectPeerKey(networkDirectoryScope(actor), targetEndpointID)
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrNotFoundOrNotAuthorized
	}
	return bundle, err
}

func (s *Service) NetworkCollaborationPeerKey(actor NetworkActor,
	targetEndpointID, purpose string) (*store.NetworkDirectPeerBundle, error) {
	bundle, err := s.store.NetworkCollaborationPeerKey(networkDirectoryScope(actor), targetEndpointID, purpose)
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrNotFoundOrNotAuthorized
	}
	return bundle, err
}

func (s *Service) networkDirectSender(nodeToken, sessionToken,
	networkID string) (NetworkActor, error) {
	credential, binding, err := s.store.GetOwnerBoundNodeCredentialByHash(HashSessionCredential(nodeToken))
	if err != nil || credential.Status != store.NodeCredentialActive || binding.State != "ACTIVE" ||
		binding.NodeID != credential.NodeID {
		return NetworkActor{}, ErrUnauthenticated
	}
	actor, err := s.AuthenticateForNetwork(sessionToken, networkID)
	if err != nil {
		return NetworkActor{}, err
	}
	endpoint, err := s.store.GetEndpointV2(actor.EndpointID)
	if err != nil || endpoint.MachineID != credential.NodeID || endpoint.Owner != binding.OwnerID ||
		endpoint.PrincipalID != actor.PrincipalID || endpoint.Status == "left" {
		return NetworkActor{}, ErrPermissionDenied
	}
	return actor, nil
}

func (s *Service) SendNetworkDirectSealed(nodeToken string,
	input NetworkDirectSendInput) (*store.RelaySealedV1Record, error) {
	actor, err := s.networkDirectSender(nodeToken, input.NetworkSessionToken, input.NetworkID)
	if err != nil {
		return nil, err
	}
	record, err := s.store.EnqueueNetworkDirectSealedSend(store.NetworkDirectSendInput{
		Scope: networkDirectoryScope(actor), TargetEndpointID: input.TargetEndpointID,
		MessageID: input.MessageID, IdempotencyKey: input.IdempotencyKey,
		Ciphertext: input.Ciphertext, NodeCredentialDigest: HashSessionCredential(nodeToken)})
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrPermissionDenied
	}
	if err == nil {
		s.notifyNetworkDirectTarget(record.Route.ReceiverEndpointID)
	}
	return record, err
}

func (s *Service) SendNetworkCollaborationSealed(nodeToken string,
	input NetworkCollaborationSendInput) (*store.RelaySealedV1Record, error) {
	actor, err := s.networkDirectSender(nodeToken, input.NetworkSessionToken, input.NetworkID)
	if err != nil {
		return nil, err
	}
	record, err := s.store.EnqueueNetworkCollaborationSealedSend(store.NetworkCollaborationSendInput{
		Scope: networkDirectoryScope(actor), NodeCredentialDigest: HashSessionCredential(nodeToken),
		Purpose: input.Purpose, TargetEndpointID: input.TargetEndpointID,
		MessageID: input.MessageID, IdempotencyKey: input.IdempotencyKey, Ciphertext: input.Ciphertext})
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrPermissionDenied
	}
	if err == nil {
		s.notifyNetworkDirectTarget(record.Route.ReceiverEndpointID)
	}
	return record, err
}

func (s *Service) AskNetworkDirectSealed(nodeToken string,
	input NetworkDirectAskInput) (*store.FabricRequest, error) {
	actor, err := s.networkDirectSender(nodeToken, input.NetworkSessionToken, input.NetworkID)
	if err != nil {
		return nil, err
	}
	request, err := s.store.EnqueueNetworkDirectSealedAsk(store.NetworkDirectAskInput{
		NetworkDirectSendInput: store.NetworkDirectSendInput{
			Scope: networkDirectoryScope(actor), NodeCredentialDigest: HashSessionCredential(nodeToken),
			TargetEndpointID: input.TargetEndpointID, MessageID: input.MessageID,
			IdempotencyKey: input.IdempotencyKey, Ciphertext: input.Ciphertext},
		RequestID: input.RequestID, ParentRequestID: input.ParentRequestID,
		ExpiresAt: input.ExpiresAt})
	if errors.Is(err, store.ErrRelayCausalParentInvalid) {
		return nil, ErrPermissionDenied
	}
	if errors.Is(err, store.ErrRelayCausalCycle) {
		return nil, ErrConflict
	}
	if errors.Is(err, store.ErrRelayCausalBudget) {
		return nil, ErrConflict
	}
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrPermissionDenied
	}
	if err == nil {
		s.notifyNetworkDirectTarget(request.ReceiverEndpointID)
	}
	return request, err
}

func (s *Service) ReplyNetworkDirectSealed(nodeToken string,
	input NetworkDirectReplyInput) (*store.FabricRequest, error) {
	actor, err := s.networkDirectSender(nodeToken, input.NetworkSessionToken, input.NetworkID)
	if err != nil {
		return nil, err
	}
	request, err := s.store.EnqueueNetworkDirectSealedReply(store.NetworkDirectReplyInput{
		Scope: networkDirectoryScope(actor), NodeCredentialDigest: HashSessionCredential(nodeToken),
		RequestID: input.RequestID, MessageID: input.MessageID,
		IdempotencyKey: input.IdempotencyKey, Ciphertext: input.Ciphertext})
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrPermissionDenied
	}
	if err == nil {
		s.notifyNetworkDirectTarget(request.SenderEndpointID)
	}
	return request, err
}

func (s *Service) NetworkDirectReplyPeerKey(nodeToken, networkSessionToken,
	networkID, requestID string) (*store.NetworkDirectReplyRoute, error) {
	actor, err := s.networkDirectSender(nodeToken, networkSessionToken, networkID)
	if err != nil {
		return nil, err
	}
	route, err := s.store.NetworkDirectReplyPeerKey(networkDirectoryScope(actor),
		HashSessionCredential(nodeToken), requestID)
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrPermissionDenied
	}
	return route, err
}

func (s *Service) notifyNetworkDirectTarget(endpointID string) {
	if endpoint, err := s.store.GetEndpointV2(endpointID); err == nil {
		s.notifyNode(endpoint.MachineID)
	}
}

func (s *Service) ClaimNetworkDirectSealed(nodeToken, nodeID string,
	input NodeClaimInput) ([]NetworkDirectDelivery, error) {
	items, err := s.store.ClaimNetworkDirectSealedInbox(store.NetworkDirectClaimInput{
		NodeID: nodeID, ConsumerID: input.ConsumerID, Limit: input.Limit,
		CredentialDigest: HashSessionCredential(nodeToken)})
	if err == store.ErrNetworkPermission {
		return nil, ErrPermissionDenied
	}
	if err != nil {
		return nil, err
	}
	deliveries := make([]NetworkDirectDelivery, 0, len(items))
	for _, item := range items {
		deliveries = append(deliveries, NetworkDirectDelivery{
			RelaySealedV1DeliveryAttempt: item.RelaySealedV1DeliveryAttempt,
			NetworkID:                    item.NetworkID, Harness: item.Harness,
			NativeSessionID: item.NativeSessionID, NodeID: item.NodeID})
	}
	return deliveries, nil
}

func (s *Service) AuthorizeNetworkDirectDelivery(nodeToken, messageID,
	attemptID string) (*store.NetworkDirectDeliveryAuthorization, error) {
	result, err := s.store.AuthorizeClaimedNetworkDirectDelivery(
		HashSessionCredential(nodeToken), messageID, attemptID)
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrPermissionDenied
	}
	return result, err
}

func (s *Service) RecordNetworkDirectReceipt(nodeToken string,
	input NodeReceiptInput) (*store.RelayReceipt, error) {
	receipt, err := s.store.RecordNetworkDirectReceipt(HashSessionCredential(nodeToken),
		store.RelayReceipt{AttemptID: input.AttemptID, MessageID: input.MessageID,
			Digest: input.Digest, TargetEndpointID: input.EndpointID,
			BindingID: input.BindingID, BindingEpoch: input.BindingEpoch,
			Layer: input.Layer, Error: input.Error})
	if err == store.ErrRelayStaleReceipt || err == store.ErrRelayInvalidReceipt ||
		err == store.ErrNetworkPermission {
		return nil, ErrPermissionDenied
	}
	return receipt, err
}

func (s *Service) NetworkDirectRequestStatus(actor NetworkActor,
	requestID string) (*store.FabricRequest, error) {
	request, err := s.store.NetworkDirectRequestStatus(networkDirectoryScope(actor), requestID)
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrPermissionDenied
	}
	return request, err
}

func (s *Service) CancelNetworkDirectRequest(actor NetworkActor,
	requestID, reason string) (*store.FabricRequest, error) {
	request, err := s.store.CancelNetworkDirectRequest(networkDirectoryScope(actor), requestID, reason)
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrPermissionDenied
	}
	return request, err
}
