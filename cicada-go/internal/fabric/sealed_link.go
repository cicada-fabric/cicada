package fabric

import (
	"errors"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

// NodeSealedLinkSendInput contains no caller identity. The current Node
// credential and the durable Link determine every route identity and scope.
type NodeSealedLinkSendInput struct {
	LinkID         string `json:"link_id"`
	MessageID      string `json:"message_id"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	DataScope      string `json:"data_scope"`
	Ciphertext     []byte `json:"ciphertext"`
}

type NodeSealedLinkAskInput struct {
	LinkID         string `json:"link_id"`
	MessageID      string `json:"message_id"`
	RequestID      string `json:"request_id"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	DataScope      string `json:"data_scope"`
	ExpiresAt      string `json:"expires_at"`
	Ciphertext     []byte `json:"ciphertext"`
}

type NodeSealedLinkReplyInput struct {
	RequestID      string `json:"request_id"`
	MessageID      string `json:"message_id"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	DataScope      string `json:"data_scope"`
	Ciphertext     []byte `json:"ciphertext"`
}

type NodeSealedDelivery struct {
	store.RelaySealedV1DeliveryAttempt
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	NodeID          string `json:"node_id"`
}

// SendNodeSealedLinkMessage accepts one endpoint-sealed SEND. Control's
// management services are absent from this path; the Store transaction checks
// both owner grants and the exact key-bound Link before committing the bytes.
func (s *Service) SendNodeSealedLinkMessage(nodeToken string, input NodeSealedLinkSendInput) (*store.RelaySealedV1Record, error) {
	record, err := s.store.EnqueueCommunicationLinkSealedSend(store.CommunicationLinkSealedSend{
		NodeCredentialDigest: HashSessionCredential(nodeToken),
		LinkID:               input.LinkID, MessageID: input.MessageID,
		IdempotencyKey: input.IdempotencyKey, DataScope: input.DataScope,
		Ciphertext: input.Ciphertext,
	})
	if err != nil {
		return nil, err
	}
	if target, err := s.store.GetEndpointV2(record.Route.ReceiverEndpointID); err == nil {
		s.notifyNode(target.MachineID)
	}
	return record, nil
}

// AskNodeSealedLinkMessage accepts one asynchronous, endpoint-encrypted
// REQUEST. The Store derives both actors from the current Node credential and
// Link, and atomically creates the Relay item and request lifecycle.
func (s *Service) AskNodeSealedLinkMessage(nodeToken string, input NodeSealedLinkAskInput) (*store.FabricRequest, error) {
	request, err := s.store.EnqueueCommunicationLinkSealedAsk(store.CommunicationLinkSealedAsk{
		NodeCredentialDigest: HashSessionCredential(nodeToken),
		LinkID:               input.LinkID, MessageID: input.MessageID, RequestID: input.RequestID,
		IdempotencyKey: input.IdempotencyKey, DataScope: input.DataScope,
		ExpiresAt: input.ExpiresAt, Ciphertext: input.Ciphertext,
	})
	if err != nil {
		return nil, err
	}
	if target, err := s.store.GetEndpointV2(request.ReceiverEndpointID); err == nil {
		s.notifyNode(target.MachineID)
	}
	return request, nil
}

// ReplyNodeSealedLinkMessage accepts only the original responder's encrypted
// reply. Late evidence is persisted but never notifies or wakes the requester.
func (s *Service) ReplyNodeSealedLinkMessage(nodeToken string, input NodeSealedLinkReplyInput) (*store.FabricRequest, error) {
	request, err := s.store.EnqueueCommunicationLinkSealedReply(store.CommunicationLinkSealedReply{
		NodeCredentialDigest: HashSessionCredential(nodeToken),
		RequestID:            input.RequestID, MessageID: input.MessageID,
		IdempotencyKey: input.IdempotencyKey, DataScope: input.DataScope,
		Ciphertext: input.Ciphertext,
	})
	if err != nil {
		return nil, err
	}
	if request.State == store.FabricRequestReplied {
		if target, err := s.store.GetEndpointV2(request.SenderEndpointID); err == nil {
			s.notifyNode(target.MachineID)
		}
	}
	return request, nil
}

func (s *Service) NodeSealedLinkRequestStatus(nodeToken, requestID string) (*store.FabricRequest, error) {
	return s.store.GetCommunicationLinkSealedRequestForNodeCredential(
		HashSessionCredential(nodeToken), requestID)
}

func (s *Service) CancelNodeSealedLinkRequest(nodeToken, requestID, reason string) (*store.FabricRequest, error) {
	return s.store.RequestCommunicationLinkSealedAskCancellation(
		HashSessionCredential(nodeToken), requestID, reason)
}

// ClaimNodeSealedDeliveries exposes ciphertext only to the currently bound
// receiver Node. The Store repeats the Link/grant check inside each claim
// transaction, fencing queued bytes when consent or a binding becomes stale.
func (s *Service) ClaimNodeSealedDeliveries(nodeToken, nodeID string, input NodeClaimInput) ([]NodeSealedDelivery, error) {
	nodeID = strings.TrimSpace(nodeID)
	input.ConsumerID = strings.TrimSpace(input.ConsumerID)
	if nodeID == "" || input.ConsumerID == "" {
		return nil, errors.New("node_id and consumer_id are required")
	}
	credential, ownerBinding, err := s.store.GetOwnerBoundNodeCredentialByHash(HashSessionCredential(nodeToken))
	if err != nil || credential.NodeID != nodeID || ownerBinding.NodeID != nodeID ||
		credential.Status != store.NodeCredentialActive || ownerBinding.State != "ACTIVE" {
		return nil, ErrUnauthenticated
	}
	if input.Limit <= 0 || input.Limit > 100 {
		input.Limit = 50
	}
	if _, _, err := s.store.RecoverStaleRelayClaims(s.now().UTC().Add(-2 * time.Minute)); err != nil {
		return nil, err
	}
	endpoints, err := s.store.ListEndpointsV2(store.EndpointV2Filter{
		NodeID: nodeID, MigrationState: store.EndpointMigrationReady, Limit: 1000,
	})
	if err != nil {
		return nil, err
	}
	deliveries := make([]NodeSealedDelivery, 0, input.Limit)
	for _, endpoint := range endpoints {
		if len(deliveries) >= input.Limit {
			break
		}
		if endpoint.Status == "left" || endpoint.Owner != ownerBinding.OwnerID {
			continue
		}
		binding, err := s.store.GetActiveSessionBinding(endpoint.ID)
		if err != nil || binding.NodeID != nodeID || binding.ID != endpoint.BindingID {
			continue
		}
		if err := s.store.ValidateSessionBindingLease(binding.ID, binding.LeaseOwner, binding.Epoch); err != nil {
			continue
		}
		attempts, err := s.store.ClaimRelaySealedV1Inbox(store.RelayClaimInput{
			RecipientEndpointID: endpoint.ID, ConsumerID: input.ConsumerID,
			BindingID: binding.ID, BindingEpoch: binding.Epoch,
			Limit: input.Limit - len(deliveries),
		})
		if errors.Is(err, store.ErrRelayNoDelivery) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, attempt := range attempts {
			deliveries = append(deliveries, NodeSealedDelivery{
				RelaySealedV1DeliveryAttempt: attempt,
				Harness:                      endpoint.Harness, NativeSessionID: binding.NativeSessionID,
				NodeID: nodeID,
			})
		}
	}
	return deliveries, nil
}

// AuthorizeNodeSealedDelivery rechecks the exact claimed attempt immediately
// before a Node opens its ciphertext or wakes a native session. The returned
// public bundle is evidence for the Node's independent owner-key verifier,
// not a substitute for that verification.
func (s *Service) AuthorizeNodeSealedDelivery(nodeToken, messageID, attemptID string) (*store.CommunicationLinkSealedDeliveryAuthorization, error) {
	return s.store.AuthorizeClaimedCommunicationLinkSealedSend(
		HashSessionCredential(nodeToken), messageID, attemptID)
}
