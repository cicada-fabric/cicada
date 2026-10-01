package fabric

import (
	"errors"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

// NodeSameGroupSealedV1SendInput contains routing selectors and opaque bytes,
// but no caller-controlled sender identity or route authorization. Store
// verifies that the Node credential currently owns SourceEndpointID and that
// both endpoints remain authorized in GroupID.
type NodeSameGroupSealedV1SendInput struct {
	GroupID          string `json:"group_id"`
	SourceEndpointID string `json:"source_endpoint_id"`
	TargetEndpointID string `json:"target_endpoint_id"`
	MessageID        string `json:"message_id"`
	IdempotencyKey   string `json:"idempotency_key,omitempty"`
	DataScope        string `json:"data_scope"`
	Ciphertext       []byte `json:"ciphertext"`
}

type NodeSameGroupSealedV1AskInput struct {
	GroupID          string `json:"group_id"`
	SourceEndpointID string `json:"source_endpoint_id"`
	TargetEndpointID string `json:"target_endpoint_id"`
	MessageID        string `json:"message_id"`
	RequestID        string `json:"request_id"`
	ParentRequestID  string `json:"parent_request_id,omitempty"`
	IdempotencyKey   string `json:"idempotency_key,omitempty"`
	DataScope        string `json:"data_scope"`
	ExpiresAt        string `json:"expires_at"`
	Ciphertext       []byte `json:"ciphertext"`
}

// Reply identities, group, data scope, and destination are derived from the
// durable Ask by Store. A responder cannot substitute route fields.
type NodeSameGroupSealedV1ReplyInput struct {
	RequestID      string `json:"request_id"`
	MessageID      string `json:"message_id"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Ciphertext     []byte `json:"ciphertext"`
}

func (s *Service) SendNodeSameGroupSealedV1Message(nodeToken string,
	input NodeSameGroupSealedV1SendInput) (*store.RelaySealedV1Record, error) {
	record, err := s.store.EnqueueSameGroupSealedV1Send(store.SameGroupSealedV1Send{
		NodeCredentialDigest: HashSessionCredential(nodeToken),
		GroupID:              input.GroupID, SourceEndpointID: input.SourceEndpointID,
		TargetEndpointID: input.TargetEndpointID, MessageID: input.MessageID,
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

func (s *Service) AskNodeSameGroupSealedV1Message(nodeToken string,
	input NodeSameGroupSealedV1AskInput) (*store.FabricRequest, error) {
	request, err := s.store.EnqueueSameGroupSealedV1Ask(store.SameGroupSealedV1Ask{
		NodeCredentialDigest: HashSessionCredential(nodeToken),
		GroupID:              input.GroupID, SourceEndpointID: input.SourceEndpointID,
		TargetEndpointID: input.TargetEndpointID, MessageID: input.MessageID,
		RequestID: input.RequestID, ParentRequestID: input.ParentRequestID,
		IdempotencyKey: input.IdempotencyKey,
		DataScope:      input.DataScope, ExpiresAt: input.ExpiresAt,
		Ciphertext: input.Ciphertext,
	})
	if err != nil {
		return nil, err
	}
	if target, err := s.store.GetEndpointV2(request.ReceiverEndpointID); err == nil {
		s.notifyNode(target.MachineID)
	}
	return request, nil
}

func (s *Service) ReplyNodeSameGroupSealedV1Message(nodeToken string,
	input NodeSameGroupSealedV1ReplyInput) (*store.FabricRequest, error) {
	request, err := s.store.EnqueueSameGroupSealedV1Reply(store.SameGroupSealedV1Reply{
		NodeCredentialDigest: HashSessionCredential(nodeToken),
		RequestID:            input.RequestID, MessageID: input.MessageID,
		IdempotencyKey: input.IdempotencyKey, Ciphertext: input.Ciphertext,
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

func (s *Service) NodeSameGroupSealedV1RequestStatus(nodeToken, requestID string) (*store.FabricRequest, error) {
	return s.store.GetSameGroupSealedV1RequestStatus(HashSessionCredential(nodeToken), requestID)
}

func (s *Service) CancelNodeSameGroupSealedV1Request(nodeToken, requestID string) (*store.FabricRequest, error) {
	return s.store.CancelSameGroupSealedV1Request(HashSessionCredential(nodeToken), requestID)
}

func (s *Service) NodeSameGroupSealedV1PeerKey(nodeToken, groupID, sourceEndpointID,
	targetEndpointID string) (*store.SameGroupSealedV1PeerKey, error) {
	return s.store.GetSameGroupSealedV1PeerKey(HashSessionCredential(nodeToken),
		groupID, sourceEndpointID, targetEndpointID)
}

// ClaimNodeSameGroupSealedV1Deliveries only examines Endpoint bindings on the
// authenticated Node and its owner. Store claims each item in a transaction
// that revalidates the current Group grants and rejects stale route evidence.
func (s *Service) ClaimNodeSameGroupSealedV1Deliveries(nodeToken, nodeID string,
	input NodeClaimInput) ([]NodeSealedDelivery, error) {
	nodeID = strings.TrimSpace(nodeID)
	input.ConsumerID = strings.TrimSpace(input.ConsumerID)
	if nodeID == "" || input.ConsumerID == "" {
		return nil, errors.New("node_id and consumer_id are required")
	}
	digest := HashSessionCredential(nodeToken)
	credential, ownerBinding, err := s.store.GetOwnerBoundNodeCredentialByHash(digest)
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
		attempts, err := s.store.ClaimSameGroupSealedV1Inbox(digest, store.RelayClaimInput{
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

// AuthorizeNodeSameGroupSealedV1Delivery is the final server-side guard before
// injection. The Store binds the current Node credential to the receiving
// side, then rechecks the exact claimed attempt, Group memberships, bindings,
// owner grants, and route snapshot in one transaction.
func (s *Service) AuthorizeNodeSameGroupSealedV1Delivery(nodeToken,
	messageID, attemptID string) (*store.SameGroupSealedV1DeliveryAuthorization, error) {
	return s.store.AuthorizeClaimedSameGroupSealedV1Delivery(
		HashSessionCredential(nodeToken), messageID, attemptID)
}
