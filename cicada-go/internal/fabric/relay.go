package fabric

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

// ErrResourceExhausted and ResourceExhaustedError expose relay admission
// failures at the Fabric boundary without making the Fabric package duplicate
// the Store's retry metadata. Callers can use errors.Is/errors.As and inspect
// RetryAfterDuration for a bounded retry delay.
var ErrResourceExhausted = store.ErrRelayResourceExhausted

type ResourceExhaustedError = store.RelayAdmissionError

// validateActorCurrent proves that the transport-authenticated actor still
// owns the active native-session lease. It is intentionally repeated at the
// service boundary so direct in-process callers cannot bypass HTTP auth.
func (s *Service) validateActorCurrent(actor Actor) (*store.SessionBinding, error) {
	if err := actor.Validate(); err != nil {
		return nil, err
	}
	binding, err := s.store.GetSessionBinding(actor.BindingID)
	if err != nil {
		return nil, ErrStaleBinding
	}
	if binding.EndpointID != actor.EndpointID || binding.PrincipalID != actor.PrincipalID {
		return nil, ErrPermissionDenied
	}
	if binding.Epoch != actor.BindingEpoch || binding.LeaseOwner != actor.LeaseOwner {
		return nil, ErrStaleBinding
	}
	if err := s.store.ValidateSessionBindingLease(binding.ID, binding.LeaseOwner, binding.Epoch); err != nil {
		return nil, ErrStaleBinding
	}
	endpoint, err := s.store.GetEndpointV2(actor.EndpointID)
	if err != nil || endpoint.MigrationState != store.EndpointMigrationReady || endpoint.BindingID != binding.ID ||
		endpoint.PrincipalID != actor.PrincipalID || endpoint.Status == "left" {
		return nil, ErrStaleBinding
	}
	if endpoint.Owner != s.ownerID {
		// Guest sessions are valid only while their Node remains bound to the
		// same owner. Revoking the Node cannot leave behind an independently
		// usable Fabric Session token.
		principal, principalErr := s.store.GetPrincipal(actor.PrincipalID)
		nodeOwner, nodeErr := s.store.CurrentBoundNodeOwner(binding.NodeID)
		if principalErr != nil || principal.Status != store.PrincipalStatusActive ||
			principal.OwnerID != endpoint.Owner || endpoint.MachineID != binding.NodeID ||
			nodeErr != nil || nodeOwner != endpoint.Owner {
			return nil, ErrStaleBinding
		}
	}
	joined, err := s.store.IsEndpointGroupActive(actor.EndpointID, actor.GroupID)
	if err != nil || !joined {
		return nil, ErrPermissionDenied
	}
	if err := s.store.NetworkGuardGroup(actor.PrincipalID, actor.EndpointID, actor.GroupID, actor.NetworkID); err != nil {
		return nil, ErrPermissionDenied
	}
	return binding, nil
}

func (s *Service) resolvePeer(actor Actor, query string) (*NetworkCard, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("target is required")
	}
	// A stable ID is an explicit routing attempt. Report the policy denial
	// without exposing other members of the foreign group. Alias searches stay
	// group-scoped and return the indistinguishable not-found result.
	if endpoint, err := s.store.GetEndpointV2(query); err == nil && endpoint != nil &&
		endpoint.MigrationState == store.EndpointMigrationReady {
		joined, joinedErr := s.store.IsEndpointGroupActive(endpoint.ID, actor.GroupID)
		if joinedErr != nil {
			return nil, joinedErr
		}
		if !joined {
			return nil, ErrCrossGroupDirectDenied
		}
	}
	card, err := s.Resolve(actor, ResolveInput{Query: query})
	if err != nil {
		return nil, err
	}
	if card.EndpointID == actor.EndpointID {
		return nil, errors.New("fabric peer message requires two different endpoints")
	}
	return card, nil
}

func validateMessageBody(body string) (string, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return "", errors.New("message body is required")
	}
	if len([]byte(body)) > MaxMessageBytes {
		return "", fmt.Errorf("message body exceeds %d bytes", MaxMessageBytes)
	}
	return body, nil
}

// rejectPlaintextPeerIfSealed checks the current authoritative capability on
// both route endpoints. The Store repeats this check inside the write
// transaction to close the capability-update/write race; this early check
// keeps the Fabric boundary's denial behavior explicit for HTTP callers.
func (s *Service) rejectPlaintextPeerIfSealed(sourceEndpointID, targetEndpointID string) error {
	seen := make(map[string]struct{}, 2)
	for _, endpointID := range []string{sourceEndpointID, targetEndpointID} {
		endpointID = strings.TrimSpace(endpointID)
		if endpointID == "" {
			return ErrPermissionDenied
		}
		if _, ok := seen[endpointID]; ok {
			continue
		}
		seen[endpointID] = struct{}{}
		endpoint, err := s.store.GetEndpointV2(endpointID)
		if err != nil || endpoint == nil {
			return ErrPermissionDenied
		}
		if _, present := endpoint.Capabilities["local_peer_delivery"]; present {
			return fmt.Errorf("%w: endpoint has a peer-delivery capability that disallows plaintext", ErrPermissionDenied)
		}
	}
	return nil
}

func validateExpiry(raw string, current time.Time) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, raw)
	}
	if err != nil || !parsed.After(current) {
		return "", errors.New("expires_at must be a future RFC3339 timestamp")
	}
	return parsed.UTC().Format(time.RFC3339Nano), nil
}

func (s *Service) Send(actor Actor, input SendInput) (*store.RelayMessageRecord, error) {
	if err := s.Authorize(actor, "message.send"); err != nil {
		return nil, err
	}
	body, err := validateMessageBody(input.Body)
	if err != nil {
		return nil, err
	}
	expiresAt, err := validateExpiry(input.ExpiresAt, s.now())
	if err != nil {
		return nil, err
	}
	target, err := s.resolvePeer(actor, input.Target)
	if err != nil {
		return nil, err
	}
	if err := s.rejectPlaintextPeerIfSealed(actor.EndpointID, target.EndpointID); err != nil {
		return nil, err
	}
	record, err := s.store.EnqueueRelayMessage(store.RelayMessageInput{
		Message: store.FabricMessage{
			FromEndpointID: actor.EndpointID, ToEndpointID: target.EndpointID,
			Kind: "send", Body: body, Metadata: input.Metadata,
		},
		Security: store.RelayMessageSecurity{
			SenderEndpointID: actor.EndpointID, SenderPrincipalID: actor.PrincipalID,
			SenderGroupID: actor.GroupID, SenderBindingID: actor.BindingID,
			SenderBindingEpoch: actor.BindingEpoch, ReceiverEndpointID: target.EndpointID,
			ReceiverPrincipalID: target.PrincipalID, ReceiverGroupID: target.GroupID,
			ReceiverBindingID: target.BindingID, ReceiverBindingEpoch: target.BindingEpoch,
			AuthorizationRef: actor.MembershipID,
		},
		IdempotencyKey: strings.TrimSpace(input.IdempotencyKey), ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, mapRelayError(err)
	}
	s.notifyNode(target.NodeID)
	return record, nil
}

func (s *Service) Ask(actor Actor, input AskInput) (*RequestView, error) {
	if err := s.Authorize(actor, "message.ask"); err != nil {
		return nil, err
	}
	body, err := validateMessageBody(input.Question)
	if err != nil {
		return nil, err
	}
	expiresAt, err := validateExpiry(input.ExpiresAt, s.now())
	if err != nil {
		return nil, err
	}
	target, err := s.resolvePeer(actor, input.Target)
	if err != nil {
		return nil, err
	}
	if err := s.rejectPlaintextPeerIfSealed(actor.EndpointID, target.EndpointID); err != nil {
		return nil, err
	}
	request, err := s.store.CreateFabricRequest(store.FabricRequest{
		SenderEndpointID: actor.EndpointID, SenderPrincipalID: actor.PrincipalID,
		SenderGroupID: actor.GroupID, SenderBindingID: actor.BindingID,
		SenderBindingEpoch: actor.BindingEpoch, ReceiverEndpointID: target.EndpointID,
		ReceiverPrincipalID: target.PrincipalID, ReceiverGroupID: target.GroupID,
		ReceiverBindingID: target.BindingID, ReceiverBindingEpoch: target.BindingEpoch,
		IdempotencyKey: strings.TrimSpace(input.IdempotencyKey), ExpiresAt: expiresAt,
		AuthorizationRef: actor.MembershipID, Body: body, Metadata: input.Metadata,
	})
	if err != nil {
		return nil, mapRelayError(err)
	}
	s.notifyNode(target.NodeID)
	return requestView(request), nil
}

func (s *Service) Reply(actor Actor, input ReplyInput) (*RequestView, error) {
	if err := s.Authorize(actor, "message.reply"); err != nil {
		return nil, err
	}
	body, err := validateMessageBody(input.Body)
	if err != nil {
		return nil, err
	}
	request, err := s.store.GetRelayFabricRequest(strings.TrimSpace(input.RequestID))
	if err != nil || request == nil {
		return nil, ErrNotFoundOrNotAuthorized
	}
	if request.ReceiverEndpointID != actor.EndpointID || request.ReceiverPrincipalID != actor.PrincipalID ||
		request.ReceiverGroupID != actor.GroupID {
		return nil, ErrPermissionDenied
	}
	if err := s.rejectPlaintextPeerIfSealed(actor.EndpointID, request.SenderEndpointID); err != nil {
		return nil, err
	}
	updated, err := s.store.SubmitFabricReply(store.FabricReply{
		RequestID: request.RequestID, ResponderEndpointID: actor.EndpointID,
		ResponderPrincipalID: actor.PrincipalID, ResponderGroupID: actor.GroupID,
		ReceiverBindingID: request.SenderBindingID, ReceiverBindingEpoch: request.SenderBindingEpoch,
		Body: body, Metadata: input.Metadata, IdempotencyKey: strings.TrimSpace(input.IdempotencyKey),
	})
	if err != nil {
		return nil, mapRelayError(err)
	}
	// The original requester may have rejoined on another Node. The durable
	// reply was committed above; resolve its current locator only for the hint.
	if sender, lookupErr := s.store.GetEndpointV2(request.SenderEndpointID); lookupErr == nil {
		s.notifyNode(sender.MachineID)
	}
	return requestView(updated), nil
}

func (s *Service) Request(actor Actor, requestID string) (*RequestView, error) {
	if _, err := s.validateActorCurrent(actor); err != nil {
		return nil, err
	}
	request, err := s.store.GetRelayFabricRequest(strings.TrimSpace(requestID))
	if err != nil || request == nil {
		return nil, ErrNotFoundOrNotAuthorized
	}
	if !(request.SenderEndpointID == actor.EndpointID && request.SenderGroupID == actor.GroupID) &&
		!(request.ReceiverEndpointID == actor.EndpointID && request.ReceiverGroupID == actor.GroupID) {
		return nil, ErrNotFoundOrNotAuthorized
	}
	return requestView(request), nil
}

func (s *Service) CancelRequest(actor Actor, input RequestCancelInput) (*RequestView, error) {
	if _, err := s.validateActorCurrent(actor); err != nil {
		return nil, err
	}
	request, err := s.store.GetRelayFabricRequest(strings.TrimSpace(input.RequestID))
	if err != nil || request == nil {
		return nil, ErrNotFoundOrNotAuthorized
	}
	if request.SenderEndpointID != actor.EndpointID || request.SenderPrincipalID != actor.PrincipalID ||
		request.SenderGroupID != actor.GroupID {
		return nil, ErrPermissionDenied
	}
	updated, err := s.store.RequestFabricRequestCancellation(request.RequestID, strings.TrimSpace(input.Reason))
	if err != nil {
		return nil, mapRelayError(err)
	}
	return requestView(updated), nil
}

// Receive is a non-destructive authenticated mailbox view. Node delivery uses
// the claim/receipt API; reading from a model tool never pretends the runtime
// consumed or acknowledged a message.
func (s *Service) Receive(actor Actor, input ReceiveInput) (*ReceiveResult, error) {
	if err := s.Authorize(actor, "message.receive"); err != nil {
		return nil, err
	}
	result, err := s.store.ReceiveRelayInboxForBindingGroup(actor.EndpointID,
		"session:"+actor.BindingID+":"+actor.GroupID, actor.BindingID, actor.BindingEpoch,
		actor.GroupID, strings.TrimSpace(input.Cursor), input.Limit)
	if err != nil {
		return nil, mapRelayError(err)
	}
	return &ReceiveResult{Messages: result.Messages, NextCursor: result.NextCursor}, nil
}

// ClaimNodeDeliveries is the transport boundary used by a machine-side Node
// Agent. It routes by the Directory's verified SessionBinding and never calls
// Control planning, scheduling, intent, or reporting code.
func (s *Service) ClaimNodeDeliveries(nodeID string, input NodeClaimInput) ([]Delivery, error) {
	nodeID = strings.TrimSpace(nodeID)
	input.ConsumerID = strings.TrimSpace(input.ConsumerID)
	if nodeID == "" || input.ConsumerID == "" {
		return nil, errors.New("node_id and consumer_id are required")
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
	deliveries := make([]Delivery, 0, input.Limit)
	for _, endpoint := range endpoints {
		if len(deliveries) >= input.Limit {
			break
		}
		if endpoint.Status == "left" {
			continue
		}
		binding, bindErr := s.store.GetActiveSessionBinding(endpoint.ID)
		if bindErr != nil || binding.NodeID != nodeID || binding.ID != endpoint.BindingID {
			continue
		}
		if leaseErr := s.store.ValidateSessionBindingLease(binding.ID, binding.LeaseOwner, binding.Epoch); leaseErr != nil {
			continue
		}
		attempts, claimErr := s.store.ClaimRelayInbox(store.RelayClaimInput{
			RecipientEndpointID: endpoint.ID, ConsumerID: input.ConsumerID,
			BindingID: binding.ID, BindingEpoch: binding.Epoch,
			Limit: input.Limit - len(deliveries),
		})
		if errors.Is(claimErr, store.ErrRelayNoDelivery) {
			continue
		}
		if claimErr != nil {
			return nil, mapRelayError(claimErr)
		}
		for _, attempt := range attempts {
			if attempt.Message == nil {
				continue
			}
			deliveries = append(deliveries, Delivery{
				MessageID: attempt.MessageID, RequestID: attempt.Message.RequestID,
				SenderEndpointID: attempt.Message.FromEndpointID, ReplyTo: attempt.Message.ReplyTo,
				Kind: attempt.Message.Kind, Digest: attempt.Digest, EndpointID: endpoint.ID,
				GroupID: attempt.ReceiverGroupID, BindingID: binding.ID, BindingEpoch: binding.Epoch,
				Harness: endpoint.Harness, NativeSessionID: binding.NativeSessionID,
				NodeID: nodeID, AttemptID: attempt.AttemptID, Body: attempt.Message.Body,
			})
		}
	}
	return deliveries, nil
}

func (s *Service) RecordNodeReceipt(nodeID string, input NodeReceiptInput) (*store.RelayReceipt, error) {
	nodeID = strings.TrimSpace(nodeID)
	input.AttemptID = strings.TrimSpace(input.AttemptID)
	input.MessageID = strings.TrimSpace(input.MessageID)
	input.Digest = strings.TrimSpace(input.Digest)
	input.EndpointID = strings.TrimSpace(input.EndpointID)
	input.BindingID = strings.TrimSpace(input.BindingID)
	input.Layer = strings.TrimSpace(input.Layer)
	switch strings.TrimSpace(input.Layer) {
	case ReceiptNodeReceived, ReceiptCodexQueueAccepted, ReceiptNativeThreadResumed,
		ReceiptRuntimeInjected, ReceiptConsumptionUncertain,
		ReceiptInjectionUncertain, ReceiptFailed:
		// These receipt layers describe durable Node inbox and runtime facts.
	default:
		// Application acknowledgement and result acceptance belong to the
		// receiving application/session, not to the machine-level Node bearer.
		return nil, ErrPermissionDenied
	}
	endpoint, err := s.store.GetEndpointV2(input.EndpointID)
	if err != nil || endpoint.MigrationState != store.EndpointMigrationReady {
		return nil, ErrPermissionDenied
	}
	binding, err := s.store.GetSessionBinding(input.BindingID)
	if err != nil || binding.EndpointID != endpoint.ID {
		return nil, ErrStaleBinding
	}
	if binding.NodeID != nodeID {
		return nil, ErrPermissionDenied
	}
	currentBinding := binding.Epoch == input.BindingEpoch && endpoint.MachineID == nodeID && endpoint.BindingID == binding.ID &&
		s.store.ValidateSessionBindingLease(binding.ID, binding.LeaseOwner, binding.Epoch) == nil
	if !currentBinding {
		// Exact duplicate historical receipts are harmless to return. A stale
		// binding may otherwise report only uncertainty for a Node-received
		// attempt; it cannot first claim queueing, resume, injection, or
		// consumption after its authority expired.
		coordinates := store.RelayReceipt{
			AttemptID: input.AttemptID, MessageID: input.MessageID, Digest: input.Digest,
			TargetEndpointID: endpoint.ID, BindingID: binding.ID,
			BindingEpoch: input.BindingEpoch,
		}
		exactDuplicate, err := s.store.HasRelayReceiptForAttempt(store.RelayReceipt{
			AttemptID: coordinates.AttemptID, MessageID: coordinates.MessageID, Digest: coordinates.Digest,
			TargetEndpointID: coordinates.TargetEndpointID, BindingID: coordinates.BindingID,
			BindingEpoch: coordinates.BindingEpoch, Layer: input.Layer,
		})
		if err != nil {
			return nil, err
		}
		if !exactDuplicate {
			if input.Layer != ReceiptInjectionUncertain {
				return nil, ErrStaleBinding
			}
			coordinates.Layer = ReceiptNodeReceived
			seenNodeReceived, err := s.store.HasRelayReceiptForAttempt(coordinates)
			if err != nil {
				return nil, err
			}
			if !seenNodeReceived {
				return nil, ErrStaleBinding
			}
		}
	}
	receipt, err := s.store.RecordRelayReceipt(store.RelayReceipt{
		AttemptID: input.AttemptID, MessageID: input.MessageID,
		Digest: input.Digest, TargetEndpointID: endpoint.ID,
		BindingID: binding.ID, BindingEpoch: input.BindingEpoch, Layer: input.Layer,
		Error: strings.TrimSpace(input.Error),
	})
	if err != nil {
		return nil, mapRelayError(err)
	}
	return receipt, nil
}

func requestView(request *store.FabricRequest) *RequestView {
	if request == nil {
		return nil
	}
	delivery := "RELAY_ACCEPTED"
	if request.State == store.FabricRequestReplied || request.State == store.FabricRequestLateResult {
		delivery = "RESULT_ACCEPTED"
	}
	view := &RequestView{
		RequestID: request.RequestID, MessageID: request.MessageID,
		SenderEndpointID: request.SenderEndpointID, SenderGroupID: request.SenderGroupID,
		State:    request.State,
		Delivery: delivery, ReplyMode: "asynchronous", ExpiresAt: request.ExpiresAt,
		CancelledAt: request.CancelledAt, ReplyMessageID: request.ReplyMessageID,
		LateReply: request.State == store.FabricRequestLateResult,
	}
	switch request.State {
	case store.FabricRequestOpen:
		view.NextAction = "receive correlated reply later"
	case store.FabricRequestCancelRequested:
		view.NextAction = "wait for runtime cancellation outcome"
	}
	return view
}

func mapRelayError(err error) error {
	switch {
	case errors.Is(err, store.ErrRelayResourceExhausted):
		return err
	case errors.Is(err, store.ErrRelayIdempotencyConflict), errors.Is(err, store.ErrRelayMessageConflict):
		return fmt.Errorf("%w: %v", ErrConflict, err)
	case errors.Is(err, store.ErrRelayBindingMismatch), errors.Is(err, store.ErrRelayStaleReceipt):
		return fmt.Errorf("%w: %v", ErrStaleBinding, err)
	case errors.Is(err, store.ErrRelayRequestTerminal):
		return fmt.Errorf("%w: %v", ErrRequestTerminal, err)
	case errors.Is(err, store.ErrRelayPlaintextSealedPeer):
		return fmt.Errorf("%w: %v", ErrPermissionDenied, err)
	case errors.Is(err, store.ErrRelayRequestNotFound), errors.Is(err, store.ErrRelayMessageNotFound):
		return ErrNotFoundOrNotAuthorized
	default:
		return err
	}
}
