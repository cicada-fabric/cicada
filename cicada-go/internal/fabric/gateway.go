package fabric

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func representativeOwner(actor Actor) string { return "binding:" + actor.BindingID }

func (s *Service) representativeForActor(actor Actor, assignmentID string) (*store.RepresentativeAssignment, error) {
	if err := s.Authorize(actor, "federation.represent"); err != nil {
		return nil, err
	}
	assignment, err := s.store.GetRepresentativeAssignment(strings.TrimSpace(assignmentID))
	if err != nil || assignment.EndpointID != actor.EndpointID || assignment.PrincipalID != actor.PrincipalID || assignment.GroupID != actor.GroupID {
		return nil, ErrPermissionDenied
	}
	return assignment, nil
}

func (s *Service) ClaimRepresentation(actor Actor, assignmentID string, leaseSeconds int) (*store.RepresentativeAssignment, error) {
	assignment, err := s.representativeForActor(actor, assignmentID)
	if err != nil {
		return nil, err
	}
	duration := time.Duration(leaseSeconds) * time.Second
	if duration <= 0 {
		duration = 5 * time.Minute
	}
	if duration > time.Hour {
		duration = time.Hour
	}
	claimed, err := s.store.ClaimRepresentative(store.RepresentativeClaimInput{
		AssignmentID: assignment.ID, OwnerID: representativeOwner(actor),
		LeaseExpiresAt: s.now().UTC().Add(duration).Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, mapGatewayError(err)
	}
	return claimed, nil
}

// Federate is called by the authorized source representative after a Worker
// has asked it locally. The original local request is the durable A -> MA leg;
// this method verifies it, persists the bilateral contract request, and only
// then emits the MA -> MB Relay envelope.
func (s *Service) Federate(actor Actor, input FederateInput) (*store.FederationRequest, error) {
	sourceRep, err := s.representativeForActor(actor, input.SourceRepresentativeAssignmentID)
	if err != nil {
		return nil, err
	}
	if err := s.store.ValidateRepresentativeOwner(sourceRep.ID, representativeOwner(actor), sourceRep.Epoch); err != nil {
		return nil, mapGatewayError(err)
	}
	if len(input.ArtifactRefs) != 0 {
		if err := s.ValidateGatewayArtifactRefs(actor, input.TargetGroupID, input.ArtifactRefs, nil); err != nil {
			return nil, err
		}
	}
	origin, err := s.store.GetRelayFabricRequest(strings.TrimSpace(input.OriginRequestID))
	if err != nil || origin == nil || origin.ReceiverEndpointID != actor.EndpointID ||
		origin.ReceiverPrincipalID != actor.PrincipalID || origin.ReceiverGroupID != actor.GroupID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	originMessage, err := s.store.GetRelayMessage(origin.MessageID)
	if err != nil || originMessage == nil {
		return nil, ErrNotFoundOrNotAuthorized
	}
	targetRep, err := s.store.GetRepresentativeAssignment(strings.TrimSpace(input.TargetRepresentativeAssignmentID))
	if err != nil || targetRep.GroupID != strings.TrimSpace(input.TargetGroupID) {
		return nil, ErrNotFoundOrNotAuthorized
	}
	targetEndpoint, err := s.store.GetEndpointV2(targetRep.EndpointID)
	if err != nil || targetEndpoint.MigrationState != store.EndpointMigrationReady || targetEndpoint.GroupID != targetRep.GroupID || targetEndpoint.PrincipalID != targetRep.PrincipalID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	targetBinding, err := s.store.GetActiveSessionBinding(targetEndpoint.ID)
	if err != nil {
		return nil, ErrRepresentativeUnavailable
	}
	request, err := s.store.CreateFederationRequest(store.FederationRequest{
		OriginRequestID: origin.RequestID, SourceGroupID: actor.GroupID,
		TargetGroupID: targetRep.GroupID, SourceRepresentativeEndpointID: actor.EndpointID,
		TargetRepresentativeEndpointID:   targetRep.EndpointID,
		SourceRepresentativeAssignmentID: sourceRep.ID,
		TargetRepresentativeAssignmentID: targetRep.ID,
		OriginPrincipalID:                origin.SenderPrincipalID, Capability: strings.TrimSpace(input.Capability),
		ContractID: strings.TrimSpace(input.ContractID), RequestDigest: origin.Digest,
		Scopes: input.Scopes, ArtifactRefs: input.ArtifactRefs,
		Deadline: strings.TrimSpace(input.Deadline), MaxHops: input.MaxHops,
	})
	if err != nil {
		return nil, mapGatewayError(err)
	}
	_, err = s.store.EnqueueRelayMessage(store.RelayMessageInput{
		Message: store.FabricMessage{
			RequestID: request.ID, FromEndpointID: actor.EndpointID,
			ToEndpointID: targetEndpoint.ID, Kind: "federation_request",
			Body:     originMessage.Message.Body,
			Metadata: map[string]any{"federation_request_id": request.ID, "capability": request.Capability, "scopes": request.Scopes},
		},
		Security: store.RelayMessageSecurity{
			SenderEndpointID: actor.EndpointID, SenderPrincipalID: actor.PrincipalID,
			SenderGroupID: actor.GroupID, SenderBindingID: actor.BindingID,
			SenderBindingEpoch: actor.BindingEpoch, ReceiverEndpointID: targetEndpoint.ID,
			ReceiverPrincipalID: targetEndpoint.PrincipalID, ReceiverGroupID: targetEndpoint.GroupID,
			ReceiverBindingID: targetBinding.ID, ReceiverBindingEpoch: targetBinding.Epoch,
			AuthorizationRef: request.ContractID,
		},
		IdempotencyKey: "federation-request:" + request.ID, ExpiresAt: request.Deadline,
	})
	if err != nil {
		return nil, mapRelayError(err)
	}
	s.notifyNode(targetEndpoint.MachineID)
	return request, nil
}

func (s *Service) AcceptFederation(actor Actor, requestID string) (*store.FederationRequest, error) {
	request, err := s.store.GetFederationRequest(strings.TrimSpace(requestID))
	if err != nil || request.TargetGroupID != actor.GroupID || request.TargetRepresentativeEndpointID != actor.EndpointID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	assignment, err := s.representativeForActor(actor, request.TargetRepresentativeAssignmentID)
	if err != nil {
		return nil, err
	}
	if err := s.store.ValidateRepresentativeOwner(assignment.ID, representativeOwner(actor), assignment.Epoch); err != nil {
		return nil, mapGatewayError(err)
	}
	claimed, claimErr := s.store.ClaimRepresentativeMailbox(store.RepresentativeMailboxClaimInput{
		GroupID: actor.GroupID, RepresentativeEndpointID: actor.EndpointID,
		RepresentativeAssignmentID: assignment.ID, OwnerID: representativeOwner(actor),
		Epoch: assignment.Epoch, Limit: 100,
	})
	if claimErr != nil && !errors.Is(claimErr, store.ErrGatewayNoMailbox) {
		return nil, mapGatewayError(claimErr)
	}
	for _, item := range claimed {
		if item.RequestID == request.ID {
			_, _ = s.store.AcknowledgeRepresentativeMailbox(item.ID, representativeOwner(actor), assignment.Epoch)
			break
		}
	}
	accepted, err := s.store.AcceptFederationRequest(request.ID, representativeOwner(actor), assignment.Epoch)
	if err != nil {
		return nil, mapGatewayError(err)
	}
	started, err := s.store.BeginFederationRequest(accepted.ID, representativeOwner(actor), assignment.Epoch)
	if err != nil {
		return nil, mapGatewayError(err)
	}
	return started, nil
}

// SubmitFederationResult derives the producer from a completed group-local
// Relay request. The representative cannot claim that it produced another
// Endpoint's result and cannot fabricate a user approval flag.
func (s *Service) SubmitFederationResult(actor Actor, input FederationResultInput) (*store.FederationRequest, error) {
	request, err := s.store.GetFederationRequest(strings.TrimSpace(input.FederationRequestID))
	if err != nil || request.TargetGroupID != actor.GroupID || request.TargetRepresentativeEndpointID != actor.EndpointID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	assignment, err := s.representativeForActor(actor, request.TargetRepresentativeAssignmentID)
	if err != nil {
		return nil, err
	}
	if err := s.store.ValidateRepresentativeOwner(assignment.ID, representativeOwner(actor), assignment.Epoch); err != nil {
		return nil, mapGatewayError(err)
	}
	local, err := s.store.GetRelayFabricRequest(strings.TrimSpace(input.LocalRequestID))
	if err != nil || local.SenderEndpointID != actor.EndpointID || local.SenderGroupID != actor.GroupID ||
		local.State != store.FabricRequestReplied || local.ReplyMessageID == "" {
		return nil, ErrNotFoundOrNotAuthorized
	}
	reply, err := s.store.GetRelayMessage(local.ReplyMessageID)
	if err != nil || reply == nil {
		return nil, ErrNotFoundOrNotAuthorized
	}
	if reply.Security.SenderGroupID != actor.GroupID || reply.Security.SenderEndpointID != local.ReceiverEndpointID {
		return nil, ErrPermissionDenied
	}
	if len(input.ArtifactRefs) != 0 {
		if err := s.ValidateGatewayArtifactRefs(actor, request.SourceGroupID, input.ArtifactRefs, nil); err != nil {
			return nil, err
		}
	}
	provenance := append([]string(nil), input.ProvenanceRefs...)
	provenance = append(provenance, "relay-request:"+local.RequestID, "relay-message:"+reply.Message.ID)
	updated, err := s.store.SubmitFederationResult(store.FederationResult{
		RequestID: request.ID, Digest: reply.Security.Digest,
		ProducerPrincipalID: reply.Security.SenderPrincipalID,
		ProducerEndpointID:  reply.Security.SenderEndpointID,
		ProducerGroupID:     reply.Security.SenderGroupID, ArtifactRefs: input.ArtifactRefs,
		EvidenceRefs: input.EvidenceRefs, ProvenanceRefs: provenance,
		VerificationLevel: strings.TrimSpace(input.VerificationLevel),
		PayloadRef:        reply.Message.ID, SubmittedByEndpointID: actor.EndpointID,
	}, representativeOwner(actor), assignment.Epoch)
	if err != nil {
		return nil, mapGatewayError(err)
	}
	sourceEndpoint, err := s.store.GetEndpointV2(updated.SourceRepresentativeEndpointID)
	if err != nil {
		return nil, ErrRepresentativeUnavailable
	}
	sourceBinding, err := s.store.GetActiveSessionBinding(sourceEndpoint.ID)
	if err != nil {
		return nil, ErrRepresentativeUnavailable
	}
	_, err = s.store.EnqueueRelayMessage(store.RelayMessageInput{
		Message: store.FabricMessage{RequestID: updated.ID, FromEndpointID: actor.EndpointID,
			ToEndpointID: sourceEndpoint.ID, Kind: "federation_result", Body: reply.Message.Body,
			Metadata: map[string]any{"federation_request_id": updated.ID, "producer_endpoint_id": reply.Security.SenderEndpointID, "evidence_refs": input.EvidenceRefs}},
		Security: store.RelayMessageSecurity{
			SenderEndpointID: actor.EndpointID, SenderPrincipalID: actor.PrincipalID,
			SenderGroupID: actor.GroupID, SenderBindingID: actor.BindingID,
			SenderBindingEpoch: actor.BindingEpoch, ReceiverEndpointID: sourceEndpoint.ID,
			ReceiverPrincipalID: sourceEndpoint.PrincipalID, ReceiverGroupID: sourceEndpoint.GroupID,
			ReceiverBindingID: sourceBinding.ID, ReceiverBindingEpoch: sourceBinding.Epoch,
			AuthorizationRef: updated.ContractID,
		}, IdempotencyKey: "federation-result:" + updated.ResultID,
	})
	if err != nil {
		return nil, mapRelayError(err)
	}
	s.notifyNode(sourceEndpoint.MachineID)
	return updated, nil
}

func (s *Service) AcceptFederationResult(actor Actor, requestID string) (*store.FederationRequest, error) {
	request, err := s.store.GetFederationRequest(strings.TrimSpace(requestID))
	if err != nil || request.SourceGroupID != actor.GroupID || request.SourceRepresentativeEndpointID != actor.EndpointID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	assignment, err := s.representativeForActor(actor, request.SourceRepresentativeAssignmentID)
	if err != nil {
		return nil, err
	}
	if err := s.store.ValidateRepresentativeOwner(assignment.ID, representativeOwner(actor), assignment.Epoch); err != nil {
		return nil, mapGatewayError(err)
	}
	result, err := s.store.GetFederationResultForRequest(request.ID)
	if err != nil {
		return nil, mapGatewayError(err)
	}
	if len(result.ArtifactRefs) != 0 {
		if _, err := s.ResolveArtifactRefsV2(actor, result.ArtifactRefs, nil); err != nil {
			return nil, err
		}
	}
	if request.State == store.FederationRequestResultSubmitted {
		request, err = s.store.AcceptFederationResult(request.ID, request.ResultID, representativeOwner(actor), assignment.Epoch)
		if err != nil {
			return nil, mapGatewayError(err)
		}
	}
	payload, err := s.store.GetRelayMessage(result.PayloadRef)
	if err != nil || payload == nil {
		return nil, errors.New("federation result payload is unavailable")
	}
	origin, err := s.store.GetRelayFabricRequest(request.OriginRequestID)
	if err != nil {
		return nil, ErrNotFoundOrNotAuthorized
	}
	if origin.State == store.FabricRequestOpen {
		if _, err := s.Reply(actor, ReplyInput{RequestID: origin.RequestID, Body: payload.Message.Body,
			Metadata: map[string]any{"federation_request_id": request.ID, "producer_endpoint_id": result.ProducerEndpointID, "evidence_refs": result.EvidenceRefs, "provenance_refs": result.ProvenanceRefs}}); err != nil {
			return nil, err
		}
	}
	if request.State == store.FederationRequestResultAccepted {
		request, err = s.store.SettleFederationRequest(request.ID, representativeOwner(actor), assignment.Epoch)
		if err != nil {
			return nil, mapGatewayError(err)
		}
	}
	return request, nil
}

func (s *Service) FederationRequest(actor Actor, requestID string) (*store.FederationRequest, error) {
	if _, err := s.validateActorCurrent(actor); err != nil {
		return nil, err
	}
	request, err := s.store.GetFederationRequest(strings.TrimSpace(requestID))
	if err != nil {
		return nil, ErrNotFoundOrNotAuthorized
	}
	allowed := (actor.PrincipalID == request.OriginPrincipalID && actor.GroupID == request.SourceGroupID) ||
		(actor.EndpointID == request.SourceRepresentativeEndpointID && actor.GroupID == request.SourceGroupID) ||
		(actor.EndpointID == request.TargetRepresentativeEndpointID && actor.GroupID == request.TargetGroupID) ||
		(actor.EndpointID == request.ProducerEndpointID && actor.GroupID == request.ProducerGroupID)
	if !allowed {
		return nil, ErrNotFoundOrNotAuthorized
	}
	return request, nil
}

func mapGatewayError(err error) error {
	switch {
	case errors.Is(err, store.ErrGatewayStaleEpoch), errors.Is(err, store.ErrGatewayLeaseExpired):
		return fmt.Errorf("%w: %v", ErrStaleBinding, err)
	case errors.Is(err, store.ErrGatewayLeaseHeld), errors.Is(err, store.ErrGatewayLeaseOwner),
		errors.Is(err, store.ErrGatewayAuthorization), errors.Is(err, store.ErrGatewayScopeDenied),
		errors.Is(err, store.ErrGatewayGroupMismatch), errors.Is(err, store.ErrGatewayContractExpired):
		return fmt.Errorf("%w: %v", ErrPermissionDenied, err)
	case errors.Is(err, store.ErrFederationRequestNotFound), errors.Is(err, store.ErrFederationResultNotFound),
		errors.Is(err, store.ErrRepresentativeAssignmentNotFound), errors.Is(err, store.ErrFederationContractNotFound):
		return ErrNotFoundOrNotAuthorized
	case errors.Is(err, store.ErrGatewayDigestConflict), errors.Is(err, store.ErrGatewayInvalidState):
		return fmt.Errorf("%w: %v", ErrConflict, err)
	default:
		return err
	}
}
