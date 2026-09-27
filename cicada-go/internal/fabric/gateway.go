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

// Federate is retained as an explicit refusal for callers of the retired
// Monitor-mediated plaintext Federation write path. Federation request
// records remain readable; new body-bearing peer writes must use sealed
// CommunicationLink delivery.
func (s *Service) Federate(actor Actor, input FederateInput) (*store.FederationRequest, error) {
	return nil, ErrFederationBodyWritesRetired
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

// SubmitFederationResult is retained as an explicit refusal for the retired
// Monitor-mediated plaintext Federation write path.
func (s *Service) SubmitFederationResult(actor Actor, input FederationResultInput) (*store.FederationRequest, error) {
	return nil, ErrFederationBodyWritesRetired
}

// AcceptFederationResult cannot re-emit a historical Federation payload as
// an ordinary plaintext peer reply. Historical request/result records remain
// readable through FederationRequest and the existing read APIs.
func (s *Service) AcceptFederationResult(actor Actor, requestID string) (*store.FederationRequest, error) {
	return nil, ErrFederationBodyWritesRetired
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
