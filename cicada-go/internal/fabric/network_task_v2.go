package fabric

import (
	"errors"

	"github.com/cicada-ai/cicada/internal/store"
)

// Network Task bodies are existing NetworkDirect sealed SEND messages. These
// methods only bind signed message routes to SharedTask responsibility state.
func networkTaskError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNetworkPermission), errors.Is(err, store.ErrSharedTaskNotFound):
		return ErrNotFoundOrNotAuthorized
	case errors.Is(err, store.ErrNetworkConflict), errors.Is(err, store.ErrSharedTaskConflict),
		errors.Is(err, store.ErrSharedTaskStaleOwner):
		return ErrConflict
	default:
		return err
	}
}

func (s *Service) PublishNetworkTaskOffer(actor NetworkActor, input store.NetworkTaskOfferInput) (*store.NetworkTaskOffer, error) {
	if err := s.authorizeNetwork(actor, "task.offer.publish"); err != nil {
		return nil, err
	}
	task, err := s.store.PublishNetworkTaskOffer(networkDirectoryScope(actor), input)
	if err != nil {
		return nil, networkTaskError(err)
	}
	// The SEND can wake a Node before its offer route is committed. Wake every
	// exact reader again after the durable publish so the still-READY inbox row
	// is reconciled even when the earlier Relay hint was already consumed.
	for _, endpointID := range task.NotifyEndpointIDs {
		s.notifyNetworkDirectTarget(endpointID)
	}
	task.NotifyEndpointIDs = nil
	return task, nil
}

func (s *Service) ListNetworkTaskOffers(actor NetworkActor, limit int) ([]store.NetworkTaskOffer, error) {
	if err := s.authorizeNetwork(actor, "task.offer.list"); err != nil {
		return nil, err
	}
	tasks, err := s.store.ListNetworkTaskOffers(networkDirectoryScope(actor), limit)
	return tasks, networkTaskError(err)
}

func (s *Service) GetNetworkTaskOffer(actor NetworkActor, taskID string) (*store.NetworkTaskOffer, error) {
	if err := s.authorizeNetwork(actor, "task.offer.list"); err != nil {
		return nil, err
	}
	task, err := s.store.GetNetworkTaskOffer(networkDirectoryScope(actor), taskID)
	return task, networkTaskError(err)
}

func (s *Service) ClaimNetworkTaskOffer(actor NetworkActor, input TaskClaimInput) (*store.NetworkTaskOffer, error) {
	if err := s.authorizeNetwork(actor, "task.offer.claim"); err != nil {
		return nil, err
	}
	task, err := s.store.ClaimNetworkTaskOffer(networkDirectoryScope(actor), input.TaskID,
		input.ExpectedRevision, input.IdempotencyKey, input.LeaseSeconds)
	return task, networkTaskError(err)
}

func (s *Service) SubmitNetworkTaskResult(actor NetworkActor, input store.NetworkTaskResultInput) (*store.NetworkTaskResult, error) {
	if err := s.authorizeNetwork(actor, "task.offer.result"); err != nil {
		return nil, err
	}
	result, err := s.store.SubmitNetworkTaskResult(networkDirectoryScope(actor), input)
	if err != nil {
		return nil, networkTaskError(err)
	}
	s.notifyNetworkDirectTarget(result.NotifyEndpointID)
	result.NotifyEndpointID = ""
	return result, nil
}

func (s *Service) AcceptNetworkTaskResult(actor NetworkActor, input TaskAcceptInput) (*store.NetworkTaskOffer, error) {
	if err := s.authorizeNetwork(actor, "task.offer.accept"); err != nil {
		return nil, err
	}
	task, err := s.store.AcceptNetworkTaskResult(networkDirectoryScope(actor), input.TaskID,
		input.ResultID, input.ExpectedRevision)
	return task, networkTaskError(err)
}
