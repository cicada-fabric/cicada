package fabric

import (
	"errors"
	"github.com/cicada-ai/cicada/internal/store"
)

// A normal sealed SEND is only a candidate. Registration, current assignment,
// exact route and transaction fences confer Task authority separately.
func (s *Service) RegisterTaskSealedRef(actor Actor, input store.SharedTaskSealedRefInput) (*store.SharedTaskSealedRef, error) {
	action := "task.read"
	if input.Purpose == store.SharedTaskResultPurpose {
		action = "task.submit"
	}
	if err := s.Authorize(actor, action); err != nil {
		return nil, err
	}
	ref, err := s.store.RegisterSharedTaskSealedRefForActor(nativeActorScope(actor), input)
	if errors.Is(err, store.ErrSharedTaskSealedReference) || errors.Is(err, store.ErrSharedTaskStaleOwner) || errors.Is(err, store.ErrSharedTaskConflict) {
		return nil, ErrConflict
	}
	return ref, mapRelayError(err)
}
