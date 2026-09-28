package fabric

import (
	"errors"
	"github.com/cicada-ai/cicada/internal/store"
)

func (s *Service) resourceLeaseForActor(actor Actor, id string, action string) (*store.ResourceLease, error) {
	if err := s.Authorize(actor, action); err != nil {
		return nil, err
	}
	lease, err := s.store.GetResourceLease(id)
	if err != nil || lease.HolderGroupID != actor.GroupID || lease.HolderPrincipalID != actor.PrincipalID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	return lease, nil
}

func (s *Service) RenewResourceLease(actor Actor, id string, epoch int64, ttlSeconds int) (*store.ResourceLease, error) {
	if _, err := s.resourceLeaseForActor(actor, id, "task.claim"); err != nil {
		return nil, err
	}
	lease, err := s.store.RenewResourceLeaseForActor(nativeActorScope(actor), id, epoch, ttlSeconds)
	if errors.Is(err, store.ErrResourceStaleEpoch) || errors.Is(err, store.ErrResourceLeaseExpired) {
		return nil, ErrConflict
	}
	return lease, mapRelayError(err)
}

func (s *Service) QuarantineResourceLease(actor Actor, id string, epoch int64) (*store.ResourceLease, error) {
	if _, err := s.resourceLeaseForActor(actor, id, "task.claim"); err != nil {
		return nil, err
	}
	lease, err := s.store.QuarantineResourceLeaseForActor(nativeActorScope(actor), id, epoch)
	if errors.Is(err, store.ErrResourceStaleEpoch) {
		return nil, ErrConflict
	}
	return lease, mapRelayError(err)
}

func (s *Service) WriteManagedBlob(actor Actor, id string, epoch int64, body []byte) (string, error) {
	if _, err := s.resourceLeaseForActor(actor, id, "resource.execute"); err != nil {
		return "", err
	}
	digest, err := s.store.WriteManagedBlobForActor(nativeActorScope(actor), id, epoch, body)
	if errors.Is(err, store.ErrResourceStaleEpoch) || errors.Is(err, store.ErrResourceLeaseExpired) {
		return "", ErrConflict
	}
	return digest, mapRelayError(err)
}
