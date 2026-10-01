package fabric

import (
	"errors"

	"github.com/cicada-ai/cicada/internal/store"
)

// Communication Link reviewer operations expose metadata only. The Store
// rechecks the actor's exact reviewer assignment and current link.review
// membership/binding on every operation; ciphertext and decoded message body
// never cross this API.
func (s *Service) ListCommunicationLinkReviews(actor Actor, cursor string, limit int) (*store.CommunicationLinkMessageReviewPage, error) {
	if err := s.Authorize(actor, "link.review"); err != nil {
		return nil, err
	}
	page, err := s.store.ListCommunicationLinkMessageReviewsPageForActor(nativeActorScope(actor), cursor, limit)
	if err != nil {
		return nil, communicationLinkReviewError(err)
	}
	return page, nil
}

func (s *Service) GetCommunicationLinkReview(actor Actor, messageID string) (*store.CommunicationLinkMessageReview, error) {
	if err := s.Authorize(actor, "link.review"); err != nil {
		return nil, err
	}
	review, err := s.store.GetCommunicationLinkMessageReviewForActor(nativeActorScope(actor), messageID)
	if err != nil {
		return nil, communicationLinkReviewError(err)
	}
	return review, nil
}

func (s *Service) ClaimNextCommunicationLinkReview(actor Actor, input CommunicationLinkReviewClaimInput) (*store.CommunicationLinkMessageReview, error) {
	if err := s.Authorize(actor, "link.review"); err != nil {
		return nil, err
	}
	review, err := s.store.ClaimNextCommunicationLinkReviewForActor(nativeActorScope(actor), input.MessageID,
		input.ExpectedVersion, input.ExpectedOwnerEpoch)
	if err != nil {
		return nil, communicationLinkReviewError(err)
	}
	return review, nil
}

func (s *Service) DecideCommunicationLinkReview(actor Actor, input CommunicationLinkReviewDecisionInput) (*store.CommunicationLinkMessageReview, error) {
	if err := s.Authorize(actor, "link.review"); err != nil {
		return nil, err
	}
	review, err := s.store.DecideCommunicationLinkMessageReviewForActor(nativeActorScope(actor), input.MessageID,
		input.ExpectedVersion, input.ExpectedOwnerEpoch, input.Decision)
	if err != nil {
		return nil, communicationLinkReviewError(err)
	}
	return review, nil
}

func communicationLinkReviewError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNetworkPermission):
		return ErrPermissionDenied
	case errors.Is(err, store.ErrCommunicationLinkReviewPolicy),
		errors.Is(err, store.ErrCommunicationLinkNotFound):
		return ErrNotFoundOrNotAuthorized
	case errors.Is(err, store.ErrCommunicationLinkReviewConflict),
		errors.Is(err, store.ErrCommunicationLinkReviewExpired),
		errors.Is(err, store.ErrCommunicationLinkReviewRejected),
		errors.Is(err, store.ErrVersionConflict):
		return ErrConflict
	default:
		return mapRelayError(err)
	}
}

type CommunicationLinkReviewClaimInput struct {
	MessageID          string `json:"message_id"`
	ExpectedVersion    int64  `json:"expected_version"`
	ExpectedOwnerEpoch int64  `json:"expected_owner_epoch"`
}

type CommunicationLinkReviewDecisionInput struct {
	MessageID          string `json:"message_id"`
	ExpectedVersion    int64  `json:"expected_version"`
	ExpectedOwnerEpoch int64  `json:"expected_owner_epoch"`
	Decision           string `json:"decision"`
}
