package control

import (
	"github.com/cicada-ai/cicada/internal/store"
)

func (c *Control) ClientPreviewCommunicationLinkReviewPolicy(ownerID, linkID string,
	policy store.CommunicationLinkReviewPolicy) (*store.CommunicationLinkReviewPolicyPreview, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.PreviewCommunicationLinkReviewPolicyForOwner(linkID, ownerID, policy)
}

func (c *Control) ClientRecordCommunicationLinkReviewPolicy(ownerID, linkID, side,
	keyID string, expectedPolicyVersion int64, policy store.CommunicationLinkReviewPolicy,
	proof []byte) (*store.CommunicationLinkReviewPolicyStatus, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.RecordCommunicationLinkReviewPolicyForOwner(linkID, side, keyID,
		expectedPolicyVersion, policy, proof)
}

func (c *Control) ClientCommunicationLinkReviewPolicy(ownerID, linkID string) (*store.CommunicationLinkReviewPolicyStatus, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.GetCommunicationLinkReviewPolicyForOwner(linkID, ownerID)
}
