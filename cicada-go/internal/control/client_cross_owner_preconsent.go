package control

import "github.com/cicada-ai/cicada/internal/store"

// PreviewCrossOwnerGroupPreconsentForClientRequest returns only the exact
// current foreign admission that belongs to the authenticated Endpoint Owner.
func (c *Control) PreviewCrossOwnerGroupPreconsentForClientRequest(requestID, ownerID,
	admissionID string) (*store.CrossOwnerGroupPreconsentPreview, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.PreviewCrossOwnerGroupPreconsentForClientRequest(requestID, ownerID, admissionID)
}
