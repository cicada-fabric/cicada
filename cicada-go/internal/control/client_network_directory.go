package control

import "github.com/cicada-ai/cicada/internal/store"

type ClientNetworkDirectoryPage struct {
	NetworkID  string                            `json:"network_id"`
	Endpoints  []store.ClientNetworkEndpointCard `json:"endpoints"`
	NextCursor string                            `json:"next_cursor,omitempty"`
}

// ListClientOwnerNetworkEndpointCardsForRequest returns only cards published
// by currently enrolled Network members. Store binds the operation to this
// exact accepted Client request and rechecks Owner, Hub, Network and grants.
func (c *Control) ListClientOwnerNetworkEndpointCardsForRequest(requestID, ownerID,
	networkID, afterEndpointID string, limit int) (*ClientNetworkDirectoryPage, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	endpoints, next, err := c.store.ListClientOwnerNetworkEndpointCards(requestID,
		ownerID, networkID, afterEndpointID, limit)
	if err != nil {
		return nil, err
	}
	return &ClientNetworkDirectoryPage{NetworkID: networkID, Endpoints: endpoints, NextCursor: next}, nil
}
