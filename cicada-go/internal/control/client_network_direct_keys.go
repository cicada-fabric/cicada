package control

import "github.com/cicada-ai/cicada/internal/store"

// These owner-key operations are reachable only through an authenticated,
// encrypted Client device session. The Node publishes its own public key and
// the Owner independently approves the current Network-specific manifest.
func (c *Control) ClientPreviewNetworkDirectKeyGrant(ownerID, networkID, endpointID, ownerKeyID string) (*store.NetworkDirectKeyManifest, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.PreviewNetworkDirectKeyGrant(ownerID, networkID, endpointID, ownerKeyID)
}

func (c *Control) ClientAcceptNetworkDirectKeyGrant(ownerID, clientRequestID, networkID, endpointID string, proof []byte) (*store.OwnerNetworkDirectKeyGrant, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.AcceptNetworkDirectKeyGrantForClientRequest(clientRequestID, ownerID, networkID, endpointID, proof)
}

func (c *Control) ClientNetworkDirectKeyGrantStatus(ownerID, networkID, endpointID string) (*store.OwnerNetworkDirectKeyGrant, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.GetNetworkDirectKeyGrant(ownerID, networkID, endpointID)
}
