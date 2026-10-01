package control

import "github.com/cicada-ai/cicada/internal/store"

func (c *Control) ClientPreviewNetworkCollaborationKeyGrant(ownerID, networkID,
	endpointID, purpose, ownerKeyID string) (*store.NetworkCollaborationKeyManifest, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.PreviewNetworkCollaborationKeyGrant(ownerID, networkID, endpointID, purpose, ownerKeyID)
}

func (c *Control) ClientAcceptNetworkCollaborationKeyGrant(ownerID, requestID,
	networkID, endpointID, purpose string, proof []byte) (*store.OwnerNetworkCollaborationKeyGrant, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.AcceptNetworkCollaborationKeyGrantForClientRequest(requestID,
		ownerID, networkID, endpointID, purpose, proof)
}

func (c *Control) ClientNetworkCollaborationKeyGrantStatus(ownerID, networkID,
	endpointID, purpose string) (*store.OwnerNetworkCollaborationKeyGrant, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.GetNetworkCollaborationKeyGrant(ownerID, networkID, endpointID, purpose)
}

func (c *Control) ClientRevokeNetworkCollaborationKeyGrant(ownerID, networkID,
	endpointID, purpose string, expectedRevision int64) (*store.OwnerNetworkCollaborationKeyGrant, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.RevokeNetworkCollaborationKeyGrant(ownerID, networkID, endpointID, purpose, expectedRevision)
}
