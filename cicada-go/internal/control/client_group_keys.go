package control

import (
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

// These methods are reachable only through the authenticated encrypted Client
// RPC. The owner comes from the durable device binding, and the Store derives
// the Group, Endpoint, Node binding, and candidate key from authoritative rows.
func (c *Control) ClientPreviewGroupEndpointKeyGrant(ownerID, groupID, endpointID, ownerKeyID string,
	issuedAt, expiresAt time.Time) (*store.GroupEndpointKeyGrantManifest, error) {
	if err := c.validateClientGroupEndpointKeyGrantScope(ownerID, groupID, endpointID); err != nil {
		return nil, err
	}
	return c.store.PreviewGroupEndpointKeyGrant(ownerID, groupID, endpointID, ownerKeyID,
		issuedAt, expiresAt)
}

func (c *Control) ClientAcceptGroupEndpointKeyGrant(ownerID, groupID, endpointID,
	ownerKeyID string, signedProof []byte) (*store.OwnerGroupEndpointKeyGrant, error) {
	if err := c.validateClientGroupEndpointKeyGrantScope(ownerID, groupID, endpointID); err != nil {
		return nil, err
	}
	return c.store.AcceptGroupEndpointKeyGrant(ownerID, groupID, endpointID, ownerKeyID, signedProof)
}

func (c *Control) ClientGroupEndpointKeyGrantStatus(ownerID, groupID,
	endpointID string) (*store.OwnerGroupEndpointKeyGrant, error) {
	if err := c.validateClientGroupEndpointKeyGrantScope(ownerID, groupID, endpointID); err != nil {
		return nil, err
	}
	return c.store.GetGroupEndpointKeyGrant(ownerID, groupID, endpointID)
}

func (c *Control) validateClientGroupEndpointKeyGrantScope(ownerID, groupID, endpointID string) error {
	if c == nil || c.store == nil {
		return errors.New("Group Endpoint key grant registry is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return err
	}
	if _, err := c.clientOwnedGroup(ownerID, groupID); err != nil {
		return err
	}
	if _, err := c.clientOwnedEndpoint(ownerID, endpointID); err != nil {
		return err
	}
	return nil
}
