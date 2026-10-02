package control

import (
	"errors"

	"github.com/cicada-ai/cicada/internal/store"
)

// These methods are reachable only through the authenticated encrypted Client
// RPC. The owner is taken from its durable device binding, not the request
// body. Accepted consent evidence is distinct from routing authorization and
// native consumption. Clients still require independently trusted Owner keys.
func (c *Control) ClientCommunicationLinkKeyManifest(ownerID, linkID string) (*store.CommunicationLinkKeyManifest, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("communication link key registry is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.GetCommunicationLinkKeyManifest(linkID, ownerID)
}

func (c *Control) ClientCommunicationLinkKeyGrants(ownerID, linkID string) ([]store.CommunicationLinkKeyGrantStatus, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("communication link key registry is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.GetCommunicationLinkKeyGrantStatuses(linkID, ownerID)
}

func (c *Control) ClientRecordCommunicationLinkKeyGrant(ownerID, linkID, side,
	ownerKeyID string, signedProof []byte) (*store.CommunicationLinkKeyGrantStatus, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("communication link key registry is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.RecordCommunicationLinkKeyGrant(ownerID, linkID, side, ownerKeyID, signedProof)
}
