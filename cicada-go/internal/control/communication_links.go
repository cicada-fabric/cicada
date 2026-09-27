package control

import (
	"errors"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// CommunicationLinkProposalInput contains contract terms only. The proposing
// owner comes from Control's authenticated management identity, never JSON.
type CommunicationLinkProposalInput struct {
	SourceEndpointID string   `json:"source_endpoint_id"`
	SourceGroupID    string   `json:"source_group_id"`
	TargetEndpointID string   `json:"target_endpoint_id"`
	TargetGroupID    string   `json:"target_group_id"`
	Direction        string   `json:"direction"`
	Actions          []string `json:"actions"`
	DataScopes       []string `json:"data_scopes"`
	TransportHubID   string   `json:"transport_hub_id,omitempty"`
	ExpiresAt        string   `json:"expires_at"`
}

func (c *Control) communicationLinkOwnerID() (string, error) {
	ownerID := strings.TrimSpace(c.Identity().ID)
	if ownerID == "" {
		return "", errors.New("Control owner identity is unavailable")
	}
	return ownerID, nil
}

func (c *Control) ProposeCommunicationLink(input CommunicationLinkProposalInput) (*store.CommunicationLink, error) {
	ownerID, err := c.communicationLinkOwnerID()
	if err != nil {
		return nil, err
	}
	return c.store.ProposeCommunicationLink(store.CommunicationLinkProposal{
		SourceEndpointID: input.SourceEndpointID, SourceGroupID: input.SourceGroupID,
		TargetEndpointID: input.TargetEndpointID, TargetGroupID: input.TargetGroupID,
		Direction: input.Direction, Actions: input.Actions, DataScopes: input.DataScopes,
		TransportHubID: input.TransportHubID, ExpiresAt: input.ExpiresAt,
		ActorOwnerID: ownerID,
	})
}

func (c *Control) CommunicationLink(id string) (*store.CommunicationLink, error) {
	ownerID, err := c.communicationLinkOwnerID()
	if err != nil {
		return nil, err
	}
	return c.store.GetCommunicationLinkForOwner(id, ownerID)
}

func (c *Control) CommunicationLinks() ([]store.CommunicationLink, error) {
	ownerID, err := c.communicationLinkOwnerID()
	if err != nil {
		return nil, err
	}
	return c.store.ListCommunicationLinksForOwner(ownerID, 200)
}

func (c *Control) RevokeCommunicationLink(id string, expectedVersion int64, reason string) (*store.CommunicationLink, error) {
	ownerID, err := c.communicationLinkOwnerID()
	if err != nil {
		return nil, err
	}
	return c.store.RevokeCommunicationLink(id, ownerID, expectedVersion, reason)
}
