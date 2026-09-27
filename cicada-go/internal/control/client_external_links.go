package control

import (
	"errors"

	"github.com/cicada-ai/cicada/internal/store"
)

type ClientCommunicationLinkView struct {
	Link   ClientTopologyLink `json:"link"`
	MySide string             `json:"my_side"`
}

type ClientCommunicationLinksPage struct {
	Links   []ClientCommunicationLinkView `json:"links"`
	Cursor  string                        `json:"cursor"`
	HasMore bool                          `json:"has_more"`
}

// ClientCommunicationLinks gives both sides a recoverable, owner-scoped view
// of accepted proposal IDs without exposing other owners' topology or native
// session metadata. A proposal remains non-routable.
func (c *Control) ClientCommunicationLinks(ownerID, cursor string, limit int) (*ClientCommunicationLinksPage, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("communication link registry is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	links, next, err := c.store.ListCommunicationLinksPageForOwner(ownerID, cursor, limit)
	if err != nil {
		return nil, err
	}
	page := &ClientCommunicationLinksPage{Links: make([]ClientCommunicationLinkView, 0, len(links)),
		Cursor: next, HasMore: next != ""}
	for _, link := range links {
		side := "SOURCE"
		if link.TargetOwnerID == ownerID && link.SourceOwnerID != ownerID {
			side = "TARGET"
		}
		page.Links = append(page.Links, ClientCommunicationLinkView{
			Link: projectClientTopologyLink(link), MySide: side})
	}
	return page, nil
}

// External Link invitations are Client-authorized, owner-scoped proposals.
// Neither token preview nor acceptance activates a peer route. Endpoint key
// grants and the transport Guard must be established separately.
func (c *Control) CreateClientExternalThreadInvite(ownerID string,
	input store.ExternalThreadInviteInput) (*store.ExternalThreadInviteCreated, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("external Thread invitation registry is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	input.OwnerID = ownerID
	return c.store.CreateExternalThreadInvite(input)
}

func (c *Control) PreviewClientExternalThreadInvite(ownerID, token string) (*store.ExternalThreadInvitePreview, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("external Thread invitation registry is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.PreviewExternalThreadInvite(token)
}

func (c *Control) AcceptClientExternalThreadInvite(ownerID, token, endpointID,
	groupID string) (*store.ExternalThreadInviteAcceptance, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("external Thread invitation registry is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.AcceptExternalThreadInvite(token, ownerID, endpointID, groupID)
}
