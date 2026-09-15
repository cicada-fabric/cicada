package control

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

// DiscoveryRequests lists signed identity announcements waiting for, or
// having received, an operator decision.
func (c *Control) DiscoveryRequests(status string) ([]store.DiscoveryRequest, error) {
	return c.store.ListDiscoveryRequests(strings.ToLower(strings.TrimSpace(status)))
}

func (c *Control) DiscoveryRequest(id string) (*store.DiscoveryRequest, error) {
	return c.store.GetDiscoveryRequest(strings.TrimSpace(id))
}

// SignContactAnnouncement creates a signed public identity announcement for
// this Control instance. The private key never leaves the process; callers
// receive only the portable, verifiable public record.
func (c *Control) SignContactAnnouncement(label string) ([]byte, error) {
	if c.identity == nil {
		return nil, errors.New("local E2EE identity is unavailable")
	}
	return c.identity.SignContactAnnouncement(label)
}

// SubmitContactDiscovery verifies a peer's ML-DSA announcement and stores it
// as pending. It never creates a trusted Contact automatically.
func (c *Control) SubmitContactDiscovery(announcement []byte) (*store.DiscoveryRequest, error) {
	identity, label, err := e2ee.VerifyContactAnnouncement(announcement)
	if err != nil {
		return nil, err
	}
	if c.identity != nil && identity.ID == c.identity.Public().ID {
		return nil, errors.New("cannot discover the local identity")
	}
	if existing, err := c.store.GetDiscoveryRequestByRemoteID(identity.ID); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	request, err := c.store.CreateDiscoveryRequest(store.DiscoveryRequest{
		RemoteID: identity.ID, Label: label, Identity: identity,
		Announcement: append([]byte(nil), announcement...), Status: "pending",
	})
	if err != nil {
		if existing, lookupErr := c.store.GetDiscoveryRequestByRemoteID(identity.ID); lookupErr == nil && existing != nil {
			return existing, nil
		}
		return nil, err
	}
	c.notify("", "contact.discovery", "P1", "Contact discovery request", fmt.Sprintf("%s wants to connect", label))
	return request, nil
}

// AcceptContactDiscovery creates a pending Contact. A separate trust update
// is required before peer messages can be sent or accepted.
func (c *Control) AcceptContactDiscovery(id string) (*store.DiscoveryRequest, error) {
	request, err := c.store.GetDiscoveryRequest(strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, os.ErrNotExist
	}
	if request.Status != "pending" {
		return request, nil
	}
	resolved, _, accepted, err := c.store.AcceptDiscoveryRequest(request.ID)
	if err != nil {
		return nil, err
	}
	if resolved == nil {
		return nil, os.ErrNotExist
	}
	if accepted {
		c.notify("", "contact.discovery.accepted", "P1", "Contact awaits trust", request.Label)
	}
	return resolved, nil
}

func (c *Control) RejectContactDiscovery(id string) (*store.DiscoveryRequest, error) {
	request, err := c.store.GetDiscoveryRequest(strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, os.ErrNotExist
	}
	if request.Status != "pending" {
		return request, nil
	}
	resolved, err := c.store.ResolveDiscoveryRequest(request.ID, "rejected", "")
	if err != nil {
		return nil, err
	}
	if resolved == nil {
		return nil, errors.New("discovery request disappeared")
	}
	_, _ = c.store.CreateNotification(store.Notification{
		Kind: "contact.discovery.rejected", Priority: "P3",
		Title: "Contact discovery rejected", Body: request.Label,
	})
	return resolved, nil
}
