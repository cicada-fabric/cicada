package control

import (
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/store"
)

// ManagerOwnerID is the persisted human association, never a crypto key ID.
func (c *Control) ManagerOwnerID() string {
	if c == nil {
		return ""
	}
	return c.managerOwnerID
}
func (c *Control) HubOwnerSetup() (*store.HubOwnerSetup, error) {
	if c == nil || c.hubOwner == nil {
		return nil, store.ErrHubOwnerSetupConflict
	}
	return c.hubOwner.HubOwnerSetup()
}

// Existing management/CLI callers retain the finite Hub-owned service facade.
func (c *Control) IssueOwnerBootstrapLocal(candidate e2ee.PublicIdentity, expectedFingerprint string) (*ownerbootstrap.PairingFile, error) {
	if c == nil || c.hubOwner == nil {
		return nil, store.ErrOwnerBootstrapRejected
	}
	return c.hubOwner.IssueOwnerBootstrapLocal(candidate, expectedFingerprint)
}
func (c *Control) AcceptOwnerBootstrap(packet []byte) ([]byte, error) {
	if c == nil || c.hubOwner == nil {
		return nil, store.ErrOwnerBootstrapRejected
	}
	return c.hubOwner.AcceptOwnerBootstrap(packet)
}
