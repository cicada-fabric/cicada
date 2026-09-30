package control

import "github.com/cicada-ai/cicada/internal/store"

// These methods are called only after the encrypted Client RPC has accepted
// the device packet. Store rechecks that exact request and Owner in its write
// transaction, so an MCP actor cannot supply Owner approval.
func (c *Control) GetRegroupProposalForClientRequest(clientRequestID, ownerID, proposalID string) (*store.RegroupProposal, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.GetRegroupProposalForClientRequest(clientRequestID, ownerID, proposalID)
}

func (c *Control) IssueRegroupDelegationForClientRequest(clientRequestID, ownerID, proposalID, expiresAt string, maxUses int) (*store.RegroupDelegation, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.IssueRegroupDelegationForClientRequest(clientRequestID, ownerID, proposalID, expiresAt, maxUses)
}

func (c *Control) RevokeRegroupDelegationForClientRequest(clientRequestID, ownerID, delegationID string, expectedVersion int64) (*store.RegroupDelegation, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.RevokeRegroupDelegationForClientRequest(clientRequestID, ownerID, delegationID, expectedVersion)
}
