package fabric

import "github.com/cicada-ai/cicada/internal/store"

type RegroupProposalInput = store.RegroupProposalInput
type RegroupProposal = store.RegroupProposal
type RegroupDelegation = store.RegroupDelegation
type RegroupApplyResult = store.RegroupApplyResult

const (
	RegroupSetParent   = store.RegroupSetParent
	RegroupCreateChild = store.RegroupCreateChild
)

func (s *Service) ProposeRegroup(nodeToken, sessionToken string,
	in RegroupProposalInput) (*RegroupProposal, error) {
	actor, err := s.groupSpaceActor(nodeToken, sessionToken, in.SourceGroupID)
	if err != nil {
		return nil, err
	}
	return s.store.ProposeRegroup(actor, in)
}

func (s *Service) ApplyDelegatedRegroup(nodeToken, sessionToken,
	proposalID, delegationID string) (*RegroupApplyResult, error) {
	groupID, err := s.store.RegroupProposalSourceGroupID(proposalID)
	if err != nil {
		return nil, err
	}
	actor, err := s.groupSpaceActor(nodeToken, sessionToken, groupID)
	if err != nil {
		return nil, err
	}
	return s.store.ApplyDelegatedRegroup(actor, proposalID, delegationID)
}
