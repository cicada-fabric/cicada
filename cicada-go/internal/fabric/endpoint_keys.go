package fabric

import (
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// RegisterEndpointKeyCandidate binds a self-attested public key to the exact
// currently leased native Session. It does not establish another user's pin,
// approve a CommunicationLink, or enable ciphertext routing.
func (s *Service) RegisterEndpointKeyCandidate(actor Actor, attestation []byte) (*store.EndpointKeyCandidate, error) {
	return s.store.RegisterEndpointKeyCandidateForActor(nativeActorScope(actor), attestation)
}

// EndpointKeyCandidate exposes the caller's own current public candidate, or
// a peer the caller can resolve in its selected Group. A stale Node or binding
// snapshot is withheld until that Endpoint reattests its current binding.
func (s *Service) EndpointKeyCandidate(actor Actor, target string) (*store.EndpointKeyCandidate, error) {
	target = strings.TrimSpace(target)
	if target == actor.EndpointID {
		return s.store.GetOwnEndpointKeyCandidateForActor(nativeActorScope(actor))
	}
	card, err := s.Resolve(actor, ResolveInput{Query: target})
	if err != nil {
		return nil, err
	}
	candidate, err := s.store.GetEndpointKeyCandidate(card.EndpointID)
	if err != nil {
		return nil, err
	}
	if candidate.PrincipalID != card.PrincipalID || candidate.NodeID != card.NodeID ||
		candidate.BindingID != card.BindingID || candidate.BindingEpoch != card.BindingEpoch {
		return nil, ErrNotFoundOrNotAuthorized
	}
	return candidate, nil
}
