package fabric

import (
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// RegisterEndpointKeyCandidate binds a self-attested public key to the exact
// currently leased native Session. It does not establish another user's pin,
// approve a CommunicationLink, or enable ciphertext routing.
func (s *Service) RegisterEndpointKeyCandidate(actor Actor, attestation []byte) (*store.EndpointKeyCandidate, error) {
	if err := s.Authorize(actor, "directory.read"); err != nil {
		return nil, err
	}
	return s.store.RegisterEndpointKeyCandidate(actor.EndpointID, actor.PrincipalID,
		actor.BindingID, actor.BindingEpoch, attestation)
}

// EndpointKeyCandidate only exposes a public candidate for an Endpoint the
// caller can already resolve in its selected Group. A stale Node or binding
// snapshot is withheld until that Endpoint reattests its current binding.
func (s *Service) EndpointKeyCandidate(actor Actor, target string) (*store.EndpointKeyCandidate, error) {
	card, err := s.Resolve(actor, ResolveInput{Query: strings.TrimSpace(target)})
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
