package fabric

import (
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// NodeForTransportAuthorization derives the Node from the actual credential.
// Existing operation-specific Guards still run after this additional boundary.
func (s *Service) NodeForTransportAuthorization(authorization, groupID, networkID string) (*store.NodeTransportBinding, error) {
	var nodeID string
	if token, err := NodeCredentialFromAuthorization(authorization); err == nil {
		nodeID, err = s.AuthenticateNode(token)
		if err != nil {
			return nil, ErrUnauthenticated
		}
	} else if token, err := SessionCredentialFromAuthorization(authorization); err == nil {
		actor, err := s.AuthenticateForGroup(token, groupID)
		if err != nil {
			return nil, ErrUnauthenticated
		}
		binding, err := s.store.GetSessionBindingByCredentialHash(HashSessionCredential(token))
		if err != nil || binding.ID != actor.BindingID || binding.Epoch != actor.BindingEpoch {
			return nil, ErrUnauthenticated
		}
		nodeID = binding.NodeID
	} else {
		const prefix = "Cicada-Network-Session "
		if !strings.HasPrefix(authorization, prefix) || networkID == "" {
			return nil, ErrUnauthenticated
		}
		token := strings.TrimPrefix(authorization, prefix)
		actor, err := s.AuthenticateForNetwork(token, networkID)
		if err != nil {
			return nil, ErrUnauthenticated
		}
		access, err := s.store.GetNetworkAccessSessionByHash(HashSessionCredential(token))
		if err != nil || access.ID != actor.BindingID || access.Epoch != actor.BindingEpoch {
			return nil, ErrUnauthenticated
		}
		nodeID = access.NodeID
	}
	binding, err := s.store.CurrentNodeTransportBinding(nodeID)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return binding, nil
}
