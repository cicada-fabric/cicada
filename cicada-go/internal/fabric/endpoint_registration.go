package fabric

import (
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

// These self operations use the existing Store authority, without a provider
// or a Control inference service. rpc is constructed by the authenticated
// Node server carrier and is never decoded from caller JSON.
func (s *Service) RegisterNodeEndpoint(rpc store.NodeControlRPCInput, in nodewire.EndpointRegistration) (*nodewire.EndpointRegistrationResult, error) {
	return s.store.RegisterNodeEndpoint(rpc, in)
}

func (s *Service) LeaveNodeEndpoint(rpc store.NodeControlRPCInput, in nodewire.EndpointLeave) (*nodewire.EndpointRegistrationResult, error) {
	return s.store.LeaveNodeEndpoint(rpc, in)
}

func (s *Service) AvailableNodeNativePairs(rpc store.NodeControlRPCInput, controlPublic e2ee.PublicIdentity) (*nodewire.AvailableNativePairs, error) {
	return s.store.AvailableNodeNativePairs(rpc, controlPublic)
}
