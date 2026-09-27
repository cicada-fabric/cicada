package fabric

import "github.com/cicada-ai/cicada/internal/store"

type RelayNativeWakeAuthorization = store.RelayNativeWakeAuthorization
type RelayNativeWakeAuthorizationInput = store.RelayNativeWakeAuthorizationInput

// AuthorizeNodeNativeWake re-reads the current credential, attempt, lease,
// Endpoint, and Group joins under one Store transaction. The response is a
// coordinate-only snapshot with no message body or credential material.
func (s *Service) AuthorizeNodeNativeWake(nodeToken, nodeID string,
	input RelayNativeWakeAuthorizationInput) (*RelayNativeWakeAuthorization, error) {
	return s.store.AuthorizeRelayNativeWakeForNodeCredential(HashSessionCredential(nodeToken), nodeID, input)
}
