package fabric

import "github.com/cicada-ai/cicada/internal/store"

type LocalDeliveryAuthorizationInput = store.LocalDeliveryAuthorizationInput
type LocalDeliveryRevalidationInput = store.LocalDeliveryRevalidationInput
type LocalDeliveryAuthorization = store.LocalDeliveryAuthorization

// AuthorizeNodeLocalDelivery returns the current read-only authorization
// snapshot for a Node's same-Group local adapter. Both credentials are
// hashed before the Store lookup; callers must re-call immediately before
// native queue injection.
func (s *Service) AuthorizeNodeLocalDelivery(nodeToken, sessionToken string,
	input LocalDeliveryAuthorizationInput) (*LocalDeliveryAuthorization, error) {
	return s.store.AuthorizeLocalDeliveryForNodeCredential(
		HashSessionCredential(nodeToken), HashSessionCredential(sessionToken), input)
}

// RevalidateNodeLocalDelivery repeats the current authorization checks for an
// exact route stored by the Node's durable inbox. It requires the current Node
// credential but no longer depends on the original Session bearer.
func (s *Service) RevalidateNodeLocalDelivery(nodeToken string,
	input LocalDeliveryRevalidationInput) (*LocalDeliveryAuthorization, error) {
	return s.store.RevalidateLocalDeliveryForNodeCredential(HashSessionCredential(nodeToken), input)
}
