package fabric

import "github.com/cicada-ai/cicada/internal/store"

// NodeCommunicationLinkAuthorizationBundle derives both Node and owner from
// the current outbound Relay credential, then returns public approval evidence.
// The Node must verify it against locally trusted owner keys; this method does
// not authorize message delivery.
func (s *Service) NodeCommunicationLinkAuthorizationBundle(nodeToken, linkID string) (*store.CommunicationLinkAuthorizationBundle, error) {
	return s.store.GetCommunicationLinkAuthorizationBundleForNodeCredential(HashSessionCredential(nodeToken), linkID)
}
