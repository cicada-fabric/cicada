package fabric

import "github.com/cicada-ai/cicada/internal/store"

// NodeSameGroupBroadcastV2SnapshotInput selects a Group and a stable
// broadcast ID. Sender identity is derived from the current Session binding
// by Store; neither this DTO nor the Node adapter accepts a sender selector.
type NodeSameGroupBroadcastV2SnapshotInput struct {
	GroupID     string `json:"group_id"`
	BroadcastID string `json:"broadcast_id"`
}

// CreateNodeSameGroupBroadcastV2Snapshot asks Store to create or return the
// immutable same-Group recipient snapshot for a currently bound Node and
// Session. The Hub receives both bearer credentials only to hash them; it
// persists neither plaintext credential and does not accept caller-supplied
// sender identity.
func (s *Service) CreateNodeSameGroupBroadcastV2Snapshot(nodeToken, sessionToken string,
	input NodeSameGroupBroadcastV2SnapshotInput) (*store.SameGroupBroadcastV2Snapshot, error) {
	return s.store.CreateSameGroupBroadcastV2Snapshot(store.SameGroupBroadcastV2SnapshotInput{
		NodeCredentialDigest:    HashSessionCredential(nodeToken),
		SessionCredentialDigest: HashSessionCredential(sessionToken),
		GroupID:                 input.GroupID,
		BroadcastID:             input.BroadcastID,
	})
}

// ClientHubID returns this Fabric Store's configured Hub identity so Node
// adapters can bind an authorization snapshot to the Hub that produced it.
func (s *Service) ClientHubID() (string, error) {
	return s.store.GetClientHubID()
}
