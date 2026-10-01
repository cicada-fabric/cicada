package fabric

import "github.com/cicada-ai/cicada/internal/store"

func (s *Service) PreviewNetworkBroadcastRecipients(actor NetworkActor) (*store.NetworkBroadcastRecipientSnapshot, error) {
	snapshot, err := s.store.PreviewNetworkBroadcastRecipients(networkDirectoryScope(actor))
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrPermissionDenied
	}
	return snapshot, err
}

func (s *Service) PublishNetworkBroadcast(actor NetworkActor,
	input store.NetworkBroadcastPublishInput) (*store.NetworkBroadcast, error) {
	broadcast, err := s.store.PublishNetworkBroadcast(networkDirectoryScope(actor), input)
	if err == store.ErrNetworkPermission || err == store.ErrNetworkDirectKeyUnavailable {
		return nil, ErrPermissionDenied
	}
	if err == nil {
		for _, recipient := range broadcast.Recipients {
			s.notifyNetworkDirectTarget(recipient.EndpointID)
		}
	}
	return broadcast, err
}

func (s *Service) GetNetworkBroadcast(actor NetworkActor,
	broadcastID string) (*store.NetworkBroadcast, error) {
	broadcast, err := s.store.GetNetworkBroadcast(networkDirectoryScope(actor), broadcastID)
	if err == store.ErrNetworkPermission {
		return nil, ErrPermissionDenied
	}
	return broadcast, err
}
