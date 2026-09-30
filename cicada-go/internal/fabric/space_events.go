package fabric

import (
	"strings"
	"sync"
)

// SubscribeNodeSpaceEvents is separate from the immediate Relay claim channel.
// Missed events are recovered through SyncGroupSpace; an event never wakes a
// model or acknowledges a record as read.
func (s *Service) SubscribeNodeSpaceEvents(nodeID string) (<-chan struct{}, func()) {
	nodeID = strings.TrimSpace(nodeID)
	channel := make(chan struct{}, 1)
	s.spaceEventsMu.Lock()
	if s.spaceEvents == nil {
		s.spaceEvents = make(map[string]map[chan struct{}]struct{})
	}
	if s.spaceEvents[nodeID] == nil {
		s.spaceEvents[nodeID] = make(map[chan struct{}]struct{})
	}
	s.spaceEvents[nodeID][channel] = struct{}{}
	s.spaceEventsMu.Unlock()
	var once sync.Once
	return channel, func() {
		once.Do(func() {
			s.spaceEventsMu.Lock()
			delete(s.spaceEvents[nodeID], channel)
			if len(s.spaceEvents[nodeID]) == 0 {
				delete(s.spaceEvents, nodeID)
			}
			s.spaceEventsMu.Unlock()
		})
	}
}

// NotifyNodeSpaceHint emits only a generic coalesced signal after durable
// commit. The SSE service independently rechecks the current Node credential.
func (s *Service) NotifyNodeSpaceHint(nodeID string) {
	if s == nil || strings.TrimSpace(nodeID) == "" {
		return
	}
	s.spaceEventsMu.Lock()
	defer s.spaceEventsMu.Unlock()
	for channel := range s.spaceEvents[strings.TrimSpace(nodeID)] {
		select {
		case channel <- struct{}{}:
		default:
		}
	}
}
