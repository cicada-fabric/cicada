package fabric

import (
	"strings"
	"sync"
)

// SubscribeNodeEvents registers an in-process wake hint for one Node. The
// durable Relay inbox remains authoritative: a missed hint is recovered by
// claiming after reconnect or during periodic reconciliation. The returned
// channel never carries message bodies or endpoint details.
func (s *Service) SubscribeNodeEvents(nodeID string) (<-chan struct{}, func()) {
	nodeID = strings.TrimSpace(nodeID)
	channel := make(chan struct{}, 1)
	s.nodeEventsMu.Lock()
	if s.nodeEvents == nil {
		s.nodeEvents = make(map[string]map[chan struct{}]struct{})
	}
	if s.nodeEvents[nodeID] == nil {
		s.nodeEvents[nodeID] = make(map[chan struct{}]struct{})
	}
	s.nodeEvents[nodeID][channel] = struct{}{}
	s.nodeEventsMu.Unlock()
	var once sync.Once
	return channel, func() {
		once.Do(func() {
			s.nodeEventsMu.Lock()
			delete(s.nodeEvents[nodeID], channel)
			if len(s.nodeEvents[nodeID]) == 0 {
				delete(s.nodeEvents, nodeID)
			}
			s.nodeEventsMu.Unlock()
		})
	}
}

// NotifyNodeClaimHint publishes a generic, coalesced wake hint after the
// caller has committed durable work for this Node. The hint carries no payload;
// Node authorization and delivery remain guarded by the durable claim APIs.
func (s *Service) NotifyNodeClaimHint(nodeID string) {
	if s == nil {
		return
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	s.notifyNode(nodeID)
}

// notifyNode is intentionally nonblocking. It runs only after a message has
// been committed, and coalescing wake hints cannot lose durable messages.
func (s *Service) notifyNode(nodeID string) {
	s.nodeEventsMu.Lock()
	defer s.nodeEventsMu.Unlock()
	for channel := range s.nodeEvents[strings.TrimSpace(nodeID)] {
		select {
		case channel <- struct{}{}:
		default:
		}
	}
}
