package fabric

import (
	"strings"
	"sync"
)

const (
	maxNodeSSEStreamsPerNode    = 4
	maxNodeSSEStreamsPerService = 256
)

// AdmitNodeSSEStream reserves one authenticated Node stream slot for the life
// of an HTTP SSE connection. The returned release function is safe to call
// more than once. Admission and release are O(1), and no event payload is
// queued by this counter.
func (s *Service) AdmitNodeSSEStream(nodeID string) (release func(), admitted bool) {
	if s == nil {
		return nil, false
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil, false
	}

	s.nodeSSEStreamMu.Lock()
	if s.nodeSSEStreamCount >= maxNodeSSEStreamsPerService ||
		s.nodeSSEStreams[nodeID] >= maxNodeSSEStreamsPerNode {
		s.nodeSSEStreamMu.Unlock()
		return nil, false
	}
	if s.nodeSSEStreams == nil {
		s.nodeSSEStreams = make(map[string]int)
	}
	s.nodeSSEStreams[nodeID]++
	s.nodeSSEStreamCount++
	s.nodeSSEStreamMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			s.nodeSSEStreamMu.Lock()
			if current := s.nodeSSEStreams[nodeID]; current > 0 {
				if current == 1 {
					delete(s.nodeSSEStreams, nodeID)
				} else {
					s.nodeSSEStreams[nodeID] = current - 1
				}
				s.nodeSSEStreamCount--
			}
			s.nodeSSEStreamMu.Unlock()
		})
	}, true
}

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
