package native

import (
	"github.com/cicada-ai/cicada/internal/appcore"
	"slices"
	"time"
)

// Only schedule the explicit, typed ACK status read while its existing
// authority and deadline are live. No model loop, service or hidden retry of an
// uncertain mutation is introduced. A failure stops polling until user action.
type nodePairingPollScheduler struct {
	review string
	at     time.Time
}

func (p *nodePairingPollScheduler) reset() { *p = nodePairingPollScheduler{} }
func (p *nodePairingPollScheduler) next(s appcore.Snapshot, now time.Time, busy bool) (time.Time, bool) {
	t := s.Node.Pairing
	if t == nil || t.State != "OWNER_APPROVED" || t.ReviewID == "" || t.ErrorCode != "" || s.ErrorCode != "" || !s.Hub.Verified || !slices.Contains(s.AvailableActions, appcore.ActionRefreshNodePairing) {
		p.reset()
		return time.Time{}, false
	}
	for _, raw := range []string{t.ExpiresAt, s.Account.SessionExpiresAt} {
		end, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || !now.Before(end) {
			p.reset()
			return time.Time{}, false
		}
	}
	if busy {
		return time.Time{}, false
	}
	if p.review != t.ReviewID || p.at.IsZero() {
		p.review = t.ReviewID
		p.at = now.Add(5 * time.Second)
	}
	if now.Before(p.at) {
		return p.at, false
	}
	p.at = now.Add(5 * time.Second)
	return p.at, true
}
