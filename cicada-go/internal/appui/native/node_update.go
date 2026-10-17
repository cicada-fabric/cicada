package native

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

const nodeStatusUpdateInterval = 30 * time.Second

func (u *nodeStatusUpdater) pauseForAccountScreen() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.armed = false
}

// The Windows frame loop and portable tests share this coordinator. All due
// decisions happen after foreground controls have had their turn in the frame.
type nodeStatusUpdater struct {
	mu                     sync.Mutex
	target                 appcore.NodeStatusTarget
	next                   time.Time
	armed, paused, running bool
	minimized, stopped     bool
	ctx                    context.Context
	cancel                 context.CancelFunc
}

func (u *nodeStatusUpdater) afterControls(s appcore.Snapshot, now time.Time, busy bool) (time.Time, *appcore.NodeStatusTarget) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.running {
		// The core also bounds HTTP by these deadlines. A frame observing a
		// lifecycle/authority change cancels promptly without making a new read.
		if u.cancel != nil && (u.target != nodeStatusTargetInView(s) || s.Node.Candidate != nil ||
			s.Node.Access.State != "ACTIVE" || !nodeUpdateDeadlinesLive(s, now)) {
			u.cancel()
		}
		return time.Time{}, nil
	}
	if u.stopped || u.minimized || u.paused {
		return time.Time{}, nil
	}
	target, ok := appcore.AutomaticNodeStatusTarget(s, now)
	if !ok || busy {
		u.armed = false
		return time.Time{}, nil
	}
	if !u.armed || target != u.target {
		u.target, u.next, u.armed = target, now.Add(nodeStatusUpdateInterval), true
	}
	if now.Before(u.next) {
		return u.next, nil
	}
	u.armed, u.running = false, true
	copy := target
	return time.Time{}, &copy
}

func (u *nodeStatusUpdater) begin(parent context.Context) context.Context {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ctx, u.cancel = context.WithCancel(parent)
	if u.stopped || u.paused {
		u.cancel()
	}
	return u.ctx
}

func (u *nodeStatusUpdater) complete(s appcore.Snapshot, now time.Time, err error) {
	u.completeAndRelease(s, now, err, nil)
}

func (u *nodeStatusUpdater) completeAndRelease(s appcore.Snapshot, now time.Time, err error, release func()) {
	u.mu.Lock()
	defer u.mu.Unlock()
	defer func() {
		// Release UI busy ownership after every old-job state write. A new
		// foreground scope starts only after this final release.
		if release != nil {
			release()
		}
	}()
	if u.cancel != nil {
		u.cancel()
	}
	u.ctx, u.cancel = nil, nil
	u.running = false
	target, eligible := appcore.AutomaticNodeStatusTarget(s, now)
	if err != nil && !errors.Is(err, appcore.ErrControllerBusy) {
		u.paused, u.armed = true, false
		return
	}
	if !eligible || target != u.target || u.stopped || u.minimized {
		u.armed = false
		return
	}
	u.next, u.armed = now.Add(nodeStatusUpdateInterval), true
}

func (u *nodeStatusUpdater) foregroundCompleted(s appcore.Snapshot, now time.Time, action appcore.Action, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.armed = false
	if u.stopped || err != nil {
		return
	}
	target, eligible := appcore.AutomaticNodeStatusTarget(s, now)
	if !eligible {
		return
	}
	if u.paused {
		switch action.Kind {
		case appcore.ActionRefreshNode, appcore.ActionRecoverNode, appcore.ActionRefresh, appcore.ActionApproveNode, appcore.ActionResumeProfile:
			u.paused = false
		default:
			return
		}
	}
	u.target, u.next, u.armed = target, now.Add(nodeStatusUpdateInterval), true
}

func (u *nodeStatusUpdater) setMinimized(minimized bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.minimized != minimized {
		u.minimized, u.armed = minimized, false
	}
	// Minimizing is not cancellation or revocation. An existing read finishes.
}

func (u *nodeStatusUpdater) close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopped, u.armed = true, false
	if u.cancel != nil {
		u.cancel()
	}
}

func nodeStatusTargetInView(s appcore.Snapshot) appcore.NodeStatusTarget {
	if s.Node.Binding == nil {
		return appcore.NodeStatusTarget{}
	}
	b := s.Node.Binding
	return appcore.NodeStatusTarget{Origin: s.Hub.Origin, HubID: s.Hub.HubID, AccountID: s.Account.AccountID,
		OwnerID: s.Account.OwnerID, DeviceID: s.Account.DeviceID, BindingID: b.ID, NodeID: b.NodeID,
		BindingVersion: b.Version, ReviewID: s.Node.Access.ReviewID}
}

// This changes presentation only for our own normal in-flight read. It never
// overlays an old ACTIVE/Current value or grants an action during the request.
func (u *nodeStatusUpdater) showingProgress(s appcore.Snapshot, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.running || u.ctx == nil || u.ctx.Err() != nil || u.target != nodeStatusTargetInView(s) ||
		!s.Node.Pending || s.Node.Candidate != nil || s.ErrorCode != "" || s.Node.ErrorCode != "" ||
		!s.Hub.Verified || s.Account.RootState != appcore.RootStateActive ||
		(s.Account.State != appcore.AccountStateSessionActive && s.Account.State != appcore.AccountStateOwnerReady) || s.Node.Access.State != "ACTIVE" {
		return false
	}
	for _, kind := range s.AvailableActions {
		if kind == appcore.ActionRecover || kind == appcore.ActionRetry {
			return false
		}
	}
	return nodeUpdateDeadlinesLive(s, now)
}

func nodeUpdateDeadlinesLive(s appcore.Snapshot, now time.Time) bool {
	if !s.Hub.Verified || s.Account.RootState != appcore.RootStateActive ||
		(s.Account.State != appcore.AccountStateSessionActive && s.Account.State != appcore.AccountStateOwnerReady) {
		return false
	}
	for _, raw := range []string{s.Account.SessionExpiresAt, s.Node.Access.ExpiresAt} {
		end, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || !now.Before(end) {
			return false
		}
	}
	return true
}

func (u *nodeStatusUpdater) accountFlow(s appcore.Snapshot, now time.Time) appui.SetupFlow {
	if !u.showingProgress(s, now) {
		return appui.Flow(s)
	}
	// This is only a layout decision for the known running read. The actual
	// snapshot and all authority/freshness fields remain untouched.
	copy := s
	copy.Node.Pending = false
	copy.AvailableActions = nil
	for _, kind := range s.AvailableActions {
		if kind != appcore.ActionRecoverNode {
			copy.AvailableActions = append(copy.AvailableActions, kind)
		}
	}
	return appui.Flow(copy)
}
