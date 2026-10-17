package native

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gioui.org/io/input"
	"gioui.org/layout"
	"gioui.org/op"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

func autoStatusView(now time.Time) appcore.Snapshot {
	s := redrawFixture(now)
	s.Hub.Origin, s.Hub.HubID = "https://synthetic-auto.invalid", "synthetic-hub"
	s.Account.AccountID, s.Account.OwnerID, s.Account.DeviceID = "synthetic-account", "synthetic-owner", "synthetic-app"
	s.Node.Binding.Version, s.Node.Access.ReviewID = 1, strings.Repeat("a", 64)
	s.AvailableActions = []appcore.ActionKind{appcore.ActionRefresh, appcore.ActionLogout, appcore.ActionRefreshNode}
	return s
}

func beginAutoStatus(t *testing.T, u *nodeStatusUpdater, s appcore.Snapshot, now time.Time) context.Context {
	t.Helper()
	if at, target := u.afterControls(s, now, false); target != nil || !at.Equal(now.Add(30*time.Second)) {
		t.Fatal("eligible view did not schedule its first interval")
	}
	if _, target := u.afterControls(s, now.Add(30*time.Second), false); target == nil {
		t.Fatal("due view did not claim an automatic read")
	}
	return u.begin(context.Background())
}

func inFlightAutoView(s appcore.Snapshot) appcore.Snapshot {
	s.Node.Pending, s.Node.Access.Confirmed, s.Node.Connectivity.Current = true, false, false
	s.AvailableActions = []appcore.ActionKind{appcore.ActionRefresh, appcore.ActionLogout, appcore.ActionRecoverNode}
	return s
}

func TestNativeAutomaticStatusSchedulesThroughGioAndContinuesFromUnknownOrStale(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, state := range []string{"unknown", "stale", "connected"} {
		t.Run(state, func(t *testing.T) {
			var u nodeStatusUpdater
			s := autoStatusView(now)
			s.Node.Connectivity.State = state
			s.Node.Connectivity.Known = state != "unknown"
			var router input.Router
			var ops op.Ops
			at, target := u.afterControls(s, now, false)
			if target != nil {
				t.Fatal("first eligible frame sent immediately")
			}
			layout.Context{Ops: &ops, Source: router.Source()}.Execute(op.InvalidateCmd{At: at})
			router.Frame(&ops)
			if wake, ok := router.WakeupTime(); !ok || !wake.Equal(now.Add(30*time.Second)) {
				t.Fatal("production scheduler did not provide a real Gio interval wakeup")
			}
			if _, target = u.afterControls(s, now.Add(30*time.Second), false); target == nil {
				t.Fatal("non-online status prevented the next authorized observation")
			}
			u.begin(context.Background())
			if _, another := u.afterControls(inFlightAutoView(s), now.Add(31*time.Second), true); another != nil {
				t.Fatal("in-flight pending produced a second packet")
			}
			u.complete(s, now.Add(35*time.Second), nil)
			if at, next := u.afterControls(s, now.Add(time.Minute), false); next != nil || !at.Equal(now.Add(65*time.Second)) {
				t.Fatal("next interval was measured from claim instead of completion")
			}
			u.close()
		})
	}
}

func TestNativeAutomaticStatusForegroundBusyDropsTickAndMinimizeDoesNotCancel(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := autoStatusView(now)
	var u nodeStatusUpdater
	u.afterControls(s, now, false)
	// The real renderer calls this after processing the manual button. The
	// foreground busy flag therefore wins even when both are due this frame.
	if at, target := u.afterControls(s, now.Add(30*time.Second), true); target != nil || !at.IsZero() {
		t.Fatal("automatic tick took a frame already claimed by a manual action")
	}
	u.foregroundCompleted(s, now.Add(32*time.Second), appcore.Action{Kind: appcore.ActionRefreshNode}, nil)
	if at, target := u.afterControls(s, now.Add(time.Minute), false); target != nil || !at.Equal(now.Add(62*time.Second)) {
		t.Fatal("manual completion did not restart the interval")
	}
	_, target := u.afterControls(s, now.Add(62*time.Second), false)
	if target == nil {
		t.Fatal("authorized interval did not resume")
	}
	ctx := u.begin(context.Background())
	u.setMinimized(true)
	if ctx.Err() != nil {
		t.Fatal("minimization cancelled a legitimate in-flight request")
	}
	u.complete(s, now.Add(63*time.Second), nil)
	if at, next := u.afterControls(s, now.Add(2*time.Minute), false); next != nil || !at.IsZero() {
		t.Fatal("minimized window started a new interval")
	}
	u.setMinimized(false)
	at, _ := u.afterControls(s, now.Add(2*time.Minute), false)
	u.setMinimized(false) // Unchanged mode, including focus-only config events.
	if after, next := u.afterControls(s, now.Add(121*time.Second), false); next != nil || !after.Equal(at) {
		t.Fatal("unchanged window mode reset or accelerated the restored interval")
	}
	u.close()
}

func TestNativeAutomaticStatusFailurePausesUntilExplicitFreshRecovery(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := autoStatusView(now)
	var u nodeStatusUpdater
	beginAutoStatus(t, &u, s, now)
	pending := inFlightAutoView(s)
	pending.Node.ErrorCode = "APP_NODE_REQUEST_UNKNOWN"
	if u.showingProgress(pending, now.Add(31*time.Second)) || u.accountFlow(pending, now).Stage != "node-recovery" {
		t.Fatal("a failed read was hidden behind normal background progress")
	}
	u.complete(pending, now.Add(31*time.Second), errors.New("synthetic lost response"))
	for _, later := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
		if at, target := u.afterControls(s, now.Add(later), false); target != nil || !at.IsZero() {
			t.Fatal("error latch silently started a new packet")
		}
	}
	u.foregroundCompleted(s, now.Add(3*time.Minute), appcore.Action{Kind: appcore.ActionSelectCanvas}, nil)
	if _, target := u.afterControls(s, now.Add(4*time.Minute), false); target != nil {
		t.Fatal("unrelated local interaction cleared the error latch")
	}
	u.foregroundCompleted(s, now.Add(4*time.Minute), appcore.Action{Kind: appcore.ActionRecoverNode}, nil)
	if _, target := u.afterControls(s, now.Add(4*time.Minute+30*time.Second), false); target == nil {
		t.Fatal("explicit current recovery did not resume the interval")
	}
	u.complete(s, now.Add(4*time.Minute+31*time.Second), nil)
	u.close()
}

func TestNativeAutomaticStatusProgressNeverRestoresAuthorityAcrossExpiry(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := autoStatusView(now)
	s.Node.Access.ExpiresAt = now.Add(35 * time.Second).Format(time.RFC3339Nano)
	var u nodeStatusUpdater
	ctx := beginAutoStatus(t, &u, s, now)
	pending := inFlightAutoView(s)
	if !u.showingProgress(pending, now.Add(31*time.Second)) || u.accountFlow(pending, now.Add(31*time.Second)).Stage != "ready" {
		t.Fatal("normal background read flashed packet recovery")
	}
	if !pending.Node.Pending || pending.Node.Access.Confirmed || pending.Node.Connectivity.Current ||
		appui.NodeObservationVisible(pending) || pending.Node.ConnectionState() == appcore.NodeOnline {
		t.Fatal("quiet presentation overlaid old live authority or observation")
	}
	u.afterControls(pending, now.Add(35*time.Second), true)
	if ctx.Err() == nil || u.showingProgress(pending, now.Add(35*time.Second)) {
		t.Fatal("in-flight update kept its progress/authority past the access deadline")
	}
	u.complete(pending, now.Add(35*time.Second), ctx.Err())
	u.close()
}

func TestNativeAutomaticStatusCloseSurvivesClaimBeforeBegin(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := autoStatusView(now)
	var u nodeStatusUpdater
	u.afterControls(s, now, false)
	u.afterControls(s, now.Add(30*time.Second), false)
	u.close()
	ctx := u.begin(context.Background())
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("close was lost between frame claim and worker context creation")
	}
	u.complete(s, now.Add(31*time.Second), ctx.Err())
	if at, target := u.afterControls(s, now.Add(time.Minute), false); target != nil || !at.IsZero() {
		t.Fatal("closed updater started another request")
	}
}

func TestNativeAutomaticStatusScopeWaitsForFinalBusyRelease(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := autoStatusView(now)
	var u nodeStatusUpdater
	ctx := beginAutoStatus(t, &u, s, now)
	var busy, autoBusy atomic.Bool
	busy.Store(true)
	autoBusy.Store(true)
	if busy.CompareAndSwap(false, true) || ctx.Err() != nil {
		t.Fatal("foreground scope preempted or cancelled an in-flight read")
	}
	u.completeAndRelease(s, now.Add(31*time.Second), nil, func() {
		if !busy.Load() {
			t.Fatal("old worker released foreground ownership before its final writes")
		}
		autoBusy.Store(false)
		busy.Store(false)
	})
	if autoBusy.Load() || !busy.CompareAndSwap(false, true) {
		t.Fatal("completed read did not release its UI busy ownership")
	}
	other := s
	other.Hub.HubID = "synthetic-other-hub"
	u.foregroundCompleted(other, now.Add(32*time.Second), appcore.Action{Kind: appcore.ActionResumeProfile}, nil)
	if !busy.Load() || u.showingProgress(inFlightAutoView(other), now.Add(33*time.Second)) {
		t.Fatal("old completion cleared the new job's busy flag or entered its view")
	}
	busy.Store(false)
	if _, target := u.afterControls(other, now.Add(62*time.Second), false); target == nil || target.HubID != other.Hub.HubID {
		t.Fatal("new profile did not establish its own delayed interval")
	}
	u.complete(other, now.Add(63*time.Second), nil)
	u.close()
}
