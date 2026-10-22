package native

import (
	"testing"
	"time"

	"gioui.org/io/input"
	"gioui.org/layout"
	"gioui.org/op"
	"github.com/cicada-ai/cicada/internal/appcore"
)

func redrawFixture(now time.Time) appcore.Snapshot {
	stamp := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	return appcore.Snapshot{
		Hub:           appcore.HubSnapshot{Verified: true},
		Account:       appcore.AccountSnapshot{State: appcore.AccountStateSessionActive, RootState: appcore.RootStateActive, SessionExpiresAt: stamp(now.Add(10 * time.Minute))},
		Authorization: appcore.AuthorizationSnapshot{State: "EXPIRED", ExpiresAt: stamp(now.Add(-time.Hour))},
		Node: appcore.NodeSetupSnapshot{Available: true,
			Access:  appcore.NodeAccessSnapshot{State: "ACTIVE", Confirmed: true, ExpiresAt: stamp(now.Add(8 * time.Minute))},
			Binding: &appcore.NodeBindingSnapshot{ID: "synthetic-binding", NodeID: "synthetic-node", Authorized: true},
			Connectivity: appcore.NodeConnectivitySnapshot{State: "connected", Known: true, Current: true,
				LastHeartbeatAt: stamp(now), FreshUntil: stamp(now.Add(2 * time.Minute))},
		},
	}
}

// Run the actual production scheduling function and Gio's command/frame/router
// processing. No Win32 window, network request or user event is simulated here.
func redrawFrame(snapshot appcore.Snapshot, now time.Time) (time.Time, bool) {
	var router input.Router
	var ops op.Ops
	scheduleSnapshotRedraw(layout.Context{Ops: &ops, Source: router.Source(), Now: now}, snapshot, now)
	router.Frame(&ops)
	return router.WakeupTime()
}

func TestNativeRedrawLocalCollaborationDeadlinesResampleOnce(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute)
	for _, kind := range []string{"review", "policy"} {
		t.Run(kind, func(t *testing.T) {
			s := appcore.Snapshot{}
			if kind == "review" {
				s.LocalCollaboration.ReviewExpiresAt = deadline.Format(time.RFC3339Nano)
				s.AvailableActions = []appcore.ActionKind{appcore.ActionActivateLocalCollaboration}
			} else {
				s.LocalCollaboration.State = "ACTIVE"
				s.LocalCollaboration.ExpiresAt = deadline.Format(time.RFC3339Nano)
			}
			if at, wake := redrawFrame(s, now); !wake || !at.Equal(deadline) {
				t.Fatal("domain expiry did not schedule native wakeup")
			}
			if at, wake := redrawFrame(s, deadline); !wake || !at.IsZero() {
				t.Fatal("crossed domain deadline did not resample snapshot")
			}
			s.AvailableActions = nil
			s.LocalCollaboration.State = "EXPIRED"
			if _, wake := redrawFrame(s, deadline); wake {
				t.Fatal("expired domain projection caused idle redraw loop")
			}
		})
	}
	s := appcore.Snapshot{LocalCollaboration: appcore.LocalCollaborationSnapshot{State: "ACTIVE", Current: true}}
	if _, wake := redrawFrame(s, now); wake {
		t.Fatal("until-revoke policy invented a deadline")
	}
}

func TestNativeRedrawOwnerReadParkDeadlineResamplesOnce(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute)
	s := appcore.Snapshot{OwnerEndpoints: appcore.OwnerEndpointSnapshot{Pending: true, ParkAfter: deadline.Format(time.RFC3339Nano)}}
	if at, wake := redrawFrame(s, now); !wake || !at.Equal(deadline) {
		t.Fatal("pending readonly expiry has no native wakeup")
	}
	if at, wake := redrawFrame(s, deadline); !wake || !at.IsZero() {
		t.Fatal("crossed snapshot boundary did not request a fresh frame")
	}
	s.AvailableActions = []appcore.ActionKind{appcore.ActionParkOwnerEndpoints}
	if _, wake := redrawFrame(s, deadline); wake {
		t.Fatal("already exposed local retention creates an idle redraw loop")
	}
}

func TestNativeRedrawRetainsHeartbeatDeadlineAcrossSnapshotBoundary(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	snapshot := redrawFixture(now)
	deadline := now.Add(2 * time.Minute)
	if snapshot.Node.ConnectionState() != appcore.NodeOnline {
		t.Fatal("fixture did not capture an online projection before the deadline")
	}
	for _, at := range []time.Time{deadline, deadline.Add(time.Nanosecond)} {
		t.Run(at.Format(time.RFC3339Nano), func(t *testing.T) {
			// Snapshot was sampled before D, but layout reaches its deadline
			// selection at/after D. An immediate frame must resample it.
			wakeAt, wake := redrawFrame(snapshot, at)
			if !wake || !wakeAt.IsZero() {
				t.Fatalf("expired online projection scheduled %v (wake=%t), want immediate frame", wakeAt, wake)
			}
		})
	}
}

func TestNativeRedrawChoosesEarliestFutureDeadline(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name string
		edit func(*appcore.Snapshot)
		want time.Duration
	}{
		{"heartbeat-before-session-and-access", func(*appcore.Snapshot) {}, 2 * time.Minute},
		{"account", func(s *appcore.Snapshot) { s.Account.SessionExpiresAt = now.Add(time.Minute).Format(time.RFC3339Nano) }, time.Minute},
		{"node-access", func(s *appcore.Snapshot) { s.Node.Access.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339Nano) }, time.Minute},
		{"review", func(s *appcore.Snapshot) {
			s.Node.Candidate = &appcore.NodeCandidateSnapshot{ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
			s.AvailableActions = []appcore.ActionKind{appcore.ActionApproveNode}
		}, time.Minute},
		{"review-authorization", func(s *appcore.Snapshot) {
			s.Node.Candidate = &appcore.NodeCandidateSnapshot{ExpiresAt: now.Add(3 * time.Minute).Format(time.RFC3339Nano), AuthorizationExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
			s.AvailableActions = []appcore.ActionKind{appcore.ActionApproveNode}
		}, time.Minute},
		{"initial-access", func(s *appcore.Snapshot) {
			s.Authorization.State, s.Authorization.Confirmed = "ACTIVE", true
			s.Authorization.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339Nano)
		}, time.Minute},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := redrawFixture(now)
			tt.edit(&s)
			at, wake := redrawFrame(s, now)
			if !wake || !at.Equal(now.Add(tt.want)) {
				t.Fatalf("wakeup %v (wake=%t), want earliest %v", at, wake, now.Add(tt.want))
			}
		})
	}
}

func TestNativeRedrawResamplesOnlyLiveCrossedDeadlines(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Nanosecond).Format(time.RFC3339Nano)
	for _, tt := range []struct {
		name  string
		live  appcore.Snapshot
		ended appcore.Snapshot
	}{
		{"account", appcore.Snapshot{Account: appcore.AccountSnapshot{State: appcore.AccountStateSessionActive, SessionExpiresAt: past}},
			appcore.Snapshot{Account: appcore.AccountSnapshot{State: appcore.AccountStateLoginRequired, SessionExpiresAt: past}}},
		{"initial-access", appcore.Snapshot{Authorization: appcore.AuthorizationSnapshot{State: "ACTIVE", ExpiresAt: past}},
			appcore.Snapshot{Authorization: appcore.AuthorizationSnapshot{State: "EXPIRED", ExpiresAt: past}}},
		{"node-access", appcore.Snapshot{Node: appcore.NodeSetupSnapshot{Access: appcore.NodeAccessSnapshot{State: "ACTIVE", ExpiresAt: past}}},
			appcore.Snapshot{Node: appcore.NodeSetupSnapshot{Access: appcore.NodeAccessSnapshot{State: "EXPIRED", ExpiresAt: past}}}},
		{"review", appcore.Snapshot{AvailableActions: []appcore.ActionKind{appcore.ActionApproveNode}, Node: appcore.NodeSetupSnapshot{Candidate: &appcore.NodeCandidateSnapshot{ExpiresAt: past}}},
			appcore.Snapshot{Node: appcore.NodeSetupSnapshot{Candidate: &appcore.NodeCandidateSnapshot{ExpiresAt: past}}}},
		{"review-authorization", appcore.Snapshot{AvailableActions: []appcore.ActionKind{appcore.ActionApproveNode}, Node: appcore.NodeSetupSnapshot{Candidate: &appcore.NodeCandidateSnapshot{AuthorizationExpiresAt: past}}},
			appcore.Snapshot{Node: appcore.NodeSetupSnapshot{Candidate: &appcore.NodeCandidateSnapshot{AuthorizationExpiresAt: past}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if at, wake := redrawFrame(tt.live, now); !wake || !at.IsZero() {
				t.Fatalf("crossed live deadline did not resample: %v (wake=%t)", at, wake)
			}
			if at, wake := redrawFrame(tt.ended, now); wake {
				t.Fatalf("ended projection requested another frame: %v", at)
			}
		})
	}
}

func TestNativeRedrawDoesNotLoopOnStaleOrHistoricalDeadlines(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := redrawFixture(now)
	s.Node.Connectivity.Stale = true
	s.Node.Connectivity.FreshUntil = now.Add(-time.Second).Format(time.RFC3339Nano)
	at, wake := redrawFrame(s, now)
	if !wake || !at.Equal(now.Add(8*time.Minute)) {
		t.Fatalf("stale heartbeat/history displaced remaining access deadline: %v (wake=%t)", at, wake)
	}
	s.Account.State = appcore.AccountStateLoginRequired
	s.Account.SessionExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	s.Node.Access.State, s.Node.Access.Confirmed = "EXPIRED", false
	s.Node.Access.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	s.Node.Candidate = &appcore.NodeCandidateSnapshot{ExpiresAt: now.Add(-time.Second).Format(time.RFC3339Nano)}
	if at, wake := redrawFrame(s, now); wake {
		t.Fatalf("historical deadlines requested another idle frame: %v", at)
	}
}
