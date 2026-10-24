package native

import (
	"github.com/cicada-ai/cicada/internal/appcore"
	"testing"
	"time"
)

func TestDevicePairingWaitPollNeverRetriesUncertainOrExpiredWork(t *testing.T) {
	now := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	snapshot := func() appcore.Snapshot {
		return appcore.Snapshot{Hub: appcore.HubSnapshot{Verified: true}, Account: appcore.AccountSnapshot{SessionExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}, Node: appcore.NodeSetupSnapshot{Pairing: &appcore.NodePairingSnapshot{State: "OWNER_APPROVED", ReviewID: "synthetic-exact-review", ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}}, AvailableActions: []appcore.ActionKind{appcore.ActionRefreshNodePairing}}
	}
	var p nodePairingPollScheduler
	s := snapshot()
	at, due := p.next(s, now, false)
	if due || !at.Equal(now.Add(5*time.Second)) {
		t.Fatal("waiting poll did not schedule a bounded status read")
	}
	if _, due := p.next(s, at, true); due {
		t.Fatal("waiting poll interrupted foreground work")
	}
	if _, due := p.next(s, at, false); !due {
		t.Fatal("due observation did not run")
	}
	if _, due := p.next(s, at, false); due {
		t.Fatal("one frame queued duplicate status reads")
	}
	for _, mode := range []string{"unknown", "refused", "acked", "unverified", "missing-action", "expired-code", "expired-session"} {
		t.Run(mode, func(t *testing.T) {
			s := snapshot()
			switch mode {
			case "unknown":
				s.Node.Pairing.State = "UNKNOWN"
			case "refused":
				s.Node.Pairing.ErrorCode = "APP_NODE_PAIRING_UNKNOWN"
			case "acked":
				s.Node.Pairing.State = "ACKED"
			case "unverified":
				s.Hub.Verified = false
			case "missing-action":
				s.AvailableActions = nil
			case "expired-code":
				s.Node.Pairing.ExpiresAt = now.Format(time.RFC3339Nano)
			case "expired-session":
				s.Account.SessionExpiresAt = now.Format(time.RFC3339Nano)
			}
			if at, due := p.next(s, now.Add(time.Second*10), false); due || !at.IsZero() {
				t.Fatal("observation became hidden mutation retry or renewed expired authority")
			}
		})
	}
}

func TestDevicePairingDeadlineRedrawSamplesOnceWithoutIdleLoop(t *testing.T) {
	now := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute)
	s := appcore.Snapshot{Node: appcore.NodeSetupSnapshot{Pairing: &appcore.NodePairingSnapshot{State: "OWNER_APPROVED", ExpiresAt: deadline.Format(time.RFC3339Nano)}}}
	if at, wake := redrawFrame(s, now); !wake || !at.Equal(deadline) {
		t.Fatal("waiting deadline did not schedule a redraw")
	}
	if at, wake := redrawFrame(s, deadline); !wake || !at.IsZero() {
		t.Fatal("crossed pairing deadline lost the next sample")
	}
	s.Node.Pairing.DeadlineReached = true
	if _, wake := redrawFrame(s, deadline); wake {
		t.Fatal("local deadline copy created an idle redraw loop")
	}
}
