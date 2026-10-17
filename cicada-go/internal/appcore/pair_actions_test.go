package appcore

import (
	"slices"
	"testing"
	"time"
)

func TestPairExpiryMasksEveryAdministrativeActionWithoutRevocation(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	for _, id := range []string{"", "synthetic-pair"} {
		s := Snapshot{Account: AccountSnapshot{State: AccountStateOwnerReady, SessionExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}, Pair: PairSetupSnapshot{PairID: id, State: "ACTIVE", Current: true, AdministrativePermission: true, PeerExpiresAt: now.Format(time.RFC3339Nano), ReviewExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}, AvailableActions: []ActionKind{ActionRefreshPair, ActionApprovePairSlot, ActionCompletePair, ActionPreparePairConsent, ActionRejectPairSlot, ActionRevokePair}}
		expirePairView(&s, now)
		if s.Pair.Current || s.Pair.AdministrativePermission || s.Pair.State != "EXPIRED" || len(s.AvailableActions) != 1 || s.AvailableActions[0] != ActionRefreshPair {
			t.Fatal("expired peer retained an administrative button or was locally revoked")
		}
	}
	s := Snapshot{Account: AccountSnapshot{State: AccountStateOwnerReady, SessionExpiresAt: now.Format(time.RFC3339Nano)}, AvailableActions: []ActionKind{ActionPreparePair, ActionRefreshPair}}
	expirePairView(&s, now)
	if slices.Contains(s.AvailableActions, ActionPreparePair) {
		t.Fatal("no-Pair account expiry retained prepare authority")
	}
}
