package appui

import (
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

func TestPairFlowRequiresLoginAndSeparateSlotApprovals(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	s := accountDisplayFixture(now)
	s.AvailableActions = []appcore.ActionKind{appcore.ActionApprovePairSlot, appcore.ActionRefreshPair}
	s.Pair.Slots[0].ConsentRecorded = true
	f := PairFlow(s, now)
	if !f.Visible || f.Stage != "slot-review" || f.SlotAConsent || !f.SlotBConsent {
		t.Fatal("one recorded consent enabled both sessions or lost the remaining explicit decision")
	}
	s.Account.State = appcore.AccountStateLoginRequired
	s.AvailableActions = []appcore.ActionKind{appcore.ActionLogin, appcore.ActionRecoverPair}
	s.Pair.Pending = true
	if PairFlow(s, now).Visible {
		t.Fatal("signed-out UI exposed Pair session metadata")
	}
	p := PresentScreen(s, now)
	if p.Flow.Primary != appcore.ActionRecoverPair || p.Flow.Password || p.Snapshot.Pair.PairID != "" || p.Snapshot.Pair.Slots[0].NativeSessionID != "" {
		t.Fatal("original recovery required login or disclosed a Pair target")
	}
}

func TestAccountExpiryHidesPairWithoutRevokingItsRecordedPeerState(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	s := accountDisplayFixture(now)
	s.Account.SessionExpiresAt = now.Format(time.RFC3339Nano)
	peerEnd := s.Pair.PeerExpiresAt
	p := PresentScreen(s, now)
	if p.InformationVisible || p.Snapshot.Pair.State != "" || s.Pair.State != "ACTIVE" || s.Pair.PeerExpiresAt != peerEnd {
		t.Fatal("account expiry disclosed Pair state or changed the independent peer lifetime")
	}
}

func TestPairRecoveryAndPublicExportHaveVisibleNativeFlowEntries(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	s := accountDisplayFixture(now)
	s.Setup.OwnerKeyStored = true
	s.AvailableActions = []appcore.ActionKind{appcore.ActionRefresh, appcore.ActionLogout, appcore.ActionExportOwnerPublic}
	f := PresentScreen(s, now).Flow
	found := false
	for _, a := range f.Secondary {
		found = found || a == appcore.ActionExportOwnerPublic
	}
	if !found {
		t.Fatal("local public key export has no native flow entry")
	}
	s.Pair.Pending = true
	s.AvailableActions = []appcore.ActionKind{appcore.ActionConnect, appcore.ActionRecoverPair}
	f = PresentScreen(s, now).Flow
	if f.Stage != "pair-recovery" || f.Primary != "" || PairFlow(s, now).Stage != "recovery" {
		t.Fatal("uncertain Pair offered a new connection instead of its dedicated recovery")
	}
}
