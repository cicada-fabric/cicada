package appui

import (
	"slices"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

type PairSetupFlow struct {
	Visible          bool
	Stage            string
	Prepare          bool
	BootstrapConsent bool
	ReviewSlots      bool
	SlotAConsent     bool
	SlotBConsent     bool
	Refresh          bool
	Revoke           bool
	Recover          bool
}

func PairFlow(s appcore.Snapshot, now time.Time) PairSetupFlow {
	if !AccountInformationVisible(s, now) {
		return PairSetupFlow{}
	}
	has := func(kind appcore.ActionKind) bool { return slices.Contains(s.AvailableActions, kind) }
	f := PairSetupFlow{Visible: s.Pair.PairID != "" || has(appcore.ActionPreparePair), Stage: "saved", Refresh: has(appcore.ActionRefreshPair)}
	if s.Pair.Pending && has(appcore.ActionRecoverPair) {
		f.Visible, f.Stage, f.Recover = true, "recovery", true
		return f
	}
	if has(appcore.ActionPreparePair) {
		f.Stage, f.Prepare = "prepare", true
		return f
	}
	if has(appcore.ActionCompletePair) {
		f.Stage, f.BootstrapConsent = "bootstrap-review", true
	}
	if has(appcore.ActionApprovePairSlot) {
		f.Stage = "slot-review"
		f.SlotAConsent, f.SlotBConsent = !s.Pair.Slots[0].ConsentRecorded, !s.Pair.Slots[1].ConsentRecorded
	}
	f.ReviewSlots, f.Revoke = has(appcore.ActionPreparePairConsent), has(appcore.ActionRevokePair)
	return f
}
