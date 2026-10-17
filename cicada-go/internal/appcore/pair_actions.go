package appcore

import (
	"slices"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) pairActions() []ActionKind {
	if c.storageFault || c.profileRecoveryRequired || !c.connected || c.vault == nil || c.device == nil {
		return nil
	}
	if c.hasPairPending() {
		return []ActionKind{ActionRecoverPair}
	}
	if c.hasNodePending() || !canBeginOperation(c.state.Pending) || c.state.Recovery != nil {
		return nil
	}
	var actions []ActionKind
	if c.pair.View.PairID != "" {
		actions = append(actions, ActionRefreshPair)
	}
	if !c.pairAccountReady() {
		return actions
	}
	if c.pair.View.PairID == "" || c.pair.View.State == string(wire.NativePairExpired) || c.pair.View.State == string(wire.NativePairRevoked) {
		return append(actions, ActionPreparePair)
	}
	if !c.pair.View.Current || !c.pair.View.AdministrativePermission {
		return actions
	}
	if c.pairReview != nil && c.cfg.Now().UTC().Before(parseExpiry(c.pair.View.ReviewExpiresAt)) {
		switch c.pairReview.Original.Route.Operation {
		case wire.OperationNativePairBootstrapPrepare:
			actions = append(actions, ActionCompletePair)
		case wire.OperationNativePairConsentPrepare:
			if !c.pair.View.Slots[0].ConsentRecorded || !c.pair.View.Slots[1].ConsentRecorded {
				actions = append(actions, ActionApprovePairSlot)
			}
		}
	}
	if current := c.pairCurrent; current != nil {
		if current.State == wire.NativePairWaitingJoin || current.State == wire.NativePairWaitingConsent {
			if current.SlotA != nil && current.SlotB != nil &&
				(current.SlotAState == wire.NativePairSlotCandidateReady || current.SlotAState == wire.NativePairSlotConsentRecorded) &&
				(current.SlotBState == wire.NativePairSlotCandidateReady || current.SlotBState == wire.NativePairSlotConsentRecorded) {
				actions = append(actions, ActionPreparePairConsent)
			}
			if current.SlotA != nil && current.SlotA.NativeSessionID != "" || current.SlotB != nil && current.SlotB.NativeSessionID != "" {
				actions = append(actions, ActionRejectPairSlot)
			}
		}
		if current.State != wire.NativePairRevoked {
			actions = append(actions, ActionRevokePair)
		}
	}
	return actions
}

func (c *nativeController) populatePair(view *Snapshot) {
	view.Pair = c.pair.View
	view.Pair.Available, view.Pair.Pending, view.Pair.ErrorCode = c.pairAvailable, c.hasPairPending(), c.pairError
}

func expirePairView(view *Snapshot, now time.Time) {
	accountLive := view.Account.State == AccountStateSessionActive || view.Account.State == AccountStateOwnerReady || view.Account.State == AccountStateOwnerProof
	if !accountLive || !now.Before(parseExpiry(view.Account.SessionExpiresAt)) {
		view.Pair.AdministrativePermission = false
	}
	if end := parseExpiry(view.Pair.PeerExpiresAt); !end.IsZero() && !now.Before(end) {
		view.Pair.Current, view.Pair.AdministrativePermission = false, false
		if view.Pair.State == string(wire.NativePairActive) {
			view.Pair.State = string(wire.NativePairExpired)
		}
	}
	liveReview := now.Before(parseExpiry(view.Pair.ReviewExpiresAt))
	view.AvailableActions = slices.DeleteFunc(view.AvailableActions, func(kind ActionKind) bool {
		switch kind {
		case ActionCompletePair, ActionApprovePairSlot:
			return !view.Pair.Current || !view.Pair.AdministrativePermission || !liveReview
		case ActionPreparePairConsent, ActionRejectPairSlot, ActionRevokePair:
			return !view.Pair.Current || !view.Pair.AdministrativePermission
		case ActionPreparePair:
			return !accountLive || !now.Before(parseExpiry(view.Account.SessionExpiresAt))
		}
		return false
	})
}
