package appcore

import "github.com/cicada-ai/cicada/internal/appvault"

const (
	ActionUnbindApp         ActionKind = "UNBIND_CURRENT_APP_FROM_HUB"
	ActionRebindApp         ActionKind = "REBIND_CURRENT_APP_TO_HUB"
	ActionRecoverAppBinding ActionKind = "RECOVER_APP_HUB_BINDING"
)

type AppBindingState string

const (
	AppBindingUnavailable AppBindingState = "UNAVAILABLE"
	AppBindingBound       AppBindingState = "BOUND"
	AppBindingUnbinding   AppBindingState = "UNBINDING"
	AppBindingUnbound     AppBindingState = "UNBOUND"
	AppBindingRebinding   AppBindingState = "REBINDING"
	AppBindingBoundZero   AppBindingState = "BOUND_ZERO"
)

type AppBindingAction struct {
	ReviewID string
	Confirm  bool
}

// AppBindingSnapshot contains only display-safe scope and progress metadata.
// A review ID is local exact-scope consent, never Hub authority.
type AppBindingSnapshot struct {
	State            AppBindingState `json:"state"`
	ReviewID         string          `json:"review_id,omitempty"`
	Pending          bool            `json:"pending"`
	PreviousDeviceID string          `json:"previous_device_id,omitempty"`
	DeviceID         string          `json:"device_id,omitempty"`
	DeviceKeyID      string          `json:"device_key_id,omitempty"`
	Generation       uint64          `json:"generation"`
}

func appBindingAction(kind ActionKind) bool {
	return kind == ActionUnbindApp || kind == ActionRebindApp || kind == ActionRecoverAppBinding
}

func appBindingLocalAction(kind ActionKind) bool {
	switch kind {
	case ActionConnect, ActionAddHub, ActionDisconnectHub, ActionDiscoverProfiles, ActionResumeProfile, ActionRemoveProfile, ActionRestoreProfile:
		return true
	}
	return false
}

func (c *nativeController) appBindingReview() string {
	if c.vault == nil || c.device == nil || c.owner == nil {
		return ""
	}
	var accountEpoch, deviceEpoch uint64
	if c.session != nil {
		accountEpoch, deviceEpoch = c.session.AccountEpoch, c.session.DeviceEpoch
	}
	var unbindDigest string
	if c.appIsUnbound() {
		ch, _, err := c.openAppBindingRecord(c.appBinding.unbind)
		if err != nil {
			return ""
		}
		unbindDigest = ch.Binding.Digest()
	}
	return localCollaborationReviewID(struct {
		Scope                                                       appvault.Scope
		DeviceID, DeviceKeyID, OwnerKeyID, Inspection, UnbindDigest string
		AccountEpoch, DeviceEpoch, UnbindVersion, RebindVersion     uint64
	}{cardScope(c.connection), c.state.DeviceID, c.device.Public().ID, c.owner.Public().ID,
		c.inspectionRequestID, unbindDigest, accountEpoch, deviceEpoch, c.appBinding.unbindVersion, c.appBinding.rebindVersion})
}

func (c *nativeController) appBindingHasOtherPending() bool {
	return !c.canBeginOperation() || c.hasNodePending() || c.hasThreadGroupPending() || c.scopedBusy() ||
		c.hasOwnerEndpointPending() || c.hasPairPending() || c.hasLocalDomainPending() ||
		len(c.node.OwnerDirectoryUnknown) != 0 || c.threadGroups.recovery != nil || c.localDomain.recovery != nil ||
		(c.state.Enrollment != nil && c.state.Enrollment.Target != nil && len(c.state.Enrollment.Target.Response) == 0)
}

func (c *nativeController) appBindingHoldsBusiness() bool {
	return c.appIsUnbound() || c.appBindingActive() != nil
}

func (c *nativeController) populateAppBinding(view *Snapshot) {
	view.AppBinding.State = AppBindingUnavailable
	if !c.connected || c.storageFault || c.vault == nil || c.device == nil {
		return
	}
	status, err := c.vault.AppDeviceStatus()
	if err != nil {
		return
	}
	view.AppBinding = AppBindingSnapshot{State: AppBindingUnavailable, DeviceID: c.state.DeviceID,
		DeviceKeyID: status.CurrentKeyID, Generation: status.Generation}
	if c.state.AccountDeviceEnrolled {
		view.AppBinding.State = AppBindingBound
	}
	if c.state.AccountDeviceEnrolled && status.Generation > 1 && c.session == nil {
		view.AppBinding.State = AppBindingBoundZero
	}
	if c.appIsUnbound() {
		view.AppBinding.State = AppBindingUnbound
		view.AppBinding.PreviousDeviceID = c.state.DeviceID
		view.Account.DeviceEnrolled = false
	}
	if active := c.appBindingActive(); active != nil {
		view.AppBinding.State = AppBindingUnbinding
		if active.Rebind != nil {
			view.AppBinding.State = AppBindingRebinding
		}
		view.AppBinding.Pending = true
	}
	if c.appBindingHoldsBusiness() {
		kept := view.AvailableActions[:0]
		for _, kind := range view.AvailableActions {
			if appBindingLocalAction(kind) {
				kept = append(kept, kind)
			}
		}
		view.AvailableActions = kept
		view.Management = ManagementUnavailable
		view.Authorization = AuthorizationSnapshot{}
		view.Node = NodeSetupSnapshot{}
		view.Pair = PairSetupSnapshot{}
		view.OwnerEndpoints = OwnerEndpointSnapshot{}
		view.ThreadGroups = ThreadGroupsSnapshot{}
		view.LocalCollaboration = LocalCollaborationSnapshot{}
		view.Targets = TargetSelectionSnapshot{}
		view.Canvas = CanvasSnapshot{State: CanvasNoAuthorization}
		view.Phase = PhaseConnected
		if view.AppBinding.Pending {
			view.Phase = PhaseUnavailable
			view.Account.State = AccountStateSessionCheck
		} else {
			view.Account.State = AccountStateLoginRequired
			view.Account.SessionExpiresAt = ""
		}
	}
	if c.profileRecoveryRequired || c.owner == nil || !c.localOwnerMatchesHub() {
		return
	}
	if c.appBindingActive() != nil {
		view.AvailableActions = append(view.AvailableActions, ActionRecoverAppBinding)
		return
	}
	if c.appIsUnbound() {
		view.AppBinding.ReviewID = c.appBindingReview()
		view.AvailableActions = append(view.AvailableActions, ActionRebindApp)
	} else if c.session != nil && c.sessionInspected && !c.sessionNeedsCheck && c.cfg.Now().UTC().Before(parseExpiry(c.session.ExpiresAt)) && !c.appBindingHasOtherPending() {
		view.AppBinding.ReviewID = c.appBindingReview()
		view.AvailableActions = append(view.AvailableActions, ActionUnbindApp)
	}
}
