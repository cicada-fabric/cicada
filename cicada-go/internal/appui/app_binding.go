package appui

import "github.com/cicada-ai/cicada/internal/appcore"

func appBindingFlow(s appcore.Snapshot) (SetupFlow, bool) {
	if !s.Hub.Verified {
		return SetupFlow{}, false
	}
	has := func(kind appcore.ActionKind) bool {
		for _, available := range s.AvailableActions {
			if kind == available {
				return true
			}
		}
		return false
	}
	if s.AppBinding.Pending || s.AppBinding.State == appcore.AppBindingUnbinding || s.AppBinding.State == appcore.AppBindingRebinding {
		flow := SetupFlow{Stage: "app-binding-recovery"}
		if has(appcore.ActionRecoverAppBinding) {
			flow.Primary = appcore.ActionRecoverAppBinding
		}
		return flow, true
	}
	if s.AppBinding.State == appcore.AppBindingUnbound {
		flow := SetupFlow{Stage: "app-rebind"}
		if has(appcore.ActionRebindApp) {
			flow.Primary = appcore.ActionRebindApp
		}
		return flow, true
	}
	return SetupFlow{}, false
}

// ConfirmAppBinding binds a renderer's single explicit consent to the current
// Core review. It accepts no manually supplied device, Owner, key or wire fields.
func ConfirmAppBinding(s appcore.Snapshot, kind appcore.ActionKind, review string, confirmed bool) (appcore.Action, bool) {
	if !confirmed || review == "" || review != s.AppBinding.ReviewID ||
		kind != appcore.ActionUnbindApp && kind != appcore.ActionRebindApp {
		return appcore.Action{}, false
	}
	for _, available := range s.AvailableActions {
		if available == kind {
			return appcore.Action{Kind: kind, AppBinding: appcore.AppBindingAction{ReviewID: review, Confirm: true}}, true
		}
	}
	return appcore.Action{}, false
}
