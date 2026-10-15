package appui

import "github.com/cicada-ai/cicada/internal/appcore"

// SetupFlow presents user decisions, while the controller owns all protocol
// handshakes. A renderer must never turn public availability into authorization.
type SetupFlow struct {
	Stage          string
	Primary        appcore.ActionKind
	Secondary      []appcore.ActionKind
	Username       bool
	Password       bool
	LimitedConsent bool
}

func Flow(s appcore.Snapshot) SetupFlow {
	has := func(kind appcore.ActionKind) bool {
		for _, action := range s.AvailableActions {
			if action == kind {
				return true
			}
		}
		return false
	}
	if has(appcore.ActionRecover) {
		return SetupFlow{Stage: "recovery", Primary: appcore.ActionRecover}
	}
	if has(appcore.ActionRetry) {
		return SetupFlow{Stage: "recovery", Primary: appcore.ActionRetry}
	}
	operational := false
	for _, kind := range []appcore.ActionKind{appcore.ActionGenerateOwner, appcore.ActionImportOwner, appcore.ActionActivateApp, appcore.ActionSetupAccount, appcore.ActionLogin, appcore.ActionRefresh, appcore.ActionActivationStatus} {
		if has(kind) {
			operational = true
		}
	}
	if !s.Hub.Verified || (!operational && has(appcore.ActionConnect)) {
		flow := SetupFlow{Stage: "connect", Primary: appcore.ActionConnect}
		if has(appcore.ActionDiscoverProfiles) {
			flow.Secondary = []appcore.ActionKind{appcore.ActionDiscoverProfiles}
		}
		return flow
	}
	if !s.Setup.OwnerKeyStored && (has(appcore.ActionGenerateOwner) || has(appcore.ActionImportOwner)) {
		if has(appcore.ActionGenerateOwner) {
			return SetupFlow{Stage: "keys", Primary: appcore.ActionGenerateOwner, Secondary: []appcore.ActionKind{appcore.ActionImportOwner}}
		}
		return SetupFlow{Stage: "keys", Primary: appcore.ActionImportOwner}
	}
	if has(appcore.ActionActivateApp) {
		return SetupFlow{Stage: "activate", Primary: appcore.ActionActivateApp,
			Username: s.Setup.NeedsCredentials, Password: s.Setup.NeedsCredentials, LimitedConsent: true}
	}
	if has(appcore.ActionSetupAccount) {
		return SetupFlow{Stage: "account", Primary: appcore.ActionSetupAccount, Username: true, Password: true}
	}
	if has(appcore.ActionLogin) {
		return SetupFlow{Stage: "login", Primary: appcore.ActionLogin, Username: true, Password: true}
	}
	flow := SetupFlow{Stage: "ready"}
	if has(appcore.ActionRefresh) {
		flow.Primary = appcore.ActionRefresh
	}
	if has(appcore.ActionActivationStatus) && flow.Primary == "" {
		flow.Primary = appcore.ActionActivationStatus
	}
	if has(appcore.ActionLogout) {
		flow.Secondary = []appcore.ActionKind{appcore.ActionLogout}
	}
	return flow
}
