package appui

import (
	"fmt"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

// AccountInformationVisible is a display boundary, never an authorization
// decision. These account states follow the core's authenticated session check.
func AccountInformationVisible(s appcore.Snapshot, now time.Time) bool {
	if !s.Hub.Verified || s.Hub.Origin == "" || s.Hub.HubID == "" || s.Hub.Fingerprint == "" ||
		s.Account.AccountID == "" || s.Account.OwnerID == "" || s.Account.DeviceID == "" {
		return false
	}
	switch s.Account.State {
	case appcore.AccountStateSessionActive, appcore.AccountStateOwnerReady, appcore.AccountStateOwnerProof:
	default:
		return false
	}
	end, err := time.Parse(time.RFC3339Nano, s.Account.SessionExpiresAt)
	if err != nil || end.UTC().Format(time.RFC3339Nano) != s.Account.SessionExpiresAt || !now.Before(end) {
		return false
	}
	for _, kind := range s.AvailableActions {
		switch kind {
		case appcore.ActionRecover, appcore.ActionRetry, appcore.ActionLogin, appcore.ActionLoginPrepare, appcore.ActionLoginComplete:
			return false
		}
	}
	return true
}

type ScreenPresentation struct {
	InformationVisible bool
	Snapshot           appcore.Snapshot
	Flow               SetupFlow
}

// PresentScreen gives the renderer only generic connection/recovery controls
// until the current account session is trusted. It never changes core state.
func PresentScreen(s appcore.Snapshot, now time.Time) ScreenPresentation {
	if AccountInformationVisible(s, now) {
		return ScreenPresentation{InformationVisible: true, Snapshot: s, Flow: Flow(s)}
	}
	flow := preLoginFlow(s)
	copy := s
	copy.Hub = appcore.HubSnapshot{Verified: s.Hub.Verified}
	copy.Account = appcore.AccountSnapshot{State: s.Account.State, DeviceEnrolled: s.Account.DeviceEnrolled}
	copy.Node = appcore.NodeSetupSnapshot{Pending: s.Node.Pending}
	copy.Pair = appcore.PairSetupSnapshot{Pending: s.Pair.Pending}
	copy.Authorization = appcore.AuthorizationSnapshot{}
	copy.Management, copy.Canvas = appcore.ManagementUnavailable, appcore.CanvasSnapshot{}
	copy.Setup.ExpectedOwnerKeyID = ""
	copy.Setup.OwnerKeyStored = false
	if flow.Stage != "activate" {
		copy.Setup.AuthorizationDeadline = ""
	}
	copy.Profiles = nil
	for _, profile := range s.Profiles {
		copy.Profiles = append(copy.Profiles, appcore.ProfileSnapshot{ID: profile.ID})
	}
	return ScreenPresentation{Snapshot: copy, Flow: flow}
}

func preLoginFlow(s appcore.Snapshot) SetupFlow {
	has := func(want appcore.ActionKind) bool {
		for _, kind := range s.AvailableActions {
			if kind == want {
				return true
			}
		}
		return false
	}
	for _, kind := range []appcore.ActionKind{appcore.ActionRecover, appcore.ActionRetry} {
		if has(kind) {
			return SetupFlow{Stage: "recovery", Primary: kind}
		}
	}
	if s.Pair.Pending && has(appcore.ActionRecoverPair) {
		return SetupFlow{Stage: "recovery", Primary: appcore.ActionRecoverPair}
	}
	if s.Node.Pending && has(appcore.ActionRecoverNode) {
		return SetupFlow{Stage: "recovery", Primary: appcore.ActionRecoverNode}
	}
	if has(appcore.ActionLogin) {
		return SetupFlow{Stage: "login", Primary: appcore.ActionLogin, Username: true, Password: true}
	}
	if has(appcore.ActionLoginComplete) {
		return SetupFlow{Stage: "login", Primary: appcore.ActionLoginComplete, Password: true}
	}
	if has(appcore.ActionLoginPrepare) {
		return SetupFlow{Stage: "login", Primary: appcore.ActionLoginPrepare, Username: true}
	}
	if has(appcore.ActionSessionInspect) {
		return SetupFlow{Stage: "session-check", Primary: appcore.ActionSessionInspect}
	}
	// First connection and Owner initialization keep their existing decisions.
	s.Node = appcore.NodeSetupSnapshot{}
	flow := Flow(s)
	if flow.Stage == "ready" {
		flow = SetupFlow{Stage: "session-check"}
		if has(appcore.ActionRefresh) {
			flow.Primary = appcore.ActionRefresh
		}
	}
	return flow
}

type InputScope struct {
	Origin, HubID, HubFingerprint, AccountID, OwnerID, DeviceID, OwnerFingerprint string
}

func InputScopeFor(s appcore.Snapshot) InputScope {
	return InputScope{s.Hub.Origin, s.Hub.HubID, s.Hub.Fingerprint, s.Account.AccountID,
		s.Account.OwnerID, s.Account.DeviceID, s.Account.OwnerFingerprint}
}

func ResetPresentationInputs(previous InputScope, previouslyVisible bool, s appcore.Snapshot, now time.Time) bool {
	return previous != InputScopeFor(s) || previouslyVisible != AccountInformationVisible(s, now)
}

func SavedConnectionLabel(locale Locale, index int) string {
	return fmt.Sprintf("%s %d", Text(locale, "connection.saved_connection"), index+1)
}
