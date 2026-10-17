package appui

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

func accountDisplayFixture(now time.Time) appcore.Snapshot {
	s := savedNodeView()
	s.Hub = appcore.HubSnapshot{Verified: true, Origin: "https://private-hub.invalid", HubID: "private-hub-id", Fingerprint: "private-hub-pin", Service: "private-service"}
	s.Account = appcore.AccountSnapshot{State: appcore.AccountStateOwnerReady, RootState: appcore.RootStateActive, DeviceEnrolled: true,
		AccountID: "private-account-id", OwnerID: "private-owner-id", DeviceID: "private-device-id", Username: "private-cached-user",
		OwnerFingerprint: "private-owner-pin", SessionExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano)}
	s.Setup = appcore.SetupSnapshot{OwnerKeyStored: true, Purpose: "INITIAL", ExpectedOwnerKeyID: "private-owner-key-id", AuthorizationDeadline: now.Add(11 * time.Minute).Format(time.RFC3339Nano)}
	s.Authorization = appcore.AuthorizationSnapshot{State: "EXPIRED", ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339Nano)}
	s.Node.Binding = &appcore.NodeBindingSnapshot{ID: "private-binding-id", NodeID: "private-node-id", Name: "private-node-name", Version: 1, Authorized: true}
	s.Node.Access.ExpiresAt = now.Add(8 * time.Minute).Format(time.RFC3339Nano)
	s.Node.Connectivity.ObservedAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	s.Node.Connectivity.LastHeartbeatAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	s.Profiles = []appcore.ProfileSnapshot{{ID: "opaque-locator", Origin: "https://private-profile.invalid", AccountID: "private-profile-account", OwnerID: "private-profile-owner"}}
	s.Canvas = appcore.CanvasSnapshot{State: appcore.CanvasAvailable, Objects: []appcore.CanvasObject{{ID: "private-canvas-id", Label: "private-canvas-name"}}}
	return s
}

func TestAccountInformationRequiresCurrentTrustedSession(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name string
		edit func(*appcore.Snapshot)
		want bool
	}{
		{"current-owner-ready", func(*appcore.Snapshot) {}, true},
		{"current-session-active", func(s *appcore.Snapshot) { s.Account.State = appcore.AccountStateSessionActive }, true},
		{"owner-proof-is-still-logged-in", func(s *appcore.Snapshot) {
			s.Account.State, s.Account.RootState = appcore.AccountStateOwnerProof, appcore.RootStatePending
		}, true},
		{"root-unavailable-is-not-account-logout", func(s *appcore.Snapshot) { s.Account.RootState = appcore.RootStateUnavailable }, true},
		{"unverified-hub", func(s *appcore.Snapshot) { s.Hub.Verified = false }, false},
		{"missing-hub", func(s *appcore.Snapshot) { s.Hub.HubID = "" }, false},
		{"missing-origin", func(s *appcore.Snapshot) { s.Hub.Origin = "" }, false},
		{"missing-pin", func(s *appcore.Snapshot) { s.Hub.Fingerprint = "" }, false},
		{"missing-account", func(s *appcore.Snapshot) { s.Account.AccountID = "" }, false},
		{"missing-owner", func(s *appcore.Snapshot) { s.Account.OwnerID = "" }, false},
		{"missing-device", func(s *appcore.Snapshot) { s.Account.DeviceID = "" }, false},
		{"signed-out", func(s *appcore.Snapshot) { s.Account.State = appcore.AccountStateLoginRequired }, false},
		{"saved-session-awaits-inspection", func(s *appcore.Snapshot) { s.Account.State = appcore.AccountStateSessionCheck }, false},
		{"unknown-account", func(s *appcore.Snapshot) { s.Account.State = appcore.AccountStateUnknown }, false},
		{"no-explicit-expiry", func(s *appcore.Snapshot) { s.Account.SessionExpiresAt = "" }, false},
		{"malformed-expiry", func(s *appcore.Snapshot) { s.Account.SessionExpiresAt = "not-a-time" }, false},
		{"noncanonical-expiry", func(s *appcore.Snapshot) {
			s.Account.SessionExpiresAt = now.Add(time.Hour).Format("2006-01-02T15:04:05-07:00")
		}, false},
		{"exact-expiry", func(s *appcore.Snapshot) { s.Account.SessionExpiresAt = now.Format(time.RFC3339Nano) }, false},
		{"past-expiry", func(s *appcore.Snapshot) {
			s.Account.SessionExpiresAt = now.Add(-time.Nanosecond).Format(time.RFC3339Nano)
		}, false},
		{"account-recovery", func(s *appcore.Snapshot) { s.AvailableActions = []appcore.ActionKind{appcore.ActionRecover} }, false},
		{"account-retry", func(s *appcore.Snapshot) { s.AvailableActions = []appcore.ActionKind{appcore.ActionRetry} }, false},
		{"login-challenge", func(s *appcore.Snapshot) { s.AvailableActions = []appcore.ActionKind{appcore.ActionLoginComplete} }, false},
		{"normal-node-in-flight", func(s *appcore.Snapshot) {
			s.Node.Pending, s.Node.Access.Confirmed, s.Node.Connectivity.Current = true, false, false
			s.AvailableActions = []appcore.ActionKind{appcore.ActionRefresh, appcore.ActionRecoverNode}
		}, true},
		{"status-access-ended", func(s *appcore.Snapshot) { s.Node.Access.State, s.Node.Access.Confirmed = "EXPIRED", false }, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := accountDisplayFixture(now)
			tt.edit(&s)
			if got := AccountInformationVisible(s, now); got != tt.want {
				t.Fatalf("information visible=%t, want %t", got, tt.want)
			}
		})
	}
}

func TestPreLoginPresentationHidesIdentityButPreservesGenericRecovery(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name, stage string
		actions     []appcore.ActionKind
		nodePending bool
		primary     appcore.ActionKind
	}{
		{"signed-out", "login", []appcore.ActionKind{appcore.ActionLogin}, false, appcore.ActionLogin},
		{"prepare-login", "login", []appcore.ActionKind{appcore.ActionLoginPrepare}, false, appcore.ActionLoginPrepare},
		{"complete-login", "login", []appcore.ActionKind{appcore.ActionLoginComplete}, false, appcore.ActionLoginComplete},
		{"inspect-saved-session", "session-check", []appcore.ActionKind{appcore.ActionSessionInspect, appcore.ActionLogout}, false, appcore.ActionSessionInspect},
		{"recover-account", "recovery", []appcore.ActionKind{appcore.ActionRecover, appcore.ActionLogin}, false, appcore.ActionRecover},
		{"retry-account", "recovery", []appcore.ActionKind{appcore.ActionRetry, appcore.ActionLogin}, false, appcore.ActionRetry},
		{"recover-node-without-login", "recovery", []appcore.ActionKind{appcore.ActionRecoverNode, appcore.ActionLogin}, true, appcore.ActionRecoverNode},
		{"expired-with-old-refresh-actions", "session-check", []appcore.ActionKind{appcore.ActionRefresh, appcore.ActionLogout}, false, appcore.ActionRefresh},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := accountDisplayFixture(now)
			s.Account.State = appcore.AccountStateLoginRequired
			s.Node.Pending, s.AvailableActions = tt.nodePending, tt.actions
			before, _ := json.Marshal(s)
			view := PresentScreen(s, now)
			if view.InformationVisible || view.Flow.Stage != tt.stage || view.Flow.Primary != tt.primary || len(view.Flow.Secondary) != 0 {
				t.Fatal("login screen showed private or competing account decisions")
			}
			raw, _ := json.Marshal(view)
			for _, secret := range []string{"private-hub", "private-service", "private-account", "private-owner", "private-device", "private-cached-user", "private-node", "private-binding", "private-profile", "private-canvas", s.Account.SessionExpiresAt, s.Node.Access.ExpiresAt, s.Authorization.ExpiresAt, s.Node.Connectivity.LastHeartbeatAt} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("pre-login display contains protected metadata %q", secret)
				}
			}
			if !reflect.DeepEqual(view.Snapshot.AvailableActions, s.AvailableActions) || len(view.Snapshot.Profiles) != 1 || view.Snapshot.Profiles[0].ID != s.Profiles[0].ID {
				t.Fatal("privacy display changed available operations or profile locator selection")
			}
			after, _ := json.Marshal(s)
			if !bytes.Equal(before, after) || s.Node.Binding.ID != "private-binding-id" {
				t.Fatal("hiding information modified the saved binding or controller snapshot")
			}
		})
	}
}

func TestLoginRestoresOriginalBindingAndFirstSetupStillHasItsOwnFlow(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := accountDisplayFixture(now)
	s.Account.State = appcore.AccountStateSessionCheck
	if PresentScreen(s, now).InformationVisible {
		t.Fatal("cached uninspected session exposed information")
	}
	s.Account.State = appcore.AccountStateOwnerReady
	s.Node.Access.State, s.Node.Access.Confirmed = "EXPIRED", false
	view := PresentScreen(s, now)
	if !view.InformationVisible || view.Snapshot.Node.Binding.ID != s.Node.Binding.ID || view.Snapshot.Node.Binding.Name != s.Node.Binding.Name {
		t.Fatal("fresh account inspection did not restore the same saved Node information")
	}
	for _, tt := range []struct {
		action appcore.ActionKind
		stage  string
	}{{appcore.ActionConnect, "connect"}, {appcore.ActionGenerateOwner, "keys"}, {appcore.ActionActivateApp, "activate"}} {
		initial := appcore.Snapshot{Hub: appcore.HubSnapshot{Verified: tt.action != appcore.ActionConnect}, AvailableActions: []appcore.ActionKind{tt.action}}
		if tt.action == appcore.ActionActivateApp {
			initial.Setup.OwnerKeyStored = true
		}
		if p := PresentScreen(initial, now); p.InformationVisible || p.Flow.Stage != tt.stage || p.Flow.Primary != tt.action {
			t.Fatal("privacy boundary invented login instead of preserving necessary first setup")
		}
	}
}

func TestPresentationInputResetUsesFullScopeAndAuthenticationEdge(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := accountDisplayFixture(now)
	scope := InputScopeFor(s)
	for _, edit := range []func(*appcore.Snapshot){
		func(s *appcore.Snapshot) { s.Hub.Origin += "/other" },
		func(s *appcore.Snapshot) { s.Hub.HubID += "other" },
		func(s *appcore.Snapshot) { s.Hub.Fingerprint += "other" },
		func(s *appcore.Snapshot) { s.Account.AccountID += "other" },
		func(s *appcore.Snapshot) { s.Account.OwnerID += "other" },
		func(s *appcore.Snapshot) { s.Account.DeviceID += "other" },
		func(s *appcore.Snapshot) { s.Account.OwnerFingerprint += "other" },
	} {
		copy := s
		edit(&copy)
		if !ResetPresentationInputs(scope, true, copy, now) {
			t.Fatal("changed trusted scope retained UI inputs/details/consent")
		}
	}
	if ResetPresentationInputs(scope, true, s, now) || !ResetPresentationInputs(scope, true, s, now.Add(10*time.Minute)) {
		t.Fatal("stable login or exact expiry reset edge was incorrect")
	}
	if !ResetPresentationInputs(scope, false, s, now) {
		t.Fatal("successful login retained manually entered credentials")
	}
	s.Account.State = appcore.AccountStateLoginRequired
	if !ResetPresentationInputs(scope, true, s, now) || ResetPresentationInputs(scope, false, s, now) {
		t.Fatal("logout failed to reset once or repeated frames would erase manual retry input")
	}
	for _, locale := range []Locale{English, Chinese} {
		label := SavedConnectionLabel(locale, 1)
		if !strings.Contains(label, "2") || strings.Contains(label, "private") {
			t.Fatal("generic saved-profile selector leaked identity or lost its index")
		}
	}
}

func TestBlockedProfileRecoveryNeverOffersFirstSetup(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, code := range []string{"", "APP_PROFILE_IN_USE", "APP_PROFILE_DISCOVERY_FAILED", "APP_PROFILE_INVALID", "APP_PROFILE_HUB_UNVERIFIED", "APP_SESSION_STATE_INVALID"} {
		t.Run(code, func(t *testing.T) {
			s := accountDisplayFixture(now)
			s.Account.State = appcore.AccountStateUnknown
			s.ErrorCode = code
			s.AvailableActions = []appcore.ActionKind{appcore.ActionDiscoverProfiles, appcore.ActionResumeProfile}
			p := PresentScreen(s, now)
			f := p.Flow
			if p.InformationVisible || f.Stage != "profile-recovery" || f.Primary != appcore.ActionDiscoverProfiles ||
				f.Username || f.Password || f.LimitedConsent || len(f.Secondary) != 0 {
				t.Fatal("unavailable saved connection fell into new setup, credentials or identity generation")
			}
			if f := Flow(s); f.Stage != "profile-recovery" || f.Primary != appcore.ActionDiscoverProfiles {
				t.Fatal("an alternate renderer bypassed the core profile recovery controls")
			}
		})
	}
	s := appcore.Snapshot{AvailableActions: []appcore.ActionKind{appcore.ActionConnect, appcore.ActionDiscoverProfiles}}
	if p := PresentScreen(s, now); p.Flow.Stage != "connect" || p.Flow.Primary != appcore.ActionConnect {
		t.Fatal("successful empty discovery stranded first setup")
	}
}
