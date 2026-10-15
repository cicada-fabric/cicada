package appui

import (
	"github.com/cicada-ai/cicada/internal/appcore"
	"testing"
)

func TestSetupFlowKeepsRecoveryAheadOfCredentialsAndConsent(t *testing.T) {
	s := appcore.Snapshot{Hub: appcore.HubSnapshot{Verified: true}, Setup: appcore.SetupSnapshot{OwnerKeyStored: true},
		AvailableActions: []appcore.ActionKind{appcore.ActionLogin, appcore.ActionActivateApp, appcore.ActionRecover}}
	f := Flow(s)
	if f.Primary != appcore.ActionRecover || f.Password || f.LimitedConsent {
		t.Fatal("an uncertain packet allowed new credentials or authorization")
	}
}

func TestStorageRecoveryCanReopenSavedProfilesWithVerifiedMetadata(t *testing.T) {
	s := appcore.Snapshot{Phase: appcore.PhaseError, Hub: appcore.HubSnapshot{Verified: true}, AvailableActions: []appcore.ActionKind{appcore.ActionConnect, appcore.ActionDiscoverProfiles, appcore.ActionResumeProfile}}
	if f := Flow(s); f.Stage != "connect" || f.Primary != appcore.ActionConnect {
		t.Fatal("storage failure stranded reconnect behind verified metadata")
	}
}

func TestSetupFlowOffersOnePrimaryUserDecision(t *testing.T) {
	for _, tt := range []struct {
		name              string
		state             appcore.Snapshot
		primary           appcore.ActionKind
		password, consent bool
	}{
		{"initial-keys", appcore.Snapshot{AvailableActions: []appcore.ActionKind{appcore.ActionGenerateOwner, appcore.ActionImportOwner}}, appcore.ActionGenerateOwner, false, false},
		{"existing-owner", appcore.Snapshot{AvailableActions: []appcore.ActionKind{appcore.ActionImportOwner}}, appcore.ActionImportOwner, false, false},
		{"initial-activation", appcore.Snapshot{Setup: appcore.SetupSnapshot{OwnerKeyStored: true, NeedsCredentials: true}, AvailableActions: []appcore.ActionKind{appcore.ActionActivateApp}}, appcore.ActionActivateApp, true, true},
		{"legacy-activation", appcore.Snapshot{Setup: appcore.SetupSnapshot{OwnerKeyStored: true}, AvailableActions: []appcore.ActionKind{appcore.ActionActivateApp}}, appcore.ActionActivateApp, false, true},
		{"login", appcore.Snapshot{Setup: appcore.SetupSnapshot{OwnerKeyStored: true}, AvailableActions: []appcore.ActionKind{appcore.ActionLogin, appcore.ActionLoginPrepare}}, appcore.ActionLogin, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.state.Hub.Verified = true
			f := Flow(tt.state)
			if f.Primary != tt.primary || f.Password != tt.password || f.LimitedConsent != tt.consent {
				t.Fatalf("unexpected decision: %+v", f)
			}
			for _, a := range f.Secondary {
				if a == appcore.ActionLoginPrepare || a == appcore.ActionClaimPrepare {
					t.Fatal("protocol handshake escaped into product flow")
				}
			}
		})
	}
}
