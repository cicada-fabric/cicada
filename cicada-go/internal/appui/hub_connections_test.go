package appui

import (
	"github.com/cicada-ai/cicada/internal/appcore"
	"strings"
	"testing"
	"time"
)

func TestHubConnectionPresentationKeepsOnlyNeutralSavedScope(t *testing.T) {
	s := appcore.Snapshot{Profiles: []appcore.ProfileSnapshot{{ID: "SYNTHETIC-exact", Origin: "https://private-account.synthetic", AccountID: "private-account", OwnerID: "private-owner", Address: "192.0.2.10:8787", HubID: "synthetic-hub", Fingerprint: "synthetic-pin", Removed: true, ReviewID: "synthetic-review"}}, AvailableActions: []appcore.ActionKind{appcore.ActionAddHub, appcore.ActionDiscoverProfiles, appcore.ActionRestoreProfile}}
	p := PresentScreen(s, time.Now())
	if p.InformationVisible || len(p.Snapshot.Profiles) != 1 {
		t.Fatal("saved connection invented current account")
	}
	got := p.Snapshot.Profiles[0]
	if got.ID != s.Profiles[0].ID || !got.Removed || got.ReviewID != s.Profiles[0].ReviewID || got.Address != s.Profiles[0].Address || got.AccountID != "" || got.OwnerID != "" || got.Origin != "" {
		t.Fatal("saved selection lost exact locator or disclosed tenant identity")
	}
	for _, locale := range []Locale{English, Chinese} {
		for _, key := range []string{"connection.add_hub", "connection.hubs", "connection.remove_body", "connection.retained_body", "connection.restore_hub", "connection.manage_disconnect"} {
			text := Text(locale, key)
			if text == "" || text == key || strings.Contains(text, "OpenSSL") {
				t.Fatal("Hub management caption missing", key)
			}
		}
	}
}

func TestHubTransitionImmediatelyHidesPreviousTenant(t *testing.T) {
	s := savedNodeView()
	s.Account.AccountID, s.Account.OwnerID, s.Account.DeviceID = "private-account", "private-owner", "private-device"
	s.Hub.Origin, s.Hub.HubID, s.Hub.Fingerprint = "https://old.synthetic", "old-hub", "old-pin"
	s.Account.SessionExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	s.Management = appcore.ManagementAuthorized
	transition := HubTransitionSnapshot(s)
	if AccountInformationVisible(transition, time.Now()) || transition.Hub.Verified || transition.Account.AccountID != "" || transition.Node.Binding != nil || transition.Management == appcore.ManagementAuthorized || len(transition.AvailableActions) != 0 {
		t.Fatal("switch frame retained old authority or network controls")
	}
	if !ResetPresentationInputs(InputScopeFor(s), true, transition, time.Now()) {
		t.Fatal("switch did not clear old inputs/consents")
	}
}
