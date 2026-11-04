package appui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

func TestAppBindingPresentationPrioritizesRecoveryAndReauthorization(t *testing.T) {
	now := time.Now().UTC()
	for _, state := range []appcore.AppBindingState{appcore.AppBindingUnbound, appcore.AppBindingUnbinding, appcore.AppBindingRebinding} {
		s := accountDisplayFixture(now)
		s.AppBinding = appcore.AppBindingSnapshot{State: state, ReviewID: "SYNTHETIC_REVIEW", DeviceID: "private-old-device",
			PreviousDeviceID: "private-previous-device", DeviceKeyID: "private-new-device-key", Generation: 2,
			Pending: state != appcore.AppBindingUnbound}
		s.AvailableActions = []appcore.ActionKind{appcore.ActionConnect, appcore.ActionLogin, appcore.ActionActivateApp, appcore.ActionRebindApp, appcore.ActionRecoverAppBinding}
		p := PresentScreen(s, now)
		if p.InformationVisible || p.Flow.Password || p.Flow.Username || p.Flow.Primary == appcore.ActionConnect || p.Flow.Primary == appcore.ActionActivateApp {
			t.Fatal("App binding recovery escaped into old account/setup flow", state)
		}
		want := appcore.ActionRecoverAppBinding
		if state == appcore.AppBindingUnbound {
			want = appcore.ActionRebindApp
		}
		if p.Flow.Primary != want || Flow(s).Primary != want || p.Snapshot.AppBinding.ReviewID != "SYNTHETIC_REVIEW" || p.Snapshot.AppBinding.State != state {
			t.Fatal("neutral binding progress/consent was lost", state)
		}
		raw, _ := json.Marshal(p.Snapshot)
		for _, private := range []string{"private-old-device", "private-previous-device", "private-new-device-key", "private-account-id", "private-owner-id", "private-cached-user"} {
			if strings.Contains(string(raw), private) {
				t.Fatal("prelogin binding flow disclosed old scope details", state)
			}
		}
	}
}

func TestAppBindingConsentRequiresCurrentExactReviewAndAvailableAction(t *testing.T) {
	s := appcore.Snapshot{AppBinding: appcore.AppBindingSnapshot{ReviewID: "SYNTHETIC_CURRENT"}, AvailableActions: []appcore.ActionKind{appcore.ActionRebindApp}}
	for _, tc := range []struct {
		review    string
		confirmed bool
		kind      appcore.ActionKind
	}{
		{"SYNTHETIC_CURRENT", false, appcore.ActionRebindApp}, {"SYNTHETIC_OLD", true, appcore.ActionRebindApp},
		{"", true, appcore.ActionRebindApp}, {"SYNTHETIC_CURRENT", true, appcore.ActionUnbindApp},
		{"SYNTHETIC_CURRENT", true, appcore.ActionLogin},
	} {
		if _, ok := ConfirmAppBinding(s, tc.kind, tc.review, tc.confirmed); ok {
			t.Fatal("stale/missing/wrong consent produced an action")
		}
	}
	a, ok := ConfirmAppBinding(s, appcore.ActionRebindApp, "SYNTHETIC_CURRENT", true)
	if !ok || !a.AppBinding.Confirm || a.AppBinding.ReviewID != s.AppBinding.ReviewID || a.Password != "" || a.ConnectionCard != "" || a.ActivationCode != "" || a.OwnerImport != nil {
		t.Fatal("native consent did not stay inside its exact Core decision")
	}
}

func TestAppBindingZeroAuthorityAndTransitionHideOldInformation(t *testing.T) {
	now := time.Now().UTC()
	s := accountDisplayFixture(now)
	s.AppBinding = appcore.AppBindingSnapshot{State: appcore.AppBindingBoundZero, DeviceID: "private-new-device", Generation: 2}
	s.AvailableActions = []appcore.ActionKind{appcore.ActionLogin}
	p := PresentScreen(s, now)
	if p.InformationVisible || p.Flow.Primary != appcore.ActionLogin || p.Snapshot.Management == appcore.ManagementAuthorized {
		t.Fatal("zero-access registration inherited an account/management display")
	}
	transition := HubTransitionSnapshot(s)
	if transition.AppBinding.State == appcore.AppBindingBoundZero || transition.AppBinding.DeviceID != "" || transition.AppBinding.ReviewID != "" {
		t.Fatal("scope transition retained old binding display")
	}
}

func TestAppBindingBilingualCaptionsAndReviewedErrors(t *testing.T) {
	for _, locale := range []Locale{English, Chinese} {
		for _, key := range []string{"binding.title", "binding.unbind", "binding.unbind_body", "binding.unbind_consent", "binding.rebind", "binding.unbound_body", "binding.rebind_consent", "binding.recover", "binding.pending", "binding.bound_zero", "binding.unavailable", "binding.storage_full", "binding.review_required", "binding.refused"} {
			if value := Text(locale, key); value == key || value == "" || strings.Contains(value, "OpenSSL") || strings.Contains(value, "JSON") {
				t.Fatal("missing or manual-protocol binding UI caption", locale, key)
			}
		}
		for _, code := range []string{"APP_BINDING_RESPONSE_UNKNOWN", "APP_BINDING_RESPONSE_INVALID", "APP_BINDING_UNAVAILABLE", "APP_BINDING_STORAGE_FULL", "APP_BINDING_REVIEW_REQUIRED", "APP_BINDING_REJECTED_OWNER_REVOKED", "APP_BINDING_PROMOTION_FAILED"} {
			if ErrorText(locale, code) == Text(locale, string(msgRequestFailed)) {
				t.Fatal("binding failure lacks reviewed localized feedback", locale, code)
			}
		}
	}
}
