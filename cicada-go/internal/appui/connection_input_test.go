package appui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

func TestConnectionInputKeepsDialAddressSeparateFromLegacyMaterial(t *testing.T) {
	for _, test := range []struct {
		name, address, material string
		valid                   bool
	}{
		{"legacy-card", "", "cicada-hub-connection-v1:SYNTHETIC_PUBLIC_CARD", true},
		{"legacy-code", "", "SYNTHETIC_SECRET_ACTIVATION", true},
		{"direct", " 203.0.113.10:8787 ", " SYNTHETIC_SECRET_BOOTSTRAP ", true},
		{"direct-ipv6", "[2001:db8::1]:8787", "SYNTHETIC_SECRET_BOOTSTRAP", true},
		{"missing-material", "203.0.113.10:8787", " \t ", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			action, ok := ConnectionInputAction(test.address, test.material)
			if ok != test.valid {
				t.Fatal("connection input readiness changed")
			}
			if !ok {
				return
			}
			if action.Kind != appcore.ActionConnect {
				t.Fatal("connection input produced another action")
			}
			if test.address != "" {
				if action.HubAddress != strings.TrimSpace(test.address) || action.BootstrapCode != strings.TrimSpace(test.material) || action.ConnectionCard != "" || action.ActivationCode != "" {
					t.Fatal("direct dial target was mixed with legacy material")
				}
			} else if action.HubAddress != "" || action.BootstrapCode != "" {
				t.Fatal("legacy connection was assigned a direct transport")
			} else if strings.HasPrefix(test.material, "cicada-hub-connection-v1:") {
				if action.ConnectionCard != test.material || action.ActivationCode != "" {
					t.Fatal("legacy public card changed entry path")
				}
			} else if action.ActivationCode != test.material || action.ConnectionCard != "" {
				t.Fatal("legacy activation changed entry path")
			}
			if strings.Contains(fmt.Sprintf("%v %#v", action, action), "SYNTHETIC") {
				t.Fatal("native action formatting exposed connection material")
			}
		})
	}
}

func TestConnectionTargetVisibleBeforeAccountWithoutSavedIdentityDetails(t *testing.T) {
	s := appcore.Snapshot{Hub: appcore.HubSnapshot{
		Address: "203.0.113.10:8787", TransportState: appcore.HubTransportVerifying,
		Origin: "https://synthetic-logical.invalid", HubID: "synthetic-private-hub", Fingerprint: strings.Repeat("a", 64),
	}}
	view := PresentScreen(s, time.Now())
	if view.InformationVisible || view.Snapshot.Hub.Address != s.Hub.Address || view.Snapshot.Hub.TransportState != s.Hub.TransportState {
		t.Fatal("connection target or verification progress disappeared before login")
	}
	if view.Snapshot.Hub.HubID != "" || view.Snapshot.Hub.Fingerprint != "" || view.Snapshot.Hub.Origin != "" {
		t.Fatal("connection progress exposed saved identity details")
	}
}
