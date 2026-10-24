package appui

import (
	"github.com/cicada-ai/cicada/internal/appcore"
	"strings"
	"testing"
	"time"
)

func TestDevicePairingFlowSeparatesApprovalFromAdmission(t *testing.T) {
	now := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		state, stage string
		action       appcore.ActionKind
	}{
		{"CODE", "code", appcore.ActionReviewNodePairing}, {"LOOKUP", "preparing", appcore.ActionRefreshNodePairing}, {"REVIEW", "review", appcore.ActionApproveNodePairing}, {"APPROVING", "preparing", appcore.ActionRefreshNodePairing}, {"OWNER_APPROVED", "waiting", appcore.ActionRefreshNodePairing}, {"ACKED", "connected", ""}, {"CANCELLED", "ended", appcore.ActionReviewNodePairing},
	} {
		t.Run(test.state, func(t *testing.T) {
			s := appcore.Snapshot{Node: appcore.NodeSetupSnapshot{Pairing: &appcore.NodePairingSnapshot{State: test.state, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}}, AvailableActions: []appcore.ActionKind{test.action}}
			flow := NodePairingFlow(s, now)
			if flow.Stage != test.stage || flow.Primary != test.action {
				t.Fatal("pairing flow conflated approval, admission or available actions")
			}
			s.AvailableActions = []appcore.ActionKind{appcore.ActionRecoverNodePairing}
			if NodePairingFlow(s, now).Stage != "recovery" {
				t.Fatal("uncertain original packet did not take precedence")
			}
		})
	}
	s := appcore.Snapshot{Node: appcore.NodeSetupSnapshot{Pairing: &appcore.NodePairingSnapshot{State: "REVIEW", ExpiresAt: now.Format(time.RFC3339Nano)}}, AvailableActions: []appcore.ActionKind{appcore.ActionApproveNodePairing}}
	if NodePairingFlow(s, now).Stage != "expired" {
		t.Fatal("stale UI frame retained approval")
	}
}
func TestDevicePairingPresentationHidesCandidateBeforeLogin(t *testing.T) {
	s := appcore.Snapshot{Node: appcore.NodeSetupSnapshot{Pairing: &appcore.NodePairingSnapshot{State: "REVIEW", NodeID: "private-node", Name: "private-name", ReviewID: "private-review"}}}
	if PresentScreen(s, time.Now()).Snapshot.Node.Pairing != nil {
		t.Fatal("signed-out presentation exposed a pairing candidate")
	}
}
func TestDevicePairingCaptionsHaveBothLocalesWithoutManualKeyInstructions(t *testing.T) {
	for _, locale := range []Locale{English, Chinese} {
		for _, key := range []string{"node_pairing.title", "node_pairing.intro", "node_pairing.approve", "node_pairing.waiting_title", "node_pairing.waiting_body", "node_pairing.connected", "node_pairing.legacy", "node_pairing.default"} {
			caption := Text(locale, key)
			if caption == key || caption == "" {
				t.Fatal("pairing caption missing")
			}
			if strings.Contains(caption, "OpenSSL") || strings.Contains(caption, "descriptor") || strings.Contains(caption, "公钥") {
				t.Fatal("default pairing UI asks for manual trust files")
			}
		}
	}
}

func TestDevicePairingDeadlineChangesCopyWithoutInventingTerminalState(t *testing.T) {
	now := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	s := appcore.Snapshot{Node: appcore.NodeSetupSnapshot{Pairing: &appcore.NodePairingSnapshot{State: "OWNER_APPROVED", ExpiresAt: now.Format(time.RFC3339Nano)}}, AvailableActions: []appcore.ActionKind{appcore.ActionRefreshNodePairing}}
	flow := NodePairingFlow(s, now)
	if flow.Stage != "deadline" || flow.Primary != appcore.ActionRefreshNodePairing || s.Node.Pairing.State != "OWNER_APPROVED" {
		t.Fatal("deadline either stayed waiting, dropped observation or invented Hub expiry")
	}
}
