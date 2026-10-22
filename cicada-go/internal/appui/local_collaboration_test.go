package appui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

func TestLocalCollaborationPresentationNeedsAuthenticatedPolicyObservation(t *testing.T) {
	now := time.Date(2026, 10, 22, 18, 0, 0, 0, time.UTC)
	s := accountDisplayFixture(now)
	s.LocalCollaboration = appcore.LocalCollaborationSnapshot{AvailabilityKnown: true, Available: true}
	s.AvailableActions = []appcore.ActionKind{appcore.ActionPrepareLocalCollaboration, appcore.ActionRefreshLocalCollaboration}
	if flow := LocalCollaborationFlow(s, now); !flow.Visible || flow.Stage != "unchecked" || flow.Prepare {
		t.Fatal("missing local policy was called unconfigured")
	}
	s.LocalCollaboration.State, s.LocalCollaboration.Current = "UNCONFIGURED", true
	if flow := LocalCollaborationFlow(s, now); flow.Stage != "unconfigured" || !flow.Prepare {
		t.Fatal("authenticated no-policy state cannot be configured")
	}
	s.LocalCollaboration.Available = false
	if flow := LocalCollaborationFlow(s, now); flow.Stage != "unavailable" || flow.Prepare || flow.Activate {
		t.Fatal("unsupported Hub offered a mutation")
	}
	s.LocalCollaboration.Available = true
	s.LocalCollaboration.State = "ACTIVE"
	s.LocalCollaboration.Current = false
	if flow := LocalCollaborationFlow(s, now); flow.Stage != "saved" || flow.Revoke {
		t.Fatal("saved ACTIVE metadata was presented as current")
	}
}

func TestLocalCollaborationPendingAndAccountPrivacyPreserveOriginal(t *testing.T) {
	now := time.Date(2026, 10, 22, 18, 0, 0, 0, time.UTC)
	s := accountDisplayFixture(now)
	s.LocalCollaboration = appcore.LocalCollaborationSnapshot{AvailabilityKnown: true, Available: true, Pending: true, Current: true, State: "ACTIVE", PolicyID: "synthetic-private-policy", NodeID: "synthetic-private-node", LocalUserScope: "uid:12345", NetworkID: "synthetic-private-network"}
	s.AvailableActions = []appcore.ActionKind{appcore.ActionRecoverLocalCollaboration, appcore.ActionActivateLocalCollaboration, appcore.ActionRevokeLocalCollaboration, appcore.ActionRefreshLocalCollaboration}
	if flow := LocalCollaborationFlow(s, now); flow.Stage != "pending" || !flow.Recover || flow.Activate || flow.Revoke || flow.Prepare || flow.Refresh {
		t.Fatal("pending request retained another action")
	}
	s.Account.SessionExpiresAt = now.Format(time.RFC3339Nano)
	p := PresentScreen(s, now)
	raw, err := json.Marshal(p.Snapshot.LocalCollaboration)
	if err != nil {
		t.Fatal(err)
	}
	if p.InformationVisible || p.Flow.Primary != appcore.ActionRecoverLocalCollaboration || p.Flow.Password || strings.Contains(string(raw), "synthetic-private-") || strings.Contains(string(raw), "uid:") {
		t.Fatal("signed-out recovery disclosed policy scope or required a new login")
	}
	if s.LocalCollaboration.PolicyID != "synthetic-private-policy" || s.LocalCollaboration.State != "ACTIVE" {
		t.Fatal("display privacy erased or revoked the saved policy")
	}
}
