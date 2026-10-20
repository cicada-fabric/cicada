package appui

import (
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

func TestOwnerEndpointDirectoryKeepsFullNamesAndPathsWithinAccountBoundary(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	card := appcore.OwnerEndpointView{EndpointID: "synthetic_endpoint", Name: "合成项目 Thread", Workspace: "/synthetic/" + strings.Repeat("workspace/", 96), Harness: "codex", Presence: "offline"}
	s := appcore.Snapshot{Hub: appcore.HubSnapshot{Verified: true, Origin: "https://synthetic.invalid", HubID: "synthetic_hub", Fingerprint: strings.Repeat("a", 64)},
		Account:        appcore.AccountSnapshot{AccountID: "synthetic_account", OwnerID: "synthetic_owner", DeviceID: "synthetic_device", State: appcore.AccountStateOwnerReady, RootState: appcore.RootStateActive, SessionExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)},
		OwnerEndpoints: appcore.OwnerEndpointSnapshot{NodeID: "synthetic_node", State: "SNAPSHOT_ONLY", Endpoints: []appcore.OwnerEndpointView{card}}}
	fields := OwnerEndpointPublicFields(s, card, now)
	if !OwnerEndpointDirectoryVisible(s, now) || len(fields) != 2 || fields[0].Value != card.Name || fields[1].Value != card.Workspace {
		t.Fatal("primary names/workspaces were shortened or unavailable")
	}
	foreign := card
	foreign.EndpointID = "synthetic_foreign_endpoint"
	if len(OwnerEndpointPublicFields(s, foreign, now)) != 0 {
		t.Fatal("non-snapshot row accepted")
	}
	for _, state := range []appcore.AccountState{appcore.AccountStateLoginRequired, appcore.AccountStateSessionCheck, appcore.AccountStateUnknown} {
		s.Account.State = state
		if OwnerEndpointDirectoryVisible(s, now) || len(OwnerEndpointPublicFields(s, card, now)) != 0 {
			t.Fatal("unconfirmed account exposed directory")
		}
		view := PresentScreen(s, now).Snapshot.OwnerEndpoints
		if len(view.Endpoints) != 0 || view.NodeID != "" || view.ReviewID != "" {
			t.Fatal("presentation retained protected directory")
		}
	}
	s.Account.State = appcore.AccountStateOwnerReady
	if OwnerEndpointDirectoryVisible(s, now.Add(time.Hour)) {
		t.Fatal("expired account exposed directory")
	}
}

func TestOwnerEndpointUnknownReadDoesNotReplaceLoginWithPrivateRecovery(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	s := accountDisplayFixture(now)
	s.Account.State = appcore.AccountStateLoginRequired
	s.OwnerEndpoints = appcore.OwnerEndpointSnapshot{Pending: true, NodeID: "SYNTHETIC_PRIVATE_NODE", RetainedUnknown: 3, ParkReviewID: "SYNTHETIC_PRIVATE_REVIEW", Endpoints: []appcore.OwnerEndpointView{{Name: "SYNTHETIC_PRIVATE_THREAD"}}}
	s.AvailableActions = []appcore.ActionKind{appcore.ActionLogin, appcore.ActionRecoverOwnerEndpoints, appcore.ActionParkOwnerEndpoints}
	view := PresentScreen(s, now)
	if view.InformationVisible || view.Flow.Stage != "login" || view.Flow.Primary != appcore.ActionLogin || view.Snapshot.OwnerEndpoints.NodeID != "" || view.Snapshot.OwnerEndpoints.RetainedUnknown != 0 || len(view.Snapshot.OwnerEndpoints.Endpoints) != 0 || view.Snapshot.OwnerEndpoints.ParkReviewID != "" {
		t.Fatal("unknown readonly request replaced pure login or exposed metadata")
	}
	s.AvailableActions = []appcore.ActionKind{appcore.ActionSessionInspect, appcore.ActionRecoverOwnerEndpoints, appcore.ActionParkOwnerEndpoints}
	if view := PresentScreen(s, now); view.Flow.Stage != "session-check" || view.Flow.Primary != appcore.ActionSessionInspect {
		t.Fatal("historical read bypassed saved-session verification")
	}
}
