package appcore

import (
	"slices"
	"testing"
	"time"
)

func TestThreadGroupsLoginExpiryHidesPrivateDataAndKeepsPending(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	s := Snapshot{Hub: HubSnapshot{Verified: true}, Account: AccountSnapshot{
		State: AccountStateOwnerReady, RootState: RootStateActive, LocalOwnerKeyPresent: true,
		SessionExpiresAt: now.Add(-time.Second).Format(time.RFC3339Nano),
	}, ThreadGroups: ThreadGroupsSnapshot{Available: true, AvailabilityKnown: true, Pending: true, Current: true,
		Threads: []GroupThreadView{{Name: "synthetic-private-name", Workspace: "synthetic-private-workspace"}},
		Review:  &ThreadGroupReview{GestureID: "synthetic-review", GroupName: "synthetic-private-group"}},
		AvailableActions: []ActionKind{ActionLogin, ActionReadThreadGroups, ActionRecoverThreadGroup, ActionApplyThreadGroup}}
	expireThreadGroupsView(&s, now)
	if !s.ThreadGroups.Pending || s.ThreadGroups.Current || len(s.ThreadGroups.Threads) != 0 || s.ThreadGroups.Review != nil || s.ThreadGroups.GestureID != "" {
		t.Fatal("login expiry discarded pending or retained private Group data/gesture")
	}
	if !slices.Equal(s.AvailableActions, []ActionKind{ActionLogin}) {
		t.Fatal("login expiry left a Group action or hid the original account login")
	}
}

func TestThreadGroupsSnapshotsDoNotShareRelationsOrReview(t *testing.T) {
	thread := GroupThreadView{Name: "synthetic-original", Relations: []ThreadGroupRelation{{Name: "synthetic-group", Contributions: []ThreadGroupContribution{{Source: "OWNER_EXPLICIT"}}}}}
	s := Snapshot{ThreadGroups: ThreadGroupsSnapshot{Threads: []GroupThreadView{thread}, Selected: &thread,
		Candidates: []ThreadGroupCandidate{{Name: "synthetic-candidate"}}, Review: &ThreadGroupReview{GroupName: "synthetic-reviewed"}}}
	copy := cloneSnapshot(s)
	copy.ThreadGroups.Threads[0].Relations[0].Contributions[0].Source = "changed"
	copy.ThreadGroups.Selected.Relations[0].Name = "changed"
	copy.ThreadGroups.Candidates[0].Name = "changed"
	copy.ThreadGroups.Review.GroupName = "changed"
	if s.ThreadGroups.Threads[0].Relations[0].Contributions[0].Source != "OWNER_EXPLICIT" || s.ThreadGroups.Selected.Relations[0].Name != "synthetic-group" || s.ThreadGroups.Candidates[0].Name != "synthetic-candidate" || s.ThreadGroups.Review.GroupName != "synthetic-reviewed" {
		t.Fatal("renderer could mutate Core's reviewed Group target or authority projection")
	}
}

func TestThreadGroupsPendingOnlyOffersRecoveryAndReviewCannotOutliveLogin(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	s := Snapshot{Hub: HubSnapshot{Verified: true, HubID: "synthetic-hub", Origin: "https://hub.synthetic.invalid", Fingerprint: "synthetic-pin"},
		Account:          AccountSnapshot{State: AccountStateOwnerReady, AccountID: "synthetic-account", OwnerID: "synthetic-owner", DeviceID: "synthetic-device", RootState: RootStateActive, LocalOwnerKeyPresent: true, SessionExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)},
		Node:             NodeSetupSnapshot{Binding: &NodeBindingSnapshot{NodeID: "synthetic-node"}},
		ThreadGroups:     ThreadGroupsSnapshot{NodeID: "synthetic-node", Available: true, Current: true, Pending: true, FreshUntil: now.Add(time.Minute).Format(time.RFC3339Nano)},
		AvailableActions: []ActionKind{ActionReadThreadGroups, ActionPrepareThreadGroup, ActionApplyThreadGroup, ActionDismissThreadGroup, ActionRecoverThreadGroup}}
	expireThreadGroupsView(&s, now)
	if !slices.Equal(s.AvailableActions, []ActionKind{ActionRecoverThreadGroup}) || !s.ThreadGroups.Pending {
		t.Fatal("uncertain Group request allowed replacement or discarded pending")
	}
	s.ThreadGroups.Pending, s.ThreadGroups.Current = false, true
	s.ThreadGroups.Review = &ThreadGroupReview{GestureID: "synthetic-review", ExpiresAt: now.Add(-time.Second).Format(time.RFC3339Nano)}
	s.AvailableActions = []ActionKind{ActionApplyThreadGroup, ActionDismissThreadGroup}
	expireThreadGroupsView(&s, now)
	if !slices.Equal(s.AvailableActions, []ActionKind{ActionDismissThreadGroup}) {
		t.Fatal("expired review could apply or could not be dismissed")
	}
	s.ThreadGroups.NodeID = "synthetic-other-node"
	if ThreadGroupsVisible(s, now) {
		t.Fatal("a different selected Node retained the previous Thread's private view")
	}
}
