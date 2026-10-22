package appcore

import (
	"slices"
	"testing"
	"time"
)

func TestLocalCollaborationAccountExpiryDoesNotExpirePolicy(t *testing.T) {
	now := time.Date(2026, 10, 22, 18, 0, 0, 0, time.UTC)
	s := Snapshot{Hub: HubSnapshot{Verified: true}, Account: AccountSnapshot{State: AccountStateOwnerReady, RootState: RootStateActive, SessionExpiresAt: now.Format(time.RFC3339Nano)},
		LocalCollaboration: LocalCollaborationSnapshot{Available: true, Current: true, State: "ACTIVE", PolicyID: "synthetic-policy", StateReviewID: "synthetic-review"},
		AvailableActions:   []ActionKind{ActionRevokeLocalCollaboration, ActionRefreshLocalCollaboration, ActionLogout}}
	expireLocalCollaborationView(&s, now)
	if s.LocalCollaboration.State != "ACTIVE" || s.LocalCollaboration.ExpiresAt != "" || s.LocalCollaboration.Current || !slices.Equal(s.AvailableActions, []ActionKind{ActionLogout}) {
		t.Fatal("account display expiry changed independent policy lifetime or retained management actions")
	}
}

func TestLocalCollaborationPendingAndUnobservedScopeCannotStartNewWork(t *testing.T) {
	now := time.Date(2026, 10, 22, 18, 0, 0, 0, time.UTC)
	base := Snapshot{Hub: HubSnapshot{Verified: true}, Account: AccountSnapshot{State: AccountStateOwnerReady, RootState: RootStateActive, SessionExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}}
	s := base
	s.LocalCollaboration = LocalCollaborationSnapshot{Available: true, Pending: true, Current: true, State: "ACTIVE"}
	s.AvailableActions = []ActionKind{ActionPrepareLocalCollaboration, ActionActivateLocalCollaboration, ActionRefreshLocalCollaboration, ActionRevokeLocalCollaboration, ActionRecoverLocalCollaboration}
	expireLocalCollaborationView(&s, now)
	if s.LocalCollaboration.Current || !slices.Equal(s.AvailableActions, []ActionKind{ActionRecoverLocalCollaboration}) {
		t.Fatal("pending original was shadowed by a new operation")
	}
	s = base
	s.LocalCollaboration = LocalCollaborationSnapshot{AvailabilityKnown: true, Available: true}
	s.AvailableActions = []ActionKind{ActionPrepareLocalCollaboration, ActionRefreshLocalCollaboration}
	expireLocalCollaborationView(&s, now)
	if slices.Contains(s.AvailableActions, ActionPrepareLocalCollaboration) {
		t.Fatal("a missing local cache was treated as authenticated no-policy")
	}
}

func TestLocalCollaborationPolicyAndReviewDeadlinesAreIndependent(t *testing.T) {
	now := time.Date(2026, 10, 22, 18, 0, 0, 0, time.UTC)
	s := Snapshot{Hub: HubSnapshot{Verified: true}, Account: AccountSnapshot{State: AccountStateOwnerReady, RootState: RootStateActive, SessionExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)},
		LocalCollaboration: LocalCollaborationSnapshot{Available: true, Current: true, State: "PREPARED", ReviewID: "synthetic-review", ReviewExpiresAt: now.Format(time.RFC3339Nano)}, AvailableActions: []ActionKind{ActionActivateLocalCollaboration, ActionRefreshLocalCollaboration}}
	expireLocalCollaborationView(&s, now)
	if s.LocalCollaboration.State != "PREPARED" || slices.Contains(s.AvailableActions, ActionActivateLocalCollaboration) {
		t.Fatal("expired short review became an active or expired long policy")
	}
	s.LocalCollaboration.State = "ACTIVE"
	s.LocalCollaboration.ExpiresAt = now.Format(time.RFC3339Nano)
	s.LocalCollaboration.StateReviewID = "synthetic-current-review"
	s.AvailableActions = []ActionKind{ActionRevokeLocalCollaboration, ActionRefreshLocalCollaboration}
	expireLocalCollaborationView(&s, now)
	if s.LocalCollaboration.State != "EXPIRED" || s.LocalCollaboration.Current || slices.Contains(s.AvailableActions, ActionRevokeLocalCollaboration) {
		t.Fatal("policy deadline retained current authority")
	}
}
