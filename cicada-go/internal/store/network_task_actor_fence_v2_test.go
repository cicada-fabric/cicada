package store

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestNetworkTaskWritesRecheckNativeBindingEpochInWriteTransaction(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	grantMembership := func(endpoint sameGroupSealedV1EndpointFixture) {
		t.Helper()
		membership, err := f.store.GetMembershipByPrincipalGroup(endpoint.principal, f.groupID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles,
			[]string{"task.claim", "task.read", "task.submit"}, membership.Authorization, membership.Version); err != nil {
			t.Fatal(err)
		}
	}
	grantMembership(f.source)
	grantMembership(f.target)
	actor := func(endpoint sameGroupSealedV1EndpointFixture) NativeActorScope {
		t.Helper()
		membership, err := f.store.GetMembershipByPrincipalGroup(endpoint.principal, f.groupID)
		if err != nil {
			t.Fatal(err)
		}
		return NativeActorScope{PrincipalID: endpoint.principal, EndpointID: endpoint.id,
			GroupID: f.groupID, NetworkID: networkID, MembershipID: membership.ID,
			MembershipRevision: membership.Revision, BindingID: endpoint.binding.ID,
			BindingEpoch: endpoint.binding.Epoch, LeaseOwner: endpoint.binding.LeaseOwner}
	}
	sourceActor, targetActor := actor(f.source), actor(f.target)
	makeClaimed := func(id, key string, scope NativeActorScope) *SharedTask {
		t.Helper()
		task, err := f.store.CreateSharedTask(SharedTask{ID: id, GroupID: f.groupID,
			Objective: "synthetic epoch fence", AcceptanceCriteria: "no stale write"})
		if err != nil {
			t.Fatal(err)
		}
		ready, err := f.store.ReadySharedTask(task.ID, task.Revision, "synthetic-reconciler")
		if err != nil {
			t.Fatal(err)
		}
		claimed, err := f.store.ClaimSharedTaskForActor(scope, task.ID, ready.Revision, key, 120)
		if err != nil {
			t.Fatal(err)
		}
		return claimed
	}
	first := makeClaimed("network_task_epoch_first", "synthetic_claim_first", sourceActor)
	second := makeClaimed("network_task_epoch_second", "synthetic_claim_second", sourceActor)
	third, err := f.store.CreateSharedTask(SharedTask{ID: "network_task_epoch_ready", GroupID: f.groupID,
		Objective: "synthetic ready Task", AcceptanceCriteria: "stale claim denied"})
	if err != nil {
		t.Fatal(err)
	}
	third, err = f.store.ReadySharedTask(third.ID, third.Revision, "synthetic-reconciler")
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := f.store.ProposeSharedTaskHandoffForActor(sourceActor, SharedTaskHandoff{
		TaskID: first.ID, GroupID: f.groupID, FromPrincipalID: sourceActor.PrincipalID,
		FromEndpointID: sourceActor.EndpointID, ToPrincipalID: targetActor.PrincipalID,
		ToEndpointID: targetActor.EndpointID, FromOwnerEpoch: first.OwnerEpoch,
		TaskRevision: first.Revision, PendingWork: "synthetic pending work",
		ArtifactRefs: []string{"synthetic_missing_artifact"},
	})
	if err != nil {
		t.Fatal(err)
	}
	beforeEvents := networkTaskTableCount(t, f.store, "shared_task_v2_events")
	beforeResults := networkTaskTableCount(t, f.store, "shared_task_v2_results")
	beforeHandoffs := networkTaskTableCount(t, f.store, "shared_task_v2_handoffs")
	firstBefore, secondBefore, thirdBefore := first, second, third
	otherGroupActor := sourceActor
	otherGroupActor.GroupID = "synthetic_wrong_group_scope"
	if _, err := f.store.ClaimSharedTaskForActor(otherGroupActor, third.ID, third.Revision,
		"wrong_group_claim", 60); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("actor scope from a different Group claimed Task: %v", err)
	}
	if _, err := f.store.ProposeSharedTaskHandoffForActor(otherGroupActor, SharedTaskHandoff{
		TaskID: second.ID, GroupID: f.groupID, FromPrincipalID: sourceActor.PrincipalID,
		FromEndpointID: sourceActor.EndpointID, ToPrincipalID: targetActor.PrincipalID,
		ToEndpointID: targetActor.EndpointID, FromOwnerEpoch: second.OwnerEpoch,
		TaskRevision: second.Revision, PendingWork: "wrong group handoff",
	}); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("actor scope from a different Group proposed Handoff: %v", err)
	}
	wrongGroupTarget := targetActor
	wrongGroupTarget.GroupID = "synthetic_wrong_group_scope"
	if err := f.store.MarkSharedTaskHandoffMissingArtifactsForActor(wrongGroupTarget, handoff.ID,
		[]string{"synthetic_wrong_group_artifact"}); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("actor scope from a different Group changed Handoff: %v", err)
	}
	if _, err := f.store.AcceptSharedTaskHandoffForActor(wrongGroupTarget, handoff.ID, 60); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("actor scope from a different Group accepted Handoff: %v", err)
	}

	rotate := func(endpoint sameGroupSealedV1EndpointFixture, old NativeActorScope, lease string) {
		t.Helper()
		past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
		if _, err := f.store.db.Exec(`UPDATE session_bindings SET lease_expires_at=? WHERE id=?`, past, old.BindingID); err != nil {
			t.Fatal(err)
		}
		fresh, err := f.store.AcquireSessionBindingLease(old.BindingID, lease, old.BindingEpoch,
			time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
		if err != nil || fresh.Epoch <= old.BindingEpoch || fresh.LeaseOwner != lease {
			t.Fatalf("synthetic native lease rotation failed: fresh=%#v err=%v", fresh, err)
		}
	}
	rotate(f.source, sourceActor, "synthetic_replacement_source_lease")
	if _, err := f.store.ClaimSharedTaskForActor(sourceActor, third.ID, third.Revision, "stale_claim", 60); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old native epoch claimed Task: %v", err)
	}
	if _, err := f.store.ReleaseSharedTaskClaimForActor(sourceActor, first.ID, first.Revision, first.OwnerEpoch); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old native epoch released Task: %v", err)
	}
	if _, err := f.store.RenewSharedTaskClaimForActor(sourceActor, second.ID, second.Revision, second.OwnerEpoch, 60); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old native epoch renewed Task: %v", err)
	}
	if _, err := f.store.SubmitSharedTaskResultForActor(sourceActor, second.ID, second.OwnerEpoch,
		second.Revision, "stale result", []string{"synthetic evidence"}); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old native epoch submitted Task result: %v", err)
	}
	if _, err := f.store.ProposeSharedTaskHandoffForActor(sourceActor, SharedTaskHandoff{
		TaskID: second.ID, GroupID: f.groupID, FromPrincipalID: sourceActor.PrincipalID,
		FromEndpointID: sourceActor.EndpointID, ToPrincipalID: targetActor.PrincipalID,
		ToEndpointID: targetActor.EndpointID, FromOwnerEpoch: second.OwnerEpoch,
		TaskRevision: second.Revision, PendingWork: "stale handoff",
	}); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old native epoch proposed handoff: %v", err)
	}

	rotate(f.target, targetActor, "synthetic_replacement_target_lease")
	if err := f.store.MarkSharedTaskHandoffMissingArtifactsForActor(targetActor, handoff.ID,
		[]string{"synthetic_missing_artifact"}); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old recipient native epoch marked missing artifact: %v", err)
	}
	if _, err := f.store.AcceptSharedTaskHandoffForActor(targetActor, handoff.ID, 60); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old recipient native epoch accepted handoff: %v", err)
	}
	for _, expected := range []*SharedTask{firstBefore, secondBefore, thirdBefore} {
		actual, err := f.store.GetSharedTask(expected.ID)
		if err != nil || actual.Revision != expected.Revision || actual.OwnerEpoch != expected.OwnerEpoch || actual.Status != expected.Status {
			t.Fatalf("denied stale Task write changed %s: actual=%#v err=%v", expected.ID, actual, err)
		}
	}
	actualHandoff, err := f.store.GetSharedTaskHandoff(handoff.ID)
	if err != nil || actualHandoff.Status != HandoffProposed || len(actualHandoff.MissingArtifactRefs) != 0 {
		t.Fatalf("denied stale Handoff write changed state: %#v err=%v", actualHandoff, err)
	}
	if got := networkTaskTableCount(t, f.store, "shared_task_v2_events"); got != beforeEvents {
		t.Fatalf("denied stale Task/Handoff writes added events: before=%d after=%d", beforeEvents, got)
	}
	if got := networkTaskTableCount(t, f.store, "shared_task_v2_results"); got != beforeResults {
		t.Fatalf("denied stale result added evidence rows: before=%d after=%d", beforeResults, got)
	}
	if got := networkTaskTableCount(t, f.store, "shared_task_v2_handoffs"); got != beforeHandoffs {
		t.Fatalf("denied stale handoff added rows: before=%d after=%d", beforeHandoffs, got)
	}
}

func networkTaskTableCount(t *testing.T, s *Store, table string) int64 {
	t.Helper()
	// Table names come from the fixed test-only call sites above.
	var count int64
	if err := s.db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, table)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
