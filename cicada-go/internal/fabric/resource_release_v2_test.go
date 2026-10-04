package fabric

import (
	"errors"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestResourceLeaseReleaseServiceGuardAndFence(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	joined, actor := joinFabricPeer(t, service, group.ID, "release-worker", "release-session", "release-node")
	membership, err := persistence.GetMembership(actor.MembershipID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = persistence.UpdateMembershipAuthorization(membership.ID, []string{"worker"}, []string{"task.claim", "resource.execute"}, membership.Authorization, membership.Version)
	if err != nil {
		t.Fatal(err)
	}
	actor, err = service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	task, err := persistence.CreateSharedTask(store.SharedTask{GroupID: group.ID, Objective: "synthetic bounded write", AcceptanceCriteria: "current writer"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = persistence.ReadySharedTask(task.ID, task.Revision, group.OwnerPrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.ClaimTask(actor, TaskClaimInput{TaskID: task.ID, ExpectedRevision: task.Revision, IdempotencyKey: "synthetic-release"})
	if err != nil {
		t.Fatal(err)
	}
	acquire := store.ResourceLeaseRequest{ResourceID: "managed_blob/service-release/write", GroupID: group.ID, TaskID: task.ID, PrincipalID: actor.PrincipalID, TTLSeconds: 300}
	lease, err := persistence.AcquireResourceLease(acquire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.ReleaseResourceLease(Actor{}, lease.ID, lease.FencingEpoch); !errors.Is(err, ErrPermissionDenied) && !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("untrusted actor: %v", err)
	}
	foreign := actor
	foreign.PrincipalID = "synthetic-foreign"
	if _, err = service.ReleaseResourceLease(foreign, lease.ID, lease.FencingEpoch); !errors.Is(err, ErrPermissionDenied) && !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("foreign holder: %v", err)
	}
	if _, err = service.ReleaseResourceLease(actor, "missing", lease.FencingEpoch); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("missing lease disclosed: %v", err)
	}
	if _, err = service.ReleaseResourceLease(actor, lease.ID, lease.FencingEpoch+1); !errors.Is(err, ErrConflict) || !errors.Is(err, store.ErrResourceStaleEpoch) {
		t.Fatalf("stale epoch reason lost: %v", err)
	}
	released, err := service.ReleaseResourceLease(actor, lease.ID, lease.FencingEpoch)
	if err != nil || released.State != store.LeaseReleased {
		t.Fatalf("release: %v", err)
	}
	retry, err := service.ReleaseResourceLease(actor, lease.ID, lease.FencingEpoch)
	if err != nil || retry.UpdatedAt != released.UpdatedAt || retry.ExpiresAt != lease.ExpiresAt {
		t.Fatalf("retry changed lease: %v", err)
	}
	if _, err = service.WriteManagedBlob(actor, lease.ID, lease.FencingEpoch, []byte("old writer")); !errors.Is(err, ErrConflict) {
		t.Fatalf("released writer: %v", err)
	}
	next, err := persistence.AcquireResourceLease(acquire)
	if err != nil || next.FencingEpoch != lease.FencingEpoch+1 {
		t.Fatalf("successor: %v", err)
	}
	if _, err = service.ReleaseResourceLease(actor, lease.ID, lease.FencingEpoch); !errors.Is(err, ErrConflict) {
		t.Fatalf("old retry released successor: %v", err)
	}
	if _, err = service.WriteManagedBlob(actor, next.ID, next.FencingEpoch, []byte("new writer")); err != nil {
		t.Fatal(err)
	}
	membership, err = persistence.GetMembership(actor.MembershipID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = persistence.UpdateMembershipAuthorization(membership.ID, membership.Roles, []string{}, membership.Authorization, membership.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ReleaseResourceLease(actor, next.ID, next.FencingEpoch); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked cached actor: %v", err)
	}
	current, err := persistence.GetResourceLease(next.ID)
	if err != nil || current.State != store.LeaseActive {
		t.Fatalf("revocation changed lease: %v", err)
	}
}

func TestResourceLeaseReleaseServiceRequiresReconciliation(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	joined, actor := joinFabricPeer(t, service, group.ID, "worker", "session", "node")
	membership, err := persistence.GetMembership(actor.MembershipID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = persistence.UpdateMembershipAuthorization(membership.ID, []string{"worker"}, []string{"task.claim"}, membership.Authorization, membership.Version); err != nil {
		t.Fatal(err)
	}
	actor, err = service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	task, err := persistence.CreateSharedTask(store.SharedTask{GroupID: group.ID, Objective: "synthetic", AcceptanceCriteria: "fenced"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = persistence.ReadySharedTask(task.ID, task.Revision, group.OwnerPrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.ClaimTask(actor, TaskClaimInput{TaskID: task.ID, ExpectedRevision: task.Revision, IdempotencyKey: "claim"}); err != nil {
		t.Fatal(err)
	}
	for _, resourceID := range []string{"machine/synthetic/gpu/0", "workspace/synthetic/write", "managed_blob/quarantined/write"} {
		lease, err := persistence.AcquireResourceLease(store.ResourceLeaseRequest{ResourceID: resourceID, GroupID: group.ID, TaskID: task.ID, PrincipalID: actor.PrincipalID, TTLSeconds: 300})
		if err != nil {
			t.Fatal(err)
		}
		if lease.Enforcement == store.LeaseExecutorEnforced {
			if _, err = service.QuarantineResourceLease(actor, lease.ID, lease.FencingEpoch); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = service.ReleaseResourceLease(actor, lease.ID, lease.FencingEpoch); !errors.Is(err, ErrConflict) || !errors.Is(err, store.ErrResourceReconciliation) {
			t.Fatalf("reconciliation reason for %s: %v", resourceID, err)
		}
		current, err := persistence.GetResourceLease(lease.ID)
		if err != nil || current.State == store.LeaseReleased {
			t.Fatalf("unconfirmed release: %v", err)
		}
	}
}
