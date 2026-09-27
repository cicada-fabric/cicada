package fabric

import (
	"errors"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func grantTaskWorker(t *testing.T, persistence *store.Store, actor Actor) {
	t.Helper()
	membership, err := persistence.GetMembership(actor.MembershipID)
	if err != nil {
		t.Fatal(err)
	}
	grants := append(append([]string{}, membership.Grants...), "task.read", "task.claim", "task.submit")
	_, err = persistence.UpdateMembershipAuthorization(membership.ID, []string{"worker"}, grants, membership.Authorization, membership.Version)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTaskHandoffPeerAuthorizationAndMissingArtifactIsDurable(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	a, oldA := joinFabricPeer(t, service, group.ID, "task-owner", "native-task-owner", "node-a")
	b, oldB := joinFabricPeer(t, service, group.ID, "task-receiver", "native-task-receiver", "node-b")
	grantTaskWorker(t, persistence, oldA)
	grantTaskWorker(t, persistence, oldB)
	actorA, err := service.Authenticate(a.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	actorB, err := service.Authenticate(b.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	task, err := persistence.CreateSharedTask(store.SharedTask{GroupID: group.ID, Objective: "handoff task", AcceptanceCriteria: "verified record"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = persistence.ReadySharedTask(task.ID, task.Revision, "manager")
	if err != nil {
		t.Fatal(err)
	}
	task, err = service.ClaimTask(actorA, TaskClaimInput{TaskID: task.ID, ExpectedRevision: task.Revision, IdempotencyKey: "claim-a"})
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := service.ProposeTaskHandoff(actorA, TaskHandoffProposeInput{
		TaskID: task.ID, Target: b.Endpoint.ID, ExpectedRevision: task.Revision, OwnerEpoch: task.OwnerEpoch,
		PendingWork: "review the experiment", ArtifactRefs: []string{"aref_missing"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.AcceptTaskHandoff(actorA, proposed.ID, 300); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("sender accepted receiver handoff: %v", err)
	}
	if _, err = service.AcceptTaskHandoff(actorB, proposed.ID, 300); !errors.Is(err, store.ErrSharedTaskHandoffMissingArtifact) {
		t.Fatalf("missing ArtifactRef accepted: %v", err)
	}
	stored, err := service.GetTaskHandoff(actorB, proposed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != store.HandoffProposed || len(stored.MissingArtifactRefs) != 1 || stored.MissingArtifactRefs[0] != "aref_missing" {
		t.Fatalf("missing context was not retained: %#v", stored)
	}
	still, err := persistence.GetSharedTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if still.OwnerEndpointID != actorA.EndpointID || still.OwnerEpoch != task.OwnerEpoch {
		t.Fatalf("failed handoff transferred owner: %#v", still)
	}
	// A separate handoff without ArtifactRefs moves responsibility only after
	// the receiver explicitly accepts it.
	second, err := persistence.CreateSharedTask(store.SharedTask{GroupID: group.ID, Objective: "handoff without artifacts", AcceptanceCriteria: "verified record"})
	if err != nil {
		t.Fatal(err)
	}
	second, err = persistence.ReadySharedTask(second.ID, second.Revision, "manager")
	if err != nil {
		t.Fatal(err)
	}
	second, err = service.ClaimTask(actorA, TaskClaimInput{TaskID: second.ID, ExpectedRevision: second.Revision, IdempotencyKey: "claim-second"})
	if err != nil {
		t.Fatal(err)
	}
	clean, err := service.ProposeTaskHandoff(actorA, TaskHandoffProposeInput{TaskID: second.ID, Target: b.Endpoint.ID, ExpectedRevision: second.Revision, OwnerEpoch: second.OwnerEpoch, PendingWork: "finish review"})
	if err != nil {
		t.Fatal(err)
	}
	transferred, err := service.AcceptTaskHandoff(actorB, clean.ID, 300)
	if err != nil || transferred.OwnerEndpointID != actorB.EndpointID || transferred.OwnerEpoch <= second.OwnerEpoch {
		t.Fatalf("authorized handoff failed: %#v err=%v", transferred, err)
	}
}
