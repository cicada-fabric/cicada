package fabric

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestSharedTaskAuthorizationUsesCurrentSessionMembership(t *testing.T) {
	persistence, err := store.New(filepath.Join(t.TempDir(), "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	owner, err := persistence.CreatePrincipal(store.Principal{Kind: store.PrincipalKindHuman, Name: "owner", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	groupA, err := persistence.CreateGroup(store.Group{Name: "A", OwnerPrincipalID: owner.ID, State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := persistence.CreateGroup(store.Group{Name: "B", OwnerPrincipalID: owner.ID, State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(persistence, owner.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	joinedA, actorA := joinFabricPeer(t, service, groupA.ID, "worker-a", "session-a", "node-a")
	_, actorB := joinFabricPeer(t, service, groupB.ID, "worker-b", "session-b", "node-b")
	task, err := persistence.CreateSharedTask(store.SharedTask{GroupID: groupA.ID, Objective: "measure", AcceptanceCriteria: "independent test record"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = persistence.ReadySharedTask(task.ID, task.Revision, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.GetTask(actorB, task.ID); !errors.Is(err, ErrNotFoundOrNotAuthorized) && !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-group task visible: %v", err)
	}
	if _, err = service.ClaimTask(actorA, TaskClaimInput{TaskID: task.ID, ExpectedRevision: task.Revision, IdempotencyKey: "claim-1"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("unbound member claimed a worker task: %v", err)
	}
	membership, err := persistence.GetMembership(actorA.MembershipID)
	if err != nil {
		t.Fatal(err)
	}
	grants := append(append([]string{}, membership.Grants...), "task.read", "task.claim", "task.submit")
	_, err = persistence.UpdateMembershipAuthorization(membership.ID, []string{"worker"}, grants, membership.Authorization, membership.Version)
	if err != nil {
		t.Fatal(err)
	}
	// A previously derived Actor cannot survive a membership revision change.
	if _, err = service.ClaimTask(actorA, TaskClaimInput{TaskID: task.ID, ExpectedRevision: task.Revision, IdempotencyKey: "claim-1"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("stale actor remained authorized: %v", err)
	}
	actorA, err = service.Authenticate(joinedA.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := service.ClaimTask(actorA, TaskClaimInput{TaskID: task.ID, ExpectedRevision: task.Revision, IdempotencyKey: "claim-1"})
	if err != nil {
		t.Fatal(err)
	}
	if claimed.OwnerEndpointID != actorA.EndpointID {
		t.Fatalf("caller forged claim owner: %#v", claimed)
	}
	result, err := service.SubmitTaskResult(actorA, TaskResultInput{TaskID: task.ID, OwnerEpoch: claimed.OwnerEpoch, ExpectedRevision: claimed.Revision, Summary: "done", Evidence: []string{"artifact:verified"}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := persistence.GetSharedTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.AcceptTaskResult(actorA, TaskAcceptInput{TaskID: task.ID, ResultID: result.ID, ExpectedRevision: current.Revision}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("worker self-approved result: %v", err)
	}
}
