package store

import (
	"errors"
	"testing"
)

func TestSharedTaskHandoffAtomicallyFencesOldOwnerAndRetainsSideEffects(t *testing.T) {
	s, groupID := newSharedTaskTestStore(t)
	defer s.Close()
	task := createTask(t, s, groupID, "measure once")
	var err error
	task, err = s.ReadySharedTask(task.ID, task.Revision, "manager")
	if err != nil {
		t.Fatal(err)
	}
	task, err = claimPreparingSharedTaskFixture(t, s, task.ID, task.Revision,
		"principal-old", "ep-old", "old-claim", 300)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := proposePreparingSharedTaskHandoffFixture(t, s, SharedTaskHandoff{
		TaskID: task.ID, GroupID: groupID, FromPrincipalID: "principal-old", FromEndpointID: "ep-old",
		ToPrincipalID: "principal-new", ToEndpointID: "ep-new", FromOwnerEpoch: task.OwnerEpoch, TaskRevision: task.Revision,
		PendingWork: "verify result", WorkspaceState: "clean worktree at rev abc",
		EvidenceRefs: []string{"log:run-1"}, SideEffects: []string{"started benchmark process 391"}, NoRepeatActions: []string{"do not relaunch benchmark"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AcceptSharedTaskHandoff(proposal.ID, "wrong-principal", "ep-new", 300); !errors.Is(err, ErrSharedTaskHandoffConflict) {
		t.Fatalf("wrong receiver accepted: %v", err)
	}
	accepted, err := s.AcceptSharedTaskHandoff(proposal.ID, "principal-new", "ep-new", 300)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.OwnerPrincipalID != "principal-new" || accepted.OwnerEpoch <= task.OwnerEpoch || accepted.Status != SharedTaskClaimed {
		t.Fatalf("handoff did not fence owner: %#v", accepted)
	}
	stored, err := s.GetSharedTaskHandoff(proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != HandoffTransferred || stored.AcceptedAt == "" || len(stored.SideEffects) != 1 || len(stored.NoRepeatActions) != 1 {
		t.Fatalf("handoff ledger incomplete: %#v", stored)
	}
	if _, err = s.AcceptSharedTaskHandoff(proposal.ID, "principal-new", "ep-new", 300); !errors.Is(err, ErrSharedTaskHandoffConflict) {
		t.Fatalf("double accept succeeded: %v", err)
	}
	stale, err := s.SubmitSharedTaskResult(task.ID, "principal-old", "ep-old", task.OwnerEpoch, task.Revision, "old process result", []string{"log:old"})
	if !errors.Is(err, ErrSharedTaskStaleOwner) || stale == nil || stale.Authority != "CANDIDATE" {
		t.Fatalf("old owner submitted authoritative result: %#v err=%v", stale, err)
	}
	current, err := s.GetSharedTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.OwnerEndpointID != "ep-new" || current.Status != SharedTaskClaimed {
		t.Fatalf("old result changed owner: %#v", current)
	}
	newResult, err := s.SubmitSharedTaskResult(task.ID, "principal-new", "ep-new", accepted.OwnerEpoch, accepted.Revision, "verified done", []string{"artifact:sha256:new"})
	if err != nil || newResult.Authority != "PENDING" {
		t.Fatalf("new owner result=%#v err=%v", newResult, err)
	}
}
