package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func newSharedTaskTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.initializeSharedTaskV2Schema(); err != nil {
		s.Close()
		t.Fatal(err)
	}
	owner, err := s.CreatePrincipal(Principal{Kind: PrincipalKindHuman, Name: "owner", Status: PrincipalStatusActive})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	group, err := s.CreateGroup(Group{Name: "task-test", OwnerPrincipalID: owner.ID, State: GroupStateActive})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	return s, group.ID
}

func createTask(t *testing.T, s *Store, groupID, objective string) *SharedTask {
	t.Helper()
	task, err := s.CreateSharedTask(SharedTask{GroupID: groupID, Objective: objective, AcceptanceCriteria: "verified evidence"})
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestSharedTaskConcurrentClaimAndStaleCandidate(t *testing.T) {
	s, groupID := newSharedTaskTestStore(t)
	defer s.Close()
	task := createTask(t, s, groupID, "measure benchmark")
	ready, err := s.ReadySharedTask(task.ID, task.Revision, "manager")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	type claimResult struct {
		task *SharedTask
		err  error
	}
	results := make([]claimResult, 24)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i].task, results[i].err = s.ClaimSharedTask(task.ID, ready.Revision, "principal-"+string(rune('a'+i)), "ep-"+string(rune('a'+i)), "key-"+string(rune('a'+i)), 300)
		}(i)
	}
	wg.Wait()
	winners := 0
	var winner *SharedTask
	for _, result := range results {
		if result.err == nil {
			winners++
			winner = result.task
		} else if !errors.Is(result.err, ErrSharedTaskConflict) {
			t.Fatalf("unexpected claim error: %v", result.err)
		}
	}
	if winners != 1 || winner.OwnerEpoch != 1 {
		t.Fatalf("winners=%d winner=%#v", winners, winner)
	}
	retry, err := s.ClaimSharedTask(task.ID, ready.Revision, winner.OwnerPrincipalID, winner.OwnerEndpointID, winner.ClaimKey, 300)
	if err != nil || retry.Revision != winner.Revision {
		t.Fatalf("idempotent claim retry=%#v err=%v", retry, err)
	}
	released, err := s.ReleaseSharedTaskClaim(task.ID, winner.Revision, winner.OwnerEpoch, winner.OwnerPrincipalID, winner.OwnerEndpointID)
	if err != nil || released.Status != SharedTaskReady {
		t.Fatalf("release=%#v err=%v", released, err)
	}
	newOwner, err := s.ClaimSharedTask(task.ID, released.Revision, "new-principal", "new-endpoint", "new-key", 300)
	if err != nil || newOwner.OwnerEpoch <= winner.OwnerEpoch {
		t.Fatalf("reclaim=%#v err=%v", newOwner, err)
	}
	stale, err := s.SubmitSharedTaskResult(task.ID, winner.OwnerPrincipalID, winner.OwnerEndpointID, winner.OwnerEpoch, winner.Revision, "old process finished", []string{"old-log"})
	if !errors.Is(err, ErrSharedTaskStaleOwner) || stale == nil || stale.Authority != "CANDIDATE" {
		t.Fatalf("stale result=%#v err=%v", stale, err)
	}
	current, err := s.GetSharedTask(task.ID)
	if err != nil || current.Status != SharedTaskClaimed || current.OwnerEndpointID != "new-endpoint" || current.AcceptedResultID != "" {
		t.Fatalf("stale owner mutated task: %#v err=%v", current, err)
	}
	result, err := s.SubmitSharedTaskResult(task.ID, newOwner.OwnerPrincipalID, newOwner.OwnerEndpointID, newOwner.OwnerEpoch, newOwner.Revision, "verified run", nil)
	if err != nil || result.Authority != "PENDING" {
		t.Fatalf("submit=%#v err=%v", result, err)
	}
	current, err = s.GetSharedTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != SharedTaskResultSubmitted {
		t.Fatalf("self-report completed task: %#v", current)
	}
	if _, err = s.AcceptSharedTaskResult(task.ID, result.ID, current.Revision, "verifier"); !errors.Is(err, ErrSharedTaskConflict) {
		t.Fatalf("evidence-free result accepted: %v", err)
	}
}

func TestSharedTaskDependenciesPreventCyclesAndPrematureClaim(t *testing.T) {
	s, groupID := newSharedTaskTestStore(t)
	defer s.Close()
	a := createTask(t, s, groupID, "A")
	b := createTask(t, s, groupID, "B")
	c := createTask(t, s, groupID, "C")
	var err error
	a, err = s.AddSharedTaskDependency(a.ID, b.ID, a.Revision, "manager")
	if err != nil {
		t.Fatal(err)
	}
	b, err = s.AddSharedTaskDependency(b.ID, c.ID, b.Revision, "manager")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AddSharedTaskDependency(c.ID, a.ID, c.Revision, "manager"); !errors.Is(err, ErrSharedTaskDependency) {
		t.Fatalf("cycle accepted: %v", err)
	}
	if _, err = s.ReadySharedTask(a.ID, a.Revision, "manager"); !errors.Is(err, ErrSharedTaskDependency) {
		t.Fatalf("unmet dependency was ready: %v", err)
	}
	c, err = s.ReadySharedTask(c.ID, c.Revision, "manager")
	if err != nil {
		t.Fatal(err)
	}
	c, err = s.ClaimSharedTask(c.ID, c.Revision, "worker", "ep-worker", "claim-c", 300)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.SubmitSharedTaskResult(c.ID, "worker", "ep-worker", c.OwnerEpoch, c.Revision, "tests passed", []string{"artifact:sha256:abc"})
	if err != nil {
		t.Fatal(err)
	}
	c, err = s.GetSharedTask(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	c, err = s.AcceptSharedTaskResult(c.ID, result.ID, c.Revision, "verifier")
	if err != nil || c.Status != SharedTaskCompleted {
		t.Fatalf("accept=%#v err=%v", c, err)
	}
	b, err = s.ReadySharedTask(b.ID, b.Revision, "manager")
	if err != nil || b.Status != SharedTaskReady {
		t.Fatalf("dependency did not unblock: %#v err=%v", b, err)
	}
}
