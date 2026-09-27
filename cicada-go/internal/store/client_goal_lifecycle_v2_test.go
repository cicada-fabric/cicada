package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnedQueuedGoalPauseResumeFencesRemoteClaim(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.UpsertMachine("remote-node", "remote", nil, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := s.CreateGoal("goal-pause", "test pause", "done", "", 50, "remote-node", "", "/workspace")
	if err != nil {
		t.Fatal(err)
	}
	worker, err := s.CreateWorkerAtHarness("worker-pause", goal.ID, "remote-node", "codex", "/response", "/workspace")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE goals SET owner_id='owner-a' WHERE id=?`, goal.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeOwnedQueuedGoalLifecycle("owner-b", "device-a", "request-1", goal.ID, "pause", 1); !errors.Is(err, ErrClientGoalLifecycleConflict) {
		t.Fatalf("wrong owner changed Goal: %v", err)
	}
	paused, err := s.ChangeOwnedQueuedGoalLifecycle("owner-a", "device-a", "request-2", goal.ID, "pause", 1)
	if err != nil || paused.Status != "paused" || paused.LifecycleVersion != 2 {
		t.Fatalf("pause failed: goal=%#v err=%v", paused, err)
	}
	if _, err := s.ChangeOwnedQueuedGoalLifecycle("owner-a", "device-a", "request-3", goal.ID, "resume", 1); !errors.Is(err, ErrClientGoalLifecycleConflict) {
		t.Fatalf("stale version resumed Goal: %v", err)
	}
	jobs, err := s.ListWorkersForMachine("remote-node")
	if err != nil || len(jobs) != 0 {
		t.Fatalf("paused Goal remained in legacy jobs: jobs=%#v err=%v", jobs, err)
	}
	claimed, err := s.ClaimWorker(worker.ID, "remote-node")
	if err != nil || claimed != nil {
		t.Fatalf("legacy claim started paused Goal: worker=%#v err=%v", claimed, err)
	}
	resumed, err := s.ChangeOwnedQueuedGoalLifecycle("owner-a", "device-a", "request-4", goal.ID, "resume", 2)
	if err != nil || resumed.Status != "queued" || resumed.LifecycleVersion != 3 {
		t.Fatalf("resume failed: goal=%#v err=%v", resumed, err)
	}
	claimed, err = s.ClaimWorker(worker.ID, "remote-node")
	if err != nil || claimed == nil || claimed.Status != "running" {
		t.Fatalf("resumed Goal not claimable: worker=%#v err=%v", claimed, err)
	}
	if _, err := s.ChangeOwnedQueuedGoalLifecycle("owner-a", "device-a", "request-5", goal.ID, "pause", 3); !errors.Is(err, ErrClientGoalLifecycleConflict) {
		t.Fatalf("running Worker was labelled paused: %v", err)
	}
	current, err := s.GetGoal(goal.ID)
	if err != nil || current.Status != "queued" || current.LifecycleVersion != 3 {
		t.Fatalf("rejected pause changed Goal: goal=%#v err=%v", current, err)
	}
	events, err := s.ListEvents(goal.ID, 0, 10)
	if err != nil || len(events) < 2 || events[len(events)-1].Type != "GoalResumed" ||
		!strings.Contains(string(events[len(events)-1].Payload), `"client_request_id":"request-4"`) {
		t.Fatalf("lifecycle audit events missing: %#v err=%v", events, err)
	}
}
