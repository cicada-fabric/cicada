package control

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRemoteCompletionIsVerifiedOnceAcrossConcurrentResults(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	verifier, state := fakeCompletionVerifier(t, "accept")
	controlPlane.config.CompletionVerifierBin = verifier
	controlPlane.config.CompletionVerifierTime = 2 * time.Second
	if _, err := controlPlane.RegisterMachine("remote-verifier", "Remote verifier", map[string]any{"harnesses": []string{"shell"}}, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := controlPlane.CreateGoal(GoalInput{
		Objective: "verify one remote result", MachineID: "remote-verifier", Harness: "shell",
		Resources: map[string]any{"argv": []any{"/bin/true"}, "completion_verifier": "model"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.ClaimRemoteWorker(goal.Worker.ID, "remote-verifier"); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, completeErr := controlPlane.CompleteRemoteWorker(goal.Worker.ID, "remote-verifier", "completed", "REMOTE_VERIFIED", "", "")
			results <- completeErr
		}()
	}
	close(start)
	group.Wait()
	close(results)
	successes, conflicts := 0, 0
	for result := range results {
		if result == nil {
			successes++
		} else if errors.Is(result, ErrWorkerUnavailable) {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent result error: %v", result)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent completion results successes=%d conflicts=%d", successes, conflicts)
	}
	count, err := os.ReadFile(state)
	if err != nil || string(count) != "1" {
		t.Fatalf("remote result was verified more than once: count=%q err=%v", count, err)
	}
}

func TestRemoteCompletionRequeuesWithVerifierCorrection(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	verifier, _ := fakeCompletionVerifier(t, "revise_once")
	controlPlane.config.CompletionVerifierBin = verifier
	controlPlane.config.CompletionVerifierTime = 2 * time.Second
	if _, err := controlPlane.RegisterMachine("remote-correction", "Remote correction", map[string]any{"harnesses": []string{"shell"}}, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := controlPlane.CreateGoal(GoalInput{
		Objective: "return verified remote evidence", MachineID: "remote-correction", Harness: "shell",
		Resources: map[string]any{"argv": []any{"/bin/true"}, "completion_verifier": "model"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.ClaimRemoteWorker(goal.Worker.ID, "remote-correction"); err != nil {
		t.Fatal(err)
	}
	worker, err := controlPlane.CompleteRemoteWorker(goal.Worker.ID, "remote-correction", "completed", "first claim", "thread-1", "")
	if err != nil || worker.Status != "queued" || !strings.Contains(worker.Prompt, "verification") {
		t.Fatalf("rejected remote completion was not corrected: %#v err=%v", worker, err)
	}
	job, err := controlPlane.ClaimRemoteWorker(goal.Worker.ID, "remote-correction")
	if err != nil || !strings.Contains(job.Prompt, "verification") || job.ThreadID != "thread-1" {
		t.Fatalf("remote correction was not resumed: %#v err=%v", job, err)
	}
	if _, err := controlPlane.CompleteRemoteWorker(goal.Worker.ID, "remote-correction", "completed", "verified claim", "thread-1", ""); err != nil {
		t.Fatal(err)
	}
	final, err := controlPlane.Goal(goal.ID)
	if err != nil || final.Status != "completed" || final.Summary != "verified claim" {
		t.Fatalf("corrected remote Goal did not complete: %#v err=%v", final, err)
	}
}

func TestExplicitModelVerifierOutageRetainsRemoteResultWithoutRequeue(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	if _, err := controlPlane.RegisterMachine("remote-required-verifier", "Remote verifier", map[string]any{"harnesses": []string{"shell"}}, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := controlPlane.CreateGoal(GoalInput{
		Objective: "retain a result when required verification is unavailable",
		MachineID: "remote-required-verifier", Harness: "shell",
		Resources: map[string]any{"argv": []any{"/bin/true"}, "completion_verifier": "model"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.ClaimRemoteWorker(goal.Worker.ID, "remote-required-verifier"); err != nil {
		t.Fatal(err)
	}
	const candidate = "completed result retained for manager review"
	worker, err := controlPlane.CompleteRemoteWorker(goal.Worker.ID, "remote-required-verifier",
		"completed", candidate, "thread-verifier-outage", "")
	if err != nil || worker == nil || worker.Status != "failed" || worker.Summary != candidate ||
		!strings.Contains(worker.LastError, "Required completion verification is unavailable") {
		t.Fatalf("required verifier outage did not retain and fail the result safely: worker=%#v err=%v", worker, err)
	}
	currentGoal, err := controlPlane.Goal(goal.ID)
	if err != nil || currentGoal == nil || currentGoal.Status != "failed" {
		t.Fatalf("Goal did not enter a blocked terminal state: goal=%#v err=%v", currentGoal, err)
	}
	if _, err := controlPlane.ClaimRemoteWorker(goal.Worker.ID, "remote-required-verifier"); err == nil {
		t.Fatal("verifier outage requeued Worker side effects")
	}
	artifacts, err := controlPlane.store.ListArtifacts(goal.ID)
	if err != nil || len(artifacts) != 0 {
		t.Fatalf("unverified completion created accepted artifacts: %#v err=%v", artifacts, err)
	}
	events, err := controlPlane.Events(goal.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	types := eventTypes(events)
	if !types["WorkerCompletionVerificationUnavailable"] || !types["GoalBlocked"] || types["WorkerRecovered"] || types["WorkerCompleted"] {
		t.Fatalf("verifier outage lifecycle events are inconsistent: %v", types)
	}
}
