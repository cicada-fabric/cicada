package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

// fakeCodex speaks just enough of Codex's app-server JSON-RPC protocol to
// exercise the real Control lifecycle without spending relay tokens.
func fakeCodex(t *testing.T, mode string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-codex")
	script := fmt.Sprintf(`#!/usr/bin/env bash
set -eu
mode=%q
turn_file="$PWD/.cicada-fake-turns"
fail_file="$PWD/.cicada-fake-failed"
while IFS= read -r line; do
  [ -n "$line" ] || continue
  id="$(printf '%%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%%s,"result":{}}\n' "$id"
      ;;
    *'"method":"thread/start"'*)
      printf '%%s\n' '{"jsonrpc":"2.0","method":"thread/started","params":{"thread":{"id":"fake-thread"}}}'
      printf '{"jsonrpc":"2.0","id":%%s,"result":{"thread":{"id":"fake-thread"}}}\n' "$id"
      ;;
    *'"method":"thread/resume"'*)
      printf '{"jsonrpc":"2.0","id":%%s,"result":{"thread":{"id":"fake-thread"}}}\n' "$id"
      ;;
    *'"method":"turn/start"'*)
      printf '{"jsonrpc":"2.0","id":%%s,"result":{"turn":{"id":"fake-turn"}}}\n' "$id"
      turns=0
      if [ -f "$turn_file" ]; then turns="$(cat "$turn_file")"; fi
      turns=$((turns + 1))
      printf '%%s\n' "$turns" > "$turn_file"
      if [ "$mode" = fail_once ] && [ ! -f "$fail_file" ]; then
        : > "$fail_file"
        exit 42
      fi
      if [ "$mode" = correction ]; then sleep 0.2; fi
      if [ "$mode" = approval ]; then
        printf '%%s\n' '{"jsonrpc":"2.0","id":77,"method":"item/commandExecution/requestApproval","params":{"command":["echo","approved"]}}'
        while IFS= read -r approval_response; do
          case "$approval_response" in
            *'"id":77'*) break ;;
          esac
        done
      fi
      text="FAKE_READY"
      if [ "$mode" = fail_once ]; then text="FAKE_RECOVERED_READY"; fi
      if [ "$mode" = correction ] && [ "$turns" -gt 1 ]; then text="FAKE_CORRECTED_READY"; fi
      if [ "$mode" = approval ]; then text="FAKE_APPROVED_READY"; fi
      printf '{"jsonrpc":"2.0","method":"item/completed","params":{"item":{"type":"agentMessage","text":"%%s"}}}\n' "$text"
      printf '%%s\n' '{"jsonrpc":"2.0","method":"turn/completed","params":{"turn":{"status":"completed"}}}'
      ;;
  esac
done
`, mode)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTestControl(t *testing.T, mode string) *Control {
	t.Helper()
	root := t.TempDir()
	controlPlane, err := New(Config{
		StateDir:      filepath.Join(root, "state"),
		WorkspaceRoot: filepath.Join(root, "workspace"),
		CodexBinary:   fakeCodex(t, mode),
		WorkerTimeout: 10 * time.Second,
		MaxRecoveries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controlPlane.Start(); err != nil {
		_ = controlPlane.Shutdown(context.Background())
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controlPlane.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown control: %v", err)
		}
	})
	return controlPlane
}

func waitTestGoal(t *testing.T, controlPlane *Control, goalID string) *store.Goal {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		goal, err := controlPlane.Goal(goalID)
		if err != nil {
			t.Fatal(err)
		}
		if goal != nil && (goal.Status == "completed" || goal.Status == "failed" || goal.Status == "cancelled") {
			return goal
		}
		time.Sleep(10 * time.Millisecond)
	}
	goal, _ := controlPlane.Goal(goalID)
	t.Fatalf("goal did not reach a terminal state: %#v", goal)
	return nil
}

func waitTestApproval(t *testing.T, controlPlane *Control) *store.Approval {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		approvals, err := controlPlane.Approvals(true)
		if err != nil {
			t.Fatal(err)
		}
		if len(approvals) > 0 {
			return &approvals[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("approval was not requested")
	return nil
}

func eventTypes(events []store.Event) map[string]bool {
	result := make(map[string]bool)
	for _, event := range events {
		result[event.Type] = true
	}
	return result
}

func TestControlRecoversCodexProcess(t *testing.T) {
	controlPlane := newTestControl(t, "fail_once")
	goal, err := controlPlane.CreateGoal(GoalInput{Objective: "recover the worker"})
	if err != nil {
		t.Fatal(err)
	}
	final := waitTestGoal(t, controlPlane, goal.ID)
	if final.Status != "completed" || final.Summary != "FAKE_RECOVERED_READY" {
		t.Fatalf("unexpected recovered goal: %#v", final)
	}
	if final.Worker == nil || final.Worker.Attempt != 2 {
		t.Fatalf("expected second attempt, got %#v", final.Worker)
	}
	events, err := controlPlane.Events(goal.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	types := eventTypes(events)
	for _, required := range []string{"WorkerFailed", "WorkerRecovered", "WorkerCompleted", "GoalCompleted"} {
		if !types[required] {
			t.Fatalf("missing %s in events: %v", required, types)
		}
	}
}

func TestControlMonitorCorrectionStartsAnotherTurn(t *testing.T) {
	controlPlane := newTestControl(t, "correction")
	goal, err := controlPlane.CreateGoal(GoalInput{Objective: "follow monitor correction"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	runningObserved := false
	for time.Now().Before(deadline) {
		current, lookupErr := controlPlane.Goal(goal.ID)
		if lookupErr != nil {
			t.Fatal(lookupErr)
		}
		if current.Worker != nil && current.Worker.Status == "running" {
			runningObserved = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !runningObserved {
		t.Fatal("worker never entered running state")
	}
	machines, err := controlPlane.Machines()
	if err != nil {
		t.Fatal(err)
	}
	busy := false
	for _, machine := range machines {
		if machine.ID == goal.MachineID && machine.Status == "busy" {
			busy = true
		}
	}
	if !busy {
		t.Fatalf("selected machine was not marked busy: %#v", machines)
	}
	if _, err := controlPlane.SendCommand(goal.ID, "Correction: use the corrected answer"); err != nil {
		t.Fatal(err)
	}
	final := waitTestGoal(t, controlPlane, goal.ID)
	if final.Status != "completed" || final.Summary != "FAKE_CORRECTED_READY" {
		t.Fatalf("unexpected corrected goal: %#v", final)
	}
	events, err := controlPlane.Events(goal.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	types := eventTypes(events)
	if !types["MonitorCommandQueued"] || !types["MonitorCommandSent"] {
		t.Fatalf("missing monitor command events: %v", types)
	}
	if final.Monitor == nil || final.Monitor.Status != "active" {
		t.Fatalf("monitor was not bound/active: %#v", final.Monitor)
	}
}

func TestControlStopsGoalWhenRuntimeBudgetIsExceeded(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		CodexBinary: fakeCodex(t, "correction"), WorkerTimeout: 2 * time.Second,
		MaxRecoveries: 1, MonitorInterval: 10 * time.Millisecond, MonitorStallAfter: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controlPlane.Start(); err != nil {
		_ = controlPlane.Shutdown(context.Background())
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controlPlane.Shutdown(context.Background()) })
	goal, err := controlPlane.CreateGoal(GoalInput{
		Objective: "stop over-budget work", Budget: map[string]any{"max_runtime_seconds": 0.01},
	})
	if err != nil {
		t.Fatal(err)
	}
	final := waitTestGoal(t, controlPlane, goal.ID)
	if final.Status != "cancelled" {
		t.Fatalf("runtime budget did not cancel goal: %#v", final)
	}
	events, err := controlPlane.Events(goal.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !eventTypes(events)["GoalBudgetExceeded"] {
		t.Fatalf("missing budget event: %v", eventTypes(events))
	}
}

func TestControlApprovalPausesUntilResolved(t *testing.T) {
	controlPlane := newTestControl(t, "approval")
	goal, err := controlPlane.CreateGoal(GoalInput{Objective: "run an approved action"})
	if err != nil {
		t.Fatal(err)
	}
	approval := waitTestApproval(t, controlPlane)
	if approval.GoalID != goal.ID || approval.Status != "pending" {
		t.Fatalf("unexpected approval: %#v", approval)
	}
	if _, err := controlPlane.ResolveApproval(approval.ID, "approve"); err != nil {
		t.Fatal(err)
	}
	final := waitTestGoal(t, controlPlane, goal.ID)
	if final.Status != "completed" || final.Summary != "FAKE_APPROVED_READY" {
		t.Fatalf("unexpected approved goal: %#v", final)
	}
	resolved, err := controlPlane.Approvals(false)
	if err != nil {
		t.Fatal(err)
	}
	foundResolved := false
	for _, item := range resolved {
		if item.ID == approval.ID && item.Status == "resolved" && item.Decision == "accept" {
			foundResolved = true
		}
	}
	if !foundResolved {
		t.Fatalf("approval was not durably resolved: %#v", resolved)
	}
	events, err := controlPlane.Events(goal.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	types := eventTypes(events)
	if !types["ApprovalRequested"] || !types["ApprovalResolved"] {
		t.Fatalf("missing approval events: %v", types)
	}
}

func TestControlPeerMessageUsesPostQuantumEnvelope(t *testing.T) {
	alice := newTestControl(t, "success")
	bob := newTestControl(t, "success")
	aliceContact, err := alice.CreateContact("bob", bob.Identity())
	if err != nil {
		t.Fatal(err)
	}
	bobContact, err := bob.CreateContact("alice", alice.Identity())
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := alice.SendPeerMessage(aliceContact.ID, "benchmark evidence is ready", []byte("goal=demo"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, inbound, err := bob.ReceivePeerMessage(bobContact.ID, outbound.Envelope, []byte("goal=demo"))
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "benchmark evidence is ready" || inbound.Sequence != outbound.Sequence {
		t.Fatalf("unexpected peer message: plaintext=%q inbound=%#v outbound=%#v", plaintext, inbound, outbound)
	}
	if _, _, err := bob.ReceivePeerMessage(bobContact.ID, outbound.Envelope, []byte("goal=demo")); err != store.ErrPeerReplay {
		t.Fatalf("expected persistent replay rejection, got %v", err)
	}
}

func TestControlPermissionBlocksPeerMessage(t *testing.T) {
	alice := newTestControl(t, "success")
	bob := newTestControl(t, "success")
	contact, err := alice.CreateContact("bob", bob.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := alice.UpdateContact(contact.ID, "bob revoked", "revoked"); err != nil || revoked.Status != "revoked" {
		t.Fatalf("contact trust status was not updated: %#v err=%v", revoked, err)
	}
	if _, err := alice.SendPeerMessage(contact.ID, "should be blocked", nil); err == nil {
		t.Fatal("revoked contact accepted a peer message")
	}
	contact, err = alice.UpdateContact(contact.ID, "bob", "trusted")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.SetPermission(PermissionInput{
		SubjectType: "contact", SubjectID: contact.ID, Action: "peer.message", Effect: "deny",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.SendPeerMessage(contact.ID, "should be blocked", nil); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected denied peer message, got %v", err)
	}
	if _, err := alice.SetPermission(PermissionInput{
		SubjectType: "contact", SubjectID: contact.ID, Action: "peer.message", Effect: "approval",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.SendPeerMessage(contact.ID, "needs approval", nil); !errors.Is(err, ErrPermissionApproval) {
		t.Fatalf("expected approval-gated peer message, got %v", err)
	}
}

func TestSchedulerMatchesMachineCapabilitiesAndHeartbeat(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	if _, err := controlPlane.RegisterMachine("gpu-test", "GPU test", map[string]any{
		"harnesses": []string{"codex"}, "os": "linux", "accelerator": "H100", "memory_gb": 80,
	}, "available"); err != nil {
		t.Fatal(err)
	}
	selected, err := controlPlane.chooseMachine("", map[string]any{"accelerator": "H100", "min_memory_gb": 40, "harness": "codex"})
	if err != nil || selected != "gpu-test" {
		t.Fatalf("scheduler selected %q err=%v", selected, err)
	}
	heartbeat, err := controlPlane.HeartbeatMachine("gpu-test", "busy", nil)
	if err != nil || heartbeat.Status != "busy" {
		t.Fatalf("heartbeat did not update machine: %#v err=%v", heartbeat, err)
	}
	if _, err := controlPlane.chooseMachine("gpu-test", map[string]any{"accelerator": "A100"}); err == nil {
		t.Fatal("scheduler accepted an incompatible accelerator")
	}
}

func TestWorkspaceLifecycleActions(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	workspace, err := controlPlane.CreateWorkspace(WorkspaceInput{Path: filepath.Join(controlPlane.config.WorkspaceRoot, "source"), Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.Path, "evidence.txt"), []byte("ready"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := controlPlane.WorkspaceAction(workspace.ID, "snapshot", "")
	if err != nil || snapshot.Status != "snapshot" || snapshot.Revision == "" {
		t.Fatalf("snapshot failed: %#v err=%v", snapshot, err)
	}
	archiveRule, err := controlPlane.SetPermission(PermissionInput{
		SubjectType: "workspace", SubjectID: workspace.ID, Action: "workspace.archive", Effect: "deny",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.WorkspaceAction(workspace.ID, "archive", ""); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected workspace archive to be denied, got %v", err)
	}
	if err := controlPlane.DeletePermission(archiveRule.ID); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(controlPlane.config.WorkspaceRoot, "migrated")
	occupied := filepath.Join(controlPlane.config.WorkspaceRoot, "occupied")
	if err := os.MkdirAll(occupied, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(occupied, "keep.txt"), []byte("do not overwrite"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.WorkspaceAction(workspace.ID, "migrate", occupied); err == nil {
		t.Fatal("migration overwrote a non-empty target")
	}
	migrated, err := controlPlane.WorkspaceAction(workspace.ID, "migrate", target)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Path != target {
		t.Fatalf("workspace did not migrate: %#v", migrated)
	}
	content, err := os.ReadFile(filepath.Join(target, "evidence.txt"))
	if err != nil || string(content) != "ready" {
		t.Fatalf("migrated evidence missing: %q err=%v", content, err)
	}
	if _, err := controlPlane.WorkspaceAction(workspace.ID, "archive", ""); err != nil {
		t.Fatal(err)
	}
	resumed, err := controlPlane.WorkspaceAction(workspace.ID, "resume", "")
	if err != nil || resumed.Status != "active" {
		t.Fatalf("workspace did not resume: %#v err=%v", resumed, err)
	}
}

func TestGoalCanRunMultipleWorkersInSeparateWorkspaces(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	if _, err := controlPlane.RegisterMachine("worker-2", "Worker 2", map[string]any{"harnesses": []string{"codex"}}, "available"); err != nil {
		t.Fatal(err)
	}
	goalID, monitorID := "goal_multi", "monitor_multi"
	goalPath := filepath.Join(controlPlane.config.WorkspaceRoot, "goals", goalID)
	if err := os.MkdirAll(goalPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.store.CreateGoal(goalID, "run two workers", "", "", 50, "worker-local", monitorID, goalPath); err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.store.CreateMonitor(monitorID, goalID, "supervise"); err != nil {
		t.Fatal(err)
	}
	worker, err := controlPlane.AddWorker(goalID, WorkerInput{MachineID: "worker-2", Prompt: "inspect the shared goal independently"})
	if err != nil {
		t.Fatal(err)
	}
	if worker.Workspace == "" || worker.Workspace == goalPath || !strings.HasPrefix(worker.Workspace, filepath.Join(goalPath, "workers")) {
		t.Fatalf("worker did not receive an isolated workspace: %#v", worker)
	}
	workers, err := controlPlane.store.ListWorkersForGoal(goalID)
	if err != nil || len(workers) != 1 {
		t.Fatalf("unexpected goal workers: %#v err=%v", workers, err)
	}
}

func TestMonitorQueuesCorrectionAfterStall(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		CodexBinary: fakeCodex(t, "correction"), WorkerTimeout: 10 * time.Second, MaxRecoveries: 1,
		MonitorInterval: 20 * time.Millisecond, MonitorStallAfter: 30 * time.Millisecond, MachineStaleAfter: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controlPlane.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controlPlane.Shutdown(context.Background()) })
	goal, err := controlPlane.CreateGoal(GoalInput{Objective: "monitor a slow worker"})
	if err != nil {
		t.Fatal(err)
	}
	final := waitTestGoal(t, controlPlane, goal.ID)
	if final.Status != "completed" || final.Summary != "FAKE_CORRECTED_READY" {
		t.Fatalf("monitor did not correct worker: %#v", final)
	}
	events, err := controlPlane.Events(goal.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	types := eventTypes(events)
	if !types["MonitorCorrectionQueued"] {
		t.Fatalf("monitor correction event missing: %v", types)
	}
	notifications, err := controlPlane.Notifications(true)
	if err != nil || len(notifications) == 0 {
		t.Fatalf("monitor notification missing: %#v err=%v", notifications, err)
	}
}

func TestIdeaResearchCreatesNonExecutionGoal(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	idea, err := controlPlane.CreateIdea(IdeaInput{Title: "Research opportunity", Description: "Assess whether this benchmark is worth pursuing"})
	if err != nil {
		t.Fatal(err)
	}
	goal, err := controlPlane.ResearchIdea(idea.ID)
	if err != nil {
		t.Fatal(err)
	}
	final := waitTestGoal(t, controlPlane, goal.ID)
	if final.Status != "completed" || !strings.Contains(final.Objective, "without executing it") {
		t.Fatalf("research goal did not complete as constrained analysis: %#v", final)
	}
	updated, err := controlPlane.Idea(idea.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "researching" || updated.GoalID != goal.ID {
		t.Fatalf("idea was not linked to research goal: %#v", updated)
	}
}

func TestUnsupportedHarnessIsRejectedBeforeWorkerCreation(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	if _, err := controlPlane.CreateGoal(GoalInput{Objective: "try unsupported harness", Harness: "claude-code"}); err == nil {
		t.Fatal("unsupported harness was accepted")
	}
}

func TestGoalDeadlineMustBeRFC3339(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	if _, err := controlPlane.CreateGoal(GoalInput{Objective: "bad deadline", Deadline: "tomorrow"}); err == nil {
		t.Fatal("invalid deadline was accepted")
	}
}

func waitTestWorkerRunning(t *testing.T, controlPlane *Control, goalID string) *store.Goal {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		goal, err := controlPlane.Goal(goalID)
		if err != nil {
			t.Fatal(err)
		}
		if goal != nil && goal.Worker != nil && goal.Worker.Status == "running" {
			return goal
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("worker did not enter running state: %s", goalID)
	return nil
}

func TestControlRoutesMessagesBetweenCodexThreads(t *testing.T) {
	controlPlane := newTestControl(t, "correction")
	first, err := controlPlane.CreateGoal(GoalInput{Objective: "thread A prepare a result"})
	if err != nil {
		t.Fatal(err)
	}
	// Wait until worker-local is reserved, so the second Goal demonstrates
	// scheduler selection of the other registered machine.
	waitTestWorkerRunning(t, controlPlane, first.ID)
	second, err := controlPlane.CreateGoal(GoalInput{Objective: "thread B review a peer result"})
	if err != nil {
		t.Fatal(err)
	}
	first = waitTestGoal(t, controlPlane, first.ID)
	second = waitTestGoal(t, controlPlane, second.ID)
	if first.Worker == nil || second.Worker == nil || first.Worker.ThreadID == "" || second.Worker.ThreadID == "" {
		t.Fatalf("both goals need Codex threads: first=%#v second=%#v", first.Worker, second.Worker)
	}
	if first.MachineID == second.MachineID {
		t.Fatalf("scheduler reused a busy machine: first=%s second=%s", first.MachineID, second.MachineID)
	}

	sent, err := controlPlane.SendThreadMessage(first.Worker.ID, second.Worker.ID, "Thread A reports evidence; verify it and respond.")
	if err != nil {
		t.Fatal(err)
	}
	if sent.Status != "dispatched" || sent.FromThreadID != first.Worker.ThreadID || sent.ToThreadID != second.Worker.ThreadID {
		t.Fatalf("unexpected peer dispatch: %#v", sent)
	}
	second = waitTestGoal(t, controlPlane, second.ID)
	if second.Summary != "FAKE_CORRECTED_READY" {
		t.Fatalf("thread B did not resume with peer context: %q", second.Summary)
	}

	returned, err := controlPlane.SendThreadMessage(second.Worker.ID, first.Worker.ID, "Thread B verified the evidence; continue with the shared conclusion.")
	if err != nil {
		t.Fatal(err)
	}
	if returned.Status != "dispatched" {
		t.Fatalf("unexpected return dispatch: %#v", returned)
	}
	first = waitTestGoal(t, controlPlane, first.ID)
	if first.Summary != "FAKE_CORRECTED_READY" {
		t.Fatalf("thread A did not receive the return message: %q", first.Summary)
	}

	firstEvents, err := controlPlane.Events(first.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	secondEvents, err := controlPlane.Events(second.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstTypes, secondTypes := eventTypes(firstEvents), eventTypes(secondEvents)
	if !firstTypes["PeerMessageSent"] || !firstTypes["PeerMessageReceived"] {
		t.Fatalf("thread A peer events missing: %v", firstTypes)
	}
	if !secondTypes["PeerMessageSent"] || !secondTypes["PeerMessageReceived"] || !secondTypes["PeerMessageDispatched"] {
		t.Fatalf("thread B peer events missing: %v", secondTypes)
	}
}
