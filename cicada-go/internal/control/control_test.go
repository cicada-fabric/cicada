package control

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	for time.Now().Before(deadline) {
		current, lookupErr := controlPlane.Goal(goal.ID)
		if lookupErr != nil {
			t.Fatal(lookupErr)
		}
		if current.Worker != nil && current.Worker.Status == "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
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
