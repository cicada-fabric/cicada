package store

import (
	"encoding/json"
	"testing"
)

func TestStorePersistsControlObjects(t *testing.T) {
	persistence, err := New(t.TempDir() + "/state/cicada.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()

	machine, err := persistence.UpsertMachine("worker-local", "Worker", map[string]any{"harnesses": []string{"codex"}}, "available")
	if err != nil {
		t.Fatal(err)
	}
	if machine.Capabilities["harnesses"].([]any)[0] != "codex" {
		t.Fatalf("machine capabilities were not decoded: %#v", machine.Capabilities)
	}

	goal, err := persistence.CreateGoal("goal_test", "run benchmark", "report evidence", "workspace only", 80, machine.ID, "monitor_test", "/workspace/goals/goal_test")
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := persistence.CreateMonitor("monitor_test", goal.ID, "supervise")
	if err != nil {
		t.Fatal(err)
	}
	if monitor.Status != "active" || monitor.Policy != "supervise" {
		t.Fatalf("unexpected monitor: %#v", monitor)
	}
	if err := persistence.TouchMonitor(monitor.ID, "active"); err != nil {
		t.Fatal(err)
	}
	worker, err := persistence.CreateWorker("worker_test", goal.ID, machine.ID, "/workspace/goals/goal_test/.last-message")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.AppendEvent(goal.ID, worker.ID, "WorkerQueued", map[string]any{"attempt": 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.EnqueueCommand(goal.ID, worker.ID, "check the memory profile"); err != nil {
		t.Fatal(err)
	}
	commands, err := persistence.ClaimPendingCommands(goal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || commands[0].Status != "consumed" {
		t.Fatalf("unexpected claimed commands: %#v", commands)
	}

	approval, err := persistence.CreateApproval("approval_test", goal.ID, worker.ID, "item/commandExecution/requestApproval", map[string]any{"command": []string{"make", "test"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ResolveApproval(approval.ID, "accept"); err != nil {
		t.Fatal(err)
	}
	resolved, err := persistence.GetApproval(approval.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Status != "resolved" || resolved.Decision != "accept" {
		t.Fatalf("approval was not resolved: %#v", resolved)
	}

	events, err := persistence.ListEvents(goal.ID, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "WorkerQueued" {
		t.Fatalf("unexpected events: %#v", events)
	}
	var payload map[string]any
	if err := json.Unmarshal(events[0].Payload, &payload); err != nil || payload["attempt"] != float64(1) {
		t.Fatalf("event payload was not persisted: %s", events[0].Payload)
	}
}
