package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
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
	if _, err := persistence.UpsertMachine("remote-test", "Remote", nil, "available"); err != nil {
		t.Fatal(err)
	}
	stale, err := persistence.MarkStaleMachines(time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	if err != nil || len(stale) != 1 || stale[0] != "remote-test" {
		t.Fatalf("stale sweep touched reserved local machines: ids=%v err=%v", stale, err)
	}
	local, err := persistence.GetMachine("worker-local")
	if err != nil || local.Status != "available" {
		t.Fatalf("local machine was marked stale: %#v err=%v", local, err)
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
	sibling, err := persistence.CreateWorker("worker_sibling", goal.ID, machine.ID, "/workspace/goals/goal_test/.sibling-message")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.EnqueueCommand(goal.ID, worker.ID, "first worker only"); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.EnqueueCommand(goal.ID, sibling.ID, "sibling only"); err != nil {
		t.Fatal(err)
	}
	commands, err = persistence.ClaimPendingCommandsForWorker(goal.ID, worker.ID)
	if err != nil || len(commands) != 1 || commands[0].WorkerID != worker.ID {
		t.Fatalf("worker-scoped claim returned %#v err=%v", commands, err)
	}
	pending, err := persistence.ListPendingCommands(goal.ID, sibling.ID)
	if err != nil || len(pending) != 1 || pending[0].WorkerID != sibling.ID {
		t.Fatalf("sibling command was consumed: %#v err=%v", pending, err)
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

func TestStorePersistsIdeasWorkspacesMemoriesAndArtifacts(t *testing.T) {
	persistence, err := New(t.TempDir() + "/state/cicada.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()

	machine, err := persistence.UpsertMachine("worker-local", "Worker", nil, "available")
	if err != nil {
		t.Fatal(err)
	}
	goal, err := persistence.CreateGoalWithDetails("goal_objects", "ship feature", "tests pass", "", 60,
		"2030-01-01T00:00:00Z", map[string]any{"tokens": 1000}, map[string]any{"gpu": "H100"},
		machine.ID, "monitor_objects", "/workspace/goals/goal_objects")
	if err != nil {
		t.Fatal(err)
	}
	if goal.Deadline == "" || goal.Budget["tokens"] != float64(1000) || goal.Resources["gpu"] != "H100" {
		t.Fatalf("goal details were not decoded: %#v", goal)
	}

	workspace, err := persistence.CreateWorkspace("workspace_objects", goal.ID, goal.Workspace, "git", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Status != "active" || workspace.Revision != "abc123" {
		t.Fatalf("unexpected workspace: %#v", workspace)
	}

	idea, err := persistence.CreateIdea(Idea{Title: "Try feature", Description: "Explore a feature", Status: "parked", RevisitWhen: "after release"})
	if err != nil {
		t.Fatal(err)
	}
	if idea.Status != "parked" {
		t.Fatalf("unexpected idea: %#v", idea)
	}
	if _, err := persistence.UpdateIdea(idea.ID, "started", "worth doing", idea.RevisitWhen, goal.ID); err != nil {
		t.Fatal(err)
	}
	updatedIdea, err := persistence.GetIdea(idea.ID)
	if err != nil || updatedIdea.GoalID != goal.ID || updatedIdea.Status != "started" {
		t.Fatalf("idea was not linked to goal: %#v err=%v", updatedIdea, err)
	}

	memory, err := persistence.CreateMemory(Memory{Scope: "project", Namespace: goal.ID, Content: "Use a deterministic benchmark", Importance: 90})
	if err != nil {
		t.Fatal(err)
	}
	memories, err := persistence.ListMemories("project", goal.ID)
	if err != nil || len(memories) != 1 || memories[0].ID != memory.ID {
		t.Fatalf("memory was not listed: %#v err=%v", memories, err)
	}

	artifact, err := persistence.CreateArtifact(Artifact{GoalID: goal.ID, WorkspaceID: workspace.ID, Name: "report", Path: "report.md", Kind: "evidence", Evidence: "benchmark output"})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := persistence.ListArtifacts(goal.ID)
	if err != nil || len(artifacts) != 1 || artifacts[0].ID != artifact.ID {
		t.Fatalf("artifact was not listed: %#v err=%v", artifacts, err)
	}
}

func TestStorePersistsContactSequencesAndOpaquePeerMessages(t *testing.T) {
	persistence, err := New(t.TempDir() + "/state/cicada.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	contact, err := persistence.CreateContact(Contact{Label: "peer", Identity: identity.Public()})
	if err != nil {
		t.Fatal(err)
	}
	updatedContact, err := persistence.UpdateContact(contact.ID, "revoked peer", "revoked")
	if err != nil || updatedContact.Status != "revoked" || updatedContact.Label != "revoked peer" {
		t.Fatalf("contact was not updated: %#v err=%v", updatedContact, err)
	}
	if sequence, err := persistence.AllocateContactSequence(contact.ID); err != nil || sequence != 1 {
		t.Fatalf("unexpected first outbound sequence: %d err=%v", sequence, err)
	}
	if sequence, err := persistence.AllocateContactSequence(contact.ID); err != nil || sequence != 2 {
		t.Fatalf("unexpected second outbound sequence: %d err=%v", sequence, err)
	}
	if err := persistence.AcceptContactSequence(contact.ID, 5); err != nil {
		t.Fatal(err)
	}
	if err := persistence.AcceptContactSequence(contact.ID, 5); err != ErrPeerReplay {
		t.Fatalf("expected persistent replay rejection, got %v", err)
	}
	message, err := persistence.CreatePeerMessage(PeerMessage{
		ContactID: contact.ID, Direction: "outbound", SenderID: "local", RecipientID: identity.Public().ID,
		Sequence: 1, Envelope: json.RawMessage(`{"ciphertext":"opaque"}`), AAD: "Z29hbD1kZW1v",
	})
	if err != nil {
		t.Fatal(err)
	}
	messages, err := persistence.ListPeerMessages(contact.ID)
	if err != nil || len(messages) != 1 || messages[0].ID != message.ID || messages[0].AAD != "Z29hbD1kZW1v" {
		t.Fatalf("peer message was not persisted: %#v err=%v", messages, err)
	}
}

func TestStorePersistsNotificationsAndReadState(t *testing.T) {
	persistence, err := New(t.TempDir() + "/state/cicada.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	notification, err := persistence.CreateNotification(Notification{Kind: "approval.requested", Priority: "P1", Title: "Approve", Body: "Choose a path"})
	if err != nil {
		t.Fatal(err)
	}
	unread, err := persistence.ListNotifications(true)
	if err != nil || len(unread) != 1 || unread[0].ID != notification.ID {
		t.Fatalf("unexpected unread notifications: %#v err=%v", unread, err)
	}
	read, err := persistence.MarkNotificationRead(notification.ID)
	if err != nil || read.Status != "read" || read.ReadAt == "" {
		t.Fatalf("notification was not marked read: %#v err=%v", read, err)
	}
	unread, err = persistence.ListNotifications(true)
	if err != nil || len(unread) != 0 {
		t.Fatalf("read notification remained unread: %#v err=%v", unread, err)
	}
}

func TestStorePersistsAndResolvesPermissions(t *testing.T) {
	persistence, err := New(t.TempDir() + "/state/cicada.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()

	permission, err := persistence.UpsertPermission(Permission{
		SubjectType: "contact", SubjectID: "contact_alice", Action: "peer.message",
		Resource: "", Effect: "deny",
	})
	if err != nil {
		t.Fatal(err)
	}
	if permission.ID == "" || permission.Effect != "deny" {
		t.Fatalf("unexpected permission: %#v", permission)
	}
	resolved, err := persistence.LookupPermission("contact", "contact_alice", "peer.message", "")
	if err != nil || resolved == nil || resolved.ID != permission.ID {
		t.Fatalf("permission was not resolved: %#v err=%v", resolved, err)
	}
	if _, err := persistence.UpsertPermission(Permission{
		SubjectType: "contact", SubjectID: "contact_alice", Action: "peer.message",
		Effect: "allow",
	}); err != nil {
		t.Fatal(err)
	}
	resolved, err = persistence.LookupPermission("contact", "contact_alice", "peer.message", "")
	if err != nil || resolved == nil || resolved.Effect != "allow" || resolved.ID != permission.ID {
		t.Fatalf("permission was not updated: %#v err=%v", resolved, err)
	}
	global, err := persistence.UpsertPermission(Permission{
		SubjectType: "global", SubjectID: "*", Action: "peer.message", Effect: "approval",
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err = persistence.LookupPermission("contact", "contact_bob", "peer.message", "")
	if err != nil || resolved == nil || resolved.ID != global.ID || resolved.Effect != "approval" {
		t.Fatalf("global permission was not resolved: %#v err=%v", resolved, err)
	}
	permissions, err := persistence.ListPermissions("", "")
	if err != nil || len(permissions) != 2 || global.ID == "" {
		t.Fatalf("unexpected permissions: %#v err=%v", permissions, err)
	}
	deleted, err := persistence.DeletePermission(global.ID)
	if err != nil || !deleted {
		t.Fatalf("permission was not deleted: %v", err)
	}
}
