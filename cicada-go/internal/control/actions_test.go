package control

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func newActionFixture(t *testing.T) (*Control, string, string) {
	t.Helper()
	root := t.TempDir()
	controlPlane, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controlPlane.Shutdown(context.Background()) })
	machine, err := controlPlane.store.UpsertMachine("machine-actions", "actions", nil, "available")
	if err != nil {
		t.Fatal(err)
	}
	goalID, monitorID := store.NewID("goal"), store.NewID("monitor")
	workspace := filepath.Join(root, "workspace", goalID)
	if _, err := controlPlane.store.CreateGoal(goalID, "external action test", "durable action", "", 50, machine.ID, monitorID, workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.store.CreateMonitor(monitorID, goalID, "supervise"); err != nil {
		t.Fatal(err)
	}
	worker, err := controlPlane.store.CreateWorker(store.NewID("worker"), goalID, machine.ID, filepath.Join(workspace, "result"))
	if err != nil {
		t.Fatal(err)
	}
	return controlPlane, goalID, worker.ID
}

func TestExternalActionApprovalAndExecutorLifecycle(t *testing.T) {
	controlPlane, goalID, workerID := newActionFixture(t)
	action, err := controlPlane.RequestExternalAction(ExternalActionInput{
		GoalID: goalID, WorkerID: workerID, Kind: "form_fill", Method: "POST",
		URL: "https://example.com/form", Payload: []byte(`{"field":"value"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if action.Status != "pending_approval" || action.ApprovalID == "" {
		t.Fatalf("destructive action bypassed approval: %#v", action)
	}
	approvals, err := controlPlane.Approvals(true)
	if err != nil || len(approvals) != 1 {
		t.Fatalf("approval was not durable: %#v err=%v", approvals, err)
	}
	if _, err := controlPlane.ResolveApproval(approvals[0].ID, "approve"); err != nil {
		t.Fatal(err)
	}
	action, err = controlPlane.ExternalAction(action.ID)
	if err != nil || action.Status != "queued" {
		t.Fatalf("approval did not queue action: %#v err=%v", action, err)
	}
	action, err = controlPlane.ClaimExternalAction(action.ID)
	if err != nil || action.Status != "running" {
		t.Fatalf("action was not claimable: %#v err=%v", action, err)
	}
	action, err = controlPlane.CompleteExternalAction(action.ID, []byte(`{"status":"ok"}`), "")
	if err != nil || action.Status != "completed" {
		t.Fatalf("action did not complete: %#v err=%v", action, err)
	}
	events, err := controlPlane.Events(goalID, 0)
	if err != nil {
		t.Fatal(err)
	}
	types := eventTypes(events)
	for _, eventType := range []string{"ExternalActionRequested", "ExternalActionApproved", "ExternalActionClaimed", "ExternalActionCompleted"} {
		if !types[eventType] {
			t.Errorf("missing action audit event %q: %#v", eventType, events)
		}
	}
}

func TestExternalActionRejectsSecretsAndPrivateTargets(t *testing.T) {
	controlPlane, goalID, workerID := newActionFixture(t)
	if _, err := controlPlane.RequestExternalAction(ExternalActionInput{
		GoalID: goalID, WorkerID: workerID, Kind: "fetch", URL: "http://127.0.0.1:8080/health",
	}); err == nil {
		t.Fatal("private target was accepted")
	}
	if _, err := controlPlane.RequestExternalAction(ExternalActionInput{
		GoalID: goalID, WorkerID: workerID, Kind: "fetch", URL: "https://example.com",
		Payload: []byte(`{"api_token":"should-not-persist"}`),
	}); err == nil {
		t.Fatal("credential-like payload was accepted")
	}
	if _, err := controlPlane.SetPermission(PermissionInput{
		SubjectType: "goal", SubjectID: goalID, Action: "external.fetch",
		Resource: "example.com", Effect: "deny",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := controlPlane.RequestExternalAction(ExternalActionInput{
		GoalID: goalID, WorkerID: workerID, Kind: "fetch", URL: "https://example.com",
	})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("goal domain deny was not enforced: %v", err)
	}
}
