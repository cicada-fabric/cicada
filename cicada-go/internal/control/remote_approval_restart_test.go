package control

import (
	"encoding/json"
	"testing"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestHubStartHoldsAcceptedRemoteApprovalAndCancelsOldPending(t *testing.T) {
	c, ownerID, _ := newNodeBindingControl(t)
	_, credentialDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	const nodeID = "node-restart-approval"
	challenge, err := c.StartNodeDeviceBinding(nodeID, "Restart approval Node", credentialDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ConfirmNodeDeviceCode(ownerID, "android", challenge.UserCode); err != nil {
		t.Fatal(err)
	}
	if err := c.store.RecordBoundNodeMachineHeartbeat(credentialDigest, "available",
		map[string]any{"harnesses": []string{"codex"}}); err != nil {
		t.Fatal(err)
	}
	goal, err := c.CreateGoalForOwner(ownerID, GoalInput{
		Objective: "Preserve accepted approval after Hub restart", SuccessCriteria: "Reconcile original Node result",
		MachineID: nodeID, Harness: "codex",
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := c.ClaimBoundNodeRemoteWorker(credentialDigest, nodeID, goal.Worker.ID)
	if err != nil || claimed.Attempt != 1 {
		t.Fatalf("claim Worker: job=%#v err=%v", claimed, err)
	}
	accepted, _, err := c.store.CreateBoundNodeApproval(credentialDigest, nodeID, goal.Worker.ID, 1,
		"native-accepted", store.NodeApprovalCommandExecution, json.RawMessage(`{"command":["true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.ResolveApproval(accepted.ID, "accept"); err != nil {
		t.Fatal(err)
	}
	pending, _, err := c.store.CreateBoundNodeApproval(credentialDigest, nodeID, goal.Worker.ID, 1,
		"native-pending", store.NodeApprovalFileChange, json.RawMessage(`{"grantRoot":"/tmp"}`))
	if err != nil {
		t.Fatal(err)
	}
	c.config.MonitorInterval = time.Hour
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	worker, err := c.store.GetWorker(goal.Worker.ID)
	if err != nil || worker == nil || worker.Status != store.RemoteWorkerOutcomeUncertain || worker.Attempt != 1 {
		t.Fatalf("Hub restart replayed an approved Worker: worker=%#v err=%v", worker, err)
	}
	oldPending, err := c.store.GetApproval(pending.ID)
	if err != nil || oldPending == nil || oldPending.Status != "cancelled" {
		t.Fatalf("Hub restart left an old native RPC pending: approval=%#v err=%v", oldPending, err)
	}
	jobs, err := c.BoundNodeMachineJobs(credentialDigest, nodeID)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("Hub offered uncertain Worker for a second claim: jobs=%#v err=%v", jobs, err)
	}
	events, err := c.Events(goal.ID, 0)
	if err != nil || !eventTypes(events)["WorkerOutcomeUncertain"] {
		t.Fatalf("Hub omitted uncertainty event: events=%#v err=%v", events, err)
	}
	completed, err := c.CompleteBoundNodeRemoteWorker(credentialDigest, nodeID, goal.Worker.ID, 1,
		"completed", "Original Node reconciled its completed native turn", "thread-original", "", "")
	if err != nil || completed == nil || completed.Status != "completed" || completed.Attempt != 1 {
		t.Fatalf("same-attempt late result did not reconcile: worker=%#v err=%v", completed, err)
	}
	if _, err := c.CompleteBoundNodeRemoteWorker(credentialDigest, nodeID, goal.Worker.ID, 1,
		"completed", "duplicate", "thread-original", "", ""); err == nil {
		t.Fatal("duplicate original Node result was admitted twice")
	}
}
