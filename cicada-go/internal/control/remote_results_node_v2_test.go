package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestBoundNodeResultRevocationDuringVerificationDiscardsResultAndRecoversAttempt(t *testing.T) {
	c, ownerID, _ := newNodeBindingControl(t)
	nodeToken, credentialDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	const nodeID = "node-result-fence"
	challenge, err := c.StartNodeDeviceBinding(nodeID, "Result fence Node", credentialDigest)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := c.ConfirmNodeDeviceCode(ownerID, "android", challenge.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.RecordBoundNodeMachineHeartbeat(credentialDigest, "available",
		map[string]any{"harnesses": []string{"codex"}}); err != nil {
		t.Fatal(err)
	}
	goal, err := c.CreateGoalForOwner(ownerID, GoalInput{
		Objective:       "keep a revoked Node result from being committed",
		SuccessCriteria: "the result is verified only while the current Node binding is active",
		MachineID:       nodeID, Harness: "codex",
		Resources: map[string]any{"completion_verifier": "model"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := c.ClaimBoundNodeRemoteWorker(credentialDigest, nodeID, goal.Worker.ID)
	if err != nil || claimed.Attempt != 1 {
		t.Fatalf("claim bound Node Worker: job=%#v err=%v", claimed, err)
	}

	root := t.TempDir()
	enteredPath := filepath.Join(root, "entered")
	releasePath := filepath.Join(root, "release")
	verifier := filepath.Join(root, "verifier")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
output=''
previous=''
for argument in "$@"; do
  if [ "$previous" = '--output-last-message' ]; then output="$argument"; fi
  previous="$argument"
done
touch '%s'
while [ ! -f '%s' ]; do sleep 0.01; done
printf '%%s' '{"decision":"accept","confidence":0.99,"rationale":"verified","correction":""}' > "$output"
`, enteredPath, releasePath)
	if err := os.WriteFile(verifier, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	c.config.CompletionVerifierBin = verifier
	c.config.CompletionVerifierTime = 10 * time.Second

	type result struct {
		worker *store.Worker
		err    error
	}
	resultCh := make(chan result, 1)
	go func() {
		worker, completeErr := c.CompleteBoundNodeRemoteWorker(credentialDigest, nodeID, goal.Worker.ID,
			claimed.Attempt, "completed", "completion data from the Node", "thread-node", "", "")
		resultCh <- result{worker: worker, err: completeErr}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(enteredPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("completion verifier did not reach the revocation barrier")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := c.RevokeNodeDeviceBinding(ownerID, binding.ID, binding.Version); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(releasePath, []byte("continue"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case completed := <-resultCh:
		if completed.worker != nil || !errors.Is(completed.err, store.ErrNodeWorkerNotAuthorized) {
			t.Fatalf("revoked result was committed: worker=%#v err=%v", completed.worker, completed.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Node result did not finish after verifier release")
	}

	worker, err := c.store.GetWorker(goal.Worker.ID)
	if err != nil || worker == nil || worker.Status != "recovering" || worker.Attempt != claimed.Attempt ||
		worker.Summary != "" || worker.ThreadID != "" || !strings.Contains(worker.LastError, "result discarded") {
		t.Fatalf("revoked result did not leave a safely recoverable attempt: worker=%#v err=%v", worker, err)
	}
	events, err := c.Events(goal.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	types := eventTypes(events)
	if !types["WorkerResultDiscarded"] || types["WorkerCompletionVerified"] || types["WorkerCompleted"] || types["ArtifactProduced"] {
		t.Fatalf("revoked result emitted completion side effects: events=%v", types)
	}
	if _, err := c.Fabric().AuthenticateNode(nodeToken); !errors.Is(err, fabricpkg.ErrUnauthenticated) {
		t.Fatalf("revoked Node token remained active: %v", err)
	}
}

func TestExplicitModelVerifierOutageFailsBoundNodeResultWithoutReclaim(t *testing.T) {
	c, ownerID, _ := newNodeBindingControl(t)
	_, credentialDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	const nodeID = "node-required-verifier"
	challenge, err := c.StartNodeDeviceBinding(nodeID, "Required verifier Node", credentialDigest)
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
		Objective: "retain a bound Node result when required verification is unavailable",
		MachineID: nodeID, Harness: "codex",
		Resources: map[string]any{"completion_verifier": "model"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := c.ClaimBoundNodeRemoteWorker(credentialDigest, nodeID, goal.Worker.ID)
	if err != nil {
		t.Fatal(err)
	}
	const candidate = "bound result retained for manager review"
	worker, err := c.CompleteBoundNodeRemoteWorker(credentialDigest, nodeID, goal.Worker.ID,
		claimed.Attempt, "completed", candidate, "thread-required-verifier", "", "")
	if err != nil || worker == nil || worker.Status != "failed" || worker.Summary != candidate {
		t.Fatalf("bound Node verifier outage did not retain a failed result: worker=%#v err=%v", worker, err)
	}
	if _, err := c.ClaimBoundNodeRemoteWorker(credentialDigest, nodeID, goal.Worker.ID); err == nil {
		t.Fatal("bound Node Worker was made claimable after verifier outage")
	}
	currentGoal, err := c.Goal(goal.ID)
	if err != nil || currentGoal == nil || currentGoal.Status != "failed" {
		t.Fatalf("bound Node Goal did not fail closed: goal=%#v err=%v", currentGoal, err)
	}
}
