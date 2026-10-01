package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestMachineAgentBinaryRemoteApprovalEndToEnd runs the built cicada binary
// against a real in-process Hub HTTP handler. Its app-server executable is a
// protocol fake: this covers the remote Node/Hub/Client boundary, not native
// Codex runtime behavior.
func TestMachineAgentBinaryRemoteApprovalEndToEnd(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "hub-state")
	const (
		apiToken = "synthetic-machine-agent-test-control-token"
		nodeID   = "node-binary-approval"
	)
	controlPlane, err := control.New(control.Config{
		StateDir: stateDir, WorkspaceRoot: filepath.Join(root, "hub-workspace"), APIToken: apiToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := controlPlane.Shutdown(ctx); err != nil {
			t.Errorf("shutdown Control: %v", err)
		}
	})

	hub := httptest.NewServer(NewHandler(controlPlane))
	t.Cleanup(hub.Close)
	httpClient := hub.Client()

	identityStatus, identityBody := clientNodeChainHTTP(t, httpClient, hub.URL,
		http.MethodGet, "/v2/client/identity", nil, "")
	if identityStatus != http.StatusOK {
		t.Fatalf("Client identity status=%d body=%s", identityStatus, identityBody)
	}
	var hubIdentity struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if err := json.Unmarshal(identityBody, &hubIdentity); err != nil || hubIdentity.HubID == "" {
		t.Fatalf("decode Client identity: err=%v body=%s", err, identityBody)
	}

	ownerID := controlPlane.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.CreateGroup(control.GroupCreateInput{Name: "Machine agent approval integration"}); err != nil {
		t.Fatal(err)
	}
	registry, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		_ = registry.Close()
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "phone-machine-agent-test", deviceKey.Public(),
		hubIdentity.HubID, e2ee.OwnerDevicePurposeControl,
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "phone-machine-agent-test", "device_public_identity": deviceKey.Public(),
		"owner_device_grant": grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollStatus, enrollBody := clientNodeChainHTTP(t, httpClient, hub.URL,
		http.MethodPost, "/v2/client/devices/enroll", enrollment, "")
	if enrollStatus != http.StatusCreated {
		t.Fatalf("Client device enrollment status=%d body=%s", enrollStatus, enrollBody)
	}

	binding := clientwire.Binding{
		HubID: hubIdentity.HubID, OwnerID: ownerID, DeviceID: "phone-machine-agent-test",
		SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1,
	}
	var sequence uint64
	callClientRPC := func(operation string, body []byte) json.RawMessage {
		t.Helper()
		sequence++
		route := clientwire.Route{
			Version: clientwire.Version, Direction: clientwire.DirectionRequest,
			HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
			SessionEpoch: binding.SessionEpoch, Sequence: sequence,
			OperationID: fmt.Sprintf("machine-agent-approval-%s-%d", operation, sequence),
			Operation:   operation, SenderKeyID: deviceKey.Public().ID, SenderKeyVersion: binding.DeviceKeyVersion,
			ReceiverKeyID: hubIdentity.ControlPublicIdentity.ID, ReceiverKeyVersion: binding.HubKeyVersion,
		}
		packet, err := clientwire.SealRequest(deviceKey, hubIdentity.ControlPublicIdentity, binding, route, body)
		if err != nil {
			t.Fatal(err)
		}
		status, responseBody := clientNodeChainHTTP(t, httpClient, hub.URL,
			http.MethodPost, "/v2/client/rpc", packet, "")
		if status != http.StatusOK {
			t.Fatalf("encrypted Client RPC %s status=%d body=%s", operation, status, responseBody)
		}
		opened, err := clientwire.OpenResponse(deviceKey, hubIdentity.ControlPublicIdentity, binding, responseBody)
		if err != nil {
			t.Fatalf("open encrypted Client RPC %s response: %v", operation, err)
		}
		var envelope struct {
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if err := json.Unmarshal(opened.Plaintext, &envelope); err != nil || !envelope.OK {
			t.Fatalf("Client RPC %s failed: decode=%v envelope=%s", operation, err, opened.Plaintext)
		}
		return envelope.Result
	}

	nodeStateDir := filepath.Join(root, "node-state")
	nodeHome := filepath.Join(root, "node-home")
	nodeWorkspaceRoot := filepath.Join(root, "node-workspaces")
	if err := os.MkdirAll(nodeStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nodeHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nodeWorkspaceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "cicada")
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration test source path")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	buildCtx, cancelBuild := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancelBuild()
	build := exec.CommandContext(buildCtx, "go", "build", "-buildvcs=false", "-o", binary, "./cmd/cicada")
	build.Dir = moduleRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cicada machine agent binary: %v\n%s", err, output)
	}

	runAgentOnce := func() ([]byte, error) {
		pairCtx, cancelPair := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancelPair()
		pairAgent := exec.CommandContext(pairCtx, binary, "machine", "agent", "--id", nodeID,
			"--name", "Binary approval integration", "--control-url", hub.URL,
			"--state-dir", nodeStateDir, "--interval", "1s", "--once")
		pairAgent.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + nodeHome,
			// Capability discovery only checks that the configured Codex executable
			// exists. This --once process only installs the binding and heartbeat;
			// the separate worker process below receives the actual fixture wrapper.
			"CICADA_CODEX_BIN=" + binary, "CICADA_WORKSPACE_ROOT=" + nodeWorkspaceRoot,
			"CICADA_NODE_RESOURCE_ID=gpu/0"}
		return pairAgent.CombinedOutput()
	}
	// Let the production Agent create its local bearer and PQ signing/KEM key,
	// submit its proof-of-possession candidate, and print the comparison code.
	// This first --once invocation must stop at the explicit Owner gate.
	pairOutput, pairErr := runAgentOnce()
	pairOutputText := string(pairOutput)
	if pairErr == nil || !strings.Contains(pairOutputText, "waiting for explicit Owner approval") {
		t.Fatalf("production Node did not stop at the explicit PQ pairing gate: err=%v output=%s", pairErr, pairOutputText)
	}
	codeMatch := regexp.MustCompile(`Device code: ([A-Z0-9-]{14}) \(valid for `).FindStringSubmatch(pairOutputText)
	if len(codeMatch) != 2 {
		t.Fatalf("production Node did not print its Owner comparison code: output=%s", pairOutputText)
	}
	previewRequest, err := json.Marshal(map[string]string{"user_code": codeMatch[1]})
	if err != nil {
		t.Fatal(err)
	}
	var candidate store.NodeControlKeyCandidate
	if err := json.Unmarshal(callClientRPC("nodes.preview", previewRequest), &candidate); err != nil ||
		candidate.RequestID == "" || candidate.NodeID != nodeID || candidate.Version <= 0 ||
		candidate.CandidateDigest == "" || candidate.NodeKeyFingerprint == "" || candidate.HubNodeControlFingerprint == "" {
		t.Fatalf("encrypted Owner preview did not show the exact production Node candidate: candidate=%#v err=%v", candidate, err)
	}
	if !strings.Contains(pairOutputText, "Node key "+candidate.NodeKeyID+" ("+candidate.NodeKeyFingerprint+")") ||
		!strings.Contains(pairOutputText, "Hub Node-Control key "+candidate.HubNodeControlKeyID+" ("+candidate.HubNodeControlFingerprint+")") {
		t.Fatalf("Owner preview evidence does not match the Node's displayed key fingerprints: candidate=%#v", candidate)
	}
	confirmRequest, err := json.Marshal(map[string]any{"user_code": codeMatch[1],
		"candidate_digest": candidate.CandidateDigest, "candidate_version": candidate.Version})
	if err != nil {
		t.Fatal(err)
	}
	var nodeBinding store.NodeControlKeyBinding
	if err := json.Unmarshal(callClientRPC("nodes.confirm", confirmRequest), &nodeBinding); err != nil ||
		nodeBinding.NodeID != nodeID || nodeBinding.State != store.NodeControlKeyActive ||
		nodeBinding.NodeKeyFingerprint != candidate.NodeKeyFingerprint ||
		nodeBinding.HubKeyFingerprint != candidate.HubNodeControlFingerprint ||
		nodeBinding.ApprovedCandidateDigest != candidate.CandidateDigest {
		t.Fatalf("encrypted Client did not confirm the exact Node-Control key candidate: binding=%#v err=%v", nodeBinding, err)
	}
	activationOutput, activationErr := runAgentOnce()
	if activationErr != nil {
		t.Fatalf("production Node did not install its Owner-approved key and publish its sealed heartbeat: err=%v output=%s", activationErr, activationOutput)
	}

	intentBody := []byte(`{"text":"Run the approval protocol fixture for this Node","kind":"goal","goal":{"objective":"Run the approval protocol fixture for this Node","success_criteria":"Return the fake app-server completion summary","constraints":"Do not modify files or contact external services","machine_id":"node-binary-approval","harness":"codex","resources":{"physical_resource_id":"gpu/0"}}}`)
	var accepted struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(callClientRPC("intent.submit", intentBody), &accepted); err != nil || accepted.ID == "" {
		t.Fatalf("encrypted Client intent submission failed: intent=%#v err=%v", accepted, err)
	}
	var progress *control.ClientIntentProgress
	intentDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(intentDeadline) {
		progress, err = controlPlane.ClientIntentStatus(ownerID, accepted.ID)
		if err != nil {
			t.Fatal(err)
		}
		if progress.Job.State == store.ClientIntentDone && progress.Intent.Status == "resolved" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if progress == nil || progress.Job.State != store.ClientIntentDone || progress.Intent.Status != "resolved" {
		if progress == nil {
			t.Fatal("Client intent status was unavailable")
		}
		t.Fatalf("Client intent did not resolve: job=%+v intent=%+v", progress.Job, progress.Intent)
	}
	var intentResult struct {
		GoalID string `json:"goal_id"`
	}
	if err := json.Unmarshal(progress.Intent.Result, &intentResult); err != nil || intentResult.GoalID == "" {
		t.Fatalf("Client intent did not produce a Goal: result=%s err=%v", progress.Intent.Result, err)
	}
	goal, err := controlPlane.Goal(intentResult.GoalID)
	if err != nil || goal == nil || goal.Worker == nil || goal.Worker.Status != "queued" || goal.MachineID != nodeID {
		t.Fatalf("Hub did not queue the owner-bound Node Worker: goal=%#v err=%v", goal, err)
	}
	workspaces, err := controlPlane.Workspaces(goal.ID)
	if err != nil || len(workspaces) != 1 {
		t.Fatalf("Goal workspace was not created: workspaces=%#v err=%v", workspaces, err)
	}
	if _, err := controlPlane.SnapshotWorkspace(workspaces[0].ID); err != nil {
		t.Fatalf("seed Workspace snapshot for the Node binary: %v", err)
	}

	codexBin := filepath.Join(root, "fake-codex")
	approvalCapture := filepath.Join(root, "app-server-approval-reply.json")
	fakeAppServer := `#!/bin/sh
set -eu
test "$1" = app-server
test "$2" = --stdio
test "$3" = --disable
test "$4" = plugins
test -z "${CICADA_API_TOKEN:-}"
test -z "${CICADA_API_TOKEN_FILE:-}"
test -z "${CICADA_NODE_TOKEN:-}"
test -z "${CICADA_NODE_TOKEN_FILE:-}"
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*) printf '%s\n' '{"id":1,"result":{}}' ;;
    *'"method":"thread/start"'*) printf '%s\n' '{"id":2,"result":{"thread":{"id":"fake-native-thread"}}}' ;;
    *'"method":"turn/start"'*)
      printf '%s\n' '{"id":3,"result":{"turn":{"id":"fake-native-turn","status":"inProgress"}}}'
      printf '%s\n' '{"id":77,"method":"item/commandExecution/requestApproval","params":{"threadId":"fake-native-thread","turnId":"fake-native-turn","itemId":"fake-native-item","availableDecisions":["accept","decline"],"command":"echo fake approval integration"}}'
      ;;
    *'"id":77'*)
      printf '%s\n' "$line" > "$CICADA_TEST_APPROVAL_CAPTURE"
      case "$line" in
        *'"decision":"accept"'*)
          printf '%s\n' '{"method":"turn/completed","params":{"turn":{"status":"completed"},"item":{"type":"agentMessage","text":"FAKE_APP_SERVER_APPROVAL_COMPLETE"}}}'
          ;;
        *)
          printf '%s\n' '{"method":"turn/completed","params":{"turn":{"status":"failed"}}}'
          ;;
      esac
      ;;
  esac
done
`
	if err := os.WriteFile(codexBin, []byte(fakeAppServer), 0o700); err != nil {
		t.Fatal(err)
	}
	processCtx, cancelProcess := context.WithTimeout(context.Background(), 35*time.Second)
	agent := exec.CommandContext(processCtx, binary, "machine", "agent", "--id", nodeID,
		"--name", "Binary approval integration", "--control-url", hub.URL,
		"--state-dir", nodeStateDir, "--interval", "1s", "--once")
	pathEnv := os.Getenv("PATH")
	agent.Env = []string{
		"PATH=" + pathEnv, "HOME=" + nodeHome,
		"CICADA_CODEX_BIN=" + codexBin, "CICADA_CODEX_MODEL=fake-model",
		"CICADA_NODE_RESOURCE_ID=gpu/0",
		"CICADA_TEST_APPROVAL_CAPTURE=" + approvalCapture,
		"CICADA_WORKSPACE_ROOT=" + nodeWorkspaceRoot,
		"CICADA_WORKER_TIMEOUT_SECONDS=25",
	}
	var agentStdout, agentStderr bytes.Buffer
	agent.Stdout, agent.Stderr = &agentStdout, &agentStderr
	if err := agent.Start(); err != nil {
		cancelProcess()
		t.Fatalf("start cicada machine agent binary: %v", err)
	}
	processDone := make(chan error, 1)
	processFinished := make(chan struct{})
	go func() {
		processDone <- agent.Wait()
		close(processFinished)
	}()
	t.Cleanup(func() {
		cancelProcess()
		select {
		case <-processFinished:
		case <-time.After(5 * time.Second):
			t.Errorf("machine agent process did not stop after test cleanup")
		}
	})

	var approvals []store.Approval
	approvalDeadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(approvalDeadline) {
		select {
		case processErr := <-processDone:
			finishedGoal, goalErr := controlPlane.Goal(goal.ID)
			var status, lastError string
			if finishedGoal != nil && finishedGoal.Worker != nil {
				status, lastError = finishedGoal.Worker.Status, finishedGoal.Worker.LastError
			}
			t.Fatalf("machine agent exited before the Client approval was observed: err=%v worker_status=%s worker_error=%q goalErr=%v stdout=%s stderr=%s",
				processErr, status, lastError, goalErr, agentStdout.String(), agentStderr.String())
		default:
		}
		listBody, err := json.Marshal(map[string]bool{"pending_only": true})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(callClientRPC("approvals.list", listBody), &approvals); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, item := range approvals {
			if item.GoalID == goal.ID && item.Method == store.NodeApprovalCommandExecution && item.Status == "pending" {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var pending *store.Approval
	for index := range approvals {
		if approvals[index].GoalID == goal.ID && approvals[index].Method == store.NodeApprovalCommandExecution &&
			approvals[index].Status == "pending" {
			pending = &approvals[index]
			break
		}
	}
	if pending == nil || pending.Attempt != 1 || !strings.Contains(string(pending.Request), "fake approval integration") {
		failedGoal, goalErr := controlPlane.Goal(goal.ID)
		var workerStatus, workerError string
		if failedGoal != nil && failedGoal.Worker != nil {
			workerStatus, workerError = failedGoal.Worker.Status, failedGoal.Worker.LastError
		}
		t.Fatalf("encrypted Client approvals.list did not expose the live fake app-server request: approvals=%#v worker_status=%s worker_error=%q goalErr=%v stdout=%s stderr=%s",
			approvals, workerStatus, workerError, goalErr, agentStdout.String(), agentStderr.String())
	}
	goal, err = controlPlane.Goal(goal.ID)
	if err != nil || goal == nil || goal.Worker == nil || goal.Worker.Status != "running" || goal.Worker.Attempt != 1 {
		t.Fatalf("approval did not remain attached to the binary's running Worker attempt: goal=%#v err=%v stdout=%s stderr=%s",
			goal, err, agentStdout.String(), agentStderr.String())
	}
	decisionRequest, err := json.Marshal(map[string]string{"approval_id": pending.ID, "decision": "accept"})
	if err != nil {
		t.Fatal(err)
	}
	var decided store.Approval
	if err := json.Unmarshal(callClientRPC("approvals.decide", decisionRequest), &decided); err != nil ||
		decided.ID != pending.ID || decided.Status != "resolved" || decided.Decision != "accept" {
		currentApproval, _ := controlPlane.ClientApproval(ownerID, pending.ID)
		currentGoal, _ := controlPlane.Goal(goal.ID)
		t.Fatalf("encrypted Client approval decision failed: approval=%#v current=%#v worker=%#v err=%v",
			decided, currentApproval, currentGoal.Worker, err)
	}

	select {
	case processErr := <-processDone:
		if processErr != nil {
			t.Fatalf("cicada machine agent failed: %v stdout=%s stderr=%s", processErr,
				agentStdout.String(), agentStderr.String())
		}
	case <-processCtx.Done():
		t.Fatalf("cicada machine agent did not finish after approval: stdout=%s stderr=%s",
			agentStdout.String(), agentStderr.String())
	}
	cancelProcess()

	approvalReply, err := os.ReadFile(approvalCapture)
	if err != nil || !bytes.Contains(approvalReply, []byte(`"id":77`)) ||
		!bytes.Contains(approvalReply, []byte(`"decision":"accept"`)) {
		currentGoal, goalErr := controlPlane.Goal(goal.ID)
		t.Fatalf("fake app-server did not receive the original approval request ID and Client decision: %s err=%v worker=%#v goalErr=%v stdout=%s stderr=%s",
			approvalReply, err, currentGoal.Worker, goalErr, agentStdout.String(), agentStderr.String())
	}

	goalResultRequest, err := json.Marshal(map[string]string{"intent_id": accepted.ID})
	if err != nil {
		t.Fatal(err)
	}
	var goalResult control.ClientGoalResult
	if err := json.Unmarshal(callClientRPC("goal.result", goalResultRequest), &goalResult); err != nil ||
		goalResult.IntentID != accepted.ID || goalResult.GoalID != goal.ID || len(goalResult.Workers) != 1 ||
		goalResult.Workers[0].Status != "completed" ||
		goalResult.Workers[0].Summary != "FAKE_APP_SERVER_APPROVAL_COMPLETE" {
		t.Fatalf("encrypted Client goal.result omitted the actual Node binary result: result=%#v err=%v", goalResult, err)
	}
	finishedGoal, err := controlPlane.Goal(goal.ID)
	if err != nil || finishedGoal == nil || finishedGoal.Worker == nil ||
		finishedGoal.Worker.Status != "completed" ||
		!strings.Contains(finishedGoal.Worker.LastError, "physical resource stop is unverified") ||
		!strings.Contains(finishedGoal.Worker.LastError, "remains quarantined") {
		t.Fatalf("successful business result did not retain its separate resource-stop warning: goal=%#v err=%v",
			finishedGoal, err)
	}
	localControlState := filepath.Join(nodeStateDir, "nodes", "node-"+nodeID, "node-control-state.json")
	controlStateBytes, err := os.ReadFile(localControlState)
	if err != nil {
		t.Fatalf("read durable Node-Control claim fence: %v", err)
	}
	var localControlStateProjection struct {
		ClaimTicket json.RawMessage `json:"claim_ticket"`
	}
	if err := json.Unmarshal(controlStateBytes, &localControlStateProjection); err != nil ||
		len(localControlStateProjection.ClaimTicket) != 0 && string(localControlStateProjection.ClaimTicket) != "null" {
		t.Fatalf("reported Worker result retained the singleton claim ticket and would block other resources: state=%s err=%v",
			controlStateBytes, err)
	}
	resourceManager, err := nodelock.OpenResourceExecutionManager(nodeStateDir)
	if err != nil {
		t.Fatalf("open Node physical-resource state: %v", err)
	}
	resourceRecord, err := resourceManager.Inspect("gpu/0")
	if err != nil || resourceRecord == nil || resourceRecord.State != nodelock.ResourceExecutionQuarantined ||
		resourceRecord.Outcome != "resource_stop_unverified" || resourceRecord.FencingEpoch <= 0 {
		t.Fatalf("unverified stop did not quarantine only its explicit physical resource: record=%#v err=%v",
			resourceRecord, err)
	}

	// The quarantined gpu/0 lease must not consume the single claim slot or
	// prevent an ordinary Worker from running on the same Node.
	secondIntentBody := []byte(`{"text":"Run an ordinary shell Worker after the isolated resource was quarantined","kind":"goal","goal":{"objective":"Print an ordinary sequential Worker result","success_criteria":"Return ORDINARY_SECOND_WORKER","constraints":"Do not modify files or contact external services","machine_id":"node-binary-approval","harness":"shell","resources":{"argv":["/bin/sh","-c","printf ORDINARY_SECOND_WORKER"]}}}`)
	var secondIntent struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(callClientRPC("intent.submit", secondIntentBody), &secondIntent); err != nil || secondIntent.ID == "" {
		t.Fatalf("could not queue the ordinary Worker after physical resource quarantine: intent=%#v err=%v", secondIntent, err)
	}
	var secondProgress *control.ClientIntentProgress
	secondDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(secondDeadline) {
		secondProgress, err = controlPlane.ClientIntentStatus(ownerID, secondIntent.ID)
		if err != nil {
			t.Fatal(err)
		}
		if secondProgress.Job.State == store.ClientIntentDone && secondProgress.Intent.Status == "resolved" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if secondProgress == nil || secondProgress.Job.State != store.ClientIntentDone || secondProgress.Intent.Status != "resolved" {
		t.Fatalf("ordinary second Worker intent did not resolve: progress=%#v", secondProgress)
	}
	var secondAssociation struct {
		GoalID string `json:"goal_id"`
	}
	if err := json.Unmarshal(secondProgress.Intent.Result, &secondAssociation); err != nil || secondAssociation.GoalID == "" {
		t.Fatalf("ordinary second Worker intent lacks its Goal: result=%s err=%v", secondProgress.Intent.Result, err)
	}
	secondAgentOutput, secondAgentErr := runAgentOnce()
	if secondAgentErr != nil {
		t.Fatalf("ordinary second Worker was blocked by the isolated resource lease: err=%v output=%s",
			secondAgentErr, secondAgentOutput)
	}
	secondGoalResultRequest, err := json.Marshal(map[string]string{"intent_id": secondIntent.ID})
	if err != nil {
		t.Fatal(err)
	}
	var secondGoalResult control.ClientGoalResult
	if err := json.Unmarshal(callClientRPC("goal.result", secondGoalResultRequest), &secondGoalResult); err != nil ||
		secondGoalResult.GoalID != secondAssociation.GoalID || len(secondGoalResult.Workers) != 1 ||
		secondGoalResult.Workers[0].Status != "completed" ||
		secondGoalResult.Workers[0].Summary != "ORDINARY_SECOND_WORKER" {
		t.Fatalf("ordinary second Worker did not complete after explicit resource quarantine: result=%#v err=%v",
			secondGoalResult, err)
	}

	// A new authenticated Hub claim for the same physical GPU must stop before
	// provider execution. The failed claim still reports and clears its local
	// singleton ticket, while the durable gpu/0 quarantine remains held.
	blockedMarker := filepath.Join(root, "quarantined-resource-worker-ran")
	blockedIntentBody, err := json.Marshal(map[string]any{
		"text": "A quarantined physical resource must not start a second Worker",
		"kind": "goal",
		"goal": map[string]any{
			"objective":        "Attempt a Worker against the quarantined physical resource",
			"success_criteria": "The Node must refuse before provider execution",
			"constraints":      "Do not contact external services",
			"machine_id":       nodeID, "harness": "shell",
			"resources": map[string]any{
				"physical_resource_id": "gpu/0",
				"argv":                 []string{"/bin/sh", "-c", "printf SHOULD_NOT_RUN > \"$1\"", "sh", blockedMarker},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var blockedIntent struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(callClientRPC("intent.submit", blockedIntentBody), &blockedIntent); err != nil || blockedIntent.ID == "" {
		t.Fatalf("could not queue a Worker for the quarantined physical resource: intent=%#v err=%v",
			blockedIntent, err)
	}
	var blockedProgress *control.ClientIntentProgress
	blockedDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(blockedDeadline) {
		blockedProgress, err = controlPlane.ClientIntentStatus(ownerID, blockedIntent.ID)
		if err != nil {
			t.Fatal(err)
		}
		if blockedProgress.Job != nil && blockedProgress.Job.State == store.ClientIntentDone &&
			blockedProgress.Intent != nil && blockedProgress.Intent.Status == "resolved" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var blockedAssociation struct {
		GoalID string `json:"goal_id"`
	}
	if blockedProgress == nil || blockedProgress.Job == nil || blockedProgress.Job.State != store.ClientIntentDone ||
		blockedProgress.Intent == nil || blockedProgress.Intent.Status != "resolved" ||
		json.Unmarshal(blockedProgress.Intent.Result, &blockedAssociation) != nil ||
		blockedAssociation.GoalID == "" {
		progressJSON, _ := json.Marshal(blockedProgress)
		t.Fatalf("quarantined-resource intent did not receive its Goal: progress=%s", progressJSON)
	}
	blockedAgentOutput, blockedAgentErr := runAgentOnce()
	if blockedAgentErr != nil {
		t.Fatalf("Node agent failed while refusing the quarantined resource claim: err=%v output=%s",
			blockedAgentErr, blockedAgentOutput)
	}
	var blockedGoal *store.Goal
	blockedWorkerDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(blockedWorkerDeadline) {
		blockedGoal, err = controlPlane.Goal(blockedAssociation.GoalID)
		if err != nil {
			t.Fatal(err)
		}
		if blockedGoal != nil && blockedGoal.Worker != nil && blockedGoal.Worker.Status == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if blockedGoal == nil || blockedGoal.Worker == nil || blockedGoal.Worker.Status != "failed" ||
		!strings.Contains(blockedGoal.Worker.LastError, "physical resource is unavailable") {
		t.Fatalf("Node did not report the quarantined physical-resource refusal: goal=%#v", blockedGoal)
	}
	if _, err := os.Stat(blockedMarker); !os.IsNotExist(err) {
		t.Fatalf("provider ran despite the durable gpu/0 quarantine: marker stat err=%v", err)
	}
	controlStateBytes, err = os.ReadFile(localControlState)
	if err != nil {
		t.Fatalf("read Node-Control state after the refused physical claim: %v", err)
	}
	if err := json.Unmarshal(controlStateBytes, &localControlStateProjection); err != nil ||
		len(localControlStateProjection.ClaimTicket) != 0 && string(localControlStateProjection.ClaimTicket) != "null" {
		t.Fatalf("refused physical Worker left the singleton claim ticket occupied: state=%s err=%v",
			controlStateBytes, err)
	}
	resourceRecord, err = resourceManager.Inspect("gpu/0")
	if err != nil || resourceRecord == nil || resourceRecord.State != nodelock.ResourceExecutionQuarantined ||
		resourceRecord.Outcome != "resource_stop_unverified" {
		t.Fatalf("refused claim changed the held physical-resource quarantine: record=%#v err=%v",
			resourceRecord, err)
	}
}
