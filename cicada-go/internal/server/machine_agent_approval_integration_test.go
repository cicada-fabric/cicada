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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
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

	nodeToken, nodeDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	deviceCodeRequest, err := json.Marshal(map[string]string{
		"node_id": nodeID, "node_name": "Binary approval integration", "credential_digest": nodeDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	codeStatus, codeBody := clientNodeChainHTTP(t, httpClient, hub.URL,
		http.MethodPost, "/v2/nodes/device-code", deviceCodeRequest, "")
	var deviceCode control.NodeDeviceCode
	if err := json.Unmarshal(codeBody, &deviceCode); codeStatus != http.StatusCreated || err != nil || deviceCode.UserCode == "" {
		t.Fatalf("Node device-code status=%d code=%#v err=%v body=%s", codeStatus, deviceCode, err, codeBody)
	}
	confirmRequest, err := json.Marshal(map[string]string{"user_code": deviceCode.UserCode})
	if err != nil {
		t.Fatal(err)
	}
	var nodeBinding store.NodeDeviceBinding
	if err := json.Unmarshal(callClientRPC("nodes.confirm", confirmRequest), &nodeBinding); err != nil ||
		nodeBinding.NodeID != nodeID || nodeBinding.State != "ACTIVE" || !nodeBinding.Authorized {
		t.Fatalf("encrypted Client could not bind the synthetic Node credential: binding=%#v err=%v", nodeBinding, err)
	}
	heartbeatStatus, heartbeatBody := clientNodeChainHTTP(t, httpClient, hub.URL, http.MethodPost,
		"/v2/relay/nodes/"+nodeID+"/heartbeat",
		[]byte(`{"status":"available","capabilities":{"role":"worker","harnesses":["codex"]}}`),
		"CicadaNode "+nodeToken)
	if heartbeatStatus != http.StatusNoContent {
		t.Fatalf("initial bound Node heartbeat status=%d body=%s", heartbeatStatus, heartbeatBody)
	}

	intentBody := []byte(`{"text":"Run the approval protocol fixture for this Node","kind":"goal","goal":{"objective":"Run the approval protocol fixture for this Node","success_criteria":"Return the fake app-server completion summary","constraints":"Do not modify files or contact external services","machine_id":"node-binary-approval","harness":"codex"}}`)
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

	nodeStateDir := filepath.Join(root, "node-state")
	nodeHome := filepath.Join(root, "node-home")
	nodeWorkspaceRoot := filepath.Join(root, "node-workspaces")
	if err := os.MkdirAll(filepath.Join(nodeStateDir, "nodes", "node-"+nodeID), 0o700); err != nil {
		t.Fatal(err)
	}
	identityData, err := json.Marshal(map[string]any{"version": 1, "node_id": nodeID})
	if err != nil {
		t.Fatal(err)
	}
	nodeIdentityDir := filepath.Join(nodeStateDir, "nodes", "node-"+nodeID)
	if err := os.WriteFile(filepath.Join(nodeIdentityDir, "identity.json"), identityData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeIdentityDir, "relay.token"), []byte(nodeToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
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

	processCtx, cancelProcess := context.WithTimeout(context.Background(), 35*time.Second)
	agent := exec.CommandContext(processCtx, binary, "machine", "agent", "--id", nodeID,
		"--name", "Binary approval integration", "--control-url", hub.URL,
		"--state-dir", nodeStateDir, "--interval", "1s", "--once")
	pathEnv := os.Getenv("PATH")
	agent.Env = []string{
		"PATH=" + pathEnv, "HOME=" + nodeHome,
		"CICADA_CODEX_BIN=" + codexBin, "CICADA_CODEX_MODEL=fake-model",
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
		t.Fatalf("encrypted Client approvals.list did not expose the live fake app-server request: %#v", approvals)
	}
	goal, err = controlPlane.Goal(goal.ID)
	if err != nil || goal == nil || goal.Worker == nil || goal.Worker.Status != "running" || goal.Worker.Attempt != 1 {
		t.Fatalf("approval did not originate from the binary's claimed Worker attempt: goal=%#v err=%v", goal, err)
	}
	decisionRequest, err := json.Marshal(map[string]string{"approval_id": pending.ID, "decision": "accept"})
	if err != nil {
		t.Fatal(err)
	}
	var decided store.Approval
	if err := json.Unmarshal(callClientRPC("approvals.decide", decisionRequest), &decided); err != nil ||
		decided.ID != pending.ID || decided.Status != "resolved" || decided.Decision != "accept" {
		t.Fatalf("encrypted Client approval decision failed: approval=%#v err=%v", decided, err)
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
		t.Fatalf("fake app-server did not receive the original approval request ID and Client decision: %s err=%v",
			approvalReply, err)
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
}
