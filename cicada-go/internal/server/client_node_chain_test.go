package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestClientIntentQueuesWorkForOwnerBoundMachineAgent covers the Hub-side
// protocol seams used by the machine agent: an owner binds its Node, and an
// encrypted Client intent creates a Worker that the Node bearer can poll,
// claim, exchange a Workspace snapshot with, and report. It deliberately does
// not start an agent process or execute the job.
func TestClientIntentQueuesWorkForOwnerBoundMachineAgent(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	const apiToken = "machine-agent-control-token"
	controlPlane, err := control.New(control.Config{
		StateDir: stateDir, WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: apiToken,
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

	server := httptest.NewServer(NewHandler(controlPlane))
	t.Cleanup(server.Close)
	httpClient := server.Client()

	identityStatus, identityBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v2/client/identity", nil, "")
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
	if _, err := controlPlane.CreateGroup(control.GroupCreateInput{Name: "Client node chain"}); err != nil {
		t.Fatal(err)
	}
	approvalStore, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := approvalStore.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		_ = approvalStore.Close()
		t.Fatal(err)
	}
	if err := approvalStore.Close(); err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "phone-chain", deviceKey.Public(), hubIdentity.HubID,
		e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "phone-chain", "device_public_identity": deviceKey.Public(),
		"owner_device_grant": grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollStatus, enrollBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v2/client/devices/enroll", enrollment, "")
	if enrollStatus != http.StatusCreated {
		t.Fatalf("Client device enrollment status=%d body=%s", enrollStatus, enrollBody)
	}

	binding := clientwire.Binding{
		HubID: hubIdentity.HubID, OwnerID: ownerID, DeviceID: "phone-chain",
		SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1,
	}
	sequence := uint64(0)
	callClientRPC := func(operation string, body []byte) json.RawMessage {
		t.Helper()
		sequence++
		route := clientwire.Route{
			Version: clientwire.Version, Direction: clientwire.DirectionRequest,
			HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
			SessionEpoch: binding.SessionEpoch, Sequence: sequence,
			OperationID: fmt.Sprintf("node-chain-%s-%d", operation, sequence), Operation: operation,
			SenderKeyID: deviceKey.Public().ID, SenderKeyVersion: binding.DeviceKeyVersion,
			ReceiverKeyID: hubIdentity.ControlPublicIdentity.ID, ReceiverKeyVersion: binding.HubKeyVersion,
		}
		packet, err := clientwire.SealRequest(deviceKey, hubIdentity.ControlPublicIdentity, binding, route, body)
		if err != nil {
			t.Fatal(err)
		}
		status, responseBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
			"/v2/client/rpc", packet, "")
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

	// Pair a locally generated Node bearer through the owner-authorized,
	// post-quantum encrypted Client RPC. Only its digest goes to device-code.
	const nodeID = "node-chain-a"
	nodeToken, nodeDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	startBody, err := json.Marshal(map[string]string{
		"node_id": nodeID, "node_name": "Node chain test", "credential_digest": nodeDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	startStatus, startResponse := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v2/nodes/device-code", startBody, "")
	if startStatus != http.StatusCreated {
		t.Fatalf("Node device-code status=%d body=%s", startStatus, startResponse)
	}
	var deviceCode control.NodeDeviceCode
	if err := json.Unmarshal(startResponse, &deviceCode); err != nil || deviceCode.UserCode == "" {
		t.Fatalf("decode Node device code: err=%v body=%s", err, startResponse)
	}
	codeBody, err := json.Marshal(map[string]string{"user_code": deviceCode.UserCode})
	if err != nil {
		t.Fatal(err)
	}
	var preview struct {
		NodeID string `json:"node_id"`
	}
	if err := json.Unmarshal(callClientRPC("nodes.preview", codeBody), &preview); err != nil || preview.NodeID != nodeID {
		t.Fatalf("encrypted Node preview did not identify candidate: err=%v preview=%#v", err, preview)
	}
	var bindingResult store.NodeDeviceBinding
	if err := json.Unmarshal(callClientRPC("nodes.confirm", codeBody), &bindingResult); err != nil ||
		bindingResult.NodeID != nodeID || bindingResult.State != "ACTIVE" || !bindingResult.Authorized {
		t.Fatalf("encrypted Node confirmation failed: err=%v binding=%#v", err, bindingResult)
	}

	// The bound Node bearer authenticates Relay liveness and worker capabilities.
	relayStatus, relayBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v2/relay/nodes/"+nodeID+"/heartbeat",
		[]byte(`{"status":"available","capabilities":{"role":"worker","harnesses":["codex"]}}`),
		"CicadaNode "+nodeToken)
	if relayStatus != http.StatusNoContent {
		t.Fatalf("bound Node Relay heartbeat status=%d body=%s", relayStatus, relayBody)
	}
	wrongNodePlaneStatus, wrongNodePlaneBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v1/machines/"+nodeID+"/jobs", nil, "CicadaNode "+nodeToken)
	if wrongNodePlaneStatus != http.StatusUnauthorized {
		t.Fatalf("Node Relay bearer authorized the separate Worker API: status=%d body=%s", wrongNodePlaneStatus, wrongNodePlaneBody)
	}
	wrongRelayPlaneStatus, wrongRelayPlaneBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v2/relay/nodes/"+nodeID+"/heartbeat", []byte(`{}`), "Bearer "+apiToken)
	if wrongRelayPlaneStatus != http.StatusUnauthorized {
		t.Fatalf("Control API bearer authorized the Node Relay: status=%d body=%s", wrongRelayPlaneStatus, wrongRelayPlaneBody)
	}

	intentBody := []byte(`{"text":"Prepare a bounded task for the paired Node","kind":"goal","goal":{"objective":"Prepare a bounded task for the paired Node","success_criteria":"Return a short completion summary","constraints":"Do not modify files or contact external services","machine_id":"node-chain-a","harness":"codex"}}`)
	var accepted struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(callClientRPC("intent.submit", intentBody), &accepted); err != nil || accepted.ID == "" {
		t.Fatalf("encrypted intent submission was not accepted: err=%v response=%#v", err, accepted)
	}

	deadline := time.Now().Add(5 * time.Second)
	var progress *control.ClientIntentProgress
	for {
		progress, err = controlPlane.ClientIntentStatus(ownerID, accepted.ID)
		if err != nil {
			t.Fatal(err)
		}
		if progress.Job.State == store.ClientIntentDone && progress.Intent.Status == "resolved" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Client intent did not durably resolve: %#v", progress)
		}
		time.Sleep(10 * time.Millisecond)
	}
	var intentResult struct {
		Type   string `json:"type"`
		GoalID string `json:"goal_id"`
	}
	if err := json.Unmarshal(progress.Intent.Result, &intentResult); err != nil ||
		intentResult.Type != "goal" || intentResult.GoalID == "" {
		t.Fatalf("resolved intent did not persist a Goal result: err=%v result=%s", err, progress.Intent.Result)
	}
	goal, err := controlPlane.Goal(intentResult.GoalID)
	if err != nil || goal == nil || goal.MachineID != nodeID || goal.Worker == nil ||
		goal.Worker.MachineID != nodeID || goal.Worker.Status != "queued" {
		t.Fatalf("Control did not persist a queued Worker for the bound Node ID: goal=%#v err=%v", goal, err)
	}
	workspaces, err := controlPlane.Workspaces(goal.ID)
	if err != nil || len(workspaces) != 1 {
		t.Fatalf("Client Goal Workspace was not created: workspaces=%#v err=%v", workspaces, err)
	}
	seededSnapshot, err := controlPlane.SnapshotWorkspace(workspaces[0].ID)
	if err != nil {
		t.Fatalf("seed Client Goal Workspace snapshot: %v", err)
	}

	// Reopen the SQLite store to establish that the Goal/Worker association is
	// committed durably before the remote agent polls it.
	persistedStore, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	persistedGoal, err := persistedStore.GetGoal(intentResult.GoalID)
	if err != nil || persistedGoal == nil || persistedGoal.MachineID != nodeID {
		_ = persistedStore.Close()
		t.Fatalf("Goal was not persisted in Control storage: goal=%#v err=%v", persistedGoal, err)
	}
	persistedWorker, err := persistedStore.GetWorker(goal.Worker.ID)
	if closeErr := persistedStore.Close(); closeErr != nil {
		t.Errorf("close verification store: %v", closeErr)
	}
	if err != nil || persistedWorker == nil || persistedWorker.GoalID != intentResult.GoalID ||
		persistedWorker.MachineID != nodeID || persistedWorker.Status != "queued" {
		t.Fatalf("Worker was not durably queued for the bound Node ID: worker=%#v err=%v", persistedWorker, err)
	}
	var paused store.Goal
	requestPause, _ := json.Marshal(map[string]any{
		"goal_id": goal.ID, "action": "pause", "expected_version": persistedGoal.LifecycleVersion,
	})
	if err := json.Unmarshal(callClientRPC("goal.lifecycle", requestPause), &paused); err != nil ||
		paused.Status != "paused" || paused.LifecycleVersion != persistedGoal.LifecycleVersion+1 {
		t.Fatalf("encrypted Client pause did not fence queued Goal: goal=%#v err=%v", paused, err)
	}
	var pausedSnapshot control.ClientStatusSnapshot
	if err := json.Unmarshal(callClientRPC("status.snapshot", []byte(`{}`)), &pausedSnapshot); err != nil {
		t.Fatal(err)
	}
	seenPaused := false
	for _, item := range pausedSnapshot.Goals {
		if item.GoalID == goal.ID && item.Lifecycle.State == control.ClientGoalPaused &&
			item.Version == paused.LifecycleVersion {
			seenPaused = true
		}
	}
	if !seenPaused {
		t.Fatalf("Client snapshot did not show authoritative paused Goal: %#v", pausedSnapshot.Goals)
	}
	pausedJobsStatus, pausedJobsBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v2/relay/nodes/"+nodeID+"/jobs", nil, "CicadaNode "+nodeToken)
	if pausedJobsStatus != http.StatusOK || !bytes.Contains(pausedJobsBody, []byte(`"jobs":[]`)) {
		t.Fatalf("paused Goal remained claimable by Node: status=%d body=%s", pausedJobsStatus, pausedJobsBody)
	}
	pausedClaimStatus, pausedClaimBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v2/relay/nodes/"+nodeID+"/jobs/"+persistedWorker.ID+"/claim", []byte(`{}`), "CicadaNode "+nodeToken)
	if pausedClaimStatus == http.StatusOK {
		t.Fatalf("Node claimed paused Goal through exact worker ID: %s", pausedClaimBody)
	}
	var resumed store.Goal
	requestResume, _ := json.Marshal(map[string]any{
		"goal_id": goal.ID, "action": "resume", "expected_version": paused.LifecycleVersion,
	})
	if err := json.Unmarshal(callClientRPC("goal.lifecycle", requestResume), &resumed); err != nil ||
		resumed.Status != "queued" || resumed.LifecycleVersion != paused.LifecycleVersion+1 {
		t.Fatalf("encrypted Client resume did not release queued Goal: goal=%#v err=%v", resumed, err)
	}

	jobsStatus, jobsBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v2/relay/nodes/"+nodeID+"/jobs", nil, "CicadaNode "+nodeToken)
	if jobsStatus != http.StatusOK {
		t.Fatalf("machine-agent jobs poll status=%d body=%s", jobsStatus, jobsBody)
	}
	var listed struct {
		Jobs []control.MachineJob `json:"jobs"`
	}
	if err := json.Unmarshal(jobsBody, &listed); err != nil || len(listed.Jobs) != 1 {
		t.Fatalf("machine-agent poll did not return exactly one queued task: err=%v body=%s", err, jobsBody)
	}
	job := listed.Jobs[0]
	if job.WorkerID != persistedWorker.ID || job.GoalID != intentResult.GoalID ||
		job.MachineID != nodeID || job.Harness != "codex" ||
		job.WorkspaceSnapshotDigest != seededSnapshot.Digest || job.WorkspaceID != workspaces[0].ID ||
		!strings.Contains(job.Prompt, "Prepare a bounded task for the paired Node") {
		t.Fatalf("polled machine task did not match persisted Goal/Worker: job=%#v", job)
	}

	claimBody := []byte(`{}`)
	claimStatus, claimResponse := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v2/relay/nodes/"+nodeID+"/jobs/"+job.WorkerID+"/claim", claimBody, "CicadaNode "+nodeToken)
	if claimStatus != http.StatusOK {
		t.Fatalf("Node worker claim status=%d body=%s", claimStatus, claimResponse)
	}
	var claimed control.MachineJob
	if err := json.Unmarshal(claimResponse, &claimed); err != nil || claimed.WorkerID != job.WorkerID ||
		claimed.GoalID != intentResult.GoalID || claimed.MachineID != nodeID || claimed.Attempt != 1 {
		t.Fatalf("Node claim did not return the assigned task: err=%v job=%#v", err, claimed)
	}
	approvalRequest := []byte(`{"attempt":1,"request_id":"thread-turn-rpc-approval-1","method":"item/commandExecution/requestApproval","request":{"command":["echo","approval integration payload"],"cwd":"/tmp"}}`)
	approvalStatus, approvalBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v2/relay/nodes/"+nodeID+"/jobs/"+job.WorkerID+"/approvals", approvalRequest, "CicadaNode "+nodeToken)
	var nodeApproval nodeWorkerApprovalResponse
	if err := json.Unmarshal(approvalBody, &nodeApproval); approvalStatus != http.StatusAccepted || err != nil ||
		nodeApproval.ApprovalID == "" || nodeApproval.GoalID != intentResult.GoalID ||
		nodeApproval.WorkerID != job.WorkerID || nodeApproval.Attempt != claimed.Attempt || nodeApproval.Status != "pending" ||
		bytes.Contains(approvalBody, []byte("approval integration payload")) {
		t.Fatalf("Node approval create response exposed content or lost its fence: status=%d response=%#v err=%v body=%s",
			approvalStatus, nodeApproval, err, approvalBody)
	}
	approvalListBody, err := json.Marshal(map[string]bool{"pending_only": true})
	if err != nil {
		t.Fatal(err)
	}
	var listedApprovals []store.Approval
	if err := json.Unmarshal(callClientRPC("approvals.list", approvalListBody), &listedApprovals); err != nil {
		t.Fatal(err)
	}
	var listedApproval *store.Approval
	for i := range listedApprovals {
		if listedApprovals[i].ID == nodeApproval.ApprovalID {
			listedApproval = &listedApprovals[i]
			break
		}
	}
	if listedApproval == nil || listedApproval.Attempt != claimed.Attempt ||
		!bytes.Contains(listedApproval.Request, []byte("approval integration payload")) {
		t.Fatalf("encrypted Client approvals.list omitted the exact remote request: %#v", listedApprovals)
	}
	decisionBody, err := json.Marshal(map[string]string{"approval_id": nodeApproval.ApprovalID, "decision": "accept"})
	if err != nil {
		t.Fatal(err)
	}
	var decided store.Approval
	if err := json.Unmarshal(callClientRPC("approvals.decide", decisionBody), &decided); err != nil ||
		decided.ID != nodeApproval.ApprovalID || decided.Status != "resolved" || decided.Decision != "accept" {
		t.Fatalf("encrypted Client approval decision failed: approval=%#v err=%v", decided, err)
	}
	decisionStatus, decisionResponse := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v2/relay/nodes/"+nodeID+"/jobs/"+job.WorkerID+"/approvals/"+nodeApproval.ApprovalID+"?attempt=1&wait_ms=0",
		nil, "CicadaNode "+nodeToken)
	var polledApproval nodeWorkerApprovalResponse
	if err := json.Unmarshal(decisionResponse, &polledApproval); decisionStatus != http.StatusOK || err != nil ||
		polledApproval.Status != "resolved" || polledApproval.Decision != "accept" || polledApproval.Attempt != claimed.Attempt {
		t.Fatalf("Node did not retrieve the accepted Client decision: status=%d approval=%#v err=%v body=%s",
			decisionStatus, polledApproval, err, decisionResponse)
	}
	wrongAttemptStatus, _ := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v2/relay/nodes/"+nodeID+"/jobs/"+job.WorkerID+"/approvals/"+nodeApproval.ApprovalID+"?attempt=2&wait_ms=0",
		nil, "CicadaNode "+nodeToken)
	if wrongAttemptStatus != http.StatusConflict {
		t.Fatalf("Node approval poll accepted a forged attempt: status=%d", wrongAttemptStatus)
	}

	snapshotHeaders := make(http.Header)
	snapshotHeaders.Set("Authorization", "CicadaNode "+nodeToken)
	snapshotHeaders.Set("X-Cicada-Worker-Attempt", "1")
	snapshotHeaders.Set("X-Cicada-Workspace-ID", job.WorkspaceID)
	downloadHeaders := snapshotHeaders.Clone()
	downloadStatus, downloadedResponseHeaders, downloadedArchive := clientNodeChainHTTPWithHeaders(t, httpClient,
		server.URL, http.MethodGet, "/v2/relay/nodes/"+nodeID+"/jobs/"+job.WorkerID+"/snapshot/"+seededSnapshot.Digest,
		nil, downloadHeaders)
	if downloadStatus != http.StatusOK || downloadedResponseHeaders.Get("X-Cicada-Snapshot-Digest") != seededSnapshot.Digest ||
		downloadedResponseHeaders.Get("Content-Type") != "application/x-cicada-workspace-tar" || len(downloadedArchive) == 0 {
		t.Fatalf("Node snapshot download failed: status=%d headers=%v bytes=%d", downloadStatus, downloadedResponseHeaders, len(downloadedArchive))
	}
	uploadHeaders := snapshotHeaders.Clone()
	uploadHeaders.Set("Content-Type", "application/x-cicada-workspace-tar")
	uploadHeaders.Set("X-Cicada-Snapshot-Digest", seededSnapshot.Digest)
	uploadStatus, _, uploadResponse := clientNodeChainHTTPWithHeaders(t, httpClient, server.URL, http.MethodPost,
		"/v2/relay/nodes/"+nodeID+"/jobs/"+job.WorkerID+"/snapshot", downloadedArchive, uploadHeaders)
	if uploadStatus != http.StatusCreated {
		t.Fatalf("Node snapshot upload failed: status=%d body=%s", uploadStatus, uploadResponse)
	}
	result, err := json.Marshal(map[string]any{
		"attempt": claimed.Attempt, "status": "completed", "summary": "Task completed with bounded evidence.",
	})
	if err != nil {
		t.Fatal(err)
	}
	resultStatus, resultBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v2/relay/nodes/"+nodeID+"/jobs/"+job.WorkerID+"/result", result, "CicadaNode "+nodeToken)
	if resultStatus != http.StatusOK {
		t.Fatalf("Node worker result status=%d body=%s", resultStatus, resultBody)
	}
	var completed store.Worker
	if err := json.Unmarshal(resultBody, &completed); err != nil || completed.Status != "completed" || completed.Attempt != 1 {
		t.Fatalf("Node result did not complete its fenced attempt: worker=%#v err=%v", completed, err)
	}
	claimedGoal, err := controlPlane.Goal(intentResult.GoalID)
	if err != nil || claimedGoal == nil || claimedGoal.Worker == nil || claimedGoal.Worker.Status != "completed" {
		t.Fatalf("Control did not persist Node result state: goal=%#v err=%v", claimedGoal, err)
	}
	readBody, err := json.Marshal(map[string]string{"intent_id": accepted.ID})
	if err != nil {
		t.Fatal(err)
	}
	var clientResult control.ClientGoalResult
	if err := json.Unmarshal(callClientRPC("goal.result", readBody), &clientResult); err != nil ||
		clientResult.IntentID != accepted.ID || clientResult.GoalID != goal.ID ||
		len(clientResult.Workers) != 1 || clientResult.Workers[0].Status != "completed" ||
		clientResult.Workers[0].Summary != "Task completed with bounded evidence." {
		t.Fatalf("encrypted Client could not read its Node result: result=%+v err=%v", clientResult, err)
	}
	terminalPollStatus, _ := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v2/relay/nodes/"+nodeID+"/jobs/"+job.WorkerID+"/approvals/"+nodeApproval.ApprovalID+"?attempt=1&wait_ms=0",
		nil, "CicadaNode "+nodeToken)
	if terminalPollStatus != http.StatusConflict {
		t.Fatalf("terminal Worker attempt returned an old approval decision: status=%d", terminalPollStatus)
	}
	if _, err := controlPlane.ClientGoalResultForIntent("another-owner", accepted.ID); err == nil {
		t.Fatal("another owner read a Client Goal result")
	}
	approvalStore, err = store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := approvalStore.RevokeNodeDeviceBinding(ownerID, bindingResult.ID, bindingResult.Version); err != nil {
		_ = approvalStore.Close()
		t.Fatal(err)
	}
	if err := approvalStore.Close(); err != nil {
		t.Fatal(err)
	}
	revokedPollStatus, _ := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v2/relay/nodes/"+nodeID+"/jobs/"+job.WorkerID+"/approvals/"+nodeApproval.ApprovalID+"?attempt=1&wait_ms=0",
		nil, "CicadaNode "+nodeToken)
	if revokedPollStatus != http.StatusUnauthorized {
		t.Fatalf("revoked Node credential polled an approval: status=%d", revokedPollStatus)
	}
}

func clientNodeChainHTTP(t *testing.T, client *http.Client, base, method, path string, body []byte, authorization string) (int, []byte) {
	t.Helper()
	headers := make(http.Header)
	if body != nil {
		headers.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		headers.Set("Authorization", authorization)
	}
	status, _, responseBody := clientNodeChainHTTPWithHeaders(t, client, base, method, path, body, headers)
	return status, responseBody
}

func clientNodeChainHTTPWithHeaders(t *testing.T, client *http.Client, base, method, path string, body []byte, headers http.Header) (int, http.Header, []byte) {
	t.Helper()
	var requestBody *bytes.Reader
	if body != nil {
		requestBody = bytes.NewReader(body)
	} else {
		requestBody = bytes.NewReader(nil)
	}
	request, err := http.NewRequest(method, base+path, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBytes := new(bytes.Buffer)
	if _, err := responseBytes.ReadFrom(response.Body); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header.Clone(), responseBytes.Bytes()
}
