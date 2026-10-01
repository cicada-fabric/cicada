package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
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
	nodeToken, _, nodeKey, nodeHubIdentity, deviceCode, _ := startPQNodeDeviceCodeFixture(t,
		func(method, path string, body []byte) (int, []byte) {
			return clientNodeChainHTTP(t, httpClient, server.URL, method, path, body, "")
		}, nodeID, "Node chain test")
	codeBody, err := json.Marshal(map[string]string{"user_code": deviceCode.UserCode})
	if err != nil {
		t.Fatal(err)
	}
	var preview store.NodeControlKeyCandidate
	if err := json.Unmarshal(callClientRPC("nodes.preview", codeBody), &preview); err != nil ||
		preview.NodeID != nodeID || preview.RequestID != deviceCode.Candidate.RequestID ||
		preview.CandidateDigest == "" || preview.Version <= 0 {
		t.Fatalf("encrypted Node preview did not identify exact candidate: err=%v preview=%#v", err, preview)
	}
	confirmBody, err := json.Marshal(map[string]any{"user_code": deviceCode.UserCode,
		"candidate_digest": preview.CandidateDigest, "candidate_version": preview.Version})
	if err != nil {
		t.Fatal(err)
	}
	var bindingResult store.NodeControlKeyBinding
	if err := json.Unmarshal(callClientRPC("nodes.confirm", confirmBody), &bindingResult); err != nil ||
		bindingResult.NodeID != nodeID || bindingResult.State != store.NodeControlKeyActive ||
		bindingResult.ApprovedCandidateDigest != preview.CandidateDigest {
		t.Fatalf("encrypted Node confirmation failed: err=%v binding=%#v", err, bindingResult)
	}
	pairingStatus, pairingStatusBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v2/node/device-code/"+preview.RequestID+"/status?node_id="+nodeID, nil, "CicadaNode "+nodeToken)
	var pairedCandidate store.NodeControlKeyCandidate
	if pairingStatus != http.StatusOK || json.Unmarshal(pairingStatusBody, &pairedCandidate) != nil ||
		pairedCandidate.State != store.NodeControlPairingConfirmed || pairedCandidate.BindingID != bindingResult.OwnerBindingID ||
		pairedCandidate.BindingVersion != bindingResult.BindingVersion {
		t.Fatalf("Node pairing status omitted confirmed binding: status=%d body=%s", pairingStatus, pairingStatusBody)
	}
	nodeClient := &nodeControlFixtureClient{t: t, httpClient: httpClient, baseURL: server.URL,
		token: nodeToken, key: nodeKey, binding: nodewire.Binding{
			HubID: nodeHubIdentity.HubID, NodeID: nodeID, BindingID: bindingResult.OwnerBindingID,
			BindingVersion: bindingResult.BindingVersion, NodeKeyEpoch: bindingResult.NodeKeyEpoch,
			HubKeyVersion: bindingResult.HubKeyVersion, NodeKeyVersion: bindingResult.NodeKeyVersion,
			NodeKey: nodeKey.Public(), HubKey: nodeHubIdentity.PublicIdentity,
		}}

	// Node liveness and management now use the separately Owner-approved PQ
	// Node-Control channel; a bare Relay bearer is only the transport identity.
	if reply := nodeClient.call("node.heartbeat",
		[]byte(`{"status":"available","capabilities":{"harnesses":["codex"]}}`)); !reply.OK {
		t.Fatalf("Node-Control heartbeat failed: code=%s", reply.ErrorCode)
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
	pausedJobsReply := nodeClient.call("node.jobs.list", []byte(`{}`))
	var pausedJobs struct {
		Jobs []control.MachineJob `json:"jobs"`
	}
	if !pausedJobsReply.OK || json.Unmarshal(pausedJobsReply.Result, &pausedJobs) != nil || len(pausedJobs.Jobs) != 0 {
		t.Fatalf("paused Goal remained visible to Node: ok=%t code=%s result=%s",
			pausedJobsReply.OK, pausedJobsReply.ErrorCode, pausedJobsReply.Result)
	}
	pausedClaimBody, _ := json.Marshal(map[string]string{"worker_id": persistedWorker.ID})
	if pausedClaimReply := nodeClient.call("node.jobs.claim", pausedClaimBody); pausedClaimReply.OK {
		t.Fatalf("Node claimed paused Goal through exact worker ID: %s", pausedClaimReply.Result)
	}
	var resumed store.Goal
	requestResume, _ := json.Marshal(map[string]any{
		"goal_id": goal.ID, "action": "resume", "expected_version": paused.LifecycleVersion,
	})
	if err := json.Unmarshal(callClientRPC("goal.lifecycle", requestResume), &resumed); err != nil ||
		resumed.Status != "queued" || resumed.LifecycleVersion != paused.LifecycleVersion+1 {
		t.Fatalf("encrypted Client resume did not release queued Goal: goal=%#v err=%v", resumed, err)
	}

	jobsReply := nodeClient.call("node.jobs.list", []byte(`{}`))
	var listed struct {
		Jobs []control.MachineJob `json:"jobs"`
	}
	if err := json.Unmarshal(jobsReply.Result, &listed); err != nil || !jobsReply.OK || len(listed.Jobs) != 1 {
		t.Fatalf("Node-Control jobs list did not return exactly one queued task: err=%v code=%s result=%s",
			err, jobsReply.ErrorCode, jobsReply.Result)
	}
	job := listed.Jobs[0]
	if job.WorkerID != persistedWorker.ID || job.GoalID != intentResult.GoalID ||
		job.MachineID != nodeID || job.Harness != "codex" ||
		job.WorkspaceSnapshotDigest != seededSnapshot.Digest || job.WorkspaceID != workspaces[0].ID ||
		!strings.Contains(job.Prompt, "Prepare a bounded task for the paired Node") {
		t.Fatalf("polled machine task did not match persisted Goal/Worker: job=%#v", job)
	}

	claimBody, _ := json.Marshal(map[string]string{"worker_id": job.WorkerID})
	claimReply := nodeClient.call("node.jobs.claim", claimBody)
	var claimed control.MachineJob
	if err := json.Unmarshal(claimReply.Result, &claimed); err != nil || !claimReply.OK || claimed.WorkerID != job.WorkerID ||
		claimed.GoalID != intentResult.GoalID || claimed.MachineID != nodeID || claimed.Attempt != 1 {
		t.Fatalf("Node-Control claim did not return the assigned task: err=%v code=%s job=%#v", err, claimReply.ErrorCode, claimed)
	}
	approvalRequest := json.RawMessage(`{"command":["echo","approval integration payload"],"cwd":"/tmp"}`)
	approvalRequestBody, err := json.Marshal(map[string]any{
		"worker_id": job.WorkerID, "attempt": claimed.Attempt,
		"request_id": "thread-turn-rpc-approval-1", "method": "item/commandExecution/requestApproval",
		"request": approvalRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	approvalReply := nodeClient.call("node.approvals.create", approvalRequestBody)
	var nodeApproval nodeWorkerApprovalResponse
	if err := json.Unmarshal(approvalReply.Result, &nodeApproval); !approvalReply.OK || err != nil ||
		nodeApproval.ApprovalID == "" || nodeApproval.GoalID != intentResult.GoalID ||
		nodeApproval.WorkerID != job.WorkerID || nodeApproval.Attempt != claimed.Attempt || nodeApproval.Status != "pending" ||
		bytes.Contains(approvalReply.Result, []byte("approval integration payload")) {
		t.Fatalf("Node approval create response exposed content or lost its fence: ok=%t response=%#v err=%v body=%s",
			approvalReply.OK, nodeApproval, err, approvalReply.Result)
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
	approvalStatusBody, _ := json.Marshal(map[string]any{
		"worker_id": job.WorkerID, "attempt": claimed.Attempt, "approval_id": nodeApproval.ApprovalID,
	})
	decisionReply := nodeClient.call("node.approvals.status", approvalStatusBody)
	var polledApproval nodeWorkerApprovalResponse
	if err := json.Unmarshal(decisionReply.Result, &polledApproval); !decisionReply.OK || err != nil ||
		polledApproval.Status != "resolved" || polledApproval.Decision != "accept" || polledApproval.Attempt != claimed.Attempt {
		t.Fatalf("Node did not retrieve the accepted Client decision: ok=%t approval=%#v err=%v body=%s",
			decisionReply.OK, polledApproval, err, decisionReply.Result)
	}
	wrongAttemptBody, _ := json.Marshal(map[string]any{
		"worker_id": job.WorkerID, "attempt": 2, "approval_id": nodeApproval.ApprovalID,
	})
	if wrongAttemptReply := nodeClient.call("node.approvals.status", wrongAttemptBody); wrongAttemptReply.OK {
		t.Fatalf("Node-Control approval status accepted a forged attempt: %s", wrongAttemptReply.Result)
	}

	downloadManifest, downloadedArchive, err := nodeClient.downloadSnapshot(job.WorkerID, nodewire.SnapshotManifest{
		WorkerID: job.WorkerID, Attempt: claimed.Attempt, WorkspaceID: job.WorkspaceID, Digest: seededSnapshot.Digest,
	})
	if err != nil || downloadManifest.Digest != seededSnapshot.Digest || len(downloadedArchive) == 0 {
		t.Fatalf("Node-Control snapshot download failed: manifest=%#v bytes=%d err=%v",
			downloadManifest, len(downloadedArchive), err)
	}
	if err := nodeClient.uploadSnapshot(job.WorkerID, downloadManifest, downloadedArchive); err != nil {
		t.Fatalf("Node-Control snapshot upload failed: %v", err)
	}
	result, err := json.Marshal(map[string]any{
		"worker_id": job.WorkerID, "attempt": claimed.Attempt, "status": "completed",
		"summary": "Task completed with bounded evidence.",
	})
	if err != nil {
		t.Fatal(err)
	}
	resultReply := nodeClient.call("node.jobs.result", result)
	var completed store.Worker
	if err := json.Unmarshal(resultReply.Result, &completed); err != nil || !resultReply.OK ||
		completed.Status != "completed" || completed.Attempt != 1 {
		t.Fatalf("Node-Control result did not complete its fenced attempt: ok=%t worker=%#v err=%v",
			resultReply.OK, completed, err)
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
	if terminalReply := nodeClient.call("node.approvals.status", approvalStatusBody); terminalReply.OK {
		t.Fatalf("terminal Worker attempt returned an old approval decision: %s", terminalReply.Result)
	}
	if _, err := controlPlane.ClientGoalResultForIntent("another-owner", accepted.ID); err == nil {
		t.Fatal("another owner read a Client Goal result")
	}
	approvalStore, err = store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := approvalStore.RevokeNodeDeviceBinding(ownerID, bindingResult.OwnerBindingID, int64(bindingResult.BindingVersion)); err != nil {
		_ = approvalStore.Close()
		t.Fatal(err)
	}
	if err := approvalStore.Close(); err != nil {
		t.Fatal(err)
	}
	revokedPollStatus, revokedPollBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v2/node/device-code/"+preview.RequestID+"/status?node_id="+url.QueryEscape(nodeID),
		nil, "CicadaNode "+nodeToken)
	if revokedPollStatus != http.StatusNotFound {
		t.Fatalf("revoked Node credential was not hidden from pairing status: status=%d body=%s", revokedPollStatus, revokedPollBody)
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

type nodeControlFixtureRequest func(method, path string, body []byte) (int, []byte)

// startPQNodeDeviceCodeFixture creates a synthetic Node identity and bearer,
// then follows the public proof-bearing Node-Control pairing endpoint. Owner
// preview and confirmation remain separate encrypted Client RPC decisions.
func startPQNodeDeviceCodeFixture(t *testing.T, request nodeControlFixtureRequest,
	nodeID, nodeName string) (string, string, *e2ee.Identity, control.NodeControlHubIdentity, control.NodeControlDeviceCode, []byte) {
	t.Helper()
	status, response := request(http.MethodGet, "/v2/node/identity", nil)
	if status != http.StatusOK {
		t.Fatalf("Node-Control Hub identity status=%d body=%s", status, response)
	}
	var hub control.NodeControlHubIdentity
	if err := json.Unmarshal(response, &hub); err != nil || hub.HubID == "" || hub.KeyVersion == 0 ||
		hub.KeyID == "" || hub.Fingerprint == "" {
		t.Fatalf("invalid Node-Control Hub identity: err=%v body=%s", err, response)
	}
	nodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("generate synthetic Node-Control identity", err)
	}
	nodeToken, credentialDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal("generate synthetic Node bearer", err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal("generate Node pairing nonce", err)
	}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{
		HubID: hub.HubID, NodeID: nodeID, RequestNonce: nonce, CredentialDigest: credentialDigest,
		NodePublicIdentity: nodeKey.Public(), HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion,
	})
	if err != nil {
		t.Fatal("build Node pairing proof transcript", err)
	}
	proofPacket, err := e2ee.Seal(nodeKey, hub.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal("seal Node pairing proof", err)
	}
	startBody, err := json.Marshal(map[string]any{
		"node_id": nodeID, "node_name": nodeName, "credential_digest": credentialDigest,
		"request_nonce": nonce, "node_public_identity": nodeKey.Public(),
		"node_fingerprint": nodewire.IdentityFingerprint(nodeKey.Public()), "proof_packet": proofPacket,
		"hub_id": hub.HubID, "hub_public_identity": hub.PublicIdentity,
		"hub_key_version": hub.KeyVersion, "hub_fingerprint": hub.Fingerprint,
	})
	if err != nil {
		t.Fatal("encode Node-Control pairing request", err)
	}
	status, response = request(http.MethodPost, "/v2/nodes/device-code", startBody)
	if status != http.StatusCreated || bytes.Contains(response, []byte(nodeToken)) ||
		bytes.Contains(response, []byte(credentialDigest)) {
		t.Fatalf("Node-Control device-code start failed or leaked credential: status=%d body=%s", status, response)
	}
	var challenge control.NodeControlDeviceCode
	if err := json.Unmarshal(response, &challenge); err != nil || challenge.UserCode == "" || challenge.Candidate == nil ||
		challenge.Candidate.RequestID == "" || challenge.Candidate.CandidateDigest == "" || challenge.Candidate.Version <= 0 {
		t.Fatalf("invalid Node-Control device-code response: err=%v body=%s", err, response)
	}
	return nodeToken, credentialDigest, nodeKey, hub, challenge, startBody
}

type nodeControlFixtureReply struct {
	OK        bool            `json:"ok"`
	Result    json.RawMessage `json:"result"`
	ErrorCode string          `json:"error_code"`
}

type nodeControlFixtureClient struct {
	t          *testing.T
	httpClient *http.Client
	baseURL    string
	token      string
	key        *e2ee.Identity
	binding    nodewire.Binding
	sequence   uint64
}

func (c *nodeControlFixtureClient) call(operation string, body []byte) nodeControlFixtureReply {
	c.t.Helper()
	c.sequence++
	route := nodewire.Route{
		Version: nodewire.Version, Direction: nodewire.DirectionRequest,
		HubID: c.binding.HubID, NodeID: c.binding.NodeID, BindingID: c.binding.BindingID,
		BindingVersion: c.binding.BindingVersion, NodeKeyEpoch: c.binding.NodeKeyEpoch,
		Sequence: c.sequence, OperationID: fmt.Sprintf("node-client-chain-%d", c.sequence), Operation: operation,
		SenderKeyID: c.binding.NodeKey.ID, SenderKeyVersion: c.binding.NodeKeyVersion,
		ReceiverKeyID: c.binding.HubKey.ID, ReceiverKeyVersion: c.binding.HubKeyVersion,
	}
	packet, err := nodewire.SealRequest(c.key, c.binding.HubKey, c.binding, route, body)
	if err != nil {
		c.t.Fatalf("seal Node-Control %s request: %v", operation, err)
	}
	response, err := c.httpCall(http.MethodPost, "/v2/node/control/rpc", packet,
		"application/octet-stream", "application/octet-stream")
	if err != nil {
		c.t.Fatalf("Node-Control %s request failed: %v", operation, err)
	}
	opened, err := nodewire.OpenResponse(c.key, c.binding.HubKey, c.binding, response)
	if err != nil || opened.Route.OperationID != route.OperationID || opened.Route.Sequence != route.Sequence {
		c.t.Fatalf("open Node-Control %s response: %v", operation, err)
	}
	var reply nodeControlFixtureReply
	if err := json.Unmarshal(opened.Plaintext, &reply); err != nil {
		c.t.Fatalf("decode Node-Control %s response: %v", operation, err)
	}
	return reply
}

func (c *nodeControlFixtureClient) httpCall(method, path string, body []byte,
	contentType, accept string) ([]byte, error) {
	c.t.Helper()
	headers := make(http.Header)
	headers.Set("Authorization", "CicadaNode "+c.token)
	if contentType != "" {
		headers.Set("Content-Type", contentType)
	}
	if accept != "" {
		headers.Set("Accept", accept)
	}
	status, _, response := clientNodeChainHTTPWithHeaders(c.t, c.httpClient, c.baseURL,
		method, path, body, headers)
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d: %s", status, response)
	}
	return response, nil
}

func (c *nodeControlFixtureClient) nextRoute(operation string) nodewire.Route {
	c.sequence++
	return nodewire.Route{
		Version: nodewire.Version, Direction: nodewire.DirectionRequest,
		HubID: c.binding.HubID, NodeID: c.binding.NodeID, BindingID: c.binding.BindingID,
		BindingVersion: c.binding.BindingVersion, NodeKeyEpoch: c.binding.NodeKeyEpoch,
		Sequence: c.sequence, OperationID: fmt.Sprintf("node-client-chain-snapshot-%d", c.sequence), Operation: operation,
		SenderKeyID: c.binding.NodeKey.ID, SenderKeyVersion: c.binding.NodeKeyVersion,
		ReceiverKeyID: c.binding.HubKey.ID, ReceiverKeyVersion: c.binding.HubKeyVersion,
	}
}

func (c *nodeControlFixtureClient) downloadSnapshot(workerID string,
	requestManifest nodewire.SnapshotManifest) (nodewire.SnapshotManifest, []byte, error) {
	requestManifest.Version = nodewire.Version
	requestManifest.Direction = nodewire.SnapshotDirectionDownload
	requestManifest.Size, requestManifest.FileCount = 0, 0
	requestManifest.ChunkSize, requestManifest.ChunkCount = 0, 0
	route := c.nextRoute(nodewire.SnapshotDownloadOperation)
	packet, err := nodewire.SealRequest(c.key, c.binding.HubKey, c.binding, route, mustJSONNodeChain(c.t, requestManifest))
	if err != nil {
		return nodewire.SnapshotManifest{}, nil, err
	}
	var requestFrame bytes.Buffer
	if err := nodewire.WriteFrame(&requestFrame, packet); err != nil {
		return nodewire.SnapshotManifest{}, nil, err
	}
	response, err := c.httpCall(http.MethodPost,
		"/v2/relay/nodes/"+url.PathEscape(c.binding.NodeID)+"/jobs/"+url.PathEscape(workerID)+"/snapshot/download",
		requestFrame.Bytes(), nodeControlSnapshotContentType, nodeControlSnapshotContentType)
	if err != nil {
		return nodewire.SnapshotManifest{}, nil, err
	}
	frames := bytes.NewReader(response)
	manifestPacket, err := nodewire.ReadFrame(frames, nodewire.MaxPacketBytes)
	if err != nil {
		return nodewire.SnapshotManifest{}, nil, err
	}
	opened, err := nodewire.OpenResponse(c.key, c.binding.HubKey, c.binding, manifestPacket)
	if err != nil || !sameNodeControlResponseRoute(opened.Route, route) {
		return nodewire.SnapshotManifest{}, nil, fmt.Errorf("invalid sealed Node-Control snapshot manifest: %v", err)
	}
	var result nodeControlSnapshotResult
	var manifest nodewire.SnapshotManifest
	if err := json.Unmarshal(opened.Plaintext, &result); err != nil || !result.OK ||
		result.OperationID != route.OperationID || result.Sequence != route.Sequence ||
		json.Unmarshal(result.Result, &manifest) != nil || manifest.Validate(false) != nil {
		return nodewire.SnapshotManifest{}, nil, fmt.Errorf("invalid snapshot manifest response: %v", err)
	}
	archive := make([]byte, 0, manifest.Size)
	for index := 0; index < manifest.ChunkCount; index++ {
		frame, err := nodewire.ReadFrame(frames, nodewire.SnapshotMaxChunkFrame)
		if err != nil {
			return nodewire.SnapshotManifest{}, nil, err
		}
		chunk, err := nodewire.OpenSnapshotChunk(c.key, c.binding.HubKey,
			nodeControlSnapshotResponseRoute(route), manifest, index, frame)
		if err != nil {
			return nodewire.SnapshotManifest{}, nil, err
		}
		archive = append(archive, chunk...)
	}
	if frames.Len() != 0 || int64(len(archive)) != manifest.Size {
		return nodewire.SnapshotManifest{}, nil, errors.New("snapshot stream size or framing mismatch")
	}
	digest := sha256.Sum256(archive)
	if hex.EncodeToString(digest[:]) != manifest.Digest {
		return nodewire.SnapshotManifest{}, nil, errors.New("snapshot stream digest mismatch")
	}
	return manifest, archive, nil
}

func (c *nodeControlFixtureClient) uploadSnapshot(workerID string, manifest nodewire.SnapshotManifest,
	archive []byte) error {
	if int64(len(archive)) != manifest.Size {
		return errors.New("snapshot upload bytes do not match manifest size")
	}
	manifest.Direction = nodewire.SnapshotDirectionUpload
	manifest.ChunkSize = nodewire.SnapshotChunkBytes
	manifest.ChunkCount = (len(archive) + nodewire.SnapshotChunkBytes - 1) / nodewire.SnapshotChunkBytes
	route := c.nextRoute(nodewire.SnapshotUploadOperation)
	packet, err := nodewire.SealRequest(c.key, c.binding.HubKey, c.binding, route, mustJSONNodeChain(c.t, manifest))
	if err != nil {
		return err
	}
	var requestFrame bytes.Buffer
	if err := nodewire.WriteFrame(&requestFrame, packet); err != nil {
		return err
	}
	for index := 0; index < manifest.ChunkCount; index++ {
		start := index * nodewire.SnapshotChunkBytes
		end := start + nodewire.SnapshotChunkBytes
		if end > len(archive) {
			end = len(archive)
		}
		chunk, err := nodewire.SealSnapshotChunk(c.key, c.binding.HubKey, route,
			manifest, index, archive[start:end])
		if err != nil {
			return err
		}
		if err := nodewire.WriteFrame(&requestFrame, chunk); err != nil {
			return err
		}
	}
	response, err := c.httpCall(http.MethodPost,
		"/v2/relay/nodes/"+url.PathEscape(c.binding.NodeID)+"/jobs/"+url.PathEscape(workerID)+"/snapshot/upload",
		requestFrame.Bytes(), nodeControlSnapshotContentType, nodeControlSnapshotContentType)
	if err != nil {
		return err
	}
	responseFrame, err := nodewire.ReadFrame(bytes.NewReader(response), nodewire.MaxPacketBytes)
	if err != nil {
		return err
	}
	opened, err := nodewire.OpenResponse(c.key, c.binding.HubKey, c.binding, responseFrame)
	if err != nil || !sameNodeControlResponseRoute(opened.Route, route) {
		return fmt.Errorf("invalid sealed snapshot upload response: %v", err)
	}
	var reply nodeControlSnapshotResult
	if err := json.Unmarshal(opened.Plaintext, &reply); err != nil || !reply.OK ||
		reply.OperationID != route.OperationID || reply.Sequence != route.Sequence {
		return fmt.Errorf("snapshot upload was not acknowledged: %v", err)
	}
	return nil
}

func mustJSONNodeChain(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
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
