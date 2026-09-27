package server

import (
	"bytes"
	"context"
	"encoding/json"
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
// protocol seams used by the machine agent: an owner binds its Node, the
// agent registers the same stable ID with the bearer-protected machine API,
// and an encrypted Client intent creates a Worker that the agent can poll and
// claim. It deliberately does not start an agent process or execute the job.
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
			OperationID: "node-chain-" + operation, Operation: operation,
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

	// The bound Node bearer authenticates the Relay heartbeat. Machine-agent's
	// separate Control API bearer registers its worker identity and polls jobs.
	relayStatus, relayBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v2/relay/nodes/"+nodeID+"/heartbeat", []byte(`{}`), "CicadaNode "+nodeToken)
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
	registration, err := json.Marshal(map[string]any{
		"id": nodeID, "name": "Node chain test", "status": "available",
		"capabilities": map[string]any{"role": "worker", "harnesses": []string{"codex"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	registrationStatus, registrationBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v1/machines", registration, "Bearer "+apiToken)
	if registrationStatus != http.StatusCreated {
		t.Fatalf("machine-agent registration status=%d body=%s", registrationStatus, registrationBody)
	}
	heartbeat, err := json.Marshal(map[string]any{
		"status": "available", "capabilities": map[string]any{"role": "worker", "harnesses": []string{"codex"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	heartbeatStatus, heartbeatBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v1/machines/"+nodeID+"/heartbeat", heartbeat, "Bearer "+apiToken)
	if heartbeatStatus != http.StatusOK {
		t.Fatalf("machine-agent heartbeat status=%d body=%s", heartbeatStatus, heartbeatBody)
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

	jobsStatus, jobsBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v1/machines/"+nodeID+"/jobs", nil, "Bearer "+apiToken)
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
		!strings.Contains(job.Prompt, "Prepare a bounded task for the paired Node") {
		t.Fatalf("polled machine task did not match persisted Goal/Worker: job=%#v", job)
	}

	claimBody, err := json.Marshal(map[string]string{"machine_id": nodeID})
	if err != nil {
		t.Fatal(err)
	}
	claimStatus, claimResponse := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v1/workers/"+job.WorkerID+"/claim", claimBody, "Bearer "+apiToken)
	if claimStatus != http.StatusOK {
		t.Fatalf("machine-agent worker claim status=%d body=%s", claimStatus, claimResponse)
	}
	var claimed control.MachineJob
	if err := json.Unmarshal(claimResponse, &claimed); err != nil || claimed.WorkerID != job.WorkerID ||
		claimed.GoalID != intentResult.GoalID || claimed.MachineID != nodeID || claimed.Attempt != 1 {
		t.Fatalf("machine-agent claim did not return the assigned task: err=%v job=%#v", err, claimed)
	}
	claimedGoal, err := controlPlane.Goal(intentResult.GoalID)
	if err != nil || claimedGoal == nil || claimedGoal.Worker == nil || claimedGoal.Worker.Status != "running" {
		t.Fatalf("Control did not persist machine claim state: goal=%#v err=%v", claimedGoal, err)
	}
}

func clientNodeChainHTTP(t *testing.T, client *http.Client, base, method, path string, body []byte, authorization string) (int, []byte) {
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
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
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
	return response.StatusCode, responseBytes.Bytes()
}
