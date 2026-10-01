package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func newMachineNodeControlRecoveryFixture(t *testing.T, origin string) (*machineNodeControlClient,
	context.Context, *e2ee.Identity, nodewire.Binding) {
	t.Helper()
	stateDir := t.TempDir()
	const nodeID, hubID, token = "node-recovery-test", "hub-recovery-test", "synthetic-node-token"
	nodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	identityPath, statePath := machineNodeControlPaths(stateDir, nodeID)
	if err := os.MkdirAll(filepath.Dir(identityPath), 0o700); err != nil {
		t.Fatal(err)
	}
	identityData, err := nodeKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistNodeSecretFile(identityPath, identityData, ".test-node-control-key-"); err != nil {
		t.Fatal(err)
	}
	client, err := openMachineNodeControlClient(stateDir, origin, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	client.state.HubID, client.state.HubKeyID = hubID, hubKey.Public().ID
	client.state.HubFingerprint = nodewire.IdentityFingerprint(hubKey.Public())
	client.state.HubKeyVersion, client.state.HubPublicIdentity = 1, hubKey.Public()
	client.state.NodeKeyID, client.state.NodeKeyFingerprint = nodeKey.Public().ID,
		nodewire.IdentityFingerprint(nodeKey.Public())
	client.state.NodeKeyVersion, client.state.BindingID = 1, "binding-recovery-test"
	client.state.BindingVersion, client.state.NodeKeyEpoch = 1, 1
	if err := client.persistLocked(); err != nil {
		client.mu.Unlock()
		t.Fatal(err)
	}
	client.mu.Unlock()
	t.Cleanup(func() { machineNodeControlClients.Delete(statePath) })
	ctx := withMachineHubContext(context.Background(), machineHubContext{HubID: hubID, Origin: origin,
		NodeID: nodeID, StateDir: stateDir, Token: token, WriterRoot: stateDir, WriterScope: "synthetic-account"})
	binding := nodewire.Binding{HubID: hubID, NodeID: nodeID, BindingID: "binding-recovery-test",
		BindingVersion: 1, NodeKeyEpoch: 1, NodeKeyVersion: 1, HubKeyVersion: 1,
		NodeKey: nodeKey.Public(), HubKey: hubKey.Public()}
	return client, ctx, hubKey, binding
}

func TestMachineNodeControlRetriesExactPacketAndKeepsSignedInProgress(t *testing.T) {
	var mu sync.Mutex
	var packets [][]byte
	var hubKey *e2ee.Identity
	var binding nodewire.Binding
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		packet, err := ioReadAllBounded(request)
		if err != nil {
			t.Errorf("read request packet: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		packets = append(packets, append([]byte(nil), packet...))
		attempt := len(packets)
		mu.Unlock()
		if attempt == 1 {
			response.WriteHeader(http.StatusServiceUnavailable) // Simulated lost post-dispatch response.
			return
		}
		decoded, err := nodewire.OpenRequest(hubKey, binding.NodeKey, binding, packet)
		if err != nil {
			t.Errorf("open exact retry packet: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		code := "IN_PROGRESS"
		var body []byte
		if attempt == 2 {
			body = nodeControlTestEnvelope(t, decoded.Route, false, nil, code)
		} else {
			body = nodeControlTestEnvelope(t, decoded.Route, true, map[string]any{"ok": true}, "")
		}
		responseRoute := nodeControlTestResponseRoute(decoded.Route)
		sealed, err := nodewire.SealResponse(hubKey, binding.NodeKey, binding, responseRoute, body)
		if err != nil {
			t.Errorf("seal response: %v", err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(sealed)
	}))
	defer server.Close()
	client, ctx, hubKey, binding := newMachineNodeControlRecoveryFixture(t, server.URL)
	token := "synthetic-node-token"
	input := struct {
		Status string `json:"status"`
	}{Status: "available"}
	if err := client.call(ctx, token, "node.heartbeat", input, nil); err == nil {
		t.Fatal("first request did not simulate a lost HTTP response")
	}
	client.mu.Lock()
	firstPacket := append([]byte(nil), client.state.PendingPacket...)
	client.mu.Unlock()
	if len(firstPacket) == 0 {
		t.Fatal("lost response cleared the durable exact outbox")
	}
	if err := client.call(ctx, token, "node.heartbeat", input, nil); !errors.Is(err, errMachineNodeControlInProgress) {
		t.Fatalf("signed IN_PROGRESS was not surfaced as retryable: %v", err)
	}
	client.mu.Lock()
	if !bytes.Equal(client.state.PendingPacket, firstPacket) || len(client.state.PendingOperationID) == 0 {
		client.mu.Unlock()
		t.Fatal("signed IN_PROGRESS discarded or changed the exact request packet")
	}
	client.mu.Unlock()
	if err := client.call(ctx, token, "node.heartbeat", input, nil); err != nil {
		t.Fatalf("exact retry did not complete: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(packets) != 3 || !bytes.Equal(packets[0], packets[1]) || !bytes.Equal(packets[1], packets[2]) ||
		!bytes.Equal(packets[0], firstPacket) {
		t.Fatal("retry regenerated the Node-Control packet or operation identity")
	}
}

func TestMachineNodeControlClaimTicketSurvivesRestartWithoutPlaintextState(t *testing.T) {
	t.Setenv("CICADA_NODE_RESOURCE_ID", "gpu/0")
	var hubKey *e2ee.Identity
	var binding nodewire.Binding
	var mu sync.Mutex
	var packets [][]byte
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		packet, err := ioReadAllBounded(request)
		if err != nil {
			t.Errorf("read request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		opened, err := nodewire.OpenRequest(hubKey, binding.NodeKey, binding, packet)
		if err != nil || opened.Route.Operation != "node.jobs.claim" {
			t.Errorf("invalid claim request: route=%#v err=%v", opened.Route, err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		packets = append(packets, append([]byte(nil), packet...))
		attempt := len(packets)
		mu.Unlock()
		if attempt == 1 {
			response.WriteHeader(http.StatusServiceUnavailable) // Claim committed; reply was lost.
			return
		}
		job := map[string]any{"worker_id": "worker-recovered", "goal_id": "goal-a",
			"machine_id": "node-recovery-test", "harness": "codex", "workspace_id": "workspace-a",
			"workspace": "/workspace/workspace-a", "response_file": "/workspace/workspace-a/response.txt",
			"thread_id": "thread-a", "prompt": "synthetic private prompt",
			"resources": map[string]any{"physical_resource_id": "gpu/0"}, "attempt": 4}
		body := nodeControlTestEnvelope(t, opened.Route, true, job, "")
		sealed, err := nodewire.SealResponse(hubKey, binding.NodeKey, binding,
			nodeControlTestResponseRoute(opened.Route), body)
		if err != nil {
			t.Errorf("seal claim response: %v", err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = response.Write(sealed)
	}))
	defer server.Close()
	client, ctx, hubKey, binding := newMachineNodeControlRecoveryFixture(t, server.URL)
	if err := os.Chmod(client.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	providerLedger, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(client.stateDir, "provider-admission.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer providerLedger.Close()
	resourceManager, err := nodelock.OpenResourceExecutionManager(client.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	hubContext, ok := machineHubFrom(ctx)
	if !ok {
		t.Fatal("recovery fixture lacks its trusted Hub context")
	}
	hubContext.ProviderAdmissions, hubContext.ResourceExecutions = providerLedger, resourceManager
	ctx = withMachineHubContext(ctx, hubContext)
	if err := client.call(ctx, "synthetic-node-token", "node.jobs.claim",
		map[string]string{"worker_id": "worker-recovered"}, nil); err == nil {
		t.Fatal("claim fixture did not simulate losing its first response")
	}
	if err := client.recoverPending(ctx, "synthetic-node-token"); err != nil {
		t.Fatalf("recover exact pending claim: %v", err)
	}
	statePath := client.statePath
	client.mu.Lock()
	stateBytes, err := os.ReadFile(statePath)
	client.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateBytes, []byte("synthetic private prompt")) {
		t.Fatal("Node persisted the decrypted Worker prompt instead of the sealed claim response")
	}
	machineNodeControlClients.Delete(statePath)
	reopened, err := openMachineNodeControlClient(client.stateDir, server.URL, client.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.claimTicketJob()
	if err != nil || recovered == nil || recovered.WorkerID != "worker-recovered" || recovered.Attempt != 4 ||
		recovered.Prompt != "synthetic private prompt" {
		t.Fatalf("sealed claim ticket did not recover exact job: %#v err=%v", recovered, err)
	}
	// Establish the provider generation durably before forcing the later
	// resource-fence write to fail. This keeps the test focused on the resource
	// fence window; the separate generation-fence test covers a crash between
	// ledger Admit and persisting ProviderAttempt.
	reopened.mu.Lock()
	providerIntent := reopened.state.ClaimTicket.ProviderAdmissionIntent
	reopened.mu.Unlock()
	providerDecision, err := providerLedger.AdmitProviderAttempt(ctx, nodeinbox.ProviderAdmissionRequest{
		ExecutionID: recovered.executionID, ProviderID: recovered.providerID, AdmissionIntent: providerIntent})
	if err != nil || providerDecision == nil || !providerDecision.Admitted || providerDecision.Attempt <= 0 {
		t.Fatalf("admit recovered provider generation: decision=%#v err=%v", providerDecision, err)
	}
	reopened.mu.Lock()
	reopened.state.ClaimTicket.ProviderAttempt = providerDecision.Attempt
	if err := reopened.persistLocked(); err != nil {
		reopened.mu.Unlock()
		t.Fatal(err)
	}
	reopened.mu.Unlock()
	recovered.providerAttempt = providerDecision.Attempt
	originalStatePath := reopened.statePath
	stateBytesBeforeFence, err := os.ReadFile(originalStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateBytesBeforeFence, []byte("synthetic private prompt")) {
		t.Fatal("Node persisted the decrypted Worker prompt with the provider generation")
	}
	blockedParent := filepath.Join(client.stateDir, "blocked-parent")
	if err := os.WriteFile(blockedParent, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened.statePath = filepath.Join(blockedParent, "node-control.json")
	if _, _, err := prepareMachineNodeClaimExecution(ctx, reopened, *recovered); err == nil {
		t.Fatal("claim preparation succeeded after its durable fence write was forced to fail")
	}
	reopened.mu.Lock()
	if reopened.state.ClaimTicket == nil || reopened.state.ClaimTicket.ResourceID != "" ||
		reopened.state.ClaimTicket.FencingEpoch != 0 {
		reopened.mu.Unlock()
		t.Fatal("failed fence persistence left an in-memory resource fence")
	}
	reopened.statePath = originalStatePath
	reopened.mu.Unlock()
	diskAfterFailedFence, err := os.ReadFile(originalStatePath)
	if err != nil || !bytes.Equal(stateBytesBeforeFence, diskAfterFailedFence) {
		t.Fatalf("failed fence persistence changed durable ticket bytes: err=%v", err)
	}
	prepared, admission, err := prepareMachineNodeClaimExecution(ctx, reopened, *recovered)
	if err != nil || admission == nil || !admission.Admitted {
		t.Fatalf("prepare recovered claim with the current Node execution fence: admission=%#v err=%v", admission, err)
	}
	if err := reopened.beginClaimExecution(prepared); err != nil {
		t.Fatal(err)
	}
	machineNodeControlClients.Delete(statePath)
	restarted, err := openMachineNodeControlClient(client.stateDir, server.URL, client.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.claimTicketJob(); err == nil {
		t.Fatal("restart treated an EXECUTING ticket as permission to dispatch the Worker again")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(packets) != 2 || !bytes.Equal(packets[0], packets[1]) {
		t.Fatal("lost claim response was retried with a regenerated packet")
	}
}

func TestMachineNodeOrdinaryWorkersRunSequentiallyWhileUnrelatedResourceIsQuarantined(t *testing.T) {
	t.Setenv("CICADA_NODE_RESOURCE_ID", "")
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, server.URL)
	if err := os.Chmod(client.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	providerLedger, err := nodeinbox.OpenProviderAdmissionLedger(
		filepath.Join(client.stateDir, "node-provider-admission.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer providerLedger.Close()
	resourceManager, err := nodelock.OpenResourceExecutionManager(client.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	held, err := resourceManager.Begin(nodelock.ResourceExecutionRequest{ResourceID: "gpu/0",
		LeaseID: "lease-held-gpu", FencingEpoch: 1, ExecutionID: "exec-held-gpu"})
	if err != nil {
		t.Fatal(err)
	}
	if err := held.MarkStarted(); err != nil {
		t.Fatal(err)
	}
	if err := held.QuarantineStopUnverified(); err != nil {
		t.Fatal(err)
	}
	hub, _ := machineHubFrom(ctx)
	hub.ProviderAdmissions, hub.ResourceExecutions = providerLedger, resourceManager
	ctx, cancel := context.WithTimeout(withMachineHubContext(ctx, hub), 5*time.Second)
	defer cancel()

	for index := 1; index <= 2; index++ {
		suffix := strconv.Itoa(index)
		job := machineJob{WorkerID: "ordinary-worker-" + suffix, Attempt: 1,
			MachineID: "node-recovery-test", Harness: "shell", Resources: map[string]any{},
			executionID: "ordinary-execution-" + suffix, providerID: "shell", leaseID: "ordinary-lease-" + suffix}
		if err := installMachineNodeRecoveryClaimTicket(client, job); err != nil {
			t.Fatal(err)
		}
		prepared, admission, err := prepareMachineNodeClaimExecution(ctx, client, job)
		if err != nil || admission == nil || !admission.Admitted || prepared.resourceID != "" || prepared.fencingEpoch != 0 {
			t.Fatalf("ordinary Worker %s acquired or inherited a physical resource fence: prepared=%#v admission=%#v err=%v",
				job.WorkerID, prepared, admission, err)
		}
		if err := client.beginClaimExecution(prepared); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMachineNodeOrdinaryWorkerCommandHelper$")
		command.Env = append(os.Environ(), "CICADA_ORDINARY_WORKER_HELPER=1")
		waitErr, stopErr, started := runMachineNodeResourceCommand(ctx, prepared, command)
		if !started || waitErr != nil || stopErr != nil {
			t.Fatalf("ordinary Worker %s could not execute while gpu/0 was quarantined: started=%v wait=%v stop=%v",
				job.WorkerID, started, waitErr, stopErr)
		}
		result := machineJobResult{Status: "completed", Summary: "synthetic ordinary Worker completed",
			providerStarted: started}
		if err := recordMachineNodeProviderOutcome(ctx, prepared, result); err != nil {
			t.Fatalf("record ordinary Worker %s outcome: %v", job.WorkerID, err)
		}
		if err := client.finishClaimExecution(prepared); err != nil {
			t.Fatal(err)
		}
		client.mu.Lock()
		pendingTicket := client.state.ClaimTicket != nil
		client.mu.Unlock()
		if pendingTicket {
			t.Fatalf("ordinary Worker %s left the Node singleton claim ticket occupied", job.WorkerID)
		}
	}
	if _, err := resourceManager.Begin(nodelock.ResourceExecutionRequest{ResourceID: "gpu/0",
		LeaseID: "lease-next-gpu", FencingEpoch: 2, ExecutionID: "exec-next-gpu"}); !errors.Is(err, nodelock.ErrResourceExecutionBusy) {
		t.Fatalf("ordinary work released the unrelated quarantined physical resource: %v", err)
	}
}

func TestMachineNodeOrdinaryWorkerCommandHelper(t *testing.T) {
	if os.Getenv("CICADA_ORDINARY_WORKER_HELPER") != "1" {
		return
	}
}

func TestMachineNodeRejectsPhysicalResourceOutsideOperatorMapping(t *testing.T) {
	t.Setenv("CICADA_NODE_RESOURCE_ID", "gpu/0")
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, server.URL)
	if err := os.Chmod(client.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	providerLedger, err := nodeinbox.OpenProviderAdmissionLedger(
		filepath.Join(client.stateDir, "node-provider-admission.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer providerLedger.Close()
	resourceManager, err := nodelock.OpenResourceExecutionManager(client.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	hub, _ := machineHubFrom(ctx)
	hub.ProviderAdmissions, hub.ResourceExecutions = providerLedger, resourceManager
	ctx = withMachineHubContext(ctx, hub)
	job := machineJob{WorkerID: "mismapped-resource-worker", Attempt: 1,
		MachineID: "node-recovery-test", Harness: "shell",
		Resources:   map[string]any{"physical_resource_id": "gpu/1"},
		executionID: "mismapped-resource-execution", providerID: "shell", leaseID: "mismapped-resource-lease"}
	if err := installMachineNodeRecoveryClaimTicket(client, job); err != nil {
		t.Fatal(err)
	}
	prepared, admission, err := prepareMachineNodeClaimExecution(ctx, client, job)
	if !errors.Is(err, errMachineNodePhysicalResourceClaim) || admission == nil || !admission.Admitted ||
		prepared.resourceID != "" || prepared.fencingEpoch != 0 {
		t.Fatalf("Node trusted mapping did not reject a fake Hub resource ID: prepared=%#v admission=%#v err=%v",
			prepared, admission, err)
	}
}

func installMachineNodeRecoveryClaimTicket(client *machineNodeControlClient, job machineJob) error {
	intent, err := newMachineNodeProviderAdmissionIntent()
	if err != nil {
		return err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.state.ClaimTicket = &machineNodeControlClaimTicket{
		Version:  machineNodeControlClaimTicketVersion,
		WorkerID: job.WorkerID, Attempt: job.Attempt, Phase: "READY",
		BindingID: client.state.BindingID, BindingVersion: client.state.BindingVersion,
		NodeKeyEpoch: client.state.NodeKeyEpoch, ExecutionID: job.executionID,
		ProviderID: job.providerID, ProviderAdmissionIntent: intent, LeaseID: job.leaseID,
	}
	return client.persistLocked()
}

func ioReadAllBounded(request *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(request.Body, int64(nodewire.MaxRequestPacketBytes)+1))
}

func nodeControlTestResponseRoute(request nodewire.Route) nodewire.Route {
	request.Direction = nodewire.DirectionResponse
	request.SenderKeyID, request.ReceiverKeyID = request.ReceiverKeyID, request.SenderKeyID
	request.SenderKeyVersion, request.ReceiverKeyVersion = request.ReceiverKeyVersion, request.SenderKeyVersion
	return request
}

func nodeControlTestEnvelope(t *testing.T, route nodewire.Route, ok bool, result any, code string) []byte {
	t.Helper()
	value := map[string]any{"ok": ok, "operation_id": route.OperationID, "sequence": route.Sequence}
	if ok {
		value["result"] = result
	} else {
		value["error_code"] = code
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
