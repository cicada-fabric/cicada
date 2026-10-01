package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

func TestMachineNodeProviderAttemptGenerationPersistsAndFencesLocalTicket(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, server.URL)
	if err := os.Chmod(client.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(client.stateDir, "provider-admission.sqlite3")
	ledger, err := nodeinbox.OpenProviderAdmissionLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	hub, _ := machineHubFrom(ctx)
	hub.ProviderAdmissions = ledger
	ctx = withMachineHubContext(ctx, hub)
	job := machineJob{WorkerID: "worker-provider-attempt", Attempt: 3,
		MachineID: client.nodeID, Harness: "shell", Resources: map[string]any{},
		executionID: "execution-provider-attempt", providerID: "shell", leaseID: "lease-provider-attempt"}
	if err := installMachineNodeRecoveryClaimTicket(client, job); err != nil {
		t.Fatal(err)
	}

	prepared, decision, err := prepareMachineNodeClaimExecution(ctx, client, job)
	if err != nil || decision == nil || !decision.Admitted || decision.Attempt != 1 || prepared.providerAttempt != 1 {
		t.Fatalf("provider generation did not flow from admission into prepared job: prepared=%#v decision=%#v err=%v",
			prepared, decision, err)
	}
	client.mu.Lock()
	persistedAttempt := client.state.ClaimTicket.ProviderAttempt
	client.mu.Unlock()
	if persistedAttempt != decision.Attempt {
		t.Fatalf("ticket generation was not durably persisted: ticket=%d admitted=%d", persistedAttempt, decision.Attempt)
	}
	if err := client.beginClaimExecution(prepared); err != nil {
		t.Fatal(err)
	}

	stale := prepared
	stale.providerAttempt++
	if err := recordMachineNodeProviderOutcome(ctx, stale, machineJobResult{Status: "completed"}); !errors.Is(err, nodeinbox.ErrProviderAdmissionStaleAttempt) {
		t.Fatalf("delayed local result with a different provider generation was accepted: %v", err)
	}
	if err := client.finishClaimExecution(stale); err == nil {
		t.Fatal("stale completion cleared the current durable claim ticket")
	}
	client.mu.Lock()
	stillExecuting := client.state.ClaimTicket != nil && client.state.ClaimTicket.Phase == "EXECUTING" &&
		client.state.ClaimTicket.ProviderAttempt == decision.Attempt
	client.mu.Unlock()
	if !stillExecuting {
		t.Fatal("stale completion changed the durable claim state")
	}

	if err := recordMachineNodeProviderOutcome(ctx, prepared, machineJobResult{Status: "completed"}); err != nil {
		t.Fatal(err)
	}
	if err := client.finishClaimExecution(prepared); err != nil {
		t.Fatalf("exact provider generation could not finish its ticket: %v", err)
	}
}

func TestMachineNodePositiveGenerationValidationDoesNotAdvanceBackoff(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, server.URL)
	if err := os.Chmod(client.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(client.stateDir, "provider-admission.sqlite3")
	ledger, err := nodeinbox.OpenProviderAdmissionLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	hub, _ := machineHubFrom(ctx)
	hub.ProviderAdmissions = ledger
	ctx = withMachineHubContext(ctx, hub)
	job := machineJob{WorkerID: "worker-positive-generation", Attempt: 2,
		MachineID: client.nodeID, Harness: "shell", Resources: map[string]any{},
		executionID: "execution-positive-generation", providerID: "shell", leaseID: "lease-positive-generation"}
	if err := installMachineNodeRecoveryClaimTicket(client, job); err != nil {
		t.Fatal(err)
	}
	prepared, decision, err := prepareMachineNodeClaimExecution(ctx, client, job)
	if err != nil || decision == nil || decision.Attempt != 1 || prepared.providerAttempt != 1 {
		t.Fatalf("initial generation was not durably established: prepared=%#v decision=%#v err=%v", prepared, decision, err)
	}
	client.mu.Lock()
	originalIntent := client.state.ClaimTicket.ProviderAdmissionIntent
	client.mu.Unlock()
	if _, err := ledger.RecordProviderAdmissionOutcome(context.Background(), nodeinbox.ProviderAdmissionOutcome{
		ExecutionID: job.executionID, ProviderID: job.providerID,
		Attempt: 1, Class: nodeinbox.ProviderOutcomeRetryableNotInjected,
	}); err != nil {
		t.Fatal(err)
	}
	ledgerDB, err := sql.Open("sqlite", ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ledgerDB.Close()
	_, err = ledgerDB.ExecContext(context.Background(), `UPDATE node_provider_admission_v1
SET next_retry_at_ms=0 WHERE execution_id=? AND provider_id=?`, job.executionID, job.providerID)
	if err != nil {
		t.Fatal(err)
	}

	// A stale READY ticket with a positive generation and a different valid
	// intent must be rejected by Inspect before it can advance BACKOFF.
	wrongIntent, err := newMachineNodeProviderAdmissionIntent()
	if err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	client.state.ClaimTicket.ProviderAdmissionIntent = wrongIntent
	if err := client.persistLocked(); err != nil {
		client.mu.Unlock()
		t.Fatal(err)
	}
	client.mu.Unlock()
	if _, _, err := prepareMachineNodeClaimExecution(ctx, client, prepared); !errors.Is(err, nodeinbox.ErrProviderAdmissionIntentMismatch) {
		t.Fatalf("mismatched positive generation did not fail before admission: %v", err)
	}
	after, err := ledger.InspectProviderAttempt(context.Background(), nodeinbox.ProviderAdmissionRequest{
		ExecutionID: job.executionID, ProviderID: job.providerID, AdmissionIntent: originalIntent})
	if err != nil || after == nil || after.State != nodeinbox.ProviderAdmissionBackoff || after.Attempt != 1 {
		t.Fatalf("rejected positive ticket advanced or changed the sidecar generation: decision=%#v err=%v", after, err)
	}
	var intentRows int
	if err := ledgerDB.QueryRowContext(context.Background(), `SELECT count(*) FROM node_provider_admission_intents_v1
WHERE execution_id=? AND provider_id=?`, job.executionID, job.providerID).Scan(&intentRows); err != nil || intentRows != 1 {
		t.Fatalf("rejected ticket changed intent bindings: rows=%d err=%v", intentRows, err)
	}
}

func TestMachineNodeRecoveryDoesNotInferLostProviderTicketGeneration(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, server.URL)
	if err := os.Chmod(client.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(client.stateDir, "provider-admission.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	hub, _ := machineHubFrom(ctx)
	hub.ProviderAdmissions = ledger
	ctx = withMachineHubContext(ctx, hub)
	job := machineJob{WorkerID: "worker-lost-provider-generation", Attempt: 5,
		MachineID: client.nodeID, Harness: "shell", Resources: map[string]any{},
		executionID: "execution-lost-provider-generation", providerID: "shell", leaseID: "lease-lost-provider-generation"}
	if err := installMachineNodeRecoveryClaimTicket(client, job); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	intent := client.state.ClaimTicket.ProviderAdmissionIntent
	originalStatePath := client.statePath
	client.mu.Unlock()
	if !validMachineNodeProviderAdmissionIntent(intent) {
		t.Fatal("sealed claim ticket did not durably carry a local provider admission intent")
	}

	// Force only the generation-ticket write to fail. The sidecar Admit still
	// commits; reloading the old READY ticket must recover only by its exact
	// previously persisted intent.
	blockedStatePath := filepath.Join(client.stateDir, "blocked-state-path")
	if err := os.Mkdir(blockedStatePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockedStatePath, "occupied"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	client.statePath = blockedStatePath
	_, decision, err := prepareMachineNodeClaimExecution(ctx, client, job)
	client.statePath = originalStatePath
	if err == nil || decision != nil {
		t.Fatalf("forced generation persistence failure was not returned: decision=%#v err=%v", decision, err)
	}
	admitted, err := ledger.InspectProviderAttempt(context.Background(), nodeinbox.ProviderAdmissionRequest{
		ExecutionID: job.executionID, ProviderID: job.providerID,
	})
	if err != nil || admitted == nil || admitted.Attempt != 1 || admitted.State != nodeinbox.ProviderAdmissionInProgress {
		t.Fatalf("sidecar admission was not committed before local write failure: decision=%#v err=%v", admitted, err)
	}

	reloadedState, err := readMachineNodeControlLocalState(client.stateDir, client.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if reloadedState.ClaimTicket == nil || reloadedState.ClaimTicket.ProviderAttempt != 0 ||
		reloadedState.ClaimTicket.Phase != "READY" || reloadedState.ClaimTicket.ProviderAdmissionIntent != intent {
		t.Fatal("failed generation write did not leave the exact intent-bound READY ticket on disk")
	}
	recovered := &machineNodeControlClient{stateDir: client.stateDir, statePath: originalStatePath,
		base: client.base, nodeID: client.nodeID, identity: client.identity, state: reloadedState}
	prepared, decision, err := prepareMachineNodeClaimExecution(ctx, recovered, job)
	if err != nil || decision == nil || !decision.Admitted || decision.Attempt != 1 || prepared.providerAttempt != 1 {
		t.Fatalf("exact persisted intent did not recover the same generation after reload: prepared=%#v decision=%#v err=%v",
			prepared, decision, err)
	}
	if err := recovered.beginClaimExecution(prepared); err != nil {
		t.Fatalf("recovered exact READY ticket could not begin after persisting its generation: %v", err)
	}
	if _, _, err := prepareMachineNodeClaimExecution(ctx, recovered, prepared); err == nil {
		t.Fatal("EXECUTING claim ticket was re-admitted for a second provider execution")
	}
	if _, err := ledger.RecordProviderAdmissionOutcome(context.Background(), nodeinbox.ProviderAdmissionOutcome{
		ExecutionID: job.executionID, ProviderID: job.providerID,
		Attempt: decision.Attempt, Class: nodeinbox.ProviderOutcomeFailedNotInjected,
	}); err != nil {
		t.Fatalf("close synthetic recovered admission after execution fence: %v", err)
	}
	if err := recovered.finishClaimExecution(prepared); err != nil {
		t.Fatalf("finish exact recovered claim: %v", err)
	}

	legacyJob := job
	legacyJob.WorkerID = "worker-legacy-ticket"
	legacyJob.executionID = "execution-legacy-provider-ticket"
	legacyJob.leaseID = "lease-legacy-provider-ticket"
	client.mu.Lock()
	client.state.ClaimTicket = &machineNodeControlClaimTicket{
		// Version one has no provider admission intent and cannot be upgraded by
		// attaching a current sidecar generation.
		Version:  machineNodeControlLegacyClaimTicketVersion,
		WorkerID: legacyJob.WorkerID, Attempt: legacyJob.Attempt, Phase: "READY",
		BindingID: client.state.BindingID, BindingVersion: client.state.BindingVersion,
		NodeKeyEpoch: client.state.NodeKeyEpoch, ExecutionID: legacyJob.executionID,
		ProviderID: legacyJob.providerID, LeaseID: legacyJob.leaseID,
	}
	if err := client.persistLocked(); err != nil {
		client.mu.Unlock()
		t.Fatal(err)
	}
	client.mu.Unlock()
	if _, _, err := prepareMachineNodeClaimExecution(ctx, client, legacyJob); err == nil {
		t.Fatal("legacy intentless ticket was automatically upgraded for execution")
	}
	if _, err := ledger.InspectProviderAttempt(context.Background(), nodeinbox.ProviderAdmissionRequest{
		ExecutionID: legacyJob.executionID, ProviderID: legacyJob.providerID,
	}); !errors.Is(err, nodeinbox.ErrProviderAdmissionUnknown) {
		t.Fatalf("legacy ticket guard created provider state before rejecting: %v", err)
	}
}

func TestMachineNodeOperatorReconciliationUsesTicketProviderGeneration(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client, _, _, _ := newMachineNodeControlRecoveryFixture(t, server.URL)
	if err := os.Chmod(client.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(client.stateDir, "node-provider-admission.sqlite3")
	ledger, err := nodeinbox.OpenProviderAdmissionLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := newMachineNodeProviderAdmissionIntent()
	if err != nil {
		t.Fatal(err)
	}
	request := nodeinbox.ProviderAdmissionRequest{ExecutionID: "operator-execution", ProviderID: "codex",
		AdmissionIntent: intent}
	admitted, err := ledger.AdmitProviderAttempt(context.Background(), request)
	if err != nil || admitted == nil || admitted.Attempt != 1 || !admitted.Admitted {
		t.Fatalf("admit operator fixture attempt: decision=%#v err=%v", admitted, err)
	}
	uncertain, err := ledger.RecordProviderAdmissionOutcome(context.Background(), nodeinbox.ProviderAdmissionOutcome{
		ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
		Attempt: admitted.Attempt, Class: nodeinbox.ProviderOutcomeInjectionUncertain,
	})
	if err != nil || uncertain == nil || uncertain.State != nodeinbox.ProviderAdmissionInjectionUncertain {
		t.Fatalf("mark operator fixture uncertain: decision=%#v err=%v", uncertain, err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	resourceManager, err := nodelock.OpenResourceExecutionManager(client.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	resourceRequest := nodelock.ResourceExecutionRequest{ResourceID: "gpu/19", LeaseID: "operator-lease",
		FencingEpoch: 9, ExecutionID: request.ExecutionID}
	execution, err := resourceManager.Begin(resourceRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.MarkStarted(); err != nil {
		t.Fatal(err)
	}
	verifier := nodelock.ResourceStopVerifier(func(record nodelock.ResourceExecutionRecord) (nodelock.ResourceStopReceipt, error) {
		return nodelock.ResourceStopReceipt{ResourceID: record.ResourceID, LeaseID: record.LeaseID,
			FencingEpoch: record.FencingEpoch, ExecutionID: record.ExecutionID,
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
	})
	if err := execution.ConfirmStopped(verifier); err != nil {
		t.Fatal(err)
	}
	if err := execution.Close(); err != nil {
		t.Fatal(err)
	}

	client.mu.Lock()
	client.state.ClaimTicket = &machineNodeControlClaimTicket{
		Version:  machineNodeControlClaimTicketVersion,
		WorkerID: "operator-worker", Attempt: 4, Phase: "EXECUTING",
		BindingID: client.state.BindingID, BindingVersion: client.state.BindingVersion,
		NodeKeyEpoch: client.state.NodeKeyEpoch, ExecutionID: request.ExecutionID,
		ProviderID: request.ProviderID, ProviderAttempt: admitted.Attempt,
		ProviderAdmissionIntent: intent,
		ResourceID:              resourceRequest.ResourceID, LeaseID: resourceRequest.LeaseID,
		FencingEpoch: resourceRequest.FencingEpoch,
	}
	if err := client.persistLocked(); err != nil {
		client.mu.Unlock()
		t.Fatal(err)
	}
	client.mu.Unlock()

	args := []string{"reconcile-provider", "--state-dir", client.stateDir, "--writer-root", client.stateDir,
		"--node-id", client.nodeID, "--resolution", nodeinbox.ProviderReconcileCompleted,
		"--idempotency-key", "operator-key-exact", "--evidence-id", "operator-stop-observation",
		"--observed-at", time.Now().UTC().Format(time.RFC3339Nano)}
	client.mu.Lock()
	client.state.ClaimTicket.ProviderAttempt = admitted.Attempt + 1
	if err := client.persistLocked(); err != nil {
		client.mu.Unlock()
		t.Fatal(err)
	}
	client.mu.Unlock()
	if err := machineNodeControlOperatorCommand(args, nil); !errors.Is(err, nodeinbox.ErrProviderAdmissionStaleAttempt) {
		t.Fatalf("operator substituted current ledger generation for a stale ticket: %v", err)
	}
	ledger, err = nodeinbox.OpenProviderAdmissionLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := ledger.InspectProviderAttempt(context.Background(), request)
	if err != nil || decision.State != nodeinbox.ProviderAdmissionInjectionUncertain || decision.Attempt != admitted.Attempt {
		_ = ledger.Close()
		t.Fatalf("stale operator ticket changed uncertain generation: decision=%#v err=%v", decision, err)
	}
	_ = ledger.Close()

	client.mu.Lock()
	client.state.ClaimTicket.ProviderAttempt = admitted.Attempt
	if err := client.persistLocked(); err != nil {
		client.mu.Unlock()
		t.Fatal(err)
	}
	client.mu.Unlock()
	var report machineNodeControlOperatorReport
	var output bytes.Buffer
	if err := machineNodeControlOperatorCommand(args, &output); err != nil {
		t.Fatalf("operator could not reconcile exact ticket generation: %v", err)
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.Provider == nil ||
		report.Provider.State != nodeinbox.ProviderAdmissionCompleted || report.Provider.Attempt != admitted.Attempt {
		t.Fatalf("operator did not report exact reconciled generation: report=%#v err=%v", report, err)
	}
	output.Reset()
	if err := machineNodeControlOperatorCommand(args, &output); err != nil {
		t.Fatalf("exact operator response-loss replay failed: %v", err)
	}
}
