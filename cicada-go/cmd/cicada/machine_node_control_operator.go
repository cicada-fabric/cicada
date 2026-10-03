package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/nodebackup"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

const machineNodeControlOperatorUsage = "usage: cicada machine node-control inspect|mark-uncertain|reconcile-provider --state-dir DIR --node-id ID [--writer-root DIR]"

type machineNodeControlOperatorClaim struct {
	Version         int    `json:"version"`
	WorkerID        string `json:"worker_id"`
	Attempt         int    `json:"attempt"`
	Phase           string `json:"phase"`
	ExecutionID     string `json:"execution_id"`
	ProviderID      string `json:"provider_id"`
	ProviderAttempt int    `json:"provider_attempt,omitempty"`
	ResourceID      string `json:"resource_id,omitempty"`
	LeaseID         string `json:"lease_id"`
	FencingEpoch    int64  `json:"fencing_epoch,omitempty"`
}

type machineNodeControlOperatorReport struct {
	NodeID                string                               `json:"node_id"`
	HubID                 string                               `json:"hub_id,omitempty"`
	BindingID             string                               `json:"binding_id,omitempty"`
	BindingVersion        uint64                               `json:"binding_version,omitempty"`
	NodeKeyEpoch          uint64                               `json:"node_key_epoch,omitempty"`
	PendingOperation      string                               `json:"pending_operation,omitempty"`
	PendingSequence       uint64                               `json:"pending_sequence,omitempty"`
	Claim                 *machineNodeControlOperatorClaim     `json:"claim,omitempty"`
	Provider              *nodeinbox.ProviderAdmissionDecision `json:"provider_admission,omitempty"`
	Resource              *machineNodeControlOperatorResource  `json:"resource_execution,omitempty"`
	Action                string                               `json:"action,omitempty"`
	WriterRootQuarantined bool                                 `json:"writer_root_quarantined,omitempty"`
}

type machineNodeControlOperatorResource struct {
	ResourceID   string `json:"resource_id"`
	LeaseID      string `json:"lease_id"`
	FencingEpoch int64  `json:"fencing_epoch"`
	ExecutionID  string `json:"execution_id"`
	State        string `json:"state"`
}

func machineNodeControlOperatorCommand(args []string, output io.Writer) error {
	if output == nil {
		output = io.Discard
	}
	if len(args) == 0 {
		return errors.New(machineNodeControlOperatorUsage)
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	if action != "inspect" && action != "mark-uncertain" && action != "reconcile-provider" {
		return errors.New(machineNodeControlOperatorUsage)
	}
	flags := flag.NewFlagSet("machine node-control "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "private per-Hub Node state directory")
	writerRoot := flags.String("writer-root", "", "shared Node writer root (defaults to state-dir)")
	nodeID := flags.String("node-id", "", "Node ID")
	resolution := flags.String("resolution", "", "terminal provider resolution: COMPLETED_CONFIRMED or FAILED_TERMINAL_CONFIRMED")
	idempotencyKey := flags.String("idempotency-key", "", "independent stable key for retries of this exact reconciliation")
	evidenceID := flags.String("evidence-id", "", "opaque local evidence identifier for the operator decision")
	observedAt := flags.String("observed-at", "", "RFC3339Nano time when the operator verified the outcome")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("%s: %w", machineNodeControlOperatorUsage, err)
	}
	if len(flags.Args()) != 0 || strings.TrimSpace(*stateDir) == "" || strings.TrimSpace(*nodeID) == "" {
		return errors.New(machineNodeControlOperatorUsage)
	}
	if strings.TrimSpace(*writerRoot) == "" {
		*writerRoot = *stateDir
	}
	if err := rejectMachineRecoveryMutation(*stateDir, *writerRoot, *nodeID); err != nil {
		return err
	}
	var err error
	var agentLock *nodelock.AgentLock
	if action != "inspect" {
		agentLock, err = nodelock.AcquireAgent(*stateDir, *nodeID)
		if err != nil {
			return errors.New("stop the Node Agent before operator reconciliation; its execution ownership is still active")
		}
		defer agentLock.Close()
	} else {
		maintenance, err := nodelock.AcquireMaintenance(*stateDir, *nodeID)
		if err != nil {
			return err
		}
		defer maintenance.Close()
	}
	writerRootLock, err := nodelock.AcquireWriterRoot(*writerRoot)
	if err != nil {
		return fmt.Errorf("acquire shared Node WriterRoot lock: %w", err)
	}
	defer writerRootLock.Close()
	if err := rejectMachineRecoveryMutation(*stateDir, *writerRoot, *nodeID); err != nil {
		return err
	}
	rootQuarantined, err := nodebackup.WriterRootRecoveryQuarantineActive(*writerRoot)
	if err != nil {
		return fmt.Errorf("inspect shared WriterRoot recovery quarantine: %w", err)
	}
	if rootQuarantined && action != "inspect" {
		return errors.New("shared WriterRoot is quarantined after restore; reconcile shared fences before operator writes")
	}
	state, err := readMachineNodeControlLocalState(*stateDir, *nodeID)
	if err != nil {
		return err
	}
	report := machineNodeControlOperatorReport{NodeID: state.NodeID, HubID: state.HubID,
		BindingID: state.BindingID, BindingVersion: state.BindingVersion, NodeKeyEpoch: state.NodeKeyEpoch,
		PendingOperation: state.PendingOperation, PendingSequence: state.PendingSequence,
		WriterRootQuarantined: rootQuarantined}
	if state.ClaimTicket != nil {
		ticket := state.ClaimTicket
		report.Claim = &machineNodeControlOperatorClaim{Version: ticket.Version, WorkerID: ticket.WorkerID, Attempt: ticket.Attempt,
			Phase: ticket.Phase, ExecutionID: ticket.ExecutionID, ProviderID: ticket.ProviderID,
			ProviderAttempt: ticket.ProviderAttempt,
			ResourceID:      ticket.ResourceID, LeaseID: ticket.LeaseID, FencingEpoch: ticket.FencingEpoch}
	}
	if action == "inspect" {
		if err := populateMachineNodeControlOperatorStatus(*writerRoot, state, &report); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(report)
	}
	if state.ClaimTicket == nil ||
		(state.ClaimTicket.Version != machineNodeControlClaimTicketVersion &&
			state.ClaimTicket.Version != machineNodeControlLegacyClaimTicketVersion) ||
		state.ClaimTicket.ExecutionID == "" || state.ClaimTicket.ProviderID == "" ||
		state.ClaimTicket.ProviderAttempt <= 0 {
		return errors.New("no exact durable Worker claim is available for explicit reconciliation")
	}
	if state.ClaimTicket.Version == machineNodeControlClaimTicketVersion &&
		!validMachineNodeProviderAdmissionIntent(state.ClaimTicket.ProviderAdmissionIntent) {
		return errors.New("new Worker claim lacks its durable provider admission intent")
	}
	ledger, err := openExistingMachineProviderAdmissionLedger(filepath.Join(*writerRoot, "node-provider-admission.sqlite3"))
	if err != nil {
		return err
	}
	defer ledger.Close()
	ctx := context.Background()
	request := nodeinbox.ProviderAdmissionRequest{ExecutionID: state.ClaimTicket.ExecutionID,
		ProviderID: state.ClaimTicket.ProviderID}
	if state.ClaimTicket.Version == machineNodeControlClaimTicketVersion {
		request.AdmissionIntent = state.ClaimTicket.ProviderAdmissionIntent
	}
	switch action {
	case "mark-uncertain":
		if state.ClaimTicket.Phase != "EXECUTING" {
			return errors.New("only an EXECUTING Worker claim can be explicitly marked uncertain")
		}
		if err := requireMachineNodeControlOperatorStop(*writerRoot, state.ClaimTicket); err != nil {
			return err
		}
		decision, err := ledger.RecordProviderAdmissionOutcome(ctx, nodeinbox.ProviderAdmissionOutcome{
			ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
			Attempt: state.ClaimTicket.ProviderAttempt,
			Class:   nodeinbox.ProviderOutcomeInjectionUncertain})
		if err != nil {
			return fmt.Errorf("record explicit uncertain provider outcome: %w", err)
		}
		report.Provider, report.Action = decision, "PROVIDER_MARKED_UNCERTAIN"
	case "reconcile-provider":
		if state.ClaimTicket.Phase != "EXECUTING" {
			return errors.New("provider reconciliation requires the exact EXECUTING Worker claim")
		}
		resolution := strings.TrimSpace(*resolution)
		if resolution != "COMPLETED_CONFIRMED" && resolution != "FAILED_TERMINAL_CONFIRMED" {
			return errors.New("--resolution must be COMPLETED_CONFIRMED or FAILED_TERMINAL_CONFIRMED")
		}
		evidenceID := strings.TrimSpace(*evidenceID)
		idempotencyKey := strings.TrimSpace(*idempotencyKey)
		if evidenceID == "" || len(evidenceID) > 512 || strings.ContainsAny(evidenceID, "\x00\r\n") ||
			idempotencyKey == "" || len(idempotencyKey) > 256 || strings.ContainsAny(idempotencyKey, "\x00\r\n") {
			return errors.New("--evidence-id and --idempotency-key must be bounded opaque operator identifiers")
		}
		if err := requireMachineNodeControlOperatorStop(*writerRoot, state.ClaimTicket); err != nil {
			return err
		}
		observed := strings.TrimSpace(*observedAt)
		parsed, err := time.Parse(time.RFC3339Nano, observed)
		if err != nil || parsed.IsZero() || parsed.After(time.Now().Add(time.Minute)) {
			return errors.New("--observed-at must be a valid, non-future RFC3339Nano time")
		}
		decision, err := ledger.ReconcileProviderInjectionUncertain(ctx, nodeinbox.ProviderAdmissionReconciliation{
			ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
			Attempt:    state.ClaimTicket.ProviderAttempt,
			Resolution: resolution, IdempotencyKey: idempotencyKey,
			EvidenceID: evidenceID, ObservedAt: parsed.UTC().Format(time.RFC3339Nano)})
		if err != nil {
			return fmt.Errorf("reconcile exact uncertain provider attempt: %w", err)
		}
		report.Provider, report.Action = decision, "PROVIDER_OUTCOME_TERMINALLY_RECONCILED"
	}
	// The durable claim ticket stays in place. This local decision never proves
	// Hub completion, clears a sealed result outbox, or authorizes a new attempt.
	return json.NewEncoder(output).Encode(report)
}

func requireMachineNodeControlOperatorStop(writerRoot string,
	ticket *machineNodeControlClaimTicket) error {
	if ticket == nil || ticket.ResourceID == "" || ticket.LeaseID == "" ||
		ticket.FencingEpoch <= 0 || ticket.ExecutionID == "" {
		return errors.New("exact physical-resource fence is missing; refusing operator reconciliation")
	}
	manager, err := nodelock.OpenResourceExecutionManager(writerRoot)
	if err != nil {
		return err
	}
	resource, err := manager.Inspect(ticket.ResourceID)
	if err != nil || resource == nil || resource.ResourceID != ticket.ResourceID ||
		resource.LeaseID != ticket.LeaseID || resource.FencingEpoch != ticket.FencingEpoch ||
		resource.ExecutionID != ticket.ExecutionID || resource.State != nodelock.ResourceExecutionStopConfirmed {
		return errors.New("physical-resource stop is not confirmed for this exact execution fence; refusing reconciliation")
	}
	return nil
}

func readMachineNodeControlLocalState(stateDir, nodeID string) (machineNodeControlState, error) {
	_, path := machineNodeControlPaths(stateDir, nodeID)
	info, err := os.Lstat(path)
	if err != nil {
		return machineNodeControlState{}, fmt.Errorf("inspect Node-Control recovery state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxMachineNodeControlStateBytes {
		return machineNodeControlState{}, errors.New("Node-Control recovery state is not a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return machineNodeControlState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state machineNodeControlState
	if err := decoder.Decode(&state); err != nil {
		return machineNodeControlState{}, fmt.Errorf("decode Node-Control recovery state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return machineNodeControlState{}, errors.New("Node-Control recovery state has trailing data")
	}
	if state.Version != machineNodeControlStateVersion || state.NodeID != nodeID || state.HubOrigin == "" {
		return machineNodeControlState{}, errors.New("Node-Control recovery state does not match the requested Node")
	}
	return state, nil
}

func openExistingMachineProviderAdmissionLedger(path string) (*nodeinbox.ProviderAdmissionLedger, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect shared provider admission ledger: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("shared provider admission ledger is not a regular file")
	}
	return nodeinbox.OpenProviderAdmissionLedger(path)
}

func populateMachineNodeControlOperatorStatus(writerRoot string, state machineNodeControlState,
	report *machineNodeControlOperatorReport) error {
	if report == nil || state.ClaimTicket == nil {
		return nil
	}
	ledger, err := openExistingMachineProviderAdmissionLedger(filepath.Join(writerRoot, "node-provider-admission.sqlite3"))
	if err == nil {
		decision, inspectErr := ledger.InspectProviderAttempt(context.Background(), nodeinbox.ProviderAdmissionRequest{
			ExecutionID: state.ClaimTicket.ExecutionID, ProviderID: state.ClaimTicket.ProviderID})
		_ = ledger.Close()
		if inspectErr == nil {
			report.Provider = decision
		} else if !errors.Is(inspectErr, nodeinbox.ErrProviderAdmissionUnknown) {
			return inspectErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if state.ClaimTicket.ResourceID != "" {
		manager, err := nodelock.OpenResourceExecutionManager(writerRoot)
		if err != nil {
			return err
		}
		record, inspectErr := manager.Inspect(state.ClaimTicket.ResourceID)
		if inspectErr == nil {
			report.Resource = &machineNodeControlOperatorResource{ResourceID: record.ResourceID,
				LeaseID: record.LeaseID, FencingEpoch: record.FencingEpoch,
				ExecutionID: record.ExecutionID, State: record.State}
		} else if !errors.Is(inspectErr, os.ErrNotExist) {
			return inspectErr
		}
	}
	return nil
}
