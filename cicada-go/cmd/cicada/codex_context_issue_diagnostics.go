package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"time"
)

// The existing private daemon stderr is the sole destination. This record is
// not an authorization result or an RPC: no raw error, native ID, credential,
// argument, nonce, ticket, path or protocol body is included.
type codexIssueFailureDiagnostic struct {
	Stage          string          `json:"stage"`
	Error          string          `json:"error"`
	StartedAt      string          `json:"started_at"`
	ObservedAt     string          `json:"observed_at"`
	BudgetMS       int64           `json:"original_budget_ms"`
	ElapsedMS      int64           `json:"elapsed_ms"`
	Snapshot       string          `json:"snapshot_status"`
	StateBytes     int             `json:"state_bytes,omitempty"`
	ManagedReserve int             `json:"managed_reserve_bytes,omitempty"`
	Limit          int             `json:"state_limit_bytes,omitempty"`
	RPCReserve     int             `json:"generic_rpc_reserve_bytes,omitempty"`
	Headroom       int             `json:"generic_rpc_headroom_bytes,omitempty"`
	Pending        map[string]bool `json:"pending_flags_15,omitempty"`
}

func codexIssueErrorEnum(err error) string {
	if err == nil {
		return "NONE"
	}
	var native *LocalCodexContextError
	if errors.As(err, &native) {
		switch native.Stage {
		case "ROOT", "PATH", "OWNERSHIP", "PERMISSION", "INODE", "METADATA", "SOURCE", "SESSION", "WORKSPACE":
			return "NATIVE_RECORD_" + native.Stage
		}
		return "NATIVE_RECORD_UNKNOWN"
	}
	var refusal *endpointGroupsNodeError
	if errors.As(err, &refusal) && endpointGroupsNodeCode(refusal.code) {
		return "HUB_" + refusal.code
	}
	for _, entry := range []struct {
		err  error
		code string
	}{
		{context.DeadlineExceeded, "DEADLINE_EXCEEDED"}, {context.Canceled, "CANCELED"}, {os.ErrDeadlineExceeded, "DEADLINE_EXCEEDED"},
		{errLocalEndpointHistoryFull, "ENDPOINT_LOCAL_HISTORY_FULL"}, {errLocalEndpointIntentConflict, "ENDPOINT_LOCAL_INTENT_CONFLICT"}, {errLocalEndpointReceiptExpired, "ENDPOINT_LOCAL_RECEIPT_EXPIRED"},
		{errEndpointGroupsOffline, "ENDPOINT_LOCAL_OFFLINE"}, {errEndpointGroupsUnsupported, "UNSUPPORTED_PROFILE"}, {errEndpointGroupsRegistration, "REGISTRATION_REJECTED"},
		{errMachineNodeControlOutcomeUncertain, "OUTCOME_UNCERTAIN"}, {errLocalCodexContext, "CONTEXT_UNSUPPORTED"}, {errLocalJoinBridgeUnavailable, "BRIDGE_UNAVAILABLE"},
	} {
		if errors.Is(err, entry.err) {
			return entry.code
		}
	}
	var path *os.PathError
	if errors.As(err, &path) {
		return "LOCAL_IO"
	}
	return "OTHER"
}
func (b *machineAgentJoinBridge) codexIssueFailureDiagnostic(stage string, err error, started, deadline time.Time) codexIssueFailureDiagnostic {
	switch stage {
	case "INPUT", "BINDING", "VERIFICATION", "TRANSCRIPT", "BUDGET", "ISSUE":
	default:
		stage = "UNKNOWN"
	}
	now := time.Now()
	d := codexIssueFailureDiagnostic{Stage: stage, Error: codexIssueErrorEnum(err), StartedAt: started.UTC().Format(time.RFC3339Nano), ObservedAt: now.UTC().Format(time.RFC3339Nano), BudgetMS: deadline.Sub(started).Milliseconds(), ElapsedMS: now.Sub(started).Milliseconds(), Snapshot: "NOT_CACHED"}
	_, path := machineNodeControlPaths(b.stateDir, b.nodeID)
	cached, ok := machineNodeControlClients.Load(path)
	if !ok {
		return d
	}
	c, ok := cached.(*machineNodeControlClient)
	if !ok || c == nil {
		return d
	}
	if !c.mu.TryLock() {
		d.Snapshot = "BUSY"
		return d
	}
	defer c.mu.Unlock()
	raw, marshalErr := json.Marshal(c.state)
	if marshalErr != nil {
		d.Snapshot = "ENCODING_UNAVAILABLE"
		return d
	}
	defer clear(raw)
	d.Snapshot = "AVAILABLE"
	d.StateBytes = len(raw)
	d.ManagedReserve = managedPairStateReserve(c.state)
	d.Limit = maxMachineNodeControlStateBytes
	d.RPCReserve = 2 << 20
	d.Headroom = d.Limit - d.StateBytes - d.ManagedReserve - d.RPCReserve
	s := c.state
	d.Pending = map[string]bool{"operation": s.PendingOperation != "", "operation_id": s.PendingOperationID != "", "sequence": s.PendingSequence != 0, "plaintext_digest": s.PendingPlaintextDigest != "", "packet": len(s.PendingPacket) > 0, "response": len(s.PendingResponsePacket) > 0, "local_intent": s.PendingLocalEndpointIntentID != "", "native_pair_body": len(s.PendingNativePairBody) > 0, "worker_id": s.PendingWorkerID != "", "worker_attempt": s.PendingWorkerAttempt != 0, "snapshot_path": s.PendingSnapshotPath != "", "snapshot_manifest": s.PendingSnapshotManifest != nil, "claim_ticket": s.ClaimTicket != nil, "endpoint_groups_diagnostic": s.EndpointGroupsDiagnostic != nil, "native_pair_diagnostic": s.NativePairDiagnostic != nil}
	return d
}
func (b *machineAgentJoinBridge) logCodexIssueFailure(stage string, err error, started, deadline time.Time) {
	d := b.codexIssueFailureDiagnostic(stage, err, started, deadline)
	raw, marshalErr := json.Marshal(d)
	if marshalErr != nil {
		return
	}
	log.Printf("CICADA_NODE_CONTEXT_ISSUE_FAILURE %s", raw)
}
