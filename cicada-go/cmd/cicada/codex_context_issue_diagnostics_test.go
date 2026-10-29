package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCodexIssueFailureDiagnosticClosedErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errLocalEndpointHistoryFull, "ENDPOINT_LOCAL_HISTORY_FULL"}, {fmt.Errorf("wrapped: %w", errLocalEndpointHistoryFull), "ENDPOINT_LOCAL_HISTORY_FULL"},
		{context.DeadlineExceeded, "DEADLINE_EXCEEDED"}, {context.Canceled, "CANCELED"}, {&LocalCodexContextError{Stage: "PERMISSION"}, "NATIVE_RECORD_PERMISSION"},
		{&LocalCodexContextError{Stage: "synthetic-private-native-id"}, "NATIVE_RECORD_UNKNOWN"}, {&endpointGroupsNodeError{code: "TARGET_NOT_AUTHORIZED"}, "HUB_TARGET_NOT_AUTHORIZED"},
		{errors.New("synthetic-private-secret"), "OTHER"},
	} {
		if got := codexIssueErrorEnum(tc.err); got != tc.want {
			t.Fatalf("closed diagnostic got=%s want=%s", got, tc.want)
		}
	}
}
func TestCodexIssueFailureDiagnosticReadOnlyAndBusy(t *testing.T) {
	const secret = "synthetic-private-secret-not-to-log"
	b := &machineAgentJoinBridge{stateDir: filepath.Join(t.TempDir(), secret), nodeID: secret}
	_, path := machineNodeControlPaths(b.stateDir, b.nodeID)
	c := &machineNodeControlClient{state: machineNodeControlState{NodeID: secret, PendingOperation: secret, PendingOperationID: secret, PendingSequence: 7, PendingPlaintextDigest: secret, PendingPacket: []byte(secret), PendingResponsePacket: []byte(secret), PendingLocalEndpointIntentID: secret, PendingNativePairBody: []byte(secret), PendingWorkerID: secret, PendingWorkerAttempt: 1, PendingSnapshotPath: secret}}
	machineNodeControlClients.Store(path, c)
	t.Cleanup(func() { machineNodeControlClients.Delete(path) })
	before, _ := json.Marshal(c.state)
	started := time.Now().Add(-20 * time.Millisecond)
	deadline := started.Add(30 * time.Second)
	d := b.codexIssueFailureDiagnostic(secret, errors.New(secret), started, deadline)
	raw, _ := json.Marshal(d)
	after, _ := json.Marshal(c.state)
	if string(before) != string(after) || d.Snapshot != "AVAILABLE" || d.Stage != "UNKNOWN" || d.Error != "OTHER" || len(d.Pending) != 15 || d.BudgetMS != 30000 || d.ElapsedMS < 20 || d.StateBytes != len(before) {
		t.Fatal("diagnostic changed state or misreported closed timing/snapshot")
	}
	for _, private := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret))} {
		if strings.Contains(string(raw), private) {
			t.Fatal("diagnostic exposed private material")
		}
	}
	c.mu.Lock()
	busy := b.codexIssueFailureDiagnostic("VERIFICATION", context.Canceled, started, deadline)
	c.mu.Unlock()
	if busy.Snapshot != "BUSY" || busy.Pending != nil || busy.StateBytes != 0 {
		t.Fatal("busy snapshot pretended empty or waited for its own lock")
	}
	machineNodeControlClients.Delete(path)
	absent := b.codexIssueFailureDiagnostic("INPUT", errLocalCodexContext, started, deadline)
	if absent.Snapshot != "NOT_CACHED" || absent.Pending != nil {
		t.Fatal("missing snapshot initialized or invented state")
	}
}
