package nodelock

import (
	"errors"
	"testing"
	"time"
)

func TestResourceExecutionNeedsTrustedStopVerifier(t *testing.T) {
	manager, err := OpenResourceExecutionManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := ResourceExecutionRequest{ResourceID: "gpu/0", LeaseID: "lease-1",
		FencingEpoch: 1, ExecutionID: "exec-1"}
	execution, err := manager.Begin(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.MarkStarted(); err != nil {
		t.Fatal(err)
	}
	if err := execution.ConfirmStopped(nil); !errors.Is(err, ErrResourceStopUnverified) {
		t.Fatalf("nil runtime verifier error = %v, want unverified", err)
	}
	if err := execution.QuarantineStopUnverified(); err != nil {
		t.Fatal(err)
	}
	record, err := manager.Inspect(request.ResourceID)
	if err != nil || record == nil || record.State != ResourceExecutionQuarantined ||
		record.Outcome != "resource_stop_unverified" {
		t.Fatalf("unverified resource state = %#v, err=%v", record, err)
	}
	if _, err := manager.Begin(ResourceExecutionRequest{ResourceID: request.ResourceID,
		LeaseID: "lease-2", FencingEpoch: 2, ExecutionID: "exec-2"}); !errors.Is(err, ErrResourceExecutionBusy) {
		t.Fatalf("next fencing epoch acquired unverified resource: %v", err)
	}
}

func TestResourceExecutionConfirmRejectsStaleReceiptAndAcceptsExactVerifier(t *testing.T) {
	manager, err := OpenResourceExecutionManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := ResourceExecutionRequest{ResourceID: "gpu/1", LeaseID: "lease-1",
		FencingEpoch: 4, ExecutionID: "exec-4"}
	execution, err := manager.Begin(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.MarkStarted(); err != nil {
		t.Fatal(err)
	}
	stale := ResourceStopVerifier(func(record ResourceExecutionRecord) (ResourceStopReceipt, error) {
		return ResourceStopReceipt{ResourceID: record.ResourceID, LeaseID: record.LeaseID,
			FencingEpoch: record.FencingEpoch, ExecutionID: "older-execution",
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
	})
	if err := execution.ConfirmStopped(stale); !errors.Is(err, ErrResourceExecutionStale) {
		t.Fatalf("stale stop receipt error = %v", err)
	}
	exact := ResourceStopVerifier(func(record ResourceExecutionRecord) (ResourceStopReceipt, error) {
		return ResourceStopReceipt{ResourceID: record.ResourceID, LeaseID: record.LeaseID,
			FencingEpoch: record.FencingEpoch, ExecutionID: record.ExecutionID,
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
	})
	if err := execution.ConfirmStopped(exact); err != nil {
		t.Fatal(err)
	}
	record, err := manager.Inspect(request.ResourceID)
	if err != nil || record == nil || record.State != ResourceExecutionStopConfirmed {
		t.Fatalf("exact stop verifier did not confirm resource: %#v err=%v", record, err)
	}
	second, err := manager.Begin(ResourceExecutionRequest{ResourceID: request.ResourceID,
		LeaseID: "lease-2", FencingEpoch: 5, ExecutionID: "exec-5"})
	if err != nil {
		t.Fatalf("higher epoch could not acquire exactly verified stop: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestResourceExecutionRecoveryRejectsStaleStopReceipt(t *testing.T) {
	manager, err := OpenResourceExecutionManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := ResourceExecutionRequest{ResourceID: "gpu/2", LeaseID: "lease-1",
		FencingEpoch: 7, ExecutionID: "exec-7"}
	execution, err := manager.Begin(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.MarkStarted(); err != nil {
		t.Fatal(err)
	}
	if err := execution.QuarantineStopUnverified(); err != nil {
		t.Fatal(err)
	}
	stale := ResourceStopVerifier(func(record ResourceExecutionRecord) (ResourceStopReceipt, error) {
		return ResourceStopReceipt{ResourceID: record.ResourceID, LeaseID: record.LeaseID,
			FencingEpoch: record.FencingEpoch - 1, ExecutionID: record.ExecutionID,
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
	})
	if err := manager.ReconcileStopped(request, stale); !errors.Is(err, ErrResourceExecutionStale) {
		t.Fatalf("stale recovery receipt error = %v", err)
	}
	exact := ResourceStopVerifier(func(record ResourceExecutionRecord) (ResourceStopReceipt, error) {
		return ResourceStopReceipt{ResourceID: record.ResourceID, LeaseID: record.LeaseID,
			FencingEpoch: record.FencingEpoch, ExecutionID: record.ExecutionID,
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
	})
	if err := manager.ReconcileStopped(request, exact); err != nil {
		t.Fatal(err)
	}
	record, err := manager.Inspect(request.ResourceID)
	if err != nil || record == nil || record.State != ResourceExecutionStopConfirmed {
		t.Fatalf("exact recovery verifier did not confirm resource: %#v err=%v", record, err)
	}
}
