package nodelock

import (
	"context"
	"errors"
	"testing"
)

func syntheticNativeOperation() NativeOperation {
	return NativeOperation{HubID: "hub-a", NodeID: "node-a", EndpointID: "endpoint-a",
		BindingID: "binding-a", BindingEpoch: 7, MessageID: "message-a", Digest: "sha256:a",
		AttemptID: "attempt-one"}
}

func TestNativeOutcomeFencesCrashAndChangedRelayAttempt(t *testing.T) {
	root := t.TempDir()
	first, err := AcquireNativeWriter(context.Background(), root, "uid:1000", "codex", "native-a")
	if err != nil {
		t.Fatal(err)
	}
	op := syntheticNativeOperation()
	if state, err := first.BeginNativeOperation(op); err != nil || state != NativeInjecting {
		t.Fatalf("begin: %s %v", state, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireNativeWriter(context.Background(), root, "uid:1000", "codex", "native-a")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.FinishNativeOperation(op, NativeQueueAccepted); !errors.Is(err, ErrNativeWriterStale) {
		t.Fatalf("stale completion: %v", err)
	}
	op.AttemptID = "attempt-two"
	if state, err := second.BeginNativeOperation(op); state != NativeUncertain || !errors.Is(err, ErrNativeOperationUncertain) {
		t.Fatalf("crash retry: %s %v", state, err)
	}
	if state, err := second.NativeOperationOutcome(op); err != nil || state != NativeUncertain {
		t.Fatalf("durable crash state: %s %v", state, err)
	}
	conflict := op
	conflict.Digest = "sha256:changed"
	if _, err := second.BeginNativeOperation(conflict); !errors.Is(err, ErrNativeOperationConflict) {
		t.Fatalf("changed digest: %v", err)
	}
}

func TestNativeOutcomeAcceptedReusedAcrossAttemptsButNotHubOrBinding(t *testing.T) {
	root := t.TempDir()
	first, err := AcquireNativeWriter(context.Background(), root, "uid:1000", "codex", "native-a")
	if err != nil {
		t.Fatal(err)
	}
	op := syntheticNativeOperation()
	if _, err := first.BeginNativeOperation(op); err != nil {
		t.Fatal(err)
	}
	if err := first.FinishNativeOperation(op, NativeQueueAccepted); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireNativeWriter(context.Background(), root, "uid:1000", "codex", "native-a")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	op.AttemptID = "attempt-two"
	if state, err := second.BeginNativeOperation(op); err != nil || state != NativeQueueAccepted {
		t.Fatalf("accepted replay: %s %v", state, err)
	}
	if err := second.FinishNativeOperation(op, NativeUncertain); !errors.Is(err, ErrNativeWriterStale) {
		t.Fatalf("late overwrite: %v", err)
	}
	changedBinding := op
	changedBinding.BindingEpoch++
	if _, err := second.BeginNativeOperation(changedBinding); !errors.Is(err, ErrNativeOperationConflict) {
		t.Fatalf("rotated binding: %v", err)
	}
	otherHub := op
	otherHub.HubID = "hub-b"
	if state, err := second.BeginNativeOperation(otherHub); err != nil || state != NativeInjecting {
		t.Fatalf("separate Hub operation: %s %v", state, err)
	}
}

func TestNativeOutcomeRejectsMissingScopeBeforeInjection(t *testing.T) {
	lock, err := AcquireNativeWriter(context.Background(), t.TempDir(), "uid:1000", "codex", "native-a")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	op := syntheticNativeOperation()
	op.HubID = ""
	if _, err := lock.BeginNativeOperation(op); err == nil {
		t.Fatal("unpinned Hub accepted")
	}
}
