//go:build linux && cicada_scoped_app_integration

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

func nodeHubAcceptanceNativeContext(parent context.Context, p LocalNodeConnectionPin) context.Context {
	return withMachineHubContext(parent, machineHubContext{HubID: p.HubID, Origin: p.APIOrigin, NodeID: p.NodeID,
		StateDir: p.StateDir, WriterRoot: p.WriterRoot, WriterScope: machineNativeWriterScope(), MultiHub: true,
		ManagedUserRoot: p.UserRoot, ManagedConnectionID: p.ConnectionID, ManagedConnectionEpoch: p.ConnectionEpoch})
}

func nodeHubAcceptanceNativeOperation(p LocalNodeConnectionPin, suffix string) nodelock.NativeOperation {
	return nodelock.NativeOperation{HubID: p.HubID, NodeID: p.NodeID, EndpointID: "SYNTHETIC-fence-endpoint-" + suffix,
		BindingID: "SYNTHETIC-fence-binding-" + suffix, BindingEpoch: 1, MessageID: "SYNTHETIC-fence-message-" + suffix,
		Digest: "SYNTHETIC-fence-digest-" + suffix, AttemptID: "SYNTHETIC-fence-attempt-" + suffix}
}

func (f *nodeHubLifecycleAcceptance) queueCount(thread string) int {
	f.t.Helper()
	sum := sha256.Sum256([]byte(thread))
	raw, err := os.ReadFile(filepath.Join(f.queueRoot, hex.EncodeToString(sum[:])+".count"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		f.t.Fatal("private offline queue counter", err)
	}
	count := 0
	for _, value := range raw {
		if value == '\n' {
			count++
		}
	}
	return count
}

func TestNodeHubLifecycleAdmissionRemovalBarrierAcceptance(t *testing.T) {
	f := newNodeHubLifecycleAcceptance(t)
	a, b := f.add(0), f.add(1)
	thread := "SYNTHETIC-shared-physical-fence-Thread"
	entered, release := make(chan struct{}), make(chan struct{})
	released := false
	ctxA := nodeHubAcceptanceNativeContext(f.ctx, a.Pin)
	ctxA = context.WithValue(ctxA, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{
		command: f.queueCommand,
		observe: func(phase string) {
			if phase == "managed_admission_checked" {
				close(entered)
				select {
				case <-release:
				case <-f.ctx.Done():
				}
			}
		},
	})
	operation := nodeHubAcceptanceNativeOperation(a.Pin, "A")
	done := make(chan error, 1)
	finished := false
	defer func() {
		if !released {
			close(release)
		}
		if !finished {
			select {
			case <-done:
			case <-time.After(16 * time.Second):
				t.Error("isolated native adapter did not terminate during cleanup")
			}
		}
	}()
	go func() {
		done <- runMachineNativeDelivery(ctxA, thread, operation, func(context.Context) (string, []nodeinbox.NativeContextScopeInput, error) {
			return "SYNTHETIC barrier body A", nil, nil
		}, nil)
	}()
	select {
	case <-entered:
	case err := <-done:
		finished = true
		t.Fatal("actual adapter failed before final admission barrier", err)
	case <-time.After(8 * time.Second):
		t.Fatal("actual adapter did not reach final admission barrier")
	}
	// Remove must actually contend for the same admission gate. A bounded
	// call expires while the old final-admission reader is held; there is no
	// scheduler-timing assertion pretending repeated unlocked reads are atomic.
	removeCtx, cancel := context.WithTimeout(f.ctx, 150*time.Millisecond)
	removed, err := RemoveLocalNodeHubConnection(removeCtx, LocalNodeHubSelection{UserRoot: f.root, ConnectionID: a.Pin.ConnectionID})
	cancel()
	if !errors.Is(err, errNodeHubPending) || removed.State == "LOCAL_STOPPED" {
		t.Fatal("remove did not wait on held final check/Begin/Start admission gate", err)
	}
	entry, exists := f.entry("SYNTHETIC-A")
	if !exists || entry.LocalFence != a.Pin.ConnectionEpoch || entry.DesiredState != "ENABLED" || f.queueCount(thread) != 0 {
		t.Fatal("held admission changed fence or started a queue")
	}
	// A different physical Thread at B remains independent of A's gate.
	ctxB := nodeHubAcceptanceNativeContext(f.ctx, b.Pin)
	other := "SYNTHETIC-independent-B-fence-Thread"
	if err := runMachineNativeDelivery(ctxB, other, nodeHubAcceptanceNativeOperation(b.Pin, "B-other"), func(context.Context) (string, []nodeinbox.NativeContextScopeInput, error) {
		return "SYNTHETIC independent B body", nil, nil
	}, nil); err != nil || f.queueCount(other) != 1 {
		t.Fatal("B independent Thread stalled behind A removal/admission", err)
	}
	// The same physical Thread remains held even though the Hub is distinct.
	busyCtx, busyCancel := context.WithTimeout(f.ctx, 100*time.Millisecond)
	held, busyErr := nodelock.AcquireNativeWriter(busyCtx, b.Pin.WriterRoot, machineNativeWriterScope(), "codex", thread)
	busyCancel()
	if busyErr == nil {
		held.Close()
		t.Fatal("B obtained A's held physical Thread writer")
	}
	if !errors.Is(busyErr, context.DeadlineExceeded) {
		t.Fatal("B same-Thread attempt did not reach real writer contention", busyErr)
	}
	close(release)
	released = true
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal("admitted A did not finish before removal", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("admitted A did not finish after release")
	}
	if f.queueCount(thread) != 1 {
		t.Fatal("old admitted A did not start exactly once")
	}
	removed, err = RemoveLocalNodeHubConnection(f.ctx, LocalNodeHubSelection{UserRoot: f.root, ConnectionID: a.Pin.ConnectionID})
	if err != nil || removed.State != "LOCAL_STOPPED" || removed.LocalFence != a.Pin.ConnectionEpoch+1 {
		t.Fatal("released old A did not fence and quiesce", err)
	}
	// The original stale managed pin now refuses before a new Start. This is
	// a new immutable message, so operation replay dedup cannot mask a gap.
	oldCtx := nodeHubAcceptanceNativeContext(f.ctx, a.Pin)
	err = runMachineNativeDelivery(oldCtx, thread, nodeHubAcceptanceNativeOperation(a.Pin, "A-after-fence"), func(context.Context) (string, []nodeinbox.NativeContextScopeInput, error) {
		return "SYNTHETIC stale A body", nil, nil
	}, nil)
	if err == nil || f.queueCount(thread) != 1 {
		t.Fatal("retired managed pin caused a post-fence native Start")
	}
	oldWriter, err := nodelock.AcquireNativeWriter(f.ctx, b.Pin.WriterRoot, machineNativeWriterScope(), "codex", thread)
	if err != nil {
		t.Fatal("released shared writer was not acquirable", err)
	}
	oldEpoch := oldWriter.Epoch
	if err := oldWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runMachineNativeDelivery(ctxB, thread, nodeHubAcceptanceNativeOperation(b.Pin, "B-same-physical"), func(context.Context) (string, []nodeinbox.NativeContextScopeInput, error) {
		return "SYNTHETIC B same physical Thread after release", nil, nil
	}, nil); err != nil || f.queueCount(thread) != 2 {
		t.Fatal("B could not use original physical Thread after release", err)
	}
	newWriter, err := nodelock.AcquireNativeWriter(f.ctx, b.Pin.WriterRoot, machineNativeWriterScope(), "codex", thread)
	if err != nil {
		t.Fatal(err)
	}
	if newWriter.Epoch <= oldEpoch || !errors.Is(oldWriter.CheckCurrent(), nodelock.ErrNativeWriterStale) {
		newWriter.Close()
		t.Fatal("shared physical writer epoch did not increase or old handle remained current")
	}
	if err := newWriter.Close(); err != nil {
		t.Fatal(err)
	}
	f.assertUnchanged(b)
	t.Log("actual managed fence/native adapter interlock and offline subprocess; synthetic operations test atomicity only; Group Guard is qualified by the separate full-chain target; native Runtime NOT_RUN")
}
