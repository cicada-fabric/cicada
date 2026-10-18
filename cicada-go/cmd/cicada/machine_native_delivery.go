package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

// Private per-call dependencies keep deterministic process barriers out of the
// production configuration and do not replace the durable writer or Guard.
type machineNativeDeliveryLifecycle struct {
	command func(context.Context, string, ...string) *exec.Cmd
	observe func(string)
}

type machineNativeDeliveryLifecycleKey struct{}

// Internal admission callbacks may inspect this only after the physical writer
// has checked and read its exact durable operation outcome.
type machineNativeWriterOutcomeKey struct{}

// Current permission cannot rewrite a matching writer's past execution. This
// error deliberately does not unwrap into a fresh no-injection denial.
type machineNativeHistoricalOutcomeError struct {
	Outcome nodelock.NativeOutcomeState
	Cause   error
}

func (e *machineNativeHistoricalOutcomeError) Error() string {
	return fmt.Sprintf("original native writer outcome %s retained; current authorization cannot settle it as unexecuted: %v", e.Outcome, e.Cause)
}

func machineNativeHasHistoricalOutcome(state nodelock.NativeOutcomeState) bool {
	return state == nodelock.NativeQueueAccepted || state == nodelock.NativeUncertain || state == nodelock.NativeInjecting
}

// Even a denial obtained before queue preparation must respect the original
// writer ledger. Keep the writer held through the local rejection so another
// caller cannot start the same operation between the check and that write.
func rejectMachineNativeUnexecuted(ctx context.Context, nativeSessionID string, operation nodelock.NativeOperation, reject func(context.Context) error) (result error) {
	hub, ok := machineHubFrom(ctx)
	if !ok || hub.HubID == "" || operation.HubID != hub.HubID || operation.NodeID != hub.NodeID {
		return errors.New("native rejection has no pinned original operation")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	writer, err := nodelock.AcquireNativeWriter(ctx, hub.WriterRoot, hub.WriterScope, "codex", nativeSessionID)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, writer.Close()) }()
	previous, err := writer.NativeOperationOutcome(operation)
	if err != nil && !errors.Is(err, nodelock.ErrNativeOperationConflict) {
		return err
	}
	// A different immutable operation remains fenced by its own ledger row;
	// rejecting this conflicting inbox body does not rewrite that prior row.
	if machineNativeHasHistoricalOutcome(previous) {
		return &machineNativeHistoricalOutcomeError{Outcome: previous, Cause: errors.New("current delivery authority was denied")}
	}
	return reject(ctx)
}

func machineNativeDeliveryDependencies(ctx context.Context) machineNativeDeliveryLifecycle {
	dependencies, _ := ctx.Value(machineNativeDeliveryLifecycleKey{}).(machineNativeDeliveryLifecycle)
	if dependencies.command == nil {
		dependencies.command = exec.CommandContext
	}
	return dependencies
}

func (d machineNativeDeliveryLifecycle) observed(phase string) {
	if d.observe != nil {
		d.observe(phase)
	}
}

// runMachineNativeDelivery obtains one physical writer. Preparation (including
// same-Group's current Hub Guard) and fallible preflight precede both intents.
// The writer is released before any caller reconciles inbox or remote receipts.
func runMachineNativeDelivery(parent context.Context, nativeSessionID string, operation nodelock.NativeOperation,
	prepare func(context.Context) (string, []nodeinbox.NativeContextScopeInput, error),
	admit func(context.Context) error) (result error) {
	if strings.TrimSpace(nativeSessionID) == "" {
		return errors.New("v2 relay delivery is missing its native session")
	}
	hub, ok := machineHubFrom(parent)
	if !ok || hub.HubID == "" || operation.HubID != hub.HubID || operation.NodeID != hub.NodeID {
		return errors.New("exact native queue requires a pinned Hub and operation scope")
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	dependencies := machineNativeDeliveryDependencies(parent)
	dependencies.observed("writer_wait")
	writer, err := nodelock.AcquireNativeWriter(ctx, hub.WriterRoot, hub.WriterScope, "codex", nativeSessionID)
	if err != nil {
		return fmt.Errorf("acquire exact native writer: %w", err)
	}
	defer func() {
		closeErr := writer.Close()
		if closeErr != nil && result == nil {
			result = &nativeInjectionUncertainError{cause: fmt.Errorf("close accepted native writer: %w", closeErr)}
		} else {
			result = errors.Join(result, closeErr)
		}
		if result == nil {
			dependencies.observed("accepted_writer_closed")
		}
	}()
	previous, err := writer.NativeOperationOutcome(operation)
	if err != nil {
		return err
	}
	prompt, scopes, err := prepare(ctx)
	if err != nil {
		if machineNativeHasHistoricalOutcome(previous) {
			return &machineNativeHistoricalOutcomeError{Outcome: previous, Cause: err}
		}
		return err
	}
	err = executeMachineNativeCodexHeld(ctx, writer, nativeSessionID, prompt, operation, scopes, admit, dependencies)
	var uncertain *nativeInjectionUncertainError
	if err != nil && machineNativeHasHistoricalOutcome(previous) && !errors.As(err, &uncertain) {
		return &machineNativeHistoricalOutcomeError{Outcome: previous, Cause: err}
	}
	return err
}

func executeMachineNativeCodexHeld(ctx context.Context, writer *nodelock.NativeWriterLock,
	nativeSessionID, prompt string, operation nodelock.NativeOperation, scopes []nodeinbox.NativeContextScopeInput,
	admit func(context.Context) error, dependencies machineNativeDeliveryLifecycle) error {
	if prompt == "" || len(scopes) > 1 {
		return errors.New("native queue received missing body or ambiguous scope evidence")
	}
	hub, _ := machineHubFrom(ctx)
	if len(scopes) == 1 {
		if scopes[0].NativeSessionID != nativeSessionID || scopes[0].HubID != hub.HubID ||
			scopes[0].EndpointID != operation.EndpointID || scopes[0].BindingID != operation.BindingID ||
			scopes[0].BindingEpoch != operation.BindingEpoch {
			return errors.New("native scope differs from the exact queue operation binding")
		}
		if _, err := checkMachineNativeContext(ctx, scopes[0]); err != nil {
			return fmt.Errorf("check current native scope before queue injection: %w", err)
		}
	} else if hub.RequireNativeContext {
		return errors.New("managed native queue has no current trusted context-scope evidence")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writer.CheckCurrent(); err != nil {
		return err
	}
	// Exact durable outcomes survive a missing CLI and changes to remote attempt
	// IDs. Preflight/current authorization still ran; no new command is needed.
	previous, err := writer.NativeOperationOutcome(operation)
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, machineNativeWriterOutcomeKey{}, previous)
	if previous == nodelock.NativeQueueAccepted || previous == nodelock.NativeUncertain || previous == nodelock.NativeInjecting {
		if admit != nil {
			if err := admit(ctx); err != nil {
				return err
			}
		}
		if previous == nodelock.NativeQueueAccepted {
			return nil
		}
		return &nativeInjectionUncertainError{cause: nodelock.ErrNativeOperationUncertain}
	}
	binary := strings.TrimSpace(os.Getenv("CICADA_CODEX_BIN"))
	if binary == "" {
		binary = "codex"
	}
	command := dependencies.command(ctx, binary, "queue", "--thread", nativeSessionID, "--message", prompt)
	command.Env = machineWorkerEnvironment(os.Environ(), true)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if command.Err != nil {
		return fmt.Errorf("codex queue could not be prepared: %w", command.Err)
	}
	if _, err := exec.LookPath(command.Path); err != nil {
		return fmt.Errorf("codex queue executable is unavailable: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if admit != nil {
		if err := admit(ctx); err != nil {
			return err
		}
	}
	state, err := writer.BeginNativeOperation(operation)
	if errors.Is(err, nodelock.ErrNativeOperationUncertain) {
		return &nativeInjectionUncertainError{cause: err}
	}
	if err != nil {
		// A failed durable write cannot prove that no intent reached disk.
		return &nativeInjectionUncertainError{cause: err}
	}
	if state == nodelock.NativeQueueAccepted {
		return nil
	}
	if err := command.Start(); err != nil {
		if finishErr := writer.FinishNativeOperation(operation, nodelock.NativeNotStarted); finishErr != nil {
			return &nativeInjectionUncertainError{cause: finishErr}
		}
		return fmt.Errorf("codex queue could not start: %w", err)
	}
	if err := command.Wait(); err != nil {
		finishErr := writer.FinishNativeOperation(operation, nodelock.NativeUncertain)
		return &nativeInjectionUncertainError{cause: errors.Join(err, ctx.Err(), finishErr)}
	}
	dependencies.observed("queue_wait_succeeded")
	if err := writer.FinishNativeOperation(operation, nodelock.NativeQueueAccepted); err != nil {
		return &nativeInjectionUncertainError{cause: err}
	}
	dependencies.observed("accepted_durable")
	return nil
}

// Only a still-CLAIMED local attempt can be abandoned with this independent
// deadline. It is never used for Hub authority, queue execution, or unknown
// injection cleanup; AbandonClaim itself fences INJECTING and uncertain rows.
func abandonMachineNativeClaim(ctx context.Context, inbox *nodeinbox.Inbox, claim nodeinbox.Claim) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := inbox.AbandonClaim(cleanup, claim.AttemptID); err != nil {
		return fmt.Errorf("release unstarted native delivery claim: %w", err)
	}
	return nil
}

type machineNativeDeliveryDeniedError struct{ cause error }

func (e *machineNativeDeliveryDeniedError) Error() string {
	return "current native delivery denied: " + e.cause.Error()
}
func (e *machineNativeDeliveryDeniedError) Unwrap() error { return e.cause }

func machineNativeDeliveryIdentityConflict(err error) bool {
	return errors.Is(err, nodelock.ErrNativeOperationConflict)
}
