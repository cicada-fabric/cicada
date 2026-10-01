package nodeinbox

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func providerAdmissionTestIntent(label string) string {
	digest := sha256.Sum256([]byte("synthetic provider admission intent: " + label))
	return hex.EncodeToString(digest[:])
}

func openProviderAdmissionTestLedger(t *testing.T, path string) *ProviderAdmissionLedger {
	t.Helper()
	ledger, err := OpenProviderAdmissionLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	return ledger
}

func TestProviderAdmissionAttemptGenerationFencesDelayedOutcomesAcrossLedgers(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "provider-admission.sqlite3")
	firstLedger := openProviderAdmissionTestLedger(t, path)
	secondLedger := openProviderAdmissionTestLedger(t, path)
	ctx := context.Background()
	request := ProviderAdmissionRequest{ExecutionID: "exec-generation-fence", ProviderID: "codex",
		AdmissionIntent: providerAdmissionTestIntent("first")}

	first, err := firstLedger.AdmitProviderAttempt(ctx, request)
	if err != nil || first == nil || !first.Admitted || first.Attempt != 1 {
		t.Fatalf("admit first generation: decision=%#v err=%v", first, err)
	}
	backoff, err := firstLedger.RecordProviderAdmissionOutcome(ctx, ProviderAdmissionOutcome{
		ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
		Attempt: first.Attempt, Class: ProviderOutcomeRetryableNotInjected,
	})
	if err != nil || backoff == nil || backoff.State != ProviderAdmissionBackoff || backoff.Attempt != 1 {
		t.Fatalf("close first generation into backoff: decision=%#v err=%v", backoff, err)
	}
	// Move only the test row's deadline; keep production admission and CAS paths.
	firstLedger.inbox.mu.Lock()
	_, err = firstLedger.inbox.db.ExecContext(ctx, `UPDATE node_provider_admission_v1
SET next_retry_at_ms=0 WHERE execution_id=? AND provider_id=?`, request.ExecutionID, request.ProviderID)
	firstLedger.inbox.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	secondRequest := request
	secondRequest.AdmissionIntent = providerAdmissionTestIntent("second")
	second, err := secondLedger.AdmitProviderAttempt(ctx, secondRequest)
	if err != nil || second == nil || !second.Admitted || second.Attempt != 2 {
		t.Fatalf("admit second generation through independent handle: decision=%#v err=%v", second, err)
	}

	// A delayed duplicate of attempt 1 uses the same class that originally
	// closed attempt 1. It must not alter attempt 2, even when racing its result.
	start := make(chan struct{})
	type outcomeResult struct {
		decision *ProviderAdmissionDecision
		err      error
	}
	var wait sync.WaitGroup
	wait.Add(2)
	var staleResult, currentResult outcomeResult
	go func() {
		defer wait.Done()
		<-start
		staleResult.decision, staleResult.err = firstLedger.RecordProviderAdmissionOutcome(ctx, ProviderAdmissionOutcome{
			ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
			Attempt: first.Attempt, Class: ProviderOutcomeRetryableNotInjected,
		})
	}()
	go func() {
		defer wait.Done()
		<-start
		currentResult.decision, currentResult.err = secondLedger.RecordProviderAdmissionOutcome(ctx, ProviderAdmissionOutcome{
			ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
			Attempt: second.Attempt, Class: ProviderOutcomeCompleted,
		})
	}()
	close(start)
	wait.Wait()
	if !errors.Is(staleResult.err, ErrProviderAdmissionStaleAttempt) {
		t.Fatalf("old same-class outcome was not rejected as stale: decision=%#v err=%v", staleResult.decision, staleResult.err)
	}
	if currentResult.err != nil || currentResult.decision == nil ||
		currentResult.decision.State != ProviderAdmissionCompleted || currentResult.decision.Attempt != 2 {
		t.Fatalf("current generation did not complete: decision=%#v err=%v", currentResult.decision, currentResult.err)
	}

	// Recover a lost response only for the exact generation and exact class.
	replay, err := secondLedger.RecordProviderAdmissionOutcome(ctx, ProviderAdmissionOutcome{
		ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
		Attempt: second.Attempt, Class: ProviderOutcomeCompleted,
	})
	if err != nil || replay == nil || replay.State != ProviderAdmissionCompleted || replay.Attempt != 2 {
		t.Fatalf("exact terminal response replay was not idempotent: decision=%#v err=%v", replay, err)
	}
	if _, err := secondLedger.RecordProviderAdmissionOutcome(ctx, ProviderAdmissionOutcome{
		ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
		Attempt: first.Attempt, Class: ProviderOutcomeCompleted,
	}); !errors.Is(err, ErrProviderAdmissionStaleAttempt) {
		t.Fatalf("old generation replay was accepted after terminal completion: %v", err)
	}
}

func TestProviderAdmissionUncertainAndTerminalOutcomesCannotBeReadmitted(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger := openProviderAdmissionTestLedger(t, filepath.Join(dir, "provider-admission.sqlite3"))
	ctx := context.Background()
	request := ProviderAdmissionRequest{ExecutionID: "exec-uncertain-fence", ProviderID: "codex",
		AdmissionIntent: providerAdmissionTestIntent("uncertain")}
	admitted, err := ledger.AdmitProviderAttempt(ctx, request)
	if err != nil || admitted == nil || !admitted.Admitted || admitted.Attempt != 1 {
		t.Fatalf("admit: decision=%#v err=%v", admitted, err)
	}
	if _, err := ledger.RecordProviderAdmissionOutcome(ctx, ProviderAdmissionOutcome{
		ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
		Class: ProviderOutcomeInjectionUncertain,
	}); !errors.Is(err, ErrProviderAdmissionInvalid) {
		t.Fatalf("outcome without trusted generation was accepted: %v", err)
	}
	uncertain, err := ledger.RecordProviderAdmissionOutcome(ctx, ProviderAdmissionOutcome{
		ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
		Attempt: admitted.Attempt, Class: ProviderOutcomeInjectionUncertain,
	})
	if err != nil || uncertain == nil || uncertain.State != ProviderAdmissionInjectionUncertain {
		t.Fatalf("record uncertain outcome: decision=%#v err=%v", uncertain, err)
	}
	blocked, err := ledger.AdmitProviderAttempt(ctx, request)
	if err != nil || blocked == nil || blocked.Admitted || blocked.Attempt != admitted.Attempt ||
		blocked.State != ProviderAdmissionInjectionUncertain {
		t.Fatalf("uncertain execution was readmitted: decision=%#v err=%v", blocked, err)
	}
	baseReconciliation := ProviderAdmissionReconciliation{
		ExecutionID: request.ExecutionID, ProviderID: request.ProviderID, Attempt: admitted.Attempt,
		Resolution: ProviderReconcileCompleted, IdempotencyKey: "operator-reconcile-key",
		EvidenceID: "local-stop-receipt", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	wrongGeneration := baseReconciliation
	wrongGeneration.Attempt++
	if _, err := ledger.ReconcileProviderInjectionUncertain(ctx, wrongGeneration); !errors.Is(err, ErrProviderAdmissionStaleAttempt) {
		t.Fatalf("operator reconciliation with a different expected generation was accepted: %v", err)
	}
	resolved, err := ledger.ReconcileProviderInjectionUncertain(ctx, baseReconciliation)
	if err != nil || resolved == nil || resolved.State != ProviderAdmissionCompleted || resolved.Attempt != admitted.Attempt {
		t.Fatalf("exact operator reconciliation failed: decision=%#v err=%v", resolved, err)
	}
	replay, err := ledger.ReconcileProviderInjectionUncertain(ctx, baseReconciliation)
	if err != nil || replay == nil || replay.State != ProviderAdmissionCompleted || replay.Attempt != admitted.Attempt {
		t.Fatalf("lost operator response was not recoverable: decision=%#v err=%v", replay, err)
	}
	if _, err := ledger.ReconcileProviderInjectionUncertain(ctx, wrongGeneration); !errors.Is(err, ErrProviderAdmissionStaleAttempt) {
		t.Fatalf("old operator generation replay was accepted: %v", err)
	}

	terminalRequest := ProviderAdmissionRequest{ExecutionID: "exec-cancelled-terminal", ProviderID: "codex",
		AdmissionIntent: providerAdmissionTestIntent("cancelled")}
	terminal, err := ledger.AdmitProviderAttempt(ctx, terminalRequest)
	if err != nil || terminal == nil || !terminal.Admitted {
		t.Fatalf("admit terminal test: decision=%#v err=%v", terminal, err)
	}
	if _, err := ledger.RecordProviderAdmissionOutcome(ctx, ProviderAdmissionOutcome{
		ExecutionID: terminalRequest.ExecutionID, ProviderID: terminalRequest.ProviderID,
		Attempt: terminal.Attempt, Class: ProviderOutcomeFailedNotInjected,
	}); err != nil {
		t.Fatal(err)
	}
	cancelled, err := ledger.AdmitProviderAttempt(ctx, terminalRequest)
	if err != nil || cancelled == nil || cancelled.Admitted || cancelled.State != ProviderAdmissionFailed {
		t.Fatalf("terminal non-injected failure was automatically retried: decision=%#v err=%v", cancelled, err)
	}
}

func TestProviderAdmissionIntentReplayAndMismatchFenceGenerations(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "provider-admission.sqlite3")
	firstLedger := openProviderAdmissionTestLedger(t, path)
	secondLedger := openProviderAdmissionTestLedger(t, path)
	ctx := context.Background()
	request := ProviderAdmissionRequest{ExecutionID: "exec-intent-fence", ProviderID: "codex",
		AdmissionIntent: providerAdmissionTestIntent("intent-a")}
	first, err := firstLedger.AdmitProviderAttempt(ctx, request)
	if err != nil || first == nil || first.Attempt != 1 || !first.Admitted {
		t.Fatalf("initial intent admission failed: decision=%#v err=%v", first, err)
	}
	replay, err := secondLedger.AdmitProviderAttempt(ctx, request)
	if err != nil || replay == nil || replay.Attempt != 1 || !replay.Admitted {
		t.Fatalf("exact intent did not recover the same generation across ledgers: decision=%#v err=%v", replay, err)
	}
	wrongIntent := request
	wrongIntent.AdmissionIntent = providerAdmissionTestIntent("intent-b")
	if _, err := secondLedger.AdmitProviderAttempt(ctx, wrongIntent); !errors.Is(err, ErrProviderAdmissionIntentMismatch) {
		t.Fatalf("different intent adopted current generation: %v", err)
	}
	if _, err := secondLedger.InspectProviderAttempt(ctx, wrongIntent); !errors.Is(err, ErrProviderAdmissionIntentMismatch) {
		t.Fatalf("read-only exact-generation inspection accepted a different intent: %v", err)
	}

	backoff, err := firstLedger.RecordProviderAdmissionOutcome(ctx, ProviderAdmissionOutcome{
		ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
		Attempt: first.Attempt, Class: ProviderOutcomeRetryableNotInjected,
	})
	if err != nil || backoff == nil || backoff.State != ProviderAdmissionBackoff {
		t.Fatalf("record safe backoff: decision=%#v err=%v", backoff, err)
	}
	firstLedger.inbox.mu.Lock()
	_, err = firstLedger.inbox.db.ExecContext(ctx, `UPDATE node_provider_admission_v1
SET next_retry_at_ms=0 WHERE execution_id=? AND provider_id=?`, request.ExecutionID, request.ProviderID)
	firstLedger.inbox.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondLedger.AdmitProviderAttempt(ctx, request); !errors.Is(err, ErrProviderAdmissionIntentMismatch) {
		t.Fatalf("closed generation intent was reused to create a retry generation: %v", err)
	}
	secondIntent := wrongIntent
	second, err := secondLedger.AdmitProviderAttempt(ctx, secondIntent)
	if err != nil || second == nil || second.Attempt != 2 || !second.Admitted {
		t.Fatalf("fresh intent did not atomically create the next generation: decision=%#v err=%v", second, err)
	}
	if _, err := firstLedger.AdmitProviderAttempt(ctx, request); !errors.Is(err, ErrProviderAdmissionIntentMismatch) {
		t.Fatalf("old generation intent adopted a newer in-progress generation: %v", err)
	}
}

func TestProviderAdmissionLegacyInProgressAndBackoffRemainUnbound(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "legacy-provider-admission.sqlite3")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().UnixMilli()
	_, err = db.Exec(`PRAGMA foreign_keys=ON;
CREATE TABLE node_provider_admission_v1 (
 execution_id TEXT NOT NULL, provider_id TEXT NOT NULL,
 state TEXT NOT NULL, attempts INTEGER NOT NULL,
 created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
 next_retry_at_ms INTEGER NOT NULL DEFAULT 0,
 last_class TEXT NOT NULL DEFAULT '', PRIMARY KEY(execution_id,provider_id));`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	for _, row := range []struct {
		executionID string
		state       string
		lastClass   string
	}{
		{executionID: "legacy-in-progress", state: ProviderAdmissionInProgress},
		{executionID: "legacy-backoff", state: ProviderAdmissionBackoff, lastClass: ProviderOutcomeRetryableNotInjected},
	} {
		if _, err := db.Exec(`INSERT INTO node_provider_admission_v1
(execution_id,provider_id,state,attempts,created_at_ms,updated_at_ms,next_retry_at_ms,last_class)
VALUES(?,?,?,1,?,?,0,?)`, row.executionID, "codex", row.state, now, now, row.lastClass); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ledger := openProviderAdmissionTestLedger(t, path)
	for _, item := range []struct {
		executionID string
		state       string
	}{
		{executionID: "legacy-in-progress", state: ProviderAdmissionInProgress},
		{executionID: "legacy-backoff", state: ProviderAdmissionBackoff},
	} {
		request := ProviderAdmissionRequest{ExecutionID: item.executionID, ProviderID: "codex",
			AdmissionIntent: providerAdmissionTestIntent(item.executionID)}
		if _, err := ledger.AdmitProviderAttempt(context.Background(), request); !errors.Is(err, ErrProviderAdmissionIntentUnbound) {
			t.Fatalf("legacy %s row silently acquired a new intent: %v", item.state, err)
		}
		decision, err := ledger.InspectProviderAttempt(context.Background(), ProviderAdmissionRequest{
			ExecutionID: item.executionID, ProviderID: "codex"})
		if err != nil || decision == nil || decision.State != item.state || decision.Attempt != 1 {
			t.Fatalf("legacy %s row changed while blocked: decision=%#v err=%v", item.state, decision, err)
		}
	}
}

func TestProviderAdmissionIntentConcurrentAcrossIndependentLedgers(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "provider-admission.sqlite3")
	firstLedger := openProviderAdmissionTestLedger(t, path)
	secondLedger := openProviderAdmissionTestLedger(t, path)
	ctx := context.Background()
	shared := ProviderAdmissionRequest{ExecutionID: "exec-intent-concurrent", ProviderID: "codex",
		AdmissionIntent: providerAdmissionTestIntent("shared-intent")}
	start := make(chan struct{})
	decisions := make([]*ProviderAdmissionDecision, 2)
	errs := make([]error, 2)
	var wait sync.WaitGroup
	for index, ledger := range []*ProviderAdmissionLedger{firstLedger, secondLedger} {
		index, ledger := index, ledger
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for attempt := 0; attempt < 20; attempt++ {
				decisions[index], errs[index] = ledger.AdmitProviderAttempt(ctx, shared)
				if errs[index] == nil {
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	close(start)
	wait.Wait()
	for index := range decisions {
		if errs[index] != nil || decisions[index] == nil || !decisions[index].Admitted || decisions[index].Attempt != 1 {
			t.Fatalf("exact concurrent intent was not idempotent at ledger %d: decision=%#v err=%v", index, decisions[index], errs[index])
		}
	}
	var rows int
	if err := firstLedger.inbox.db.QueryRowContext(ctx, `SELECT count(*) FROM node_provider_admission_intents_v1
WHERE execution_id=? AND provider_id=?`, shared.ExecutionID, shared.ProviderID).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("concurrent exact intent produced %d generation bindings: err=%v", rows, err)
	}

	conflicting := []ProviderAdmissionRequest{
		{ExecutionID: "exec-intent-conflict", ProviderID: "codex", AdmissionIntent: providerAdmissionTestIntent("conflict-a")},
		{ExecutionID: "exec-intent-conflict", ProviderID: "codex", AdmissionIntent: providerAdmissionTestIntent("conflict-b")},
	}
	start = make(chan struct{})
	decisions = make([]*ProviderAdmissionDecision, 2)
	errs = make([]error, 2)
	for index, ledger := range []*ProviderAdmissionLedger{firstLedger, secondLedger} {
		index, ledger := index, ledger
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for attempt := 0; attempt < 20; attempt++ {
				decisions[index], errs[index] = ledger.AdmitProviderAttempt(ctx, conflicting[index])
				if errs[index] == nil || errors.Is(errs[index], ErrProviderAdmissionIntentMismatch) {
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	close(start)
	wait.Wait()
	winners, mismatches := 0, 0
	for index := range decisions {
		if errs[index] == nil && decisions[index] != nil && decisions[index].Admitted && decisions[index].Attempt == 1 {
			winners++
		} else if errors.Is(errs[index], ErrProviderAdmissionIntentMismatch) {
			mismatches++
		} else {
			t.Fatalf("conflicting concurrent intent had unexpected result at ledger %d: decision=%#v err=%v", index, decisions[index], errs[index])
		}
	}
	if winners != 1 || mismatches != 1 {
		t.Fatalf("conflicting intents were not serialized to one generation: winners=%d mismatches=%d", winners, mismatches)
	}
	if err := firstLedger.inbox.db.QueryRowContext(ctx, `SELECT count(*) FROM node_provider_admission_intents_v1
WHERE execution_id='exec-intent-conflict' AND provider_id='codex'`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("conflicting concurrent intents left %d generation bindings: err=%v", rows, err)
	}
}
