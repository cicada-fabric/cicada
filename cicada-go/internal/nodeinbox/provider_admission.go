package nodeinbox

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const providerAdmissionIntentSchemaV1 = `
CREATE TABLE IF NOT EXISTS node_provider_admission_intents_v1 (
 execution_id TEXT NOT NULL, provider_id TEXT NOT NULL,
 attempt INTEGER NOT NULL CHECK(attempt>0),
 intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
 created_at_ms INTEGER NOT NULL,
 PRIMARY KEY(execution_id,provider_id,attempt),
 UNIQUE(execution_id,provider_id,intent_hash),
 FOREIGN KEY(execution_id,provider_id)
  REFERENCES node_provider_admission_v1(execution_id,provider_id) ON DELETE CASCADE
);`

// ProviderAdmissionLedger is a Node-wide sidecar, opened below the shared
// WriterRoot so provider backoff is consistent across per-Hub inboxes.
type ProviderAdmissionLedger struct {
	inbox *Inbox
}

func OpenProviderAdmissionLedger(path string) (*ProviderAdmissionLedger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("provider admission ledger path is required")
	}
	if path != ":memory:" {
		if err := preparePrivateInboxPath(path); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open provider admission ledger: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS node_provider_admission_v1 (
 execution_id TEXT NOT NULL, provider_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('IN_PROGRESS','BACKOFF','COMPLETED','FAILED','INJECTION_UNCERTAIN','EXHAUSTED')),
 attempts INTEGER NOT NULL CHECK(attempts>0), created_at_ms INTEGER NOT NULL,
 updated_at_ms INTEGER NOT NULL, next_retry_at_ms INTEGER NOT NULL DEFAULT 0,
 last_class TEXT NOT NULL DEFAULT '', PRIMARY KEY(execution_id,provider_id));
CREATE INDEX IF NOT EXISTS node_provider_admission_retention_v1_idx
 ON node_provider_admission_v1(updated_at_ms,state);`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize provider admission ledger: %w", err)
	}
	if _, err := db.Exec(providerAdmissionIntentSchemaV1); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize provider admission intent schema: %w", err)
	}
	return &ProviderAdmissionLedger{inbox: &Inbox{db: db}}, nil
}

func (l *ProviderAdmissionLedger) Close() error {
	if l == nil || l.inbox == nil {
		return nil
	}
	return l.inbox.Close()
}

func (l *ProviderAdmissionLedger) AdmitProviderAttempt(ctx context.Context,
	request ProviderAdmissionRequest) (*ProviderAdmissionDecision, error) {
	if l == nil || l.inbox == nil {
		return nil, ErrProviderAdmissionInvalid
	}
	return l.inbox.AdmitProviderAttempt(ctx, request)
}

func (l *ProviderAdmissionLedger) RecordProviderAdmissionOutcome(ctx context.Context,
	outcome ProviderAdmissionOutcome) (*ProviderAdmissionDecision, error) {
	if l == nil || l.inbox == nil {
		return nil, ErrProviderAdmissionInvalid
	}
	return l.inbox.RecordProviderAdmissionOutcome(ctx, outcome)
}

// InspectProviderAttempt returns the durable state without creating an
// attempt or granting permission to redispatch it.
func (l *ProviderAdmissionLedger) InspectProviderAttempt(ctx context.Context,
	request ProviderAdmissionRequest) (*ProviderAdmissionDecision, error) {
	if l == nil || l.inbox == nil {
		return nil, ErrProviderAdmissionInvalid
	}
	return l.inbox.InspectProviderAttempt(ctx, request)
}

// ReconcileProviderInjectionUncertain resolves an uncertain attempt only to a
// terminal state based on an explicit local executor/operator observation.
func (l *ProviderAdmissionLedger) ReconcileProviderInjectionUncertain(ctx context.Context,
	reconciliation ProviderAdmissionReconciliation) (*ProviderAdmissionDecision, error) {
	if l == nil || l.inbox == nil {
		return nil, ErrProviderAdmissionInvalid
	}
	return l.inbox.ReconcileProviderInjectionUncertain(ctx, reconciliation)
}

const (
	ProviderAdmissionInProgress         = "IN_PROGRESS"
	ProviderAdmissionBackoff            = "BACKOFF"
	ProviderAdmissionCompleted          = "COMPLETED"
	ProviderAdmissionFailed             = "FAILED"
	ProviderAdmissionInjectionUncertain = "INJECTION_UNCERTAIN"
	ProviderAdmissionExhausted          = "EXHAUSTED"

	ProviderOutcomeRateLimitedNotInjected = "RATE_LIMITED_NOT_INJECTED"
	ProviderOutcomeRetryableNotInjected   = "RETRYABLE_NOT_INJECTED"
	ProviderOutcomeCompleted              = "COMPLETED"
	ProviderOutcomeFailedNotInjected      = "FAILED_NOT_INJECTED"
	ProviderOutcomeInjectionUncertain     = "INJECTION_UNCERTAIN"
	ProviderReconcileCompleted            = "COMPLETED_CONFIRMED"
	ProviderReconcileFailed               = "FAILED_TERMINAL_CONFIRMED"

	providerAdmissionMaxAttempts = 8
	providerAdmissionMaxRows     = 4096
	providerAdmissionMaxAge      = 24 * time.Hour
	providerAdmissionMaxBackoff  = 15 * time.Minute
	providerAdmissionRetention   = 30 * 24 * time.Hour
)

var (
	ErrProviderAdmissionInvalid        = errors.New("provider admission input is invalid")
	ErrProviderAdmissionCapacity       = errors.New("provider admission ledger is at capacity")
	ErrProviderAdmissionUnknown        = errors.New("provider admission record is unavailable")
	ErrProviderAdmissionStaleAttempt   = errors.New("provider admission attempt generation is stale")
	ErrProviderAdmissionIntentMissing  = errors.New("provider admission intent is missing")
	ErrProviderAdmissionIntentMismatch = errors.New("provider admission intent does not match the durable attempt")
	ErrProviderAdmissionIntentUnbound  = errors.New("legacy provider admission has no durable intent binding")
)

// ProviderAdmissionRequest identifies one stable execution attempt and one
// provider. Reusing the pair is idempotent; callers must not mint a new ID to
// bypass exhausted or uncertain state.
type ProviderAdmissionRequest struct {
	ExecutionID     string
	ProviderID      string
	AdmissionIntent string
}

// ProviderAdmissionDecision is a bounded scheduling result. A false Admitted
// value with BACKOFF includes the earliest safe retry; permanent and
// uncertain outcomes are never automatically retried.
type ProviderAdmissionDecision struct {
	ExecutionID     string `json:"execution_id"`
	ProviderID      string `json:"provider_id"`
	State           string `json:"state"`
	Attempt         int    `json:"attempt"`
	Admitted        bool   `json:"admitted"`
	Retryable       bool   `json:"retryable"`
	NextRetryAt     string `json:"next_retry_at,omitempty"`
	nextRetryMillis int64
}

// ProviderAdmissionOutcome must be built from a structured provider/runtime
// result. Free-form model text is not an outcome class. RATE_LIMITED and
// RETRYABLE are accepted only when the adapter knows no injection occurred.
type ProviderAdmissionOutcome struct {
	ExecutionID string        `json:"execution_id"`
	ProviderID  string        `json:"provider_id"`
	Attempt     int           `json:"attempt"`
	Class       string        `json:"class"`
	RetryAfter  time.Duration `json:"retry_after,omitempty"`
}

// ProviderAdmissionReconciliation is accepted only by a local trusted Node
// integration after inspecting the uncertain execution. IdempotencyKey is a
// distinct stable retry key; EvidenceID is the opaque local execution/provider
// observation ID. Only a digest of both is persisted. This is not a model or
// remote Hub assertion.
type ProviderAdmissionReconciliation struct {
	ExecutionID    string `json:"execution_id"`
	ProviderID     string `json:"provider_id"`
	Attempt        int    `json:"attempt"`
	Resolution     string `json:"resolution"`
	IdempotencyKey string `json:"idempotency_key"`
	EvidenceID     string `json:"evidence_id"`
	ObservedAt     string `json:"observed_at"`
}

// AdmitProviderAttempt grants one bounded provider attempt or returns the
// durable backoff/terminal state for the same execution/provider key.
func (i *Inbox) AdmitProviderAttempt(ctx context.Context,
	request ProviderAdmissionRequest) (*ProviderAdmissionDecision, error) {
	request, err := normalizeProviderAdmissionRequest(request)
	if err != nil {
		return nil, err
	}
	intentHash, err := providerAdmissionIntentHash(request.AdmissionIntent)
	if err != nil {
		return nil, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkOpen(); err != nil {
		return nil, err
	}
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin provider admission: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	nowMS := now.UnixMilli()
	if _, err := tx.ExecContext(ctx, `DELETE FROM node_provider_admission_v1
WHERE state IN ('COMPLETED','FAILED','EXHAUSTED') AND updated_at_ms < ?`, now.Add(-providerAdmissionRetention).UnixMilli()); err != nil {
		return nil, fmt.Errorf("expire provider admission history: %w", err)
	}
	decision, err := scanProviderAdmissionDecision(tx.QueryRowContext(ctx, `SELECT state,attempts,created_at_ms,next_retry_at_ms
FROM node_provider_admission_v1 WHERE execution_id=? AND provider_id=?`, request.ExecutionID, request.ProviderID), request)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM node_provider_admission_v1`).Scan(&count); err != nil {
			return nil, err
		}
		if count >= providerAdmissionMaxRows {
			return nil, ErrProviderAdmissionCapacity
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO node_provider_admission_v1
(execution_id,provider_id,state,attempts,created_at_ms,updated_at_ms,next_retry_at_ms,last_class)
VALUES(?,?,?,1,?,?,0,'')`, request.ExecutionID, request.ProviderID,
			ProviderAdmissionInProgress, nowMS, nowMS)
		if err != nil {
			return nil, fmt.Errorf("record provider admission: %w", err)
		}
		if err := insertProviderAdmissionIntentTx(ctx, tx, request, 1, intentHash, nowMS); err != nil {
			return nil, err
		}
		decision = &ProviderAdmissionDecision{ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
			State: ProviderAdmissionInProgress, Attempt: 1, Admitted: true}
	} else if err != nil {
		return nil, err
	} else {
		switch decision.State {
		case ProviderAdmissionInProgress:
			if err := requireProviderAdmissionIntentTx(ctx, tx, request, decision.Attempt, intentHash); err != nil {
				return nil, err
			}
			// Only a replay carrying the intent already durably paired to this
			// generation may recover admission after a lost local ticket write.
			decision.Admitted = true
		case ProviderAdmissionBackoff:
			if err := requireProviderAdmissionIntentBoundTx(ctx, tx, request, decision.Attempt); err != nil {
				return nil, err
			}
			var createdMS int64
			if err := tx.QueryRowContext(ctx, `SELECT created_at_ms FROM node_provider_admission_v1 WHERE execution_id=? AND provider_id=?`,
				request.ExecutionID, request.ProviderID).Scan(&createdMS); err != nil {
				return nil, err
			}
			var previousAttempt int
			intentErr := tx.QueryRowContext(ctx, `SELECT attempt FROM node_provider_admission_intents_v1
WHERE execution_id=? AND provider_id=? AND intent_hash=?`, request.ExecutionID, request.ProviderID, intentHash).Scan(&previousAttempt)
			if intentErr == nil {
				return nil, ErrProviderAdmissionIntentMismatch
			}
			if !errors.Is(intentErr, sql.ErrNoRows) {
				return nil, intentErr
			}
			if decision.Attempt >= providerAdmissionMaxAttempts || nowMS-createdMS >= providerAdmissionMaxAge.Milliseconds() {
				decision.State = ProviderAdmissionExhausted
				decision.Retryable = false
				decision.NextRetryAt = ""
				if _, err := tx.ExecContext(ctx, `UPDATE node_provider_admission_v1 SET state=?,next_retry_at_ms=0,updated_at_ms=?
WHERE execution_id=? AND provider_id=? AND state=?`, ProviderAdmissionExhausted, nowMS,
					request.ExecutionID, request.ProviderID, ProviderAdmissionBackoff); err != nil {
					return nil, err
				}
			} else if nowMS < decision.nextRetryMillis {
				decision.Retryable = true
			} else {
				decision.Attempt++
				decision.State = ProviderAdmissionInProgress
				decision.Admitted = true
				decision.Retryable = false
				decision.NextRetryAt = ""
				result, err := tx.ExecContext(ctx, `UPDATE node_provider_admission_v1 SET state=?,attempts=?,next_retry_at_ms=0,updated_at_ms=?
WHERE execution_id=? AND provider_id=? AND state=? AND attempts=?`, ProviderAdmissionInProgress,
					decision.Attempt, nowMS, request.ExecutionID, request.ProviderID,
					ProviderAdmissionBackoff, decision.Attempt-1)
				if err != nil {
					return nil, err
				}
				changed, err := result.RowsAffected()
				if err != nil || changed != 1 {
					return nil, ErrProviderAdmissionStaleAttempt
				}
				if err := insertProviderAdmissionIntentTx(ctx, tx, request, decision.Attempt, intentHash, nowMS); err != nil {
					return nil, err
				}
			}
		case ProviderAdmissionCompleted, ProviderAdmissionFailed,
			ProviderAdmissionInjectionUncertain, ProviderAdmissionExhausted:
			decision.Retryable = decision.State == ProviderAdmissionBackoff
		default:
			return nil, ErrProviderAdmissionInvalid
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit provider admission: %w", err)
	}
	return decision, nil
}

// RecordProviderAdmissionOutcome closes the current attempt. Only structured
// not-injected rate-limit/transient outcomes schedule another bounded attempt;
// INJECTION_UNCERTAIN remains terminal until a separate trusted reconciliation.
func (i *Inbox) RecordProviderAdmissionOutcome(ctx context.Context,
	outcome ProviderAdmissionOutcome) (*ProviderAdmissionDecision, error) {
	if outcome.Attempt <= 0 {
		return nil, ErrProviderAdmissionInvalid
	}
	request, err := normalizeProviderAdmissionRequest(ProviderAdmissionRequest{
		ExecutionID: outcome.ExecutionID, ProviderID: outcome.ProviderID,
	})
	if err != nil {
		return nil, err
	}
	switch outcome.Class {
	case ProviderOutcomeRateLimitedNotInjected, ProviderOutcomeRetryableNotInjected,
		ProviderOutcomeCompleted, ProviderOutcomeFailedNotInjected, ProviderOutcomeInjectionUncertain:
	default:
		return nil, ErrProviderAdmissionInvalid
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkOpen(); err != nil {
		return nil, err
	}
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin provider outcome: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	decision, err := scanProviderAdmissionDecision(tx.QueryRowContext(ctx, `SELECT state,attempts,created_at_ms,next_retry_at_ms
FROM node_provider_admission_v1 WHERE execution_id=? AND provider_id=?`, request.ExecutionID, request.ProviderID), request)
	if err != nil {
		return nil, err
	}
	if decision.Attempt != outcome.Attempt {
		return nil, ErrProviderAdmissionStaleAttempt
	}
	if decision.State != ProviderAdmissionInProgress {
		// An exact repeat of the terminal outcome is safe to recover after a lost
		// response; a different transition cannot advance the attempt twice.
		var previous string
		if scanErr := tx.QueryRowContext(ctx, `SELECT last_class FROM node_provider_admission_v1 WHERE execution_id=? AND provider_id=?`,
			request.ExecutionID, request.ProviderID).Scan(&previous); scanErr != nil || previous != outcome.Class {
			return nil, ErrInvalidState
		}
		decision.Admitted = false
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return decision, nil
	}
	state := ""
	nextRetryMS := int64(0)
	var createdMS int64
	if err := tx.QueryRowContext(ctx, `SELECT created_at_ms FROM node_provider_admission_v1 WHERE execution_id=? AND provider_id=?`,
		request.ExecutionID, request.ProviderID).Scan(&createdMS); err != nil {
		return nil, err
	}
	switch outcome.Class {
	case ProviderOutcomeRateLimitedNotInjected, ProviderOutcomeRetryableNotInjected:
		if decision.Attempt >= providerAdmissionMaxAttempts || now.UnixMilli()-createdMS >= providerAdmissionMaxAge.Milliseconds() {
			state = ProviderAdmissionExhausted
		} else {
			state = ProviderAdmissionBackoff
			delay := time.Second << min(decision.Attempt-1, 10)
			if delay > providerAdmissionMaxBackoff {
				delay = providerAdmissionMaxBackoff
			}
			if outcome.Class == ProviderOutcomeRateLimitedNotInjected && outcome.RetryAfter > delay {
				delay = outcome.RetryAfter
			}
			if delay > providerAdmissionMaxBackoff {
				delay = providerAdmissionMaxBackoff
			}
			nextRetryMS = now.Add(delay).UnixMilli()
		}
	case ProviderOutcomeCompleted:
		state = ProviderAdmissionCompleted
	case ProviderOutcomeFailedNotInjected:
		state = ProviderAdmissionFailed
	case ProviderOutcomeInjectionUncertain:
		state = ProviderAdmissionInjectionUncertain
	}
	result, err := tx.ExecContext(ctx, `UPDATE node_provider_admission_v1 SET state=?,next_retry_at_ms=?,updated_at_ms=?,last_class=?
WHERE execution_id=? AND provider_id=? AND state=? AND attempts=?`, state, nextRetryMS,
		now.UnixMilli(), outcome.Class, request.ExecutionID, request.ProviderID,
		ProviderAdmissionInProgress, outcome.Attempt)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, ErrProviderAdmissionStaleAttempt
	}
	decision.State = state
	decision.Admitted = false
	decision.Retryable = state == ProviderAdmissionBackoff
	decision.NextRetryAt = ""
	if nextRetryMS > 0 {
		decision.NextRetryAt = time.UnixMilli(nextRetryMS).UTC().Format(time.RFC3339Nano)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit provider outcome: %w", err)
	}
	return decision, nil
}

// InspectProviderAttempt reads a current state without advancing or creating
// the attempt. IN_PROGRESS and INJECTION_UNCERTAIN never grant a retry.
func (i *Inbox) InspectProviderAttempt(ctx context.Context,
	request ProviderAdmissionRequest) (*ProviderAdmissionDecision, error) {
	request, err := normalizeProviderAdmissionRequest(request)
	if err != nil {
		return nil, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkOpen(); err != nil {
		return nil, err
	}
	decision, err := scanProviderAdmissionDecision(i.db.QueryRowContext(ctx, `SELECT state,attempts,created_at_ms,next_retry_at_ms
FROM node_provider_admission_v1 WHERE execution_id=? AND provider_id=?`, request.ExecutionID, request.ProviderID), request)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProviderAdmissionUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("inspect provider attempt: %w", err)
	}
	if request.AdmissionIntent != "" {
		intentHash, hashErr := providerAdmissionIntentHash(request.AdmissionIntent)
		if hashErr != nil {
			return nil, hashErr
		}
		if matchErr := requireProviderAdmissionIntentDB(ctx, i.db, request, decision.Attempt, intentHash); matchErr != nil {
			return nil, matchErr
		}
	}
	return decision, nil
}

// ReconcileProviderInjectionUncertain can only resolve the existing uncertain
// attempt to a terminal state. It does not create a replacement execution or
// schedule another attempt. Exact evidence/decision retries are idempotent.
func (i *Inbox) ReconcileProviderInjectionUncertain(ctx context.Context,
	reconciliation ProviderAdmissionReconciliation) (*ProviderAdmissionDecision, error) {
	if reconciliation.Attempt <= 0 {
		return nil, ErrProviderAdmissionInvalid
	}
	request, err := normalizeProviderAdmissionRequest(ProviderAdmissionRequest{
		ExecutionID: reconciliation.ExecutionID, ProviderID: reconciliation.ProviderID,
	})
	if err != nil {
		return nil, err
	}
	if reconciliation.Resolution != ProviderReconcileCompleted && reconciliation.Resolution != ProviderReconcileFailed {
		return nil, ErrProviderAdmissionInvalid
	}
	reconciliation.IdempotencyKey = strings.TrimSpace(reconciliation.IdempotencyKey)
	reconciliation.EvidenceID = strings.TrimSpace(reconciliation.EvidenceID)
	if reconciliation.IdempotencyKey == "" || len(reconciliation.IdempotencyKey) > 256 ||
		reconciliation.EvidenceID == "" || len(reconciliation.EvidenceID) > 512 ||
		strings.ContainsAny(reconciliation.IdempotencyKey+reconciliation.EvidenceID, "\x00\r\n") {
		return nil, ErrProviderAdmissionInvalid
	}
	observedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(reconciliation.ObservedAt))
	if err != nil || observedAt.IsZero() || observedAt.After(time.Now().Add(time.Minute)) {
		return nil, ErrProviderAdmissionInvalid
	}
	evidenceDigest := sha256.Sum256([]byte(reconciliation.IdempotencyKey + "\x00" + reconciliation.EvidenceID))
	lastClass := "RECONCILED:" + reconciliation.Resolution + ":" + hex.EncodeToString(evidenceDigest[:])
	terminalState := ProviderAdmissionCompleted
	if reconciliation.Resolution == ProviderReconcileFailed {
		terminalState = ProviderAdmissionFailed
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkOpen(); err != nil {
		return nil, err
	}
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin provider reconciliation: %w", err)
	}
	defer tx.Rollback()
	decision, err := scanProviderAdmissionDecision(tx.QueryRowContext(ctx, `SELECT state,attempts,created_at_ms,next_retry_at_ms
FROM node_provider_admission_v1 WHERE execution_id=? AND provider_id=?`, request.ExecutionID, request.ProviderID), request)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProviderAdmissionUnknown
	}
	if err != nil {
		return nil, err
	}
	if decision.Attempt != reconciliation.Attempt {
		return nil, ErrProviderAdmissionStaleAttempt
	}
	var previousClass string
	if err := tx.QueryRowContext(ctx, `SELECT last_class FROM node_provider_admission_v1 WHERE execution_id=? AND provider_id=?`,
		request.ExecutionID, request.ProviderID).Scan(&previousClass); err != nil {
		return nil, err
	}
	if decision.State == terminalState && previousClass == lastClass {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return decision, nil
	}
	if decision.State != ProviderAdmissionInjectionUncertain {
		return nil, ErrInvalidState
	}
	result, err := tx.ExecContext(ctx, `UPDATE node_provider_admission_v1 SET state=?,next_retry_at_ms=0,updated_at_ms=?,last_class=?
WHERE execution_id=? AND provider_id=? AND state=? AND attempts=?`, terminalState, observedAt.UTC().UnixMilli(), lastClass,
		request.ExecutionID, request.ProviderID, ProviderAdmissionInjectionUncertain, reconciliation.Attempt)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, ErrInvalidState
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit provider reconciliation: %w", err)
	}
	decision.State = terminalState
	decision.Admitted = false
	decision.Retryable = false
	decision.NextRetryAt = ""
	decision.nextRetryMillis = 0
	return decision, nil
}

func scanProviderAdmissionDecision(row interface{ Scan(...any) error }, request ProviderAdmissionRequest) (*ProviderAdmissionDecision, error) {
	var state string
	var attempts int
	var createdMS, nextRetryMS int64
	if err := row.Scan(&state, &attempts, &createdMS, &nextRetryMS); err != nil {
		return nil, err
	}
	decision := &ProviderAdmissionDecision{ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
		State: state, Attempt: attempts, Retryable: state == ProviderAdmissionBackoff,
		nextRetryMillis: nextRetryMS,
	}
	if nextRetryMS > 0 {
		decision.NextRetryAt = time.UnixMilli(nextRetryMS).UTC().Format(time.RFC3339Nano)
	}
	return decision, nil
}

func normalizeProviderAdmissionRequest(request ProviderAdmissionRequest) (ProviderAdmissionRequest, error) {
	request.ExecutionID = strings.TrimSpace(request.ExecutionID)
	request.ProviderID = strings.TrimSpace(request.ProviderID)
	if request.ExecutionID == "" || len(request.ExecutionID) > 256 || request.ProviderID == "" || len(request.ProviderID) > 128 ||
		strings.ContainsAny(request.ExecutionID+request.ProviderID, "\x00\r\n") {
		return ProviderAdmissionRequest{}, ErrProviderAdmissionInvalid
	}
	return request, nil
}

func providerAdmissionIntentHash(intent string) (string, error) {
	if intent != strings.TrimSpace(intent) || len(intent) != 64 || strings.ToLower(intent) != intent || strings.ContainsAny(intent, "\x00\r\n") {
		return "", ErrProviderAdmissionIntentMissing
	}
	decoded, err := hex.DecodeString(intent)
	if err != nil || len(decoded) != 32 {
		return "", ErrProviderAdmissionIntentMissing
	}
	digest := sha256.Sum256([]byte("cicada/provider-admission-intent/v1\x00" + intent))
	return hex.EncodeToString(digest[:]), nil
}

func insertProviderAdmissionIntentTx(ctx context.Context, tx *sql.Tx, request ProviderAdmissionRequest,
	attempt int, intentHash string, nowMS int64) error {
	if attempt <= 0 || intentHash == "" {
		return ErrProviderAdmissionInvalid
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO node_provider_admission_intents_v1
(execution_id,provider_id,attempt,intent_hash,created_at_ms) VALUES(?,?,?,?,?)`,
		request.ExecutionID, request.ProviderID, attempt, intentHash, nowMS); err != nil {
		return fmt.Errorf("bind provider admission intent to generation: %w", err)
	}
	return nil
}

func requireProviderAdmissionIntentTx(ctx context.Context, tx *sql.Tx, request ProviderAdmissionRequest,
	attempt int, intentHash string) error {
	var persistedHash string
	err := tx.QueryRowContext(ctx, `SELECT intent_hash FROM node_provider_admission_intents_v1
WHERE execution_id=? AND provider_id=? AND attempt=?`, request.ExecutionID, request.ProviderID, attempt).Scan(&persistedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrProviderAdmissionIntentUnbound
	}
	if err != nil {
		return err
	}
	if persistedHash != intentHash {
		return ErrProviderAdmissionIntentMismatch
	}
	return nil
}

func requireProviderAdmissionIntentBoundTx(ctx context.Context, tx *sql.Tx,
	request ProviderAdmissionRequest, attempt int) error {
	var exists int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM node_provider_admission_intents_v1
WHERE execution_id=? AND provider_id=? AND attempt=?`, request.ExecutionID, request.ProviderID, attempt).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrProviderAdmissionIntentUnbound
	}
	return err
}

func requireProviderAdmissionIntentDB(ctx context.Context, db *sql.DB, request ProviderAdmissionRequest,
	attempt int, intentHash string) error {
	var persistedHash string
	err := db.QueryRowContext(ctx, `SELECT intent_hash FROM node_provider_admission_intents_v1
WHERE execution_id=? AND provider_id=? AND attempt=?`, request.ExecutionID, request.ProviderID, attempt).Scan(&persistedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrProviderAdmissionIntentUnbound
	}
	if err != nil {
		return err
	}
	if persistedHash != intentHash {
		return ErrProviderAdmissionIntentMismatch
	}
	return nil
}
