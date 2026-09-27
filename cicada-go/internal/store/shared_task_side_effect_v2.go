package store

// Shared Task side-effect records persist intent and recovery knowledge. They
// do not execute external work and cannot make arbitrary external actions
// exactly-once; callers must inspect STARTED records after interruption and
// reconcile uncertain outcomes before authorizing another attempt.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

const (
	SharedTaskSideEffectIntended               = "INTENDED"
	SharedTaskSideEffectStarted                = "STARTED"
	SharedTaskSideEffectCompleted              = "COMPLETED"
	SharedTaskSideEffectUncertain              = "UNCERTAIN"
	SharedTaskSideEffectReconciliationRequired = "RECONCILIATION_REQUIRED"
	SharedTaskSideEffectReconciled             = "RECONCILED"
	SharedTaskSideEffectOutcomeApplied         = "APPLIED"
	SharedTaskSideEffectOutcomeNotApplied      = "NOT_APPLIED"
)

var (
	ErrSharedTaskSideEffectNotFound       = errors.New("shared task side effect not found")
	ErrSharedTaskSideEffectConflict       = errors.New("shared task side effect key or state conflicts")
	ErrSharedTaskSideEffectAlreadyStarted = errors.New("shared task side effect may already have started; reconcile before retrying")
)

// SharedTaskSideEffect is a durable operation intent, not proof that a remote
// system performed the action. Digest should commit to the operation's
// resource, intent, and action-specific input without storing credentials or
// the potentially sensitive input itself.
type SharedTaskSideEffect struct {
	ID                     string `json:"side_effect_id"`
	TaskID                 string `json:"task_id"`
	Key                    string `json:"idempotency_key"`
	Digest                 string `json:"digest"`
	Intent                 string `json:"intent"`
	ResourceID             string `json:"resource_id"`
	OwnerEpoch             int64  `json:"owner_epoch"`
	State                  string `json:"state"`
	CompletionEvidence     string `json:"completion_evidence,omitempty"`
	UncertaintyReason      string `json:"uncertainty_reason,omitempty"`
	ReconciliationReason   string `json:"reconciliation_reason,omitempty"`
	ReconciliationOutcome  string `json:"reconciliation_outcome,omitempty"`
	ReconciliationEvidence string `json:"reconciliation_evidence,omitempty"`
	StartedAt              string `json:"started_at,omitempty"`
	CompletedAt            string `json:"completed_at,omitempty"`
	UncertainAt            string `json:"uncertain_at,omitempty"`
	ReconciliationAt       string `json:"reconciliation_required_at,omitempty"`
	ReconciledAt           string `json:"reconciled_at,omitempty"`
	CreatedAt              string `json:"created_at"`
	UpdatedAt              string `json:"updated_at"`
}

// SharedTaskSideEffectIntent describes an operation before its external call.
// The (TaskID, Key) pair is the idempotency scope; Digest distinguishes a
// legitimate retry from accidental key reuse for different work.
type SharedTaskSideEffectIntent struct {
	TaskID      string
	Key         string
	Digest      string
	Intent      string
	ResourceID  string
	PrincipalID string
	EndpointID  string
	OwnerEpoch  int64
}

type SharedTaskSideEffectEvent struct {
	ID             string `json:"event_id"`
	Sequence       int64  `json:"sequence"`
	TaskID         string `json:"task_id"`
	SideEffectID   string `json:"side_effect_id"`
	Key            string `json:"idempotency_key"`
	Kind           string `json:"kind"`
	FromState      string `json:"from_state,omitempty"`
	ToState        string `json:"to_state"`
	ActorPrincipal string `json:"actor_principal_id"`
	ActorEndpoint  string `json:"actor_endpoint_id"`
	OwnerEpoch     int64  `json:"owner_epoch"`
	DetailsJSON    string `json:"details_json"`
	CreatedAt      string `json:"created_at"`
}

// SharedTaskHandoffSideEffectLedger gives a receiver one durable view of the
// handoff's no-repeat notes and this Task's side-effect entries that still
// need a decision. No-repeat notes are queryable guidance; arbitrary wording
// is not treated as an enforceable external idempotency mechanism.
type SharedTaskHandoffSideEffectLedger struct {
	Handoff                *SharedTaskHandoff     `json:"handoff"`
	NoRepeatActions        []string               `json:"no_repeat_actions"`
	SideEffects            []SharedTaskSideEffect `json:"side_effects"`
	UnconfirmedSideEffects []SharedTaskSideEffect `json:"unconfirmed_side_effects"`
}

func (s *Store) initializeSharedTaskSideEffectSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS shared_task_v2_side_effects (
 id TEXT PRIMARY KEY,
 task_id TEXT NOT NULL,
 idempotency_key TEXT NOT NULL,
 digest TEXT NOT NULL,
 intent TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 owner_epoch INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('INTENDED','STARTED','COMPLETED','UNCERTAIN','RECONCILIATION_REQUIRED','RECONCILED')),
 completion_evidence TEXT NOT NULL DEFAULT '',
 uncertainty_reason TEXT NOT NULL DEFAULT '',
 reconciliation_reason TEXT NOT NULL DEFAULT '',
 reconciliation_outcome TEXT NOT NULL DEFAULT '' CHECK(reconciliation_outcome IN ('','APPLIED','NOT_APPLIED')),
 reconciliation_evidence TEXT NOT NULL DEFAULT '',
 started_at TEXT NOT NULL DEFAULT '',
 completed_at TEXT NOT NULL DEFAULT '',
 uncertain_at TEXT NOT NULL DEFAULT '',
 reconciliation_required_at TEXT NOT NULL DEFAULT '',
 reconciled_at TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(task_id,idempotency_key),
 FOREIGN KEY(task_id) REFERENCES shared_tasks_v2(id)
);
CREATE INDEX IF NOT EXISTS shared_task_v2_side_effects_task_state_idx
 ON shared_task_v2_side_effects(task_id,state,created_at,id);
CREATE TABLE IF NOT EXISTS shared_task_v2_side_effect_events (
 id TEXT PRIMARY KEY,
 sequence INTEGER NOT NULL,
 task_id TEXT NOT NULL,
 side_effect_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 from_state TEXT NOT NULL DEFAULT '',
 to_state TEXT NOT NULL,
 actor_principal_id TEXT NOT NULL,
 actor_endpoint_id TEXT NOT NULL,
 owner_epoch INTEGER NOT NULL,
 details_json TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL,
 UNIQUE(side_effect_id,sequence),
 FOREIGN KEY(task_id) REFERENCES shared_tasks_v2(id),
 FOREIGN KEY(side_effect_id) REFERENCES shared_task_v2_side_effects(id)
);
CREATE INDEX IF NOT EXISTS shared_task_v2_side_effect_events_task_idx
 ON shared_task_v2_side_effect_events(task_id,side_effect_id,created_at,id);`)
	return err
}

const sharedTaskSideEffectColumns = `id,task_id,idempotency_key,digest,intent,resource_id,owner_epoch,state,
completion_evidence,uncertainty_reason,reconciliation_reason,reconciliation_outcome,reconciliation_evidence,
started_at,completed_at,uncertain_at,reconciliation_required_at,reconciled_at,created_at,updated_at`

func scanSharedTaskSideEffect(row interface{ Scan(...any) error }) (*SharedTaskSideEffect, error) {
	var value SharedTaskSideEffect
	err := row.Scan(&value.ID, &value.TaskID, &value.Key, &value.Digest, &value.Intent, &value.ResourceID, &value.OwnerEpoch,
		&value.State, &value.CompletionEvidence, &value.UncertaintyReason, &value.ReconciliationReason,
		&value.ReconciliationOutcome, &value.ReconciliationEvidence, &value.StartedAt, &value.CompletedAt,
		&value.UncertainAt, &value.ReconciliationAt, &value.ReconciledAt, &value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSharedTaskSideEffectNotFound
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func loadSharedTaskSideEffectTx(tx *sql.Tx, taskID, key string) (*SharedTaskSideEffect, error) {
	return scanSharedTaskSideEffect(tx.QueryRow(`SELECT `+sharedTaskSideEffectColumns+`
 FROM shared_task_v2_side_effects WHERE task_id=? AND idempotency_key=?`, taskID, key))
}

func validateSharedTaskSideEffectOwner(task *SharedTask, principalID, endpointID string, ownerEpoch int64) error {
	if task.OwnerPrincipalID != principalID || task.OwnerEndpointID != endpointID || task.OwnerEpoch != ownerEpoch ||
		!sharedTaskLeaseActive(task.LeaseExpiresAt) || (task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
		return ErrSharedTaskStaleOwner
	}
	return nil
}

func (s *Store) GetSharedTaskSideEffect(taskID, key string) (*SharedTaskSideEffect, error) {
	if strings.TrimSpace(taskID) == "" || strings.TrimSpace(key) == "" {
		return nil, ErrSharedTaskSideEffectNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanSharedTaskSideEffect(s.db.QueryRow(`SELECT `+sharedTaskSideEffectColumns+`
 FROM shared_task_v2_side_effects WHERE task_id=? AND idempotency_key=?`, taskID, key))
}

// RecordSharedTaskSideEffectIntent durably reserves one task-scoped key. A
// same-key, same-digest retry returns the existing record; a changed digest
// fails closed. This commits the intent only. It does not invoke an action.
func (s *Store) RecordSharedTaskSideEffectIntent(input SharedTaskSideEffectIntent) (*SharedTaskSideEffect, error) {
	input.TaskID = strings.TrimSpace(input.TaskID)
	input.Key = strings.TrimSpace(input.Key)
	input.Digest = strings.TrimSpace(input.Digest)
	input.Intent = strings.TrimSpace(input.Intent)
	input.ResourceID = strings.TrimSpace(input.ResourceID)
	if input.TaskID == "" || input.Key == "" || input.Digest == "" || input.Intent == "" || input.ResourceID == "" ||
		input.PrincipalID == "" || input.EndpointID == "" || input.OwnerEpoch <= 0 || len(input.Key) > 256 || len(input.Digest) > 256 ||
		len(input.Intent) > 2048 || len(input.ResourceID) > 512 {
		return nil, ErrSharedTaskSideEffectConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = acquireSharedTaskWrite(tx); err != nil {
		return nil, err
	}
	task, err := loadSharedTaskTx(tx, input.TaskID)
	if err != nil {
		return nil, err
	}
	if err = validateSharedTaskSideEffectOwner(task, input.PrincipalID, input.EndpointID, input.OwnerEpoch); err != nil {
		return nil, err
	}
	if existing, loadErr := loadSharedTaskSideEffectTx(tx, input.TaskID, input.Key); loadErr == nil {
		if existing.Digest != input.Digest {
			return nil, ErrSharedTaskSideEffectConflict
		}
		return existing, nil
	} else if !errors.Is(loadErr, ErrSharedTaskSideEffectNotFound) {
		return nil, loadErr
	}
	created := now()
	value := &SharedTaskSideEffect{ID: NewID("sidefx"), TaskID: input.TaskID, Key: input.Key, Digest: input.Digest,
		Intent: input.Intent, ResourceID: input.ResourceID, OwnerEpoch: input.OwnerEpoch,
		State: SharedTaskSideEffectIntended, CreatedAt: created, UpdatedAt: created}
	_, err = tx.Exec(`INSERT INTO shared_task_v2_side_effects (`+sharedTaskSideEffectColumns+`)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, value.ID, value.TaskID, value.Key, value.Digest, value.Intent,
		value.ResourceID, value.OwnerEpoch, value.State, value.CompletionEvidence, value.UncertaintyReason,
		value.ReconciliationReason, value.ReconciliationOutcome, value.ReconciliationEvidence, value.StartedAt,
		value.CompletedAt, value.UncertainAt, value.ReconciliationAt, value.ReconciledAt, value.CreatedAt, value.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if err = sharedTaskSideEffectEventTx(tx, value, "INTENT_RECORDED", "", value.State, input.PrincipalID, input.EndpointID,
		input.OwnerEpoch, map[string]string{"resource_id": value.ResourceID}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return value, nil
}

// MarkSharedTaskSideEffectStarted is a durable authorization point immediately
// before the caller invokes its external action. A repeated call is rejected:
// its previous response may have been lost after the external call started.
func (s *Store) MarkSharedTaskSideEffectStarted(taskID, key, digest, principalID, endpointID string, ownerEpoch int64) (*SharedTaskSideEffect, error) {
	return s.transitionSharedTaskSideEffect(taskID, key, digest, principalID, endpointID, ownerEpoch, sideEffectTransition{
		kind: "STARTED", allowed: []string{SharedTaskSideEffectIntended, SharedTaskSideEffectReconciled}, to: SharedTaskSideEffectStarted,
	})
}

func (s *Store) CompleteSharedTaskSideEffect(taskID, key, digest, principalID, endpointID string, ownerEpoch int64, evidence string) (*SharedTaskSideEffect, error) {
	evidence = strings.TrimSpace(evidence)
	if evidence == "" || len(evidence) > 2048 {
		return nil, ErrSharedTaskSideEffectConflict
	}
	return s.transitionSharedTaskSideEffect(taskID, key, digest, principalID, endpointID, ownerEpoch, sideEffectTransition{
		kind: "COMPLETED", allowed: []string{SharedTaskSideEffectStarted}, to: SharedTaskSideEffectCompleted,
		idempotent: SharedTaskSideEffectCompleted, details: map[string]string{"completion_evidence": evidence},
		sameResult: func(value *SharedTaskSideEffect) bool { return value.CompletionEvidence == evidence },
		apply: func(value *SharedTaskSideEffect, at string) {
			value.CompletionEvidence = evidence
			value.CompletedAt = at
		},
	})
}

func (s *Store) MarkSharedTaskSideEffectUncertain(taskID, key, digest, principalID, endpointID string, ownerEpoch int64, reason string) (*SharedTaskSideEffect, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 2048 {
		return nil, ErrSharedTaskSideEffectConflict
	}
	return s.transitionSharedTaskSideEffect(taskID, key, digest, principalID, endpointID, ownerEpoch, sideEffectTransition{
		kind: "UNCERTAIN", allowed: []string{SharedTaskSideEffectStarted}, to: SharedTaskSideEffectUncertain,
		idempotent: SharedTaskSideEffectUncertain, details: map[string]string{"reason": reason},
		sameResult: func(value *SharedTaskSideEffect) bool { return value.UncertaintyReason == reason },
		apply: func(value *SharedTaskSideEffect, at string) {
			value.UncertaintyReason = reason
			value.UncertainAt = at
		},
	})
}

func (s *Store) RequireSharedTaskSideEffectReconciliation(taskID, key, digest, principalID, endpointID string, ownerEpoch int64, reason string) (*SharedTaskSideEffect, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 2048 {
		return nil, ErrSharedTaskSideEffectConflict
	}
	return s.transitionSharedTaskSideEffect(taskID, key, digest, principalID, endpointID, ownerEpoch, sideEffectTransition{
		kind: "RECONCILIATION_REQUIRED", allowed: []string{SharedTaskSideEffectStarted, SharedTaskSideEffectUncertain},
		to: SharedTaskSideEffectReconciliationRequired, idempotent: SharedTaskSideEffectReconciliationRequired,
		details:    map[string]string{"reason": reason},
		sameResult: func(value *SharedTaskSideEffect) bool { return value.ReconciliationReason == reason },
		apply: func(value *SharedTaskSideEffect, at string) {
			value.ReconciliationReason = reason
			value.ReconciliationAt = at
		},
	})
}

// ReconcileSharedTaskSideEffect records evidence that the action did or did
// not take effect. An unknown outcome is intentionally not accepted as a
// resolution; the record remains reconciliation-required until evidence can
// distinguish the two outcomes.
func (s *Store) ReconcileSharedTaskSideEffect(taskID, key, digest, principalID, endpointID string, ownerEpoch int64, outcome, evidence string) (*SharedTaskSideEffect, error) {
	outcome = strings.TrimSpace(outcome)
	evidence = strings.TrimSpace(evidence)
	if outcome != SharedTaskSideEffectOutcomeApplied && outcome != SharedTaskSideEffectOutcomeNotApplied || evidence == "" || len(evidence) > 2048 {
		return nil, ErrSharedTaskSideEffectConflict
	}
	return s.transitionSharedTaskSideEffect(taskID, key, digest, principalID, endpointID, ownerEpoch, sideEffectTransition{
		kind: "RECONCILED", allowed: []string{SharedTaskSideEffectReconciliationRequired}, to: SharedTaskSideEffectReconciled,
		idempotent: SharedTaskSideEffectReconciled, details: map[string]string{"outcome": outcome, "evidence": evidence},
		apply: func(value *SharedTaskSideEffect, at string) {
			value.ReconciliationOutcome = outcome
			value.ReconciliationEvidence = evidence
			value.ReconciledAt = at
		},
		sameResult: func(value *SharedTaskSideEffect) bool {
			return value.ReconciliationOutcome == outcome && value.ReconciliationEvidence == evidence
		},
	})
}

type sideEffectTransition struct {
	kind       string
	allowed    []string
	to         string
	idempotent string
	details    any
	apply      func(*SharedTaskSideEffect, string)
	sameResult func(*SharedTaskSideEffect) bool
}

func (s *Store) transitionSharedTaskSideEffect(taskID, key, digest, principalID, endpointID string, ownerEpoch int64, transition sideEffectTransition) (*SharedTaskSideEffect, error) {
	taskID, key, digest = strings.TrimSpace(taskID), strings.TrimSpace(key), strings.TrimSpace(digest)
	if taskID == "" || key == "" || digest == "" || principalID == "" || endpointID == "" || ownerEpoch <= 0 {
		return nil, ErrSharedTaskSideEffectConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = acquireSharedTaskWrite(tx); err != nil {
		return nil, err
	}
	task, err := loadSharedTaskTx(tx, taskID)
	if err != nil {
		return nil, err
	}
	if err = validateSharedTaskSideEffectOwner(task, principalID, endpointID, ownerEpoch); err != nil {
		return nil, err
	}
	value, err := loadSharedTaskSideEffectTx(tx, taskID, key)
	if err != nil {
		return nil, err
	}
	if value.Digest != digest {
		return nil, ErrSharedTaskSideEffectConflict
	}
	if transition.kind == "STARTED" && value.State == SharedTaskSideEffectReconciled &&
		value.ReconciliationOutcome != SharedTaskSideEffectOutcomeNotApplied {
		return nil, ErrSharedTaskSideEffectAlreadyStarted
	}
	if value.State == transition.idempotent {
		if transition.sameResult != nil && !transition.sameResult(value) {
			return nil, ErrSharedTaskSideEffectConflict
		}
		return value, nil
	}
	allowed := false
	for _, state := range transition.allowed {
		if value.State == state {
			allowed = true
			break
		}
	}
	if !allowed {
		if transition.kind == "STARTED" && (value.State == SharedTaskSideEffectStarted || value.State == SharedTaskSideEffectUncertain ||
			value.State == SharedTaskSideEffectReconciliationRequired || value.State == SharedTaskSideEffectCompleted ||
			value.State == SharedTaskSideEffectReconciled && value.ReconciliationOutcome == SharedTaskSideEffectOutcomeApplied) {
			return nil, ErrSharedTaskSideEffectAlreadyStarted
		}
		return nil, ErrSharedTaskSideEffectConflict
	}
	previousState := value.State
	at := now()
	if transition.kind == "STARTED" {
		// An INTENDED record is known to be pre-invocation. A new epoch may
		// safely adopt it after handoff; a started record instead requires a
		// positive reconciliation outcome before any retry.
		value.OwnerEpoch = ownerEpoch
		value.CompletionEvidence = ""
		value.UncertaintyReason = ""
		value.ReconciliationReason = ""
		value.ReconciliationOutcome = ""
		value.ReconciliationEvidence = ""
		value.CompletedAt = ""
		value.UncertainAt = ""
		value.ReconciliationAt = ""
		value.ReconciledAt = ""
		value.StartedAt = at
		value.UpdatedAt = at
	} else {
		if transition.apply != nil {
			transition.apply(value, at)
		}
		value.State = transition.to
		value.UpdatedAt = at
	}
	if transition.kind == "STARTED" {
		value.State = transition.to
	}
	result, err := tx.Exec(`UPDATE shared_task_v2_side_effects SET owner_epoch=?,state=?,completion_evidence=?,uncertainty_reason=?,
 reconciliation_reason=?,reconciliation_outcome=?,reconciliation_evidence=?,started_at=?,completed_at=?,uncertain_at=?,
 reconciliation_required_at=?,reconciled_at=?,updated_at=? WHERE id=? AND state=?`, value.OwnerEpoch, value.State,
		value.CompletionEvidence, value.UncertaintyReason, value.ReconciliationReason, value.ReconciliationOutcome,
		value.ReconciliationEvidence, value.StartedAt, value.CompletedAt, value.UncertainAt, value.ReconciliationAt,
		value.ReconciledAt, value.UpdatedAt, value.ID, previousState)
	if err != nil {
		return nil, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rows != 1 {
		return nil, ErrSharedTaskSideEffectConflict
	}
	if err = sharedTaskSideEffectEventTx(tx, value, transition.kind, previousState, value.State, principalID, endpointID, ownerEpoch, transition.details); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return value, nil
}

func sharedTaskSideEffectEventTx(tx *sql.Tx, value *SharedTaskSideEffect, kind, fromState, toState, principalID, endpointID string, ownerEpoch int64, details any) error {
	encoded, err := json.Marshal(details)
	if err != nil {
		return err
	}
	var sequence int64
	if err = tx.QueryRow(`SELECT COALESCE(MAX(sequence),0)+1 FROM shared_task_v2_side_effect_events WHERE side_effect_id=?`, value.ID).Scan(&sequence); err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO shared_task_v2_side_effect_events
(id,sequence,task_id,side_effect_id,kind,from_state,to_state,actor_principal_id,actor_endpoint_id,owner_epoch,details_json,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, NewID("sfxevt"), sequence, value.TaskID, value.ID, kind, fromState, toState, principalID, endpointID,
		ownerEpoch, string(encoded), now())
	return err
}

func (s *Store) ListSharedTaskSideEffects(taskID string) ([]SharedTaskSideEffect, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, ErrSharedTaskNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRow(`SELECT count(*) FROM shared_tasks_v2 WHERE id=?`, taskID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, ErrSharedTaskNotFound
	}
	values, err := listSharedTaskSideEffectsTx(tx, taskID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return values, nil
}

func isSharedTaskSideEffectUnconfirmed(state string) bool {
	switch state {
	case SharedTaskSideEffectIntended, SharedTaskSideEffectStarted, SharedTaskSideEffectUncertain,
		SharedTaskSideEffectReconciliationRequired:
		return true
	default:
		return false
	}
}

func (s *Store) ListUnconfirmedSharedTaskSideEffects(taskID string) ([]SharedTaskSideEffect, error) {
	values, err := s.ListSharedTaskSideEffects(taskID)
	if err != nil {
		return nil, err
	}
	result := make([]SharedTaskSideEffect, 0, len(values))
	for _, value := range values {
		if isSharedTaskSideEffectUnconfirmed(value.State) {
			result = append(result, value)
		}
	}
	return result, nil
}

func (s *Store) ListSharedTaskSideEffectEvents(taskID, key string) ([]SharedTaskSideEffectEvent, error) {
	taskID, key = strings.TrimSpace(taskID), strings.TrimSpace(key)
	if taskID == "" || key == "" {
		return nil, ErrSharedTaskSideEffectNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var exists int
	if err := s.db.QueryRow(`SELECT count(*) FROM shared_task_v2_side_effects WHERE task_id=? AND idempotency_key=?`, taskID, key).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, ErrSharedTaskSideEffectNotFound
	}
	rows, err := s.db.Query(`SELECT e.id,e.sequence,e.task_id,e.side_effect_id,s.idempotency_key,e.kind,e.from_state,e.to_state,
 e.actor_principal_id,e.actor_endpoint_id,e.owner_epoch,e.details_json,e.created_at
 FROM shared_task_v2_side_effect_events e JOIN shared_task_v2_side_effects s ON s.id=e.side_effect_id
 WHERE e.task_id=? AND s.idempotency_key=? ORDER BY e.sequence`, taskID, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []SharedTaskSideEffectEvent{}
	for rows.Next() {
		var value SharedTaskSideEffectEvent
		if err := rows.Scan(&value.ID, &value.Sequence, &value.TaskID, &value.SideEffectID, &value.Key, &value.Kind, &value.FromState,
			&value.ToState, &value.ActorPrincipal, &value.ActorEndpoint, &value.OwnerEpoch, &value.DetailsJSON, &value.CreatedAt); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

// GetSharedTaskHandoffSideEffectLedger makes the existing handoff no-repeat
// notes and the durable Task side-effect rows queryable together. Callers can
// see which entries are unresolved without treating notes as execution fences.
func (s *Store) GetSharedTaskHandoffSideEffectLedger(id string) (*SharedTaskHandoffSideEffectLedger, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrSharedTaskHandoffNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	handoff, err := scanSharedTaskHandoff(tx.QueryRow(`SELECT `+sharedTaskHandoffColumns+` FROM shared_task_v2_handoffs WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	effects, err := listSharedTaskSideEffectsTx(tx, handoff.TaskID)
	if err != nil {
		return nil, err
	}
	unconfirmed := make([]SharedTaskSideEffect, 0, len(effects))
	for _, effect := range effects {
		if isSharedTaskSideEffectUnconfirmed(effect.State) {
			unconfirmed = append(unconfirmed, effect)
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &SharedTaskHandoffSideEffectLedger{Handoff: handoff, NoRepeatActions: append([]string{}, handoff.NoRepeatActions...),
		SideEffects: effects, UnconfirmedSideEffects: unconfirmed}, nil
}

func listSharedTaskSideEffectsTx(tx *sql.Tx, taskID string) ([]SharedTaskSideEffect, error) {
	rows, err := tx.Query(`SELECT `+sharedTaskSideEffectColumns+` FROM shared_task_v2_side_effects WHERE task_id=? ORDER BY created_at,id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []SharedTaskSideEffect{}
	for rows.Next() {
		value, err := scanSharedTaskSideEffect(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, *value)
	}
	return values, rows.Err()
}
