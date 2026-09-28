package store

// Handoff is a structured, epoch-fenced ownership transfer. A note in chat
// is never enough to change who may submit Task results.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	HandoffProposed    = "PROPOSED"
	HandoffTransferred = "TRANSFERRED"
	HandoffCancelled   = "CANCELLED"
)

var (
	ErrSharedTaskHandoffNotFound        = errors.New("shared task handoff not found")
	ErrSharedTaskHandoffConflict        = errors.New("shared task handoff conflicts with current owner or revision")
	ErrSharedTaskHandoffMissingArtifact = errors.New("handoff receiver cannot access required artifacts")
)

type SharedTaskHandoff struct {
	ID                  string   `json:"handoff_id"`
	TaskID              string   `json:"task_id"`
	GroupID             string   `json:"group_id"`
	FromPrincipalID     string   `json:"from_principal_id"`
	FromEndpointID      string   `json:"from_endpoint_id"`
	ToPrincipalID       string   `json:"to_principal_id"`
	ToEndpointID        string   `json:"to_endpoint_id"`
	FromOwnerEpoch      int64    `json:"from_owner_epoch"`
	TaskRevision        int64    `json:"task_revision"`
	PendingWork         string   `json:"pending_work"`
	WorkspaceState      string   `json:"workspace_state"`
	EvidenceRefs        []string `json:"evidence_refs"`
	ArtifactRefs        []string `json:"artifact_refs"`
	MissingArtifactRefs []string `json:"missing_artifact_refs,omitempty"`
	SideEffects         []string `json:"side_effects"`
	NoRepeatActions     []string `json:"no_repeat_actions"`
	Status              string   `json:"status"`
	AcceptedAt          string   `json:"accepted_at,omitempty"`
	TransferredAt       string   `json:"transferred_at,omitempty"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
}

func (s *Store) initializeSharedTaskHandoffSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS shared_task_v2_handoffs (
 id TEXT PRIMARY KEY, task_id TEXT NOT NULL, group_id TEXT NOT NULL,
 from_principal_id TEXT NOT NULL, from_endpoint_id TEXT NOT NULL,
 to_principal_id TEXT NOT NULL, to_endpoint_id TEXT NOT NULL,
 from_owner_epoch INTEGER NOT NULL, task_revision INTEGER NOT NULL,
 pending_work TEXT NOT NULL, workspace_state TEXT NOT NULL,
 evidence_refs_json TEXT NOT NULL, artifact_refs_json TEXT NOT NULL, missing_artifact_refs_json TEXT NOT NULL DEFAULT '[]',
 side_effects_json TEXT NOT NULL, no_repeat_actions_json TEXT NOT NULL,
 status TEXT NOT NULL, accepted_at TEXT NOT NULL DEFAULT '', transferred_at TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(task_id) REFERENCES shared_tasks_v2(id)
);
CREATE INDEX IF NOT EXISTS shared_task_v2_handoffs_task_idx ON shared_task_v2_handoffs(task_id,status,created_at);`)
	return err
}

const sharedTaskHandoffColumns = `id,task_id,group_id,from_principal_id,from_endpoint_id,to_principal_id,to_endpoint_id,
from_owner_epoch,task_revision,pending_work,workspace_state,evidence_refs_json,artifact_refs_json,missing_artifact_refs_json,side_effects_json,
no_repeat_actions_json,status,accepted_at,transferred_at,created_at,updated_at`

func scanSharedTaskHandoff(row interface{ Scan(...any) error }) (*SharedTaskHandoff, error) {
	var value SharedTaskHandoff
	var evidence, artifacts, missing, effects, noRepeat string
	err := row.Scan(&value.ID, &value.TaskID, &value.GroupID, &value.FromPrincipalID, &value.FromEndpointID, &value.ToPrincipalID,
		&value.ToEndpointID, &value.FromOwnerEpoch, &value.TaskRevision, &value.PendingWork, &value.WorkspaceState,
		&evidence, &artifacts, &missing, &effects, &noRepeat, &value.Status, &value.AcceptedAt, &value.TransferredAt, &value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSharedTaskHandoffNotFound
	}
	if err != nil {
		return nil, err
	}
	for _, pair := range []struct {
		raw string
		dst *[]string
	}{{evidence, &value.EvidenceRefs}, {artifacts, &value.ArtifactRefs}, {missing, &value.MissingArtifactRefs}, {effects, &value.SideEffects}, {noRepeat, &value.NoRepeatActions}} {
		if err = json.Unmarshal([]byte(pair.raw), pair.dst); err != nil {
			return nil, err
		}
	}
	return &value, nil
}

func (s *Store) GetSharedTaskHandoff(id string) (*SharedTaskHandoff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanSharedTaskHandoff(s.db.QueryRow(`SELECT `+sharedTaskHandoffColumns+` FROM shared_task_v2_handoffs WHERE id=?`, id))
}

func (s *Store) ProposeSharedTaskHandoff(input SharedTaskHandoff) (*SharedTaskHandoff, error) {
	return s.proposeSharedTaskHandoff(input, nil)
}

func (s *Store) ProposeSharedTaskHandoffForActor(scope NativeActorScope, input SharedTaskHandoff) (*SharedTaskHandoff, error) {
	return s.proposeSharedTaskHandoff(input, &scope)
}

func (s *Store) proposeSharedTaskHandoff(input SharedTaskHandoff, scope *NativeActorScope) (*SharedTaskHandoff, error) {
	if input.TaskID == "" || input.FromPrincipalID == "" || input.FromEndpointID == "" || input.ToPrincipalID == "" || input.ToEndpointID == "" ||
		input.FromPrincipalID == input.ToPrincipalID && input.FromEndpointID == input.ToEndpointID || strings.TrimSpace(input.PendingWork) == "" {
		return nil, ErrSharedTaskHandoffConflict
	}
	if input.EvidenceRefs == nil {
		input.EvidenceRefs = []string{}
	}
	if input.ArtifactRefs == nil {
		input.ArtifactRefs = []string{}
	}
	input.MissingArtifactRefs = []string{}
	if input.SideEffects == nil {
		input.SideEffects = []string{}
	}
	if input.NoRepeatActions == nil {
		input.NoRepeatActions = []string{}
	}
	evidence, _ := json.Marshal(input.EvidenceRefs)
	artifacts, _ := json.Marshal(input.ArtifactRefs)
	effects, _ := json.Marshal(input.SideEffects)
	noRepeat, _ := json.Marshal(input.NoRepeatActions)
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
	if task.GroupID != input.GroupID || task.Revision != input.TaskRevision || task.OwnerEpoch != input.FromOwnerEpoch ||
		task.OwnerPrincipalID != input.FromPrincipalID || task.OwnerEndpointID != input.FromEndpointID ||
		!sharedTaskLeaseActive(task.LeaseExpiresAt) || (task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
		return nil, ErrSharedTaskHandoffConflict
	}
	at := time.Now().UTC()
	if err := guardSharedTaskMutationActorTx(tx, scope, input.FromPrincipalID, input.FromEndpointID, input.GroupID, "task.submit"); err != nil {
		return nil, err
	}
	if err := networkGuardGroupEndpointTx(tx, input.ToPrincipalID, input.ToEndpointID, input.GroupID, at); err != nil {
		return nil, err
	}
	var other int
	if err = tx.QueryRow(`SELECT count(*) FROM shared_task_v2_handoffs WHERE task_id=? AND status=?`, task.ID, HandoffProposed).Scan(&other); err != nil {
		return nil, err
	}
	if other != 0 {
		return nil, ErrSharedTaskHandoffConflict
	}
	input.ID = NewID("handoff")
	input.Status = HandoffProposed
	input.CreatedAt = now()
	input.UpdatedAt = input.CreatedAt
	_, err = tx.Exec(`INSERT INTO shared_task_v2_handoffs (`+sharedTaskHandoffColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		input.ID, input.TaskID, input.GroupID, input.FromPrincipalID, input.FromEndpointID, input.ToPrincipalID, input.ToEndpointID,
		input.FromOwnerEpoch, input.TaskRevision, input.PendingWork, input.WorkspaceState, string(evidence), string(artifacts), "[]", string(effects),
		string(noRepeat), input.Status, "", "", input.CreatedAt, input.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "HANDOFF_PROPOSED", input.FromPrincipalID, map[string]string{"handoff_id": input.ID, "to_endpoint_id": input.ToEndpointID}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &input, nil
}

func (s *Store) MarkSharedTaskHandoffMissingArtifacts(id, receiverPrincipalID, receiverEndpointID string, refs []string) error {
	return s.markSharedTaskHandoffMissingArtifacts(id, receiverPrincipalID, receiverEndpointID, refs, nil)
}

func (s *Store) MarkSharedTaskHandoffMissingArtifactsForActor(scope NativeActorScope, id string, refs []string) error {
	return s.markSharedTaskHandoffMissingArtifacts(id, scope.PrincipalID, scope.EndpointID, refs, &scope)
}

func (s *Store) markSharedTaskHandoffMissingArtifacts(id, receiverPrincipalID, receiverEndpointID string,
	refs []string, scope *NativeActorScope) error {
	if len(refs) == 0 {
		return nil
	}
	encoded, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = acquireSharedTaskWrite(tx); err != nil {
		return err
	}
	handoff, err := scanSharedTaskHandoff(tx.QueryRow(`SELECT `+sharedTaskHandoffColumns+` FROM shared_task_v2_handoffs WHERE id=?`, id))
	if err != nil {
		return err
	}
	if handoff.Status != HandoffProposed || handoff.ToPrincipalID != receiverPrincipalID || handoff.ToEndpointID != receiverEndpointID {
		return ErrSharedTaskHandoffConflict
	}
	if err := guardSharedTaskMutationActorTx(tx, scope, receiverPrincipalID, receiverEndpointID, handoff.GroupID, "task.claim"); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE shared_task_v2_handoffs SET missing_artifact_refs_json=?,updated_at=? WHERE id=? AND status=?`, string(encoded), now(), id, HandoffProposed); err != nil {
		return err
	}
	task, err := loadSharedTaskTx(tx, handoff.TaskID)
	if err != nil {
		return err
	}
	if err = sharedTaskEvent(tx, task, "HANDOFF_CONTEXT_MISSING", receiverPrincipalID, map[string]any{"handoff_id": id, "missing_artifact_refs": refs}); err != nil {
		return err
	}
	return tx.Commit()
}

// AcceptSharedTaskHandoff atomically records acceptance and transfers
// ownership. The previous epoch is fenced in the same write transaction.
func (s *Store) AcceptSharedTaskHandoff(id, receiverPrincipalID, receiverEndpointID string, leaseSeconds int) (*SharedTask, error) {
	return s.acceptSharedTaskHandoff(id, receiverPrincipalID, receiverEndpointID, leaseSeconds, nil)
}

func (s *Store) AcceptSharedTaskHandoffForActor(scope NativeActorScope, id string, leaseSeconds int) (*SharedTask, error) {
	return s.acceptSharedTaskHandoff(id, scope.PrincipalID, scope.EndpointID, leaseSeconds, &scope)
}

func (s *Store) acceptSharedTaskHandoff(id, receiverPrincipalID, receiverEndpointID string,
	leaseSeconds int, scope *NativeActorScope) (*SharedTask, error) {
	if leaseSeconds <= 0 {
		leaseSeconds = 300
	}
	if leaseSeconds > 3600 {
		leaseSeconds = 3600
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
	handoff, err := scanSharedTaskHandoff(tx.QueryRow(`SELECT `+sharedTaskHandoffColumns+` FROM shared_task_v2_handoffs WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	if handoff.Status != HandoffProposed || handoff.ToPrincipalID != receiverPrincipalID || handoff.ToEndpointID != receiverEndpointID {
		return nil, ErrSharedTaskHandoffConflict
	}
	if err := guardSharedTaskMutationActorTx(tx, scope, receiverPrincipalID, receiverEndpointID, handoff.GroupID, "task.claim"); err != nil {
		return nil, err
	}
	task, err := loadSharedTaskTx(tx, handoff.TaskID)
	if err != nil {
		return nil, err
	}
	if task.Revision != handoff.TaskRevision || task.OwnerEpoch != handoff.FromOwnerEpoch || task.OwnerPrincipalID != handoff.FromPrincipalID ||
		task.OwnerEndpointID != handoff.FromEndpointID || !sharedTaskLeaseActive(task.LeaseExpiresAt) ||
		(task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
		return nil, ErrSharedTaskHandoffConflict
	}
	until := time.Now().UTC().Add(time.Duration(leaseSeconds) * time.Second).Format(time.RFC3339Nano)
	updated := now()
	result, err := tx.Exec(`UPDATE shared_tasks_v2 SET owner_principal_id=?,owner_endpoint_id=?,owner_epoch=owner_epoch+1,claim_key=?,
 lease_expires_at=?,status=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND owner_epoch=?`,
		receiverPrincipalID, receiverEndpointID, "handoff:"+id, until, SharedTaskClaimed, updated, task.ID, task.Revision, task.OwnerEpoch)
	if err != nil {
		return nil, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return nil, ErrSharedTaskHandoffConflict
	}
	_, err = tx.Exec(`UPDATE shared_task_v2_handoffs SET status=?,accepted_at=?,transferred_at=?,missing_artifact_refs_json='[]',updated_at=? WHERE id=? AND status=?`,
		HandoffTransferred, updated, updated, updated, id, HandoffProposed)
	if err != nil {
		return nil, err
	}
	task, err = loadSharedTaskTx(tx, task.ID)
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "HANDOFF_ACCEPTED", receiverPrincipalID, map[string]string{"handoff_id": id}); err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "HANDOFF_TRANSFERRED", receiverPrincipalID, map[string]string{"handoff_id": id}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}
