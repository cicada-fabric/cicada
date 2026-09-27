package store

// Shared Tasks are durable responsibility records. Conversation remains in
// Fabric; this store owns claim, result, and acceptance state, never prompts.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	SharedTaskDraft           = "DRAFT"
	SharedTaskReady           = "READY"
	SharedTaskClaimed         = "CLAIMED"
	SharedTaskRunning         = "RUNNING"
	SharedTaskResultSubmitted = "RESULT_SUBMITTED"
	SharedTaskCompleted       = "COMPLETED"
	SharedTaskBlocked         = "BLOCKED"
	SharedTaskNeedsRevision   = "NEEDS_REVISION"
	SharedTaskCancelled       = "CANCELLED"
)

var (
	ErrSharedTaskNotFound       = errors.New("shared task not found")
	ErrSharedTaskConflict       = errors.New("shared task revision or state conflict")
	ErrSharedTaskDependency     = errors.New("shared task dependency is invalid, blocked, or cyclic")
	ErrSharedTaskStaleOwner     = errors.New("shared task owner epoch is stale")
	ErrSharedTaskResultNotFound = errors.New("shared task result not found")
)

type SharedTask struct {
	ID                 string `json:"task_id"`
	GroupID            string `json:"group_id"`
	GoalID             string `json:"goal_id,omitempty"`
	Objective          string `json:"objective"`
	AcceptanceCriteria string `json:"acceptance_criteria"`
	Priority           int    `json:"priority"`
	Status             string `json:"status"`
	OwnerPrincipalID   string `json:"owner_principal_id,omitempty"`
	OwnerEndpointID    string `json:"owner_endpoint_id,omitempty"`
	Revision           int64  `json:"revision"`
	OwnerEpoch         int64  `json:"owner_epoch"`
	ClaimKey           string `json:"-"`
	LeaseExpiresAt     string `json:"lease_expires_at,omitempty"`
	AcceptedResultID   string `json:"accepted_result_id,omitempty"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

type SharedTaskResult struct {
	ID                   string   `json:"result_id"`
	TaskID               string   `json:"task_id"`
	SubmitterPrincipalID string   `json:"submitter_principal_id"`
	SubmitterEndpointID  string   `json:"submitter_endpoint_id"`
	OwnerEpoch           int64    `json:"owner_epoch"`
	Summary              string   `json:"summary"`
	Evidence             []string `json:"evidence"`
	Authority            string   `json:"authority"` // CANDIDATE or PENDING or ACCEPTED
	CreatedAt            string   `json:"created_at"`
}

func (s *Store) initializeSharedTaskV2Schema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS shared_task_v2_guard (id INTEGER PRIMARY KEY CHECK(id=1), touched_at TEXT NOT NULL);
INSERT OR IGNORE INTO shared_task_v2_guard(id,touched_at) VALUES (1,'');
CREATE TABLE IF NOT EXISTS shared_tasks_v2 (
 id TEXT PRIMARY KEY, group_id TEXT NOT NULL, goal_id TEXT NOT NULL DEFAULT '',
 objective TEXT NOT NULL, acceptance_criteria TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL, owner_principal_id TEXT NOT NULL DEFAULT '', owner_endpoint_id TEXT NOT NULL DEFAULT '',
 revision INTEGER NOT NULL DEFAULT 1, owner_epoch INTEGER NOT NULL DEFAULT 0,
 claim_key TEXT NOT NULL DEFAULT '', lease_expires_at TEXT NOT NULL DEFAULT '',
 accepted_result_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(group_id) REFERENCES groups(id)
);
CREATE INDEX IF NOT EXISTS shared_tasks_v2_group_status_idx ON shared_tasks_v2(group_id,status,priority);
CREATE TABLE IF NOT EXISTS shared_task_v2_dependencies (
 task_id TEXT NOT NULL, depends_on_id TEXT NOT NULL,
 PRIMARY KEY(task_id,depends_on_id),
 FOREIGN KEY(task_id) REFERENCES shared_tasks_v2(id),
 FOREIGN KEY(depends_on_id) REFERENCES shared_tasks_v2(id)
);
CREATE TABLE IF NOT EXISTS shared_task_v2_results (
 id TEXT PRIMARY KEY, task_id TEXT NOT NULL, submitter_principal_id TEXT NOT NULL,
 submitter_endpoint_id TEXT NOT NULL, owner_epoch INTEGER NOT NULL,
 summary TEXT NOT NULL, evidence_json TEXT NOT NULL, authority TEXT NOT NULL,
 created_at TEXT NOT NULL, FOREIGN KEY(task_id) REFERENCES shared_tasks_v2(id)
);
CREATE INDEX IF NOT EXISTS shared_task_v2_results_task_idx ON shared_task_v2_results(task_id,created_at);
CREATE TABLE IF NOT EXISTS shared_task_v2_events (
 id TEXT PRIMARY KEY, task_id TEXT NOT NULL, kind TEXT NOT NULL, actor_principal_id TEXT NOT NULL,
 owner_epoch INTEGER NOT NULL, revision INTEGER NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(task_id) REFERENCES shared_tasks_v2(id)
);`)
	return err
}

const sharedTaskColumns = `id,group_id,goal_id,objective,acceptance_criteria,priority,status,owner_principal_id,owner_endpoint_id,revision,owner_epoch,claim_key,lease_expires_at,accepted_result_id,created_at,updated_at`

func scanSharedTask(row interface{ Scan(...any) error }) (*SharedTask, error) {
	var task SharedTask
	err := row.Scan(&task.ID, &task.GroupID, &task.GoalID, &task.Objective, &task.AcceptanceCriteria, &task.Priority, &task.Status,
		&task.OwnerPrincipalID, &task.OwnerEndpointID, &task.Revision, &task.OwnerEpoch, &task.ClaimKey, &task.LeaseExpiresAt,
		&task.AcceptedResultID, &task.CreatedAt, &task.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSharedTaskNotFound
	}
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func loadSharedTaskTx(tx *sql.Tx, id string) (*SharedTask, error) {
	return scanSharedTask(tx.QueryRow(`SELECT `+sharedTaskColumns+` FROM shared_tasks_v2 WHERE id=?`, id))
}

func (s *Store) GetSharedTask(id string) (*SharedTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanSharedTask(s.db.QueryRow(`SELECT `+sharedTaskColumns+` FROM shared_tasks_v2 WHERE id=?`, id))
}

func (s *Store) ListSharedTasks(groupID string, limit int) ([]SharedTask, error) {
	if strings.TrimSpace(groupID) == "" {
		return nil, ErrGroupNotFound
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT `+sharedTaskColumns+` FROM shared_tasks_v2 WHERE group_id=? ORDER BY priority DESC,created_at,id LIMIT ?`, groupID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []SharedTask
	for rows.Next() {
		task, err := scanSharedTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, *task)
	}
	return tasks, rows.Err()
}

// ListSharedTaskResults returns the evidence submissions visible in one
// Group's Task graph. It deliberately includes candidate and pending results;
// callers must inspect Authority rather than treating every submission as
// accepted work.
func (s *Store) ListSharedTaskResults(groupID string, limit int) ([]SharedTaskResult, error) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return nil, ErrGroupNotFound
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT r.id,r.task_id,r.submitter_principal_id,r.submitter_endpoint_id,
 r.owner_epoch,r.summary,r.evidence_json,r.authority,r.created_at
 FROM shared_task_v2_results r
 JOIN shared_tasks_v2 t ON t.id=r.task_id
 WHERE t.group_id=?
 ORDER BY r.created_at DESC,r.id
 LIMIT ?`, groupID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := []SharedTaskResult{}
	for rows.Next() {
		var result SharedTaskResult
		var evidenceJSON string
		if err := rows.Scan(&result.ID, &result.TaskID, &result.SubmitterPrincipalID, &result.SubmitterEndpointID,
			&result.OwnerEpoch, &result.Summary, &evidenceJSON, &result.Authority, &result.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(evidenceJSON), &result.Evidence); err != nil {
			return nil, err
		}
		if result.Evidence == nil {
			result.Evidence = []string{}
		}
		results = append(results, result)
	}
	return results, rows.Err()
}

func (s *Store) CreateSharedTask(task SharedTask) (*SharedTask, error) {
	if strings.TrimSpace(task.GroupID) == "" || strings.TrimSpace(task.Objective) == "" || strings.TrimSpace(task.AcceptanceCriteria) == "" {
		return nil, errors.New("group, objective and acceptance criteria are required")
	}
	if task.ID == "" {
		task.ID = NewID("task")
	}
	task.Status = SharedTaskDraft
	task.Revision = 1
	task.OwnerEpoch = 0
	task.CreatedAt = now()
	task.UpdatedAt = task.CreatedAt
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO shared_tasks_v2 (`+sharedTaskColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		task.ID, task.GroupID, task.GoalID, task.Objective, task.AcceptanceCriteria, task.Priority, task.Status, "", "", task.Revision,
		task.OwnerEpoch, "", "", "", task.CreatedAt, task.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func acquireSharedTaskWrite(tx *sql.Tx) error {
	_, err := tx.Exec(`UPDATE shared_task_v2_guard SET touched_at=? WHERE id=1`, now())
	return err
}

func sharedTaskEvent(tx *sql.Tx, task *SharedTask, kind, actor string, data any) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO shared_task_v2_events(id,task_id,kind,actor_principal_id,owner_epoch,revision,data_json,created_at)
VALUES(?,?,?,?,?,?,?,?)`, NewID("tevt"), task.ID, kind, actor, task.OwnerEpoch, task.Revision, string(encoded), now())
	return err
}

// AddSharedTaskDependency checks both group isolation and cycles while
// holding the SQLite write lock. Dependencies are mutable only in DRAFT.
func (s *Store) AddSharedTaskDependency(taskID, dependsOnID string, expectedRevision int64, actor string) (*SharedTask, error) {
	if taskID == dependsOnID {
		return nil, ErrSharedTaskDependency
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
	dep, err := loadSharedTaskTx(tx, dependsOnID)
	if err != nil {
		return nil, err
	}
	if task.GroupID != dep.GroupID || task.Status != SharedTaskDraft {
		return nil, ErrSharedTaskDependency
	}
	if task.Revision != expectedRevision {
		return nil, ErrSharedTaskConflict
	}
	var duplicate int
	if err = tx.QueryRow(`SELECT count(*) FROM shared_task_v2_dependencies WHERE task_id=? AND depends_on_id=?`, taskID, dependsOnID).Scan(&duplicate); err != nil {
		return nil, err
	}
	if duplicate != 0 {
		return nil, ErrSharedTaskConflict
	}
	// A new edge task -> dep forms a cycle iff dep already reaches task.
	var cycle int
	err = tx.QueryRow(`WITH RECURSIVE reachable(id) AS (
 SELECT depends_on_id FROM shared_task_v2_dependencies WHERE task_id=?
 UNION SELECT d.depends_on_id FROM shared_task_v2_dependencies d JOIN reachable r ON d.task_id=r.id
) SELECT count(*) FROM reachable WHERE id=?`, dependsOnID, taskID).Scan(&cycle)
	if err != nil {
		return nil, err
	}
	if cycle != 0 {
		return nil, ErrSharedTaskDependency
	}
	if _, err = tx.Exec(`INSERT INTO shared_task_v2_dependencies(task_id,depends_on_id) VALUES(?,?)`, taskID, dependsOnID); err != nil {
		return nil, err
	}
	result, err := tx.Exec(`UPDATE shared_tasks_v2 SET revision=revision+1,updated_at=? WHERE id=? AND revision=?`, now(), taskID, expectedRevision)
	if err != nil {
		return nil, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return nil, ErrSharedTaskConflict
	}
	task, err = loadSharedTaskTx(tx, taskID)
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "DEPENDENCY_ADDED", actor, map[string]string{"depends_on_id": dependsOnID}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

func sharedTaskDependenciesComplete(tx *sql.Tx, taskID string) (bool, error) {
	var incomplete int
	err := tx.QueryRow(`SELECT count(*) FROM shared_task_v2_dependencies d JOIN shared_tasks_v2 parent ON parent.id=d.depends_on_id
WHERE d.task_id=? AND parent.status<>?`, taskID, SharedTaskCompleted).Scan(&incomplete)
	return incomplete == 0, err
}

func sharedTaskLeaseActive(expiresAt string) bool {
	deadline, err := time.Parse(time.RFC3339Nano, expiresAt)
	return err == nil && time.Now().UTC().Before(deadline)
}

func (s *Store) ReadySharedTask(id string, expectedRevision int64, actor string) (*SharedTask, error) {
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
	task, err := loadSharedTaskTx(tx, id)
	if err != nil {
		return nil, err
	}
	if task.Revision != expectedRevision || (task.Status != SharedTaskDraft && task.Status != SharedTaskBlocked && task.Status != SharedTaskNeedsRevision) {
		return nil, ErrSharedTaskConflict
	}
	complete, err := sharedTaskDependenciesComplete(tx, id)
	if err != nil {
		return nil, err
	}
	if !complete {
		return nil, ErrSharedTaskDependency
	}
	result, err := tx.Exec(`UPDATE shared_tasks_v2 SET status=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?`, SharedTaskReady, now(), id, expectedRevision)
	if err != nil {
		return nil, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return nil, ErrSharedTaskConflict
	}
	task, err = loadSharedTaskTx(tx, id)
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "READY", actor, nil); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

func (s *Store) ClaimSharedTask(id string, expectedRevision int64, principalID, endpointID, key string, leaseSeconds int) (*SharedTask, error) {
	if principalID == "" || endpointID == "" || strings.TrimSpace(key) == "" {
		return nil, errors.New("claim actor and idempotency key are required")
	}
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
	task, err := loadSharedTaskTx(tx, id)
	if err != nil {
		return nil, err
	}
	if task.ClaimKey == key && task.OwnerPrincipalID == principalID && task.OwnerEndpointID == endpointID && task.Status == SharedTaskClaimed && sharedTaskLeaseActive(task.LeaseExpiresAt) {
		return task, nil
	}
	if task.Revision != expectedRevision || task.Status != SharedTaskReady {
		return nil, ErrSharedTaskConflict
	}
	complete, err := sharedTaskDependenciesComplete(tx, id)
	if err != nil {
		return nil, err
	}
	if !complete {
		return nil, ErrSharedTaskDependency
	}
	until := time.Now().UTC().Add(time.Duration(leaseSeconds) * time.Second).Format(time.RFC3339Nano)
	result, err := tx.Exec(`UPDATE shared_tasks_v2 SET status=?,owner_principal_id=?,owner_endpoint_id=?,claim_key=?,owner_epoch=owner_epoch+1,
 lease_expires_at=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND status=?`, SharedTaskClaimed, principalID, endpointID, key, until, now(), id, expectedRevision, SharedTaskReady)
	if err != nil {
		return nil, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return nil, ErrSharedTaskConflict
	}
	task, err = loadSharedTaskTx(tx, id)
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "CLAIMED", principalID, map[string]string{"endpoint_id": endpointID}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

// ReleaseSharedTaskClaim relinquishes responsibility and increments the owner
// epoch immediately. A paused native session cannot later submit an
// authoritative result under the old epoch, even before another claim.
func (s *Store) ReleaseSharedTaskClaim(id string, expectedRevision, ownerEpoch int64, principalID, endpointID string) (*SharedTask, error) {
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
	task, err := loadSharedTaskTx(tx, id)
	if err != nil {
		return nil, err
	}
	if task.OwnerPrincipalID != principalID || task.OwnerEndpointID != endpointID || task.OwnerEpoch != ownerEpoch {
		return nil, ErrSharedTaskStaleOwner
	}
	if !sharedTaskLeaseActive(task.LeaseExpiresAt) {
		return nil, ErrSharedTaskStaleOwner
	}
	if task.Revision != expectedRevision || (task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
		return nil, ErrSharedTaskConflict
	}
	result, err := tx.Exec(`UPDATE shared_tasks_v2 SET status=?,owner_principal_id='',owner_endpoint_id='',claim_key='',
 owner_epoch=owner_epoch+1,lease_expires_at='',revision=revision+1,updated_at=? WHERE id=? AND revision=? AND owner_epoch=?`,
		SharedTaskReady, now(), id, expectedRevision, ownerEpoch)
	if err != nil {
		return nil, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return nil, ErrSharedTaskConflict
	}
	task, err = loadSharedTaskTx(tx, id)
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "CLAIM_RELEASED", principalID, map[string]string{"endpoint_id": endpointID}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

func (s *Store) RenewSharedTaskClaim(id string, expectedRevision, ownerEpoch int64, principalID, endpointID string, leaseSeconds int) (*SharedTask, error) {
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
	task, err := loadSharedTaskTx(tx, id)
	if err != nil {
		return nil, err
	}
	if task.OwnerPrincipalID != principalID || task.OwnerEndpointID != endpointID || task.OwnerEpoch != ownerEpoch || !sharedTaskLeaseActive(task.LeaseExpiresAt) {
		return nil, ErrSharedTaskStaleOwner
	}
	if task.Revision != expectedRevision || (task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) {
		return nil, ErrSharedTaskConflict
	}
	until := time.Now().UTC().Add(time.Duration(leaseSeconds) * time.Second).Format(time.RFC3339Nano)
	_, err = tx.Exec(`UPDATE shared_tasks_v2 SET lease_expires_at=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND owner_epoch=?`, until, now(), id, expectedRevision, ownerEpoch)
	if err != nil {
		return nil, err
	}
	task, err = loadSharedTaskTx(tx, id)
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "CLAIM_RENEWED", principalID, map[string]string{"endpoint_id": endpointID}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

// ReconcileExpiredSharedTaskClaim is a manager decision point. Expiry fences
// the old Task owner but blocks the Task until side effects are checked; it
// does not assert that any running process has stopped.
func (s *Store) ReconcileExpiredSharedTaskClaim(id string, expectedRevision int64, managerPrincipalID string) (*SharedTask, error) {
	if managerPrincipalID == "" {
		return nil, errors.New("manager principal is required")
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
	task, err := loadSharedTaskTx(tx, id)
	if err != nil {
		return nil, err
	}
	if task.Revision != expectedRevision || (task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) || sharedTaskLeaseActive(task.LeaseExpiresAt) {
		return nil, ErrSharedTaskConflict
	}
	previousOwner := task.OwnerPrincipalID
	_, err = tx.Exec(`UPDATE shared_tasks_v2 SET status=?,owner_principal_id='',owner_endpoint_id='',claim_key='',
 owner_epoch=owner_epoch+1,lease_expires_at='',revision=revision+1,updated_at=? WHERE id=? AND revision=?`,
		SharedTaskBlocked, now(), id, expectedRevision)
	if err != nil {
		return nil, err
	}
	task, err = loadSharedTaskTx(tx, id)
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "OWNER_EXPIRED_RECONCILIATION_REQUIRED", managerPrincipalID, map[string]string{"previous_owner": previousOwner}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

// SubmitSharedTaskResult retains a stale owner's answer as non-authoritative
// evidence. It never changes current task state or accepted result.
func (s *Store) SubmitSharedTaskResult(taskID, principalID, endpointID string, ownerEpoch, expectedRevision int64, summary string, evidence []string) (*SharedTaskResult, error) {
	if strings.TrimSpace(summary) == "" || principalID == "" || endpointID == "" {
		return nil, errors.New("result summary and actor are required")
	}
	if evidence == nil {
		evidence = []string{}
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return nil, err
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
	authoritative := sharedTaskLeaseActive(task.LeaseExpiresAt) && task.Revision == expectedRevision && task.OwnerEpoch == ownerEpoch && task.OwnerPrincipalID == principalID && task.OwnerEndpointID == endpointID &&
		(task.Status == SharedTaskClaimed || task.Status == SharedTaskRunning)
	authority := "CANDIDATE"
	if authoritative {
		authority = "PENDING"
	}
	result := &SharedTaskResult{ID: NewID("result"), TaskID: taskID, SubmitterPrincipalID: principalID, SubmitterEndpointID: endpointID,
		OwnerEpoch: ownerEpoch, Summary: summary, Evidence: evidence, Authority: authority, CreatedAt: now()}
	if _, err = tx.Exec(`INSERT INTO shared_task_v2_results(id,task_id,submitter_principal_id,submitter_endpoint_id,owner_epoch,summary,evidence_json,authority,created_at)
 VALUES(?,?,?,?,?,?,?,?,?)`, result.ID, result.TaskID, result.SubmitterPrincipalID, result.SubmitterEndpointID, result.OwnerEpoch, result.Summary, string(encoded), result.Authority, result.CreatedAt); err != nil {
		return nil, err
	}
	if authoritative {
		_, err = tx.Exec(`UPDATE shared_tasks_v2 SET status=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND owner_epoch=?`,
			SharedTaskResultSubmitted, now(), taskID, expectedRevision, ownerEpoch)
		if err != nil {
			return nil, err
		}
		task.Revision++
		task.Status = SharedTaskResultSubmitted
	}
	if err = sharedTaskEvent(tx, task, "RESULT_SUBMITTED", principalID, map[string]string{"result_id": result.ID, "authority": authority}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if !authoritative {
		return result, ErrSharedTaskStaleOwner
	}
	return result, nil
}

func (s *Store) AcceptSharedTaskResult(taskID, resultID string, expectedRevision int64, verifierPrincipalID string) (*SharedTask, error) {
	if verifierPrincipalID == "" {
		return nil, errors.New("verifier principal is required")
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
	if task.Revision != expectedRevision || task.Status != SharedTaskResultSubmitted {
		return nil, ErrSharedTaskConflict
	}
	var authority string
	var epoch int64
	var evidenceJSON string
	err = tx.QueryRow(`SELECT authority,owner_epoch,evidence_json FROM shared_task_v2_results WHERE id=? AND task_id=?`, resultID, taskID).Scan(&authority, &epoch, &evidenceJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSharedTaskResultNotFound
	}
	if err != nil {
		return nil, err
	}
	if authority != "PENDING" || epoch != task.OwnerEpoch {
		return nil, ErrSharedTaskStaleOwner
	}
	var evidence []string
	if err = json.Unmarshal([]byte(evidenceJSON), &evidence); err != nil {
		return nil, err
	}
	if len(evidence) == 0 {
		return nil, fmt.Errorf("result has no inspectable evidence: %w", ErrSharedTaskConflict)
	}
	if _, err = tx.Exec(`UPDATE shared_task_v2_results SET authority='ACCEPTED' WHERE id=?`, resultID); err != nil {
		return nil, err
	}
	update, err := tx.Exec(`UPDATE shared_tasks_v2 SET status=?,accepted_result_id=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?`,
		SharedTaskCompleted, resultID, now(), taskID, expectedRevision)
	if err != nil {
		return nil, err
	}
	n, _ := update.RowsAffected()
	if n != 1 {
		return nil, ErrSharedTaskConflict
	}
	task, err = loadSharedTaskTx(tx, taskID)
	if err != nil {
		return nil, err
	}
	if err = sharedTaskEvent(tx, task, "RESULT_ACCEPTED", verifierPrincipalID, map[string]string{"result_id": resultID}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}
