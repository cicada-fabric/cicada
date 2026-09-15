package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

func (s *Store) CreateExternalAction(action ExternalAction) (*ExternalAction, error) {
	if action.ID == "" {
		action.ID = NewID("action")
	}
	if action.GoalID == "" || action.WorkerID == "" || action.Kind == "" ||
		action.Method == "" || action.URL == "" || action.Domain == "" {
		return nil, errors.New("goal, worker, kind, method, url, and domain are required")
	}
	if len(action.Payload) == 0 {
		action.Payload = json.RawMessage(`{}`)
	}
	if !json.Valid(action.Payload) {
		return nil, errors.New("external action payload must be valid JSON")
	}
	if action.Status == "" {
		action.Status = "queued"
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO external_actions
(id, goal_id, worker_id, kind, method, url, domain, payload_json, status, approval_id,
 result_json, error, created_at, updated_at, started_at, completed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, action.ID, action.GoalID,
		action.WorkerID, action.Kind, action.Method, action.URL, action.Domain,
		string(action.Payload), action.Status, nullableString(action.ApprovalID),
		jsonOrEmpty(action.Result), action.Error, timestamp, timestamp,
		nullableString(action.StartedAt), nullableString(action.CompletedAt))
	if err != nil {
		return nil, fmt.Errorf("create external action: %w", err)
	}
	return s.getExternalActionLocked(action.ID)
}

func (s *Store) GetExternalAction(id string) (*ExternalAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getExternalActionLocked(id)
}

func (s *Store) ListExternalActions(goalID, status string) ([]ExternalAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT id FROM external_actions ORDER BY created_at DESC`
	args := []any{}
	if goalID != "" && status != "" {
		query = `SELECT id FROM external_actions WHERE goal_id = ? AND status = ? ORDER BY created_at DESC`
		args = append(args, goalID, status)
	} else if goalID != "" {
		query = `SELECT id FROM external_actions WHERE goal_id = ? ORDER BY created_at DESC`
		args = append(args, goalID)
	} else if status != "" {
		query = `SELECT id FROM external_actions WHERE status = ? ORDER BY created_at DESC`
		args = append(args, status)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]ExternalAction, 0, len(ids))
	for _, id := range ids {
		action, err := s.getExternalActionLocked(id)
		if err != nil {
			return nil, err
		}
		if action != nil {
			result = append(result, *action)
		}
	}
	return result, nil
}

func (s *Store) AttachExternalActionApproval(id, approvalID string) (*ExternalAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE external_actions SET approval_id = ?, updated_at = ? WHERE id = ?`,
		nullableString(approvalID), now(), id)
	if err != nil {
		return nil, err
	}
	return s.getExternalActionLocked(id)
}

func (s *Store) UpdateExternalActionStatus(id, status, result, actionError string) (*ExternalAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if result == "" {
		result = "{}"
	}
	if !json.Valid([]byte(result)) {
		return nil, errors.New("external action result must be valid JSON")
	}
	_, err := s.db.Exec(`UPDATE external_actions SET status = ?, result_json = ?, error = ?, updated_at = ? WHERE id = ?`,
		status, result, actionError, now(), id)
	if err != nil {
		return nil, err
	}
	return s.getExternalActionLocked(id)
}

func (s *Store) ClaimExternalAction(id string) (*ExternalAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	timestamp := now()
	result, err := s.db.Exec(`UPDATE external_actions SET status = 'running', started_at = ?, updated_at = ?
WHERE id = ? AND status = 'queued'`, timestamp, timestamp, id)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed == 0 {
		return s.getExternalActionLocked(id)
	}
	return s.getExternalActionLocked(id)
}

func (s *Store) CompleteExternalAction(id, status, result, actionError string) (*ExternalAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if result == "" {
		result = "{}"
	}
	if !json.Valid([]byte(result)) {
		return nil, errors.New("external action result must be valid JSON")
	}
	if status != "completed" && status != "failed" {
		return nil, fmt.Errorf("unsupported external action terminal status: %s", status)
	}
	timestamp := now()
	_, err := s.db.Exec(`UPDATE external_actions SET status = ?, result_json = ?, error = ?,
completed_at = ?, updated_at = ? WHERE id = ? AND status = 'running'`, status,
		result, actionError, timestamp, timestamp, id)
	if err != nil {
		return nil, err
	}
	return s.getExternalActionLocked(id)
}

func (s *Store) CancelExternalAction(id string) (*ExternalAction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	timestamp := now()
	_, err := s.db.Exec(`UPDATE external_actions SET status = 'cancelled', completed_at = ?, updated_at = ?
WHERE id = ? AND status IN ('pending_approval', 'queued', 'running')`, timestamp, timestamp, id)
	if err != nil {
		return nil, err
	}
	return s.getExternalActionLocked(id)
}

func (s *Store) getExternalActionLocked(id string) (*ExternalAction, error) {
	var action ExternalAction
	var payload, approvalID, result, actionError, startedAt, completedAt sql.NullString
	err := s.db.QueryRow(`SELECT id, goal_id, worker_id, kind, method, url, domain,
payload_json, status, approval_id, result_json, error, created_at, updated_at,
started_at, completed_at FROM external_actions WHERE id = ?`, id).Scan(
		&action.ID, &action.GoalID, &action.WorkerID, &action.Kind, &action.Method,
		&action.URL, &action.Domain, &payload, &action.Status, &approvalID, &result,
		&actionError, &action.CreatedAt, &action.UpdatedAt, &startedAt, &completedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	action.Payload = json.RawMessage(payload.String)
	action.ApprovalID = approvalID.String
	action.Result = json.RawMessage(result.String)
	action.Error = actionError.String
	action.StartedAt = startedAt.String
	action.CompletedAt = completedAt.String
	return &action, nil
}

func jsonOrEmpty(value json.RawMessage) string {
	if len(value) == 0 {
		return "{}"
	}
	return string(value)
}
