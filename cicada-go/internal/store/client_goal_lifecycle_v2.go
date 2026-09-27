package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var ErrClientGoalLifecycleConflict = errors.New("Goal lifecycle changed or cannot be paused safely")

func (s *Store) initializeClientGoalLifecycleSchema() error {
	return s.ensureColumn("goals", "lifecycle_version", `ALTER TABLE goals ADD COLUMN lifecycle_version INTEGER NOT NULL DEFAULT 1`)
}

// ChangeOwnedQueuedGoalLifecycle is a narrow execution-safe pause/resume.
// Only an unclaimed, remote Node job can be paused. Running native work is not
// stopped here; callers must never label it paused until a stop is confirmed.
// The worker check, version guard, status transition and audit event share a
// transaction with Node Worker claim's store mutex.
func (s *Store) ChangeOwnedQueuedGoalLifecycle(ownerID, deviceID, requestID, goalID, action string, expectedVersion int64) (*Goal, error) {
	ownerID, goalID = strings.TrimSpace(ownerID), strings.TrimSpace(goalID)
	deviceID, requestID = strings.TrimSpace(deviceID), strings.TrimSpace(requestID)
	if ownerID == "" || deviceID == "" || requestID == "" || goalID == "" || expectedVersion <= 0 {
		return nil, ErrClientGoalLifecycleConflict
	}
	from, to, eventType := "queued", "paused", "GoalPaused"
	switch action {
	case "pause":
	case "resume":
		from, to, eventType = "paused", "queued", "GoalResumed"
	default:
		return nil, fmt.Errorf("%w: unsupported action", ErrClientGoalLifecycleConflict)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	stamp := now()
	result, err := tx.Exec(`UPDATE goals SET status=?, lifecycle_version=lifecycle_version+1, updated_at=?
WHERE id=? AND owner_id=? AND status=? AND lifecycle_version=?
  AND machine_id NOT IN ('control-local','worker-local')
  AND EXISTS (SELECT 1 FROM workers WHERE goal_id=goals.id)
  AND NOT EXISTS (SELECT 1 FROM workers WHERE goal_id=goals.id AND status<>'queued')`,
		to, stamp, goalID, ownerID, from, expectedVersion)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, ErrClientGoalLifecycleConflict
	}
	payload, err := json.Marshal(map[string]string{
		"source": "client", "action": action, "device_id": deviceID, "client_request_id": requestID,
	})
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO events (goal_id, worker_id, type, payload_json, created_at)
VALUES (?, NULL, ?, ?, ?)`, goalID, eventType, string(payload), stamp); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getGoalLocked(goalID)
}
