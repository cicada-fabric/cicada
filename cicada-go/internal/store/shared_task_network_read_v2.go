package store

import (
	"time"
)

// GetSharedTaskForActor reads Task data from the same snapshot that proves the
// native Group and current Network enrollment. Control's trusted management
// views keep their separate, unscoped Store methods.
func (s *Store) GetSharedTaskForActor(scope NativeActorScope, taskID, action string) (*SharedTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := guardNativeActorTx(tx, scope, action, time.Now().UTC()); err != nil {
		return nil, err
	}
	task, err := loadSharedTaskTx(tx, taskID)
	if err != nil {
		return nil, err
	}
	if task.GroupID != scope.GroupID {
		return nil, ErrSharedTaskNotFound
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

func (s *Store) ListSharedTasksForActor(scope NativeActorScope, limit int) ([]SharedTask, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := guardNativeActorTx(tx, scope, "task.read", time.Now().UTC()); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT `+sharedTaskColumns+` FROM shared_tasks_v2
WHERE group_id=? ORDER BY priority DESC,created_at,id LIMIT ?`, scope.GroupID, limit)
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return tasks, nil
}

func (s *Store) GetSharedTaskHandoffForActor(scope NativeActorScope, id, action string) (*SharedTaskHandoff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := guardNativeActorTx(tx, scope, action, time.Now().UTC()); err != nil {
		return nil, err
	}
	handoff, err := scanSharedTaskHandoff(tx.QueryRow(`SELECT `+sharedTaskHandoffColumns+`
FROM shared_task_v2_handoffs WHERE id=? AND group_id=?`, id, scope.GroupID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return handoff, nil
}
