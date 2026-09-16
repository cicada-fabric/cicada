package store

// ClaimPendingCommandsForWorker consumes only commands addressed to one
// worker. This prevents one member of a multi-worker goal from stealing a
// sibling's monitor correction.
func (s *Store) ClaimPendingCommandsForWorker(goalID, workerID string) ([]Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	timestamp := now()
	rows, err := s.db.Query(`SELECT id FROM commands WHERE goal_id = ? AND worker_id = ?
AND status = 'pending' ORDER BY id`, goalID, workerID)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
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
	result := make([]Command, 0, len(ids))
	for _, id := range ids {
		updated, err := s.db.Exec(`UPDATE commands SET status = 'consumed', consumed_at = ?
WHERE id = ? AND status = 'pending'`, timestamp, id)
		if err != nil {
			return nil, err
		}
		changed, err := updated.RowsAffected()
		if err != nil {
			return nil, err
		}
		if changed == 0 {
			continue
		}
		command, err := s.getCommandLocked(id)
		if err != nil {
			return nil, err
		}
		result = append(result, *command)
	}
	return result, nil
}
