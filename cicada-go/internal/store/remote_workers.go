package store

// ListWorkersForMachine returns queued work for a remote agent to claim.
func (s *Store) ListWorkersForMachine(machineID string) ([]Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id FROM workers
WHERE machine_id = ? AND status IN ('queued', 'recovering') ORDER BY created_at`, machineID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
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
	result := make([]Worker, 0, len(ids))
	for _, id := range ids {
		worker, err := s.getWorkerLocked(id)
		if err != nil {
			return nil, err
		}
		if worker != nil {
			result = append(result, *worker)
		}
	}
	return result, nil
}

// ClaimWorker atomically reserves one queued worker for a remote machine.
func (s *Store) ClaimWorker(id, machineID string) (*Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE workers SET status = 'running', attempt = attempt + 1,
started_at = ?, ended_at = NULL, pid = NULL, updated_at = ?
WHERE id = ? AND machine_id = ? AND status IN ('queued', 'recovering')`, now(), now(), id, machineID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed == 0 {
		return nil, nil
	}
	return s.getWorkerLocked(id)
}

// RequeueRunningWorkersForMachine releases work whose remote machine stopped
// heartbeating. A later claim increments the attempt and resumes normal
// recovery processing.
func (s *Store) RequeueRunningWorkersForMachine(machineID, reason string) ([]Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id FROM workers WHERE machine_id = ? AND status = 'running' ORDER BY created_at`, machineID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
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
	result := make([]Worker, 0, len(ids))
	for _, id := range ids {
		if _, err := s.db.Exec(`UPDATE workers SET status = 'queued', pid = NULL,
ended_at = NULL, last_error = ?, updated_at = ? WHERE id = ? AND status = 'running'`, reason, now(), id); err != nil {
			return nil, err
		}
		worker, err := s.getWorkerLocked(id)
		if err != nil {
			return nil, err
		}
		if worker != nil {
			result = append(result, *worker)
		}
	}
	return result, nil
}
