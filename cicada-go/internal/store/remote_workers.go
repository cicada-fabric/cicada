package store

const RemoteWorkerOutcomeUncertain = "outcome_uncertain"

// CancelPendingRemoteWorkerApprovals retires requests from a lost native turn.
// A fresh attempt must issue its own request; the old app-server RPC ID is not
// a reusable user authorization.
func (s *Store) CancelPendingRemoteWorkerApprovals(id, nodeID string, attempt int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE approvals SET status='cancelled', resolved_at=?
WHERE worker_id=? AND source_node_id=? AND worker_attempt=? AND status='pending'`,
		now(), id, nodeID, attempt)
	return err
}

// ProtectApprovedRemoteWorker stops automatic replay after an accepted native
// approval. The Node may have executed the action before losing its result.
func (s *Store) ProtectApprovedRemoteWorker(id string, attempt int, reason string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE workers SET status=?, pid=NULL, last_error=?, updated_at=?
WHERE id=? AND attempt=? AND status IN ('running','verifying')
AND EXISTS (SELECT 1 FROM approvals WHERE worker_id=workers.id
AND source_node_id=workers.machine_id AND worker_attempt=workers.attempt
AND status='resolved' AND decision IN ('accept','acceptForSession'))`,
		RemoteWorkerOutcomeUncertain, reason, now(), id, attempt)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed != 0, err
}

// ListWorkersForMachine returns queued work for a remote agent to claim.
func (s *Store) ListWorkersForMachine(machineID string) ([]Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id FROM workers
WHERE machine_id = ? AND status IN ('queued', 'recovering')
AND EXISTS (SELECT 1 FROM goals WHERE goals.id=workers.goal_id AND goals.status<>'paused')
ORDER BY created_at`, machineID)
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
WHERE id = ? AND machine_id = ? AND status IN ('queued', 'recovering')
AND EXISTS (SELECT 1 FROM goals WHERE goals.id=workers.goal_id AND goals.status<>'paused')`, now(), now(), id, machineID)
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

// TransitionWorkerStatus performs a compare-and-swap transition. Remote
// completion uses it to ensure retries cannot verify or finalize one attempt
// twice, while cancellation can still win the race safely.
func (s *Store) TransitionWorkerStatus(id, machineID, from, to string) (*Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE workers SET status = ?, updated_at = ?
WHERE id = ? AND machine_id = ? AND status = ?`, to, now(), id, machineID, from)
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
// heartbeating. Attempts with an accepted approval are held for reconciliation
// instead of silently replaying a possibly executed native action.
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
		if _, err := s.db.Exec(`UPDATE workers SET status = CASE WHEN EXISTS (
SELECT 1 FROM approvals WHERE worker_id=workers.id AND source_node_id=workers.machine_id
AND worker_attempt=workers.attempt AND status='resolved'
AND decision IN ('accept','acceptForSession')) THEN 'outcome_uncertain' ELSE 'queued' END,
pid = NULL, ended_at = NULL, last_error = ?, updated_at = ?
WHERE id = ? AND status = 'running'`, reason, now(), id); err != nil {
			return nil, err
		}
		if _, err := s.db.Exec(`UPDATE approvals SET status='cancelled', resolved_at=?
WHERE worker_id=? AND source_node_id=? AND status='pending'`, now(), id, machineID); err != nil {
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
