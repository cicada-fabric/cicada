package store

import (
	"database/sql"
	"encoding/json"
)

// ClaimBoundNodeWorkerControlRPC commits the claim, pending monitor commands,
// machine/Goal projections, and the WorkerStarted event under the same live
// Node-Control request fence. This keeps the operation atomic across an Owner
// key upgrade and avoids calling Control while holding Store's mutex.
func (s *Store) ClaimBoundNodeWorkerControlRPC(input NodeControlRPCInput,
	workerID string) (*Worker, []Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	if err := verifyNodeControlRPCProcessingTx(tx, input); err != nil {
		return nil, nil, err
	}
	stamp := now()
	result, err := tx.Exec(`UPDATE workers AS worker SET status='running', attempt=attempt+1,
started_at=?, ended_at=NULL, pid=NULL, updated_at=?
WHERE worker.id=? AND worker.machine_id=? AND worker.status IN ('queued','recovering') AND `+nodeWorkerAuthorizationExists,
		stamp, stamp, workerID, input.NodeID, input.CredentialDigest, input.NodeID)
	if err != nil {
		return nil, nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, nil, err
	}
	if changed != 1 {
		return nil, nil, classifyBoundNodeWorkerTx(tx, input.CredentialDigest, input.NodeID, workerID)
	}
	worker, err := scanNodeWorker(tx.QueryRow(`SELECT id, goal_id, machine_id, harness, status,
pid, thread_id, attempt, started_at, ended_at, last_error, summary, prompt,
response_file, workspace, created_at, updated_at FROM workers WHERE id=?`, workerID))
	if err != nil {
		return nil, nil, err
	}
	if err := s.cancelRemoteApprovalsForOldAttemptsTx(tx, worker.ID, input.NodeID, worker.Attempt); err != nil {
		return nil, nil, err
	}

	rows, err := tx.Query(`SELECT id FROM commands WHERE goal_id=? AND worker_id=? AND status='pending' ORDER BY id`,
		worker.GoalID, worker.ID)
	if err != nil {
		return nil, nil, err
	}
	var commandIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, nil, err
		}
		commandIDs = append(commandIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	commands := make([]Command, 0, len(commandIDs))
	for _, id := range commandIDs {
		updated, err := tx.Exec(`UPDATE commands SET status='consumed',consumed_at=?
WHERE id=? AND goal_id=? AND worker_id=? AND status='pending'`, stamp, id, worker.GoalID, worker.ID)
		if err != nil {
			return nil, nil, err
		}
		rowsAffected, err := updated.RowsAffected()
		if err != nil {
			return nil, nil, err
		}
		if rowsAffected != 1 {
			continue
		}
		var command Command
		var workerID sql.NullString
		var consumedAt sql.NullString
		if err := tx.QueryRow(`SELECT id,goal_id,worker_id,command,status,created_at,consumed_at
FROM commands WHERE id=?`, id).Scan(&command.ID, &command.GoalID, &workerID,
			&command.Command, &command.Status, &command.CreatedAt, &consumedAt); err != nil {
			return nil, nil, err
		}
		command.WorkerID, command.ConsumedAt = workerID.String, consumedAt.String
		commands = append(commands, command)
	}

	machineResult, err := tx.Exec(`UPDATE machines SET status='busy',last_seen=? WHERE id=? AND owner_id=(
SELECT owner_id FROM node_owner_bindings_v2 WHERE id=? AND state='ACTIVE')`, stamp, input.NodeID, input.BindingID)
	if err != nil {
		return nil, nil, err
	}
	machineChanged, err := machineResult.RowsAffected()
	if err != nil || machineChanged != 1 {
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrNodeControlKeyUnauthorized
	}
	goalResult, err := tx.Exec(`UPDATE goals SET status='running',updated_at=?,
lifecycle_version=lifecycle_version+1 WHERE id=? AND owner_id=(
SELECT owner_id FROM node_owner_bindings_v2 WHERE id=? AND state='ACTIVE')`, stamp, worker.GoalID, input.BindingID)
	if err != nil {
		return nil, nil, err
	}
	goalChanged, err := goalResult.RowsAffected()
	if err != nil || goalChanged != 1 {
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrNodeControlKeyUnauthorized
	}
	payload, err := json.Marshal(map[string]any{"attempt": worker.Attempt, "remote": true, "machine_id": input.NodeID})
	if err != nil {
		return nil, nil, err
	}
	if _, err := tx.Exec(`INSERT INTO events(goal_id,worker_id,type,payload_json,created_at)
VALUES (?,?, 'WorkerStarted', ?, ?)`, worker.GoalID, worker.ID, string(payload), stamp); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return worker, commands, nil
}
