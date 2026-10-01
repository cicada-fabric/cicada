package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNodeWorkerNotAuthorized        = errors.New("Node credential is not authorized for this worker")
	ErrNodeWorkerUnavailable          = errors.New("Node Worker is not claimable or result attempt is stale")
	ErrOwnerNodeUnavailable           = errors.New("machine is not currently bound to this owner")
	ErrNodeMachineOwnershipConflict   = errors.New("Node ID is already registered as an unowned or differently owned machine")
	ErrOwnerBoundMachineManagedByNode = errors.New("owner-bound Node machine state must be reported with its Node credential")
	ErrNodeMachineHeartbeatInput      = errors.New("invalid Node machine heartbeat input")
)

// initializeOwnerScopedNodeJobsV2Schema adds explicit ownership only to new
// Client-origin work. The empty default deliberately leaves all preexisting
// Goals and accepted Client intents unattributed and therefore invisible to
// the Node-scoped Worker API.
func (s *Store) initializeOwnerScopedNodeJobsV2Schema() error {
	for _, column := range []struct {
		table string
		name  string
		ddl   string
	}{
		{"machines", "owner_id", `ALTER TABLE machines ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''`},
		{"goals", "owner_id", `ALTER TABLE goals ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''`},
		{"client_control_intents_v2", "owner_id", `ALTER TABLE client_control_intents_v2 ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''`},
	} {
		if err := s.ensureColumn(column.table, column.name, column.ddl); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS goals_owner_status_idx
ON goals(owner_id, status, machine_id, created_at)`); err != nil {
		return fmt.Errorf("create Goal owner index: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS client_control_intents_v2_owner_state_idx
ON client_control_intents_v2(owner_id, state, created_at, intent_id)`); err != nil {
		return fmt.Errorf("create Client intent owner index: %w", err)
	}
	return nil
}

// nodeWorkerAuthorizationExists is embedded in reads and state transitions.
// Owner identity is sourced only from the current credential's active binding;
// Goal ownership and the Worker-to-Node machine relation are checked in the
// same SQL statement as the protected operation.
const nodeWorkerAuthorizationExists = `EXISTS (
  SELECT 1
  FROM fabric_node_credentials credential
  JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
    AND binding.node_credential_digest=credential.credential_hash
    AND binding.node_credential_version=credential.version
    AND binding.state='ACTIVE'
  JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
  JOIN principals principal ON principal.id=binding.owner_id
    AND principal.kind='human' AND principal.status='active'
  JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
    AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
  JOIN machines authorized_machine ON authorized_machine.id=credential.node_id
  JOIN goals authorized_goal ON authorized_goal.id=worker.goal_id
  WHERE credential.credential_hash=? AND credential.status='active'
    AND credential.node_id=?
    AND worker.machine_id=credential.node_id
    AND authorized_goal.status<>'paused'
    AND authorized_machine.id=worker.machine_id
    AND authorized_machine.owner_id<>'' AND authorized_machine.owner_id=binding.owner_id
    AND authorized_goal.owner_id<>'' AND authorized_goal.owner_id=binding.owner_id
)`

// currentBoundNodeOwnerTx resolves a bearer to its current owner and Node
// inside the caller's transaction. The requested Node is only a path check;
// neither owner nor Node identity is accepted from a JSON body.
func currentBoundNodeOwnerTx(tx *sql.Tx, credentialDigest, requestedNodeID string) (string, error) {
	var nodeID, ownerID string
	err := tx.QueryRow(`SELECT credential.node_id, binding.owner_id
FROM fabric_node_credentials credential
JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
  AND binding.node_credential_digest=credential.credential_hash
  AND binding.node_credential_version=credential.version AND binding.state='ACTIVE'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN principals principal ON principal.id=binding.owner_id
  AND principal.kind='human' AND principal.status='active'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
  AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
WHERE credential.credential_hash=? AND credential.status='active'`, credentialDigest).
		Scan(&nodeID, &ownerID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && nodeID != requestedNodeID) {
		return "", ErrNodeWorkerNotAuthorized
	}
	if err != nil {
		return "", err
	}
	return ownerID, nil
}

func classifyBoundNodeWorkerTx(tx *sql.Tx, credentialDigest, requestedNodeID, workerID string) error {
	if _, err := currentBoundNodeOwnerTx(tx, credentialDigest, requestedNodeID); err != nil {
		return ErrNodeWorkerNotAuthorized
	}
	var found int
	err := tx.QueryRow(`SELECT 1 FROM workers worker
JOIN goals goal ON goal.id=worker.goal_id
JOIN machines machine ON machine.id=worker.machine_id
WHERE worker.id=? AND worker.machine_id=? AND `+nodeWorkerAuthorizationExists,
		workerID, requestedNodeID, credentialDigest, requestedNodeID).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeWorkerNotAuthorized
	}
	if err != nil {
		return err
	}
	return ErrNodeWorkerUnavailable
}

// OwnerBoundNodeMachine returns the machine currently paired to ownerID. The
// binding and credential are checked together with the machine row, so owner
// scoped Goal placement cannot select a legacy or another owner's machine.
func (s *Store) OwnerBoundNodeMachine(ownerID, nodeID string) (*Machine, error) {
	ownerID = strings.TrimSpace(ownerID)
	nodeID = strings.TrimSpace(nodeID)
	if ownerID == "" || nodeID == "" {
		return nil, ErrOwnerNodeUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return readOwnerBoundNodeMachine(s.db.QueryRow(ownerBoundNodeMachineSelect+`
WHERE machine.id=? AND binding.owner_id=?`, nodeID, ownerID))
}

// ListOwnerBoundNodeMachines returns only currently active Node bindings for
// an owner, in machine-ID order. Local executors remain managed separately by
// Control and are not represented as Node bindings.
func (s *Store) ListOwnerBoundNodeMachines(ownerID string) ([]Machine, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return []Machine{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(ownerBoundNodeMachineSelect+`
WHERE binding.owner_id=? ORDER BY machine.id`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var machines []Machine
	for rows.Next() {
		machine, err := scanMachine(rows)
		if err != nil {
			return nil, err
		}
		machines = append(machines, *machine)
	}
	return machines, rows.Err()
}

const ownerBoundNodeMachineSelect = `SELECT machine.id, machine.name, machine.status,
machine.capabilities_json, machine.last_seen, machine.created_at
FROM machines machine
JOIN fabric_node_credentials credential ON credential.node_id=machine.id
  AND credential.status='active'
JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
  AND binding.node_credential_digest=credential.credential_hash
  AND binding.node_credential_version=credential.version AND binding.state='ACTIVE'
  AND binding.owner_id=machine.owner_id
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN principals principal ON principal.id=binding.owner_id
  AND principal.kind='human' AND principal.status='active'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
  AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'`

func readOwnerBoundNodeMachine(row interface{ Scan(...any) error }) (*Machine, error) {
	machine, err := scanMachine(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOwnerNodeUnavailable
	}
	return machine, err
}

func scanMachine(row interface{ Scan(...any) error }) (*Machine, error) {
	var machine Machine
	var capabilitiesJSON string
	if err := row.Scan(&machine.ID, &machine.Name, &machine.Status, &capabilitiesJSON,
		&machine.LastSeen, &machine.CreatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(capabilitiesJSON), &machine.Capabilities); err != nil {
		return nil, fmt.Errorf("decode machine capabilities: %w", err)
	}
	return &machine, nil
}

// ListBoundNodeWorkerIDs performs the entire authorization decision and the
// queued-work selection in one read transaction. A revoked or rotated token
// cannot pass the binding lookup, and ownerless legacy work is never selected.
func (s *Store) ListBoundNodeWorkerIDs(credentialDigest, requestedNodeID string, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := currentBoundNodeOwnerTx(tx, credentialDigest, requestedNodeID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT worker.id FROM workers worker
JOIN goals goal ON goal.id=worker.goal_id
JOIN machines machine ON machine.id=worker.machine_id
WHERE worker.status IN ('queued','recovering') AND `+nodeWorkerAuthorizationExists+`
ORDER BY worker.created_at, worker.id LIMIT ?`, credentialDigest, requestedNodeID, limit)
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
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
}

// GetBoundNodeWorker returns the authorized queued Worker snapshot used for
// Control's existing permission checks. Claim still repeats every identity,
// owner, machine and status condition in the atomic update below.
func (s *Store) GetBoundNodeWorker(credentialDigest, requestedNodeID, workerID string) (*Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := currentBoundNodeOwnerTx(tx, credentialDigest, requestedNodeID); err != nil {
		return nil, err
	}
	var authorized int
	err = tx.QueryRow(`SELECT 1 FROM workers worker
JOIN goals goal ON goal.id=worker.goal_id
JOIN machines machine ON machine.id=worker.machine_id
WHERE worker.id=? AND worker.status IN ('queued','recovering') AND `+nodeWorkerAuthorizationExists,
		workerID, credentialDigest, requestedNodeID).Scan(&authorized)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeWorkerNotAuthorized
	}
	if err != nil {
		return nil, err
	}
	worker, err := scanNodeWorker(tx.QueryRow(`SELECT id, goal_id, machine_id, harness, status,
pid, thread_id, attempt, started_at, ended_at, last_error, summary, prompt,
response_file, workspace, created_at, updated_at FROM workers WHERE id=?`, workerID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return worker, nil
}

// ClaimBoundNodeWorker is the authoritative Worker claim guard. The update is
// conditioned on the live Node credential, active binding owner, machine
// relation, Goal owner and queued state in the same SQLite statement.
func (s *Store) ClaimBoundNodeWorker(credentialDigest, requestedNodeID, workerID string) (*Worker, error) {
	return s.claimBoundNodeWorker(credentialDigest, requestedNodeID, workerID, nil)
}

// ClaimBoundNodeWorkerNodeControl is the Node-Control variant. It verifies
// the admitted encrypted request and current key epoch in the same transaction
// as the worker claim.
func (s *Store) ClaimBoundNodeWorkerNodeControl(input NodeControlRPCInput, workerID string) (*Worker, error) {
	return s.claimBoundNodeWorker(input.CredentialDigest, input.NodeID, workerID, &input)
}

func (s *Store) claimBoundNodeWorker(credentialDigest, requestedNodeID, workerID string, guard *NodeControlRPCInput) (*Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if guard != nil {
		if err := verifyNodeControlRPCProcessingTx(tx, *guard); err != nil {
			return nil, err
		}
	}
	stamp := now()
	result, err := tx.Exec(`UPDATE workers AS worker SET status='running', attempt=attempt+1,
started_at=?, ended_at=NULL, pid=NULL, updated_at=?
WHERE worker.id=? AND worker.machine_id=? AND worker.status IN ('queued','recovering') AND `+nodeWorkerAuthorizationExists,
		stamp, stamp, workerID, requestedNodeID, credentialDigest, requestedNodeID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, classifyBoundNodeWorkerTx(tx, credentialDigest, requestedNodeID, workerID)
	}
	worker, err := scanNodeWorker(tx.QueryRow(`SELECT id, goal_id, machine_id, harness, status,
pid, thread_id, attempt, started_at, ended_at, last_error, summary, prompt,
response_file, workspace, created_at, updated_at FROM workers WHERE id=?`, workerID))
	if err != nil {
		return nil, err
	}
	if err := s.cancelRemoteApprovalsForOldAttemptsTx(tx, worker.ID, requestedNodeID, worker.Attempt); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return worker, nil
}

// BeginBoundNodeWorkerResult fences a Node result to the current attempt. It
// authenticates the binding and moves running (or an uncertain original
// attempt reporting late) to verifying in one statement;
// stale attempts, other owners, revoked credentials, and wrong-machine results
// produce no result-processing side effects.
func (s *Store) BeginBoundNodeWorkerResult(credentialDigest, requestedNodeID, workerID string, attempt int) (*Worker, error) {
	return s.beginBoundNodeWorkerResult(credentialDigest, requestedNodeID, workerID, attempt, nil)
}

// BeginBoundNodeWorkerResultNodeControl also requires the exact Node-Control
// request to remain PROCESSING under the currently active binding epoch.
func (s *Store) BeginBoundNodeWorkerResultNodeControl(input NodeControlRPCInput, workerID string, attempt int) (*Worker, error) {
	return s.beginBoundNodeWorkerResult(input.CredentialDigest, input.NodeID, workerID, attempt, &input)
}

func (s *Store) beginBoundNodeWorkerResult(credentialDigest, requestedNodeID, workerID string, attempt int, guard *NodeControlRPCInput) (*Worker, error) {
	if attempt <= 0 {
		return nil, ErrNodeWorkerNotAuthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if guard != nil {
		if err := verifyNodeControlRPCProcessingTx(tx, *guard); err != nil {
			return nil, err
		}
	}
	stamp := now()
	result, err := tx.Exec(`UPDATE workers AS worker SET status='verifying', updated_at=?
WHERE worker.id=? AND worker.machine_id=? AND worker.attempt=?
AND worker.status IN ('running','outcome_uncertain') AND `+nodeWorkerAuthorizationExists,
		stamp, workerID, requestedNodeID, attempt, credentialDigest, requestedNodeID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, classifyBoundNodeWorkerTx(tx, credentialDigest, requestedNodeID, workerID)
	}
	worker, err := scanNodeWorker(tx.QueryRow(`SELECT id, goal_id, machine_id, harness, status,
pid, thread_id, attempt, started_at, ended_at, last_error, summary, prompt,
response_file, workspace, created_at, updated_at FROM workers WHERE id=?`, workerID))
	if err != nil {
		return nil, err
	}
	if err := s.cancelRemoteApprovalsForWorkerAttemptTx(tx, worker.ID, requestedNodeID, attempt); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return worker, nil
}

func (s *Store) TransitionWorkerStatusAtAttempt(id, machineID, from, to string, attempt int) (*Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE workers SET status=?, updated_at=?
WHERE id=? AND machine_id=? AND status=? AND attempt=?`, to, now(), id, machineID, from, attempt)
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

// UpdateWorkerAtAttempt atomically records a result and makes its next status
// visible. The attempt/status fence prevents an old completion from changing a
// newer execution attempt.
func (s *Store) UpdateWorkerAtAttempt(id, machineID, from, to string, attempt int, update WorkerUpdate) (*Worker, error) {
	return s.updateWorkerAtAttempt("", "", id, machineID, from, to, attempt, update)
}

// UpdateBoundNodeWorkerAtAttempt repeats the current Node credential and
// owner-binding guard in the final result write. This closes the interval
// between result admission/verifier work and making the Worker claimable or
// completed.
func (s *Store) UpdateBoundNodeWorkerAtAttempt(credentialDigest, requestedNodeID, id, from, to string, attempt int, update WorkerUpdate) (*Worker, error) {
	return s.updateWorkerAtAttempt(credentialDigest, requestedNodeID, id, requestedNodeID, from, to, attempt, update)
}

// UpdateBoundNodeWorkerAtAttemptNodeControl fences the final result commit to
// the live Node key epoch and this exact still-processing encrypted request.
func (s *Store) UpdateBoundNodeWorkerAtAttemptNodeControl(input NodeControlRPCInput, id, from, to string, attempt int, update WorkerUpdate) (*Worker, error) {
	return s.updateWorkerAtAttemptWithNodeControl(input.CredentialDigest, input.NodeID, id, input.NodeID,
		from, to, attempt, update, &input)
}

// RecoverBoundNodeWorkerAfterRevocation makes an admitted but not-yet-final
// result explicitly recoverable when the Node loses authorization during
// verification. It records no result data and cannot affect another attempt.
func (s *Store) RecoverBoundNodeWorkerAfterRevocation(id, nodeID string, attempt int) (*Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE workers SET status='recovering', pid=NULL,
ended_at=?, last_error='Node authorization changed during result verification; result discarded', updated_at=?
WHERE id=? AND machine_id=? AND status='verifying' AND attempt=?`, now(), now(), id, nodeID, attempt)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, nil
	}
	worker, err := scanNodeWorker(tx.QueryRow(`SELECT id, goal_id, machine_id, harness, status,
pid, thread_id, attempt, started_at, ended_at, last_error, summary, prompt,
response_file, workspace, created_at, updated_at FROM workers WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return worker, nil
}

func (s *Store) updateWorkerAtAttempt(credentialDigest, requestedNodeID, id, machineID, from, to string, attempt int, update WorkerUpdate) (*Worker, error) {
	return s.updateWorkerAtAttemptWithNodeControl(credentialDigest, requestedNodeID, id, machineID,
		from, to, attempt, update, nil)
}

func (s *Store) updateWorkerAtAttemptWithNodeControl(credentialDigest, requestedNodeID, id, machineID, from, to string, attempt int, update WorkerUpdate, guard *NodeControlRPCInput) (*Worker, error) {
	assignments := []string{"status=?", "updated_at=?"}
	args := []any{to, now()}
	if update.ClearPID {
		assignments = append(assignments, "pid=NULL")
	} else if update.PID != nil {
		assignments = append(assignments, "pid=?")
		args = append(args, *update.PID)
	}
	if update.ThreadID != nil {
		assignments = append(assignments, "thread_id=?")
		args = append(args, *update.ThreadID)
	}
	if update.Attempt != nil {
		assignments = append(assignments, "attempt=?")
		args = append(args, *update.Attempt)
	}
	if update.StartedAt != nil {
		assignments = append(assignments, "started_at=?")
		args = append(args, *update.StartedAt)
	}
	if update.EndedAt != nil {
		assignments = append(assignments, "ended_at=?")
		args = append(args, *update.EndedAt)
	}
	if update.LastError != nil {
		assignments = append(assignments, "last_error=?")
		args = append(args, *update.LastError)
	}
	if update.Summary != nil {
		assignments = append(assignments, "summary=?")
		args = append(args, *update.Summary)
	}
	if update.Prompt != nil {
		assignments = append(assignments, "prompt=?")
		args = append(args, *update.Prompt)
	}
	query := `UPDATE workers AS worker SET ` + join(assignments, ", ") +
		` WHERE worker.id=? AND worker.machine_id=? AND worker.status=? AND worker.attempt=?`
	args = append(args, id, machineID, from, attempt)
	if credentialDigest != "" {
		query += ` AND ` + nodeWorkerAuthorizationExists
		args = append(args, credentialDigest, requestedNodeID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if guard != nil {
		if err := verifyNodeControlRPCProcessingTx(tx, *guard); err != nil {
			return nil, err
		}
	}
	result, err := tx.Exec(query, args...)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		if credentialDigest != "" {
			return nil, classifyBoundNodeWorkerTx(tx, credentialDigest, requestedNodeID, id)
		}
		return nil, nil
	}
	worker, err := scanNodeWorker(tx.QueryRow(`SELECT id, goal_id, machine_id, harness, status,
pid, thread_id, attempt, started_at, ended_at, last_error, summary, prompt,
response_file, workspace, created_at, updated_at FROM workers WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return worker, nil
}

func scanNodeWorker(row interface{ Scan(...any) error }) (*Worker, error) {
	var worker Worker
	var pid sql.NullInt64
	var threadID, startedAt, endedAt, lastError, summary, prompt sql.NullString
	err := row.Scan(&worker.ID, &worker.GoalID, &worker.MachineID, &worker.Harness, &worker.Status,
		&pid, &threadID, &worker.Attempt, &startedAt, &endedAt, &lastError, &summary,
		&prompt, &worker.ResponseFile, &worker.Workspace, &worker.CreatedAt, &worker.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if pid.Valid {
		value := int(pid.Int64)
		worker.PID = &value
	}
	worker.ThreadID, worker.StartedAt, worker.EndedAt = threadID.String, startedAt.String, endedAt.String
	worker.LastError, worker.Summary, worker.Prompt = lastError.String, summary.String, prompt.String
	return &worker, nil
}

func (s *Store) RecordBoundNodeMachineHeartbeat(credentialDigest, status string, capabilities map[string]any) error {
	return s.recordBoundNodeMachineHeartbeat(credentialDigest, status, capabilities, nil)
}

// RecordBoundNodeMachineHeartbeatNodeControl rejects a heartbeat whose
// binding/key epoch or admitted packet changed before the database write.
func (s *Store) RecordBoundNodeMachineHeartbeatNodeControl(input NodeControlRPCInput, status string, capabilities map[string]any) error {
	return s.recordBoundNodeMachineHeartbeat(input.CredentialDigest, status, capabilities, &input)
}

func (s *Store) recordBoundNodeMachineHeartbeat(credentialDigest, status string, capabilities map[string]any, guard *NodeControlRPCInput) error {
	status = strings.TrimSpace(status)
	if status != "" && status != "available" && status != "idle" && status != "busy" {
		return fmt.Errorf("%w: status must be available, idle, or busy", ErrNodeMachineHeartbeatInput)
	}
	var encodedCapabilities any
	if capabilities != nil {
		encoded, err := json.Marshal(capabilities)
		if err != nil {
			return fmt.Errorf("%w: encode capabilities: %v", ErrNodeMachineHeartbeatInput, err)
		}
		if len(encoded) > 64*1024 {
			return fmt.Errorf("%w: capabilities exceed 65536 bytes", ErrNodeMachineHeartbeatInput)
		}
		encodedCapabilities = string(encoded)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if guard != nil {
		if err := verifyNodeControlRPCProcessingTx(tx, *guard); err != nil {
			return err
		}
	}
	var nodeID, nodeName, ownerID, machineOwnerID string
	err = tx.QueryRow(`SELECT credential.node_id, binding.node_name, binding.owner_id, machine.owner_id
FROM fabric_node_credentials credential
JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
  AND binding.node_credential_digest=credential.credential_hash
  AND binding.node_credential_version=credential.version AND binding.state='ACTIVE'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN principals principal ON principal.id=binding.owner_id
  AND principal.kind='human' AND principal.status='active'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
  AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
JOIN machines machine ON machine.id=credential.node_id
WHERE credential.credential_hash=? AND credential.status='active'`, credentialDigest).
		Scan(&nodeID, &nodeName, &ownerID, &machineOwnerID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeWorkerNotAuthorized
	}
	if err != nil {
		return err
	}
	// Legacy machine rows are ownerless after migration. A Node bearer cannot
	// claim or overwrite one, even when its credential is currently bound.
	if machineOwnerID != ownerID {
		return ErrNodeMachineOwnershipConflict
	}
	stamp := now()
	set := "name=?, last_seen=?"
	args := []any{nodeName, stamp}
	if status != "" {
		set += ", status=?"
		args = append(args, status)
	}
	if encodedCapabilities != nil {
		set += ", capabilities_json=?"
		args = append(args, encodedCapabilities)
	}
	query := `UPDATE machines SET ` + set + ` WHERE id=? AND owner_id=?`
	args = append(args, nodeID, ownerID)
	result, err := tx.Exec(query, args...)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrOwnerNodeUnavailable
	}
	return tx.Commit()
}

// CreateOwnedGoal persists owner attribution only after confirming that a
// remote target is currently bound to this owner. Existing/unowned callers
// continue to use CreateGoalWithParent and are not silently upgraded.
func (s *Store) CreateOwnedGoal(ownerID string, goal Goal) (*Goal, error) {
	ownerID = strings.TrimSpace(ownerID)
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	if goal.Budget == nil {
		goal.Budget = map[string]any{}
	}
	if goal.Resources == nil {
		goal.Resources = map[string]any{}
	}
	budgetJSON, err := json.Marshal(goal.Budget)
	if err != nil {
		return nil, fmt.Errorf("encode goal budget: %w", err)
	}
	resourcesJSON, err := json.Marshal(goal.Resources)
	if err != nil {
		return nil, fmt.Errorf("encode goal resources: %w", err)
	}
	stamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if goal.MachineID != "control-local" && goal.MachineID != "worker-local" {
		_, err := ownerBoundNodeMachineTx(tx, ownerID, goal.MachineID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrOwnerNodeUnavailable
		}
		if err != nil {
			return nil, err
		}
	}
	if goal.ParentGoalID != "" {
		var parentOwner string
		if err := tx.QueryRow(`SELECT owner_id FROM goals WHERE id=?`, goal.ParentGoalID).Scan(&parentOwner); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNodeWorkerNotAuthorized
			}
			return nil, err
		}
		if parentOwner != ownerID {
			return nil, ErrNodeWorkerNotAuthorized
		}
	}
	_, err = tx.Exec(`INSERT INTO goals
(id, parent_goal_id, objective, success_criteria, constraints, priority, deadline,
 budget_json, resources_json, status, machine_id, monitor_id, workspace, created_at,
 updated_at, owner_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?)`,
		goal.ID, nullableString(goal.ParentGoalID), goal.Objective, goal.SuccessCriteria,
		goal.Constraints, goal.Priority, nullableString(goal.Deadline), string(budgetJSON),
		string(resourcesJSON), goal.MachineID, goal.MonitorID, goal.Workspace, stamp, stamp, ownerID)
	if err != nil {
		return nil, fmt.Errorf("create owner-attributed goal: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getGoalLocked(goal.ID)
}

func (s *Store) canOwnedGoalUseMachineTx(tx *sql.Tx, goalID, machineID string) (bool, error) {
	var ownerID string
	if err := tx.QueryRow(`SELECT owner_id FROM goals WHERE id=?`, goalID).Scan(&ownerID); err != nil {
		return false, err
	}
	if ownerID == "" || machineID == "control-local" || machineID == "worker-local" {
		return true, nil
	}
	_, err := ownerBoundNodeMachineTx(tx, ownerID, machineID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func ownerBoundNodeMachineTx(tx *sql.Tx, ownerID, machineID string) (*Machine, error) {
	return scanMachine(tx.QueryRow(ownerBoundNodeMachineSelect+`
WHERE machine.id=? AND machine.owner_id=? AND binding.owner_id=?`, machineID, ownerID, ownerID))
}

// CreateWorkerAtHarness keeps legacy ownerless worker behavior. For an owned
// Goal it verifies the machine's current owner binding in the same write
// transaction that inserts the Worker.
func (s *Store) createOwnedWorkerAtHarness(id, goalID, machineID, harness, responseFile, workspace string) (*Worker, error) {
	if strings.TrimSpace(harness) == "" {
		harness = "codex"
	}
	stamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	allowed, err := s.canOwnedGoalUseMachineTx(tx, goalID, machineID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrOwnerNodeUnavailable
	}
	if _, err := tx.Exec(`INSERT INTO workers
(id, goal_id, machine_id, harness, status, response_file, workspace, created_at, updated_at)
VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?)`, id, goalID, machineID, harness, responseFile, workspace, stamp, stamp); err != nil {
		return nil, fmt.Errorf("create worker: %w", err)
	}
	worker, err := scanNodeWorker(tx.QueryRow(`SELECT id, goal_id, machine_id, harness, status,
pid, thread_id, attempt, started_at, ended_at, last_error, summary, prompt,
response_file, workspace, created_at, updated_at FROM workers WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return worker, nil
}
