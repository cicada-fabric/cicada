package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

var (
	ErrNodeApprovalNotAuthorized = errors.New("Node Worker approval is not authorized")
	ErrNodeApprovalStale         = errors.New("Node Worker approval attempt is stale")
	ErrNodeApprovalConflict      = errors.New("Node Worker approval idempotency key conflicts")
)

const (
	NodeApprovalCommandExecution = "item/commandExecution/requestApproval"
	NodeApprovalFileChange       = "item/fileChange/requestApproval"
)

func (s *Store) initializeRemoteWorkerApprovalsV2Schema() error {
	for _, column := range []struct {
		name string
		ddl  string
	}{
		{"source_node_id", `ALTER TABLE approvals ADD COLUMN source_node_id TEXT NOT NULL DEFAULT ''`},
		{"worker_attempt", `ALTER TABLE approvals ADD COLUMN worker_attempt INTEGER NOT NULL DEFAULT 0`},
		{"request_id", `ALTER TABLE approvals ADD COLUMN request_id TEXT NOT NULL DEFAULT ''`},
		{"request_hash", `ALTER TABLE approvals ADD COLUMN request_hash TEXT NOT NULL DEFAULT ''`},
	} {
		if err := s.ensureColumn("approvals", column.name, column.ddl); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS approvals_remote_request_idem_idx
ON approvals(source_node_id, worker_id, worker_attempt, request_id)
WHERE source_node_id <> '' AND request_id <> ''`)
	return err
}

func (s *Store) CreateBoundNodeApproval(credentialDigest, requestedNodeID, workerID string,
	attempt int, requestID, method string, request json.RawMessage) (*Approval, bool, error) {
	return s.createBoundNodeApproval(credentialDigest, requestedNodeID, workerID, attempt, requestID, method, request, nil)
}

// CreateBoundNodeApprovalNodeControl checks the live application key epoch
// and exact admitted RPC in the same transaction as approval insertion.
func (s *Store) CreateBoundNodeApprovalNodeControl(input NodeControlRPCInput, workerID string,
	attempt int, requestID, method string, request json.RawMessage) (*Approval, bool, error) {
	return s.createBoundNodeApproval(input.CredentialDigest, input.NodeID, workerID, attempt,
		requestID, method, request, &input)
}

func (s *Store) createBoundNodeApproval(credentialDigest, requestedNodeID, workerID string,
	attempt int, requestID, method string, request json.RawMessage, guard *NodeControlRPCInput) (*Approval, bool, error) {
	credentialDigest = strings.TrimSpace(credentialDigest)
	requestedNodeID = strings.TrimSpace(requestedNodeID)
	workerID = strings.TrimSpace(workerID)
	requestID = strings.TrimSpace(requestID)
	method = strings.TrimSpace(method)
	if credentialDigest == "" || requestedNodeID == "" || workerID == "" || requestID == "" ||
		attempt <= 0 || len(requestID) > 512 || len(method) > 128 || !validNodeApprovalMethod(method) ||
		!isJSONRequestObject(request) || len(request) > 64*1024 {
		return nil, false, ErrNodeApprovalNotAuthorized
	}
	requestHash := nodeApprovalRequestHash(method, request)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if guard != nil {
		if err := verifyNodeControlRPCProcessingTx(tx, *guard); err != nil {
			return nil, false, err
		}
	}
	ownerID, err := currentBoundNodeOwnerTx(tx, credentialDigest, requestedNodeID)
	if err != nil {
		return nil, false, ErrNodeApprovalNotAuthorized
	}
	goalID, err := validateBoundNodeApprovalAttemptTx(tx, ownerID, requestedNodeID, workerID, attempt, true)
	if err != nil {
		return nil, false, err
	}
	var existingID, existingHash string
	err = tx.QueryRow(`SELECT id, request_hash FROM approvals
WHERE source_node_id=? AND worker_id=? AND worker_attempt=? AND request_id=?`,
		requestedNodeID, workerID, attempt, requestID).Scan(&existingID, &existingHash)
	if err == nil {
		if existingHash != requestHash {
			return nil, false, ErrNodeApprovalConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		approval, err := s.getApprovalLocked(existingID)
		return approval, false, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	approvalID := NewID("approval")
	createdAt := now()
	_, err = tx.Exec(`INSERT INTO approvals
(id, goal_id, worker_id, method, request_json, status, created_at,
 source_node_id, worker_attempt, request_id, request_hash)
VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)`, approvalID, goalID, workerID,
		method, string(request), createdAt, requestedNodeID, attempt, requestID, requestHash)
	if err != nil {
		return nil, false, err
	}
	if guard != nil {
		payload, err := json.Marshal(map[string]any{"approval_id": approvalID,
			"method": method, "attempt": attempt})
		if err != nil {
			return nil, false, err
		}
		if _, err := tx.Exec(`INSERT INTO events(goal_id,worker_id,type,payload_json,created_at)
VALUES (?,?, 'ApprovalRequested', ?, ?)`, goalID, workerID, string(payload), createdAt); err != nil {
			return nil, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	approval, err := s.getApprovalLocked(approvalID)
	return approval, true, err
}

func (s *Store) GetBoundNodeApproval(credentialDigest, requestedNodeID, workerID string,
	attempt int, approvalID string) (*Approval, error) {
	return s.getBoundNodeApproval(credentialDigest, requestedNodeID, workerID, attempt, approvalID, nil)
}

// GetBoundNodeApprovalNodeControl verifies the caller's current key epoch
// even if stale-attempt reconciliation needs to cancel an approval row.
func (s *Store) GetBoundNodeApprovalNodeControl(input NodeControlRPCInput, workerID string,
	attempt int, approvalID string) (*Approval, error) {
	return s.getBoundNodeApproval(input.CredentialDigest, input.NodeID, workerID, attempt, approvalID, &input)
}

func (s *Store) getBoundNodeApproval(credentialDigest, requestedNodeID, workerID string,
	attempt int, approvalID string, guard *NodeControlRPCInput) (*Approval, error) {
	credentialDigest = strings.TrimSpace(credentialDigest)
	requestedNodeID = strings.TrimSpace(requestedNodeID)
	workerID = strings.TrimSpace(workerID)
	approvalID = strings.TrimSpace(approvalID)
	if credentialDigest == "" || requestedNodeID == "" || workerID == "" || approvalID == "" || attempt <= 0 {
		return nil, ErrNodeApprovalNotAuthorized
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
	ownerID, err := currentBoundNodeOwnerTx(tx, credentialDigest, requestedNodeID)
	if err != nil {
		return nil, ErrNodeApprovalNotAuthorized
	}
	goalID, workerStatus, goalStatus, err := readBoundNodeApprovalAttemptTx(tx, ownerID, requestedNodeID, workerID)
	if err != nil {
		return nil, ErrNodeApprovalNotAuthorized
	}
	var currentAttempt int
	if err := tx.QueryRow(`SELECT attempt FROM workers WHERE id=? AND machine_id=?`, workerID, requestedNodeID).Scan(&currentAttempt); err != nil {
		return nil, ErrNodeApprovalNotAuthorized
	}
	if currentAttempt != attempt {
		return nil, ErrNodeApprovalStale
	}
	approval, err := scanApprovalRecord(tx.QueryRow(`SELECT id, goal_id, worker_id, method, request_json,
status, decision, created_at, resolved_at, source_node_id, worker_attempt, request_id, request_hash
FROM approvals WHERE id=? AND goal_id=? AND worker_id=? AND source_node_id=? AND worker_attempt=?`,
		approvalID, goalID, workerID, requestedNodeID, attempt))
	if err != nil {
		return nil, err
	}
	if approval == nil {
		return nil, ErrNodeApprovalNotAuthorized
	}
	if goalStatus == "paused" || (approval.Status == "pending" && workerStatus != "running") {
		if approval.Status == "pending" {
			if err := s.cancelRemoteApprovalsForWorkerAttemptTx(tx, workerID, requestedNodeID, attempt); err != nil {
				return nil, err
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
		}
		return nil, ErrNodeApprovalStale
	}
	if approval.Status != "pending" && approval.Status != "resolved" {
		return nil, ErrNodeApprovalStale
	}
	if approval.Status == "resolved" && workerStatus != "running" && workerStatus != "verifying" && workerStatus != RemoteWorkerOutcomeUncertain {
		return nil, ErrNodeApprovalStale
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return approval, nil
}

func (s *Store) ValidateRemoteApprovalForDecision(approvalID string, requireRunnable bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	approval, err := s.getApprovalLocked(approvalID)
	if err != nil {
		return err
	}
	if approval == nil {
		return nil
	}
	return s.validateRemoteApprovalForDecisionLocked(approval, requireRunnable)
}

func (s *Store) validateRemoteApprovalForDecisionLocked(approval *Approval, requireRunnable bool) error {
	if approval == nil || approval.NodeID == "" {
		return nil
	}
	var current bool
	query := remoteApprovalCurrentExists
	if requireRunnable {
		query = remoteApprovalRunnableExists
	}
	if err := s.db.QueryRow(`SELECT `+query+` FROM approvals WHERE id=?`, approval.ID).Scan(&current); err != nil {
		return err
	}
	if !current {
		return ErrNodeApprovalStale
	}
	return nil
}

func validateBoundNodeApprovalAttemptTx(tx *sql.Tx, ownerID, nodeID, workerID string,
	attempt int, requireRunning bool) (string, error) {
	goalID, workerStatus, goalStatus, err := readBoundNodeApprovalAttemptTx(tx, ownerID, nodeID, workerID)
	if err != nil {
		return "", ErrNodeApprovalNotAuthorized
	}
	var currentAttempt int
	if err := tx.QueryRow(`SELECT attempt FROM workers WHERE id=? AND machine_id=?`, workerID, nodeID).Scan(&currentAttempt); err != nil {
		return "", ErrNodeApprovalNotAuthorized
	}
	if currentAttempt != attempt || (requireRunning && workerStatus != "running") || goalStatus == "paused" {
		return "", ErrNodeApprovalStale
	}
	return goalID, nil
}

func readBoundNodeApprovalAttemptTx(tx *sql.Tx, ownerID, nodeID, workerID string) (goalID, workerStatus, goalStatus string, err error) {
	err = tx.QueryRow(`SELECT goal.id, worker.status, goal.status
FROM workers worker
JOIN goals goal ON goal.id=worker.goal_id
JOIN machines machine ON machine.id=worker.machine_id
WHERE worker.id=? AND worker.machine_id=? AND machine.owner_id=?
  AND goal.owner_id=?`, workerID, nodeID, ownerID, ownerID).
		Scan(&goalID, &workerStatus, &goalStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", ErrNodeApprovalNotAuthorized
	}
	return goalID, workerStatus, goalStatus, err
}

func scanApprovalRecord(row interface{ Scan(...any) error }) (*Approval, error) {
	var approval Approval
	var request, decision, resolvedAt sql.NullString
	err := row.Scan(&approval.ID, &approval.GoalID, &approval.WorkerID, &approval.Method,
		&request, &approval.Status, &decision, &approval.CreatedAt, &resolvedAt,
		&approval.NodeID, &approval.Attempt, &approval.RequestID, &approval.RequestHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	approval.Request = json.RawMessage(request.String)
	approval.Decision, approval.ResolvedAt = decision.String, resolvedAt.String
	return &approval, nil
}

func validNodeApprovalMethod(method string) bool {
	switch method {
	case NodeApprovalCommandExecution, NodeApprovalFileChange:
		return true
	default:
		return false
	}
}

func isJSONRequestObject(request json.RawMessage) bool {
	var object map[string]json.RawMessage
	return json.Valid(request) && json.Unmarshal(request, &object) == nil && object != nil
}

func nodeApprovalRequestHash(method string, request json.RawMessage) string {
	digest := sha256.Sum256(append(append([]byte(method), 0), request...))
	return hex.EncodeToString(digest[:])
}

const remoteApprovalCurrentExists = `EXISTS (
  SELECT 1
  FROM workers worker
  JOIN goals goal ON goal.id=worker.goal_id
  JOIN machines machine ON machine.id=worker.machine_id
  JOIN fabric_node_credentials credential ON credential.node_id=approvals.source_node_id
    AND credential.status='active'
  JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
    AND binding.node_credential_digest=credential.credential_hash
    AND binding.node_credential_version=credential.version AND binding.state='ACTIVE'
  JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
  JOIN principals principal ON principal.id=binding.owner_id
    AND principal.kind='human' AND principal.status='active'
  JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
    AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
  WHERE worker.id=approvals.worker_id AND worker.machine_id=approvals.source_node_id
    AND worker.attempt=approvals.worker_attempt AND goal.id=approvals.goal_id
    AND goal.owner_id<>'' AND machine.owner_id=goal.owner_id
    AND binding.owner_id=goal.owner_id
)`

const remoteApprovalRunnableExists = `EXISTS (
  SELECT 1
  FROM workers worker
  JOIN goals goal ON goal.id=worker.goal_id
  JOIN machines machine ON machine.id=worker.machine_id
  JOIN fabric_node_credentials credential ON credential.node_id=approvals.source_node_id
    AND credential.status='active'
  JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
    AND binding.node_credential_digest=credential.credential_hash
    AND binding.node_credential_version=credential.version AND binding.state='ACTIVE'
  JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
  JOIN principals principal ON principal.id=binding.owner_id
    AND principal.kind='human' AND principal.status='active'
  JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
    AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
  WHERE worker.id=approvals.worker_id AND worker.machine_id=approvals.source_node_id
    AND worker.attempt=approvals.worker_attempt AND worker.status='running'
    AND goal.id=approvals.goal_id AND goal.status<>'paused'
    AND goal.owner_id<>'' AND machine.owner_id=goal.owner_id
    AND binding.owner_id=goal.owner_id
)`

func (s *Store) cancelRemoteApprovalsForWorkerAttemptTx(tx *sql.Tx, workerID, nodeID string, attempt int) error {
	_, err := tx.Exec(`UPDATE approvals SET status='cancelled', resolved_at=?
WHERE worker_id=? AND source_node_id=? AND worker_attempt=? AND status='pending'`,
		now(), workerID, nodeID, attempt)
	return err
}

func (s *Store) cancelRemoteApprovalsForOldAttemptsTx(tx *sql.Tx, workerID, nodeID string, attempt int) error {
	_, err := tx.Exec(`UPDATE approvals SET status='cancelled', resolved_at=?
WHERE worker_id=? AND source_node_id=? AND worker_attempt<>? AND status='pending'`,
		now(), workerID, nodeID, attempt)
	return err
}
