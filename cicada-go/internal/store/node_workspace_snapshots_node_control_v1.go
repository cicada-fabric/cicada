package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// CheckBoundNodeWorkerWorkspaceSnapshotNodeControl rechecks the live approved
// key epoch and the exact running Worker/Workspace relation. Set
// requireProcessing for streamed upload chunks; download chunks only require
// the still-current binding because the small authenticated manifest response
// has already completed in the replay ledger.
func (s *Store) CheckBoundNodeWorkerWorkspaceSnapshotNodeControl(input NodeControlRPCInput,
	workerID string, attempt int, workspaceID string, requireProcessing bool) (string, error) {
	if input.NodeID == "" || input.CredentialDigest == "" || workerID == "" || attempt <= 0 ||
		strings.TrimSpace(workspaceID) == "" ||
		(input.Operation != "node.workspace.snapshot.upload" && input.Operation != "node.workspace.snapshot.download") {
		return "", ErrNodeWorkerNotAuthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if requireProcessing {
		if err := verifyNodeControlRPCProcessingTx(tx, input); err != nil {
			return "", err
		}
	} else if err := verifyNodeControlBindingTx(tx, input); err != nil {
		return "", err
	}
	var digest sql.NullString
	err = tx.QueryRow(`SELECT workspace.snapshot_digest
FROM workers worker
JOIN goals goal ON goal.id=worker.goal_id
JOIN machines machine ON machine.id=worker.machine_id
JOIN workspaces workspace ON workspace.goal_id=goal.id AND workspace.path=worker.workspace
WHERE worker.id=? AND worker.machine_id=? AND worker.attempt=? AND worker.status='running'
  AND machine.owner_id=goal.owner_id AND workspace.id=? AND workspace.status='active'
  AND `+nodeWorkerAuthorizationExists,
		workerID, input.NodeID, attempt, workspaceID, input.CredentialDigest, input.NodeID).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		return "", classifyBoundNodeWorkerTx(tx, input.CredentialDigest, input.NodeID, workerID)
	}
	if err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return digest.String, nil
}

// AttachBoundNodeWorkerWorkspaceSnapshotNodeControl changes the Workspace CAS
// pointer and caches the signed Node-Control reply in the same SQLite
// transaction. A lost reply can therefore replay the exact encrypted request
// and receive the exact cached packet without reattaching under a new epoch.
func (s *Store) AttachBoundNodeWorkerWorkspaceSnapshotNodeControl(input NodeControlRPCInput,
	workerID string, attempt int, workspaceID, expectedCurrentDigest, digest string,
	responsePacket []byte) (*Workspace, error) {
	if input.Operation != "node.workspace.snapshot.upload" || attempt <= 0 || workerID == "" ||
		strings.TrimSpace(workspaceID) == "" || !validSHA256Digest(strings.TrimSpace(digest)) ||
		strings.ToLower(strings.TrimSpace(digest)) != strings.TrimSpace(digest) ||
		len(responsePacket) == 0 || len(responsePacket) > nodeControlMaxPacketBytes {
		return nil, ErrNodeWorkerNotAuthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := verifyNodeControlRPCProcessingTx(tx, input); err != nil {
		return nil, err
	}
	result, err := tx.Exec(`UPDATE workspaces AS workspace SET snapshot_digest=?, updated_at=?
WHERE workspace.id=? AND workspace.status='active'
  AND (workspace.snapshot_digest=? OR workspace.snapshot_digest=?) AND EXISTS (
  SELECT 1 FROM workers worker
  JOIN goals goal ON goal.id=worker.goal_id
  JOIN machines machine ON machine.id=worker.machine_id
  WHERE worker.id=? AND worker.machine_id=? AND worker.attempt=? AND worker.status='running'
    AND machine.owner_id=goal.owner_id
    AND workspace.goal_id=goal.id AND workspace.path=worker.workspace
    AND `+nodeWorkerAuthorizationExists+`
)`, digest, now(), workspaceID, expectedCurrentDigest, digest,
		workerID, input.NodeID, attempt, input.CredentialDigest, input.NodeID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, classifyBoundNodeWorkerTx(tx, input.CredentialDigest, input.NodeID, workerID)
	}
	workspace, err := scanNodeWorkspaceSnapshot(tx.QueryRow(`SELECT id, goal_id, path, source, revision,
snapshot_digest, status, created_at, updated_at FROM workspaces WHERE id=?`, workspaceID))
	if err != nil {
		return nil, err
	}
	if err := completeNodeControlRPCInTransaction(tx, input, responsePacket); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return workspace, nil
}

func completeNodeControlRPCInTransaction(tx *sql.Tx, input NodeControlRPCInput, responsePacket []byte) error {
	if len(responsePacket) == 0 || len(responsePacket) > nodeControlMaxPacketBytes ||
		!validSHA256Digest(input.RequestDigest) || !validateNodeControlOperation(input.Operation) {
		return ErrNodeControlRPCConflict
	}
	if err := verifyNodeControlBindingTx(tx, input); err != nil {
		return err
	}
	var operation, digest, state string
	var existingPacket []byte
	err := tx.QueryRow(`SELECT operation,request_digest,state,response_packet FROM node_control_rpc_inbox_v1
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=?`,
		input.BindingID, input.NodeKeyEpoch, input.Sequence, input.OperationID).
		Scan(&operation, &digest, &state, &existingPacket)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeControlRPCConflict
	}
	if err != nil {
		return err
	}
	if operation != input.Operation || digest != input.RequestDigest {
		return ErrNodeControlRPCConflict
	}
	if state == NodeControlRPCComplete {
		if string(existingPacket) != string(responsePacket) {
			return ErrNodeControlRPCConflict
		}
		return nil
	}
	if state != NodeControlRPCProcessing {
		return ErrNodeControlRPCUncertain
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	updated, err := tx.Exec(`UPDATE node_control_rpc_inbox_v1 SET state='COMPLETE',response_packet=?,updated_at=?
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=?
  AND operation=? AND request_digest=? AND state='PROCESSING'`, responsePacket, stamp,
		input.BindingID, input.NodeKeyEpoch, input.Sequence, input.OperationID,
		input.Operation, input.RequestDigest)
	if err != nil {
		return err
	}
	changed, err := updated.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrNodeControlRPCConflict
	}
	return pruneNodeControlRPCResponsesTx(tx, time.Now().UTC())
}
