package store

import (
	"database/sql"
	"errors"
	"os"
	"strings"
)

// CheckBoundNodeWorkerWorkspaceSnapshot verifies the live Node, owner, Worker
// attempt and exact Workspace relation before the caller spends time ingesting
// an archive. Attachment repeats every condition transactionally after CAS
// ingestion; this preflight is only an early rejection and does not grant a
// durable capability.
func (s *Store) CheckBoundNodeWorkerWorkspaceSnapshot(credentialDigest, nodeID, workerID string, attempt int, workspaceID string) (string, error) {
	if attempt <= 0 || strings.TrimSpace(workspaceID) == "" {
		return "", ErrNodeWorkerNotAuthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := currentBoundNodeOwnerTx(tx, credentialDigest, nodeID); err != nil {
		return "", ErrNodeWorkerNotAuthorized
	}
	var currentDigest sql.NullString
	err = tx.QueryRow(`SELECT workspace.snapshot_digest FROM workers worker
JOIN goals goal ON goal.id=worker.goal_id
JOIN machines machine ON machine.id=worker.machine_id
JOIN workspaces workspace ON workspace.goal_id=goal.id AND workspace.path=worker.workspace
WHERE worker.id=? AND worker.machine_id=? AND worker.attempt=? AND worker.status='running'
  AND machine.owner_id=goal.owner_id
  AND workspace.id=? AND workspace.status='active'
  AND `+nodeWorkerAuthorizationExists,
		workerID, nodeID, attempt, workspaceID, credentialDigest, nodeID).Scan(&currentDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return "", classifyBoundNodeWorkerTx(tx, credentialDigest, nodeID, workerID)
	}
	if err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return currentDigest.String, nil
}

// AttachBoundNodeWorkerWorkspaceSnapshot publishes a previously ingested CAS
// object only if the same Node credential and owner binding still authorize
// the running Worker attempt and exact Workspace. The UPDATE is the final
// authorization check, so revocation or an attempt transition during upload
// cannot attach the object.
func (s *Store) AttachBoundNodeWorkerWorkspaceSnapshot(credentialDigest, nodeID, workerID string, attempt int, workspaceID, expectedCurrentDigest, digest string) (*Workspace, error) {
	if attempt <= 0 || strings.TrimSpace(workspaceID) == "" || !validSHA256Digest(strings.TrimSpace(digest)) || strings.ToLower(strings.TrimSpace(digest)) != strings.TrimSpace(digest) {
		return nil, ErrNodeWorkerNotAuthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := currentBoundNodeOwnerTx(tx, credentialDigest, nodeID); err != nil {
		return nil, ErrNodeWorkerNotAuthorized
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
)`, digest, now(), workspaceID, expectedCurrentDigest, digest, workerID, nodeID, attempt, credentialDigest, nodeID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, classifyBoundNodeWorkerTx(tx, credentialDigest, nodeID, workerID)
	}
	workspace, err := scanNodeWorkspaceSnapshot(tx.QueryRow(`SELECT id, goal_id, path, source, revision,
snapshot_digest, status, created_at, updated_at FROM workspaces WHERE id=?`, workspaceID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return workspace, nil
}

// GetBoundNodeWorkerWorkspaceSnapshot authorizes one current download. The
// caller supplies the advertised digest, which must match the exact active
// Workspace's current pointer under the same running Worker attempt.
func (s *Store) GetBoundNodeWorkerWorkspaceSnapshot(credentialDigest, nodeID, workerID string, attempt int, workspaceID, digest string) (*Workspace, error) {
	if attempt <= 0 || strings.TrimSpace(workspaceID) == "" || strings.TrimSpace(digest) == "" {
		return nil, ErrNodeWorkerNotAuthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := currentBoundNodeOwnerTx(tx, credentialDigest, nodeID); err != nil {
		return nil, ErrNodeWorkerNotAuthorized
	}
	workspace, err := scanNodeWorkspaceSnapshot(tx.QueryRow(`SELECT workspace.id, workspace.goal_id, workspace.path,
workspace.source, workspace.revision, workspace.snapshot_digest, workspace.status,
workspace.created_at, workspace.updated_at
FROM workspaces workspace
JOIN goals goal ON goal.id=workspace.goal_id
JOIN workers worker ON worker.goal_id=goal.id AND worker.workspace=workspace.path
JOIN machines machine ON machine.id=worker.machine_id
WHERE workspace.id=? AND workspace.status='active' AND workspace.snapshot_digest=?
  AND worker.id=? AND worker.machine_id=? AND worker.attempt=? AND worker.status='running'
  AND machine.owner_id=goal.owner_id AND `+nodeWorkerAuthorizationExists,
		workspaceID, digest, workerID, nodeID, attempt, credentialDigest, nodeID))
	if errors.Is(err, sql.ErrNoRows) {
		var currentDigest string
		currentErr := tx.QueryRow(`SELECT workspace.snapshot_digest
FROM workspaces workspace
JOIN goals goal ON goal.id=workspace.goal_id
JOIN workers worker ON worker.goal_id=goal.id AND worker.workspace=workspace.path
JOIN machines machine ON machine.id=worker.machine_id
WHERE workspace.id=? AND workspace.status='active'
  AND worker.id=? AND worker.machine_id=? AND worker.attempt=? AND worker.status='running'
  AND machine.owner_id=goal.owner_id AND `+nodeWorkerAuthorizationExists,
			workspaceID, workerID, nodeID, attempt, credentialDigest, nodeID).Scan(&currentDigest)
		if errors.Is(currentErr, sql.ErrNoRows) {
			return nil, classifyBoundNodeWorkerTx(tx, credentialDigest, nodeID, workerID)
		}
		if currentErr != nil {
			return nil, currentErr
		}
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return workspace, nil
}

func scanNodeWorkspaceSnapshot(row interface{ Scan(...any) error }) (*Workspace, error) {
	var workspace Workspace
	var goalID, source, revision, digest sql.NullString
	err := row.Scan(&workspace.ID, &goalID, &workspace.Path, &source, &revision,
		&digest, &workspace.Status, &workspace.CreatedAt, &workspace.UpdatedAt)
	if err != nil {
		return nil, err
	}
	workspace.GoalID, workspace.Source, workspace.Revision, workspace.SnapshotDigest =
		goalID.String, source.String, revision.String, digest.String
	return &workspace, nil
}
