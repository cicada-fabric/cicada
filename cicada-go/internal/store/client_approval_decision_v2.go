package store

import (
	"database/sql"
	"errors"
	"strings"
)

var (
	ErrClientApprovalDecisionUnauthorized = errors.New("approval decision is not authorized for this Client request")
	ErrClientApprovalNotPending           = errors.New("approval is not pending")
	ErrClientApprovalUnavailable          = errors.New("approval is unavailable")
)

// ResolveApprovalForClientRequest commits a Client approval only while the
// exact accepted encrypted RPC, device epoch, Owner key and Goal ownership are
// current. The request and decision are checked under one Store transaction.
func (s *Store) ResolveApprovalForClientRequest(clientRequestID, authenticatedOwnerID,
	approvalID, decision string) (*Approval, error) {
	clientRequestID = strings.TrimSpace(clientRequestID)
	authenticatedOwnerID = strings.TrimSpace(authenticatedOwnerID)
	approvalID = strings.TrimSpace(approvalID)
	if clientRequestID == "" || authenticatedOwnerID == "" || approvalID == "" {
		return nil, ErrClientApprovalDecisionUnauthorized
	}
	switch decision {
	case "accept", "acceptForSession", "decline":
	default:
		return nil, errors.New("invalid approval decision")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Take the SQLite writer lock before reading mutable request or identity
	// state. A device/key revoke through another Store therefore serializes
	// either before this decision (and is observed here) or after its commit.
	if _, err := tx.Exec(`UPDATE client_device_requests_v2 SET updated_at=updated_at WHERE id=?`, clientRequestID); err != nil {
		return nil, err
	}
	actor, err := trustedClientRequestTx(tx, clientRequestID)
	if err != nil || actor.OwnerID != authenticatedOwnerID {
		return nil, ErrClientApprovalDecisionUnauthorized
	}
	var operation string
	if err := tx.QueryRow(`SELECT route_operation FROM client_device_requests_v2
WHERE id=? AND status='PROCESSING'`, clientRequestID).Scan(&operation); err != nil || operation != "approvals.decide" {
		return nil, ErrClientApprovalDecisionUnauthorized
	}

	var goalOwner, status string
	err = tx.QueryRow(`SELECT goal.owner_id, approval.status
FROM approvals approval JOIN goals goal ON goal.id=approval.goal_id
WHERE approval.id=?`, approvalID).Scan(&goalOwner, &status)
	if errors.Is(err, sql.ErrNoRows) || err == nil && goalOwner != authenticatedOwnerID {
		return nil, ErrClientApprovalUnavailable
	}
	if err != nil {
		return nil, err
	}
	if status != "pending" {
		return nil, ErrClientApprovalNotPending
	}

	var sourceNodeID string
	if err := tx.QueryRow(`SELECT source_node_id FROM approvals WHERE id=?`, approvalID).Scan(&sourceNodeID); err != nil {
		return nil, err
	}
	if sourceNodeID != "" {
		var runnable bool
		if err := tx.QueryRow(`SELECT `+remoteApprovalRunnableExists+` FROM approvals WHERE id=?`, approvalID).Scan(&runnable); err != nil {
			return nil, err
		}
		if !runnable {
			return nil, ErrNodeApprovalStale
		}
	}

	result, err := tx.Exec(`UPDATE approvals SET status='resolved', decision=?, resolved_at=?
	WHERE id=? AND status='pending'`, decision, now(), approvalID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, ErrClientApprovalNotPending
	}
	resolved, err := scanApprovalRecord(tx.QueryRow(`SELECT id, goal_id, worker_id, method, request_json,
status, decision, created_at, resolved_at, source_node_id, worker_attempt, request_id, request_hash
FROM approvals WHERE id=?`, approvalID))
	if err != nil || resolved == nil || resolved.Status != "resolved" || resolved.Decision != decision {
		if err != nil {
			return nil, err
		}
		return nil, ErrClientApprovalNotPending
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return resolved, nil
}
