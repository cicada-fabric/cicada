package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	UserMonitorBroadcastV2OutcomePending  = "PENDING"
	UserMonitorBroadcastV2OutcomeFailed   = "FAILED"
	UserMonitorBroadcastV2OutcomeUnknown  = "UNKNOWN"
	UserMonitorBroadcastV2OutcomeAccepted = "ACCEPTED"
	UserMonitorBroadcastV2EvidenceNode    = "NODE_REPORTED"
	UserMonitorBroadcastV2EvidenceRelay   = "RELAY_PERSISTED"
)

type UserMonitorBroadcastV2RecipientReport struct {
	Ordinal          int    `json:"ordinal"`
	EndpointID       string `json:"endpoint_id"`
	ChildOperationID string `json:"child_operation_id"`
	MessageID        string `json:"message_id"`
	State            string `json:"state"`
	Evidence         string `json:"evidence,omitempty"`
	FailureCode      string `json:"failure_code,omitempty"`
}

type UserMonitorBroadcastV2OutcomeReportInput struct {
	NodeCredentialDigest    string                                  `json:"-"`
	SessionCredentialDigest string                                  `json:"-"`
	PreviewID               string                                  `json:"preview_id"`
	BroadcastID             string                                  `json:"broadcast_id"`
	OperationID             string                                  `json:"operation_id"`
	SnapshotDigest          string                                  `json:"snapshot_digest"`
	Results                 []UserMonitorBroadcastV2RecipientReport `json:"results"`
}

type UserMonitorBroadcastV2RecipientOutcome struct {
	Ordinal     int    `json:"ordinal"`
	EndpointID  string `json:"endpoint_id"`
	State       string `json:"state"`
	Evidence    string `json:"evidence,omitempty"`
	MessageID   string `json:"message_id,omitempty"`
	FailureCode string `json:"failure_code,omitempty"`
	ReportedAt  string `json:"reported_at,omitempty"`
}

type UserMonitorBroadcastV2OutcomeStatus struct {
	PreviewID      string                                   `json:"preview_id"`
	BroadcastID    string                                   `json:"broadcast_id"`
	GroupID        string                                   `json:"group_id"`
	ApprovalStatus string                                   `json:"approval_status"`
	ExpiresAt      string                                   `json:"expires_at"`
	Recipients     []UserMonitorBroadcastV2RecipientOutcome `json:"recipients"`
}

func (s *Store) initializeUserMonitorBroadcastV2OutcomeSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS user_monitor_broadcast_v2_recipient_outcomes (
 preview_id TEXT NOT NULL REFERENCES user_monitor_broadcast_v2(preview_id),
 ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<32),
 endpoint_id TEXT NOT NULL,
 node_id TEXT NOT NULL,
 child_operation_id TEXT NOT NULL,
 expected_message_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('PENDING','FAILED','UNKNOWN','ACCEPTED')),
 evidence TEXT NOT NULL DEFAULT '' CHECK(evidence IN ('','NODE_REPORTED','RELAY_PERSISTED')),
 failure_code TEXT NOT NULL DEFAULT '' CHECK(failure_code IN ('','DELIVERY_REJECTED','DELIVERY_OUTCOME_UNKNOWN')),
 reported_at TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(preview_id,ordinal),
 UNIQUE(preview_id,endpoint_id),
 UNIQUE(preview_id,child_operation_id)
);`)
	if err != nil {
		return err
	}
	// v32 could have reserved a dispatch just before upgrade. Its outcome is
	// unknown, so populate only immutable PENDING slots from its old snapshot.
	// Page through old approvals to bound migration memory.
	lastID := ""
	for {
		rows, err := s.db.Query(`SELECT preview_id,broadcast_id FROM user_monitor_broadcast_v2
WHERE status='DISPATCH_AUTHORIZED' AND preview_id>? ORDER BY preview_id LIMIT 64`, lastID)
		if err != nil {
			return err
		}
		type candidate struct{ previewID, broadcastID string }
		page := make([]candidate, 0, 64)
		for rows.Next() {
			var c candidate
			if err := rows.Scan(&c.previewID, &c.broadcastID); err != nil {
				rows.Close()
				return err
			}
			page = append(page, c)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, c := range page {
			if err := backfillUserMonitorBroadcastOutcomes(s.db, c.previewID, c.broadcastID); err != nil {
				return err
			}
		}
		if len(page) < 64 {
			return nil
		}
		lastID = page[len(page)-1].previewID
	}
}

func backfillUserMonitorBroadcastOutcomes(db *sql.DB, previewID, broadcastID string) error {
	var expectedCount int
	if err := db.QueryRow(`SELECT recipient_count FROM group_broadcast_v2_snapshots WHERE broadcast_id=?`,
		broadcastID).Scan(&expectedCount); err != nil {
		return err
	}
	if expectedCount < 0 || expectedCount > SameGroupBroadcastV2MaxRecipients {
		return ErrUserMonitorBroadcastV2Conflict
	}
	rows, err := db.Query(`SELECT ordinal,endpoint_id,node_id FROM group_broadcast_v2_snapshot_recipients
WHERE broadcast_id=? ORDER BY ordinal LIMIT 33`, broadcastID)
	if err != nil {
		return err
	}
	type recipient struct {
		ordinal            int
		endpointID, nodeID string
	}
	recipients := make([]recipient, 0, expectedCount)
	for rows.Next() {
		var r recipient
		if err := rows.Scan(&r.ordinal, &r.endpointID, &r.nodeID); err != nil {
			rows.Close()
			return err
		}
		recipients = append(recipients, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(recipients) != expectedCount {
		return ErrUserMonitorBroadcastV2Conflict
	}
	for ordinal, r := range recipients {
		if r.ordinal != ordinal {
			return ErrUserMonitorBroadcastV2Conflict
		}
		childID, messageID, err := UserMonitorBroadcastV2ChildIDs(broadcastID, r.endpointID)
		if err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT INTO user_monitor_broadcast_v2_recipient_outcomes
(preview_id,ordinal,endpoint_id,node_id,child_operation_id,expected_message_id,state)
VALUES(?,?,?,?,?,?,'PENDING') ON CONFLICT(preview_id,ordinal) DO NOTHING`, previewID, ordinal, r.endpointID, r.nodeID, childID, messageID); err != nil {
			return err
		}
		var storedEndpoint, storedNode, storedChild, storedMessage string
		if err := db.QueryRow(`SELECT endpoint_id,node_id,child_operation_id,expected_message_id
FROM user_monitor_broadcast_v2_recipient_outcomes WHERE preview_id=? AND ordinal=?`, previewID, ordinal).
			Scan(&storedEndpoint, &storedNode, &storedChild, &storedMessage); err != nil ||
			storedEndpoint != r.endpointID || storedNode != r.nodeID || storedChild != childID || storedMessage != messageID {
			return ErrUserMonitorBroadcastV2Conflict
		}
	}
	return nil
}

// UserMonitorBroadcastV2ChildIDs matches the Node's fixed child ID domain.
// It never accepts an arbitrary caller-selected operation or message ID.
func UserMonitorBroadcastV2ChildIDs(broadcastID, endpointID string) (string, string, error) {
	if len(broadcastID) != 35 || !strings.HasPrefix(broadcastID, "bc_") ||
		!validSameGroupSealedV1Token(endpointID) {
		return "", "", ErrUserMonitorBroadcastV2Denied
	}
	decoded, err := hex.DecodeString(broadcastID[3:])
	if err != nil || len(decoded) != 16 || strings.ToLower(broadcastID[3:]) != broadcastID[3:] {
		return "", "", ErrUserMonitorBroadcastV2Denied
	}
	hash := sha256.Sum256([]byte("cicada/group-broadcast-child/v1\x00" + broadcastID + "\x00" + endpointID))
	suffix := hex.EncodeToString(hash[:16])
	return "op_" + suffix, "msg_" + suffix, nil
}

func seedUserMonitorBroadcastOutcomesTx(tx *sql.Tx, r *UserMonitorBroadcastV2) error {
	if r == nil || r.Snapshot == nil || r.Status != UserMonitorBroadcastV2DispatchAuthorized ||
		len(r.Snapshot.Recipients) > SameGroupBroadcastV2MaxRecipients {
		return ErrUserMonitorBroadcastV2Denied
	}
	for ordinal, recipient := range r.Snapshot.Recipients {
		childID, messageID, err := UserMonitorBroadcastV2ChildIDs(r.BroadcastID, recipient.EndpointID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT OR IGNORE INTO user_monitor_broadcast_v2_recipient_outcomes
(preview_id,ordinal,endpoint_id,node_id,child_operation_id,expected_message_id,state)
VALUES(?,?,?,?,?,?,'PENDING')`, r.PreviewID, ordinal, recipient.EndpointID, recipient.NodeID, childID, messageID)
		if err != nil {
			return err
		}
		var storedEndpoint, storedNode, storedChild, storedMessage string
		if err := tx.QueryRow(`SELECT endpoint_id,node_id,child_operation_id,expected_message_id
FROM user_monitor_broadcast_v2_recipient_outcomes WHERE preview_id=? AND ordinal=?`, r.PreviewID, ordinal).
			Scan(&storedEndpoint, &storedNode, &storedChild, &storedMessage); err != nil ||
			storedEndpoint != recipient.EndpointID || storedNode != recipient.NodeID ||
			storedChild != childID || storedMessage != messageID {
			return ErrUserMonitorBroadcastV2Conflict
		}
	}
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM user_monitor_broadcast_v2_recipient_outcomes WHERE preview_id=?`, r.PreviewID).Scan(&count); err != nil {
		return err
	}
	if count != len(r.Snapshot.Recipients) {
		return ErrUserMonitorBroadcastV2Conflict
	}
	return nil
}

func userMonitorReportRank(state string) int {
	switch state {
	case UserMonitorBroadcastV2OutcomePending:
		return 0
	case UserMonitorBroadcastV2OutcomeFailed:
		return 1
	case UserMonitorBroadcastV2OutcomeUnknown:
		return 2
	case UserMonitorBroadcastV2OutcomeAccepted:
		return 3
	}
	return -1
}

// ReportUserMonitorBroadcastV2RecipientOutcomes records historical facts about
// one already-reserved dispatch. Expiry and Client revocation do not erase a
// report, but the original Node and live Fabric SessionBinding must still own
// the same epoch. This method cannot authorize or retry a child send.
func (s *Store) ReportUserMonitorBroadcastV2RecipientOutcomes(input UserMonitorBroadcastV2OutcomeReportInput) ([]UserMonitorBroadcastV2RecipientOutcome, error) {
	// Concurrent Store handles may race while upgrading a deferred SQLite read
	// transaction to a writer. Retry only that lock failure, after rollback and
	// releasing the handle mutex; this transaction has no external side effects.
	for attempt := 0; ; attempt++ {
		outcomes, err := s.reportUserMonitorBroadcastV2RecipientOutcomes(input)
		if err == nil || !isSQLiteBusy(err) || attempt == 3 {
			return outcomes, err
		}
		time.Sleep(time.Duration(1<<attempt) * 10 * time.Millisecond)
	}
}

func (s *Store) reportUserMonitorBroadcastV2RecipientOutcomes(input UserMonitorBroadcastV2OutcomeReportInput) ([]UserMonitorBroadcastV2RecipientOutcome, error) {
	if !validNodeCredentialDigest(input.NodeCredentialDigest) || !validNodeCredentialDigest(input.SessionCredentialDigest) ||
		!validSameGroupSealedV1Token(input.PreviewID) || !validSameGroupSealedV1Token(input.BroadcastID) ||
		!validSameGroupSealedV1Token(input.OperationID) || !canonicalClientDigest(input.SnapshotDigest) ||
		len(input.Results) == 0 || len(input.Results) > 8 {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := readUserMonitorBroadcastTx(tx, input.PreviewID)
	if err != nil || r.Status != UserMonitorBroadcastV2DispatchAuthorized ||
		r.BroadcastID != input.BroadcastID || r.OperationID != input.OperationID ||
		r.SnapshotDigest != input.SnapshotDigest {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	nodeID, ownerID, _, _, err := readCurrentBoundNodeOwnerTx(tx, input.NodeCredentialDigest)
	if err != nil || nodeID != r.consumeNodeID || ownerID != r.OwnerID {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	snapshot, err := readSameGroupBroadcastV2SnapshotTx(tx, r.BroadcastID)
	if err != nil || snapshot.SnapshotDigest != r.SnapshotDigest || snapshot.Source.NodeID != nodeID ||
		snapshot.Source.BindingID != r.consumeBindingID || snapshot.Source.BindingEpoch != r.consumeBindingEpoch {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	// Keep this historical-report fence narrower than live broadcast Guard: a
	// removed recipient or expired Client approval must not erase a factual send.
	var currentBinding int
	err = tx.QueryRow(`SELECT 1 FROM session_bindings binding
JOIN fabric_endpoints endpoint ON endpoint.binding_id=binding.id AND endpoint.id=binding.endpoint_id
WHERE binding.id=? AND binding.epoch=? AND binding.credential_hash=?
 AND binding.status='leased' AND binding.lease_owner!=''
 AND julianday(binding.lease_expires_at)>julianday(?)
 AND binding.node_id=? AND binding.native_session_id=?
 AND endpoint.machine_id=? AND endpoint.native_session_id=?
 AND endpoint.principal_id=? AND endpoint.status!='left'`, r.consumeBindingID,
		r.consumeBindingEpoch, input.SessionCredentialDigest, time.Now().UTC().Format(time.RFC3339Nano),
		nodeID, snapshot.Source.NativeSessionID, nodeID, snapshot.Source.NativeSessionID,
		snapshot.Source.PrincipalID).Scan(&currentBinding)
	if err != nil || currentBinding != 1 {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	r.Snapshot = snapshot
	if err := seedUserMonitorBroadcastOutcomesTx(tx, r); err != nil {
		return nil, err
	}
	seen := make(map[int]struct{}, len(input.Results))
	for _, result := range input.Results {
		if result.Ordinal < 0 || result.Ordinal >= len(snapshot.Recipients) {
			return nil, ErrUserMonitorBroadcastV2Denied
		}
		if _, ok := seen[result.Ordinal]; ok {
			return nil, ErrUserMonitorBroadcastV2Conflict
		}
		seen[result.Ordinal] = struct{}{}
		recipient := snapshot.Recipients[result.Ordinal]
		childID, messageID, err := UserMonitorBroadcastV2ChildIDs(r.BroadcastID, recipient.EndpointID)
		if err != nil || result.EndpointID != recipient.EndpointID ||
			result.ChildOperationID != childID || result.MessageID != messageID ||
			userMonitorReportRank(result.State) <= 0 {
			return nil, ErrUserMonitorBroadcastV2Denied
		}
		if result.State == UserMonitorBroadcastV2OutcomeAccepted {
			if result.FailureCode != "" ||
				(result.Evidence != UserMonitorBroadcastV2EvidenceNode && result.Evidence != UserMonitorBroadcastV2EvidenceRelay) {
				return nil, ErrUserMonitorBroadcastV2Denied
			}
			if recipient.NodeID == nodeID && result.Evidence != UserMonitorBroadcastV2EvidenceNode ||
				recipient.NodeID != nodeID && result.Evidence != UserMonitorBroadcastV2EvidenceRelay {
				return nil, ErrUserMonitorBroadcastV2Denied
			}
			if result.Evidence == UserMonitorBroadcastV2EvidenceRelay &&
				!userMonitorRelayChildPersistedTx(tx, r, recipient, childID, messageID) {
				return nil, ErrUserMonitorBroadcastV2Denied
			}
		} else if result.Evidence != "" ||
			(result.State == UserMonitorBroadcastV2OutcomeFailed && result.FailureCode != "DELIVERY_REJECTED") ||
			(result.State == UserMonitorBroadcastV2OutcomeUnknown && result.FailureCode != "DELIVERY_OUTCOME_UNKNOWN") {
			return nil, ErrUserMonitorBroadcastV2Denied
		}
		var previousState, previousEvidence, previousFailure string
		err = tx.QueryRow(`SELECT state,evidence,failure_code FROM user_monitor_broadcast_v2_recipient_outcomes
WHERE preview_id=? AND ordinal=? AND endpoint_id=? AND child_operation_id=? AND expected_message_id=?`,
			r.PreviewID, result.Ordinal, recipient.EndpointID, childID, messageID).
			Scan(&previousState, &previousEvidence, &previousFailure)
		if err != nil {
			return nil, ErrUserMonitorBroadcastV2Denied
		}
		if userMonitorReportRank(result.State) > userMonitorReportRank(previousState) {
			_, err = tx.Exec(`UPDATE user_monitor_broadcast_v2_recipient_outcomes
SET state=?,evidence=?,failure_code=?,reported_at=? WHERE preview_id=? AND ordinal=? AND state=?`,
				result.State, result.Evidence, result.FailureCode, time.Now().UTC().Format(time.RFC3339Nano),
				r.PreviewID, result.Ordinal, previousState)
			if err != nil {
				return nil, err
			}
		} else if userMonitorReportRank(result.State) == userMonitorReportRank(previousState) &&
			(previousEvidence != result.Evidence || previousFailure != result.FailureCode) {
			return nil, ErrUserMonitorBroadcastV2Conflict
		}
	}
	out, err := readUserMonitorOutcomesTx(tx, r.PreviewID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func userMonitorRelayChildPersistedTx(tx *sql.Tx, r *UserMonitorBroadcastV2,
	recipient SameGroupBroadcastV2Endpoint, childID, messageID string) bool {
	var found int
	err := tx.QueryRow(`SELECT 1 FROM relay_v2_message_security security
JOIN relay_v2_message_payloads payload ON payload.message_id=security.message_id AND payload.payload_mode='SEALED_V1'
JOIN relay_v2_outbox outbox ON outbox.message_id=security.message_id
WHERE security.message_id=? AND security.idempotency_key=?
 AND security.sender_endpoint_id=? AND security.sender_principal_id=? AND security.sender_group_id=?
 AND security.sender_binding_id=? AND security.sender_binding_epoch=?
 AND security.receiver_endpoint_id=? AND security.receiver_principal_id=? AND security.receiver_group_id=?
 AND security.receiver_binding_id=? AND security.receiver_binding_epoch=?
 AND outbox.recipient_endpoint_id=?`, messageID, childID,
		r.Snapshot.Source.EndpointID, r.Snapshot.Source.PrincipalID, r.GroupID,
		r.Snapshot.Source.BindingID, r.Snapshot.Source.BindingEpoch,
		recipient.EndpointID, recipient.PrincipalID, r.GroupID,
		recipient.BindingID, recipient.BindingEpoch, recipient.EndpointID).Scan(&found)
	return err == nil && found == 1
}

func readUserMonitorOutcomesTx(tx *sql.Tx, previewID string) ([]UserMonitorBroadcastV2RecipientOutcome, error) {
	rows, err := tx.Query(`SELECT ordinal,endpoint_id,state,evidence,expected_message_id,failure_code,reported_at
FROM user_monitor_broadcast_v2_recipient_outcomes WHERE preview_id=? ORDER BY ordinal LIMIT 33`, previewID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]UserMonitorBroadcastV2RecipientOutcome, 0, SameGroupBroadcastV2MaxRecipients)
	for rows.Next() {
		var v UserMonitorBroadcastV2RecipientOutcome
		if err := rows.Scan(&v.Ordinal, &v.EndpointID, &v.State, &v.Evidence, &v.MessageID, &v.FailureCode, &v.ReportedAt); err != nil {
			return nil, err
		}
		if v.State != UserMonitorBroadcastV2OutcomeAccepted {
			v.MessageID = ""
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > SameGroupBroadcastV2MaxRecipients {
		return nil, ErrUserMonitorBroadcastV2Conflict
	}
	return out, nil
}

// GetUserMonitorBroadcastV2OutcomeStatus reveals only delivery outcomes to an
// authenticated request from the original currently active Client device.
func (s *Store) GetUserMonitorBroadcastV2OutcomeStatus(clientRequestID, previewID string) (*UserMonitorBroadcastV2OutcomeStatus, error) {
	if !validateClientDeviceToken(clientRequestID) || !validSameGroupSealedV1Token(previewID) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	req, err := readUserMonitorClientRequestTx(tx, clientRequestID)
	if err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	r, err := readUserMonitorBroadcastTx(tx, previewID)
	if err != nil || r.OwnerID != req.ownerID || r.DeviceID != req.deviceID ||
		r.SessionEpoch != req.epoch || r.ClientKeyVersion != req.keyVersion {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	outcomes, err := readUserMonitorOutcomesTx(tx, previewID)
	if err != nil {
		return nil, err
	}
	if r.Status == UserMonitorBroadcastV2DispatchAuthorized {
		var expectedCount int
		if err := tx.QueryRow(`SELECT recipient_count FROM group_broadcast_v2_snapshots WHERE broadcast_id=?`, r.BroadcastID).
			Scan(&expectedCount); err != nil || expectedCount != len(outcomes) {
			return nil, fmt.Errorf("missing dispatched Monitor recipient outcomes: %w", ErrUserMonitorBroadcastV2Conflict)
		}
	}
	return &UserMonitorBroadcastV2OutcomeStatus{PreviewID: r.PreviewID, BroadcastID: r.BroadcastID,
		GroupID: r.GroupID, ApprovalStatus: r.Status, ExpiresAt: r.ExpiresAt, Recipients: outcomes}, nil
}
