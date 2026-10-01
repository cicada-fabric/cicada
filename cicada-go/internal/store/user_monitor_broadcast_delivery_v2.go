package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	UserMonitorBroadcastV2NoticePending            = "PENDING"
	UserMonitorBroadcastV2NoticeNodeAccepted       = "NODE_ACCEPTED"
	UserMonitorBroadcastV2NoticeQueueAccepted      = "QUEUE_ACCEPTED"
	UserMonitorBroadcastV2NoticeInjectionUncertain = "INJECTION_UNCERTAIN"
	UserMonitorBroadcastV2NoticeFailed             = "FAILED"
	userMonitorBroadcastV2MaxNotices               = 16
)

// This is Node-only evidence for the exact signed Client enrollment and one
// approved operation. OwnerKeyID is an identifier, not trust material: the
// receiving Node must already trust that owner's public key independently.
type UserMonitorBroadcastV2Delivery struct {
	Context             e2ee.MonitorBroadcastContext `json:"context"`
	ClientPublic        e2ee.PublicIdentity          `json:"client_public"`
	OwnerKeyID          string                       `json:"owner_key_id"`
	OwnerDeviceGrant    []byte                       `json:"owner_device_grant"`
	EnrolledAt          string                       `json:"enrolled_at"`
	Snapshot            SameGroupBroadcastV2Snapshot `json:"snapshot"`
	SealedPayload       []byte                       `json:"sealed_payload"`
	SealedPayloadDigest string                       `json:"sealed_payload_digest"`
	SealedSequence      uint64                       `json:"sealed_sequence"`
	OperationID         string                       `json:"operation_id"`
}

// A notification is a bounded routing hint, never a command to broadcast.
// Its receipt reports Node persistence/native queue handling only.
type UserMonitorBroadcastV2Notification struct {
	HubID              string                      `json:"hub_id"`
	PreviewID          string                      `json:"preview_id"`
	BroadcastID        string                      `json:"broadcast_id"`
	GroupID            string                      `json:"group_id"`
	NativeContextScope *NativeContextScopeMetadata `json:"native_context_scope,omitempty"`
	MonitorEndpointID  string                      `json:"monitor_endpoint_id"`
	NodeID             string                      `json:"node_id"`
	NativeSessionID    string                      `json:"native_session_id"`
	BindingID          string                      `json:"binding_id"`
	BindingEpoch       uint64                      `json:"binding_epoch"`
	BodyDigest         string                      `json:"body_digest"`
	SnapshotDigest     string                      `json:"snapshot_digest"`
	ExpiresAt          string                      `json:"expires_at"`
	ReceiptState       string                      `json:"receipt_state"`
}

type UserMonitorBroadcastV2NotificationReceiptInput struct {
	NodeCredentialDigest string
	PreviewID            string
	BroadcastID          string
	SnapshotDigest       string
	BindingID            string
	BindingEpoch         uint64
	State                string
}

func (s *Store) initializeUserMonitorBroadcastV2DeliverySchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS client_device_enrollment_proofs_v2 (
 owner_id TEXT NOT NULL,
 device_id TEXT NOT NULL,
 owner_key_id TEXT NOT NULL,
 grant_bytes BLOB NOT NULL CHECK(length(grant_bytes)>0 AND length(grant_bytes)<=16384),
 grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64),
 enrolled_at TEXT NOT NULL,
 PRIMARY KEY(owner_id,device_id),
 FOREIGN KEY(owner_id,device_id) REFERENCES client_devices_v2(owner_id,device_id),
 FOREIGN KEY(owner_id,owner_key_id) REFERENCES owner_approval_keys_v2(owner_id,key_id)
);
CREATE TABLE IF NOT EXISTS user_monitor_broadcast_v2_notice_receipts (
 preview_id TEXT PRIMARY KEY REFERENCES user_monitor_broadcast_v2(preview_id),
 node_id TEXT NOT NULL,
 binding_id TEXT NOT NULL,
 binding_epoch INTEGER NOT NULL CHECK(binding_epoch>0),
 snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest)=64),
 receipt_state TEXT NOT NULL CHECK(receipt_state IN ('NODE_ACCEPTED','QUEUE_ACCEPTED','INJECTION_UNCERTAIN','FAILED')),
 first_reported_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
`)
	return err
}

type userMonitorEnrollmentProof struct {
	ownerKeyID string
	grant      []byte
	enrolledAt string
}

func readUserMonitorEnrollmentProofTx(tx *sql.Tx, req userMonitorClientRequest) (userMonitorEnrollmentProof, error) {
	var proof userMonitorEnrollmentProof
	var storedDigest, deviceCreatedAt, deviceOwnerKeyID string
	err := tx.QueryRow(`SELECT proof.owner_key_id,proof.grant_bytes,proof.grant_digest,proof.enrolled_at,
device.created_at,device.owner_key_id
FROM client_device_enrollment_proofs_v2 proof
JOIN client_devices_v2 device ON device.owner_id=proof.owner_id AND device.device_id=proof.device_id
WHERE proof.owner_id=? AND proof.device_id=?`, req.ownerID, req.deviceID).Scan(
		&proof.ownerKeyID, &proof.grant, &storedDigest, &proof.enrolledAt, &deviceCreatedAt, &deviceOwnerKeyID)
	if err != nil || proof.ownerKeyID != deviceOwnerKeyID || proof.enrolledAt != deviceCreatedAt ||
		len(proof.grant) == 0 || len(proof.grant) > 16384 {
		return proof, ErrUserMonitorBroadcastV2Denied
	}
	if userMonitorProofDigest(proof.grant) != storedDigest {
		return proof, ErrUserMonitorBroadcastV2Denied
	}
	ownerKey, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,
state,version,created_at,updated_at,revoked_at FROM owner_approval_keys_v2
WHERE owner_id=? AND key_id=?`, req.ownerID, proof.ownerKeyID))
	if err != nil || ownerKey.State != OwnerApprovalKeyActive {
		return proof, ErrUserMonitorBroadcastV2Denied
	}
	enrolledTime, err := time.Parse(time.RFC3339Nano, proof.enrolledAt)
	if err != nil {
		return proof, ErrUserMonitorBroadcastV2Denied
	}
	grant, err := e2ee.VerifyOwnerDeviceGrantAtRecordedEnrollment(proof.grant, ownerKey.Public, req.devicePublic,
		req.ownerID, proof.ownerKeyID, req.deviceID, req.hubID, e2ee.OwnerDevicePurposeControl, enrolledTime)
	if err != nil {
		return proof, ErrUserMonitorBroadcastV2Denied
	}
	var nonceDigest, nonceDeviceID string
	err = tx.QueryRow(`SELECT grant_digest,device_id FROM client_device_grant_nonces_v2
WHERE owner_id=? AND owner_key_id=? AND nonce=?`, req.ownerID, proof.ownerKeyID, grant.Nonce).
		Scan(&nonceDigest, &nonceDeviceID)
	if err != nil || nonceDigest != storedDigest || nonceDeviceID != req.deviceID {
		return proof, ErrUserMonitorBroadcastV2Denied
	}
	return proof, nil
}

// AuthorizeUserMonitorBroadcastV2Delivery checks current Client, owner, Group,
// Monitor session, Node, recipients and keys in the same transaction that
// reserves the only dispatch operation. No plaintext or owner public key is
// copied into the bundle.
func (s *Store) AuthorizeUserMonitorBroadcastV2Delivery(input AuthorizeUserMonitorBroadcastV2Input) (*UserMonitorBroadcastV2Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := authorizeUserMonitorBroadcastV2Tx(tx, input)
	if err != nil {
		return nil, err
	}
	delivery, err := userMonitorBroadcastV2DeliveryTx(tx, r, input.OperationID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return delivery, nil
}

// PreviewUserMonitorBroadcastV2Delivery returns the opaque sealed approval
// evidence for a trusted Node to present to its original live Monitor Session.
// It shares the current Guard with dispatch authorization but performs no
// status, receipt, replay, outcome, or relay-ledger writes.
func (s *Store) PreviewUserMonitorBroadcastV2Delivery(input PreviewUserMonitorBroadcastV2Input) (*UserMonitorBroadcastV2Delivery, error) {
	if !validNodeCredentialDigest(input.NodeCredentialDigest) ||
		!validNodeCredentialDigest(input.SessionCredentialDigest) || !validSameGroupSealedV1Token(input.PreviewID) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	guard, err := guardUserMonitorBroadcastV2Tx(tx, input.NodeCredentialDigest,
		input.SessionCredentialDigest, input.PreviewID, nil)
	if err != nil {
		return nil, err
	}
	delivery, err := userMonitorBroadcastV2DeliveryTx(tx, guard.record, guard.operationID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return delivery, nil
}

func userMonitorBroadcastV2DeliveryTx(tx *sql.Tx, r *UserMonitorBroadcastV2,
	operationID string) (*UserMonitorBroadcastV2Delivery, error) {
	req, err := readUserMonitorHistoricalConfirmRequestTx(tx, r)
	if err != nil {
		return nil, err
	}
	proof, err := readUserMonitorEnrollmentProofTx(tx, req)
	if err != nil {
		return nil, err
	}
	if r.Snapshot == nil || r.Snapshot.Source.KeyID != r.MonitorKeyID ||
		r.SealedPayloadDigest == "" || r.SealedSequence == 0 || len(r.SealedPayload) == 0 ||
		operationID != "op_"+strings.TrimPrefix(r.BroadcastID, "bc_") {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	payloadDigest := sha256.Sum256(r.SealedPayload)
	if hex.EncodeToString(payloadDigest[:]) != r.SealedPayloadDigest {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	// Recheck the signature against the exact original DB context even after
	// persistence; a changed payload or key must not reach a Node.
	context := userMonitorBroadcastContext(req, r)
	sequence, err := e2ee.VerifyMonitorBroadcast(r.SealedPayload, req.devicePublic,
		r.Snapshot.Source.PublicKey, context)
	if err != nil || sequence != r.SealedSequence {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	delivery := &UserMonitorBroadcastV2Delivery{Context: context, ClientPublic: req.devicePublic,
		OwnerKeyID: proof.ownerKeyID, OwnerDeviceGrant: append([]byte(nil), proof.grant...),
		EnrolledAt: proof.enrolledAt, Snapshot: *r.Snapshot,
		SealedPayload:       append([]byte(nil), r.SealedPayload...),
		SealedPayloadDigest: r.SealedPayloadDigest, SealedSequence: r.SealedSequence,
		OperationID: operationID}
	return delivery, nil
}

func userMonitorNotificationTx(tx *sql.Tx, nodeID, ownerID, previewID string,
	nowTime time.Time) (*UserMonitorBroadcastV2Notification, error) {
	r, err := readUserMonitorBroadcastTx(tx, previewID)
	if err != nil || (r.Status != UserMonitorBroadcastV2Approved && r.Status != UserMonitorBroadcastV2DispatchAuthorized) ||
		r.OwnerID != ownerID || userMonitorExpiry(r, nowTime) != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	req, err := readUserMonitorHistoricalConfirmRequestTx(tx, r)
	if err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	if _, err = readUserMonitorEnrollmentProofTx(tx, req); err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	if err = currentUserMonitorSnapshotTx(tx, r, nowTime); err != nil || r.Snapshot == nil ||
		r.Snapshot.Source.NodeID != nodeID {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	source := r.Snapshot.Source
	contextScope, err := readNativeContextScopeForEndpointTx(tx, source.EndpointID, r.GroupID)
	if err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	if r.Status == UserMonitorBroadcastV2DispatchAuthorized &&
		(r.consumeNodeID != nodeID || r.consumeBindingID != source.BindingID || r.consumeBindingEpoch != source.BindingEpoch) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	var state string
	err = tx.QueryRow(`SELECT receipt_state FROM user_monitor_broadcast_v2_notice_receipts WHERE preview_id=?`,
		r.PreviewID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		state = UserMonitorBroadcastV2NoticePending
	} else if err != nil {
		return nil, err
	}
	return &UserMonitorBroadcastV2Notification{HubID: req.hubID, PreviewID: r.PreviewID,
		BroadcastID: r.BroadcastID, GroupID: r.GroupID, NativeContextScope: &contextScope,
		MonitorEndpointID: r.MonitorEndpointID,
		NodeID:            nodeID, NativeSessionID: source.NativeSessionID, BindingID: source.BindingID,
		BindingEpoch: source.BindingEpoch, BodyDigest: r.BodyDigest,
		SnapshotDigest: r.SnapshotDigest, ExpiresAt: r.ExpiresAt, ReceiptState: state}, nil
}

// GetUserMonitorBroadcastV2Notification is an authenticated metadata-only
// current-Guard read used before native queue injection and later MCP review.
func (s *Store) GetUserMonitorBroadcastV2Notification(nodeCredentialDigest, previewID string) (*UserMonitorBroadcastV2Notification, error) {
	if !validNodeCredentialDigest(nodeCredentialDigest) || !validSameGroupSealedV1Token(previewID) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	nodeID, ownerID, _, _, err := readCurrentBoundNodeOwnerTx(tx, nodeCredentialDigest)
	if err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	return userMonitorNotificationTx(tx, nodeID, ownerID, previewID, time.Now().UTC())
}

// ListUserMonitorBroadcastV2Notifications is a bounded Node-only wake hint.
// It scans one page of the owner's active ledger, then filters foreign-Node
// rows and final receipts; an empty response can therefore mean that later
// work remains beyond this page. Callers must keep periodic reconciliation.
// The persisted cursor schedules future pages but is never an ACK or Guard.
func (s *Store) ListUserMonitorBroadcastV2Notifications(nodeCredentialDigest string, limit int) ([]UserMonitorBroadcastV2Notification, error) {
	if !validNodeCredentialDigest(nodeCredentialDigest) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	if limit <= 0 || limit > userMonitorBroadcastV2MaxNotices {
		limit = userMonitorBroadcastV2MaxNotices
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	nodeID, ownerID, _, _, err := readCurrentBoundNodeOwnerTx(tx, nodeCredentialDigest)
	if err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	nowTime := time.Now().UTC()
	cursor, hasCursor, err := readUserMonitorBroadcastV2NoticeCursorTx(tx, nodeID, ownerID)
	if err != nil {
		return nil, err
	}
	var cursorPointer *userMonitorBroadcastV2NoticeCursor
	if hasCursor {
		cursorPointer = &cursor
	}
	page, err := readUserMonitorBroadcastV2NoticeCandidatesTx(tx, ownerID,
		nowTime.Format(time.RFC3339Nano), cursorPointer, true, userMonitorBroadcastV2NoticeScanPage)
	if err != nil {
		return nil, err
	}
	if hasCursor && len(page) < userMonitorBroadcastV2NoticeScanPage {
		remaining := userMonitorBroadcastV2NoticeScanPage - len(page)
		wrapped, err := readUserMonitorBroadcastV2NoticeCandidatesTx(tx, ownerID,
			nowTime.Format(time.RFC3339Nano), cursorPointer, false, remaining)
		if err != nil {
			return nil, err
		}
		page = append(page, wrapped...)
	}
	result := make([]UserMonitorBroadcastV2Notification, 0, limit)
	var lastExamined *userMonitorBroadcastV2NoticeCandidate
	for i := range page {
		item := &page[i]
		lastExamined = item
		if item.sourceNodeID != nodeID || (item.receiptState != "" &&
			item.receiptState != UserMonitorBroadcastV2NoticeNodeAccepted) {
			continue
		}
		notice, err := userMonitorNotificationTx(tx, nodeID, ownerID, item.previewID, nowTime)
		if err == nil {
			result = append(result, *notice)
			if len(result) == limit {
				break
			}
		}
		if err != nil && !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
			return nil, err
		}
	}
	if lastExamined != nil {
		newCursor := userMonitorBroadcastV2NoticeCursor{ownerID: ownerID,
			expiryJulian: lastExamined.expiryJulian, previewID: lastExamined.previewID}
		if err := writeUserMonitorBroadcastV2NoticeCursorTx(tx, nodeID, ownerID, newCursor, nowTime); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// RecordUserMonitorBroadcastV2NotificationReceipt records only Node delivery
// evidence. It cannot authorize a broadcast or attest model consumption.
func (s *Store) RecordUserMonitorBroadcastV2NotificationReceipt(input UserMonitorBroadcastV2NotificationReceiptInput) (*UserMonitorBroadcastV2Notification, error) {
	if !validNodeCredentialDigest(input.NodeCredentialDigest) || !validSameGroupSealedV1Token(input.PreviewID) ||
		!validSameGroupSealedV1Token(input.BroadcastID) || !validSameGroupSealedV1Token(input.BindingID) ||
		!canonicalClientDigest(input.SnapshotDigest) || input.BindingEpoch == 0 ||
		(input.State != UserMonitorBroadcastV2NoticeNodeAccepted && input.State != UserMonitorBroadcastV2NoticeQueueAccepted && input.State != UserMonitorBroadcastV2NoticeInjectionUncertain && input.State != UserMonitorBroadcastV2NoticeFailed) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	nodeID, ownerID, _, _, err := readCurrentBoundNodeOwnerTx(tx, input.NodeCredentialDigest)
	if err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	r, err := readUserMonitorBroadcastTx(tx, input.PreviewID)
	if err != nil || r.OwnerID != ownerID || r.BroadcastID != input.BroadcastID ||
		r.SnapshotDigest != input.SnapshotDigest || r.Status == UserMonitorBroadcastV2Prepared {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	snapshot, err := readSameGroupBroadcastV2SnapshotTx(tx, r.BroadcastID)
	if err != nil || snapshot.Source.NodeID != nodeID || snapshot.Source.BindingID != input.BindingID ||
		snapshot.Source.BindingEpoch != input.BindingEpoch || snapshot.Source.EndpointID != r.MonitorEndpointID {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	// A receipt can report a historical queue outcome after approval expiry or
	// Client revocation, but an old native owner must never write through a new
	// SessionBinding epoch. This is a fencing check, not fresh broadcast consent.
	var currentBinding int
	err = tx.QueryRow(`SELECT 1 FROM fabric_endpoints endpoint
JOIN session_bindings binding ON binding.id=endpoint.binding_id AND binding.endpoint_id=endpoint.id
WHERE endpoint.id=? AND endpoint.principal_id=? AND endpoint.machine_id=?
 AND endpoint.native_session_id=? AND endpoint.binding_id=?
 AND endpoint.status!='left' AND binding.epoch=? AND binding.status='leased'
 AND binding.lease_owner!='' AND julianday(binding.lease_expires_at)>julianday(?)`,
		snapshot.Source.EndpointID, snapshot.Source.PrincipalID, nodeID,
		snapshot.Source.NativeSessionID, input.BindingID, input.BindingEpoch,
		time.Now().UTC().Format(time.RFC3339Nano)).Scan(&currentBinding)
	if err != nil || currentBinding != 1 {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	var existingState, existingNode, existingBinding, existingDigest string
	var existingEpoch int64
	err = tx.QueryRow(`SELECT receipt_state,node_id,binding_id,binding_epoch,snapshot_digest
FROM user_monitor_broadcast_v2_notice_receipts WHERE preview_id=?`, r.PreviewID).
		Scan(&existingState, &existingNode, &existingBinding, &existingEpoch, &existingDigest)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.Exec(`INSERT INTO user_monitor_broadcast_v2_notice_receipts
(preview_id,node_id,binding_id,binding_epoch,snapshot_digest,receipt_state,first_reported_at,updated_at)
VALUES(?,?,?,?,?,?,?,?)`, r.PreviewID, nodeID, input.BindingID, input.BindingEpoch,
			r.SnapshotDigest, input.State, stamp, stamp)
		if err != nil {
			return nil, err
		}
		existingState = input.State
	} else if err != nil {
		return nil, err
	} else {
		if existingNode != nodeID || existingBinding != input.BindingID ||
			uint64(existingEpoch) != input.BindingEpoch || existingDigest != input.SnapshotDigest {
			return nil, ErrUserMonitorBroadcastV2Conflict
		}
		if existingState == input.State || ((existingState == UserMonitorBroadcastV2NoticeQueueAccepted ||
			existingState == UserMonitorBroadcastV2NoticeInjectionUncertain || existingState == UserMonitorBroadcastV2NoticeFailed) &&
			input.State == UserMonitorBroadcastV2NoticeNodeAccepted) {
			// Exact or delayed lower-tier duplicate leaves terminal evidence intact.
		} else if existingState == UserMonitorBroadcastV2NoticeNodeAccepted {
			_, err = tx.Exec(`UPDATE user_monitor_broadcast_v2_notice_receipts
SET receipt_state=?,updated_at=? WHERE preview_id=? AND receipt_state='NODE_ACCEPTED'`,
				input.State, stamp, r.PreviewID)
			if err != nil {
				return nil, err
			}
			existingState = input.State
		} else {
			return nil, ErrUserMonitorBroadcastV2Conflict
		}
	}
	var hubID string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); err != nil {
		return nil, err
	}
	contextScope, err := readNativeContextScopeForEndpointTx(tx, snapshot.Source.EndpointID, r.GroupID)
	if err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &UserMonitorBroadcastV2Notification{HubID: hubID, PreviewID: r.PreviewID, BroadcastID: r.BroadcastID,
		GroupID: r.GroupID, NativeContextScope: &contextScope,
		MonitorEndpointID: r.MonitorEndpointID, NodeID: nodeID,
		NativeSessionID: snapshot.Source.NativeSessionID, BindingID: input.BindingID,
		BindingEpoch: input.BindingEpoch, BodyDigest: r.BodyDigest, SnapshotDigest: r.SnapshotDigest,
		ExpiresAt: r.ExpiresAt, ReceiptState: existingState}, nil
}

func userMonitorProofDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
