package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

var ErrRelayNativeWakeAuthorizationUnavailable = errors.New("current native wake authorization unavailable")

type RelayNativeWakeAuthorizationInput struct {
	MessageID string
	AttemptID string
}

// RelayNativeWakeAuthorization contains only the current route coordinates
// needed by a Node to revalidate a native wake. It never returns message data,
// session credentials, or keys.
type RelayNativeWakeAuthorization struct {
	NodeID             string `json:"node_id"`
	MessageID          string `json:"message_id"`
	AttemptID          string `json:"attempt_id"`
	Digest             string `json:"digest"`
	EndpointID         string `json:"endpoint_id"`
	Harness            string `json:"harness"`
	BindingID          string `json:"binding_id"`
	BindingEpoch       uint64 `json:"binding_epoch"`
	NativeSessionID    string `json:"native_session_id"`
	LeaseOwner         string `json:"lease_owner"`
	LeaseExpiresAt     string `json:"lease_expires_at"`
	GroupID            string `json:"group_id"`
	GroupJoinRevision  int64  `json:"group_join_revision"`
	MembershipRevision int64  `json:"membership_revision"`
	Mode               string `json:"mode"`
	ContextContinuity  string `json:"context_continuity"`
}

// AuthorizeRelayNativeWakeForNodeCredential rechecks the exact current claim,
// inbox row, Node credential/owner binding, Endpoint, Group joins, and native
// session lease in one authoritative read transaction. It deliberately rejects
// SEALED_V1 payloads because this query does not recheck CommunicationLink or
// sealed-grant authorization. Call it immediately before each plaintext
// native side effect (queue and resume).
func (s *Store) AuthorizeRelayNativeWakeForNodeCredential(credentialDigest, nodeID string,
	input RelayNativeWakeAuthorizationInput) (*RelayNativeWakeAuthorization, error) {
	credentialDigest = strings.TrimSpace(credentialDigest)
	nodeID = strings.TrimSpace(nodeID)
	input.MessageID = strings.TrimSpace(input.MessageID)
	input.AttemptID = strings.TrimSpace(input.AttemptID)
	if !validNodeCredentialDigest(credentialDigest) || nodeID == "" || len(nodeID) > 256 ||
		input.MessageID == "" || len(input.MessageID) > 256 || input.AttemptID == "" || len(input.AttemptID) > 256 {
		return nil, ErrRelayNativeWakeAuthorizationUnavailable
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	currentNodeID, nodeOwnerID, _, _, err := readCurrentBoundNodeOwnerTx(tx, credentialDigest)
	if err != nil || currentNodeID != nodeID {
		return nil, ErrRelayNativeWakeAuthorizationUnavailable
	}
	nowText := time.Now().UTC().Format(time.RFC3339Nano)
	var authorization RelayNativeWakeAuthorization
	err = tx.QueryRow(`SELECT a.message_id, a.attempt_id, a.digest,
 e.id, e.harness, sb.id, sb.epoch, sb.native_session_id, sb.lease_owner,
 sb.lease_expires_at, i.receiver_group_id, eg.revision, m.revision, sb.mode,
 sb.context_continuity
FROM relay_v2_delivery_attempts a
JOIN relay_v2_inbox i ON i.recipient_endpoint_id=a.recipient_endpoint_id
 AND i.sequence=a.sequence AND i.message_id=a.message_id AND i.digest=a.digest
JOIN fabric_messages fm ON fm.id=a.message_id
-- Security metadata is updated by the narrow pending-inbox rebind operation,
-- so its receiver binding coordinates must match this exact attempt. Group
-- authority comes from the accepted inbox scope and current membership joins,
-- not the legacy single-Group Endpoint projection.
JOIN relay_v2_message_security sec ON sec.message_id=a.message_id
JOIN fabric_endpoints e ON e.id=a.recipient_endpoint_id
JOIN session_bindings sb ON sb.id=a.binding_id AND sb.endpoint_id=e.id
JOIN principals p ON p.id=sb.principal_id AND p.id=e.principal_id
JOIN memberships m ON m.principal_id=p.id AND m.group_id=i.receiver_group_id
JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=i.receiver_group_id
JOIN groups g ON g.id=i.receiver_group_id
WHERE a.attempt_id=? AND a.message_id=? AND a.state='CLAIMED'
 AND COALESCE((SELECT payload_mode FROM relay_v2_message_payloads payload
   WHERE payload.message_id=a.message_id), 'PLAINTEXT')='PLAINTEXT'
 AND i.state='CLAIMED' AND i.attempt_id=a.attempt_id
 AND i.binding_id=a.binding_id AND i.binding_epoch=a.binding_epoch
 AND sb.epoch=a.binding_epoch
	AND sec.receiver_endpoint_id=e.id AND sec.receiver_group_id=i.receiver_group_id
	AND sec.receiver_binding_id=a.binding_id AND sec.receiver_binding_epoch=a.binding_epoch
 AND EXISTS (SELECT 1 FROM relay_v2_receipts r WHERE r.attempt_id=a.attempt_id
   AND r.message_id=a.message_id AND r.digest=a.digest AND r.layer='NODE_RECEIVED')
	AND e.machine_id=? AND e.owner=? AND e.binding_id=sb.id
 AND e.native_session_id=sb.native_session_id AND e.migration_state='READY'
 AND e.status NOT IN ('left','offline')
 AND sb.node_id=? AND sb.lease_owner!='' AND julianday(sb.lease_expires_at)>julianday(?)
 AND sb.status IN ('active','leased','online','ready','acquired')
 AND p.owner_id=? AND p.status='active'
 AND m.status='active' AND (m.effective_at='' OR julianday(m.effective_at)<=julianday(?))
 AND (m.expires_at='' OR julianday(m.expires_at)>julianday(?))
 AND eg.status='active' AND g.state='ACTIVE'
 AND julianday(m.updated_at)<=julianday(fm.created_at)
 AND julianday(eg.updated_at)<=julianday(fm.created_at)
	LIMIT 1`, input.AttemptID, input.MessageID, nodeID, nodeOwnerID, nodeID,
		nowText, nodeOwnerID, nowText, nowText).Scan(
		&authorization.MessageID, &authorization.AttemptID, &authorization.Digest,
		&authorization.EndpointID, &authorization.Harness, &authorization.BindingID,
		&authorization.BindingEpoch, &authorization.NativeSessionID, &authorization.LeaseOwner,
		&authorization.LeaseExpiresAt, &authorization.GroupID, &authorization.GroupJoinRevision,
		&authorization.MembershipRevision, &authorization.Mode, &authorization.ContextContinuity)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRelayNativeWakeAuthorizationUnavailable
	}
	if err != nil {
		return nil, err
	}
	authorization.NodeID = nodeID
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &authorization, nil
}
