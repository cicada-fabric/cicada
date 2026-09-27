package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const SameGroupBroadcastV2MaxRecipients = 32

var (
	ErrSameGroupBroadcastV2Denied         = errors.New("same-Group broadcast is not currently authorized")
	ErrSameGroupBroadcastV2Conflict       = errors.New("broadcast id conflicts with an existing snapshot")
	ErrSameGroupBroadcastV2RecipientLimit = errors.New("same-Group broadcast exceeds the recipient limit")
	ErrSameGroupBroadcastV2NotReady       = errors.New("same-Group broadcast recipient is not ready")
)

type SameGroupBroadcastV2SnapshotInput struct {
	NodeCredentialDigest    string
	SessionCredentialDigest string
	GroupID                 string
	BroadcastID             string
}

type SameGroupBroadcastV2Endpoint struct {
	EndpointID         string              `json:"endpoint_id"`
	PrincipalID        string              `json:"principal_id"`
	OwnerID            string              `json:"owner_id"`
	NodeID             string              `json:"node_id"`
	GroupID            string              `json:"group_id"`
	GroupRevision      int64               `json:"group_revision"`
	MembershipRevision int64               `json:"membership_revision"`
	GroupJoinRevision  int64               `json:"group_join_revision"`
	BindingID          string              `json:"binding_id"`
	BindingEpoch       uint64              `json:"binding_epoch"`
	BindingVersion     int64               `json:"binding_version"`
	KeyID              string              `json:"key_id"`
	KeyVersion         int64               `json:"key_version"`
	KeyProofDigest     string              `json:"key_proof_digest"`
	PublicKey          e2ee.PublicIdentity `json:"public_key"`
	NativeSessionID    string              `json:"native_session_id,omitempty"`
}

type SameGroupBroadcastV2Snapshot struct {
	BroadcastID    string                         `json:"broadcast_id"`
	GroupID        string                         `json:"group_id"`
	GroupRevision  int64                          `json:"group_revision"`
	CapturedAt     string                         `json:"captured_at"`
	SnapshotDigest string                         `json:"snapshot_digest"`
	Source         SameGroupBroadcastV2Endpoint   `json:"source"`
	Recipients     []SameGroupBroadcastV2Endpoint `json:"recipients"`
}

func (s *Store) initializeGroupBroadcastV2Schema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS group_broadcast_v2_snapshots (
  broadcast_id TEXT PRIMARY KEY,
  group_id TEXT NOT NULL,
  group_revision INTEGER NOT NULL CHECK(group_revision > 0),
  source_endpoint_id TEXT NOT NULL,
  source_principal_id TEXT NOT NULL,
  source_owner_id TEXT NOT NULL,
  source_node_id TEXT NOT NULL,
  source_membership_revision INTEGER NOT NULL CHECK(source_membership_revision > 0),
  source_group_join_revision INTEGER NOT NULL CHECK(source_group_join_revision > 0),
  source_binding_id TEXT NOT NULL,
  source_binding_epoch INTEGER NOT NULL CHECK(source_binding_epoch > 0),
  source_binding_version INTEGER NOT NULL CHECK(source_binding_version > 0),
  source_key_id TEXT NOT NULL,
  source_key_version INTEGER NOT NULL CHECK(source_key_version > 0),
  source_key_proof_digest TEXT NOT NULL CHECK(length(source_key_proof_digest) = 64),
  source_public_identity_json TEXT NOT NULL,
  source_native_session_id TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest) = 64),
  recipient_count INTEGER NOT NULL CHECK(recipient_count >= 0 AND recipient_count <= 32)
);
CREATE TABLE IF NOT EXISTS group_broadcast_v2_snapshot_recipients (
  broadcast_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 32),
  endpoint_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  group_revision INTEGER NOT NULL CHECK(group_revision > 0),
  membership_revision INTEGER NOT NULL CHECK(membership_revision > 0),
  group_join_revision INTEGER NOT NULL CHECK(group_join_revision > 0),
  binding_id TEXT NOT NULL,
  binding_epoch INTEGER NOT NULL CHECK(binding_epoch > 0),
  binding_version INTEGER NOT NULL CHECK(binding_version > 0),
  key_id TEXT NOT NULL,
  key_version INTEGER NOT NULL CHECK(key_version > 0),
  key_proof_digest TEXT NOT NULL CHECK(length(key_proof_digest) = 64),
  public_identity_json TEXT NOT NULL,
  PRIMARY KEY(broadcast_id, endpoint_id),
  UNIQUE(broadcast_id, ordinal),
  FOREIGN KEY(broadcast_id) REFERENCES group_broadcast_v2_snapshots(broadcast_id)
);
CREATE INDEX IF NOT EXISTS group_broadcast_v2_snapshots_group_idx
  ON group_broadcast_v2_snapshots(group_id, captured_at, broadcast_id);
CREATE TRIGGER IF NOT EXISTS group_broadcast_v2_snapshots_immutable_update
BEFORE UPDATE ON group_broadcast_v2_snapshots
BEGIN SELECT RAISE(ABORT, 'broadcast snapshots are immutable'); END;
CREATE TRIGGER IF NOT EXISTS group_broadcast_v2_snapshots_immutable_delete
BEFORE DELETE ON group_broadcast_v2_snapshots
BEGIN SELECT RAISE(ABORT, 'broadcast snapshots are immutable'); END;
CREATE TRIGGER IF NOT EXISTS group_broadcast_v2_recipients_immutable_update
BEFORE UPDATE ON group_broadcast_v2_snapshot_recipients
BEGIN SELECT RAISE(ABORT, 'broadcast snapshot recipients are immutable'); END;
CREATE TRIGGER IF NOT EXISTS group_broadcast_v2_recipients_immutable_delete
BEFORE DELETE ON group_broadcast_v2_snapshot_recipients
BEGIN SELECT RAISE(ABORT, 'broadcast snapshot recipients are immutable'); END;
`)
	if err != nil {
		return fmt.Errorf("initialize immutable Group broadcast snapshots: %w", err)
	}
	return nil
}

// CreateSameGroupBroadcastV2Snapshot captures a fixed recipient set before any
// envelope is prepared or dispatched. The supplied credential values are
// SHA-256 digests, matching the Store's other authenticated Node operations.
// Reusing a broadcast ID returns its original snapshot without re-enumerating
// members; current source membership, binding, and broadcast authority are
// checked before either creating or returning that snapshot.
func (s *Store) CreateSameGroupBroadcastV2Snapshot(input SameGroupBroadcastV2SnapshotInput) (*SameGroupBroadcastV2Snapshot, error) {
	input.NodeCredentialDigest = strings.TrimSpace(input.NodeCredentialDigest)
	input.SessionCredentialDigest = strings.TrimSpace(input.SessionCredentialDigest)
	input.GroupID = strings.TrimSpace(input.GroupID)
	input.BroadcastID = strings.TrimSpace(input.BroadcastID)
	if !validNodeCredentialDigest(input.NodeCredentialDigest) ||
		!validNodeCredentialDigest(input.SessionCredentialDigest) ||
		!validSameGroupSealedV1Token(input.GroupID) ||
		!validSameGroupSealedV1Token(input.BroadcastID) {
		return nil, ErrSameGroupBroadcastV2Denied
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	nowTime := time.Now().UTC()
	nowText := nowTime.Format(time.RFC3339Nano)
	nodeID, nodeOwnerID, _, _, err := readCurrentBoundNodeOwnerTx(tx, input.NodeCredentialDigest)
	if err != nil {
		return nil, ErrSameGroupBroadcastV2Denied
	}
	source, err := readLocalDeliverySourceTx(tx, input.SessionCredentialDigest, input.GroupID, nowText)
	if err != nil || source.NodeID != nodeID || source.PrincipalOwnerID != nodeOwnerID || source.EndpointOwnerID != nodeOwnerID {
		return nil, ErrSameGroupBroadcastV2Denied
	}
	if err := validateLocalDeliveryEndpointSnapshot(source, input.GroupID, nowTime); err != nil {
		return nil, ErrSameGroupBroadcastV2Denied
	}
	allowed, err := localDeliveryMembershipAllows(tx, source.PrincipalID, input.GroupID, "message.broadcast", nowText)
	if err != nil || !allowed {
		return nil, ErrSameGroupBroadcastV2Denied
	}
	// Every child uses the ordinary sealed SEND path, whose authorization
	// requires message.send. Check it before freezing a snapshot so a caller
	// cannot create a broadcast that every child is guaranteed to reject.
	allowed, err = localDeliveryMembershipAllows(tx, source.PrincipalID, input.GroupID, "message.send", nowText)
	if err != nil || !allowed {
		return nil, ErrSameGroupBroadcastV2Denied
	}

	stored, err := readSameGroupBroadcastV2SnapshotTx(tx, input.BroadcastID)
	if err == nil {
		if !sameGroupBroadcastV2SourceMatches(stored, input.GroupID, source) {
			return nil, ErrSameGroupBroadcastV2Conflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return stored, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	snapshot, err := buildSameGroupBroadcastV2SnapshotTx(tx, input.BroadcastID, input.GroupID, source, nowTime)
	if err != nil {
		return nil, err
	}
	if err := insertSameGroupBroadcastV2SnapshotTx(tx, snapshot); err != nil {
		if isUniqueConstraintError(err) {
			stored, readErr := readSameGroupBroadcastV2SnapshotTx(tx, input.BroadcastID)
			if readErr == nil && sameGroupBroadcastV2SourceMatches(stored, input.GroupID, source) {
				if commitErr := tx.Commit(); commitErr != nil {
					return nil, commitErr
				}
				return stored, nil
			}
			return nil, ErrSameGroupBroadcastV2Conflict
		}
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// buildSameGroupBroadcastV2SnapshotTx shares the exact recipient and key
// selection with trusted Client-origin previews. The caller owns the transaction.
func buildSameGroupBroadcastV2SnapshotTx(tx *sql.Tx, broadcastID, groupID string,
	source localDeliveryEndpointSnapshot, nowTime time.Time) (*SameGroupBroadcastV2Snapshot, error) {
	nowText := nowTime.Format(time.RFC3339Nano)
	sourceEvidence, err := readSameGroupSealedV1EndpointTx(tx, groupID, source.EndpointID, nowTime)
	if err != nil || sourceEvidence.GroupRevision != source.GroupRevision ||
		sourceEvidence.MembershipRevision != source.MembershipRevision ||
		sourceEvidence.EndpointJoinRevision != source.GroupJoinRevision {
		return nil, ErrSameGroupBroadcastV2NotReady
	}
	resultSource, err := sameGroupBroadcastV2EndpointTx(tx, sourceEvidence, nowText, true)
	if err != nil {
		return nil, ErrSameGroupBroadcastV2NotReady
	}

	recipientIDs, err := listSameGroupBroadcastV2RecipientIDsTx(tx, groupID,
		source.EndpointID, nowText)
	if err != nil {
		return nil, err
	}
	if len(recipientIDs) > SameGroupBroadcastV2MaxRecipients {
		return nil, ErrSameGroupBroadcastV2RecipientLimit
	}
	recipients := make([]SameGroupBroadcastV2Endpoint, 0, len(recipientIDs))
	for _, endpointID := range recipientIDs {
		evidence, err := readSameGroupSealedV1EndpointTx(tx, groupID, endpointID, nowTime)
		if err != nil || evidence.OwnerID != source.OwnerID ||
			evidence.GroupRevision != source.GroupRevision {
			return nil, ErrSameGroupBroadcastV2NotReady
		}
		allowed, err := localDeliveryMembershipAllows(tx, evidence.PrincipalID,
			groupID, "message.receive", nowText)
		if err != nil || !allowed {
			return nil, ErrSameGroupBroadcastV2NotReady
		}
		recipient, err := sameGroupBroadcastV2EndpointTx(tx, evidence, nowText, false)
		if err != nil {
			return nil, ErrSameGroupBroadcastV2NotReady
		}
		recipients = append(recipients, recipient)
	}
	sort.Slice(recipients, func(i, j int) bool {
		return recipients[i].EndpointID < recipients[j].EndpointID
	})

	snapshot := &SameGroupBroadcastV2Snapshot{
		BroadcastID: broadcastID, GroupID: groupID,
		GroupRevision: source.GroupRevision, CapturedAt: nowText,
		Source: resultSource, Recipients: recipients,
	}
	snapshot.SnapshotDigest, err = sameGroupBroadcastV2SnapshotDigest(snapshot)
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}

func sameGroupBroadcastV2SourceMatches(snapshot *SameGroupBroadcastV2Snapshot, groupID string,
	source localDeliveryEndpointSnapshot) bool {
	return snapshot != nil && snapshot.GroupID == groupID &&
		snapshot.Source.EndpointID == source.EndpointID &&
		snapshot.Source.PrincipalID == source.PrincipalID &&
		snapshot.Source.OwnerID == source.OwnerID &&
		snapshot.Source.NodeID == source.NodeID &&
		snapshot.Source.NativeSessionID == source.NativeSessionID &&
		snapshot.Source.MembershipRevision == source.MembershipRevision &&
		snapshot.Source.GroupJoinRevision == source.GroupJoinRevision &&
		snapshot.Source.BindingID == source.BindingID &&
		snapshot.Source.BindingEpoch == source.BindingEpoch
}

func listSameGroupBroadcastV2RecipientIDsTx(tx *sql.Tx, groupID,
	sourceEndpointID, nowText string) ([]string, error) {
	rows, err := tx.Query(`SELECT DISTINCT e.id
FROM fabric_endpoints e
JOIN principals p ON p.id=e.principal_id
JOIN memberships m ON m.principal_id=p.id AND m.group_id=?
JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=m.group_id
JOIN groups g ON g.id=m.group_id
JOIN session_bindings sb ON sb.id=e.binding_id AND sb.endpoint_id=e.id
WHERE e.id!=? AND p.status='active'
  AND m.status='active' AND (m.effective_at='' OR julianday(m.effective_at)<=julianday(?))
  AND (m.expires_at='' OR julianday(m.expires_at)>julianday(?))
  AND (EXISTS (SELECT 1 FROM json_each(m.grants_json) AS grant_item
                 WHERE grant_item.value='message.receive')
       OR json_extract(m.authorization_json, '$.message.receive')=1)
  AND eg.status='active' AND g.state='ACTIVE'
  AND e.migration_state='READY' AND e.status!='left'
  AND sb.status='leased' AND sb.lease_owner!=''
  AND julianday(sb.lease_expires_at)>julianday(?)
  AND sb.node_id=e.machine_id AND sb.native_session_id=e.native_session_id
	ORDER BY e.id LIMIT ?`, groupID, sourceEndpointID, nowText, nowText,
		nowText, SameGroupBroadcastV2MaxRecipients+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0, SameGroupBroadcastV2MaxRecipients+1)
	seen := make(map[string]struct{}, SameGroupBroadcastV2MaxRecipients+1)
	for rows.Next() {
		var endpointID string
		if err := rows.Scan(&endpointID); err != nil {
			return nil, err
		}
		if _, duplicate := seen[endpointID]; duplicate {
			continue
		}
		seen[endpointID] = struct{}{}
		ids = append(ids, endpointID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

func sameGroupBroadcastV2EndpointTx(tx *sql.Tx, evidence SameGroupSealedV1EndpointEvidence,
	nowText string, includeNativeSession bool) (SameGroupBroadcastV2Endpoint, error) {
	var bindingVersion int64
	err := tx.QueryRow(`SELECT version FROM session_bindings
WHERE id=? AND endpoint_id=? AND principal_id=? AND node_id=? AND native_session_id=?
  AND epoch=? AND status='leased' AND lease_owner!=''
  AND julianday(lease_expires_at)>julianday(?)`, evidence.BindingID, evidence.EndpointID,
		evidence.PrincipalID, evidence.NodeID, evidence.NativeSessionID, evidence.BindingEpoch,
		nowText).Scan(&bindingVersion)
	if err != nil {
		return SameGroupBroadcastV2Endpoint{}, err
	}
	endpoint := SameGroupBroadcastV2Endpoint{
		EndpointID: evidence.EndpointID, PrincipalID: evidence.PrincipalID,
		OwnerID: evidence.OwnerID, NodeID: evidence.NodeID, GroupID: evidence.GroupID,
		GroupRevision: evidence.GroupRevision, MembershipRevision: evidence.MembershipRevision,
		GroupJoinRevision: evidence.EndpointJoinRevision, BindingID: evidence.BindingID,
		BindingEpoch: evidence.BindingEpoch, BindingVersion: bindingVersion,
		KeyID: evidence.Candidate.KeyID, KeyVersion: evidence.Candidate.Version,
		KeyProofDigest: evidence.Candidate.ProofDigest, PublicKey: evidence.Candidate.Public,
	}
	if includeNativeSession {
		endpoint.NativeSessionID = evidence.NativeSessionID
	}
	return endpoint, nil
}

func insertSameGroupBroadcastV2SnapshotTx(tx *sql.Tx, snapshot *SameGroupBroadcastV2Snapshot) error {
	source := snapshot.Source
	sourcePublicKeyJSON, err := json.Marshal(source.PublicKey)
	if err != nil {
		return fmt.Errorf("encode Group broadcast source public key: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO group_broadcast_v2_snapshots
(broadcast_id, group_id, group_revision, source_endpoint_id, source_principal_id,
 source_owner_id, source_node_id, source_membership_revision, source_group_join_revision,
 source_binding_id, source_binding_epoch, source_binding_version, source_key_id,
 source_key_version, source_key_proof_digest, source_public_identity_json, source_native_session_id, captured_at,
 snapshot_digest, recipient_count)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		snapshot.BroadcastID, snapshot.GroupID, snapshot.GroupRevision, source.EndpointID,
		source.PrincipalID, source.OwnerID, source.NodeID, source.MembershipRevision,
		source.GroupJoinRevision, source.BindingID, source.BindingEpoch, source.BindingVersion,
		source.KeyID, source.KeyVersion, source.KeyProofDigest, string(sourcePublicKeyJSON), source.NativeSessionID,
		snapshot.CapturedAt, snapshot.SnapshotDigest, len(snapshot.Recipients))
	if err != nil {
		return err
	}
	for ordinal, recipient := range snapshot.Recipients {
		publicKeyJSON, err := json.Marshal(recipient.PublicKey)
		if err != nil {
			return fmt.Errorf("encode Group broadcast recipient public key: %w", err)
		}
		_, err = tx.Exec(`INSERT INTO group_broadcast_v2_snapshot_recipients
(broadcast_id, ordinal, endpoint_id, principal_id, owner_id, node_id, group_id,
 group_revision, membership_revision, group_join_revision, binding_id, binding_epoch,
 binding_version, key_id, key_version, key_proof_digest, public_identity_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, snapshot.BroadcastID,
			ordinal, recipient.EndpointID, recipient.PrincipalID, recipient.OwnerID,
			recipient.NodeID, recipient.GroupID, recipient.GroupRevision,
			recipient.MembershipRevision, recipient.GroupJoinRevision, recipient.BindingID,
			recipient.BindingEpoch, recipient.BindingVersion, recipient.KeyID,
			recipient.KeyVersion, recipient.KeyProofDigest, string(publicKeyJSON))
		if err != nil {
			return err
		}
	}
	return nil
}

func readSameGroupBroadcastV2SnapshotTx(tx *sql.Tx,
	broadcastID string) (*SameGroupBroadcastV2Snapshot, error) {
	var snapshot SameGroupBroadcastV2Snapshot
	var source SameGroupBroadcastV2Endpoint
	var sourcePublicKeyJSON string
	var recipientCount int
	err := tx.QueryRow(`SELECT broadcast_id, group_id, group_revision, captured_at,
snapshot_digest, source_endpoint_id, source_principal_id, source_owner_id, source_node_id,
source_membership_revision, source_group_join_revision, source_binding_id, source_binding_epoch,
source_binding_version, source_key_id, source_key_version, source_key_proof_digest,
source_public_identity_json, source_native_session_id, recipient_count
FROM group_broadcast_v2_snapshots WHERE broadcast_id=?`, broadcastID).Scan(
		&snapshot.BroadcastID, &snapshot.GroupID, &snapshot.GroupRevision, &snapshot.CapturedAt,
		&snapshot.SnapshotDigest, &source.EndpointID, &source.PrincipalID, &source.OwnerID,
		&source.NodeID, &source.MembershipRevision, &source.GroupJoinRevision, &source.BindingID,
		&source.BindingEpoch, &source.BindingVersion, &source.KeyID, &source.KeyVersion,
		&source.KeyProofDigest, &sourcePublicKeyJSON, &source.NativeSessionID, &recipientCount)
	if err != nil {
		return nil, err
	}
	source.GroupID, source.GroupRevision = snapshot.GroupID, snapshot.GroupRevision
	if err := json.Unmarshal([]byte(sourcePublicKeyJSON), &source.PublicKey); err != nil {
		return nil, errors.New("stored Group broadcast source key is invalid")
	}
	snapshot.Source = source
	rows, err := tx.Query(`SELECT endpoint_id, principal_id, owner_id, node_id, group_id,
group_revision, membership_revision, group_join_revision, binding_id, binding_epoch,
binding_version, key_id, key_version, key_proof_digest, public_identity_json
FROM group_broadcast_v2_snapshot_recipients WHERE broadcast_id=? ORDER BY ordinal`, broadcastID)
	if err != nil {
		return nil, err
	}
	snapshot.Recipients = make([]SameGroupBroadcastV2Endpoint, 0, recipientCount)
	for rows.Next() {
		var recipient SameGroupBroadcastV2Endpoint
		var publicKeyJSON string
		if err := rows.Scan(&recipient.EndpointID, &recipient.PrincipalID, &recipient.OwnerID,
			&recipient.NodeID, &recipient.GroupID, &recipient.GroupRevision,
			&recipient.MembershipRevision, &recipient.GroupJoinRevision, &recipient.BindingID,
			&recipient.BindingEpoch, &recipient.BindingVersion, &recipient.KeyID,
			&recipient.KeyVersion, &recipient.KeyProofDigest, &publicKeyJSON); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if err := json.Unmarshal([]byte(publicKeyJSON), &recipient.PublicKey); err != nil {
			_ = rows.Close()
			return nil, errors.New("stored Group broadcast recipient key is invalid")
		}
		snapshot.Recipients = append(snapshot.Recipients, recipient)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(snapshot.Recipients) != recipientCount || recipientCount > SameGroupBroadcastV2MaxRecipients {
		return nil, errors.New("stored Group broadcast snapshot is incomplete")
	}
	for i, recipient := range snapshot.Recipients {
		if recipient.EndpointID == snapshot.Source.EndpointID || recipient.GroupID != snapshot.GroupID ||
			recipient.GroupRevision != snapshot.GroupRevision ||
			(i > 0 && snapshot.Recipients[i-1].EndpointID >= recipient.EndpointID) {
			return nil, errors.New("stored Group broadcast snapshot is invalid")
		}
	}
	digest, err := sameGroupBroadcastV2SnapshotDigest(&snapshot)
	if err != nil {
		return nil, err
	}
	if digest != snapshot.SnapshotDigest {
		return nil, errors.New("stored Group broadcast snapshot digest does not match")
	}
	return &snapshot, nil
}

func sameGroupBroadcastV2SnapshotDigest(snapshot *SameGroupBroadcastV2Snapshot) (string, error) {
	copy := *snapshot
	copy.SnapshotDigest = ""
	encoded, err := json.Marshal(copy)
	if err != nil {
		return "", fmt.Errorf("encode Group broadcast snapshot: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func isUniqueConstraintError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}
