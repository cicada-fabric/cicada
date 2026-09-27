package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	UserMonitorBroadcastV2TTL                = 5 * time.Minute
	UserMonitorBroadcastV2MaxSealedBytes     = 262144
	UserMonitorBroadcastV2Prepared           = "PREPARED"
	UserMonitorBroadcastV2Approved           = "APPROVED"
	UserMonitorBroadcastV2DispatchAuthorized = "DISPATCH_AUTHORIZED"
)

var (
	ErrUserMonitorBroadcastV2Denied   = errors.New("user-through-Monitor broadcast is not currently authorized")
	ErrUserMonitorBroadcastV2Conflict = errors.New("user-through-Monitor broadcast inputs conflict")
	ErrUserMonitorBroadcastV2Expired  = errors.New("user-through-Monitor broadcast preview expired")
)

// ClientRequestID is the ID returned by AcceptClientRequest after authenticated
// Client wire processing. An HTTP caller must never be allowed to choose it.
type PrepareUserMonitorBroadcastV2Input struct {
	ClientRequestID   string
	GroupID           string
	MonitorEndpointID string
	BodyDigest        string
}

type ConfirmUserMonitorBroadcastV2Input struct {
	ClientRequestID string
	PreviewID       string
	SnapshotDigest  string
	BodyDigest      string
	SealedPayload   []byte
}

type AuthorizeUserMonitorBroadcastV2Input struct {
	NodeCredentialDigest    string
	SessionCredentialDigest string
	PreviewID               string
	BroadcastID             string
	OperationID             string
	BodyDigest              string
	SnapshotDigest          string
}

// PreviewUserMonitorBroadcastV2Input identifies an already-approved ledger
// entry using only trusted Node and original Session credentials. All approval
// claims and operation fields are derived from the durable record.
type PreviewUserMonitorBroadcastV2Input struct {
	NodeCredentialDigest    string
	SessionCredentialDigest string
	PreviewID               string
}

type UserMonitorBroadcastV2 struct {
	PreviewID            string                         `json:"preview_id"`
	BroadcastID          string                         `json:"broadcast_id"`
	Status               string                         `json:"status"`
	OwnerID              string                         `json:"owner_id"`
	DeviceID             string                         `json:"device_id"`
	SessionEpoch         uint64                         `json:"session_epoch"`
	ClientKeyVersion     int64                          `json:"-"`
	GroupID              string                         `json:"group_id"`
	MonitorEndpointID    string                         `json:"monitor_endpoint_id"`
	MonitorKeyID         string                         `json:"-"`
	BodyDigest           string                         `json:"body_sha256"`
	SnapshotDigest       string                         `json:"snapshot_digest"`
	Snapshot             *SameGroupBroadcastV2Snapshot  `json:"-"`
	Preview              *UserMonitorBroadcastV2Preview `json:"preview,omitempty"`
	ExpiresAt            string                         `json:"expires_at"`
	ApprovedAt           string                         `json:"approved_at,omitempty"`
	DispatchAuthorizedAt string                         `json:"dispatch_authorized_at,omitempty"`
	OperationID          string                         `json:"operation_id,omitempty"`
	SealedPayload        []byte                         `json:"-"`
	SealedPayloadDigest  string                         `json:"sealed_payload_digest,omitempty"`
	SealedSequence       uint64                         `json:"sealed_sequence,omitempty"`
	prepareRequestID     string
	confirmRequestID     string
	consumeNodeID        string
	consumeBindingID     string
	consumeBindingEpoch  uint64
	consentDigest        string
	previewJSON          string
}

func (s *Store) initializeUserMonitorBroadcastV2Schema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS user_monitor_broadcast_v2 (
  preview_id TEXT PRIMARY KEY,
  broadcast_id TEXT NOT NULL UNIQUE REFERENCES group_broadcast_v2_snapshots(broadcast_id),
  prepare_request_id TEXT NOT NULL UNIQUE REFERENCES client_device_requests_v2(id),
  confirm_request_id TEXT UNIQUE REFERENCES client_device_requests_v2(id),
  owner_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  session_epoch INTEGER NOT NULL CHECK(session_epoch > 0),
  client_key_version INTEGER NOT NULL CHECK(client_key_version > 0),
  group_id TEXT NOT NULL,
  monitor_endpoint_id TEXT NOT NULL,
  monitor_key_id TEXT NOT NULL,
  body_digest TEXT NOT NULL CHECK(length(body_digest) = 64),
  snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest) = 64),
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PREPARED','APPROVED','DISPATCH_AUTHORIZED')),
  approved_at TEXT NOT NULL DEFAULT '',
  sealed_payload BLOB,
  sealed_payload_digest TEXT NOT NULL DEFAULT '',
  sealed_sequence INTEGER NOT NULL DEFAULT 0 CHECK(sealed_sequence >= 0),
  operation_id TEXT NOT NULL DEFAULT '',
  consume_node_id TEXT NOT NULL DEFAULT '',
  consume_binding_id TEXT NOT NULL DEFAULT '',
  consume_binding_epoch INTEGER NOT NULL DEFAULT 0,
  dispatch_authorized_at TEXT NOT NULL DEFAULT '',
  CHECK(sealed_payload IS NULL OR (length(sealed_payload)>0 AND length(sealed_payload)<=262144)),
  CHECK((status='PREPARED' AND sealed_payload IS NULL AND confirm_request_id IS NULL) OR
        (status!='PREPARED' AND sealed_payload IS NOT NULL AND confirm_request_id IS NOT NULL)),
  CHECK((status='DISPATCH_AUTHORIZED' AND operation_id!='' AND dispatch_authorized_at!='') OR
        (status!='DISPATCH_AUTHORIZED' AND operation_id='' AND dispatch_authorized_at='')),
  FOREIGN KEY(owner_id,device_id) REFERENCES client_devices_v2(owner_id,device_id)
);
CREATE INDEX IF NOT EXISTS user_monitor_broadcast_v2_device_idx
  ON user_monitor_broadcast_v2(owner_id,device_id,expires_at,preview_id);
CREATE UNIQUE INDEX IF NOT EXISTS user_monitor_broadcast_v2_sealed_sequence_idx
  ON user_monitor_broadcast_v2(owner_id,device_id,client_key_version,monitor_key_id,sealed_sequence)
  WHERE sealed_sequence>0;`)
	return err
}

func (s *Store) initializeUserMonitorBroadcastV2ConsentSchema() error {
	if err := s.ensureColumn("user_monitor_broadcast_v2", "consent_digest", `ALTER TABLE user_monitor_broadcast_v2 ADD COLUMN consent_digest TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	return s.ensureColumn("user_monitor_broadcast_v2", "preview_json", `ALTER TABLE user_monitor_broadcast_v2 ADD COLUMN preview_json TEXT NOT NULL DEFAULT ''`)
}

type userMonitorClientRequest struct {
	id, ownerID, deviceID, status, hubID string
	epoch, sequence                      uint64
	keyVersion                           int64
	devicePublic                         e2ee.PublicIdentity
}

func readUserMonitorClientRequestTx(tx *sql.Tx, requestID string) (userMonitorClientRequest, error) {
	return readUserMonitorClientRequestWithStatusTx(tx, requestID, false)
}

func readUserMonitorClientRequestWithStatusTx(tx *sql.Tx, requestID string, allowUncertain bool) (userMonitorClientRequest, error) {
	var out userMonitorClientRequest
	var epoch, sequence int64
	var deviceState, ownerKeyState, publicJSON string
	err := tx.QueryRow(`SELECT r.id,r.owner_id,r.device_id,r.session_epoch,r.sequence,r.status,
d.state,k.state,d.public_identity_json,h.hub_id,d.key_version
FROM client_device_requests_v2 r
JOIN client_devices_v2 d ON d.owner_id=r.owner_id AND d.device_id=r.device_id
JOIN owner_approval_keys_v2 k ON k.owner_id=d.owner_id AND k.key_id=d.owner_key_id
JOIN principals p ON p.id=r.owner_id AND p.kind='human' AND p.status='active'
JOIN client_device_hub_config_v2 h ON h.id=1
WHERE r.id=?`, requestID).Scan(&out.id, &out.ownerID, &out.deviceID, &epoch, &sequence,
		&out.status, &deviceState, &ownerKeyState, &publicJSON, &out.hubID, &out.keyVersion)
	if err != nil || epoch <= 0 || sequence <= 0 || deviceState != ClientDeviceActive || ownerKeyState != OwnerApprovalKeyActive {
		return out, ErrUserMonitorBroadcastV2Denied
	}
	var currentEpoch int64
	if err := tx.QueryRow(`SELECT session_epoch FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, out.ownerID, out.deviceID).Scan(&currentEpoch); err != nil || currentEpoch != epoch {
		return out, ErrUserMonitorBroadcastV2Denied
	}
	if out.status != ClientRequestProcessing && out.status != ClientRequestCompleted &&
		!(allowUncertain && out.status == ClientRequestUncertain) {
		return out, ErrUserMonitorBroadcastV2Denied
	}
	if err := json.Unmarshal([]byte(publicJSON), &out.devicePublic); err != nil {
		return out, ErrUserMonitorBroadcastV2Denied
	}
	out.epoch, out.sequence = uint64(epoch), uint64(sequence)
	return out, nil
}

// A completed Store approval can outlive an uncertain outer RPC response.
// Only this historical path may read that request, and only after the exact
// sealed approval is already durable. It cannot create a new preview or grant.
func readUserMonitorHistoricalConfirmRequestTx(tx *sql.Tx, r *UserMonitorBroadcastV2) (userMonitorClientRequest, error) {
	if r == nil || r.Status == UserMonitorBroadcastV2Prepared || r.confirmRequestID == "" ||
		r.SealedSequence == 0 || r.SealedPayloadDigest == "" || len(r.SealedPayload) == 0 {
		return userMonitorClientRequest{}, ErrUserMonitorBroadcastV2Denied
	}
	sealedDigest := sha256.Sum256(r.SealedPayload)
	if hex.EncodeToString(sealedDigest[:]) != r.SealedPayloadDigest {
		return userMonitorClientRequest{}, ErrUserMonitorBroadcastV2Denied
	}
	req, err := readUserMonitorClientRequestWithStatusTx(tx, r.confirmRequestID, true)
	if err != nil || req.ownerID != r.OwnerID || req.deviceID != r.DeviceID ||
		req.epoch != r.SessionEpoch || req.keyVersion != r.ClientKeyVersion {
		return userMonitorClientRequest{}, ErrUserMonitorBroadcastV2Denied
	}
	return req, nil
}

func userMonitorRoleTx(tx *sql.Tx, principalID, groupID string) bool {
	var permitted int
	err := tx.QueryRow(`SELECT 1 FROM memberships WHERE principal_id=? AND group_id=?
AND status='active' AND (role='monitor' OR EXISTS
 (SELECT 1 FROM json_each(roles_json) WHERE value='monitor'))`, principalID, groupID).Scan(&permitted)
	return err == nil && permitted == 1
}

func currentUserMonitorSourceTx(tx *sql.Tx, groupID, endpointID, ownerID string,
	nowTime time.Time) (localDeliveryEndpointSnapshot, error) {
	nowText := nowTime.Format(time.RFC3339Nano)
	source, err := readLocalDeliveryEndpointByIDTx(tx, groupID, endpointID, nowText)
	if err != nil || validateLocalDeliveryEndpointSnapshot(source, groupID, nowTime) != nil ||
		source.PrincipalOwnerID != ownerID || source.EndpointOwnerID != ownerID ||
		!userMonitorRoleTx(tx, source.PrincipalID, groupID) {
		return source, ErrUserMonitorBroadcastV2Denied
	}
	if err := networkGuardGroupEndpointTx(tx, source.PrincipalID, source.EndpointID, groupID, nowTime); err != nil {
		return source, ErrUserMonitorBroadcastV2Denied
	}
	var boundOwner string
	err = tx.QueryRow(`SELECT binding.owner_id FROM node_owner_bindings_v2 binding
JOIN fabric_node_credentials credential ON credential.node_id=binding.node_id
 AND credential.credential_hash=binding.node_credential_digest
 AND credential.version=binding.node_credential_version AND credential.status='active'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
 AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
WHERE binding.node_id=? AND binding.state='ACTIVE'`, source.NodeID).Scan(&boundOwner)
	if err != nil || boundOwner != ownerID {
		return source, ErrUserMonitorBroadcastV2Denied
	}
	for _, action := range []string{"message.broadcast", "message.send"} {
		allowed, err := localDeliveryMembershipAllows(tx, source.PrincipalID, groupID, action, nowText)
		if err != nil || !allowed {
			return source, ErrUserMonitorBroadcastV2Denied
		}
	}
	return source, nil
}

func currentUserMonitorSnapshotTx(tx *sql.Tx, record *UserMonitorBroadcastV2, nowTime time.Time) error {
	source, err := currentUserMonitorSourceTx(tx, record.GroupID, record.MonitorEndpointID, record.OwnerID, nowTime)
	if err != nil {
		return err
	}
	current, err := buildSameGroupBroadcastV2SnapshotTx(tx, record.BroadcastID, record.GroupID, source, nowTime)
	if err != nil {
		return ErrUserMonitorBroadcastV2Denied
	}
	stored, err := readSameGroupBroadcastV2SnapshotTx(tx, record.BroadcastID)
	if err != nil || stored.SnapshotDigest != record.SnapshotDigest {
		return ErrUserMonitorBroadcastV2Denied
	}
	// Capture time is not an authorization fact. Every revision, binding,
	// recipient and pinned key must still match the preview exactly.
	current.CapturedAt = stored.CapturedAt
	current.SnapshotDigest = stored.SnapshotDigest
	// Lease renewal increments a binding row version without changing its
	// identity or fencing epoch. A new binding/epoch still fails comparison.
	current.Source.BindingVersion = stored.Source.BindingVersion
	for i := range current.Recipients {
		if i < len(stored.Recipients) {
			current.Recipients[i].BindingVersion = stored.Recipients[i].BindingVersion
		}
	}
	if !reflect.DeepEqual(current, stored) {
		return ErrUserMonitorBroadcastV2Denied
	}
	if record.consentDigest != "" {
		_, digest, err := userMonitorConsentScope(stored)
		if err != nil || digest != record.consentDigest {
			return ErrUserMonitorBroadcastV2Denied
		}
	}
	record.Snapshot = stored
	return nil
}

func readUserMonitorBroadcastTx(tx *sql.Tx, previewID string) (*UserMonitorBroadcastV2, error) {
	var r UserMonitorBroadcastV2
	var epoch, consumeEpoch int64
	err := tx.QueryRow(`SELECT preview_id,broadcast_id,status,owner_id,device_id,session_epoch,
client_key_version,group_id,monitor_endpoint_id,monitor_key_id,body_digest,snapshot_digest,expires_at,approved_at,
dispatch_authorized_at,operation_id,sealed_payload,sealed_payload_digest,sealed_sequence,prepare_request_id,
COALESCE(confirm_request_id,''),consume_node_id,consume_binding_id,consume_binding_epoch,
consent_digest,preview_json
FROM user_monitor_broadcast_v2 WHERE preview_id=?`, previewID).Scan(&r.PreviewID, &r.BroadcastID,
		&r.Status, &r.OwnerID, &r.DeviceID, &epoch, &r.ClientKeyVersion, &r.GroupID, &r.MonitorEndpointID, &r.MonitorKeyID,
		&r.BodyDigest, &r.SnapshotDigest, &r.ExpiresAt, &r.ApprovedAt, &r.DispatchAuthorizedAt,
		&r.OperationID, &r.SealedPayload, &r.SealedPayloadDigest, &r.SealedSequence, &r.prepareRequestID,
		&r.confirmRequestID, &r.consumeNodeID, &r.consumeBindingID, &consumeEpoch,
		&r.consentDigest, &r.previewJSON)
	if err != nil {
		return nil, err
	}
	r.SessionEpoch, r.consumeBindingEpoch = uint64(epoch), uint64(consumeEpoch)
	return &r, nil
}

func (s *Store) PrepareUserMonitorBroadcastV2(input PrepareUserMonitorBroadcastV2Input) (*UserMonitorBroadcastV2, error) {
	if !validateClientDeviceToken(input.ClientRequestID) || !validSameGroupSealedV1Token(input.GroupID) ||
		!validSameGroupSealedV1Token(input.MonitorEndpointID) || !canonicalClientDigest(input.BodyDigest) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	req, err := readUserMonitorClientRequestTx(tx, input.ClientRequestID)
	if err != nil {
		return nil, err
	}
	var oldID string
	err = tx.QueryRow(`SELECT preview_id FROM user_monitor_broadcast_v2 WHERE prepare_request_id=?`, req.id).Scan(&oldID)
	if err == nil {
		r, err := readUserMonitorBroadcastTx(tx, oldID)
		if err != nil {
			return nil, err
		}
		if r.GroupID != input.GroupID || r.MonitorEndpointID != input.MonitorEndpointID || r.BodyDigest != input.BodyDigest {
			return nil, ErrUserMonitorBroadcastV2Conflict
		}
		r.Snapshot, err = readSameGroupBroadcastV2SnapshotTx(tx, r.BroadcastID)
		if err != nil {
			return nil, err
		}
		if r.consentDigest != "" {
			r.Preview, err = decodedUserMonitorPreview(r.previewJSON, r.Snapshot, r.consentDigest)
			if err != nil {
				return nil, err
			}
			if err := verifyStoredUserMonitorPreviewTx(tx, r.Preview, r.Snapshot); err != nil {
				return nil, err
			}
		}
		if err := currentUserMonitorSnapshotTx(tx, r, time.Now().UTC()); err != nil {
			return nil, ErrUserMonitorBroadcastV2Denied
		}
		return r, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if req.status != ClientRequestProcessing {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	if _, err := readUserMonitorEnrollmentProofTx(tx, req); err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	nowTime := time.Now().UTC()
	if err := checkUserMonitorBroadcastV2IntakeTx(tx, req.ownerID, req.deviceID, nowTime); err != nil {
		return nil, err
	}
	source, err := currentUserMonitorSourceTx(tx, input.GroupID, input.MonitorEndpointID, req.ownerID, nowTime)
	if err != nil {
		return nil, err
	}
	previewID := NewID("umbprev")
	var broadcastRandom [16]byte
	if _, err = rand.Read(broadcastRandom[:]); err != nil {
		return nil, err
	}
	broadcastID := "bc_" + hex.EncodeToString(broadcastRandom[:])
	snapshot, err := buildSameGroupBroadcastV2SnapshotTx(tx, broadcastID, input.GroupID, source, nowTime)
	if err != nil {
		return nil, err
	}
	preview, err := userMonitorPreviewTx(tx, snapshot, nowTime)
	if err != nil {
		return nil, err
	}
	previewJSON, err := encodedUserMonitorPreview(preview)
	if err != nil {
		return nil, err
	}
	if err = insertSameGroupBroadcastV2SnapshotTx(tx, snapshot); err != nil {
		return nil, err
	}
	r := &UserMonitorBroadcastV2{PreviewID: previewID, BroadcastID: broadcastID, Status: UserMonitorBroadcastV2Prepared,
		OwnerID: req.ownerID, DeviceID: req.deviceID, SessionEpoch: req.epoch, ClientKeyVersion: req.keyVersion, GroupID: input.GroupID,
		MonitorEndpointID: input.MonitorEndpointID, MonitorKeyID: snapshot.Source.KeyID, BodyDigest: input.BodyDigest,
		SnapshotDigest: snapshot.SnapshotDigest, Snapshot: snapshot, Preview: preview,
		consentDigest: preview.ConsentSHA256, previewJSON: previewJSON,
		ExpiresAt: nowTime.Add(UserMonitorBroadcastV2TTL).Format(time.RFC3339Nano)}
	_, err = tx.Exec(`INSERT INTO user_monitor_broadcast_v2
(preview_id,broadcast_id,prepare_request_id,owner_id,device_id,session_epoch,client_key_version,group_id,
monitor_endpoint_id,monitor_key_id,body_digest,snapshot_digest,expires_at,status,consent_digest,preview_json)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'PREPARED',?,?)`, r.PreviewID, r.BroadcastID, req.id, r.OwnerID, r.DeviceID,
		r.SessionEpoch, r.ClientKeyVersion, r.GroupID, r.MonitorEndpointID, r.MonitorKeyID, r.BodyDigest, r.SnapshotDigest, r.ExpiresAt,
		r.consentDigest, r.previewJSON)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func userMonitorExpiry(record *UserMonitorBroadcastV2, nowTime time.Time) error {
	expiry, err := time.Parse(time.RFC3339Nano, record.ExpiresAt)
	if err != nil || !expiry.After(nowTime) {
		return ErrUserMonitorBroadcastV2Expired
	}
	return nil
}

func userMonitorBroadcastContext(req userMonitorClientRequest,
	r *UserMonitorBroadcastV2) e2ee.MonitorBroadcastContext {
	source := r.Snapshot.Source
	context := e2ee.MonitorBroadcastContext{
		HubID: req.hubID, OwnerID: r.OwnerID, ClientDeviceID: r.DeviceID,
		ClientSessionEpoch: r.SessionEpoch, ClientKeyVersion: r.ClientKeyVersion,
		ApprovalID: r.PreviewID, BroadcastID: r.BroadcastID, GroupID: r.GroupID,
		MonitorEndpointID: r.MonitorEndpointID, MonitorKeyID: source.KeyID,
		MonitorBindingID: source.BindingID, MonitorBindingEpoch: source.BindingEpoch,
		BodySHA256: r.BodyDigest, RecipientSnapshotSHA256: r.SnapshotDigest, ExpiresAt: r.ExpiresAt,
	}
	if r.consentDigest != "" {
		context.ConsentSHA256 = r.consentDigest
		context.ConfirmRequestSequence = req.sequence
	}
	return context
}

// GetUserMonitorBroadcastV2Status is scoped to a trusted authenticated Client
// request from the same device/session. Status never returns the sealed bytes.
func (s *Store) GetUserMonitorBroadcastV2Status(clientRequestID, previewID string) (*UserMonitorBroadcastV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	req, err := readUserMonitorClientRequestTx(tx, clientRequestID)
	if err != nil {
		return nil, err
	}
	r, err := readUserMonitorBroadcastTx(tx, previewID)
	if err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	if r.OwnerID != req.ownerID || r.DeviceID != req.deviceID || r.SessionEpoch != req.epoch ||
		r.ClientKeyVersion != req.keyVersion {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	r.SealedPayload = nil
	r.Snapshot, err = readSameGroupBroadcastV2SnapshotTx(tx, r.BroadcastID)
	if err != nil {
		return nil, err
	}
	if r.consentDigest != "" {
		r.Preview, err = decodedUserMonitorPreview(r.previewJSON, r.Snapshot, r.consentDigest)
		if err != nil {
			return nil, err
		}
		if err := verifyStoredUserMonitorPreviewTx(tx, r.Preview, r.Snapshot); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// RecoverUserMonitorBroadcastV2 retrieves the immutable prepared consent from
// the original outer operation ID after a lost response. The current accepted
// request supplies all authority; no caller-supplied device or owner is used.
func (s *Store) RecoverUserMonitorBroadcastV2(clientRequestID, prepareOperationID string) (*UserMonitorBroadcastV2, error) {
	if !validateClientDeviceToken(clientRequestID) || len(prepareOperationID) == 0 || len(prepareOperationID) > 256 {
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
		return nil, err
	}
	var previewID string
	err = tx.QueryRow(`SELECT broadcast.preview_id FROM user_monitor_broadcast_v2 broadcast
JOIN client_device_requests_v2 original ON original.id=broadcast.prepare_request_id
WHERE original.operation_id=? AND original.owner_id=? AND original.device_id=?
AND original.session_epoch=? AND broadcast.client_key_version=?
AND broadcast.owner_id=? AND broadcast.device_id=? AND broadcast.session_epoch=?`,
		prepareOperationID, req.ownerID, req.deviceID, req.epoch, req.keyVersion,
		req.ownerID, req.deviceID, req.epoch).Scan(&previewID)
	if err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	r, err := readUserMonitorBroadcastTx(tx, previewID)
	if err != nil || r.consentDigest == "" {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	r.Snapshot, err = readSameGroupBroadcastV2SnapshotTx(tx, r.BroadcastID)
	if err != nil {
		return nil, err
	}
	r.Preview, err = decodedUserMonitorPreview(r.previewJSON, r.Snapshot, r.consentDigest)
	if err != nil {
		return nil, err
	}
	if err := verifyStoredUserMonitorPreviewTx(tx, r.Preview, r.Snapshot); err != nil {
		return nil, err
	}
	r.SealedPayload = nil
	return r, nil
}

// ConfirmUserMonitorBroadcastV2 stores only the opaque sealed envelope. The
// crypto verification hook is supplied by the Monitor envelope implementation.
func (s *Store) ConfirmUserMonitorBroadcastV2(input ConfirmUserMonitorBroadcastV2Input) (*UserMonitorBroadcastV2, error) {
	if !validateClientDeviceToken(input.ClientRequestID) || !validSameGroupSealedV1Token(input.PreviewID) ||
		!canonicalClientDigest(input.SnapshotDigest) || !canonicalClientDigest(input.BodyDigest) ||
		len(input.SealedPayload) == 0 || len(input.SealedPayload) > UserMonitorBroadcastV2MaxSealedBytes {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	req, err := readUserMonitorClientRequestTx(tx, input.ClientRequestID)
	if err != nil {
		return nil, err
	}
	r, err := readUserMonitorBroadcastTx(tx, input.PreviewID)
	if err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	if r.OwnerID != req.ownerID || r.DeviceID != req.deviceID || r.SessionEpoch != req.epoch ||
		r.prepareRequestID == req.id || r.SnapshotDigest != input.SnapshotDigest || r.BodyDigest != input.BodyDigest {
		return nil, ErrUserMonitorBroadcastV2Conflict
	}
	payloadDigest := sha256.Sum256(input.SealedPayload)
	payloadDigestHex := hex.EncodeToString(payloadDigest[:])
	if r.Status != UserMonitorBroadcastV2Prepared {
		if r.confirmRequestID != req.id || r.SealedPayloadDigest != payloadDigestHex {
			return nil, ErrUserMonitorBroadcastV2Conflict
		}
		r.SealedPayload = nil
		return r, nil
	}
	if req.status != ClientRequestProcessing {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	nowTime := time.Now().UTC()
	if err := userMonitorExpiry(r, nowTime); err != nil {
		return nil, err
	}
	if err := currentUserMonitorSnapshotTx(tx, r, nowTime); err != nil {
		return nil, err
	}
	if req.keyVersion != r.ClientKeyVersion {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	sequence, err := e2ee.VerifyMonitorBroadcast(input.SealedPayload, req.devicePublic,
		r.Snapshot.Source.PublicKey, userMonitorBroadcastContext(req, r))
	if err != nil || sequence == 0 || sequence > uint64(^uint64(0)>>1) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	stamp := nowTime.Format(time.RFC3339Nano)
	_, err = tx.Exec(`UPDATE user_monitor_broadcast_v2 SET status='APPROVED',confirm_request_id=?,
approved_at=?,sealed_payload=?,sealed_payload_digest=?,sealed_sequence=? WHERE preview_id=? AND status='PREPARED'`,
		req.id, stamp, input.SealedPayload, payloadDigestHex, sequence, r.PreviewID)
	if isUniqueConstraintError(err) {
		return nil, ErrUserMonitorBroadcastV2Conflict
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	r.Status = UserMonitorBroadcastV2Approved
	r.ApprovedAt = stamp
	r.SealedPayload = nil
	r.SealedPayloadDigest = payloadDigestHex
	r.SealedSequence = sequence
	return r, nil
}

// AuthorizeUserMonitorBroadcastV2 consumes an approval for the exact current
// Monitor Node and Fabric session. An exact retry recovers the same operation.
func (s *Store) AuthorizeUserMonitorBroadcastV2(input AuthorizeUserMonitorBroadcastV2Input) (*UserMonitorBroadcastV2, error) {
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
	req, err := readUserMonitorHistoricalConfirmRequestTx(tx, r)
	if err != nil {
		return nil, err
	}
	if _, err := readUserMonitorEnrollmentProofTx(tx, req); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

type userMonitorBroadcastV2Guard struct {
	record      *UserMonitorBroadcastV2
	operationID string
	nodeID      string
	source      localDeliveryEndpointSnapshot
	now         time.Time
}

// guardUserMonitorBroadcastV2Tx is the shared, read-only authorization check
// for both evidence preview and dispatch reservation. It validates identity,
// expiry, original Client approval, current Monitor session, and exact current
// recipient snapshot without changing the ledger or creating outcomes.
func guardUserMonitorBroadcastV2Tx(tx *sql.Tx, nodeCredentialDigest, sessionCredentialDigest,
	previewID string, expected *AuthorizeUserMonitorBroadcastV2Input) (*userMonitorBroadcastV2Guard, error) {
	if !validNodeCredentialDigest(nodeCredentialDigest) || !validNodeCredentialDigest(sessionCredentialDigest) ||
		!validSameGroupSealedV1Token(previewID) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	r, err := readUserMonitorBroadcastTx(tx, previewID)
	if err != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	if (r.Status != UserMonitorBroadcastV2Approved && r.Status != UserMonitorBroadcastV2DispatchAuthorized) ||
		!validSameGroupSealedV1Token(r.BroadcastID) || !canonicalClientDigest(r.BodyDigest) ||
		!canonicalClientDigest(r.SnapshotDigest) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	operationID := "op_" + strings.TrimPrefix(r.BroadcastID, "bc_")
	if !validSameGroupSealedV1Token(operationID) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	if expected != nil {
		if !validSameGroupSealedV1Token(expected.BroadcastID) || !validSameGroupSealedV1Token(expected.OperationID) ||
			!canonicalClientDigest(expected.BodyDigest) || !canonicalClientDigest(expected.SnapshotDigest) {
			return nil, ErrUserMonitorBroadcastV2Denied
		}
		if r.BroadcastID != expected.BroadcastID || r.BodyDigest != expected.BodyDigest ||
			r.SnapshotDigest != expected.SnapshotDigest || operationID != expected.OperationID {
			return nil, ErrUserMonitorBroadcastV2Conflict
		}
	}
	nowTime := time.Now().UTC()
	nowText := nowTime.Format(time.RFC3339Nano)
	if err := userMonitorExpiry(r, nowTime); err != nil {
		return nil, err
	}
	if _, err := readUserMonitorHistoricalConfirmRequestTx(tx, r); err != nil {
		return nil, err
	}
	nodeID, nodeOwnerID, _, _, err := readCurrentBoundNodeOwnerTx(tx, nodeCredentialDigest)
	if err != nil || nodeOwnerID != r.OwnerID {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	source, err := readLocalDeliverySourceTx(tx, sessionCredentialDigest, r.GroupID, nowText)
	if err != nil || source.EndpointID != r.MonitorEndpointID || source.NodeID != nodeID || source.PrincipalOwnerID != r.OwnerID ||
		validateLocalDeliveryEndpointSnapshot(source, r.GroupID, nowTime) != nil {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	if err := currentUserMonitorSnapshotTx(tx, r, nowTime); err != nil {
		return nil, err
	}
	if r.Status == UserMonitorBroadcastV2DispatchAuthorized {
		if r.OperationID != operationID || r.consumeNodeID != nodeID ||
			r.consumeBindingID != source.BindingID || r.consumeBindingEpoch != source.BindingEpoch {
			return nil, ErrUserMonitorBroadcastV2Conflict
		}
	}
	return &userMonitorBroadcastV2Guard{record: r, operationID: operationID,
		nodeID: nodeID, source: source, now: nowTime}, nil
}

func authorizeUserMonitorBroadcastV2Tx(tx *sql.Tx, input AuthorizeUserMonitorBroadcastV2Input) (*UserMonitorBroadcastV2, error) {
	guard, err := guardUserMonitorBroadcastV2Tx(tx, input.NodeCredentialDigest,
		input.SessionCredentialDigest, input.PreviewID, &input)
	if err != nil {
		return nil, err
	}
	r := guard.record
	if r.Status == UserMonitorBroadcastV2DispatchAuthorized {
		if err := seedUserMonitorBroadcastOutcomesTx(tx, r); err != nil {
			return nil, err
		}
		return r, nil
	}
	nowText := guard.now.Format(time.RFC3339Nano)
	_, err = tx.Exec(`UPDATE user_monitor_broadcast_v2 SET status='DISPATCH_AUTHORIZED',operation_id=?,
consume_node_id=?,consume_binding_id=?,consume_binding_epoch=?,dispatch_authorized_at=?
WHERE preview_id=? AND status='APPROVED'`, guard.operationID, guard.nodeID,
		guard.source.BindingID, guard.source.BindingEpoch, nowText, r.PreviewID)
	if err != nil {
		return nil, err
	}
	r.Status = UserMonitorBroadcastV2DispatchAuthorized
	r.OperationID = guard.operationID
	r.DispatchAuthorizedAt = nowText
	if err := seedUserMonitorBroadcastOutcomesTx(tx, r); err != nil {
		return nil, err
	}
	return r, nil
}
