package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	ClientDeviceActive  = "ACTIVE"
	ClientDeviceRevoked = "REVOKED"

	ClientRequestProcessing = "PROCESSING"
	ClientRequestCompleted  = "COMPLETED"
	ClientRequestFailed     = "FAILED"
	ClientRequestUncertain  = "UNCERTAIN"

	ClientRequestOutcomeNew        = "NEW"
	ClientRequestOutcomeExactRetry = "EXACT_RETRY"
)

var (
	ErrClientDeviceNotFound       = errors.New("Client device not found")
	ErrClientDeviceConflict       = errors.New("Client device ID is already bound or revoked")
	ErrClientDeviceRevoked        = errors.New("Client device is revoked or its owner grant key is no longer active")
	ErrClientDeviceGrantReplay    = errors.New("owner device grant nonce was already used")
	ErrClientRequestConflict      = errors.New("Client request sequence or operation ID conflicts with accepted data")
	ErrClientRequestSequence      = errors.New("Client request sequence is not the next expected value")
	ErrClientRequestNotFound      = errors.New("Client request not found")
	ErrClientRequestStateConflict = errors.New("Client request state transition conflicts with current state")
)

type ClientDevice struct {
	OwnerID         string              `json:"owner_id"`
	DeviceID        string              `json:"device_id"`
	Public          e2ee.PublicIdentity `json:"public_identity"`
	KeyID           string              `json:"key_id"`
	KeyFingerprint  string              `json:"key_fingerprint"`
	KeyVersion      uint64              `json:"key_version"`
	OwnerKeyID      string              `json:"owner_key_id"`
	State           string              `json:"state"`
	Version         int64               `json:"version"`
	SessionEpoch    uint64              `json:"session_epoch"`
	LastRequestSeq  uint64              `json:"last_request_sequence"`
	NextResponseSeq uint64              `json:"next_response_sequence"`
	CreatedAt       string              `json:"created_at"`
	UpdatedAt       string              `json:"updated_at"`
	RevokedAt       string              `json:"revoked_at,omitempty"`
}

type RegisterClientDeviceInput struct {
	OwnerID          string
	OwnerKeyID       string
	DeviceID         string
	DevicePublic     e2ee.PublicIdentity
	OwnerDeviceGrant []byte
}

type AcceptClientRequestInput struct {
	OwnerID          string
	DeviceID         string
	SessionEpoch     uint64
	Sequence         uint64
	OperationID      string
	CiphertextDigest string
}

type ClientRequest struct {
	ID               string `json:"id"`
	OwnerID          string `json:"owner_id"`
	DeviceID         string `json:"device_id"`
	SessionEpoch     uint64 `json:"session_epoch"`
	Sequence         uint64 `json:"sequence"`
	OperationID      string `json:"operation_id"`
	CiphertextDigest string `json:"ciphertext_digest"`
	Status           string `json:"status"`
	ResponsePacket   []byte `json:"response_packet,omitempty"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

type ClientRequestAcceptance struct {
	Outcome string         `json:"outcome"`
	Request *ClientRequest `json:"request"`
}

func (s *Store) initializeClientDevicesV2Schema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS client_device_hub_config_v2 (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  hub_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS client_devices_v2 (
  owner_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  public_identity_json TEXT NOT NULL,
  key_id TEXT NOT NULL,
  key_fingerprint TEXT NOT NULL CHECK(length(key_fingerprint) = 64),
  key_version INTEGER NOT NULL CHECK(key_version > 0),
  owner_key_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'REVOKED')),
  version INTEGER NOT NULL CHECK(version > 0),
  session_epoch INTEGER NOT NULL CHECK(session_epoch > 0),
  last_request_sequence INTEGER NOT NULL DEFAULT 0 CHECK(last_request_sequence >= 0),
  next_response_sequence INTEGER NOT NULL DEFAULT 1 CHECK(next_response_sequence > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(owner_id, device_id),
  UNIQUE(owner_id, key_id),
  FOREIGN KEY(owner_id, owner_key_id) REFERENCES owner_approval_keys_v2(owner_id, key_id)
);
CREATE INDEX IF NOT EXISTS client_devices_v2_owner_state_idx
  ON client_devices_v2(owner_id, state, device_id);
CREATE TABLE IF NOT EXISTS client_device_grant_nonces_v2 (
  owner_id TEXT NOT NULL,
  owner_key_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  device_id TEXT NOT NULL,
  grant_digest TEXT NOT NULL CHECK(length(grant_digest) = 64),
  created_at TEXT NOT NULL,
  PRIMARY KEY(owner_id, owner_key_id, nonce),
  FOREIGN KEY(owner_id, owner_key_id) REFERENCES owner_approval_keys_v2(owner_id, key_id),
  FOREIGN KEY(owner_id, device_id) REFERENCES client_devices_v2(owner_id, device_id)
);
CREATE TABLE IF NOT EXISTS client_device_requests_v2 (
  id TEXT NOT NULL UNIQUE,
  owner_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  session_epoch INTEGER NOT NULL CHECK(session_epoch > 0),
  sequence INTEGER NOT NULL CHECK(sequence > 0),
  operation_id TEXT NOT NULL,
  ciphertext_digest TEXT NOT NULL CHECK(length(ciphertext_digest) = 64),
  status TEXT NOT NULL CHECK(status IN ('PROCESSING', 'COMPLETED', 'FAILED', 'UNCERTAIN')),
  response_packet BLOB,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK ((status = 'COMPLETED' AND response_packet IS NOT NULL) OR
         (status != 'COMPLETED' AND response_packet IS NULL)),
  CHECK (response_packet IS NULL OR length(response_packet) <= 262144),
  PRIMARY KEY(owner_id, device_id, session_epoch, sequence),
  UNIQUE(owner_id, device_id, operation_id),
  FOREIGN KEY(owner_id, device_id) REFERENCES client_devices_v2(owner_id, device_id)
);
CREATE INDEX IF NOT EXISTS client_device_requests_v2_status_idx
  ON client_device_requests_v2(owner_id, device_id, status, created_at);
`)
	if err != nil {
		return fmt.Errorf("initialize Client device identity and replay schema: %w", err)
	}
	_, err = s.db.Exec(`INSERT OR IGNORE INTO client_device_hub_config_v2(id, hub_id, created_at)
VALUES(1, ?, ?)`, NewID("hub"), now())
	if err != nil {
		return fmt.Errorf("persist stable Hub ID: %w", err)
	}
	return nil
}

func (s *Store) GetClientHubID() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var hubID string
	err := s.db.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id = 1`).Scan(&hubID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("stable Client Hub ID is not initialized")
	}
	return hubID, err
}

func validateClientDeviceToken(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "/\\") {
		return false
	}
	for _, char := range value {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func canonicalClientDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func scanClientDevice(row v2Scanner) (*ClientDevice, error) {
	var device ClientDevice
	var encoded string
	var keyVersion, sessionEpoch, lastRequestSequence, nextResponseSequence int64
	err := row.Scan(&device.OwnerID, &device.DeviceID, &encoded, &device.KeyID,
		&device.KeyFingerprint, &keyVersion, &device.OwnerKeyID, &device.State,
		&device.Version, &sessionEpoch, &lastRequestSequence, &nextResponseSequence,
		&device.CreatedAt, &device.UpdatedAt, &device.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClientDeviceNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(encoded), &device.Public); err != nil ||
		e2ee.ValidatePublicIdentity(device.Public) != nil || device.Public.ID != device.KeyID {
		return nil, ErrClientDeviceConflict
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(device.Public)
	if err != nil || fingerprint != device.KeyFingerprint || keyVersion <= 0 ||
		sessionEpoch <= 0 || lastRequestSequence < 0 || nextResponseSequence <= 0 {
		return nil, ErrClientDeviceConflict
	}
	device.KeyVersion = uint64(keyVersion)
	device.SessionEpoch = uint64(sessionEpoch)
	device.LastRequestSeq = uint64(lastRequestSequence)
	device.NextResponseSeq = uint64(nextResponseSequence)
	return &device, nil
}

const clientDeviceSelect = `SELECT owner_id, device_id, public_identity_json, key_id,
key_fingerprint, key_version, owner_key_id, state, version, session_epoch,
last_request_sequence, next_response_sequence, created_at, updated_at, revoked_at
FROM client_devices_v2`

func (s *Store) getClientDeviceLocked(ownerID, deviceID string) (*ClientDevice, error) {
	return scanClientDevice(s.db.QueryRow(clientDeviceSelect+` WHERE owner_id = ? AND device_id = ?`, ownerID, deviceID))
}

// RegisterClientDeviceFromOwnerGrant accepts only an owner signature verified
// against an ACTIVE key already stored in the Hub's local trust table. The Hub
// ID is read from persistent configuration, never from the grant packet.
func (s *Store) RegisterClientDeviceFromOwnerGrant(input RegisterClientDeviceInput) (*ClientDevice, error) {
	if err := validateOwnerApprovalID(input.OwnerID); err != nil {
		return nil, err
	}
	if !validateClientDeviceToken(input.OwnerKeyID) || !validateClientDeviceToken(input.DeviceID) {
		return nil, errors.New("Client device registration identity is invalid")
	}
	if err := e2ee.ValidatePublicIdentity(input.DevicePublic); err != nil {
		return nil, fmt.Errorf("validate Client device public key: %w", err)
	}
	publicJSON, err := json.Marshal(input.DevicePublic)
	if err != nil {
		return nil, err
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(input.DevicePublic)
	if err != nil {
		return nil, err
	}
	grantDigest := sha256.Sum256(input.OwnerDeviceGrant)
	stamp := now()

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var hubID string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id = 1`).Scan(&hubID); err != nil {
		return nil, fmt.Errorf("load authoritative Hub ID: %w", err)
	}
	ownerKey, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id, key_id, public_identity_json,
state, version, created_at, updated_at, revoked_at FROM owner_approval_keys_v2
WHERE owner_id = ? AND key_id = ?`, input.OwnerID, input.OwnerKeyID))
	if err != nil {
		return nil, err
	}
	if ownerKey.State != OwnerApprovalKeyActive {
		return nil, ErrOwnerApprovalKeyConflict
	}
	grant, err := e2ee.VerifyOwnerDeviceGrant(input.OwnerDeviceGrant, ownerKey.Public,
		input.DevicePublic, input.OwnerID, input.OwnerKeyID, input.DeviceID,
		hubID, e2ee.OwnerDevicePurposeControl, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("verify owner device grant: %w", err)
	}
	var existing int
	err = tx.QueryRow(`SELECT 1 FROM client_devices_v2 WHERE owner_id = ? AND device_id = ?`,
		input.OwnerID, input.DeviceID).Scan(&existing)
	if err == nil {
		return nil, ErrClientDeviceConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var nonceExists int
	err = tx.QueryRow(`SELECT 1 FROM client_device_grant_nonces_v2
WHERE owner_id = ? AND owner_key_id = ? AND nonce = ?`, input.OwnerID, input.OwnerKeyID, grant.Nonce).Scan(&nonceExists)
	if err == nil {
		return nil, ErrClientDeviceGrantReplay
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO client_devices_v2
(owner_id, device_id, public_identity_json, key_id, key_fingerprint, key_version,
 owner_key_id, state, version, session_epoch, last_request_sequence,
 next_response_sequence, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 1, ?, 'ACTIVE', 1, 1, 0, 1, ?, ?)`,
		input.OwnerID, input.DeviceID, string(publicJSON), input.DevicePublic.ID,
		fingerprint, input.OwnerKeyID, stamp, stamp)
	if err != nil {
		return nil, fmt.Errorf("register Client device: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO client_device_grant_nonces_v2
(owner_id, owner_key_id, nonce, device_id, grant_digest, created_at)
VALUES (?, ?, ?, ?, ?, ?)`, input.OwnerID, input.OwnerKeyID, grant.Nonce,
		input.DeviceID, hex.EncodeToString(grantDigest[:]), stamp)
	if err != nil {
		return nil, fmt.Errorf("consume owner device grant nonce: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getClientDeviceLocked(input.OwnerID, input.DeviceID)
}

func (s *Store) GetClientDevice(ownerID, deviceID string) (*ClientDevice, error) {
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	if !validateClientDeviceToken(deviceID) {
		return nil, ErrClientDeviceNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getClientDeviceLocked(ownerID, deviceID)
}

// ListClientDevices is an owner-scoped management view. It returns public
// identities and revocation versions, never private key material or grants.
func (s *Store) ListClientDevices(ownerID string) ([]ClientDevice, error) {
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(clientDeviceSelect+` WHERE owner_id = ? ORDER BY created_at DESC, device_id LIMIT 100`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := make([]ClientDevice, 0)
	for rows.Next() {
		device, err := scanClientDevice(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, *device)
	}
	return devices, rows.Err()
}

// RevokeClientDevice permanently fences a device ID and increments the
// version. The same owner/device ID cannot later be rebound to another key.
func (s *Store) RevokeClientDevice(ownerID, deviceID string, expectedVersion int64) (*ClientDevice, error) {
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	if !validateClientDeviceToken(deviceID) || expectedVersion <= 0 {
		return nil, ErrClientDeviceNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var state string
	var version, epoch int64
	err = tx.QueryRow(`SELECT state, version, session_epoch FROM client_devices_v2
WHERE owner_id = ? AND device_id = ?`, ownerID, deviceID).Scan(&state, &version, &epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClientDeviceNotFound
	}
	if err != nil {
		return nil, err
	}
	if state != ClientDeviceActive || version != expectedVersion {
		return nil, ErrVersionConflict
	}
	if epoch >= int64(^uint64(0)>>1) || version >= int64(^uint64(0)>>1) {
		return nil, errors.New("Client device epoch or version is exhausted")
	}
	stamp := now()
	result, err := tx.Exec(`UPDATE client_devices_v2 SET state = 'REVOKED', version = version + 1,
session_epoch = session_epoch + 1, updated_at = ?, revoked_at = ?
WHERE owner_id = ? AND device_id = ? AND state = 'ACTIVE' AND version = ?`,
		stamp, stamp, ownerID, deviceID, expectedVersion)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, ErrVersionConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getClientDeviceLocked(ownerID, deviceID)
}

// AdvanceClientDeviceSessionEpoch fences every packet from the preceding
// session and resets per-session request/response counters atomically.
func (s *Store) AdvanceClientDeviceSessionEpoch(ownerID, deviceID string, expectedEpoch uint64) (*ClientDevice, error) {
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	if !validateClientDeviceToken(deviceID) || expectedEpoch == 0 || expectedEpoch > uint64(^uint64(0)>>1) {
		return nil, ErrClientDeviceNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var state, ownerKeyState string
	var epoch, version int64
	err = tx.QueryRow(`SELECT d.state, d.session_epoch, d.version, k.state
FROM client_devices_v2 d JOIN owner_approval_keys_v2 k
ON k.owner_id = d.owner_id AND k.key_id = d.owner_key_id
WHERE d.owner_id = ? AND d.device_id = ?`, ownerID, deviceID).Scan(&state, &epoch, &version, &ownerKeyState)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClientDeviceNotFound
	}
	if err != nil {
		return nil, err
	}
	if state != ClientDeviceActive || ownerKeyState != OwnerApprovalKeyActive {
		return nil, ErrClientDeviceRevoked
	}
	if epoch != int64(expectedEpoch) {
		return nil, ErrVersionConflict
	}
	if epoch >= int64(^uint64(0)>>1) || version >= int64(^uint64(0)>>1) {
		return nil, errors.New("Client device epoch or version is exhausted")
	}
	result, err := tx.Exec(`UPDATE client_devices_v2 SET session_epoch = session_epoch + 1,
version = version + 1, last_request_sequence = 0, next_response_sequence = 1, updated_at = ?
WHERE owner_id = ? AND device_id = ? AND state = 'ACTIVE' AND session_epoch = ?`,
		now(), ownerID, deviceID, expectedEpoch)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, ErrVersionConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getClientDeviceLocked(ownerID, deviceID)
}

// AcceptClientRequest atomically records authenticated request metadata and
// its ciphertext digest. It never stores decrypted request content. NEW is
// returned exactly once; an exact retransmission returns EXACT_RETRY and must
// not be dispatched again. A row left PROCESSING after restart is an
// intentionally durable recovery signal, not permission to re-execute.
func (s *Store) AcceptClientRequest(input AcceptClientRequestInput) (*ClientRequestAcceptance, error) {
	if err := validateOwnerApprovalID(input.OwnerID); err != nil {
		return nil, err
	}
	if !validateClientDeviceToken(input.DeviceID) || !validateClientDeviceToken(input.OperationID) ||
		input.SessionEpoch == 0 || input.Sequence == 0 ||
		input.SessionEpoch > uint64(^uint64(0)>>1) || input.Sequence > uint64(^uint64(0)>>1) ||
		!canonicalClientDigest(input.CiphertextDigest) {
		return nil, errors.New("invalid authenticated Client request metadata")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var deviceState, ownerKeyState string
	var epoch, lastSequence int64
	err = tx.QueryRow(`SELECT d.state, d.session_epoch, d.last_request_sequence, k.state
FROM client_devices_v2 d JOIN owner_approval_keys_v2 k
ON k.owner_id = d.owner_id AND k.key_id = d.owner_key_id
WHERE d.owner_id = ? AND d.device_id = ?`, input.OwnerID, input.DeviceID).
		Scan(&deviceState, &epoch, &lastSequence, &ownerKeyState)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClientDeviceNotFound
	}
	if err != nil {
		return nil, err
	}
	if deviceState != ClientDeviceActive || ownerKeyState != OwnerApprovalKeyActive {
		return nil, ErrClientDeviceRevoked
	}
	if epoch != int64(input.SessionEpoch) {
		return nil, ErrVersionConflict
	}
	request, lookupErr := scanClientRequest(tx.QueryRow(`SELECT id, owner_id, device_id, session_epoch,
sequence, operation_id, ciphertext_digest, status, response_packet, created_at, updated_at
FROM client_device_requests_v2 WHERE owner_id = ? AND device_id = ? AND session_epoch = ? AND sequence = ?`,
		input.OwnerID, input.DeviceID, input.SessionEpoch, input.Sequence))
	if lookupErr == nil {
		if request.OperationID != input.OperationID || request.CiphertextDigest != input.CiphertextDigest {
			return nil, ErrClientRequestConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &ClientRequestAcceptance{Outcome: ClientRequestOutcomeExactRetry, Request: request}, nil
	}
	if !errors.Is(lookupErr, ErrClientRequestNotFound) {
		return nil, lookupErr
	}
	var operationRow int
	err = tx.QueryRow(`SELECT 1 FROM client_device_requests_v2
WHERE owner_id = ? AND device_id = ? AND operation_id = ?`,
		input.OwnerID, input.DeviceID, input.OperationID).Scan(&operationRow)
	if err == nil {
		return nil, ErrClientRequestConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if input.Sequence != uint64(lastSequence)+1 {
		return nil, ErrClientRequestSequence
	}
	stamp := now()
	request = &ClientRequest{ID: NewID("clientreq"), OwnerID: input.OwnerID,
		DeviceID: input.DeviceID, SessionEpoch: input.SessionEpoch, Sequence: input.Sequence,
		OperationID: input.OperationID, CiphertextDigest: input.CiphertextDigest,
		Status: ClientRequestProcessing, CreatedAt: stamp, UpdatedAt: stamp}
	updatedDevice, err := tx.Exec(`UPDATE client_devices_v2 SET last_request_sequence = ?, updated_at = ?
WHERE owner_id = ? AND device_id = ? AND state = 'ACTIVE' AND session_epoch = ? AND last_request_sequence = ?`,
		input.Sequence, stamp, input.OwnerID, input.DeviceID, input.SessionEpoch, lastSequence)
	if err != nil {
		return nil, err
	}
	deviceChanged, err := updatedDevice.RowsAffected()
	if err != nil || deviceChanged != 1 {
		return nil, ErrClientRequestSequence
	}
	_, err = tx.Exec(`INSERT INTO client_device_requests_v2
(id, owner_id, device_id, session_epoch, sequence, operation_id, ciphertext_digest,
 status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'PROCESSING', ?, ?)`,
		request.ID, request.OwnerID, request.DeviceID, request.SessionEpoch, request.Sequence,
		request.OperationID, request.CiphertextDigest, stamp, stamp)
	if err != nil {
		return nil, fmt.Errorf("persist Client request replay state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ClientRequestAcceptance{Outcome: ClientRequestOutcomeNew, Request: request}, nil
}

func scanClientRequest(row v2Scanner) (*ClientRequest, error) {
	var request ClientRequest
	var epoch, sequence int64
	err := row.Scan(&request.ID, &request.OwnerID, &request.DeviceID, &epoch,
		&sequence, &request.OperationID, &request.CiphertextDigest, &request.Status,
		&request.ResponsePacket, &request.CreatedAt, &request.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClientRequestNotFound
	}
	if err != nil {
		return nil, err
	}
	if epoch <= 0 || sequence <= 0 || !canonicalClientDigest(request.CiphertextDigest) {
		return nil, ErrClientRequestConflict
	}
	request.SessionEpoch = uint64(epoch)
	request.Sequence = uint64(sequence)
	return &request, nil
}

func (s *Store) GetClientRequestByOperationID(ownerID, deviceID, operationID string) (*ClientRequest, error) {
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	if !validateClientDeviceToken(deviceID) || !validateClientDeviceToken(operationID) {
		return nil, ErrClientRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanClientRequest(s.db.QueryRow(`SELECT id, owner_id, device_id, session_epoch,
sequence, operation_id, ciphertext_digest, status, response_packet, created_at, updated_at
FROM client_device_requests_v2 WHERE owner_id = ? AND device_id = ? AND operation_id = ?`,
		ownerID, deviceID, operationID))
}

// MarkInterruptedClientRequestsUncertain must run once during Hub startup,
// before dispatch is enabled. It fences operations left PROCESSING by a prior
// process so a restarted dispatcher cannot mistake them for new work.
func (s *Store) MarkInterruptedClientRequestsUncertain() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE client_device_requests_v2 SET status = 'UNCERTAIN', updated_at = ?
WHERE status = 'PROCESSING'`, now())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// UpdateClientRequestStatus allows the dispatcher/recovery worker to record a
// non-sensitive outcome. Only PROCESSING can transition, preventing retries
// from reopening a terminal or uncertain operation.
func (s *Store) UpdateClientRequestStatus(ownerID, deviceID, operationID, nextStatus string) (*ClientRequest, error) {
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	if !validateClientDeviceToken(deviceID) || !validateClientDeviceToken(operationID) ||
		(nextStatus != ClientRequestFailed && nextStatus != ClientRequestUncertain) {
		return nil, ErrClientRequestStateConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE client_device_requests_v2 SET status = ?, updated_at = ?
WHERE owner_id = ? AND device_id = ? AND operation_id = ? AND status = 'PROCESSING'`,
		nextStatus, now(), ownerID, deviceID, operationID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed == 0 {
		_, getErr := scanClientRequest(s.db.QueryRow(`SELECT id, owner_id, device_id, session_epoch,
sequence, operation_id, ciphertext_digest, status, response_packet, created_at, updated_at
FROM client_device_requests_v2 WHERE owner_id = ? AND device_id = ? AND operation_id = ?`,
			ownerID, deviceID, operationID))
		if errors.Is(getErr, ErrClientRequestNotFound) {
			return nil, ErrClientRequestNotFound
		}
		return nil, ErrClientRequestStateConflict
	}
	return scanClientRequest(s.db.QueryRow(`SELECT id, owner_id, device_id, session_epoch,
sequence, operation_id, ciphertext_digest, status, response_packet, created_at, updated_at
FROM client_device_requests_v2 WHERE owner_id = ? AND device_id = ? AND operation_id = ?`,
		ownerID, deviceID, operationID))
}

// CompleteClientRequestWithSealedResponse atomically saves a sealed response
// packet and marks the request complete. Exact retries can return the same
// bytes without rerunning the operation; plaintext must never be passed here.
func (s *Store) CompleteClientRequestWithSealedResponse(ownerID, deviceID, operationID string, responsePacket []byte) (*ClientRequest, error) {
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	if !validateClientDeviceToken(deviceID) || !validateClientDeviceToken(operationID) ||
		len(responsePacket) == 0 || len(responsePacket) > 256*1024 {
		return nil, ErrClientRequestStateConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE client_device_requests_v2 SET status = 'COMPLETED',
response_packet = ?, updated_at = ? WHERE owner_id = ? AND device_id = ? AND operation_id = ?
AND status = 'PROCESSING'`, responsePacket, now(), ownerID, deviceID, operationID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed == 0 {
		request, getErr := scanClientRequest(tx.QueryRow(`SELECT id, owner_id, device_id,
session_epoch, sequence, operation_id, ciphertext_digest, status, response_packet,
created_at, updated_at FROM client_device_requests_v2
WHERE owner_id = ? AND device_id = ? AND operation_id = ?`, ownerID, deviceID, operationID))
		if getErr != nil {
			return nil, getErr
		}
		if request.Status != ClientRequestCompleted || !bytes.Equal(request.ResponsePacket, responsePacket) {
			return nil, ErrClientRequestStateConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return request, nil
	}
	request, err := scanClientRequest(tx.QueryRow(`SELECT id, owner_id, device_id, session_epoch,
sequence, operation_id, ciphertext_digest, status, response_packet, created_at, updated_at
FROM client_device_requests_v2 WHERE owner_id = ? AND device_id = ? AND operation_id = ?`,
		ownerID, deviceID, operationID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

// AllocateClientResponseSequence durably reserves the next Hub-to-device
// sequence for the active session before a response is sealed or sent.
func (s *Store) AllocateClientResponseSequence(ownerID, deviceID string, expectedEpoch uint64) (uint64, error) {
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return 0, err
	}
	if !validateClientDeviceToken(deviceID) || expectedEpoch == 0 || expectedEpoch > uint64(^uint64(0)>>1) {
		return 0, ErrClientDeviceNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var state, ownerKeyState string
	var epoch, next int64
	err = tx.QueryRow(`SELECT d.state, d.session_epoch, d.next_response_sequence, k.state
FROM client_devices_v2 d JOIN owner_approval_keys_v2 k
ON k.owner_id = d.owner_id AND k.key_id = d.owner_key_id
WHERE d.owner_id = ? AND d.device_id = ?`, ownerID, deviceID).Scan(&state, &epoch, &next, &ownerKeyState)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrClientDeviceNotFound
	}
	if err != nil {
		return 0, err
	}
	if state != ClientDeviceActive || ownerKeyState != OwnerApprovalKeyActive {
		return 0, ErrClientDeviceRevoked
	}
	if epoch != int64(expectedEpoch) {
		return 0, ErrVersionConflict
	}
	if next <= 0 || next >= int64(^uint64(0)>>1) {
		return 0, errors.New("Client response sequence is exhausted")
	}
	updatedDevice, err := tx.Exec(`UPDATE client_devices_v2 SET next_response_sequence = next_response_sequence + 1,
updated_at = ? WHERE owner_id = ? AND device_id = ? AND state = 'ACTIVE'
AND session_epoch = ? AND next_response_sequence = ?`, now(), ownerID, deviceID, expectedEpoch, next)
	if err != nil {
		return 0, err
	}
	changed, err := updatedDevice.RowsAffected()
	if err != nil || changed != 1 {
		return 0, ErrVersionConflict
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return uint64(next), nil
}
