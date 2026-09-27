package store

import (
	"database/sql"
	"errors"
	"fmt"
)

var ErrClientRequestRecoveryUnavailable = errors.New("Client request predates durable response reservation")

type ClientRequestRecovery struct {
	Request                  *ClientRequest
	ReservedResponseSequence uint64
	RecoveryPacket           []byte
	Supported                bool
}

// This table records response reservations separately from the v18 request
// ledger. Existing requests are intentionally not backfilled: their missing
// response sequence cannot be inferred safely after an interrupted write.
func (s *Store) initializeClientRequestRecoveryV2Schema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS client_device_request_recovery_v2 (
  request_id TEXT PRIMARY KEY,
  reserved_response_sequence INTEGER CHECK(reserved_response_sequence > 0),
  recovery_packet BLOB CHECK(recovery_packet IS NULL OR length(recovery_packet) <= 262144),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK(recovery_packet IS NULL OR reserved_response_sequence IS NOT NULL),
  FOREIGN KEY(request_id) REFERENCES client_device_requests_v2(id)
);`)
	if err != nil {
		return fmt.Errorf("initialize Client request recovery schema: %w", err)
	}
	return nil
}

func validateRecoveryLookup(input AcceptClientRequestInput) error {
	if err := validateOwnerApprovalID(input.OwnerID); err != nil {
		return err
	}
	if !validateClientDeviceToken(input.DeviceID) || !validateClientDeviceToken(input.OperationID) ||
		input.SessionEpoch == 0 || input.Sequence == 0 ||
		input.SessionEpoch > uint64(^uint64(0)>>1) || input.Sequence > uint64(^uint64(0)>>1) ||
		!canonicalClientDigest(input.CiphertextDigest) {
		return ErrClientRequestConflict
	}
	return nil
}

// clientRecoveryDevice checks the current authority inside the same transaction
// as the request lookup or response reservation. A signed old packet does not
// regain authority after revocation or a session-epoch change.
func clientRecoveryDevice(tx *sql.Tx, input AcceptClientRequestInput) (lastRequest, nextResponse int64, err error) {
	var state, ownerKeyState string
	var epoch int64
	err = tx.QueryRow(`SELECT d.state, k.state, d.session_epoch,
d.last_request_sequence, d.next_response_sequence
FROM client_devices_v2 d JOIN owner_approval_keys_v2 k
ON k.owner_id=d.owner_id AND k.key_id=d.owner_key_id
WHERE d.owner_id=? AND d.device_id=?`, input.OwnerID, input.DeviceID).
		Scan(&state, &ownerKeyState, &epoch, &lastRequest, &nextResponse)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrClientDeviceNotFound
	}
	if err != nil {
		return 0, 0, err
	}
	if state != ClientDeviceActive || ownerKeyState != OwnerApprovalKeyActive {
		return 0, 0, ErrClientDeviceRevoked
	}
	if epoch != int64(input.SessionEpoch) {
		return 0, 0, ErrVersionConflict
	}
	return lastRequest, nextResponse, nil
}

func clientRecoveryRow(tx *sql.Tx, input AcceptClientRequestInput) (*ClientRequestRecovery, error) {
	request, err := scanClientRequest(tx.QueryRow(`SELECT id, owner_id, device_id, session_epoch,
sequence, operation_id, ciphertext_digest, status, response_packet, created_at, updated_at
FROM client_device_requests_v2 WHERE owner_id=? AND device_id=? AND operation_id=?`,
		input.OwnerID, input.DeviceID, input.OperationID))
	if err != nil {
		return nil, err
	}
	if request.SessionEpoch != input.SessionEpoch || request.Sequence != input.Sequence ||
		request.CiphertextDigest != input.CiphertextDigest {
		return nil, ErrClientRequestConflict
	}
	result := &ClientRequestRecovery{Request: request}
	var reserved sql.NullInt64
	err = tx.QueryRow(`SELECT reserved_response_sequence, recovery_packet
FROM client_device_request_recovery_v2 WHERE request_id=?`, request.ID).
		Scan(&reserved, &result.RecoveryPacket)
	if errors.Is(err, sql.ErrNoRows) {
		return result, nil // v18-v28 historical row: no safe response reservation.
	}
	if err != nil {
		return nil, err
	}
	result.Supported = true
	if reserved.Valid {
		if reserved.Int64 <= 0 {
			return nil, ErrClientRequestStateConflict
		}
		result.ReservedResponseSequence = uint64(reserved.Int64)
	}
	return result, nil
}

// LookupClientRequestRecovery authenticates an exact previously accepted
// ciphertext digest and current device authority. It does not accept a new
// request or dispatch business logic. A legacy UNCERTAIN row is visible as
// Supported=false so it can be reported without inventing a missing sequence.
func (s *Store) LookupClientRequestRecovery(input AcceptClientRequestInput) (*ClientRequestRecovery, error) {
	if err := validateRecoveryLookup(input); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	lastRequest, _, err := clientRecoveryDevice(tx, input)
	if err != nil {
		return nil, err
	}
	result, err := clientRecoveryRow(tx, input)
	if err != nil {
		return nil, err
	}
	if (result.Request.Status == ClientRequestUncertain || result.Request.Status == ClientRequestFailed) &&
		lastRequest != int64(input.Sequence) {
		return nil, ErrClientRequestStateConflict
	}
	return result, tx.Commit()
}

// ReserveClientRequestResponseSequence binds one response sequence to a
// request before sealing. If the Hub crashes after this commit but before
// caching a response, recovery reuses the same sequence. Legacy rows without
// the v29 marker are deliberately not inferred or silently advanced.
func (s *Store) ReserveClientRequestResponseSequence(input AcceptClientRequestInput) (uint64, error) {
	if err := validateRecoveryLookup(input); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	lastRequest, nextResponse, err := clientRecoveryDevice(tx, input)
	if err != nil {
		return 0, err
	}
	result, err := clientRecoveryRow(tx, input)
	if err != nil {
		return 0, err
	}
	if !result.Supported {
		return 0, ErrClientRequestRecoveryUnavailable
	}
	if result.Request.Status != ClientRequestProcessing && result.Request.Status != ClientRequestUncertain &&
		result.Request.Status != ClientRequestFailed {
		return 0, ErrClientRequestStateConflict
	}
	if result.Request.Status != ClientRequestProcessing && lastRequest != int64(input.Sequence) {
		return 0, ErrClientRequestStateConflict
	}
	if result.ReservedResponseSequence != 0 {
		return result.ReservedResponseSequence, tx.Commit()
	}
	if nextResponse <= 0 || nextResponse >= int64(^uint64(0)>>1) {
		return 0, ErrClientRequestStateConflict
	}
	updated, err := tx.Exec(`UPDATE client_devices_v2 SET next_response_sequence=next_response_sequence+1,
updated_at=? WHERE owner_id=? AND device_id=? AND session_epoch=? AND
next_response_sequence=? AND state='ACTIVE'`, now(), input.OwnerID, input.DeviceID,
		input.SessionEpoch, nextResponse)
	if err != nil {
		return 0, err
	}
	if count, err := updated.RowsAffected(); err != nil || count != 1 {
		return 0, ErrVersionConflict
	}
	updated, err = tx.Exec(`UPDATE client_device_request_recovery_v2
SET reserved_response_sequence=?, updated_at=? WHERE request_id=? AND reserved_response_sequence IS NULL`,
		nextResponse, now(), result.Request.ID)
	if err != nil {
		return 0, err
	}
	if count, err := updated.RowsAffected(); err != nil || count != 1 {
		return 0, ErrClientRequestStateConflict
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return uint64(nextResponse), nil
}

// CacheClientRequestRecoveryPacket records a sealed uncertainty notice before
// it can be sent. The original request remains UNCERTAIN/FAILED: a transport
// notice must not be mistaken for proof that the business action succeeded.
func (s *Store) CacheClientRequestRecoveryPacket(input AcceptClientRequestInput, sequence uint64, sealed []byte) ([]byte, error) {
	if err := validateRecoveryLookup(input); err != nil {
		return nil, err
	}
	if sequence == 0 || sequence > uint64(^uint64(0)>>1) || len(sealed) == 0 || len(sealed) > 256*1024 {
		return nil, ErrClientRequestStateConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	lastRequest, _, err := clientRecoveryDevice(tx, input)
	if err != nil {
		return nil, err
	}
	result, err := clientRecoveryRow(tx, input)
	if err != nil {
		return nil, err
	}
	if !result.Supported || result.ReservedResponseSequence != sequence ||
		(result.Request.Status != ClientRequestUncertain && result.Request.Status != ClientRequestFailed) ||
		lastRequest != int64(input.Sequence) {
		return nil, ErrClientRequestStateConflict
	}
	if len(result.RecoveryPacket) != 0 {
		return result.RecoveryPacket, tx.Commit()
	}
	updated, err := tx.Exec(`UPDATE client_device_request_recovery_v2 SET recovery_packet=?, updated_at=?
WHERE request_id=? AND reserved_response_sequence=? AND recovery_packet IS NULL`,
		sealed, now(), result.Request.ID, sequence)
	if err != nil {
		return nil, err
	}
	if count, err := updated.RowsAffected(); err != nil || count != 1 {
		return nil, ErrClientRequestStateConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return sealed, nil
}
