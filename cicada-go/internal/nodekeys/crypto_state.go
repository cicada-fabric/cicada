package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

const (
	cryptoStateDBName   = "node-crypto-state.sqlite"
	cryptoStateMode     = 0o700
	cryptoDBMode        = 0o600
	cryptoBusyTimeout   = 30000
	maxCryptoIDLength   = 256
	maxWireEnvelope     = 1 << 20
	maxSQLiteSequence   = int64(^uint64(0) >> 1)
	cryptoSchemaVersion = 5
)

var (
	// ErrCryptoStateClosed means the state handle has already been closed.
	ErrCryptoStateClosed = errors.New("node crypto state is closed")
	// ErrCryptoStateNotFound means the requested outbound envelope is absent.
	ErrCryptoStateNotFound = errors.New("node crypto state record not found")
	// ErrOutboundConflict means an operation ID and source key were reused for
	// different endpoint or envelope bytes.
	ErrOutboundConflict = errors.New("node crypto outbox conflict")
	// ErrInboundReplayConflict means an inbound message ID or sequence was
	// reused with a different immutable message identity.
	ErrInboundReplayConflict = errors.New("node crypto inbound replay conflict")
	// ErrInboundRecoveryRequired means an older replay record has no durable
	// ciphertext. A retry cannot be treated as consumed until reconciled.
	ErrInboundRecoveryRequired = errors.New("node crypto inbound replay lacks recoverable ciphertext")
	// ErrSequenceExhausted means the signed SQLite sequence space is exhausted.
	ErrSequenceExhausted = errors.New("node crypto outbound sequence exhausted")
)

// OutboundRecord is an immutable, durable copy of one opaque encrypted
// envelope. Envelope contains the exact bytes supplied to StoreOutbound.
// Digest is the lowercase SHA-256 digest of those bytes.
type OutboundRecord struct {
	OperationID      string
	SourceEndpointID string
	SourceKeyID      string
	Digest           string
	Envelope         []byte
}

// InboundRecord is the exact authenticated ciphertext committed alongside its
// replay identity. It contains no decrypted message body.
type InboundRecord struct {
	ReceiverEndpointID string
	SenderKeyID        string
	MessageID          string
	Sequence           uint64
	Digest             string
	Envelope           []byte
}

// CryptoState contains Node-local sequence, outbox, replay and verified peer
// pin metadata. It has no API for plaintext or private keys. Callers pass
// opaque envelope bytes produced by their cryptographic layer and persist them
// before sending.
type CryptoState struct {
	db     *sql.DB
	mu     sync.Mutex
	closed bool
}

// OpenCryptoState opens the Node-local crypto state database beneath stateDir.
// The directory is made private (0700) and the SQLite database is kept at
// 0600. SQLite uses WAL and FULL synchronous commits for durable state changes.
func OpenCryptoState(stateDir string) (*CryptoState, error) {
	root, err := cleanStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	if err := ensureStateDirectory(root); err != nil {
		return nil, err
	}
	if err := os.Chmod(root, cryptoStateMode); err != nil {
		return nil, fmt.Errorf("protect Node crypto state directory: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect Node crypto state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != cryptoStateMode {
		return nil, errors.New("Node crypto state directory must be a real 0700 directory")
	}

	dbPath := filepath.Join(root, cryptoStateDBName)
	if err := ensureCryptoDatabaseFile(dbPath); err != nil {
		return nil, err
	}
	if err := syncCryptoStateDirectory(root); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open Node crypto state database: %w", err)
	}
	// Each handle uses one connection. BEGIN IMMEDIATE still coordinates
	// independent handles and processes through SQLite's file lock.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	state := &CryptoState{db: db}
	if err := state.initialize(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(dbPath, cryptoDBMode); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("protect Node crypto state database: %w", err)
	}
	return state, nil
}

// Close releases the SQLite handle. It is safe to call more than once.
func (s *CryptoState) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

// ReserveOutboundSequence durably allocates the next sequence for one stable
// Endpoint and source-key identity. A sequence is consumed before it is
// returned; a crash may leave a gap, but a later call will never reuse it.
func (s *CryptoState) ReserveOutboundSequence(ctx context.Context, endpointID, sourceKeyID string) (uint64, error) {
	if err := validateEndpointID(endpointID); err != nil {
		return 0, err
	}
	if err := validateCryptoToken("source key ID", sourceKeyID); err != nil {
		return 0, err
	}
	if ctx == nil {
		return 0, errors.New("context is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return 0, err
	}

	var sequence int64
	err := s.writeTx(ctx, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx, `
INSERT OR IGNORE INTO node_crypto_sequences(endpoint_id, source_key_id, last_sequence)
VALUES (?, ?, 0)`, endpointID, sourceKeyID); err != nil {
			return fmt.Errorf("create outbound sequence state: %w", err)
		}
		if err := conn.QueryRowContext(ctx, `
SELECT last_sequence FROM node_crypto_sequences
WHERE endpoint_id = ? AND source_key_id = ?`, endpointID, sourceKeyID).Scan(&sequence); err != nil {
			return fmt.Errorf("read outbound sequence state: %w", err)
		}
		if sequence >= maxSQLiteSequence {
			return ErrSequenceExhausted
		}
		sequence++
		result, err := conn.ExecContext(ctx, `
UPDATE node_crypto_sequences SET last_sequence = ?
WHERE endpoint_id = ? AND source_key_id = ?`, sequence, endpointID, sourceKeyID)
		if err != nil {
			return fmt.Errorf("reserve outbound sequence: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			if err != nil {
				return fmt.Errorf("confirm outbound sequence reservation: %w", err)
			}
			return errors.New("outbound sequence state changed unexpectedly")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return uint64(sequence), nil
}

// StoreOutbound durably stores an exact encrypted envelope under the
// operation ID and source key. A retry with byte-identical input returns the
// original row and created=false. Reusing that identity with different bytes
// or another Endpoint returns ErrOutboundConflict. A successful return means
// the transaction committed and the caller may begin transport.
func (s *CryptoState) StoreOutbound(ctx context.Context, operationID, sourceEndpointID, sourceKeyID string, envelope []byte) (OutboundRecord, bool, error) {
	if err := validateCryptoToken("operation ID", operationID); err != nil {
		return OutboundRecord{}, false, err
	}
	if err := validateEndpointID(sourceEndpointID); err != nil {
		return OutboundRecord{}, false, err
	}
	if err := validateCryptoToken("source key ID", sourceKeyID); err != nil {
		return OutboundRecord{}, false, err
	}
	if err := validateEnvelope(envelope); err != nil {
		return OutboundRecord{}, false, err
	}
	if ctx == nil {
		return OutboundRecord{}, false, errors.New("context is required")
	}
	digest := sha256.Sum256(envelope)
	var record OutboundRecord
	created := false
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return OutboundRecord{}, false, err
	}
	err := s.writeTx(ctx, func(conn *sql.Conn) error {
		var storedEndpoint string
		var storedDigest, storedEnvelope []byte
		err := conn.QueryRowContext(ctx, `
SELECT source_endpoint_id, digest, envelope FROM node_crypto_outbox
WHERE operation_id = ? AND source_key_id = ?`, operationID, sourceKeyID).
			Scan(&storedEndpoint, &storedDigest, &storedEnvelope)
		if err == nil {
			if storedEndpoint != sourceEndpointID || !bytes.Equal(storedDigest, digest[:]) || !bytes.Equal(storedEnvelope, envelope) {
				return ErrOutboundConflict
			}
			record = OutboundRecord{OperationID: operationID, SourceEndpointID: storedEndpoint,
				SourceKeyID: sourceKeyID, Digest: hex.EncodeToString(storedDigest),
				Envelope: append([]byte(nil), storedEnvelope...)}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read outbound envelope: %w", err)
		}
		if _, err := conn.ExecContext(ctx, `
INSERT INTO node_crypto_outbox(operation_id, source_endpoint_id, source_key_id, digest, envelope)
VALUES (?, ?, ?, ?, ?)`, operationID, sourceEndpointID, sourceKeyID, digest[:], envelope); err != nil {
			return fmt.Errorf("persist outbound envelope: %w", err)
		}
		record = OutboundRecord{OperationID: operationID, SourceEndpointID: sourceEndpointID,
			SourceKeyID: sourceKeyID, Digest: hex.EncodeToString(digest[:]),
			Envelope: append([]byte(nil), envelope...)}
		created = true
		return nil
	})
	if err != nil {
		return OutboundRecord{}, false, err
	}
	return record, created, nil
}

// GetOutbound fetches the exact stored bytes so transport retries can reuse
// the original envelope instead of resealing with a reserved sequence.
func (s *CryptoState) GetOutbound(ctx context.Context, operationID, sourceKeyID string) (OutboundRecord, error) {
	if err := validateCryptoToken("operation ID", operationID); err != nil {
		return OutboundRecord{}, err
	}
	if err := validateCryptoToken("source key ID", sourceKeyID); err != nil {
		return OutboundRecord{}, err
	}
	if ctx == nil {
		return OutboundRecord{}, errors.New("context is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return OutboundRecord{}, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return OutboundRecord{}, fmt.Errorf("connect to Node crypto state: %w", err)
	}
	defer conn.Close()
	if err := configureCryptoConnection(ctx, conn); err != nil {
		return OutboundRecord{}, err
	}
	var record OutboundRecord
	var digest []byte
	err = conn.QueryRowContext(ctx, `
SELECT source_endpoint_id, digest, envelope FROM node_crypto_outbox
WHERE operation_id = ? AND source_key_id = ?`, operationID, sourceKeyID).
		Scan(&record.SourceEndpointID, &digest, &record.Envelope)
	if errors.Is(err, sql.ErrNoRows) {
		return OutboundRecord{}, ErrCryptoStateNotFound
	}
	if err != nil {
		return OutboundRecord{}, fmt.Errorf("read stored outbound envelope: %w", err)
	}
	record.OperationID = operationID
	record.SourceKeyID = sourceKeyID
	record.Digest = hex.EncodeToString(digest)
	actualDigest := sha256.Sum256(record.Envelope)
	if len(digest) != sha256.Size || !bytes.Equal(digest, actualDigest[:]) {
		return OutboundRecord{}, errors.New("stored outbound envelope digest is corrupt")
	}
	record.Envelope = append([]byte(nil), record.Envelope...)
	return record, nil
}

// AcceptInbound atomically records an already authenticated ciphertext and
// its replay identity. It returns duplicate=true only when the exact envelope
// is recoverable locally. Pre-v3 replay-only rows require explicit recovery;
// they cannot be mistaken for a safely persisted inbox message. Decryption
// and sender pinning are performed by the caller before this method is invoked.
func (s *CryptoState) AcceptInbound(ctx context.Context, receiverEndpointID, pinnedSenderKeyID, messageID string, sequence uint64, envelope []byte) (bool, error) {
	if err := validateEndpointID(receiverEndpointID); err != nil {
		return false, err
	}
	if err := validateCryptoToken("pinned sender key ID", pinnedSenderKeyID); err != nil {
		return false, err
	}
	if err := validateCryptoToken("message ID", messageID); err != nil {
		return false, err
	}
	if sequence == 0 || sequence > uint64(maxSQLiteSequence) {
		return false, errors.New("inbound sequence must be positive and fit SQLite state")
	}
	if err := validateEnvelope(envelope); err != nil {
		return false, err
	}
	if ctx == nil {
		return false, errors.New("context is required")
	}
	digest := sha256.Sum256(envelope)
	duplicate := false
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return false, err
	}
	err := s.writeTx(ctx, func(conn *sql.Conn) error {
		var storedDigest []byte
		var storedSequence int64
		err := conn.QueryRowContext(ctx, `
SELECT digest, sequence FROM node_crypto_replay
WHERE receiver_endpoint_id = ? AND sender_key_id = ? AND message_id = ?`,
			receiverEndpointID, pinnedSenderKeyID, messageID).Scan(&storedDigest, &storedSequence)
		if err == nil {
			if storedSequence != int64(sequence) || !bytes.Equal(storedDigest, digest[:]) {
				return ErrInboundReplayConflict
			}
			var storedEnvelope, inboxDigest []byte
			var inboxSequence int64
			err = conn.QueryRowContext(ctx, `
SELECT digest, sequence, envelope FROM node_crypto_inbox
WHERE receiver_endpoint_id = ? AND sender_key_id = ? AND message_id = ?`,
				receiverEndpointID, pinnedSenderKeyID, messageID).Scan(&inboxDigest, &inboxSequence, &storedEnvelope)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrInboundRecoveryRequired
			}
			if err != nil {
				return fmt.Errorf("read durable inbound envelope: %w", err)
			}
			if inboxSequence != storedSequence || !bytes.Equal(inboxDigest, storedDigest) ||
				!bytes.Equal(storedEnvelope, envelope) {
				return ErrInboundReplayConflict
			}
			duplicate = true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read inbound replay state: %w", err)
		}

		var priorMessageID string
		err = conn.QueryRowContext(ctx, `
SELECT message_id FROM node_crypto_replay
WHERE receiver_endpoint_id = ? AND sender_key_id = ? AND sequence = ?`,
			receiverEndpointID, pinnedSenderKeyID, int64(sequence)).Scan(&priorMessageID)
		if err == nil {
			return ErrInboundReplayConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check inbound sequence replay: %w", err)
		}
		if _, err := conn.ExecContext(ctx, `
INSERT INTO node_crypto_replay(receiver_endpoint_id, sender_key_id, message_id, digest, sequence)
VALUES (?, ?, ?, ?, ?)`, receiverEndpointID, pinnedSenderKeyID, messageID, digest[:], int64(sequence)); err != nil {
			return fmt.Errorf("persist inbound replay state: %w", err)
		}
		if _, err := conn.ExecContext(ctx, `
INSERT INTO node_crypto_inbox(receiver_endpoint_id, sender_key_id, message_id, digest, sequence, envelope, state, created_at)
VALUES (?, ?, ?, ?, ?, ?, 'RECEIVED', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`,
			receiverEndpointID, pinnedSenderKeyID, messageID, digest[:], int64(sequence), envelope); err != nil {
			return fmt.Errorf("persist inbound ciphertext: %w", err)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return duplicate, nil
}

// GetInbound returns exact ciphertext after a Node restart. A legacy replay
// record without ciphertext is reported separately from an unknown message.
func (s *CryptoState) GetInbound(ctx context.Context, receiverEndpointID, senderKeyID, messageID string) (InboundRecord, error) {
	if err := validateEndpointID(receiverEndpointID); err != nil {
		return InboundRecord{}, err
	}
	for label, value := range map[string]string{"sender key ID": senderKeyID, "message ID": messageID} {
		if err := validateCryptoToken(label, value); err != nil {
			return InboundRecord{}, err
		}
	}
	if ctx == nil {
		return InboundRecord{}, errors.New("context is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return InboundRecord{}, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return InboundRecord{}, err
	}
	defer conn.Close()
	if err := configureCryptoConnection(ctx, conn); err != nil {
		return InboundRecord{}, err
	}
	var record InboundRecord
	var digest []byte
	var sequence int64
	err = conn.QueryRowContext(ctx, `
SELECT digest, sequence, envelope FROM node_crypto_inbox
WHERE receiver_endpoint_id = ? AND sender_key_id = ? AND message_id = ?`,
		receiverEndpointID, senderKeyID, messageID).Scan(&digest, &sequence, &record.Envelope)
	if errors.Is(err, sql.ErrNoRows) {
		var legacyCount int
		if err := conn.QueryRowContext(ctx, `
SELECT COUNT(*) FROM node_crypto_replay
WHERE receiver_endpoint_id = ? AND sender_key_id = ? AND message_id = ?`,
			receiverEndpointID, senderKeyID, messageID).Scan(&legacyCount); err != nil {
			return InboundRecord{}, err
		}
		if legacyCount != 0 {
			return InboundRecord{}, ErrInboundRecoveryRequired
		}
		return InboundRecord{}, ErrCryptoStateNotFound
	}
	if err != nil {
		return InboundRecord{}, fmt.Errorf("read durable inbound ciphertext: %w", err)
	}
	actual := sha256.Sum256(record.Envelope)
	if sequence <= 0 || len(digest) != sha256.Size || !bytes.Equal(digest, actual[:]) {
		return InboundRecord{}, errors.New("stored inbound envelope digest is corrupt")
	}
	var replayDigest []byte
	var replaySequence int64
	if err := conn.QueryRowContext(ctx, `
SELECT digest, sequence FROM node_crypto_replay
WHERE receiver_endpoint_id = ? AND sender_key_id = ? AND message_id = ?`,
		receiverEndpointID, senderKeyID, messageID).Scan(&replayDigest, &replaySequence); err != nil {
		return InboundRecord{}, fmt.Errorf("read inbound replay identity: %w", err)
	}
	if replaySequence != sequence || !bytes.Equal(replayDigest, digest) {
		return InboundRecord{}, errors.New("stored inbound replay identity conflicts with ciphertext")
	}
	record.ReceiverEndpointID = receiverEndpointID
	record.SenderKeyID = senderKeyID
	record.MessageID = messageID
	record.Sequence = uint64(sequence)
	record.Digest = hex.EncodeToString(digest)
	record.Envelope = append([]byte(nil), record.Envelope...)
	return record, nil
}

func (s *CryptoState) checkOpen() error {
	if s == nil || s.closed || s.db == nil {
		return ErrCryptoStateClosed
	}
	return nil
}

func (s *CryptoState) initialize(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("connect to Node crypto state: %w", err)
	}
	defer conn.Close()
	if err := configureCryptoConnection(ctx, conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA journal_mode = WAL`); err != nil {
		return fmt.Errorf("enable Node crypto state WAL: %w", err)
	}
	_, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`)
	if err != nil {
		return fmt.Errorf("lock Node crypto state schema: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	if _, err := conn.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS node_crypto_schema (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  version INTEGER NOT NULL
);
INSERT OR IGNORE INTO node_crypto_schema(singleton, version) VALUES (1, 1);
CREATE TABLE IF NOT EXISTS node_crypto_sequences (
  endpoint_id TEXT NOT NULL,
  source_key_id TEXT NOT NULL,
  last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
  PRIMARY KEY (endpoint_id, source_key_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS node_crypto_outbox (
  operation_id TEXT NOT NULL,
  source_endpoint_id TEXT NOT NULL,
  source_key_id TEXT NOT NULL,
  digest BLOB NOT NULL CHECK (length(digest) = 32),
  envelope BLOB NOT NULL CHECK (length(envelope) > 0),
  PRIMARY KEY (operation_id, source_key_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS node_crypto_replay (
  receiver_endpoint_id TEXT NOT NULL,
  sender_key_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  digest BLOB NOT NULL CHECK (length(digest) = 32),
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  PRIMARY KEY (receiver_endpoint_id, sender_key_id, message_id),
  UNIQUE (receiver_endpoint_id, sender_key_id, sequence)
) WITHOUT ROWID;
`); err != nil {
		return fmt.Errorf("initialize Node crypto state schema: %w", err)
	}
	var version int
	if err := conn.QueryRowContext(ctx, `SELECT version FROM node_crypto_schema WHERE singleton = 1`).Scan(&version); err != nil {
		return fmt.Errorf("read Node crypto state schema version: %w", err)
	}
	if version >= 1 && version <= cryptoSchemaVersion {
		if _, err := conn.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS node_crypto_peer_pins (
  local_endpoint_id TEXT NOT NULL,
  local_group_id TEXT NOT NULL,
  peer_endpoint_id TEXT NOT NULL,
  peer_group_id TEXT NOT NULL,
  communication_link_id TEXT NOT NULL DEFAULT '',
  peer_principal_id TEXT NOT NULL,
  peer_owner_id TEXT NOT NULL,
  peer_key_id TEXT NOT NULL,
  peer_fingerprint TEXT NOT NULL,
  public_identity_json TEXT NOT NULL,
  peer_node_id TEXT NOT NULL,
  binding_id TEXT NOT NULL,
  binding_epoch INTEGER NOT NULL CHECK (binding_epoch > 0),
  attestation_digest TEXT NOT NULL,
  link_version INTEGER NOT NULL DEFAULT 0,
  manifest_digest TEXT NOT NULL DEFAULT '',
  link_expires_at TEXT NOT NULL DEFAULT '',
  source_grant_expires_at TEXT NOT NULL DEFAULT '',
  target_grant_expires_at TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL CHECK (version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (local_endpoint_id, local_group_id, peer_endpoint_id,
    peer_group_id, communication_link_id)
) WITHOUT ROWID;
`); err != nil {
			return fmt.Errorf("initialize Node-local verified peer pin schema: %w", err)
		}
		if version == 1 {
			if _, err := conn.ExecContext(ctx, `UPDATE node_crypto_schema SET version = 2 WHERE singleton = 1`); err != nil {
				return fmt.Errorf("upgrade Node crypto state schema from v1 to v2: %w", err)
			}
			version = 2
		}
	}
	if version == 2 || version == 3 || version == cryptoSchemaVersion {
		if _, err := conn.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS node_crypto_inbox (
  receiver_endpoint_id TEXT NOT NULL,
  sender_key_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  digest BLOB NOT NULL CHECK (length(digest) = 32),
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  envelope BLOB NOT NULL CHECK (length(envelope) > 0),
  state TEXT NOT NULL CHECK (state = 'RECEIVED'),
  created_at TEXT NOT NULL,
  PRIMARY KEY (receiver_endpoint_id, sender_key_id, message_id),
  UNIQUE (receiver_endpoint_id, sender_key_id, sequence)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS node_crypto_inbox_receiver_idx
  ON node_crypto_inbox(receiver_endpoint_id, created_at, message_id);
`); err != nil {
			return fmt.Errorf("initialize Node durable ciphertext inbox: %w", err)
		}
		if version == 2 {
			if _, err := conn.ExecContext(ctx, `UPDATE node_crypto_schema SET version = 3 WHERE singleton = 1`); err != nil {
				return fmt.Errorf("upgrade Node crypto state schema from v2 to v3: %w", err)
			}
			version = 3
		}
	}
	if version == 3 {
		if err := ensurePeerPinGrantColumns(ctx, conn); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `UPDATE node_crypto_schema SET version = 4 WHERE singleton = 1`); err != nil {
			return fmt.Errorf("upgrade Node crypto state schema from v3 to v4: %w", err)
		}
		version = 4
	}
	if version == 4 {
		if _, err := conn.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS node_crypto_owner_key_trust (
  owner_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  public_identity_json TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'REVOKED')),
  version INTEGER NOT NULL CHECK (version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (owner_id, key_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS node_crypto_owner_key_trust_state_idx
  ON node_crypto_owner_key_trust(owner_id, state, key_id);
`); err != nil {
			return fmt.Errorf("initialize Node-local owner key trust: %w", err)
		}
		if _, err := conn.ExecContext(ctx, `UPDATE node_crypto_schema SET version = 5 WHERE singleton = 1`); err != nil {
			return fmt.Errorf("upgrade Node crypto state schema from v4 to v5: %w", err)
		}
		version = 5
	}
	if version != cryptoSchemaVersion {
		return fmt.Errorf("unsupported Node crypto state schema version %d", version)
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit Node crypto state schema: %w", err)
	}
	committed = true
	return nil
}

func ensurePeerPinGrantColumns(ctx context.Context, conn *sql.Conn) error {
	columns := map[string]bool{}
	rows, err := conn.QueryContext(ctx, `PRAGMA table_info(node_crypto_peer_pins)`)
	if err != nil {
		return fmt.Errorf("inspect Node peer pin schema: %w", err)
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read Node peer pin schema: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate Node peer pin schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close Node peer pin schema inspection: %w", err)
	}
	for _, statement := range []struct {
		name string
		sql  string
	}{
		{"link_version", `ALTER TABLE node_crypto_peer_pins ADD COLUMN link_version INTEGER NOT NULL DEFAULT 0`},
		{"manifest_digest", `ALTER TABLE node_crypto_peer_pins ADD COLUMN manifest_digest TEXT NOT NULL DEFAULT ''`},
		{"link_expires_at", `ALTER TABLE node_crypto_peer_pins ADD COLUMN link_expires_at TEXT NOT NULL DEFAULT ''`},
		{"source_grant_expires_at", `ALTER TABLE node_crypto_peer_pins ADD COLUMN source_grant_expires_at TEXT NOT NULL DEFAULT ''`},
		{"target_grant_expires_at", `ALTER TABLE node_crypto_peer_pins ADD COLUMN target_grant_expires_at TEXT NOT NULL DEFAULT ''`},
	} {
		if columns[statement.name] {
			continue
		}
		if _, err := conn.ExecContext(ctx, statement.sql); err != nil {
			return fmt.Errorf("upgrade Node peer pin schema with %s: %w", statement.name, err)
		}
	}
	return nil
}

func (s *CryptoState) writeTx(ctx context.Context, action func(*sql.Conn) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("connect to Node crypto state: %w", err)
	}
	defer conn.Close()
	if err := configureCryptoConnection(ctx, conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("begin Node crypto state transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	if err := action(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit Node crypto state transaction: %w", err)
	}
	committed = true
	return nil
}

func configureCryptoConnection(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA busy_timeout = %d`, cryptoBusyTimeout)); err != nil {
		return fmt.Errorf("configure Node crypto state busy timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA synchronous = FULL`); err != nil {
		return fmt.Errorf("configure Node crypto state synchronous commits: %w", err)
	}
	return nil
}

func validateCryptoToken(label, value string) error {
	if value == "" || len(value) > maxCryptoIDLength || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return fmt.Errorf("%s must be a non-empty canonical identifier", label)
	}
	for _, char := range value {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return fmt.Errorf("%s contains whitespace or control characters", label)
		}
	}
	return nil
}

func validateEnvelope(envelope []byte) error {
	if len(envelope) == 0 || len(envelope) > maxWireEnvelope {
		return errors.New("encrypted envelope must be between 1 byte and 1 MiB")
	}
	return nil
}

func ensureCryptoDatabaseFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, cryptoDBMode)
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return fmt.Errorf("inspect Node crypto state database: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("Node crypto state database must be a regular file")
		}
		file, err = os.OpenFile(path, os.O_RDWR, 0)
	}
	if err != nil {
		return fmt.Errorf("create or open Node crypto state database: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat Node crypto state database: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		return errors.New("Node crypto state database path changed while opening")
	}
	if err := file.Chmod(cryptoDBMode); err != nil {
		return fmt.Errorf("protect Node crypto state database: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync Node crypto state database file: %w", err)
	}
	return nil
}

func syncCryptoStateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Node crypto state directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Node crypto state directory: %w", err)
	}
	return nil
}
