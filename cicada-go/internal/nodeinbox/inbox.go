// Package nodeinbox persists the delivery boundary owned by a cicada Node.
//
// The inbox is deliberately independent of Control.  It records an inbound
// message before a runtime adapter is called and keeps the runtime injection
// result separate from application consumption.  In particular, an
// INJECTING row is never silently retried after a process restart: Open marks
// it INJECTION_UNCERTAIN and a caller must reconcile it with a runtime receipt.
package nodeinbox

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// State is the durable state of an inbound delivery.  The names deliberately
// match the layered receipt vocabulary in CICADA.md.
type State string

const (
	NODE_RECEIVED           State = "NODE_RECEIVED"
	INJECTING               State = "INJECTING"
	RUNTIME_INJECTED        State = "RUNTIME_INJECTED"
	CONSUMPTION_UNCONFIRMED State = "CONSUMPTION_UNCONFIRMED"
	INJECTION_UNCERTAIN     State = "INJECTION_UNCERTAIN"
	FAILED                  State = "FAILED"
)

// Descriptive aliases make call sites easier to read while retaining the
// protocol spelling above for callers that serialize states.
const (
	StateNodeReceived           = NODE_RECEIVED
	StateInjecting              = INJECTING
	StateRuntimeInjected        = RUNTIME_INJECTED
	StateConsumptionUnconfirmed = CONSUMPTION_UNCONFIRMED
	StateInjectionUncertain     = INJECTION_UNCERTAIN
	StateFailed                 = FAILED
)

var (
	// ErrMessageConflict means that an existing message_id was submitted with
	// a different digest or immutable delivery target.
	ErrMessageConflict = errors.New("node inbox message conflict")
	// ErrNoDelivery is returned when no unclaimed NODE_RECEIVED delivery exists.
	ErrNoDelivery = errors.New("node inbox has no claimable delivery")
	// ErrNotFound means that the requested message or attempt does not exist.
	ErrNotFound = errors.New("node inbox delivery not found")
	// ErrInvalidReceipt means a receipt does not identify the stored target.
	ErrInvalidReceipt = errors.New("node inbox receipt does not match delivery")
	// ErrStaleReceipt means a valid-looking receipt belongs to an old attempt
	// or a state that can no longer be advanced.
	ErrStaleReceipt = errors.New("node inbox receipt is stale")
	// ErrInvalidState means that an operation is not legal for the current
	// durable state.
	ErrInvalidState = errors.New("node inbox invalid state transition")
	// ErrInjectionUncertain is returned by operations that would blindly retry
	// a delivery whose runtime result was not recorded before a crash.
	ErrInjectionUncertain = errors.New("node inbox injection is uncertain")
)

const (
	maxIDLength        = 512
	maxDigestLength    = 256
	maxFailureLength   = 1024
	maxConsumerLength  = 256
	recoveryReason     = "runtime injection outcome was not recorded before node recovery"
	abandonedClaimNote = "consumer claim was abandoned before injection began"
)

// Message is the immutable inbound envelope accepted by a Node.  Digest is
// the caller's content digest and is part of the idempotency key.  Payload is
// opaque to this package; callers should avoid putting secrets in errors or
// logs.  The package never includes it in an error string.
type Message struct {
	MessageID    string
	Digest       string
	EndpointID   string
	SessionID    string
	BindingEpoch uint64
	Payload      []byte
}

// Delivery is a durable inbox record.  Payload is returned only to callers
// that explicitly fetch a delivery; status and routing metadata are safe for
// machine-agent state handling.  AttemptID is the currently claimed attempt,
// when one exists.
type Delivery struct {
	MessageID    string
	Digest       string
	EndpointID   string
	SessionID    string
	BindingEpoch uint64
	Payload      []byte
	State        State
	AttemptID    string
	ConsumerID   string
	ClaimedAt    time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Failure      string
}

// Claim is the single-consumer lease returned by Claim.  AttemptID is a
// capability for BeginInjection and subsequent receipt calls; it must be
// supplied to the runtime adapter by the machine agent and echoed by the
// adapter in its receipt.
type Claim struct {
	Delivery
	ConsumerID string
}

// Receipt is the authenticated result returned by a runtime adapter.  State
// must be one of RUNTIME_INJECTED, CONSUMPTION_UNCONFIRMED, or FAILED.  A
// SessionID is checked when present; endpoint, epoch and attempt are always
// checked.  Error is used only for FAILED and is length-limited before being
// persisted.
type Receipt struct {
	MessageID    string
	Digest       string
	EndpointID   string
	SessionID    string
	BindingEpoch uint64
	AttemptID    string
	State        State
	Error        string
}

// Inbox owns a SQLite database containing only Node delivery state.  It can be
// opened beside the existing Control database or in a separate Node-local
// state directory.
type Inbox struct {
	db     *sql.DB
	mu     sync.Mutex
	closed bool
}

// Open opens or creates a durable Node inbox.  Recovery is part of opening:
// unrecorded INJECTING work becomes INJECTION_UNCERTAIN and cannot be claimed
// for an automatic retry.
func Open(path string) (*Inbox, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("node inbox database path is required")
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file::memory:") {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create node inbox state directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open node inbox sqlite: %w", err)
	}
	// A single connection avoids an in-process reader/writer race while the
	// transaction still gives SQLite atomicity for separately opened Nodes.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	inbox := &Inbox{db: db}
	if err := inbox.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := inbox.recoverInFlight(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return inbox, nil
}

// New is a compatibility alias for Open for machine-agent constructors.
func New(path string) (*Inbox, error) { return Open(path) }

// Close closes the underlying SQLite handle.  A closed Inbox must not be
// reused.
func (i *Inbox) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil
	}
	i.closed = true
	return i.db.Close()
}

func (i *Inbox) initialize() error {
	_, err := i.db.Exec(`
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS node_inbox_deliveries (
  message_id TEXT PRIMARY KEY,
  digest TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  binding_epoch INTEGER NOT NULL,
  payload BLOB,
  state TEXT NOT NULL CHECK (state IN (
    'NODE_RECEIVED', 'INJECTING', 'RUNTIME_INJECTED',
    'CONSUMPTION_UNCONFIRMED', 'INJECTION_UNCERTAIN', 'FAILED'
  )),
  attempt_id TEXT,
  consumer_id TEXT,
  claimed_at TEXT,
  failure TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS node_inbox_message_digest_idx
  ON node_inbox_deliveries(message_id, digest);
CREATE INDEX IF NOT EXISTS node_inbox_claim_idx
  ON node_inbox_deliveries(state, claimed_at, created_at, message_id);
CREATE INDEX IF NOT EXISTS node_inbox_endpoint_idx
  ON node_inbox_deliveries(endpoint_id, binding_epoch, state);

CREATE TABLE IF NOT EXISTS node_inbox_attempts (
  attempt_id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL REFERENCES node_inbox_deliveries(message_id),
  endpoint_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  binding_epoch INTEGER NOT NULL,
  consumer_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN (
    'CLAIMED', 'INJECTING', 'RUNTIME_INJECTED',
    'CONSUMPTION_UNCONFIRMED', 'INJECTION_UNCERTAIN', 'FAILED', 'ABANDONED'
  )),
  claimed_at TEXT NOT NULL,
  began_at TEXT,
  finished_at TEXT,
  failure TEXT
);
CREATE INDEX IF NOT EXISTS node_inbox_attempt_message_idx
  ON node_inbox_attempts(message_id, claimed_at);
`)
	if err != nil {
		return fmt.Errorf("initialize node inbox schema: %w", err)
	}
	return nil
}

// Save durably accepts an inbound message.  It returns created=false for an
// idempotent repeat with the same message ID and digest.  A reused message ID
// with another digest is a conflict and leaves the stored row untouched.
func (i *Inbox) Save(ctx context.Context, message Message) (*Delivery, bool, error) {
	normalized, err := normalizeMessage(message)
	if err != nil {
		return nil, false, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkOpen(); err != nil {
		return nil, false, err
	}
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin node inbox save: %w", err)
	}
	defer tx.Rollback()

	existing, err := scanDelivery(tx.QueryRowContext(ctx, deliverySelect+" WHERE message_id = ?", normalized.MessageID), true)
	if err != nil {
		return nil, false, fmt.Errorf("read existing node delivery: %w", err)
	}
	if existing != nil {
		if existing.Digest != normalized.Digest || existing.EndpointID != normalized.EndpointID ||
			existing.SessionID != normalized.SessionID || existing.BindingEpoch != normalized.BindingEpoch {
			return nil, false, ErrMessageConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit idempotent node delivery: %w", err)
		}
		return existing, false, nil
	}
	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, `INSERT INTO node_inbox_deliveries
(message_id, digest, endpoint_id, session_id, binding_epoch, payload, state,
 attempt_id, consumer_id, claimed_at, failure, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)`,
		normalized.MessageID, normalized.Digest, normalized.EndpointID, normalized.SessionID,
		normalized.BindingEpoch, normalized.Payload, string(NODE_RECEIVED), formatTime(now), formatTime(now))
	if err != nil {
		// A separately opened Inbox may win the insert race.  Read the winner
		// and apply the same immutable-content checks without exposing payload.
		winner, readErr := scanDelivery(tx.QueryRowContext(ctx, deliverySelect+" WHERE message_id = ?", normalized.MessageID), true)
		if readErr == nil && winner != nil {
			if winner.Digest != normalized.Digest || winner.EndpointID != normalized.EndpointID ||
				winner.SessionID != normalized.SessionID || winner.BindingEpoch != normalized.BindingEpoch {
				return nil, false, ErrMessageConflict
			}
			if commitErr := tx.Commit(); commitErr != nil {
				return nil, false, fmt.Errorf("commit concurrent node delivery: %w", commitErr)
			}
			return winner, false, nil
		}
		return nil, false, fmt.Errorf("store node delivery: %w", err)
	}
	stored, err := scanDelivery(tx.QueryRowContext(ctx, deliverySelect+" WHERE message_id = ?", normalized.MessageID), true)
	if err != nil || stored == nil {
		if err == nil {
			err = ErrNotFound
		}
		return nil, false, fmt.Errorf("read stored node delivery: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit node delivery: %w", err)
	}
	return stored, true, nil
}

// Accept is an explicit alias for Save used by relay-facing adapters.
func (i *Inbox) Accept(ctx context.Context, message Message) (*Delivery, bool, error) {
	return i.Save(ctx, message)
}

// Get returns a durable delivery by message ID.  It never changes state.
func (i *Inbox) Get(ctx context.Context, messageID string) (*Delivery, error) {
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return nil, ErrNotFound
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkOpen(); err != nil {
		return nil, err
	}
	delivery, err := scanDelivery(i.db.QueryRowContext(ctx, deliverySelect+" WHERE message_id = ?", messageID), true)
	if err != nil {
		return nil, fmt.Errorf("get node delivery: %w", err)
	}
	if delivery == nil {
		return nil, ErrNotFound
	}
	return delivery, nil
}

// Claim atomically assigns one NODE_RECEIVED delivery to consumerID and
// creates an attempt record.  Exactly one concurrent caller can receive a
// given message.  Claims that never reach BeginInjection are cleared on the
// next process recovery because no runtime call could have happened yet.
func (i *Inbox) Claim(ctx context.Context, consumerID string) (*Claim, error) {
	consumerID = strings.TrimSpace(consumerID)
	if consumerID == "" {
		return nil, errors.New("node inbox consumer ID is required")
	}
	if len(consumerID) > maxConsumerLength {
		return nil, errors.New("node inbox consumer ID is too long")
	}
	attemptID, err := newAttemptID()
	if err != nil {
		return nil, fmt.Errorf("create node inbox attempt ID: %w", err)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkOpen(); err != nil {
		return nil, err
	}
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin node inbox claim: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE node_inbox_deliveries
SET attempt_id = ?, consumer_id = ?, claimed_at = ?, updated_at = ?
WHERE message_id = (
  SELECT message_id FROM node_inbox_deliveries
  WHERE state = ? AND (consumer_id IS NULL OR consumer_id = '')
  ORDER BY created_at, message_id LIMIT 1
) AND state = ? AND (consumer_id IS NULL OR consumer_id = '')`,
		attemptID, consumerID, formatTime(now), formatTime(now), string(NODE_RECEIVED), string(NODE_RECEIVED))
	if err != nil {
		return nil, fmt.Errorf("claim node delivery: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("check node claim: %w", err)
	}
	if changed != 1 {
		return nil, ErrNoDelivery
	}
	claimed, err := scanDelivery(tx.QueryRowContext(ctx, deliverySelect+" WHERE attempt_id = ?", attemptID), true)
	if err != nil || claimed == nil {
		if err == nil {
			err = ErrNotFound
		}
		return nil, fmt.Errorf("read claimed node delivery: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO node_inbox_attempts
(attempt_id, message_id, endpoint_id, session_id, binding_epoch, consumer_id,
 state, claimed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, attemptID, claimed.MessageID, claimed.EndpointID,
		claimed.SessionID, claimed.BindingEpoch, consumerID, "CLAIMED", formatTime(now)); err != nil {
		return nil, fmt.Errorf("store node attempt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit node claim: %w", err)
	}
	return &Claim{Delivery: *claimed, ConsumerID: consumerID}, nil
}

// ClaimNext is an alias for Claim.
func (i *Inbox) ClaimNext(ctx context.Context, consumerID string) (*Claim, error) {
	return i.Claim(ctx, consumerID)
}

// BeginInjection persists INJECTING before the machine agent calls its
// runtime adapter.  The returned attempt ID must be echoed by that adapter.
func (i *Inbox) BeginInjection(ctx context.Context, attemptID string) (*Delivery, error) {
	attemptID = strings.TrimSpace(attemptID)
	if attemptID == "" {
		return nil, ErrNotFound
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkOpen(); err != nil {
		return nil, err
	}
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin node injection: %w", err)
	}
	defer tx.Rollback()
	var messageID string
	err = tx.QueryRowContext(ctx, `SELECT message_id FROM node_inbox_attempts
WHERE attempt_id = ? AND state = 'CLAIMED'`, attemptID).Scan(&messageID)
	if errors.Is(err, sql.ErrNoRows) {
		// An attempt that survived recovery as uncertain must never be
		// restarted through BeginInjection.
		var state string
		if stateErr := tx.QueryRowContext(ctx, `SELECT state FROM node_inbox_attempts WHERE attempt_id = ?`, attemptID).Scan(&state); stateErr == nil && state == string(INJECTION_UNCERTAIN) {
			return nil, ErrInjectionUncertain
		}
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find node injection attempt: %w", err)
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE node_inbox_deliveries
SET state = ?, updated_at = ?
WHERE message_id = ? AND state = ? AND attempt_id = ?`, string(INJECTING), formatTime(now), messageID, string(NODE_RECEIVED), attemptID)
	if err != nil {
		return nil, fmt.Errorf("mark node delivery injecting: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("check node injecting transition: %w", err)
	}
	if changed != 1 {
		return nil, ErrInvalidState
	}
	if _, err := tx.ExecContext(ctx, `UPDATE node_inbox_attempts
SET state = 'INJECTING', began_at = ? WHERE attempt_id = ? AND state = 'CLAIMED'`, formatTime(now), attemptID); err != nil {
		return nil, fmt.Errorf("mark node attempt injecting: %w", err)
	}
	delivery, err := scanDelivery(tx.QueryRowContext(ctx, deliverySelect+" WHERE message_id = ?", messageID), true)
	if err != nil || delivery == nil {
		if err == nil {
			err = ErrNotFound
		}
		return nil, fmt.Errorf("read injecting node delivery: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit node injection begin: %w", err)
	}
	return delivery, nil
}

// RecordRuntimeInjected records a positively identified runtime injection.
// It may also reconcile an INJECTION_UNCERTAIN row when the runtime provides
// a native idempotency receipt after recovery.
func (i *Inbox) RecordRuntimeInjected(ctx context.Context, receipt Receipt) (*Delivery, error) {
	receipt.State = RUNTIME_INJECTED
	return i.recordReceipt(ctx, receipt)
}

// RecordConsumptionUnconfirmed records that runtime injection was accepted,
// while the harness cannot prove that the model consumed the message.
func (i *Inbox) RecordConsumptionUnconfirmed(ctx context.Context, receipt Receipt) (*Delivery, error) {
	receipt.State = CONSUMPTION_UNCONFIRMED
	return i.recordReceipt(ctx, receipt)
}

// RecordFailed records a runtime failure after a begun injection.  It does
// not accept arbitrary message content as a reason and truncates diagnostics.
func (i *Inbox) RecordFailed(ctx context.Context, receipt Receipt, reason string) (*Delivery, error) {
	receipt.State = FAILED
	receipt.Error = reason
	return i.recordReceipt(ctx, receipt)
}

// Acknowledge is a generic receipt entry point for adapters that carry the
// desired state in Receipt.State.
func (i *Inbox) Acknowledge(ctx context.Context, receipt Receipt) (*Delivery, error) {
	return i.recordReceipt(ctx, receipt)
}

// RecordReceipt is an alias for Acknowledge.
func (i *Inbox) RecordReceipt(ctx context.Context, receipt Receipt) (*Delivery, error) {
	return i.Acknowledge(ctx, receipt)
}

func (i *Inbox) recordReceipt(ctx context.Context, receipt Receipt) (*Delivery, error) {
	if receipt.State != RUNTIME_INJECTED && receipt.State != CONSUMPTION_UNCONFIRMED && receipt.State != FAILED && receipt.State != INJECTION_UNCERTAIN {
		return nil, ErrInvalidReceipt
	}
	receipt.MessageID = strings.TrimSpace(receipt.MessageID)
	receipt.Digest = strings.TrimSpace(receipt.Digest)
	receipt.EndpointID = strings.TrimSpace(receipt.EndpointID)
	receipt.SessionID = strings.TrimSpace(receipt.SessionID)
	receipt.AttemptID = strings.TrimSpace(receipt.AttemptID)
	if receipt.MessageID == "" || receipt.Digest == "" || receipt.EndpointID == "" || receipt.AttemptID == "" {
		return nil, ErrInvalidReceipt
	}
	if len(receipt.MessageID) > maxIDLength || len(receipt.Digest) > maxDigestLength || len(receipt.EndpointID) > maxIDLength || len(receipt.SessionID) > maxIDLength || len(receipt.AttemptID) > maxIDLength {
		return nil, ErrInvalidReceipt
	}
	receipt.Error = strings.TrimSpace(receipt.Error)
	if len(receipt.Error) > maxFailureLength {
		receipt.Error = receipt.Error[:maxFailureLength]
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkOpen(); err != nil {
		return nil, err
	}
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin node receipt: %w", err)
	}
	defer tx.Rollback()
	delivery, err := scanDelivery(tx.QueryRowContext(ctx, deliverySelect+" WHERE message_id = ?", receipt.MessageID), true)
	if err != nil {
		return nil, fmt.Errorf("read receipt delivery: %w", err)
	}
	if delivery == nil {
		return nil, ErrNotFound
	}
	if delivery.Digest != receipt.Digest || delivery.EndpointID != receipt.EndpointID ||
		delivery.BindingEpoch != receipt.BindingEpoch || delivery.AttemptID != receipt.AttemptID ||
		(receipt.SessionID != "" && delivery.SessionID != receipt.SessionID) {
		return nil, ErrInvalidReceipt
	}
	if delivery.State == receipt.State {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit idempotent node receipt: %w", err)
		}
		return delivery, nil
	}
	if delivery.State == INJECTION_UNCERTAIN && receipt.State == RUNTIME_INJECTED {
		// Native idempotency reconciliation is the only path out of the
		// uncertain window.  It does not invoke a runtime or retry anything.
	} else if delivery.State == INJECTING && (receipt.State == RUNTIME_INJECTED || receipt.State == FAILED || receipt.State == INJECTION_UNCERTAIN) {
		// Normal post-runtime receipt.
	} else if delivery.State == RUNTIME_INJECTED && receipt.State == CONSUMPTION_UNCONFIRMED {
		// Explicitly layered consumption uncertainty.
	} else if delivery.State == CONSUMPTION_UNCONFIRMED || delivery.State == FAILED {
		return nil, ErrStaleReceipt
	} else if delivery.State == INJECTION_UNCERTAIN {
		return nil, ErrInjectionUncertain
	} else {
		return nil, ErrInvalidState
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE node_inbox_deliveries
SET state = ?, failure = ?, updated_at = ?
WHERE message_id = ? AND state = ? AND attempt_id = ?`, string(receipt.State), nullableFailure(receipt.Error), formatTime(now), receipt.MessageID, string(delivery.State), receipt.AttemptID)
	if err != nil {
		return nil, fmt.Errorf("advance node receipt: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("check node receipt transition: %w", err)
	}
	if changed != 1 {
		return nil, ErrStaleReceipt
	}
	if _, err := tx.ExecContext(ctx, `UPDATE node_inbox_attempts
SET state = ?, finished_at = ?, failure = ?
WHERE attempt_id = ?`, string(receipt.State), formatTime(now), nullableFailure(receipt.Error), receipt.AttemptID); err != nil {
		return nil, fmt.Errorf("advance node attempt: %w", err)
	}
	updated, err := scanDelivery(tx.QueryRowContext(ctx, deliverySelect+" WHERE message_id = ?", receipt.MessageID), true)
	if err != nil || updated == nil {
		if err == nil {
			err = ErrNotFound
		}
		return nil, fmt.Errorf("read advanced node delivery: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit node receipt: %w", err)
	}
	return updated, nil
}

// Recover performs the same safe startup recovery as Open.  It is exposed so
// a machine agent can run recovery explicitly after restoring a database,
// while still never requeueing uncertain injection work.
func (i *Inbox) Recover(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkOpen(); err != nil {
		return err
	}
	return i.recoverInFlightLocked(ctx)
}

func (i *Inbox) recoverInFlight(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkOpen(); err != nil {
		return err
	}
	return i.recoverInFlightLocked(ctx)
}

func (i *Inbox) recoverInFlightLocked(ctx context.Context) error {
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node recovery: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	// INJECTING means a runtime call may already have happened.  Preserve the
	// attempt and force explicit native reconciliation instead of requeueing.
	if _, err := tx.ExecContext(ctx, `UPDATE node_inbox_deliveries
SET state = ?, failure = ?, updated_at = ? WHERE state = ?`, string(INJECTION_UNCERTAIN), recoveryReason, formatTime(now), string(INJECTING)); err != nil {
		return fmt.Errorf("recover uncertain node deliveries: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE node_inbox_attempts
SET state = ?, finished_at = ?, failure = ? WHERE state = ?`, string(INJECTION_UNCERTAIN), formatTime(now), recoveryReason, "INJECTING"); err != nil {
		return fmt.Errorf("recover uncertain node attempts: %w", err)
	}
	// A claim without BeginInjection is known not to have called runtime.  It
	// is safe to make it claimable again, while retaining an ABANDONED attempt
	// for auditability.
	if _, err := tx.ExecContext(ctx, `UPDATE node_inbox_attempts
SET state = 'ABANDONED', finished_at = ?, failure = ? WHERE state = 'CLAIMED'`, formatTime(now), abandonedClaimNote); err != nil {
		return fmt.Errorf("recover abandoned node attempts: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE node_inbox_deliveries
SET attempt_id = NULL, consumer_id = NULL, claimed_at = NULL, updated_at = ?
WHERE state = ? AND attempt_id IS NOT NULL`, formatTime(now), string(NODE_RECEIVED)); err != nil {
		return fmt.Errorf("release abandoned node claims: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit node recovery: %w", err)
	}
	return nil
}

func (i *Inbox) checkOpen() error {
	if i == nil || i.db == nil || i.closed {
		return errors.New("node inbox is closed")
	}
	return nil
}

func normalizeMessage(message Message) (Message, error) {
	message.MessageID = strings.TrimSpace(message.MessageID)
	message.Digest = strings.TrimSpace(message.Digest)
	message.EndpointID = strings.TrimSpace(message.EndpointID)
	message.SessionID = strings.TrimSpace(message.SessionID)
	if message.MessageID == "" || message.Digest == "" || message.EndpointID == "" || message.SessionID == "" {
		return Message{}, errors.New("node inbox message ID, digest, endpoint, and session are required")
	}
	if len(message.MessageID) > maxIDLength || len(message.Digest) > maxDigestLength || len(message.EndpointID) > maxIDLength || len(message.SessionID) > maxIDLength {
		return Message{}, errors.New("node inbox message routing field is too long")
	}
	if message.BindingEpoch > math.MaxInt64 {
		return Message{}, errors.New("node inbox binding epoch is out of range")
	}
	message.Payload = append([]byte(nil), message.Payload...)
	return message, nil
}

func newAttemptID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "attempt_" + hex.EncodeToString(raw[:]), nil
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func nullableFailure(value string) any {
	if value == "" {
		return nil
	}
	return value
}

const deliverySelect = `SELECT message_id, digest, endpoint_id, session_id,
binding_epoch, payload, state, attempt_id, consumer_id, claimed_at, failure,
created_at, updated_at FROM node_inbox_deliveries`

type scanner interface{ Scan(dest ...any) error }

func scanDelivery(row scanner, includePayload bool) (*Delivery, error) {
	var (
		delivery                             Delivery
		bindingEpoch                         int64
		payload                              []byte
		state, attemptID, consumerID         sql.NullString
		claimedAt, failure, created, updated sql.NullString
	)
	if err := row.Scan(&delivery.MessageID, &delivery.Digest, &delivery.EndpointID, &delivery.SessionID,
		&bindingEpoch, &payload, &state, &attemptID, &consumerID, &claimedAt, &failure, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if bindingEpoch < 0 {
		return nil, errors.New("node inbox stored a negative binding epoch")
	}
	delivery.BindingEpoch = uint64(bindingEpoch)
	delivery.State = State(state.String)
	delivery.AttemptID = attemptID.String
	delivery.ConsumerID = consumerID.String
	delivery.Failure = failure.String
	if includePayload {
		delivery.Payload = append([]byte(nil), payload...)
	}
	var err error
	if delivery.ClaimedAt, err = parseNullableTime(claimedAt); err != nil {
		return nil, err
	}
	if delivery.CreatedAt, err = parseRequiredTime(created.String); err != nil {
		return nil, err
	}
	if delivery.UpdatedAt, err = parseRequiredTime(updated.String); err != nil {
		return nil, err
	}
	return &delivery, nil
}

func parseNullableTime(value sql.NullString) (time.Time, error) {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return time.Time{}, nil
	}
	return parseRequiredTime(value.String)
}

func parseRequiredTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse node inbox timestamp: %w", err)
	}
	return parsed, nil
}
