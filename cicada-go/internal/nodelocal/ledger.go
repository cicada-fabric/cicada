// Package nodelocal stores the durable Node-local peer message and request
// ledger. Message bodies accepted by this package are already sealed opaque
// ciphertext; this package has no decryption API and never accepts plaintext.
package nodelocal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

const (
	databaseMode         = 0o600
	busyTimeoutMillis    = 30000
	maxIDLength          = 512
	maxScopeLength       = 1024
	maxCiphertext        = 1 << 20
	maxBatchSize         = 1000
	currentSchemaVersion = 2
)

// MessageKind identifies the durable peer operation represented by a row.
type MessageKind string

const (
	KindSend  MessageKind = "SEND"
	KindAsk   MessageKind = "ASK"
	KindReply MessageKind = "REPLY"
)

// RequestState is the durable lifecycle of an asynchronous ASK.
type RequestState string

const (
	RequestOpen      RequestState = "OPEN"
	RequestAnswered  RequestState = "ANSWERED"
	RequestCancelled RequestState = "CANCELLED"
	RequestExpired   RequestState = "EXPIRED"
	RequestRejected  RequestState = "REJECTED"
)

// DeliveryState records only the handoff from this ledger to nodeinbox. Native
// injection and consumption states remain exclusively owned by nodeinbox.
type DeliveryState string

const (
	DeliveryPending   DeliveryState = "PENDING"
	DeliveryHandedOff DeliveryState = "NODE_INBOX_ACCEPTED"
	DeliveryLate      DeliveryState = "LATE"
	DeliveryRejected  DeliveryState = "REJECTED"
)

var (
	ErrClosed                 = errors.New("Node-local ledger is closed")
	ErrMessageNotFound        = errors.New("Node-local message not found")
	ErrRequestNotFound        = errors.New("Node-local request not found")
	ErrMessageConflict        = errors.New("Node-local message identity conflict")
	ErrRequestConflict        = errors.New("Node-local request identity conflict")
	ErrRequestAlreadyAnswered = errors.New("Node-local request already has a final reply")
	ErrRequestClosed          = errors.New("Node-local request is already closed")
	ErrNotRequester           = errors.New("Node-local request is not owned by requester")
	ErrInvalidReply           = errors.New("Node-local reply does not match request route")
	ErrAuthorizationExpired   = errors.New("Node-local route authorization expired")
	ErrNotPending             = errors.New("Node-local message is not pending handoff")
	ErrRejectConflict         = errors.New("Node-local rejection conflicts with recorded terminal state")
	ErrInvalidInput           = errors.New("invalid Node-local ledger input")
)

// Route is the immutable snapshot assembled by the trusted Node bridge from
// its validated native-session request and Guard output.
// AuthorizationValidUntil is checked when a new message is accepted. Later
// delivery authorization and revocation checks remain the caller's duty.
// Scope is policy metadata; Ciphertext is the only persisted peer body.
// SourceSessionID and TargetSessionID are native runtime session identifiers,
// never CICADA authentication tokens or credentials.
type Route struct {
	SourceOwnerID     string `json:"source_owner_id"`
	TargetOwnerID     string `json:"target_owner_id"`
	SourceNodeID      string `json:"source_node_id"`
	TargetNodeID      string `json:"target_node_id"`
	SourcePrincipalID string `json:"source_principal_id"`
	TargetPrincipalID string `json:"target_principal_id"`
	SourceEndpointID  string `json:"source_endpoint_id"`
	TargetEndpointID  string `json:"target_endpoint_id"`
	SourceGroupID     string `json:"source_group_id"`
	TargetGroupID     string `json:"target_group_id"`
	// MembershipRevision tracks the principal's Group membership; JoinRevision
	// tracks the endpoint's own Group join edge. They are distinct fences.
	SourceMembershipRevision uint64    `json:"source_membership_revision"`
	TargetMembershipRevision uint64    `json:"target_membership_revision"`
	SourceJoinRevision       uint64    `json:"source_join_revision"`
	TargetJoinRevision       uint64    `json:"target_join_revision"`
	SourceBindingID          string    `json:"source_binding_id"`
	TargetBindingID          string    `json:"target_binding_id"`
	SourceBindingEpoch       uint64    `json:"source_binding_epoch"`
	TargetBindingEpoch       uint64    `json:"target_binding_epoch"`
	SourceKeyID              string    `json:"source_key_id"`
	TargetKeyID              string    `json:"target_key_id"`
	SourceSessionID          string    `json:"source_session_id"`
	TargetSessionID          string    `json:"target_session_id"`
	SourceCandidateID        string    `json:"source_candidate_id"`
	TargetCandidateID        string    `json:"target_candidate_id"`
	SourceCandidateVersion   uint64    `json:"source_candidate_version"`
	TargetCandidateVersion   uint64    `json:"target_candidate_version"`
	AuthorizationRevision    string    `json:"authorization_revision"`
	Action                   string    `json:"action"`
	Scope                    string    `json:"scope"`
	AuthorizationValidUntil  time.Time `json:"authorization_valid_until"`
}

// MessageInput is shared by SEND, ASK, and REPLY. Ciphertext must be an
// already sealed envelope. The ledger computes its digest and copies the
// bytes before returning.
type MessageInput struct {
	MessageID  string
	Route      Route
	Ciphertext []byte
}

// AskInput adds the stable request identity and business deadline to a sealed
// ASK. RequestID is supplied by the trusted Node bridge and should be derived
// from the durable MCP operation identity so the caller can recover it after a
// lost response.
type AskInput struct {
	MessageInput
	RequestID string
	ExpiresAt time.Time
}

// ReplyInput explicitly names both the request and the original ASK message.
// The route must reverse the original ASK's source and target identities.
type ReplyInput struct {
	MessageInput
	RequestID        string
	ReplyToMessageID string
}

// Accepted is the durable acceptance result. Created is false for an exact
// idempotent retry. Late replies are committed as evidence and marked Late,
// but are excluded from Pending.
type Accepted struct {
	MessageID  string
	RequestID  string
	Digest     string
	Kind       MessageKind
	State      DeliveryState
	Created    bool
	AcceptedAt time.Time
}

// Request is a durable asynchronous ASK record. Route is the immutable route
// captured when the ASK was accepted.
type Request struct {
	RequestID        string
	MessageID        string
	SourceEndpointID string
	TargetEndpointID string
	Scope            string
	ExpiresAt        time.Time
	State            RequestState
	ReplyMessageID   string
	// LateReplyMessageIDs point to retained replies that cannot be auto-delivered.
	LateReplyMessageIDs []string
	Route               Route
	CreatedAt           time.Time
	UpdatedAt           time.Time
	CancelledAt         time.Time
	AnsweredAt          time.Time
}

// MessageRecord returns a durable message for recovery and reauthorization.
// Ciphertext is always a defensive copy of the exact sealed bytes accepted.
type MessageRecord struct {
	MessageID        string
	Kind             MessageKind
	RequestID        string
	ReplyToMessageID string
	Digest           string
	Route            Route
	Ciphertext       []byte
	State            DeliveryState
	RejectionCode    string
	ExpiresAt        time.Time
	AcceptedAt       time.Time
	HandedOffAt      time.Time
	RejectedAt       time.Time
}

// Ledger owns an independent Node-local SQLite message/request database.
type Ledger struct {
	db     *sql.DB
	mu     sync.Mutex
	closed bool
}

// Open opens or creates the Node-local ledger at path. The SQLite database is
// protected with mode 0600 and uses WAL plus FULL synchronous commits.
func Open(path string) (*Ledger, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("%w: database path is required", ErrInvalidInput)
	}
	if !isMemoryPath(path) {
		if err := prepareDatabaseFile(path); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open Node-local ledger database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ledger := &Ledger{db: db}
	if err := ledger.initialize(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if !isMemoryPath(path) {
		if err := os.Chmod(path, databaseMode); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("protect Node-local ledger database: %w", err)
		}
	}
	return ledger, nil
}

// Close releases the SQLite handle. It is safe to call more than once.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.db.Close()
}

// AcceptSend durably accepts an already encrypted one-way peer message.
func (l *Ledger) AcceptSend(ctx context.Context, input MessageInput) (Accepted, error) {
	prepared, err := prepareMessage(input, KindSend, "", "", time.Time{})
	if err != nil {
		return Accepted{}, err
	}
	return l.acceptMessage(ctx, prepared, nil)
}

// AcceptAsk atomically persists the encrypted ASK and its request identity,
// exact source/target endpoints, scope, and expiration. It returns immediately
// after durable acceptance; it never waits for the peer's answer.
func (l *Ledger) AcceptAsk(ctx context.Context, input AskInput) (Accepted, error) {
	requestID := strings.TrimSpace(input.RequestID)
	if !strings.HasPrefix(requestID, "rq_") || !validToken(requestID, maxIDLength) {
		return Accepted{}, fmt.Errorf("%w: request ID must be a canonical rq_ identifier", ErrInvalidInput)
	}
	if input.ExpiresAt.IsZero() {
		return Accepted{}, fmt.Errorf("%w: request expiration is required", ErrInvalidInput)
	}
	expiresAt := time.UnixMicro(input.ExpiresAt.UTC().UnixMicro()).UTC()
	prepared, err := prepareMessage(input.MessageInput, KindAsk, requestID, "", expiresAt)
	if err != nil {
		return Accepted{}, err
	}
	return l.acceptMessage(ctx, prepared, &requestInsert{requestID: requestID, expiresAt: expiresAt})
}

// AcceptReply atomically records an encrypted final reply. A reply must name
// the original request and ASK message. If cancellation or expiration already
// closed the request, the reply is kept as LATE and is never auto-delivered.
func (l *Ledger) AcceptReply(ctx context.Context, input ReplyInput) (Accepted, error) {
	requestID := strings.TrimSpace(input.RequestID)
	replyTo := strings.TrimSpace(input.ReplyToMessageID)
	if !strings.HasPrefix(requestID, "rq_") || !validToken(requestID, maxIDLength) || !validToken(replyTo, maxIDLength) {
		return Accepted{}, fmt.Errorf("%w: reply request and original message IDs are required", ErrInvalidInput)
	}
	prepared, err := prepareMessage(input.MessageInput, KindReply, requestID, replyTo, time.Time{})
	if err != nil {
		return Accepted{}, err
	}
	return l.acceptReply(ctx, prepared)
}

// CancelRequest closes an OPEN request when requesterEndpointID is its
// original source. Cancellation prevents further ASK handoff from Pending;
// it cannot reverse work already injected into a native runtime.
func (l *Ledger) CancelRequest(ctx context.Context, requestID, requesterEndpointID string) (Request, error) {
	requestID = strings.TrimSpace(requestID)
	requesterEndpointID = strings.TrimSpace(requesterEndpointID)
	if !validToken(requestID, maxIDLength) || !validToken(requesterEndpointID, maxIDLength) {
		return Request{}, fmt.Errorf("%w: request and requester IDs are required", ErrInvalidInput)
	}
	if ctx == nil {
		return Request{}, fmt.Errorf("%w: context is required", ErrInvalidInput)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkOpen(); err != nil {
		return Request{}, err
	}
	var result Request
	var operationErr error
	err := l.writeTx(ctx, func(conn *sql.Conn) error {
		now := time.Now().UTC()
		if _, err := expireRequestsTx(ctx, conn, now); err != nil {
			return err
		}
		record, err := loadRequest(ctx, conn, requestID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrRequestNotFound
			}
			return fmt.Errorf("read Node-local request: %w", err)
		}
		if record.SourceEndpointID != requesterEndpointID {
			return ErrNotRequester
		}
		if record.State == RequestOpen {
			if _, err := conn.ExecContext(ctx, "UPDATE node_local_requests SET state = ?, cancelled_at_us = ?, updated_at_us = ? WHERE request_id = ? AND state = ?", string(RequestCancelled), now.UnixMicro(), now.UnixMicro(), requestID, string(RequestOpen)); err != nil {
				return fmt.Errorf("cancel Node-local request: %w", err)
			}
			record.State = RequestCancelled
			record.CancelledAt = now
			record.UpdatedAt = now
		} else if record.State != RequestCancelled {
			operationErr = ErrRequestClosed
		}
		result = record
		return nil
	})
	if err != nil {
		return Request{}, err
	}
	if operationErr != nil {
		return result, operationErr
	}
	return result, nil
}

// ExpireRequests marks OPEN requests whose business deadline is at or before
// now as EXPIRED. It never deletes their ASK or subsequent late reply bytes.
func (l *Ledger) ExpireRequests(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() || ctx == nil {
		return 0, fmt.Errorf("%w: context and expiration time are required", ErrInvalidInput)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkOpen(); err != nil {
		return 0, err
	}
	changed := 0
	err := l.writeTx(ctx, func(conn *sql.Conn) error {
		var err error
		changed, err = expireRequestsTx(ctx, conn, now.UTC())
		return err
	})
	return changed, err
}

// GetRequest returns the request identity and immutable ASK route. An elapsed
// OPEN request is first transitioned to EXPIRED so callers observe its state.
func (l *Ledger) GetRequest(ctx context.Context, requestID string) (Request, error) {
	requestID = strings.TrimSpace(requestID)
	if !validToken(requestID, maxIDLength) {
		return Request{}, fmt.Errorf("%w: request ID is required", ErrInvalidInput)
	}
	if ctx == nil {
		return Request{}, fmt.Errorf("%w: context is required", ErrInvalidInput)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkOpen(); err != nil {
		return Request{}, err
	}
	var result Request
	err := l.writeTx(ctx, func(conn *sql.Conn) error {
		if _, err := expireRequestsTx(ctx, conn, time.Now().UTC()); err != nil {
			return err
		}
		var err error
		result, err = loadRequest(ctx, conn, requestID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRequestNotFound
		}
		if err != nil {
			return fmt.Errorf("read Node-local request: %w", err)
		}
		return nil
	})
	return result, err
}

// Pending returns a bounded batch of sealed messages not yet accepted by
// nodeinbox. Call MarkNodeInboxAccepted only after nodeinbox.Save commits.
// Current authorization must be rechecked by the caller before the handoff.
func (l *Ledger) Pending(ctx context.Context, targetEndpointID string, limit int) ([]MessageRecord, error) {
	targetEndpointID = strings.TrimSpace(targetEndpointID)
	if ctx == nil || !validToken(targetEndpointID, maxIDLength) || limit < 1 || limit > maxBatchSize {
		return nil, fmt.Errorf("%w: context, target endpoint, and bounded positive limit are required", ErrInvalidInput)
	}
	return l.pending(ctx, targetEndpointID, limit)
}

// PendingAll scans a bounded batch across the ledger's recorded targets. It
// lets a restarted Node resume local handoff without asking Directory or Hub
// to enumerate endpoints. Every result still requires Guard revalidation.
func (l *Ledger) PendingAll(ctx context.Context, limit int) ([]MessageRecord, error) {
	if ctx == nil || limit < 1 || limit > maxBatchSize {
		return nil, fmt.Errorf("%w: context and bounded positive limit are required", ErrInvalidInput)
	}
	return l.pending(ctx, "", limit)
}

func (l *Ledger) pending(ctx context.Context, targetEndpointID string, limit int) ([]MessageRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkOpen(); err != nil {
		return nil, err
	}
	var records []MessageRecord
	err := l.writeTx(ctx, func(conn *sql.Conn) error {
		now := time.Now().UTC()
		if _, err := expireRequestsTx(ctx, conn, now); err != nil {
			return err
		}
		query := messageSelect + " WHERE m.terminal_state = '' AND m.delivery_state = ? AND (m.kind != 'ASK' OR EXISTS (SELECT 1 FROM node_local_requests r WHERE r.request_id = m.request_id AND r.state = 'OPEN' AND r.expires_at_us > ?))"
		args := []any{string(DeliveryPending), now.UnixMicro()}
		if targetEndpointID != "" {
			query += " AND m.target_endpoint_id = ?"
			args = append(args, targetEndpointID)
		}
		query += " ORDER BY m.accepted_at_us, m.message_id LIMIT ?"
		args = append(args, limit)
		rows, err := conn.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("scan pending Node-local messages: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			record, err := scanMessage(rows)
			if err != nil {
				return fmt.Errorf("read pending Node-local message: %w", err)
			}
			records = append(records, record)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate pending Node-local messages: %w", err)
		}
		return nil
	})
	return records, err
}

// MarkNodeInboxAccepted marks the ledger-to-nodeinbox boundary after the exact
// ciphertext has been durably accepted by nodeinbox.Save. Repeating the same
// acknowledgement is safe; this method records no native injection state.
func (l *Ledger) MarkNodeInboxAccepted(ctx context.Context, messageID, digest string) error {
	messageID = strings.TrimSpace(messageID)
	digest = strings.TrimSpace(digest)
	if ctx == nil || !validToken(messageID, maxIDLength) || len(digest) != sha256.Size*2 {
		return fmt.Errorf("%w: context, message ID, and SHA-256 digest are required", ErrInvalidInput)
	}
	digestBytes, err := hex.DecodeString(digest)
	if err != nil {
		return fmt.Errorf("%w: invalid SHA-256 digest", ErrInvalidInput)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkOpen(); err != nil {
		return err
	}
	var operationErr error
	err = l.writeTx(ctx, func(conn *sql.Conn) error {
		var storedDigest []byte
		var state, kind, requestID, terminalState string
		err := conn.QueryRowContext(ctx, "SELECT digest, delivery_state, kind, request_id, terminal_state FROM node_local_messages WHERE message_id = ?", messageID).Scan(&storedDigest, &state, &kind, &requestID, &terminalState)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMessageNotFound
		}
		if err != nil {
			return fmt.Errorf("read Node-local message handoff: %w", err)
		}
		if !bytes.Equal(storedDigest, digestBytes) {
			return ErrMessageConflict
		}
		if terminalState == string(DeliveryRejected) {
			return ErrNotPending
		}
		if state == string(DeliveryHandedOff) {
			return nil
		}
		if state != string(DeliveryPending) {
			return ErrNotPending
		}
		if kind == string(KindAsk) {
			var requestState string
			var expiresAt int64
			if err := conn.QueryRowContext(ctx, "SELECT state, expires_at_us FROM node_local_requests WHERE request_id = ?", requestID).Scan(&requestState, &expiresAt); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrNotPending
				}
				return fmt.Errorf("read ASK handoff state: %w", err)
			}
			if requestState == string(RequestOpen) && expiresAt <= time.Now().UTC().UnixMicro() {
				now := time.Now().UTC()
				if _, err := conn.ExecContext(ctx, "UPDATE node_local_requests SET state = ?, updated_at_us = ? WHERE request_id = ? AND state = ?", string(RequestExpired), now.UnixMicro(), requestID, string(RequestOpen)); err != nil {
					return fmt.Errorf("expire ASK before handoff: %w", err)
				}
				operationErr = ErrNotPending
				return nil
			}
			if requestState != string(RequestOpen) {
				return ErrNotPending
			}
		}
		now := time.Now().UTC().UnixMicro()
		result, err := conn.ExecContext(ctx, "UPDATE node_local_messages SET delivery_state = ?, handed_off_at_us = ? WHERE message_id = ? AND delivery_state = ?", string(DeliveryHandedOff), now, messageID, string(DeliveryPending))
		if err != nil {
			return fmt.Errorf("record Node inbox acceptance: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			if err != nil {
				return fmt.Errorf("confirm Node inbox acceptance: %w", err)
			}
			return ErrNotPending
		}
		return nil
	})
	if err != nil {
		return err
	}
	return operationErr
}

// RejectPending records a terminal Guard rejection for a message that has not
// crossed into nodeinbox. reason must be a stable nonsecret code, not free-form
// diagnostics or peer content. An exact repeat is idempotent; another digest,
// reason, or already handed-off state cannot overwrite the recorded outcome.
func (l *Ledger) RejectPending(ctx context.Context, messageID, digest, reason string) error {
	messageID = strings.TrimSpace(messageID)
	digest = strings.TrimSpace(digest)
	reason = strings.TrimSpace(reason)
	if ctx == nil || !validToken(messageID, maxIDLength) || len(digest) != sha256.Size*2 || !validReasonCode(reason) {
		return fmt.Errorf("%w: context, message ID, SHA-256 digest, and stable rejection code are required", ErrInvalidInput)
	}
	digestBytes, err := hex.DecodeString(digest)
	if err != nil {
		return fmt.Errorf("%w: invalid SHA-256 digest", ErrInvalidInput)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkOpen(); err != nil {
		return err
	}
	return l.writeTx(ctx, func(conn *sql.Conn) error {
		if _, err := expireRequestsTx(ctx, conn, time.Now().UTC()); err != nil {
			return err
		}
		var storedDigest []byte
		var deliveryState, terminalState, rejectionCode, kind, requestID string
		err := conn.QueryRowContext(ctx, "SELECT digest, delivery_state, terminal_state, rejection_code, kind, request_id FROM node_local_messages WHERE message_id = ?", messageID).Scan(&storedDigest, &deliveryState, &terminalState, &rejectionCode, &kind, &requestID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMessageNotFound
		}
		if err != nil {
			return fmt.Errorf("read Node-local rejection target: %w", err)
		}
		if !bytes.Equal(storedDigest, digestBytes) {
			return ErrMessageConflict
		}
		if terminalState == string(DeliveryRejected) {
			if rejectionCode == reason {
				return nil
			}
			return ErrRejectConflict
		}
		if terminalState != "" || deliveryState != string(DeliveryPending) {
			return ErrNotPending
		}
		if kind == string(KindAsk) {
			var requestState string
			if err := conn.QueryRowContext(ctx, "SELECT state FROM node_local_requests WHERE request_id = ?", requestID).Scan(&requestState); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrNotPending
				}
				return fmt.Errorf("read ASK rejection state: %w", err)
			}
			if requestState != string(RequestOpen) {
				return ErrNotPending
			}
		}
		now := time.Now().UTC().UnixMicro()
		result, err := conn.ExecContext(ctx, "UPDATE node_local_messages SET terminal_state = ?, rejection_code = ?, rejected_at_us = ? WHERE message_id = ? AND delivery_state = ? AND terminal_state = ''", string(DeliveryRejected), reason, now, messageID, string(DeliveryPending))
		if err != nil {
			return fmt.Errorf("record Node-local terminal rejection: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			if err != nil {
				return fmt.Errorf("confirm Node-local terminal rejection: %w", err)
			}
			return ErrNotPending
		}
		return nil
	})
}

// GetMessage returns one immutable message by ID, including its ciphertext
// and correlation fields. It is intended for exact recovery and reauthorization
// after nodeinbox has claimed a delivery.
func (l *Ledger) GetMessage(ctx context.Context, messageID string) (MessageRecord, error) {
	messageID = strings.TrimSpace(messageID)
	if ctx == nil || !validToken(messageID, maxIDLength) {
		return MessageRecord{}, fmt.Errorf("%w: context and message ID are required", ErrInvalidInput)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkOpen(); err != nil {
		return MessageRecord{}, err
	}
	result, err := scanMessage(l.db.QueryRowContext(ctx, messageSelect+" WHERE m.message_id = ?", messageID))
	if errors.Is(err, sql.ErrNoRows) {
		return MessageRecord{}, ErrMessageNotFound
	}
	if err != nil {
		return MessageRecord{}, fmt.Errorf("read Node-local message: %w", err)
	}
	return result, nil
}

type requestInsert struct {
	requestID string
	expiresAt time.Time
}

type preparedMessage struct {
	messageID  string
	kind       MessageKind
	requestID  string
	replyTo    string
	route      Route
	routeJSON  string
	ciphertext []byte
	digest     []byte
	digestHex  string
	expiresAt  time.Time
}

func (l *Ledger) acceptMessage(ctx context.Context, message preparedMessage, request *requestInsert) (Accepted, error) {
	if ctx == nil {
		return Accepted{}, fmt.Errorf("%w: context is required", ErrInvalidInput)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkOpen(); err != nil {
		return Accepted{}, err
	}
	var accepted Accepted
	err := l.writeTx(ctx, func(conn *sql.Conn) error {
		if existing, err := loadMessage(ctx, conn, message.messageID); err == nil {
			if !sameMessage(existing, message) {
				return ErrMessageConflict
			}
			accepted = acceptedFrom(existing, false)
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read existing Node-local message: %w", err)
		}
		now := time.Now().UTC()
		if !message.route.AuthorizationValidUntil.After(now) {
			return ErrAuthorizationExpired
		}
		if request != nil {
			if !request.expiresAt.After(now) {
				return ErrRequestClosed
			}
			var existingMessageID string
			err := conn.QueryRowContext(ctx, "SELECT ask_message_id FROM node_local_requests WHERE request_id = ?", request.requestID).Scan(&existingMessageID)
			if err == nil {
				return ErrRequestConflict
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("check Node-local request identity: %w", err)
			}
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO node_local_messages(message_id, kind, request_id, reply_to_message_id, digest, route_json, source_endpoint_id, target_endpoint_id, target_session_id, target_binding_epoch, scope, ciphertext, delivery_state, expires_at_us, accepted_at_us, handed_off_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)", message.messageID, string(message.kind), message.requestID, message.replyTo, message.digest, message.routeJSON, message.route.SourceEndpointID, message.route.TargetEndpointID, message.route.TargetSessionID, int64(message.route.TargetBindingEpoch), message.route.Scope, message.ciphertext, string(DeliveryPending), nullableTimeMicros(message.expiresAt), now.UnixMicro()); err != nil {
			return fmt.Errorf("persist Node-local message: %w", err)
		}
		if request != nil {
			if _, err := conn.ExecContext(ctx, "INSERT INTO node_local_requests(request_id, ask_message_id, source_endpoint_id, target_endpoint_id, source_group_id, target_group_id, scope, expires_at_us, state, created_at_us, updated_at_us, cancelled_at_us, answered_at_us, reply_message_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, '')", request.requestID, message.messageID, message.route.SourceEndpointID, message.route.TargetEndpointID, message.route.SourceGroupID, message.route.TargetGroupID, message.route.Scope, request.expiresAt.UnixMicro(), string(RequestOpen), now.UnixMicro(), now.UnixMicro()); err != nil {
				return fmt.Errorf("persist Node-local request: %w", err)
			}
		}
		stored, err := loadMessage(ctx, conn, message.messageID)
		if err != nil {
			return fmt.Errorf("read committed Node-local message: %w", err)
		}
		accepted = acceptedFrom(stored, true)
		return nil
	})
	if err != nil {
		return Accepted{}, err
	}
	return accepted, nil
}

func (l *Ledger) acceptReply(ctx context.Context, message preparedMessage) (Accepted, error) {
	if ctx == nil {
		return Accepted{}, fmt.Errorf("%w: context is required", ErrInvalidInput)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkOpen(); err != nil {
		return Accepted{}, err
	}
	var accepted Accepted
	err := l.writeTx(ctx, func(conn *sql.Conn) error {
		if existing, err := loadMessage(ctx, conn, message.messageID); err == nil {
			if !sameMessage(existing, message) {
				return ErrMessageConflict
			}
			accepted = acceptedFrom(existing, false)
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read existing Node-local reply: %w", err)
		}
		now := time.Now().UTC()
		if !message.route.AuthorizationValidUntil.After(now) {
			return ErrAuthorizationExpired
		}
		request, err := loadRequest(ctx, conn, message.requestID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRequestNotFound
		}
		if err != nil {
			return fmt.Errorf("read reply request: %w", err)
		}
		if request.MessageID != message.replyTo || !isReverseRoute(request.Route, message.route) {
			return ErrInvalidReply
		}
		if request.State == RequestAnswered {
			return ErrRequestAlreadyAnswered
		}
		late := request.State == RequestCancelled || request.State == RequestExpired || request.State == RequestRejected || !request.ExpiresAt.After(now)
		state := DeliveryPending
		if late {
			state = DeliveryLate
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO node_local_messages(message_id, kind, request_id, reply_to_message_id, digest, route_json, source_endpoint_id, target_endpoint_id, target_session_id, target_binding_epoch, scope, ciphertext, delivery_state, expires_at_us, accepted_at_us, handed_off_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL)", message.messageID, string(message.kind), message.requestID, message.replyTo, message.digest, message.routeJSON, message.route.SourceEndpointID, message.route.TargetEndpointID, message.route.TargetSessionID, int64(message.route.TargetBindingEpoch), message.route.Scope, message.ciphertext, string(state), now.UnixMicro()); err != nil {
			return fmt.Errorf("persist Node-local reply: %w", err)
		}
		if late {
			if request.State == RequestOpen {
				if _, err := conn.ExecContext(ctx, "UPDATE node_local_requests SET state = ?, updated_at_us = ? WHERE request_id = ? AND state = ?", string(RequestExpired), now.UnixMicro(), message.requestID, string(RequestOpen)); err != nil {
					return fmt.Errorf("expire request before late reply: %w", err)
				}
			}
		} else {
			result, err := conn.ExecContext(ctx, "UPDATE node_local_requests SET state = ?, answered_at_us = ?, updated_at_us = ?, reply_message_id = ? WHERE request_id = ? AND state = ?", string(RequestAnswered), now.UnixMicro(), now.UnixMicro(), message.messageID, message.requestID, string(RequestOpen))
			if err != nil {
				return fmt.Errorf("complete Node-local request: %w", err)
			}
			changed, err := result.RowsAffected()
			if err != nil || changed != 1 {
				if err != nil {
					return fmt.Errorf("confirm Node-local reply association: %w", err)
				}
				return ErrRequestAlreadyAnswered
			}
		}
		stored, err := loadMessage(ctx, conn, message.messageID)
		if err != nil {
			return fmt.Errorf("read stored Node-local reply: %w", err)
		}
		accepted = acceptedFrom(stored, true)
		return nil
	})
	if err != nil {
		return Accepted{}, err
	}
	return accepted, nil
}

func prepareMessage(input MessageInput, kind MessageKind, requestID, replyTo string, expiresAt time.Time) (preparedMessage, error) {
	messageID := strings.TrimSpace(input.MessageID)
	if !validToken(messageID, maxIDLength) {
		return preparedMessage{}, fmt.Errorf("%w: message ID is required", ErrInvalidInput)
	}
	route, err := normalizeRoute(input.Route)
	if err != nil {
		return preparedMessage{}, err
	}
	if len(input.Ciphertext) == 0 || len(input.Ciphertext) > maxCiphertext {
		return preparedMessage{}, fmt.Errorf("%w: sealed ciphertext must be between 1 byte and 1 MiB", ErrInvalidInput)
	}
	if route.Action != string(kind) {
		return preparedMessage{}, fmt.Errorf("%w: route action does not match message kind", ErrInvalidInput)
	}
	routeJSON, err := json.Marshal(route)
	if err != nil {
		return preparedMessage{}, fmt.Errorf("%w: route cannot be serialized", ErrInvalidInput)
	}
	digest := sha256.Sum256(input.Ciphertext)
	return preparedMessage{
		messageID: messageID, kind: kind, requestID: requestID, replyTo: replyTo,
		route: route, routeJSON: string(routeJSON),
		ciphertext: append([]byte(nil), input.Ciphertext...), digest: append([]byte(nil), digest[:]...),
		digestHex: hex.EncodeToString(digest[:]), expiresAt: expiresAt.UTC(),
	}, nil
}

func normalizeRoute(route Route) (Route, error) {
	fields := []*string{
		&route.SourceOwnerID, &route.TargetOwnerID,
		&route.SourceNodeID, &route.TargetNodeID,
		&route.SourcePrincipalID, &route.TargetPrincipalID,
		&route.SourceEndpointID, &route.TargetEndpointID,
		&route.SourceGroupID, &route.TargetGroupID,
		&route.SourceBindingID, &route.TargetBindingID,
		&route.SourceKeyID, &route.TargetKeyID,
		&route.SourceSessionID, &route.TargetSessionID,
		&route.SourceCandidateID, &route.TargetCandidateID,
		&route.AuthorizationRevision,
	}
	for _, field := range fields {
		*field = strings.TrimSpace(*field)
		if !validToken(*field, maxIDLength) {
			return Route{}, fmt.Errorf("%w: route identity fields are required", ErrInvalidInput)
		}
	}
	route.Scope = strings.TrimSpace(route.Scope)
	if !validToken(route.Scope, maxScopeLength) {
		return Route{}, fmt.Errorf("%w: route scope is required", ErrInvalidInput)
	}
	if route.SourceNodeID != route.TargetNodeID {
		return Route{}, fmt.Errorf("%w: Node-local routes must stay on one Node", ErrInvalidInput)
	}
	if route.SourceEndpointID == route.TargetEndpointID {
		return Route{}, fmt.Errorf("%w: source and target endpoints must be distinct", ErrInvalidInput)
	}
	if route.SourceMembershipRevision == 0 || route.TargetMembershipRevision == 0 ||
		route.SourceJoinRevision == 0 || route.TargetJoinRevision == 0 ||
		route.SourceBindingEpoch == 0 || route.TargetBindingEpoch == 0 ||
		route.SourceMembershipRevision > math.MaxInt64 || route.TargetMembershipRevision > math.MaxInt64 ||
		route.SourceJoinRevision > math.MaxInt64 || route.TargetJoinRevision > math.MaxInt64 ||
		route.SourceBindingEpoch > math.MaxInt64 || route.TargetBindingEpoch > math.MaxInt64 {
		return Route{}, fmt.Errorf("%w: membership/join revisions and binding epochs must be positive SQLite integers", ErrInvalidInput)
	}
	if route.SourceCandidateVersion == 0 || route.TargetCandidateVersion == 0 ||
		route.SourceCandidateVersion > math.MaxInt64 || route.TargetCandidateVersion > math.MaxInt64 {
		return Route{}, fmt.Errorf("%w: candidate versions must be positive SQLite integers", ErrInvalidInput)
	}
	route.Action = strings.ToUpper(strings.TrimSpace(route.Action))
	if route.Action != "SEND" && route.Action != "ASK" && route.Action != "REPLY" {
		return Route{}, fmt.Errorf("%w: route action must be SEND, ASK, or REPLY", ErrInvalidInput)
	}
	if route.AuthorizationValidUntil.IsZero() {
		return Route{}, fmt.Errorf("%w: route authorization deadline is required", ErrInvalidInput)
	}
	route.AuthorizationValidUntil = route.AuthorizationValidUntil.UTC()
	return route, nil
}

func isReverseRoute(ask, reply Route) bool {
	return ask.SourceOwnerID == reply.TargetOwnerID && ask.TargetOwnerID == reply.SourceOwnerID &&
		ask.SourceNodeID == reply.TargetNodeID && ask.TargetNodeID == reply.SourceNodeID &&
		ask.SourcePrincipalID == reply.TargetPrincipalID && ask.TargetPrincipalID == reply.SourcePrincipalID &&
		ask.SourceEndpointID == reply.TargetEndpointID && ask.TargetEndpointID == reply.SourceEndpointID &&
		ask.SourceGroupID == reply.TargetGroupID && ask.TargetGroupID == reply.SourceGroupID &&
		ask.SourceMembershipRevision == reply.TargetMembershipRevision && ask.TargetMembershipRevision == reply.SourceMembershipRevision &&
		ask.SourceJoinRevision == reply.TargetJoinRevision && ask.TargetJoinRevision == reply.SourceJoinRevision &&
		ask.SourceBindingID == reply.TargetBindingID && ask.TargetBindingID == reply.SourceBindingID &&
		ask.SourceBindingEpoch == reply.TargetBindingEpoch && ask.TargetBindingEpoch == reply.SourceBindingEpoch &&
		ask.SourceKeyID == reply.TargetKeyID && ask.TargetKeyID == reply.SourceKeyID &&
		ask.SourceSessionID == reply.TargetSessionID && ask.TargetSessionID == reply.SourceSessionID &&
		ask.SourceCandidateID == reply.TargetCandidateID && ask.TargetCandidateID == reply.SourceCandidateID &&
		ask.SourceCandidateVersion == reply.TargetCandidateVersion && ask.TargetCandidateVersion == reply.SourceCandidateVersion &&
		ask.Scope == reply.Scope && reply.Action == "REPLY"
}

func sameMessage(existing MessageRecord, input preparedMessage) bool {
	if existing.MessageID != input.messageID || existing.Kind != input.kind ||
		existing.RequestID != input.requestID || existing.ReplyToMessageID != input.replyTo ||
		existing.Digest != input.digestHex || !bytes.Equal(existing.Ciphertext, input.ciphertext) {
		return false
	}
	if existing.ExpiresAt.IsZero() != input.expiresAt.IsZero() || !existing.ExpiresAt.Equal(input.expiresAt) {
		return false
	}
	// A short-lived Guard authorization deadline proves the individual submit
	// attempt. It is retained in the first accepted snapshot, but refreshed
	// deadlines must not turn an otherwise exact operation retry into a route
	// conflict. AuthorizationRevision and all route identities still compare.
	oldRouteSnapshot := existing.Route
	newRouteSnapshot := input.route
	oldRouteSnapshot.AuthorizationValidUntil = time.Time{}
	newRouteSnapshot.AuthorizationValidUntil = time.Time{}
	oldRoute, errOld := json.Marshal(oldRouteSnapshot)
	newRoute, errNew := json.Marshal(newRouteSnapshot)
	return errOld == nil && errNew == nil && bytes.Equal(oldRoute, newRoute)
}

func acceptedFrom(message MessageRecord, created bool) Accepted {
	return Accepted{MessageID: message.MessageID, RequestID: message.RequestID, Digest: message.Digest,
		Kind: message.Kind, State: message.State, Created: created, AcceptedAt: message.AcceptedAt}
}

func (l *Ledger) initialize(ctx context.Context) error {
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("connect to Node-local ledger: %w", err)
	}
	defer conn.Close()
	if err := configureConnection(ctx, conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
		return fmt.Errorf("enable Node-local ledger WAL: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("lock Node-local ledger schema: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	schemaExists, err := tableExists(ctx, conn, "node_local_schema")
	if err != nil {
		return err
	}
	if !schemaExists {
		messagesExist, err := tableExists(ctx, conn, "node_local_messages")
		if err != nil {
			return err
		}
		requestsExist, err := tableExists(ctx, conn, "node_local_requests")
		if err != nil {
			return err
		}
		if messagesExist || requestsExist {
			return errors.New("unversioned Node-local ledger tables; refusing implicit migration")
		}
		if _, err := conn.ExecContext(ctx, "CREATE TABLE node_local_schema (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), version INTEGER NOT NULL)"); err != nil {
			return fmt.Errorf("create Node-local ledger schema version table: %w", err)
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO node_local_schema(singleton, version) VALUES (1, ?)", currentSchemaVersion); err != nil {
			return fmt.Errorf("initialize Node-local ledger schema version: %w", err)
		}
		if err := createSchemaV2(ctx, conn); err != nil {
			return err
		}
	} else {
		var version int
		if err := conn.QueryRowContext(ctx, "SELECT version FROM node_local_schema WHERE singleton = 1").Scan(&version); err != nil {
			return fmt.Errorf("read Node-local ledger schema version: %w", err)
		}
		switch version {
		case 1:
			if err := migrateSchemaV1ToV2(ctx, conn); err != nil {
				return err
			}
		case currentSchemaVersion:
			if err := verifySchemaV2(ctx, conn); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported Node-local ledger schema version %d", version)
		}
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit Node-local ledger schema: %w", err)
	}
	committed = true
	return nil
}

func createSchemaV2(ctx context.Context, conn *sql.Conn) error {
	for _, statement := range []string{
		"CREATE TABLE node_local_messages (message_id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('SEND','ASK','REPLY')), request_id TEXT NOT NULL DEFAULT '', reply_to_message_id TEXT NOT NULL DEFAULT '', digest BLOB NOT NULL CHECK(length(digest) = 32), route_json TEXT NOT NULL, source_endpoint_id TEXT NOT NULL, target_endpoint_id TEXT NOT NULL, target_session_id TEXT NOT NULL, target_binding_epoch INTEGER NOT NULL CHECK(target_binding_epoch > 0), scope TEXT NOT NULL, ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 0), delivery_state TEXT NOT NULL CHECK(delivery_state IN ('PENDING','NODE_INBOX_ACCEPTED','LATE')), expires_at_us INTEGER, accepted_at_us INTEGER NOT NULL, handed_off_at_us INTEGER, terminal_state TEXT NOT NULL DEFAULT '' CHECK(terminal_state IN ('','REJECTED')), rejection_code TEXT NOT NULL DEFAULT '', rejected_at_us INTEGER)",
		"CREATE INDEX node_local_pending_idx ON node_local_messages(target_endpoint_id, delivery_state, accepted_at_us, message_id)",
		"CREATE UNIQUE INDEX node_local_one_ask_per_request_idx ON node_local_messages(request_id) WHERE kind = 'ASK'",
		"CREATE UNIQUE INDEX node_local_one_reply_per_request_idx ON node_local_messages(request_id) WHERE kind = 'REPLY'",
		"CREATE TABLE node_local_requests (request_id TEXT PRIMARY KEY, ask_message_id TEXT NOT NULL UNIQUE REFERENCES node_local_messages(message_id), source_endpoint_id TEXT NOT NULL, target_endpoint_id TEXT NOT NULL, source_group_id TEXT NOT NULL, target_group_id TEXT NOT NULL, scope TEXT NOT NULL, expires_at_us INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('OPEN','ANSWERED','CANCELLED','EXPIRED')), created_at_us INTEGER NOT NULL, updated_at_us INTEGER NOT NULL, cancelled_at_us INTEGER, answered_at_us INTEGER, reply_message_id TEXT NOT NULL DEFAULT '')",
		"CREATE INDEX node_local_request_deadline_idx ON node_local_requests(state, expires_at_us)",
		"CREATE INDEX node_local_pending_active_idx ON node_local_messages(terminal_state, target_endpoint_id, delivery_state, accepted_at_us, message_id)",
	} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create Node-local ledger schema v2: %w", err)
		}
	}
	return nil
}

func migrateSchemaV1ToV2(ctx context.Context, conn *sql.Conn) error {
	for _, name := range []string{"node_local_messages", "node_local_requests"} {
		exists, err := tableExists(ctx, conn, name)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("Node-local schema v1 is missing required table %s", name)
		}
	}
	if err := ensureMessageTerminalColumns(ctx, conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS node_local_pending_active_idx ON node_local_messages(terminal_state, target_endpoint_id, delivery_state, accepted_at_us, message_id)"); err != nil {
		return fmt.Errorf("upgrade Node-local pending index: %w", err)
	}
	result, err := conn.ExecContext(ctx, "UPDATE node_local_schema SET version = ? WHERE singleton = 1 AND version = 1", currentSchemaVersion)
	if err != nil {
		return fmt.Errorf("advance Node-local ledger schema version: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return fmt.Errorf("confirm Node-local schema version update: %w", err)
		}
		return errors.New("Node-local schema version changed during v1 migration")
	}
	return nil
}

func verifySchemaV2(ctx context.Context, conn *sql.Conn) error {
	columns, err := messageColumns(ctx, conn)
	if err != nil {
		return err
	}
	for _, name := range []string{"terminal_state", "rejection_code", "rejected_at_us"} {
		if !columns[name] {
			return fmt.Errorf("Node-local schema v2 is missing message column %s", name)
		}
	}
	return nil
}

func tableExists(ctx context.Context, conn *sql.Conn, tableName string) (bool, error) {
	var exists int
	err := conn.QueryRowContext(ctx, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", tableName).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect Node-local schema table: %w", err)
	}
	return true, nil
}

func ensureMessageTerminalColumns(ctx context.Context, conn *sql.Conn) error {
	columns, err := messageColumns(ctx, conn)
	if err != nil {
		return err
	}
	for _, column := range []struct {
		name string
		sql  string
	}{
		{name: "terminal_state", sql: "ALTER TABLE node_local_messages ADD COLUMN terminal_state TEXT NOT NULL DEFAULT '' CHECK(terminal_state IN ('','REJECTED'))"},
		{name: "rejection_code", sql: "ALTER TABLE node_local_messages ADD COLUMN rejection_code TEXT NOT NULL DEFAULT ''"},
		{name: "rejected_at_us", sql: "ALTER TABLE node_local_messages ADD COLUMN rejected_at_us INTEGER"},
	} {
		if columns[column.name] {
			continue
		}
		if _, err := conn.ExecContext(ctx, column.sql); err != nil {
			return fmt.Errorf("upgrade Node-local message schema: %w", err)
		}
	}
	return nil
}

func messageColumns(ctx context.Context, conn *sql.Conn) (map[string]bool, error) {
	columns := map[string]bool{}
	rows, err := conn.QueryContext(ctx, "PRAGMA table_info(node_local_messages)")
	if err != nil {
		return nil, fmt.Errorf("inspect Node-local message schema: %w", err)
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read Node-local message schema: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate Node-local message schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close Node-local message schema inspection: %w", err)
	}
	return columns, nil
}

const messageSelect = "SELECT m.message_id, m.kind, m.request_id, m.reply_to_message_id, lower(hex(m.digest)), m.route_json, m.ciphertext, CASE WHEN m.terminal_state = 'REJECTED' THEN 'REJECTED' ELSE m.delivery_state END, m.expires_at_us, m.accepted_at_us, m.handed_off_at_us, m.rejection_code, m.rejected_at_us FROM node_local_messages m"

type rowScanner interface{ Scan(dest ...any) error }

func scanMessage(row rowScanner) (MessageRecord, error) {
	var result MessageRecord
	var routeJSON string
	var expiresAt, acceptedAt, handedOffAt, rejectedAt sql.NullInt64
	if err := row.Scan(&result.MessageID, &result.Kind, &result.RequestID, &result.ReplyToMessageID,
		&result.Digest, &routeJSON, &result.Ciphertext, &result.State, &expiresAt, &acceptedAt, &handedOffAt,
		&result.RejectionCode, &rejectedAt); err != nil {
		return MessageRecord{}, err
	}
	if err := json.Unmarshal([]byte(routeJSON), &result.Route); err != nil {
		return MessageRecord{}, errors.New("stored Node-local route is corrupt")
	}
	result.Ciphertext = append([]byte(nil), result.Ciphertext...)
	if len(result.Digest) != sha256.Size*2 {
		return MessageRecord{}, errors.New("stored Node-local message digest is corrupt")
	}
	digest, err := hex.DecodeString(result.Digest)
	if err != nil {
		return MessageRecord{}, errors.New("stored Node-local message digest is corrupt")
	}
	actual := sha256.Sum256(result.Ciphertext)
	if !bytes.Equal(digest, actual[:]) {
		return MessageRecord{}, errors.New("stored Node-local ciphertext digest is corrupt")
	}
	if expiresAt.Valid {
		result.ExpiresAt = time.UnixMicro(expiresAt.Int64).UTC()
	}
	if acceptedAt.Valid {
		result.AcceptedAt = time.UnixMicro(acceptedAt.Int64).UTC()
	}
	if handedOffAt.Valid {
		result.HandedOffAt = time.UnixMicro(handedOffAt.Int64).UTC()
	}
	if rejectedAt.Valid {
		result.RejectedAt = time.UnixMicro(rejectedAt.Int64).UTC()
	}
	return result, nil
}

func loadMessage(ctx context.Context, conn *sql.Conn, messageID string) (MessageRecord, error) {
	return scanMessage(conn.QueryRowContext(ctx, messageSelect+" WHERE m.message_id = ?", messageID))
}

func loadRequest(ctx context.Context, conn *sql.Conn, requestID string) (Request, error) {
	var request Request
	var state string
	var expiresAt, createdAt, updatedAt, cancelledAt, answeredAt sql.NullInt64
	var routeJSON string
	err := conn.QueryRowContext(ctx, "SELECT r.request_id, r.ask_message_id, r.source_endpoint_id, r.target_endpoint_id, r.scope, r.expires_at_us, CASE WHEN m.terminal_state = 'REJECTED' THEN 'REJECTED' ELSE r.state END, r.reply_message_id, m.route_json, r.created_at_us, r.updated_at_us, r.cancelled_at_us, r.answered_at_us FROM node_local_requests r JOIN node_local_messages m ON m.message_id = r.ask_message_id WHERE r.request_id = ?", requestID).Scan(&request.RequestID, &request.MessageID, &request.SourceEndpointID, &request.TargetEndpointID, &request.Scope, &expiresAt, &state, &request.ReplyMessageID, &routeJSON, &createdAt, &updatedAt, &cancelledAt, &answeredAt)
	if err != nil {
		return Request{}, err
	}
	if err := json.Unmarshal([]byte(routeJSON), &request.Route); err != nil {
		return Request{}, errors.New("stored Node-local request route is corrupt")
	}
	request.State = RequestState(state)
	request.ExpiresAt = time.UnixMicro(expiresAt.Int64).UTC()
	request.CreatedAt = time.UnixMicro(createdAt.Int64).UTC()
	request.UpdatedAt = time.UnixMicro(updatedAt.Int64).UTC()
	if cancelledAt.Valid {
		request.CancelledAt = time.UnixMicro(cancelledAt.Int64).UTC()
	}
	if answeredAt.Valid {
		request.AnsweredAt = time.UnixMicro(answeredAt.Int64).UTC()
	}
	rows, err := conn.QueryContext(ctx, "SELECT message_id FROM node_local_messages WHERE request_id = ? AND kind = 'REPLY' AND delivery_state = ? ORDER BY accepted_at_us, message_id", requestID, string(DeliveryLate))
	if err != nil {
		return Request{}, fmt.Errorf("read late Node-local replies: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var messageID string
		if err := rows.Scan(&messageID); err != nil {
			return Request{}, fmt.Errorf("read late Node-local reply ID: %w", err)
		}
		request.LateReplyMessageIDs = append(request.LateReplyMessageIDs, messageID)
	}
	if err := rows.Err(); err != nil {
		return Request{}, fmt.Errorf("iterate late Node-local replies: %w", err)
	}
	return request, nil
}

func expireRequestsTx(ctx context.Context, conn *sql.Conn, now time.Time) (int, error) {
	result, err := conn.ExecContext(ctx, "UPDATE node_local_requests SET state = ?, updated_at_us = ? WHERE state = ? AND expires_at_us <= ? AND NOT EXISTS (SELECT 1 FROM node_local_messages m WHERE m.message_id = node_local_requests.ask_message_id AND m.terminal_state = 'REJECTED')", string(RequestExpired), now.UnixMicro(), string(RequestOpen), now.UnixMicro())
	if err != nil {
		return 0, fmt.Errorf("expire Node-local requests: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count expired Node-local requests: %w", err)
	}
	return int(changed), nil
}

func (l *Ledger) writeTx(ctx context.Context, action func(*sql.Conn) error) error {
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("connect to Node-local ledger: %w", err)
	}
	defer conn.Close()
	if err := configureConnection(ctx, conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin Node-local ledger transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	if err := action(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit Node-local ledger transaction: %w", err)
	}
	committed = true
	return nil
}

func configureConnection(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout = %d", busyTimeoutMillis)); err != nil {
		return fmt.Errorf("configure Node-local ledger busy timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA synchronous = FULL"); err != nil {
		return fmt.Errorf("configure Node-local ledger synchronous commits: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("configure Node-local ledger foreign keys: %w", err)
	}
	return nil
}

func (l *Ledger) checkOpen() error {
	if l == nil || l.closed || l.db == nil {
		return ErrClosed
	}
	return nil
}

func validToken(value string, max int) bool {
	if value == "" || len(value) > max || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validReasonCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' {
			return false
		}
	}
	return true
}

func nullableTimeMicros(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC().UnixMicro()
}

func isMemoryPath(path string) bool {
	return path == ":memory:" || strings.HasPrefix(path, "file::memory:") || strings.HasPrefix(path, "file:memdb")
}

func prepareDatabaseFile(path string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create Node-local ledger directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, databaseMode)
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return fmt.Errorf("inspect Node-local ledger database: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("Node-local ledger database must be a regular file")
		}
		file, err = os.OpenFile(path, os.O_RDWR, 0)
	}
	if err != nil {
		return fmt.Errorf("create or open Node-local ledger database: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat Node-local ledger database: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		return errors.New("Node-local ledger database path changed while opening")
	}
	if err := file.Chmod(databaseMode); err != nil {
		return fmt.Errorf("protect Node-local ledger database: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync Node-local ledger database file: %w", err)
	}
	parent, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open Node-local ledger directory for sync: %w", err)
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync Node-local ledger directory: %w", err)
	}
	return nil
}
