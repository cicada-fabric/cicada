package store

// This file contains the additive v2 Relay/Ask persistence layer. Legacy
// plaintext envelopes remain in fabric_messages for compatibility. SEALED_V1
// route rows keep that body empty and store caller-supplied opaque bytes in a
// separate constrained BLOB; this Store does not perform endpoint encryption.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	RelayPayloadModePlaintext = "PLAINTEXT"
	RelayPayloadModeSealedV1  = "SEALED_V1"

	FabricRequestOpen            = "OPEN"
	FabricRequestCancelRequested = "CANCEL_REQUESTED"
	FabricRequestCancelled       = "CANCELLED"
	FabricRequestExpired         = "EXPIRED"
	FabricRequestReplied         = "REPLIED"
	FabricRequestLateResult      = "LATE_RESULT"

	RelayInboxReady     = "READY"
	RelayInboxClaimed   = "CLAIMED"
	RelayInboxInjected  = "INJECTED"
	RelayInboxAcked     = "ACKED"
	RelayInboxFailed    = "FAILED"
	RelayInboxUncertain = "INJECTION_UNCERTAIN"
	RelayInboxExpired   = "EXPIRED"
	RelayInboxCancelled = "CANCELLED"

	RelayAttemptClaimed   = "CLAIMED"
	RelayAttemptInjected  = "INJECTED"
	RelayAttemptAcked     = "ACKED"
	RelayAttemptFailed    = "FAILED"
	RelayAttemptUncertain = "INJECTION_UNCERTAIN"
	RelayAttemptCancelled = "CANCELLED"

	RelayReceiptAccepted            = "RELAY_ACCEPTED"
	RelayReceiptNodeReceived        = "NODE_RECEIVED"
	RelayReceiptCodexQueueAccepted  = "CODEX_QUEUE_ACCEPTED"
	RelayReceiptNativeThreadResumed = "NATIVE_THREAD_RESUMED"
	RelayReceiptRuntimeInjected     = "RUNTIME_INJECTED"
	RelayReceiptConsumptionUnknown  = "CONSUMPTION_UNCONFIRMED"
	RelayReceiptApplicationAck      = "APPLICATION_ACKNOWLEDGED"
	RelayReceiptResultAccepted      = "RESULT_ACCEPTED"
	RelayReceiptInjectionUncertain  = "INJECTION_UNCERTAIN"
	RelayReceiptFailed              = "FAILED"
)

// Compatibility spellings mirror the vocabulary used by the fabric package
// while keeping the persistence package independent from it.
const (
	ReceiptRelayAccepted           = RelayReceiptAccepted
	ReceiptNodeReceived            = RelayReceiptNodeReceived
	ReceiptCodexQueueAccepted      = RelayReceiptCodexQueueAccepted
	ReceiptNativeThreadResumed     = RelayReceiptNativeThreadResumed
	ReceiptRuntimeInjected         = RelayReceiptRuntimeInjected
	ReceiptConsumptionUnconfirmed  = RelayReceiptConsumptionUnknown
	ReceiptApplicationAcknowledged = RelayReceiptApplicationAck
	ReceiptResultAccepted          = RelayReceiptResultAccepted
	ReceiptInjectionUncertain      = RelayReceiptInjectionUncertain
)

// Relay admission is intentionally bounded at the Ask layer. The limits are
// persisted with the relay schema so every Store handle for the same state
// database applies the same policy. A pending request is OPEN or
// CANCEL_REQUESTED and has not passed its expiry deadline.
const (
	RelayAdmissionScopeSenderPrincipal = "sender_principal"
	RelayAdmissionScopeSenderEndpoint  = "sender_endpoint"
	RelayAdmissionScopeSenderGroup     = "sender_group"
	RelayAdmissionScopeReceiver        = "receiver_endpoint"
	RelayAdmissionScopeGlobal          = "global"

	DefaultRelayPendingAsksPerSenderEndpoint = 16
	DefaultRelayPendingAsksPerPrincipal      = 64
	DefaultRelayPendingAsksPerGroup          = 256
	DefaultRelayPendingAsksPerReceiver       = 64
	DefaultRelayPendingAsksGlobal            = 1024
	DefaultRelayAdmissionRetryAfterSec       = 1
	DefaultRelayAskLifetime                  = 30 * time.Minute
	MaxRelayAskLifetime                      = 24 * time.Hour
)

// RelayAdmissionLimits controls the maximum number of pending Ask records in
// each admission scope. Values are durable per Store database through
// ConfigureRelayAdmissionLimits. The zero value is replaced by fixed defaults
// when configuring a database.
type RelayAdmissionLimits struct {
	PerSenderPrincipal int `json:"per_sender_principal"`
	PerSenderGroup     int `json:"per_sender_group"`
	PerReceiver        int `json:"per_receiver"`
	Global             int `json:"global"`
	RetryAfterSeconds  int `json:"retry_after_seconds"`
}

// DefaultRelayAdmissionLimits returns the documented fixed defaults. It is a
// function rather than a mutable package variable so one Store cannot change
// the admission policy of another Store in the same process.
func DefaultRelayAdmissionLimits() RelayAdmissionLimits {
	return RelayAdmissionLimits{
		PerSenderPrincipal: DefaultRelayPendingAsksPerPrincipal,
		PerSenderGroup:     DefaultRelayPendingAsksPerGroup,
		PerReceiver:        DefaultRelayPendingAsksPerReceiver,
		Global:             DefaultRelayPendingAsksGlobal,
		RetryAfterSeconds:  DefaultRelayAdmissionRetryAfterSec,
	}
}

// ErrRelayResourceExhausted is returned when a pending Ask admission scope is
// full. The concrete RelayAdmissionError carries the exceeded scope, limit,
// current count, and a bounded retry delay for transport adapters.
var ErrRelayResourceExhausted = errors.New("RESOURCE_EXHAUSTED")

// RelayAdmissionError is an explainable, retryable admission rejection. It
// deliberately does not expose message bodies or identities beyond the
// bounded scope label needed by a caller to choose its retry behavior.
type RelayAdmissionError struct {
	Scope             string        `json:"scope"`
	Limit             int           `json:"limit"`
	Pending           int           `json:"pending"`
	RetryAfter        time.Duration `json:"-"`
	RetryAfterSeconds int           `json:"retry_after_seconds"`
}

func (e *RelayAdmissionError) Error() string {
	if e == nil {
		return ErrRelayResourceExhausted.Error()
	}
	retrySeconds := e.RetryAfterSeconds
	if retrySeconds <= 0 && e.RetryAfter > 0 {
		retrySeconds = int((e.RetryAfter + time.Second - 1) / time.Second)
	}
	if retrySeconds <= 0 {
		retrySeconds = DefaultRelayAdmissionRetryAfterSec
	}
	return fmt.Sprintf("%s: pending %s limit %d reached (%d); retry after %ds",
		ErrRelayResourceExhausted, e.Scope, e.Limit, e.Pending, retrySeconds)
}

func (e *RelayAdmissionError) Unwrap() error { return ErrRelayResourceExhausted }

// RetryAfterDuration implements the small transport-neutral contract used by
// HTTP/MCP adapters. RetryAfter remains an exported duration for callers that
// do not want to parse the error text.
func (e *RelayAdmissionError) RetryAfterDuration() time.Duration {
	if e == nil {
		return 0
	}
	if e.RetryAfter > 0 {
		return e.RetryAfter
	}
	seconds := e.RetryAfterSeconds
	if seconds <= 0 {
		seconds = DefaultRelayAdmissionRetryAfterSec
	}
	return time.Duration(seconds) * time.Second
}

var (
	ErrRelayRequestNotFound     = errors.New("relay request not found")
	ErrRelayMessageNotFound     = errors.New("relay message not found")
	ErrRelayDeliveryNotFound    = errors.New("relay delivery not found")
	ErrRelayIdempotencyConflict = errors.New("relay idempotency key conflicts with existing digest")
	ErrRelayMessageConflict     = errors.New("relay message conflicts with existing envelope")
	ErrRelayInvalidState        = errors.New("relay object has invalid state transition")
	ErrRelayInvalidReceipt      = errors.New("relay receipt does not match delivery")
	ErrRelayStaleReceipt        = errors.New("relay receipt is stale")
	ErrRelayNoDelivery          = errors.New("relay inbox has no claimable delivery")
	ErrRelayCursor              = errors.New("relay cursor is invalid")
	ErrRelayBindingMismatch     = errors.New("relay delivery binding does not match target")
	ErrRelayPayloadModeMismatch = errors.New("relay payload mode does not match API")
	ErrRelayCiphertextDigest    = errors.New("relay sealed payload digest does not match stored ciphertext")
	ErrRelayRequestTerminal     = errors.New("relay request is already terminal")
	ErrRelayPlaintextSealedPeer = errors.New("plaintext delivery is disabled for a sealed-capable endpoint")
)

// Aliases make the errors easy to use from callers that do not otherwise care
// whether an operation went through the relay or a request facade.
var (
	ErrIdempotencyConflict = ErrRelayIdempotencyConflict
	ErrInvalidReceipt      = ErrRelayInvalidReceipt
	ErrStaleReceipt        = ErrRelayStaleReceipt
)

// FabricRequest is the structured v2 Ask record.  MessageID points at the
// immutable legacy envelope.  Body/Metadata/Message are input conveniences;
// Get methods leave them empty unless a caller explicitly asks for the
// envelope with GetFabricMessage.
type FabricRequest struct {
	RequestID            string `json:"request_id"`
	MessageID            string `json:"message_id"`
	ParentRequestID      string `json:"parent_request_id,omitempty"`
	CausalRootRequestID  string `json:"-"`
	CausalDepth          int    `json:"-"`
	SenderEndpointID     string `json:"sender_endpoint_id"`
	SenderPrincipalID    string `json:"sender_principal_id"`
	SenderGroupID        string `json:"sender_group_id"`
	SenderBindingID      string `json:"sender_binding_id,omitempty"`
	SenderBindingEpoch   uint64 `json:"sender_binding_epoch,omitempty"`
	ReceiverEndpointID   string `json:"receiver_endpoint_id"`
	ReceiverPrincipalID  string `json:"receiver_principal_id,omitempty"`
	ReceiverGroupID      string `json:"receiver_group_id"`
	ReceiverBindingID    string `json:"receiver_binding_id,omitempty"`
	ReceiverBindingEpoch uint64 `json:"receiver_binding_epoch,omitempty"`
	Digest               string `json:"digest"`
	IdempotencyKey       string `json:"idempotency_key,omitempty"`
	VisibilityPolicyRef  string `json:"visibility_policy_ref,omitempty"`
	AuthorizationRef     string `json:"authorization_ref,omitempty"`
	State                string `json:"state"`
	ExpiresAt            string `json:"expires_at,omitempty"`
	CancelRequestedAt    string `json:"cancel_requested_at,omitempty"`
	CancelledAt          string `json:"cancelled_at,omitempty"`
	ExpiredAt            string `json:"expired_at,omitempty"`
	RepliedAt            string `json:"replied_at,omitempty"`
	LateResultAt         string `json:"late_result_at,omitempty"`
	ReplyMessageID       string `json:"reply_message_id,omitempty"`
	LateResultMessageID  string `json:"late_result_message_id,omitempty"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`

	// Input-only fields.  They are never persisted in the v2 tables.
	Body     string         `json:"body,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Message  *FabricMessage `json:"message,omitempty"`
}

// RelayMessageSecurity is routing/authentication metadata for one immutable
// fabric_messages envelope.  It intentionally does not contain the body.
type RelayMessageSecurity struct {
	MessageID            string `json:"message_id"`
	Digest               string `json:"digest"`
	IdempotencyKey       string `json:"idempotency_key,omitempty"`
	SenderEndpointID     string `json:"sender_endpoint_id"`
	SenderPrincipalID    string `json:"sender_principal_id"`
	SenderGroupID        string `json:"sender_group_id"`
	SenderBindingID      string `json:"sender_binding_id,omitempty"`
	SenderBindingEpoch   uint64 `json:"sender_binding_epoch,omitempty"`
	ReceiverEndpointID   string `json:"receiver_endpoint_id"`
	ReceiverPrincipalID  string `json:"receiver_principal_id,omitempty"`
	ReceiverGroupID      string `json:"receiver_group_id"`
	ReceiverBindingID    string `json:"receiver_binding_id,omitempty"`
	ReceiverBindingEpoch uint64 `json:"receiver_binding_epoch,omitempty"`
	VisibilityPolicyRef  string `json:"visibility_policy_ref,omitempty"`
	AuthorizationRef     string `json:"authorization_ref,omitempty"`
	CreatedAt            string `json:"created_at"`
}

// FabricMessageSecurity is kept as a descriptive alias for callers that use
// the architecture document's terminology.
type FabricMessageSecurity = RelayMessageSecurity

type RelayMessageInput struct {
	Message        FabricMessage        `json:"message"`
	Security       RelayMessageSecurity `json:"security"`
	Digest         string               `json:"digest,omitempty"`
	IdempotencyKey string               `json:"idempotency_key,omitempty"`
	ExpiresAt      string               `json:"expires_at,omitempty"`
	// Only the Link-authorized request transaction may persist a sealed Ask;
	// the generic sealed message API must not create an orphan request route.
	sealedAskAuthorized bool
	// Only the correlated Link reply transaction may persist a sealed Reply;
	// the generic sealed message API must not create an orphan reverse route.
	sealedReplyAuthorized bool
	// Set only by the Network direct sealed Store transaction after it has
	// checked both current Network enrollments and owner-approved Endpoint keys.
	networkDirectAuthorized bool
	// Set only by a CommunicationLink Store transaction after it has checked
	// the exact Link, key manifest, bilateral Owner grants and current bindings.
	communicationLinkAuthorized bool
}

// RelaySealedV1Route contains the clear routing envelope that accompanies an
// opaque caller-produced ciphertext. It deliberately has no body or arbitrary
// metadata field, so sealed payload bytes cannot be mistaken for Fabric text.
type RelaySealedV1Route struct {
	MessageID          string `json:"message_id"`
	RequestID          string `json:"request_id,omitempty"`
	ReplyTo            string `json:"reply_to,omitempty"`
	SenderEndpointID   string `json:"sender_endpoint_id"`
	ReceiverEndpointID string `json:"receiver_endpoint_id"`
	Kind               string `json:"kind"`
}

// RelaySealedV1Input stores caller-supplied bytes as an opaque BLOB. The Store
// does not encrypt, decrypt, or attest how the bytes were produced.
type RelaySealedV1Input struct {
	Route          RelaySealedV1Route   `json:"route"`
	Security       RelayMessageSecurity `json:"security"`
	Ciphertext     []byte               `json:"ciphertext"`
	Digest         string               `json:"digest,omitempty"`
	IdempotencyKey string               `json:"idempotency_key,omitempty"`
}

// RelaySealedV1Record is returned only by the dedicated sealed-payload API.
type RelaySealedV1Record struct {
	PayloadMode string               `json:"payload_mode"`
	Route       RelaySealedV1Route   `json:"route"`
	Security    RelayMessageSecurity `json:"security"`
	Ciphertext  []byte               `json:"ciphertext"`
	Sequence    int64                `json:"sequence,omitempty"`
	OutboxState string               `json:"outbox_state,omitempty"`
	CreatedAt   string               `json:"created_at,omitempty"`
}

// RelaySealedV1DeliveryAttempt is returned by ClaimRelaySealedV1Inbox. It
// carries delivery coordinates but intentionally has no FabricMessage body;
// the complete bytes and route are explicit fields.
type RelaySealedV1DeliveryAttempt struct {
	AttemptID           string               `json:"attempt_id"`
	MessageID           string               `json:"message_id"`
	RequestID           string               `json:"request_id,omitempty"`
	Digest              string               `json:"digest"`
	RecipientEndpointID string               `json:"recipient_endpoint_id"`
	ReceiverGroupID     string               `json:"receiver_group_id"`
	BindingID           string               `json:"binding_id,omitempty"`
	BindingEpoch        uint64               `json:"binding_epoch,omitempty"`
	Sequence            int64                `json:"sequence"`
	ConsumerID          string               `json:"consumer_id,omitempty"`
	State               string               `json:"state"`
	ClaimedAt           string               `json:"claimed_at"`
	CreatedAt           string               `json:"created_at"`
	PayloadMode         string               `json:"payload_mode"`
	Route               RelaySealedV1Route   `json:"route"`
	Security            RelayMessageSecurity `json:"security"`
	Ciphertext          []byte               `json:"ciphertext"`
}

type RelayMessageRecord struct {
	Message     FabricMessage        `json:"message"`
	Security    RelayMessageSecurity `json:"security"`
	Sequence    int64                `json:"sequence,omitempty"`
	OutboxState string               `json:"outbox_state,omitempty"`
}

// RelayDeliveryAttempt records one claim.  Message is loaded from the legacy
// immutable envelope table and is not copied into relay_v2_delivery_attempts.
type RelayDeliveryAttempt struct {
	AttemptID string `json:"attempt_id"`
	MessageID string `json:"message_id"`
	// EndpointID is a compatibility alias for adapters that call the target
	// endpoint simply "endpoint".  RecipientEndpointID remains authoritative.
	EndpointID          string         `json:"endpoint_id,omitempty"`
	RequestID           string         `json:"request_id,omitempty"`
	Digest              string         `json:"digest"`
	RecipientEndpointID string         `json:"recipient_endpoint_id"`
	ReceiverGroupID     string         `json:"receiver_group_id"`
	BindingID           string         `json:"binding_id,omitempty"`
	BindingEpoch        uint64         `json:"binding_epoch,omitempty"`
	Sequence            int64          `json:"sequence"`
	ConsumerID          string         `json:"consumer_id,omitempty"`
	State               string         `json:"state"`
	Failure             string         `json:"failure,omitempty"`
	ClaimedAt           string         `json:"claimed_at"`
	CompletedAt         string         `json:"completed_at,omitempty"`
	CreatedAt           string         `json:"created_at"`
	Message             *FabricMessage `json:"message,omitempty"`
}

// Short aliases keep the data model readable at transport boundaries.
type DeliveryAttempt = RelayDeliveryAttempt

// RelayReceipt is the persisted, layered acknowledgement.  An ACK is valid
// only when all immutable delivery coordinates match the claimed attempt.
type RelayReceipt struct {
	ReceiptID         string `json:"receipt_id"`
	AttemptID         string `json:"attempt_id,omitempty"`
	DeliveryAttemptID string `json:"delivery_attempt_id,omitempty"`
	MessageID         string `json:"message_id"`
	Digest            string `json:"digest"`
	MessageDigest     string `json:"message_digest,omitempty"`
	TargetEndpointID  string `json:"target_endpoint_id"`
	EndpointID        string `json:"endpoint_id,omitempty"`
	BindingID         string `json:"binding_id,omitempty"`
	BindingEpoch      uint64 `json:"binding_epoch,omitempty"`
	Layer             string `json:"layer"`
	Status            string `json:"status,omitempty"`
	Error             string `json:"error,omitempty"`
	CreatedAt         string `json:"created_at"`
}

type Receipt = RelayReceipt

type RelayInboxItem struct {
	Sequence            int64          `json:"sequence"`
	MessageID           string         `json:"message_id"`
	RequestID           string         `json:"request_id,omitempty"`
	Digest              string         `json:"digest"`
	RecipientEndpointID string         `json:"recipient_endpoint_id"`
	EndpointID          string         `json:"endpoint_id,omitempty"`
	ReceiverGroupID     string         `json:"receiver_group_id"`
	BindingID           string         `json:"binding_id,omitempty"`
	BindingEpoch        uint64         `json:"binding_epoch,omitempty"`
	AttemptID           string         `json:"attempt_id,omitempty"`
	State               string         `json:"state"`
	CreatedAt           string         `json:"created_at"`
	UpdatedAt           string         `json:"updated_at"`
	Message             *FabricMessage `json:"message,omitempty"`
}

type InboxMessage = RelayInboxItem

type RelayReceiveResult struct {
	Messages   []RelayInboxItem `json:"messages"`
	Items      []RelayInboxItem `json:"items,omitempty"`
	NextCursor string           `json:"next_cursor"`
}

type RelayCursor struct {
	RecipientEndpointID string `json:"recipient_endpoint_id"`
	ConsumerID          string `json:"consumer_id"`
	BindingID           string `json:"binding_id,omitempty"`
	BindingEpoch        uint64 `json:"binding_epoch,omitempty"`
	Sequence            int64  `json:"sequence"`
}

type relayV2Cursor = RelayCursor

// RelayClaimInput is the strict form used by Node adapters.  BindingID and
// BindingEpoch are checked against the immutable recipient metadata on every
// claim and acknowledgement.
type RelayClaimInput struct {
	RecipientEndpointID string
	EndpointID          string
	ConsumerID          string
	BindingID           string
	BindingEpoch        uint64
	Cursor              string
	Limit               int
}

type RelayRequestFilter struct {
	State              string
	SenderPrincipalID  string
	SenderGroupID      string
	ReceiverGroupID    string
	ReceiverEndpointID string
	Limit              int
}

const relayV2Schema = `
CREATE TABLE IF NOT EXISTS relay_v2_message_security (
  message_id TEXT PRIMARY KEY,
  digest TEXT NOT NULL,
  idempotency_key TEXT NOT NULL DEFAULT '',
  sender_endpoint_id TEXT NOT NULL,
  sender_principal_id TEXT NOT NULL,
  sender_group_id TEXT NOT NULL,
  sender_binding_id TEXT NOT NULL DEFAULT '',
  sender_binding_epoch INTEGER NOT NULL DEFAULT 0 CHECK(sender_binding_epoch >= 0),
  receiver_endpoint_id TEXT NOT NULL,
  receiver_principal_id TEXT NOT NULL DEFAULT '',
  receiver_group_id TEXT NOT NULL,
  receiver_binding_id TEXT NOT NULL DEFAULT '',
  receiver_binding_epoch INTEGER NOT NULL DEFAULT 0 CHECK(receiver_binding_epoch >= 0),
  visibility_policy_ref TEXT NOT NULL DEFAULT '',
  authorization_ref TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY(message_id) REFERENCES fabric_messages(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS relay_v2_message_idempotency_idx
  ON relay_v2_message_security(sender_principal_id, sender_group_id, idempotency_key)
  WHERE idempotency_key <> '';
CREATE INDEX IF NOT EXISTS relay_v2_message_sender_idx
  ON relay_v2_message_security(sender_principal_id, sender_group_id, created_at);
CREATE INDEX IF NOT EXISTS relay_v2_message_receiver_idx
  ON relay_v2_message_security(receiver_group_id, receiver_endpoint_id, created_at);

CREATE TABLE IF NOT EXISTS relay_v2_requests (
  request_id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL UNIQUE,
  sender_endpoint_id TEXT NOT NULL,
  sender_principal_id TEXT NOT NULL,
  sender_group_id TEXT NOT NULL,
  sender_binding_id TEXT NOT NULL DEFAULT '',
  sender_binding_epoch INTEGER NOT NULL DEFAULT 0 CHECK(sender_binding_epoch >= 0),
  receiver_endpoint_id TEXT NOT NULL,
  receiver_principal_id TEXT NOT NULL DEFAULT '',
  receiver_group_id TEXT NOT NULL,
  receiver_binding_id TEXT NOT NULL DEFAULT '',
  receiver_binding_epoch INTEGER NOT NULL DEFAULT 0 CHECK(receiver_binding_epoch >= 0),
  digest TEXT NOT NULL,
  idempotency_key TEXT NOT NULL DEFAULT '',
  visibility_policy_ref TEXT NOT NULL DEFAULT '',
  authorization_ref TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL CHECK(state IN ('OPEN','CANCEL_REQUESTED','CANCELLED','EXPIRED','REPLIED','LATE_RESULT')),
  expires_at TEXT NOT NULL DEFAULT '',
  cancel_requested_at TEXT NOT NULL DEFAULT '',
  cancelled_at TEXT NOT NULL DEFAULT '',
  expired_at TEXT NOT NULL DEFAULT '',
  replied_at TEXT NOT NULL DEFAULT '',
  late_result_at TEXT NOT NULL DEFAULT '',
  reply_message_id TEXT NOT NULL DEFAULT '',
  late_result_message_id TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(message_id) REFERENCES fabric_messages(id)
);
CREATE INDEX IF NOT EXISTS relay_v2_requests_state_idx
  ON relay_v2_requests(state, expires_at, updated_at);
CREATE INDEX IF NOT EXISTS relay_v2_requests_sender_idx
  ON relay_v2_requests(sender_principal_id, sender_group_id, created_at);
CREATE INDEX IF NOT EXISTS relay_v2_requests_receiver_idx
  ON relay_v2_requests(receiver_group_id, receiver_endpoint_id, created_at);

CREATE TABLE IF NOT EXISTS relay_v2_outbox (
  message_id TEXT PRIMARY KEY,
  sender_principal_id TEXT NOT NULL,
  sender_group_id TEXT NOT NULL,
  recipient_endpoint_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'RELAY_ACCEPTED',
  error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  accepted_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(message_id) REFERENCES fabric_messages(id)
);
CREATE INDEX IF NOT EXISTS relay_v2_outbox_pending_idx
  ON relay_v2_outbox(state, updated_at, message_id);

CREATE TABLE IF NOT EXISTS relay_v2_recipient_sequences (
  recipient_endpoint_id TEXT PRIMARY KEY,
  next_sequence INTEGER NOT NULL DEFAULT 1 CHECK(next_sequence > 0)
);

CREATE TABLE IF NOT EXISTS relay_v2_inbox (
  recipient_endpoint_id TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence > 0),
  message_id TEXT NOT NULL,
  digest TEXT NOT NULL,
  receiver_group_id TEXT NOT NULL,
  binding_id TEXT NOT NULL DEFAULT '',
  binding_epoch INTEGER NOT NULL DEFAULT 0 CHECK(binding_epoch >= 0),
  state TEXT NOT NULL CHECK(state IN ('READY','CLAIMED','INJECTED','ACKED','FAILED','INJECTION_UNCERTAIN','EXPIRED','CANCELLED')),
  attempt_id TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(recipient_endpoint_id, sequence),
  UNIQUE(recipient_endpoint_id, message_id),
  FOREIGN KEY(message_id) REFERENCES fabric_messages(id)
);
CREATE INDEX IF NOT EXISTS relay_v2_inbox_pending_idx
  ON relay_v2_inbox(recipient_endpoint_id, state, sequence);
CREATE INDEX IF NOT EXISTS relay_v2_inbox_message_idx
  ON relay_v2_inbox(message_id, recipient_endpoint_id);

CREATE TABLE IF NOT EXISTS relay_v2_consumer_cursors (
  recipient_endpoint_id TEXT NOT NULL,
  consumer_id TEXT NOT NULL,
  binding_id TEXT NOT NULL DEFAULT '',
  binding_epoch INTEGER NOT NULL DEFAULT 0 CHECK(binding_epoch >= 0),
  sequence INTEGER NOT NULL DEFAULT 0 CHECK(sequence >= 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY(recipient_endpoint_id, consumer_id, binding_id)
);

CREATE TABLE IF NOT EXISTS relay_v2_delivery_attempts (
  attempt_id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  request_id TEXT NOT NULL DEFAULT '',
  recipient_endpoint_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  digest TEXT NOT NULL,
  binding_id TEXT NOT NULL DEFAULT '',
  binding_epoch INTEGER NOT NULL DEFAULT 0 CHECK(binding_epoch >= 0),
  consumer_id TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL CHECK(state IN ('CLAIMED','INJECTED','ACKED','FAILED','INJECTION_UNCERTAIN','CANCELLED')),
  failure TEXT NOT NULL DEFAULT '',
  claimed_at TEXT NOT NULL,
  completed_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY(message_id) REFERENCES fabric_messages(id),
  FOREIGN KEY(recipient_endpoint_id, sequence) REFERENCES relay_v2_inbox(recipient_endpoint_id, sequence)
);
CREATE INDEX IF NOT EXISTS relay_v2_attempt_message_idx
  ON relay_v2_delivery_attempts(message_id, created_at);
CREATE INDEX IF NOT EXISTS relay_v2_attempt_pending_idx
  ON relay_v2_delivery_attempts(recipient_endpoint_id, state, claimed_at);

CREATE TABLE IF NOT EXISTS relay_v2_receipts (
  receipt_id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL DEFAULT '',
  message_id TEXT NOT NULL,
  digest TEXT NOT NULL,
  target_endpoint_id TEXT NOT NULL,
  binding_id TEXT NOT NULL DEFAULT '',
  binding_epoch INTEGER NOT NULL DEFAULT 0 CHECK(binding_epoch >= 0),
  layer TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE(message_id, attempt_id, layer),
  FOREIGN KEY(message_id) REFERENCES fabric_messages(id)
);
CREATE INDEX IF NOT EXISTS relay_v2_receipt_message_idx
  ON relay_v2_receipts(message_id, created_at);
CREATE INDEX IF NOT EXISTS relay_v2_receipt_attempt_idx
  ON relay_v2_receipts(attempt_id, created_at);

CREATE TABLE IF NOT EXISTS relay_v2_request_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  from_state TEXT NOT NULL DEFAULT '',
  to_state TEXT NOT NULL DEFAULT '',
  message_id TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY(request_id) REFERENCES relay_v2_requests(request_id)
);
CREATE INDEX IF NOT EXISTS relay_v2_request_events_idx
  ON relay_v2_request_events(request_id, event_id);

CREATE TABLE IF NOT EXISTS relay_v2_rebind_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  recipient_endpoint_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  old_binding_id TEXT NOT NULL DEFAULT '',
  old_binding_epoch INTEGER NOT NULL DEFAULT 0,
  new_binding_id TEXT NOT NULL,
  new_binding_epoch INTEGER NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY(message_id) REFERENCES fabric_messages(id)
);
CREATE INDEX IF NOT EXISTS relay_v2_rebind_events_idx
  ON relay_v2_rebind_events(recipient_endpoint_id, created_at);
`

// initializeRelayV2Schema only creates additive objects.  It deliberately
// does not alter or rewrite old Fabric rows, and is safe to invoke repeatedly
// during a migration or after a restart.
func (s *Store) initializeRelayV2AdmissionSchema() error {
	if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS relay_v2_admission_guard (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  touched_at TEXT NOT NULL
);
INSERT OR IGNORE INTO relay_v2_admission_guard(id, touched_at) VALUES (1, '');
CREATE TABLE IF NOT EXISTS relay_v2_admission_config (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  per_sender_principal INTEGER NOT NULL CHECK(per_sender_principal > 0),
  per_sender_group INTEGER NOT NULL CHECK(per_sender_group > 0),
  per_receiver INTEGER NOT NULL CHECK(per_receiver > 0),
  global_limit INTEGER NOT NULL CHECK(global_limit > 0),
  retry_after_seconds INTEGER NOT NULL CHECK(retry_after_seconds > 0)
);
INSERT OR IGNORE INTO relay_v2_admission_config
  (id, per_sender_principal, per_sender_group, per_receiver, global_limit, retry_after_seconds)
VALUES (1, 64, 256, 64, 1024, 1);`); err != nil {
		return fmt.Errorf("initialize relay admission schema: %w", err)
	}
	return nil
}

// initializeRelaySenderEndpointAskIndex adds the V21 sender-Endpoint-scoped
// pending Ask lookup index in its own additive migration. Keep it out of
// relayV2Schema so an already-applied historical Relay migration never changes
// its checksum or performs an unledgered schema write on every Open.
func (s *Store) initializeRelaySenderEndpointAskIndex() error {
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS relay_v2_requests_sender_endpoint_idx
  ON relay_v2_requests(sender_endpoint_id, state, expires_at);`); err != nil {
		return fmt.Errorf("initialize Relay sender Endpoint Ask index: %w", err)
	}
	return nil
}

func (s *Store) initializeRelayV2Schema() error {
	if _, err := s.db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		return fmt.Errorf("configure relay v2 sqlite busy timeout: %w", err)
	}
	if _, err := s.db.Exec(relayV2Schema); err != nil {
		return fmt.Errorf("initialize relay v2 schema: %w", err)
	}
	// These columns were added after the first relay migration draft.  Keep
	// that migration additive so a process can restart while the schema is
	// being rolled forward without losing old request/envelope rows.
	for _, column := range []struct {
		table string
		name  string
		ddl   string
	}{
		{"relay_v2_message_security", "sender_binding_id", `ALTER TABLE relay_v2_message_security ADD COLUMN sender_binding_id TEXT NOT NULL DEFAULT ''`},
		{"relay_v2_message_security", "sender_binding_epoch", `ALTER TABLE relay_v2_message_security ADD COLUMN sender_binding_epoch INTEGER NOT NULL DEFAULT 0`},
		{"relay_v2_requests", "sender_binding_id", `ALTER TABLE relay_v2_requests ADD COLUMN sender_binding_id TEXT NOT NULL DEFAULT ''`},
		{"relay_v2_requests", "sender_binding_epoch", `ALTER TABLE relay_v2_requests ADD COLUMN sender_binding_epoch INTEGER NOT NULL DEFAULT 0`},
	} {
		if err := s.ensureColumn(column.table, column.name, column.ddl); err != nil {
			return err
		}
	}
	return nil
}

// initializeRelaySealedPayloadSchema adds a strict, additive payload table.
// Older Relay rows are intentionally not backfilled: before this table every
// relay_v2 envelope stored plaintext in fabric_messages.body, so an absent
// marker remains a legacy plaintext row for compatibility.
func (s *Store) initializeRelaySealedPayloadSchema() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS relay_v2_message_payloads (
  message_id TEXT PRIMARY KEY,
  payload_mode TEXT NOT NULL CHECK(payload_mode IN ('PLAINTEXT', 'SEALED_V1')),
  ciphertext BLOB,
  CHECK (
    (payload_mode = 'PLAINTEXT' AND ciphertext IS NULL) OR
    (payload_mode = 'SEALED_V1' AND ciphertext IS NOT NULL AND typeof(ciphertext) = 'blob' AND length(ciphertext) > 0)
  ),
  FOREIGN KEY(message_id) REFERENCES fabric_messages(id)
);
CREATE INDEX IF NOT EXISTS relay_v2_message_payload_mode_idx
  ON relay_v2_message_payloads(payload_mode, message_id);`); err != nil {
		return fmt.Errorf("initialize relay sealed payload schema: %w", err)
	}
	return nil
}

// InitializeRelayV2Schema is an exported migration hook for programs that
// construct Store around an already-open database.  Store.initialize calls
// the unexported hook in the normal application path once the migration is
// wired by the control-plane owner.
func (s *Store) InitializeRelayV2Schema() error { return s.initializeRelayV2Schema() }

func normalizeRelayAdmissionLimits(limits RelayAdmissionLimits) (RelayAdmissionLimits, error) {
	defaults := DefaultRelayAdmissionLimits()
	if limits.PerSenderPrincipal == 0 {
		limits.PerSenderPrincipal = defaults.PerSenderPrincipal
	}
	if limits.PerSenderGroup == 0 {
		limits.PerSenderGroup = defaults.PerSenderGroup
	}
	if limits.PerReceiver == 0 {
		limits.PerReceiver = defaults.PerReceiver
	}
	if limits.Global == 0 {
		limits.Global = defaults.Global
	}
	if limits.RetryAfterSeconds == 0 {
		limits.RetryAfterSeconds = defaults.RetryAfterSeconds
	}
	if limits.PerSenderPrincipal < 1 || limits.PerSenderGroup < 1 || limits.PerReceiver < 1 ||
		limits.Global < 1 || limits.RetryAfterSeconds < 1 {
		return RelayAdmissionLimits{}, errors.New("relay admission limits must be positive")
	}
	return limits, nil
}

func scanRelayAdmissionLimits(row interface{ Scan(...any) error }) (RelayAdmissionLimits, error) {
	var limits RelayAdmissionLimits
	err := row.Scan(&limits.PerSenderPrincipal, &limits.PerSenderGroup, &limits.PerReceiver,
		&limits.Global, &limits.RetryAfterSeconds)
	if errors.Is(err, sql.ErrNoRows) {
		return RelayAdmissionLimits{}, ErrRelayMessageNotFound
	}
	if err != nil {
		return RelayAdmissionLimits{}, err
	}
	return limits, nil
}

// GetRelayAdmissionLimits reports the effective policy for this Store. It is
// useful to transport adapters that want to expose configured quotas without
// duplicating defaults in their own configuration.
func (s *Store) GetRelayAdmissionLimits() (RelayAdmissionLimits, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanRelayAdmissionLimits(s.db.QueryRow(`SELECT per_sender_principal,
per_sender_group, per_receiver, global_limit, retry_after_seconds
FROM relay_v2_admission_config WHERE id = 1`))
}

// ConfigureRelayAdmissionLimits atomically changes the durable Ask admission
// policy. Existing requests are not deleted or cancelled; the new policy is
// applied to the next admission attempt. This is intentionally separate from
// message/Reply writes so a reply can always make progress at a full quota.
func (s *Store) ConfigureRelayAdmissionLimits(input RelayAdmissionLimits) error {
	limits, err := normalizeRelayAdmissionLimits(input)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := relayAcquireAdmissionGuardTx(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE relay_v2_admission_config
SET per_sender_principal = ?, per_sender_group = ?, per_receiver = ?,
global_limit = ?, retry_after_seconds = ? WHERE id = 1`, limits.PerSenderPrincipal,
		limits.PerSenderGroup, limits.PerReceiver, limits.Global, limits.RetryAfterSeconds); err != nil {
		return fmt.Errorf("configure relay admission limits: %w", err)
	}
	return tx.Commit()
}

func normalizeRelayLimit(limit int) int {
	if limit <= 0 || limit > 1000 {
		return 100
	}
	return limit
}

func relayString(value string) string { return strings.TrimSpace(value) }

func relayDigestForMessage(message FabricMessage) string {
	// The transport message ID and timestamps are excluded, while RequestID
	// remains part of the digest because it is the correlation identity. Ask
	// retries that receive a newly allocated server-side ID are normalized to
	// the original RequestID before this digest is compared.
	canonical := struct {
		RequestID string         `json:"request_id"`
		ReplyTo   string         `json:"reply_to"`
		From      string         `json:"from_endpoint_id"`
		To        string         `json:"to_endpoint_id"`
		Kind      string         `json:"kind"`
		Body      string         `json:"body"`
		Metadata  map[string]any `json:"metadata"`
	}{message.RequestID, message.ReplyTo, message.FromEndpointID, message.ToEndpointID,
		message.Kind, message.Body, message.Metadata}
	encoded, _ := json.Marshal(canonical)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func relayCanonicalDigest(message FabricMessage, supplied string) (string, error) {
	supplied = relayString(supplied)
	if supplied != "" {
		if len(supplied) > 256 {
			return "", errors.New("relay message digest is too long")
		}
		return supplied, nil
	}
	return relayDigestForMessage(message), nil
}

func relayMetadataJSON(metadata map[string]any) (string, error) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("encode relay message metadata: %w", err)
	}
	return string(encoded), nil
}

func relayMessageIdentityEqual(a, b *FabricMessage) bool {
	if a == nil || b == nil {
		return false
	}
	return a.ID == b.ID && relayMessageSemanticEqual(a, b)
}

// relayMessageSemanticEqual compares the immutable envelope fields that make
// an Ask retry the same operation. Transport IDs are intentionally excluded;
// a retry may allocate a fresh message ID before it is matched by scoped
// idempotency.
func relayMessageSemanticEqual(a, b *FabricMessage) bool {
	if a == nil || b == nil {
		return false
	}
	left, _ := relayMetadataJSON(a.Metadata)
	right, _ := relayMetadataJSON(b.Metadata)
	return a.RequestID == b.RequestID && a.ReplyTo == b.ReplyTo &&
		a.FromEndpointID == b.FromEndpointID && a.ToEndpointID == b.ToEndpointID &&
		a.Kind == b.Kind && a.Body == b.Body && left == right
}

func scanRelaySecurity(row interface{ Scan(...any) error }) (*RelayMessageSecurity, error) {
	var security RelayMessageSecurity
	err := row.Scan(&security.MessageID, &security.Digest, &security.IdempotencyKey,
		&security.SenderEndpointID, &security.SenderPrincipalID, &security.SenderGroupID,
		&security.SenderBindingID, &security.SenderBindingEpoch,
		&security.ReceiverEndpointID, &security.ReceiverPrincipalID, &security.ReceiverGroupID,
		&security.ReceiverBindingID, &security.ReceiverBindingEpoch,
		&security.VisibilityPolicyRef, &security.AuthorizationRef, &security.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &security, nil
}

const relaySecurityColumns = `message_id, digest, idempotency_key,
sender_endpoint_id, sender_principal_id, sender_group_id,
sender_binding_id, sender_binding_epoch,
receiver_endpoint_id, receiver_principal_id, receiver_group_id,
receiver_binding_id, receiver_binding_epoch, visibility_policy_ref,
authorization_ref, created_at`

func scanRelayRequest(row interface{ Scan(...any) error }) (*FabricRequest, error) {
	var request FabricRequest
	err := row.Scan(&request.RequestID, &request.MessageID, &request.SenderEndpointID,
		&request.SenderPrincipalID, &request.SenderGroupID, &request.SenderBindingID,
		&request.SenderBindingEpoch, &request.ReceiverEndpointID,
		&request.ReceiverPrincipalID, &request.ReceiverGroupID, &request.ReceiverBindingID,
		&request.ReceiverBindingEpoch, &request.Digest, &request.IdempotencyKey,
		&request.VisibilityPolicyRef, &request.AuthorizationRef, &request.State,
		&request.ExpiresAt, &request.CancelRequestedAt, &request.CancelledAt,
		&request.ExpiredAt, &request.RepliedAt, &request.LateResultAt,
		&request.ReplyMessageID, &request.LateResultMessageID, &request.CreatedAt,
		&request.UpdatedAt, &request.ParentRequestID, &request.CausalRootRequestID,
		&request.CausalDepth)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &request, nil
}

const relayRequestColumns = `request_id, message_id, sender_endpoint_id,
sender_principal_id, sender_group_id, sender_binding_id, sender_binding_epoch,
receiver_endpoint_id,
receiver_principal_id, receiver_group_id, receiver_binding_id,
receiver_binding_epoch, digest, idempotency_key, visibility_policy_ref,
authorization_ref, state, expires_at, cancel_requested_at, cancelled_at,
expired_at, replied_at, late_result_at, reply_message_id,
late_result_message_id, created_at, updated_at, parent_request_id,
causal_root_request_id, causal_depth`

func scanRelayAttempt(row interface{ Scan(...any) error }) (*RelayDeliveryAttempt, error) {
	var attempt RelayDeliveryAttempt
	err := row.Scan(&attempt.AttemptID, &attempt.MessageID, &attempt.RequestID,
		&attempt.RecipientEndpointID, &attempt.Sequence, &attempt.Digest,
		&attempt.BindingID, &attempt.BindingEpoch, &attempt.ConsumerID,
		&attempt.State, &attempt.Failure, &attempt.ClaimedAt, &attempt.CompletedAt,
		&attempt.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &attempt, nil
}

const relayAttemptColumns = `attempt_id, message_id, request_id,
recipient_endpoint_id, sequence, digest, binding_id, binding_epoch,
consumer_id, state, failure, claimed_at, completed_at, created_at`

func scanRelayReceipt(row interface{ Scan(...any) error }) (*RelayReceipt, error) {
	var receipt RelayReceipt
	err := row.Scan(&receipt.ReceiptID, &receipt.AttemptID, &receipt.MessageID,
		&receipt.Digest, &receipt.TargetEndpointID, &receipt.BindingID,
		&receipt.BindingEpoch, &receipt.Layer, &receipt.Error, &receipt.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	receipt.Status = receipt.Layer
	return &receipt, nil
}

const relayReceiptColumns = `receipt_id, attempt_id, message_id, digest,
target_endpoint_id, binding_id, binding_epoch, layer, error, created_at`

func relayRequestInputEnvelope(request FabricRequest) FabricMessage {
	if request.Message != nil {
		message := *request.Message
		if message.ID == "" {
			message.ID = request.MessageID
		}
		if message.RequestID == "" {
			message.RequestID = request.RequestID
		}
		if message.FromEndpointID == "" {
			message.FromEndpointID = request.SenderEndpointID
		}
		if message.ToEndpointID == "" {
			message.ToEndpointID = request.ReceiverEndpointID
		}
		if message.Body == "" {
			message.Body = request.Body
		}
		if message.Metadata == nil {
			message.Metadata = request.Metadata
		}
		if message.Kind == "" {
			message.Kind = "ask"
		}
		return message
	}
	return FabricMessage{
		ID: request.MessageID, RequestID: request.RequestID,
		FromEndpointID: request.SenderEndpointID, ToEndpointID: request.ReceiverEndpointID,
		Kind: "ask", Body: request.Body, Metadata: request.Metadata,
	}
}

func validateRelayMessage(message FabricMessage, security RelayMessageSecurity) error {
	if message.Body == "" {
		return errors.New("relay message ID, endpoints, kind, and body are required")
	}
	return validateRelayMessageRoute(message, security)
}

func validateRelayMessageRoute(message FabricMessage, security RelayMessageSecurity) error {
	if relayString(message.ID) == "" || relayString(message.FromEndpointID) == "" ||
		relayString(message.ToEndpointID) == "" || relayString(message.Kind) == "" {
		return errors.New("relay message ID, endpoints, and kind are required")
	}
	if relayString(security.SenderPrincipalID) == "" || relayString(security.SenderGroupID) == "" ||
		relayString(security.ReceiverGroupID) == "" {
		return errors.New("relay sender principal/group and receiver group are required")
	}
	if security.ReceiverEndpointID == "" {
		return errors.New("relay receiver endpoint is required")
	}
	if message.ToEndpointID != security.ReceiverEndpointID || message.FromEndpointID != security.SenderEndpointID {
		return ErrRelayMessageConflict
	}
	return nil
}

func relayCiphertextDigest(ciphertext []byte) string {
	sum := sha256.Sum256(ciphertext)
	return hex.EncodeToString(sum[:])
}

func relaySecurityRouteEqual(a, b RelayMessageSecurity) bool {
	return a.SenderEndpointID == b.SenderEndpointID &&
		a.SenderPrincipalID == b.SenderPrincipalID &&
		a.SenderGroupID == b.SenderGroupID &&
		a.ReceiverEndpointID == b.ReceiverEndpointID &&
		a.ReceiverPrincipalID == b.ReceiverPrincipalID &&
		a.ReceiverGroupID == b.ReceiverGroupID &&
		a.VisibilityPolicyRef == b.VisibilityPolicyRef &&
		a.AuthorizationRef == b.AuthorizationRef
}

func relaySealedV1Message(input RelaySealedV1Input) (RelayMessageInput, error) {
	security := input.Security
	route := input.Route
	route.MessageID = relayString(route.MessageID)
	if route.MessageID == "" {
		route.MessageID = relayString(security.MessageID)
	}
	if security.MessageID != "" && route.MessageID != security.MessageID {
		return RelayMessageInput{}, ErrRelayMessageConflict
	}
	route.SenderEndpointID = relayString(route.SenderEndpointID)
	if route.SenderEndpointID == "" {
		route.SenderEndpointID = relayString(security.SenderEndpointID)
	}
	if security.SenderEndpointID != "" && route.SenderEndpointID != security.SenderEndpointID {
		return RelayMessageInput{}, ErrRelayMessageConflict
	}
	route.ReceiverEndpointID = relayString(route.ReceiverEndpointID)
	if route.ReceiverEndpointID == "" {
		route.ReceiverEndpointID = relayString(security.ReceiverEndpointID)
	}
	if security.ReceiverEndpointID != "" && route.ReceiverEndpointID != security.ReceiverEndpointID {
		return RelayMessageInput{}, ErrRelayMessageConflict
	}
	security.MessageID = route.MessageID
	security.SenderEndpointID = route.SenderEndpointID
	security.ReceiverEndpointID = route.ReceiverEndpointID
	return RelayMessageInput{
		Message: FabricMessage{ID: route.MessageID, RequestID: relayString(route.RequestID),
			ReplyTo: relayString(route.ReplyTo), FromEndpointID: route.SenderEndpointID,
			ToEndpointID: route.ReceiverEndpointID, Kind: relayString(route.Kind)},
		Security: security, Digest: relayString(input.Digest),
		IdempotencyKey: relayString(input.IdempotencyKey),
	}, nil
}

func relayRequestSecurity(request FabricRequest, message FabricMessage, digest string) RelayMessageSecurity {
	return RelayMessageSecurity{
		MessageID: message.ID, Digest: digest, IdempotencyKey: request.IdempotencyKey,
		SenderEndpointID: message.FromEndpointID, SenderPrincipalID: request.SenderPrincipalID,
		SenderGroupID: request.SenderGroupID, SenderBindingID: request.SenderBindingID,
		SenderBindingEpoch: request.SenderBindingEpoch, ReceiverEndpointID: message.ToEndpointID,
		ReceiverPrincipalID: request.ReceiverPrincipalID, ReceiverGroupID: request.ReceiverGroupID,
		ReceiverBindingID: request.ReceiverBindingID, ReceiverBindingEpoch: request.ReceiverBindingEpoch,
		VisibilityPolicyRef: request.VisibilityPolicyRef, AuthorizationRef: request.AuthorizationRef,
	}
}

func relayMessageSecurityInput(input RelayMessageInput) RelayMessageSecurity {
	security := input.Security
	if security.Digest == "" {
		security.Digest = input.Digest
	}
	if security.IdempotencyKey == "" {
		security.IdempotencyKey = input.IdempotencyKey
	}
	if security.SenderEndpointID == "" {
		security.SenderEndpointID = input.Message.FromEndpointID
	}
	if security.ReceiverEndpointID == "" {
		security.ReceiverEndpointID = input.Message.ToEndpointID
	}
	return security
}

func relayLoadMessageTx(tx *sql.Tx, id string) (*FabricMessage, error) {
	return scanFabricMessage(tx.QueryRow(`SELECT `+fabricMessageColumns+` FROM fabric_messages WHERE id = ?`, id))
}

func relayLoadMessageLocked(s *Store, id string) (*FabricMessage, error) {
	return s.getFabricMessageLocked(id)
}

func relayLoadSecurityTx(tx *sql.Tx, messageID string) (*RelayMessageSecurity, error) {
	return scanRelaySecurity(tx.QueryRow(`SELECT `+relaySecurityColumns+` FROM relay_v2_message_security WHERE message_id = ?`, messageID))
}

func relayLoadRequestTx(tx *sql.Tx, requestID string) (*FabricRequest, error) {
	return scanRelayRequest(tx.QueryRow(`SELECT `+relayRequestColumns+` FROM relay_v2_requests WHERE request_id = ?`, requestID))
}

func relayLoadRequestByMessageTx(tx *sql.Tx, messageID string) (*FabricRequest, error) {
	return scanRelayRequest(tx.QueryRow(`SELECT `+relayRequestColumns+` FROM relay_v2_requests WHERE message_id = ?`, messageID))
}

// relayValidateExistingRequestTx verifies the immutable envelope and routing
// coordinates before an existing request is returned. This keeps an explicit
// request ID from being reused with a different body/target, even when a
// caller supplies a stale or overly broad digest.
func relayValidateExistingRequestTx(tx *sql.Tx, existing *FabricRequest, candidateRequest FabricRequest, candidate FabricMessage, suppliedDigest string) error {
	if existing == nil {
		return ErrRelayRequestNotFound
	}
	existingMessage, err := relayLoadMessageTx(tx, existing.MessageID)
	if err != nil {
		return err
	}
	if existingMessage == nil {
		return ErrRelayMessageNotFound
	}
	if candidateRequest.SenderEndpointID != existing.SenderEndpointID ||
		candidateRequest.SenderPrincipalID != existing.SenderPrincipalID ||
		candidateRequest.SenderGroupID != existing.SenderGroupID ||
		candidateRequest.ReceiverEndpointID != existing.ReceiverEndpointID ||
		candidateRequest.ReceiverPrincipalID != existing.ReceiverPrincipalID ||
		candidateRequest.ReceiverGroupID != existing.ReceiverGroupID ||
		candidateRequest.ParentRequestID != existing.ParentRequestID ||
		(candidateRequest.IdempotencyKey != "" && candidateRequest.IdempotencyKey != existing.IdempotencyKey) {
		if existing.IdempotencyKey != "" || candidateRequest.IdempotencyKey != "" {
			return ErrRelayIdempotencyConflict
		}
		return ErrRelayMessageConflict
	}
	digest, err := relayCanonicalDigest(candidate, suppliedDigest)
	if err != nil {
		return err
	}
	if !relayMessageSemanticEqual(&candidate, existingMessage) {
		if existing.IdempotencyKey != "" {
			return ErrRelayIdempotencyConflict
		}
		return ErrRelayMessageConflict
	}
	if digest != existing.Digest {
		return ErrRelayIdempotencyConflict
	}
	return nil
}

func relayInsertEventTx(tx *sql.Tx, requestID, eventType, fromState, toState, messageID, reason, timestamp string) error {
	_, err := tx.Exec(`INSERT INTO relay_v2_request_events
(request_id, event_type, from_state, to_state, message_id, reason, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`, requestID, eventType, fromState, toState, messageID, reason, timestamp)
	return err
}

// relayAcquireWriteGuardTx turns a deferred SQLite transaction into a
// serialized writer before any read-then-write sequence. Store.mu covers calls
// in one process; this singleton UPDATE also fences independent Store handles
// or processes sharing the same state database.
func relayAcquireWriteGuardTx(tx *sql.Tx) error {
	if _, err := tx.Exec(`UPDATE relay_v2_admission_guard SET touched_at = ? WHERE id = 1`, now()); err != nil {
		return fmt.Errorf("acquire relay write guard: %w", err)
	}
	return nil
}

// relayAcquireAdmissionGuardTx is the Ask-specific spelling for the shared
// Relay write serialization guard.
func relayAcquireAdmissionGuardTx(tx *sql.Tx) error {
	return relayAcquireWriteGuardTx(tx)
}

func relayPendingAskCountTx(tx *sql.Tx, scope, senderEndpointID, principalID, groupID,
	receiverEndpointID, currentTime string) (int, error) {
	const pendingPredicate = `state IN (?, ?) AND cicada_network_expiry_allows(expires_at, ?) = 1`
	var query string
	var args []any
	switch scope {
	case RelayAdmissionScopeSenderPrincipal:
		query = `SELECT count(*) FROM relay_v2_requests WHERE ` + pendingPredicate + ` AND sender_principal_id = ?`
		args = []any{FabricRequestOpen, FabricRequestCancelRequested, currentTime, principalID}
	case RelayAdmissionScopeSenderEndpoint:
		query = `SELECT count(*) FROM relay_v2_requests WHERE ` + pendingPredicate + ` AND sender_endpoint_id = ?`
		args = []any{FabricRequestOpen, FabricRequestCancelRequested, currentTime, senderEndpointID}
	case RelayAdmissionScopeSenderGroup:
		query = `SELECT count(*) FROM relay_v2_requests WHERE ` + pendingPredicate + ` AND sender_group_id = ?`
		args = []any{FabricRequestOpen, FabricRequestCancelRequested, currentTime, groupID}
	case RelayAdmissionScopeReceiver:
		query = `SELECT count(*) FROM relay_v2_requests WHERE ` + pendingPredicate + ` AND receiver_endpoint_id = ?`
		args = []any{FabricRequestOpen, FabricRequestCancelRequested, currentTime, receiverEndpointID}
	case RelayAdmissionScopeGlobal:
		query = `SELECT count(*) FROM relay_v2_requests WHERE ` + pendingPredicate
		args = []any{FabricRequestOpen, FabricRequestCancelRequested, currentTime}
	default:
		return 0, fmt.Errorf("unknown relay admission scope %q", scope)
	}
	var count int
	if err := tx.QueryRow(query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func relayCheckPendingAskQuotaTx(tx *sql.Tx, security RelayMessageSecurity, limits RelayAdmissionLimits, currentTime string) error {
	scopes := []struct {
		name  string
		limit int
	}{
		{RelayAdmissionScopeSenderEndpoint, DefaultRelayPendingAsksPerSenderEndpoint},
		{RelayAdmissionScopeSenderPrincipal, limits.PerSenderPrincipal},
		{RelayAdmissionScopeSenderGroup, limits.PerSenderGroup},
		{RelayAdmissionScopeReceiver, limits.PerReceiver},
		{RelayAdmissionScopeGlobal, limits.Global},
	}
	for _, scope := range scopes {
		pending, err := relayPendingAskCountTx(tx, scope.name, security.SenderEndpointID, security.SenderPrincipalID,
			security.SenderGroupID, security.ReceiverEndpointID, currentTime)
		if err != nil {
			return fmt.Errorf("count relay admission scope %s: %w", scope.name, err)
		}
		if pending >= scope.limit {
			return &RelayAdmissionError{
				Scope: scope.name, Limit: scope.limit, Pending: pending,
				RetryAfter:        time.Duration(limits.RetryAfterSeconds) * time.Second,
				RetryAfterSeconds: limits.RetryAfterSeconds,
			}
		}
	}
	return nil
}

func relayAllocateSequenceTx(tx *sql.Tx, endpointID string) (int64, error) {
	if endpointID == "" {
		return 0, errors.New("relay recipient endpoint is required")
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO relay_v2_recipient_sequences(recipient_endpoint_id, next_sequence) VALUES (?, 1)`, endpointID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE relay_v2_recipient_sequences SET next_sequence = next_sequence + 1 WHERE recipient_endpoint_id = ?`, endpointID); err != nil {
		return 0, err
	}
	var sequence int64
	if err := tx.QueryRow(`SELECT next_sequence - 1 FROM relay_v2_recipient_sequences WHERE recipient_endpoint_id = ?`, endpointID).Scan(&sequence); err != nil {
		return 0, err
	}
	return sequence, nil
}

// relayExistingRecordTx returns the immutable envelope and its v2 security
// metadata.  It is used by idempotent retries so callers receive the original
// row rather than a newly allocated message ID.
func relayPayloadModeTx(tx *sql.Tx, messageID string) (string, error) {
	var mode string
	err := tx.QueryRow(`SELECT payload_mode FROM relay_v2_message_payloads WHERE message_id = ?`, messageID).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		// Before SEALED_V1 support all v2 Relay envelopes stored plaintext in
		// fabric_messages.body. Do not reinterpret historical rows as sealed.
		return RelayPayloadModePlaintext, nil
	}
	return mode, err
}

func relayLoadSealedV1BytesTx(tx *sql.Tx, messageID, expectedDigest string) ([]byte, error) {
	var mode string
	var ciphertext []byte
	err := tx.QueryRow(`SELECT payload_mode, ciphertext FROM relay_v2_message_payloads WHERE message_id = ?`, messageID).Scan(&mode, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRelayMessageNotFound
	}
	if err != nil {
		return nil, err
	}
	if mode != RelayPayloadModeSealedV1 {
		return nil, ErrRelayPayloadModeMismatch
	}
	if len(ciphertext) == 0 || relayCiphertextDigest(ciphertext) != expectedDigest {
		return nil, ErrRelayCiphertextDigest
	}
	return ciphertext, nil
}

func relayExistingRecordTxForMode(tx *sql.Tx, messageID, expectedMode string) (*RelayMessageRecord, error) {
	mode, err := relayPayloadModeTx(tx, messageID)
	if err != nil {
		return nil, err
	}
	if mode != expectedMode {
		return nil, ErrRelayPayloadModeMismatch
	}
	message, err := relayLoadMessageTx(tx, messageID)
	if err != nil {
		return nil, err
	}
	if message == nil {
		return nil, nil
	}
	security, err := relayLoadSecurityTx(tx, messageID)
	if err != nil {
		return nil, err
	}
	if security == nil {
		return nil, ErrRelayMessageNotFound
	}
	var sequence sql.NullInt64
	if err := tx.QueryRow(`SELECT sequence FROM relay_v2_inbox
WHERE recipient_endpoint_id = ? AND message_id = ?`, security.ReceiverEndpointID, messageID).Scan(&sequence); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var outboxState string
	if err := tx.QueryRow(`SELECT state FROM relay_v2_outbox WHERE message_id = ?`, messageID).Scan(&outboxState); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return &RelayMessageRecord{Message: *message, Security: *security,
		Sequence: sequence.Int64, OutboxState: outboxState}, nil
}

func relayExistingRecordTx(tx *sql.Tx, messageID string) (*RelayMessageRecord, error) {
	return relayExistingRecordTxForMode(tx, messageID, RelayPayloadModePlaintext)
}

func relaySealedV1RecordTx(tx *sql.Tx, messageID string) (*RelaySealedV1Record, error) {
	mode, err := relayPayloadModeTx(tx, messageID)
	if err != nil {
		return nil, err
	}
	if mode != RelayPayloadModeSealedV1 {
		return nil, ErrRelayPayloadModeMismatch
	}
	var route RelaySealedV1Route
	var createdAt string
	err = tx.QueryRow(`SELECT id, request_id, reply_to, from_endpoint_id,
to_endpoint_id, kind, created_at FROM fabric_messages WHERE id = ?`, messageID).Scan(
		&route.MessageID, &route.RequestID, &route.ReplyTo, &route.SenderEndpointID,
		&route.ReceiverEndpointID, &route.Kind, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRelayMessageNotFound
	}
	if err != nil {
		return nil, err
	}
	security, err := relayLoadSecurityTx(tx, messageID)
	if err != nil {
		return nil, err
	}
	if security == nil {
		return nil, ErrRelayMessageNotFound
	}
	ciphertext, err := relayLoadSealedV1BytesTx(tx, messageID, security.Digest)
	if err != nil {
		return nil, err
	}
	var sequence sql.NullInt64
	if err := tx.QueryRow(`SELECT sequence FROM relay_v2_inbox
WHERE recipient_endpoint_id = ? AND message_id = ?`, security.ReceiverEndpointID, messageID).Scan(&sequence); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var outboxState string
	if err := tx.QueryRow(`SELECT state FROM relay_v2_outbox WHERE message_id = ?`, messageID).Scan(&outboxState); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return &RelaySealedV1Record{PayloadMode: mode, Route: route, Security: *security,
		Ciphertext: ciphertext, Sequence: sequence.Int64, OutboxState: outboxState,
		CreatedAt: createdAt}, nil
}

func relayExistingCandidateTx(tx *sql.Tx, messageID, payloadMode string, message FabricMessage, security RelayMessageSecurity) (*RelayMessageRecord, error) {
	mode, err := relayPayloadModeTx(tx, messageID)
	if err != nil {
		return nil, err
	}
	if mode != payloadMode {
		return nil, ErrRelayIdempotencyConflict
	}
	record, err := relayExistingRecordTxForMode(tx, messageID, payloadMode)
	if err != nil || record == nil {
		return record, err
	}
	if payloadMode == RelayPayloadModeSealedV1 &&
		(!relayMessageSemanticEqual(&record.Message, &message) || !relaySecurityRouteEqual(record.Security, security)) {
		return nil, ErrRelayIdempotencyConflict
	}
	return record, nil
}

// relayEnqueueMessageTx preserves the legacy plaintext entry point.
func relayEnqueueMessageTx(tx *sql.Tx, input RelayMessageInput) (*RelayMessageRecord, bool, error) {
	return relayEnqueuePayloadTx(tx, input, RelayPayloadModePlaintext, nil)
}

// relayEnqueuePayloadTx persists an immutable route, explicit payload mode,
// outbox row, recipient sequence, inbox row, and accepted receipt in one
// transaction. The caller must hold Store.mu and commit/rollback tx.
func relayEnqueuePayloadTx(tx *sql.Tx, input RelayMessageInput, payloadMode string, ciphertext []byte) (*RelayMessageRecord, bool, error) {
	message := input.Message
	message.ID = relayString(message.ID)
	if message.ID == "" {
		message.ID = NewID("msg")
	}
	message.RequestID = relayString(message.RequestID)
	message.ReplyTo = relayString(message.ReplyTo)
	message.FromEndpointID = relayString(message.FromEndpointID)
	message.ToEndpointID = relayString(message.ToEndpointID)
	message.Kind = relayString(message.Kind)
	if message.Status == "" {
		message.Status = "queued"
	}
	security := relayMessageSecurityInput(input)
	security.MessageID = message.ID
	security.SenderEndpointID = relayString(security.SenderEndpointID)
	security.SenderPrincipalID = relayString(security.SenderPrincipalID)
	security.SenderGroupID = relayString(security.SenderGroupID)
	security.ReceiverEndpointID = relayString(security.ReceiverEndpointID)
	security.ReceiverPrincipalID = relayString(security.ReceiverPrincipalID)
	security.ReceiverGroupID = relayString(security.ReceiverGroupID)
	security.ReceiverBindingID = relayString(security.ReceiverBindingID)
	security.IdempotencyKey = relayString(security.IdempotencyKey)
	security.VisibilityPolicyRef = relayString(security.VisibilityPolicyRef)
	security.AuthorizationRef = relayString(security.AuthorizationRef)
	if security.ReceiverEndpointID == "" {
		security.ReceiverEndpointID = message.ToEndpointID
	}
	if security.SenderEndpointID == "" {
		security.SenderEndpointID = message.FromEndpointID
	}
	if input.networkDirectAuthorized {
		if payloadMode != RelayPayloadModeSealedV1 || security.SenderGroupID != "" ||
			security.ReceiverGroupID != "" || security.AuthorizationRef == "" {
			return nil, false, ErrNetworkPermission
		}
	} else if input.communicationLinkAuthorized {
		if payloadMode != RelayPayloadModeSealedV1 ||
			!strings.HasPrefix(security.AuthorizationRef, communicationLinkAuthorizationRefPrefix) {
			return nil, false, ErrNetworkPermission
		}
		if err := networkGuardCommunicationLinkRouteTx(tx, RelaySealedV1Route{
			MessageID: message.ID, RequestID: message.RequestID, ReplyTo: message.ReplyTo,
			SenderEndpointID: security.SenderEndpointID, ReceiverEndpointID: security.ReceiverEndpointID,
			Kind: message.Kind,
		}, &security, security.ReceiverGroupID, time.Now().UTC()); err != nil {
			return nil, false, ErrNetworkPermission
		}
	} else {
		if strings.HasPrefix(security.AuthorizationRef, communicationLinkAuthorizationRefPrefix) {
			return nil, false, ErrNetworkPermission
		}
		if err := networkGuardRelaySecurityTx(tx, &security, security.ReceiverGroupID, time.Now().UTC()); err != nil {
			return nil, false, err
		}
	}
	if payloadMode == RelayPayloadModePlaintext {
		if err := rejectPlaintextSealedPeerTx(tx, security.SenderEndpointID, security.ReceiverEndpointID); err != nil {
			return nil, false, err
		}
	}
	var digest string
	switch payloadMode {
	case RelayPayloadModePlaintext:
		var err error
		digest, err = relayCanonicalDigest(message, security.Digest)
		if err != nil {
			return nil, false, err
		}
		if err := validateRelayMessage(message, security); err != nil {
			return nil, false, err
		}
	case RelayPayloadModeSealedV1:
		if message.Body != "" || len(message.Metadata) != 0 {
			return nil, false, errors.New("sealed relay route cannot contain a body or arbitrary metadata")
		}
		sealedSend := message.Kind == "send" && message.RequestID == "" && message.ReplyTo == ""
		sealedAsk := input.sealedAskAuthorized && message.Kind == "ask" &&
			message.RequestID != "" && message.ReplyTo == ""
		sealedReply := input.sealedReplyAuthorized && message.Kind == "reply" &&
			message.RequestID != "" && message.ReplyTo != ""
		if !sealedSend && !sealedAsk && !sealedReply {
			return nil, false, errors.New("SEALED_V1 requires a single-recipient SEND or an internally authorized correlated request/reply")
		}
		if len(ciphertext) == 0 {
			return nil, false, errors.New("sealed relay ciphertext is required")
		}
		if !input.networkDirectAuthorized {
			if err := validateRelayMessageRoute(message, security); err != nil {
				return nil, false, err
			}
		} else if message.ID == "" || message.FromEndpointID == "" ||
			message.ToEndpointID == "" || security.SenderPrincipalID == "" ||
			security.ReceiverPrincipalID == "" || message.FromEndpointID != security.SenderEndpointID ||
			message.ToEndpointID != security.ReceiverEndpointID {
			return nil, false, ErrNetworkPermission
		}
		digest = relayCiphertextDigest(ciphertext)
		if security.Digest != "" && security.Digest != digest {
			return nil, false, ErrRelayCiphertextDigest
		}
	default:
		return nil, false, fmt.Errorf("unsupported relay payload mode %q", payloadMode)
	}
	security.Digest = digest

	// Idempotency is checked before inserting any new envelope.  The scope is
	// the authenticated sender principal and group, never a caller supplied
	// global key.
	if security.IdempotencyKey != "" {
		var existingID, existingDigest string
		err := tx.QueryRow(`SELECT message_id, digest FROM relay_v2_message_security
WHERE sender_principal_id = ? AND sender_group_id = ? AND idempotency_key = ?`,
			security.SenderPrincipalID, security.SenderGroupID, security.IdempotencyKey).Scan(&existingID, &existingDigest)
		if err == nil {
			if existingDigest != digest {
				return nil, false, ErrRelayIdempotencyConflict
			}
			record, err := relayExistingCandidateTx(tx, existingID, payloadMode, message, security)
			return record, true, err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, false, err
		}
	}

	// A message ID is also immutable.  Existing legacy rows are accepted only
	// when their full envelope matches; this permits explicit migration without
	// rewriting old IDs or bodies.
	existing, err := relayLoadMessageTx(tx, message.ID)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		existingMode, err := relayPayloadModeTx(tx, message.ID)
		if err != nil {
			return nil, false, err
		}
		if existingMode != payloadMode {
			return nil, false, ErrRelayMessageConflict
		}
		if !relayMessageIdentityEqual(existing, &message) {
			return nil, false, ErrRelayMessageConflict
		}
		existingSecurity, err := relayLoadSecurityTx(tx, message.ID)
		if err != nil {
			return nil, false, err
		}
		if existingSecurity != nil {
			if existingSecurity.Digest != digest ||
				(payloadMode == RelayPayloadModeSealedV1 && !relaySecurityRouteEqual(*existingSecurity, security)) {
				return nil, false, ErrRelayMessageConflict
			}
			record, err := relayExistingRecordTxForMode(tx, message.ID, payloadMode)
			return record, true, err
		}
	}

	metadataJSON, err := relayMetadataJSON(message.Metadata)
	if err != nil {
		return nil, false, err
	}
	timestamp := now()
	createdAt := relayString(message.CreatedAt)
	if createdAt == "" {
		createdAt = timestamp
	}
	if existing == nil {
		_, err = tx.Exec(`INSERT INTO fabric_messages
(id, request_id, reply_to, from_endpoint_id, to_endpoint_id, kind, body,
 metadata_json, status, error, created_at, delivered_at, replied_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, message.ID, message.RequestID,
			message.ReplyTo, message.FromEndpointID, message.ToEndpointID, message.Kind,
			message.Body, metadataJSON, message.Status, message.Error, createdAt,
			nullableString(message.DeliveredAt), nullableString(message.RepliedAt))
		if err != nil {
			return nil, false, fmt.Errorf("create relay fabric envelope: %w", err)
		}
	}
	security.CreatedAt = timestamp
	_, err = tx.Exec(`INSERT INTO relay_v2_message_security
(message_id, digest, idempotency_key, sender_endpoint_id, sender_principal_id,
 sender_group_id, sender_binding_id, sender_binding_epoch, receiver_endpoint_id,
 receiver_principal_id, receiver_group_id,
 receiver_binding_id, receiver_binding_epoch, visibility_policy_ref,
 authorization_ref, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, security.MessageID,
		security.Digest, security.IdempotencyKey, security.SenderEndpointID,
		security.SenderPrincipalID, security.SenderGroupID, security.SenderBindingID,
		security.SenderBindingEpoch, security.ReceiverEndpointID,
		security.ReceiverPrincipalID, security.ReceiverGroupID, security.ReceiverBindingID,
		security.ReceiverBindingEpoch, security.VisibilityPolicyRef, security.AuthorizationRef,
		security.CreatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") && security.IdempotencyKey != "" {
			var existingID, existingDigest string
			if queryErr := tx.QueryRow(`SELECT message_id, digest FROM relay_v2_message_security
WHERE sender_principal_id = ? AND sender_group_id = ? AND idempotency_key = ?`,
				security.SenderPrincipalID, security.SenderGroupID, security.IdempotencyKey).Scan(&existingID, &existingDigest); queryErr == nil {
				if existingDigest != digest {
					return nil, false, ErrRelayIdempotencyConflict
				}
				record, err := relayExistingCandidateTx(tx, existingID, payloadMode, message, security)
				return record, true, err
			}
		}
		return nil, false, fmt.Errorf("create relay message security metadata: %w", err)
	}
	if !input.networkDirectAuthorized {
		if err := networkCaptureRelayMessageEnrollmentTx(tx, &security); err != nil {
			return nil, false, err
		}
	}
	_, err = tx.Exec(`INSERT INTO relay_v2_message_payloads
(message_id, payload_mode, ciphertext) VALUES (?, ?, ?)`, message.ID, payloadMode, ciphertext)
	if err != nil {
		return nil, false, fmt.Errorf("create relay payload mode and bytes: %w", err)
	}
	_, err = tx.Exec(`INSERT OR IGNORE INTO relay_v2_outbox
(message_id, sender_principal_id, sender_group_id, recipient_endpoint_id,
 state, error, created_at, accepted_at, updated_at)
VALUES (?, ?, ?, ?, 'RELAY_ACCEPTED', '', ?, ?, ?)`, message.ID,
		security.SenderPrincipalID, security.SenderGroupID, security.ReceiverEndpointID,
		timestamp, timestamp, timestamp)
	if err != nil {
		return nil, false, fmt.Errorf("create relay outbox: %w", err)
	}
	sequence, err := relayAllocateSequenceTx(tx, security.ReceiverEndpointID)
	if err != nil {
		return nil, false, err
	}
	_, err = tx.Exec(`INSERT INTO relay_v2_inbox
(recipient_endpoint_id, sequence, message_id, digest, receiver_group_id,
 binding_id, binding_epoch, state, attempt_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 'READY', '', ?, ?)`, security.ReceiverEndpointID,
		sequence, message.ID, security.Digest, security.ReceiverGroupID, security.ReceiverBindingID,
		security.ReceiverBindingEpoch, timestamp, timestamp)
	if err != nil {
		// A retry can race an external Store connection.  Preserve the original
		// sequence/message and return it rather than allocating another envelope.
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			record, err := relayExistingCandidateTx(tx, message.ID, payloadMode, message, security)
			return record, true, err
		}
		return nil, false, fmt.Errorf("create relay inbox: %w", err)
	}
	_, err = tx.Exec(`INSERT OR IGNORE INTO relay_v2_receipts
(receipt_id, attempt_id, message_id, digest, target_endpoint_id,
 binding_id, binding_epoch, layer, error, created_at)
VALUES (?, '', ?, ?, ?, ?, ?, ?, '', ?)`, NewID("rcpt"), message.ID,
		security.Digest, security.ReceiverEndpointID, security.ReceiverBindingID,
		security.ReceiverBindingEpoch, RelayReceiptAccepted, timestamp)
	if err != nil {
		return nil, false, fmt.Errorf("create relay accepted receipt: %w", err)
	}
	record := &RelayMessageRecord{Message: message, Security: security, Sequence: sequence, OutboxState: RelayReceiptAccepted}
	return record, false, nil
}

// rejectPlaintextSealedPeerTx is the persistence-boundary downgrade guard for
// legacy plaintext Relay routes. Endpoint capability state is read in the
// same transaction that creates the message and inbox rows, so a concurrent
// capability update cannot race a previously authorized plaintext write.
// Rows absent from fabric_endpoints are legacy Store-only fixtures/routes and
// retain their historical behavior; public Fabric dispatch always resolves
// both endpoint rows before enqueueing.
func rejectPlaintextSealedPeerTx(tx *sql.Tx, endpointIDs ...string) error {
	seen := make(map[string]struct{}, len(endpointIDs))
	for _, endpointID := range endpointIDs {
		endpointID = relayString(endpointID)
		if endpointID == "" {
			continue
		}
		if _, ok := seen[endpointID]; ok {
			continue
		}
		seen[endpointID] = struct{}{}
		var raw string
		err := tx.QueryRow(`SELECT capabilities_json FROM fabric_endpoints WHERE id = ?`, endpointID).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		var capabilities map[string]any
		if err := json.Unmarshal([]byte(raw), &capabilities); err != nil {
			return fmt.Errorf("decode endpoint delivery capabilities: %w", err)
		}
		if _, present := capabilities["local_peer_delivery"]; present {
			return ErrRelayPlaintextSealedPeer
		}
	}
	return nil
}

// EnqueueRelayMessage durably accepts a non-Ask envelope and creates its
// per-recipient inbox row.  The body remains in fabric_messages.
func (s *Store) EnqueueRelayMessage(input RelayMessageInput) (*RelayMessageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := relayAcquireWriteGuardTx(tx); err != nil {
		return nil, err
	}
	record, _, err := relayEnqueueMessageTx(tx, input)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

// CreateRelayMessage is a descriptive alias for EnqueueRelayMessage.
func (s *Store) CreateRelayMessage(input RelayMessageInput) (*RelayMessageRecord, error) {
	return s.EnqueueRelayMessage(input)
}

// EnqueueRelaySealedV1 atomically stores route metadata, the opaque ciphertext
// BLOB, outbox/inbox state, and RELAY_ACCEPTED receipt. It does not perform or
// verify endpoint encryption.
func (s *Store) EnqueueRelaySealedV1(input RelaySealedV1Input) (*RelaySealedV1Record, error) {
	if len(input.Ciphertext) == 0 {
		return nil, errors.New("sealed relay ciphertext is required")
	}
	relayInput, err := relaySealedV1Message(input)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	accepted, _, err := relayEnqueuePayloadTx(tx, relayInput, RelayPayloadModeSealedV1, input.Ciphertext)
	if err != nil {
		return nil, err
	}
	if accepted == nil {
		return nil, ErrRelayMessageNotFound
	}
	record, err := relaySealedV1RecordTx(tx, accepted.Message.ID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

// GetRelaySealedV1 returns sealed bytes and their clear route metadata only
// through the dedicated payload-mode API.
func (s *Store) GetRelaySealedV1(messageID string) (*RelaySealedV1Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	record, err := relaySealedV1RecordTx(tx, relayString(messageID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

// CreateFabricRequest atomically stores an Ask envelope, its structured
// request row, relay outbox/inbox metadata, and RELAY_ACCEPTED receipt.
func (s *Store) CreateFabricRequest(request FabricRequest) (*FabricRequest, error) {
	request.RequestID = relayString(request.RequestID)
	message := relayRequestInputEnvelope(request)
	requestIDExplicit := request.RequestID != "" || relayString(message.RequestID) != ""
	if message.RequestID != "" && request.RequestID != "" && message.RequestID != request.RequestID {
		return nil, ErrRelayMessageConflict
	}
	if request.RequestID == "" {
		request.RequestID = message.RequestID
	}
	if request.RequestID == "" {
		request.RequestID = NewID("rq")
	}
	if request.SenderEndpointID != "" && message.FromEndpointID != "" && request.SenderEndpointID != message.FromEndpointID {
		return nil, ErrRelayMessageConflict
	}
	if request.ReceiverEndpointID != "" && message.ToEndpointID != "" && request.ReceiverEndpointID != message.ToEndpointID {
		return nil, ErrRelayMessageConflict
	}
	if message.ID == "" {
		message.ID = NewID("msg")
	}
	message.RequestID = request.RequestID
	message.Kind = "ask"
	request.MessageID = message.ID
	request.SenderEndpointID = relayString(request.SenderEndpointID)
	request.SenderPrincipalID = relayString(request.SenderPrincipalID)
	request.SenderGroupID = relayString(request.SenderGroupID)
	request.ReceiverEndpointID = relayString(request.ReceiverEndpointID)
	request.ReceiverPrincipalID = relayString(request.ReceiverPrincipalID)
	request.ReceiverGroupID = relayString(request.ReceiverGroupID)
	request.IdempotencyKey = relayString(request.IdempotencyKey)
	if request.SenderEndpointID == "" {
		request.SenderEndpointID = message.FromEndpointID
	}
	if request.ReceiverEndpointID == "" {
		request.ReceiverEndpointID = message.ToEndpointID
	}
	security := relayRequestSecurity(request, message, request.Digest)
	input := RelayMessageInput{Message: message, Security: security,
		Digest: request.Digest, IdempotencyKey: request.IdempotencyKey,
		ExpiresAt: request.ExpiresAt}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Serialize the quota read with every other Ask admission, including
	// callers using a second Store handle for this database.
	if err := relayAcquireAdmissionGuardTx(tx); err != nil {
		return nil, err
	}
	if err := rejectPlaintextSealedPeerTx(tx, request.SenderEndpointID, request.ReceiverEndpointID); err != nil {
		return nil, err
	}

	if existing, err := relayLoadRequestTx(tx, request.RequestID); err != nil {
		return nil, err
	} else if existing != nil {
		if err := relayValidateExistingRequestTx(tx, existing, request, message, request.Digest); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return existing, nil
	}
	// A server-side retry may allocate a fresh RequestID before reaching the
	// store. Match its scoped idempotency key first, then reconstruct an
	// automatically allocated candidate with the original RequestID so the
	// existing digest remains authoritative. A caller-provided different
	// RequestID is rejected even when it supplies the old digest.
	if request.IdempotencyKey != "" {
		var existingMessageID string
		err := tx.QueryRow(`SELECT message_id FROM relay_v2_message_security
WHERE sender_principal_id = ? AND sender_group_id = ? AND idempotency_key = ?`,
			request.SenderPrincipalID, request.SenderGroupID, request.IdempotencyKey).Scan(&existingMessageID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil {
			existing, loadErr := relayLoadRequestByMessageTx(tx, existingMessageID)
			if loadErr != nil {
				return nil, loadErr
			}
			if existing == nil {
				return nil, ErrRelayMessageConflict
			}
			if requestIDExplicit && existing.RequestID != request.RequestID {
				return nil, ErrRelayIdempotencyConflict
			}
			candidate := message
			if !requestIDExplicit {
				candidate.RequestID = existing.RequestID
			}
			if validateErr := relayValidateExistingRequestTx(tx, existing, request, candidate, request.Digest); validateErr != nil {
				return nil, validateErr
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return existing, nil
		}
	}
	record, reused, err := relayEnqueueMessageTx(tx, input)
	if err != nil {
		return nil, err
	}
	if reused {
		// Same sender scope/key/digest returns the original request, even when
		// the retry generated a fresh request ID.
		if existing, err := relayLoadRequestTx(tx, record.Message.RequestID); err != nil {
			return nil, err
		} else if existing != nil {
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return existing, nil
		}
		return nil, ErrRelayMessageConflict
	}
	limits, err := scanRelayAdmissionLimits(tx.QueryRow(`SELECT per_sender_principal,
per_sender_group, per_receiver, global_limit, retry_after_seconds
FROM relay_v2_admission_config WHERE id = 1`))
	if err != nil {
		return nil, fmt.Errorf("load relay admission limits: %w", err)
	}
	// Idempotent retries are handled by relayEnqueueMessageTx before this
	// check. Consequently a retry of an already accepted Ask returns its
	// original row even while the relevant quota remains full.
	if err := relayCheckPendingAskQuotaTx(tx, record.Security, limits, now()); err != nil {
		return nil, err
	}
	if err := relayDeriveCausalLineageTx(tx, &request, time.Now().UTC()); err != nil {
		return nil, err
	}
	timestamp := now()
	request.State = FabricRequestOpen
	request.Digest = record.Security.Digest
	request.IdempotencyKey = record.Security.IdempotencyKey
	request.CreatedAt = timestamp
	request.UpdatedAt = timestamp
	_, err = tx.Exec(`INSERT INTO relay_v2_requests
(request_id, message_id, sender_endpoint_id, sender_principal_id, sender_group_id,
 sender_binding_id, sender_binding_epoch, receiver_endpoint_id, receiver_principal_id,
 receiver_group_id, receiver_binding_id,
 receiver_binding_epoch, digest, idempotency_key, visibility_policy_ref,
 authorization_ref, state, expires_at, cancel_requested_at, cancelled_at,
 expired_at, replied_at, late_result_at, reply_message_id, late_result_message_id,
 created_at, updated_at, parent_request_id, causal_root_request_id, causal_depth)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', '', '', '', '', ?, ?, ?, ?, ?)`,
		request.RequestID, record.Message.ID, record.Security.SenderEndpointID,
		record.Security.SenderPrincipalID, record.Security.SenderGroupID,
		record.Security.SenderBindingID, record.Security.SenderBindingEpoch,
		record.Security.ReceiverEndpointID, record.Security.ReceiverPrincipalID,
		record.Security.ReceiverGroupID, record.Security.ReceiverBindingID,
		record.Security.ReceiverBindingEpoch, record.Security.Digest, record.Security.IdempotencyKey,
		record.Security.VisibilityPolicyRef, record.Security.AuthorizationRef,
		FabricRequestOpen, relayString(request.ExpiresAt), timestamp, timestamp,
		request.ParentRequestID, request.CausalRootRequestID, request.CausalDepth)
	if err != nil {
		return nil, fmt.Errorf("create relay request: %w", err)
	}
	if err := relayInsertEventTx(tx, request.RequestID, "REQUEST_CREATED", "", FabricRequestOpen, record.Message.ID, "", timestamp); err != nil {
		return nil, err
	}
	request.CreatedAt = timestamp
	request.UpdatedAt = timestamp
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &request, nil
}

// CreateRelayFabricRequest is the v2-named alias used by Relay callers.
func (s *Store) CreateRelayFabricRequest(request FabricRequest) (*FabricRequest, error) {
	return s.CreateFabricRequest(request)
}

// PutFabricRequest is another compatibility alias for durable Ask creation.
func (s *Store) PutFabricRequest(request FabricRequest) (*FabricRequest, error) {
	return s.CreateFabricRequest(request)
}

func (s *Store) GetRelayFabricRequest(requestID string) (*FabricRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, err := scanRelayRequest(s.db.QueryRow(`SELECT `+relayRequestColumns+` FROM relay_v2_requests r
WHERE r.request_id = ? AND COALESCE((SELECT p.payload_mode FROM relay_v2_message_payloads p WHERE p.message_id = r.message_id), 'PLAINTEXT') = 'PLAINTEXT'`, relayString(requestID)))
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, ErrRelayRequestNotFound
	}
	return request, nil
}

// GetFabricRequestV2 avoids colliding with the legacy GetFabricRequest, which
// intentionally returns the old FabricMessage shape.
func (s *Store) GetFabricRequestV2(requestID string) (*FabricRequest, error) {
	return s.GetRelayFabricRequest(requestID)
}

func (s *Store) GetRelayRequest(requestID string) (*FabricRequest, error) {
	return s.GetRelayFabricRequest(requestID)
}

func (s *Store) GetRelayMessageSecurity(messageID string) (*RelayMessageSecurity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	security, err := scanRelaySecurity(s.db.QueryRow(`SELECT `+relaySecurityColumns+` FROM relay_v2_message_security r
WHERE r.message_id = ? AND COALESCE((SELECT p.payload_mode FROM relay_v2_message_payloads p WHERE p.message_id = r.message_id), 'PLAINTEXT') = 'PLAINTEXT'`, relayString(messageID)))
	if err != nil {
		return nil, err
	}
	if security == nil {
		return nil, ErrRelayMessageNotFound
	}
	return security, nil
}

func (s *Store) GetRelayMessage(messageID string) (*RelayMessageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	record, err := relayExistingRecordTx(tx, relayString(messageID))
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, ErrRelayMessageNotFound
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Store) ListRelayRequests(filter RelayRequestFilter) ([]FabricRequest, error) {
	limit := normalizeRelayLimit(filter.Limit)
	query := `SELECT ` + relayRequestColumns + ` FROM relay_v2_requests r
WHERE COALESCE((SELECT p.payload_mode FROM relay_v2_message_payloads p WHERE p.message_id = r.message_id), 'PLAINTEXT') = 'PLAINTEXT'`
	args := make([]any, 0, 6)
	if value := relayString(filter.State); value != "" {
		query += ` AND state = ?`
		args = append(args, value)
	}
	if value := relayString(filter.SenderPrincipalID); value != "" {
		query += ` AND sender_principal_id = ?`
		args = append(args, value)
	}
	if value := relayString(filter.SenderGroupID); value != "" {
		query += ` AND sender_group_id = ?`
		args = append(args, value)
	}
	if value := relayString(filter.ReceiverGroupID); value != "" {
		query += ` AND receiver_group_id = ?`
		args = append(args, value)
	}
	if value := relayString(filter.ReceiverEndpointID); value != "" {
		query += ` AND receiver_endpoint_id = ?`
		args = append(args, value)
	}
	query += ` ORDER BY created_at, request_id LIMIT ?`
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]FabricRequest, 0)
	for rows.Next() {
		request, err := scanRelayRequest(rows)
		if err != nil {
			return nil, err
		}
		if request != nil {
			result = append(result, *request)
		}
	}
	return result, rows.Err()
}

func (s *Store) ListFabricRequestsV2(filter RelayRequestFilter) ([]FabricRequest, error) {
	return s.ListRelayRequests(filter)
}

func relayEncodeCursor(cursor RelayCursor) string {
	encoded, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func relayDecodeCursor(encoded string) (RelayCursor, error) {
	var cursor RelayCursor
	encoded = relayString(encoded)
	if encoded == "" {
		return cursor, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || json.Unmarshal(decoded, &cursor) != nil ||
		cursor.RecipientEndpointID == "" || cursor.ConsumerID == "" || cursor.Sequence < 0 {
		return RelayCursor{}, ErrRelayCursor
	}
	return cursor, nil
}

func scanRelayInboxItem(row interface{ Scan(...any) error }) (*RelayInboxItem, error) {
	var item RelayInboxItem
	err := row.Scan(&item.Sequence, &item.MessageID, &item.RequestID, &item.Digest,
		&item.RecipientEndpointID, &item.ReceiverGroupID, &item.BindingID,
		&item.BindingEpoch, &item.AttemptID, &item.State, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

const relayInboxColumns = `i.sequence, i.message_id, f.request_id, i.digest,
i.recipient_endpoint_id, i.receiver_group_id, i.binding_id, i.binding_epoch,
i.attempt_id, i.state, i.created_at, i.updated_at`

func (s *Store) getRelayCursorTx(tx *sql.Tx, endpointID, consumerID, bindingID string) (RelayCursor, error) {
	cursor := RelayCursor{RecipientEndpointID: endpointID, ConsumerID: consumerID, BindingID: bindingID}
	var sequence, epoch int64
	err := tx.QueryRow(`SELECT sequence, binding_epoch FROM relay_v2_consumer_cursors
WHERE recipient_endpoint_id = ? AND consumer_id = ? AND binding_id = ?`, endpointID, consumerID, bindingID).Scan(&sequence, &epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return cursor, nil
	}
	if err != nil {
		return cursor, err
	}
	cursor.Sequence = sequence
	cursor.BindingEpoch = uint64(epoch)
	return cursor, nil
}

// ReceiveRelayInbox reads a bounded batch without acknowledging it.  The
// cursor is opaque and acknowledgement advances the durable cursor only over
// contiguous terminal rows.  Unacknowledged rows remain eligible even when a
// caller reconnects with a cursor returned by a prior read.
func (s *Store) ReceiveRelayInbox(endpointID, consumerID, encodedCursor string, limit int) (*RelayReceiveResult, error) {
	return s.ReceiveRelayInboxForBinding(endpointID, consumerID, "", 0, encodedCursor, limit)
}

func (s *Store) ReceiveRelayInboxForBinding(endpointID, consumerID, bindingID string, bindingEpoch uint64, encodedCursor string, limit int) (*RelayReceiveResult, error) {
	return s.receiveRelayInboxForBindingGroup(endpointID, consumerID, bindingID, bindingEpoch, "", encodedCursor, limit)
}

// ReceiveRelayInboxForBindingGroup prevents a multi-Group native Session
// from reading another Group's mailbox through its shared Endpoint identity.
func (s *Store) ReceiveRelayInboxForBindingGroup(endpointID, consumerID, bindingID string, bindingEpoch uint64, groupID, encodedCursor string, limit int) (*RelayReceiveResult, error) {
	groupID = relayString(groupID)
	if groupID == "" {
		return nil, errors.New("receiver group is required")
	}
	return s.receiveRelayInboxForBindingGroup(endpointID, consumerID, bindingID, bindingEpoch, groupID, encodedCursor, limit)
}

func (s *Store) receiveRelayInboxForBindingGroup(endpointID, consumerID, bindingID string, bindingEpoch uint64, groupID, encodedCursor string, limit int) (*RelayReceiveResult, error) {
	endpointID, consumerID, bindingID = relayString(endpointID), relayString(consumerID), relayString(bindingID)
	if endpointID == "" || consumerID == "" {
		return nil, errors.New("relay recipient endpoint and consumer are required")
	}
	limit = normalizeRelayLimit(limit)
	provided, err := relayDecodeCursor(encodedCursor)
	if err != nil {
		return nil, err
	}
	if encodedCursor != "" && (provided.RecipientEndpointID != endpointID || provided.ConsumerID != consumerID || provided.BindingID != bindingID) {
		return nil, ErrRelayCursor
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	persisted, err := s.getRelayCursorTx(tx, endpointID, consumerID, bindingID)
	if err != nil {
		return nil, err
	}
	start := persisted.Sequence
	if encodedCursor != "" && provided.Sequence > start {
		start = provided.Sequence
	}
	query := `SELECT ` + relayInboxColumns + ` FROM relay_v2_inbox i
JOIN fabric_messages f ON f.id = i.message_id
WHERE i.recipient_endpoint_id = ?
  AND COALESCE((SELECT p.payload_mode FROM relay_v2_message_payloads p WHERE p.message_id = i.message_id), 'PLAINTEXT') = 'PLAINTEXT'
  AND i.state NOT IN ('ACKED', 'EXPIRED', 'CANCELLED')
  AND (i.sequence > ? OR i.state IN ('READY', 'CLAIMED', 'INJECTED', 'FAILED', 'INJECTION_UNCERTAIN'))`
	args := []any{endpointID, start}
	if groupID != "" {
		query += ` AND i.receiver_group_id = ?`
		args = append(args, groupID)
	}
	query += ` ORDER BY i.sequence LIMIT ?`
	args = append(args, limit)
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]RelayInboxItem, 0, limit)
	var highest int64 = start
	for rows.Next() {
		item, err := scanRelayInboxItem(rows)
		if err != nil {
			return nil, err
		}
		if item == nil {
			continue
		}
		if item.BindingID != "" && bindingID != "" && item.BindingID != bindingID {
			continue
		}
		if err := networkGuardRelayMessageTx(tx, item.MessageID, item.ReceiverGroupID, time.Now().UTC()); err != nil {
			continue
		}
		if bindingID != "" && item.BindingID == "" {
			// An unbound legacy recipient can be read only without a binding
			// assertion; a Node binding must never silently adopt it.
			continue
		}
		message, err := relayLoadMessageTx(tx, item.MessageID)
		if err != nil {
			return nil, err
		}
		item.Message = message
		result = append(result, *item)
		if item.Sequence > highest {
			highest = item.Sequence
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &RelayReceiveResult{Messages: result, NextCursor: relayEncodeCursor(RelayCursor{
		RecipientEndpointID: endpointID, ConsumerID: consumerID, BindingID: bindingID,
		BindingEpoch: bindingEpoch, Sequence: highest,
	})}, nil
}

// ReceiveRelayMessages is a short alias used by transport adapters.
func (s *Store) ReceiveRelayMessages(endpointID, consumerID, cursor string, limit int) (*RelayReceiveResult, error) {
	return s.ReceiveRelayInbox(endpointID, consumerID, cursor, limit)
}

// ListRelayInbox is a bounded history view.  It does not claim or acknowledge
// rows and therefore is safe for dashboards and recovery inspection.
func (s *Store) ListRelayInbox(endpointID string, afterSequence int64, limit int) ([]RelayInboxItem, error) {
	endpointID = relayString(endpointID)
	if endpointID == "" {
		return nil, errors.New("relay recipient endpoint is required")
	}
	if afterSequence < 0 {
		return nil, ErrRelayCursor
	}
	limit = normalizeRelayLimit(limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT `+relayInboxColumns+` FROM relay_v2_inbox i
JOIN fabric_messages f ON f.id = i.message_id
WHERE i.recipient_endpoint_id = ? AND i.sequence > ?
  AND COALESCE((SELECT p.payload_mode FROM relay_v2_message_payloads p WHERE p.message_id = i.message_id), 'PLAINTEXT') = 'PLAINTEXT'
ORDER BY i.sequence LIMIT ?`, endpointID, afterSequence, limit)
	if err != nil {
		return nil, err
	}
	result := make([]RelayInboxItem, 0, limit)
	for rows.Next() {
		item, err := scanRelayInboxItem(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		if item == nil {
			continue
		}
		result = append(result, *item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// Close the inbox cursor before loading message bodies: this Store uses one
	// SQLite connection. Batch the historical plaintext reads so a page does
	// not make one extra query per message.
	const messageBatchSize = 500
	messages := make(map[string]*FabricMessage, len(result))
	for start := 0; start < len(result); start += messageBatchSize {
		end := min(start+messageBatchSize, len(result))
		args := make([]any, 0, end-start)
		placeholders := make([]string, 0, end-start)
		for _, item := range result[start:end] {
			args = append(args, item.MessageID)
			placeholders = append(placeholders, "?")
		}
		messageRows, queryErr := s.db.Query(`SELECT `+fabricMessageColumns+` FROM fabric_messages WHERE id IN (`+strings.Join(placeholders, ",")+`)`, args...)
		if queryErr != nil {
			return nil, queryErr
		}
		for messageRows.Next() {
			message, scanErr := scanFabricMessage(messageRows)
			if scanErr != nil {
				_ = messageRows.Close()
				return nil, scanErr
			}
			messages[message.ID] = message
		}
		if scanErr := messageRows.Err(); scanErr != nil {
			_ = messageRows.Close()
			return nil, scanErr
		}
		if closeErr := messageRows.Close(); closeErr != nil {
			return nil, closeErr
		}
	}
	for index := range result {
		message, ok := messages[result[index].MessageID]
		if !ok {
			return nil, sql.ErrNoRows
		}
		result[index].Message = message
	}
	return result, nil
}

func (s *Store) GetRelayInboxItem(endpointID string, sequence int64) (*RelayInboxItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := scanRelayInboxItem(s.db.QueryRow(`SELECT `+relayInboxColumns+`
FROM relay_v2_inbox i JOIN fabric_messages f ON f.id = i.message_id
WHERE i.recipient_endpoint_id = ? AND i.sequence = ?
  AND COALESCE((SELECT p.payload_mode FROM relay_v2_message_payloads p WHERE p.message_id = i.message_id), 'PLAINTEXT') = 'PLAINTEXT'`, relayString(endpointID), sequence))
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, ErrRelayDeliveryNotFound
	}
	item.Message, err = s.getFabricMessageLocked(item.MessageID)
	return item, err
}

func relayBindingMatches(item *RelayInboxItem, bindingID string, bindingEpoch uint64) bool {
	if item == nil {
		return false
	}
	if item.BindingID != "" || bindingID != "" {
		if item.BindingID == "" || bindingID == "" || item.BindingID != bindingID {
			return false
		}
	}
	if item.BindingEpoch != 0 || bindingEpoch != 0 {
		return item.BindingEpoch != 0 && bindingEpoch != 0 && item.BindingEpoch == bindingEpoch
	}
	return true
}

func relayParseExpired(expiresAt string, current time.Time) bool {
	expiresAt = relayString(expiresAt)
	if expiresAt == "" {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, expiresAt)
	}
	return err == nil && !parsed.After(current)
}

func relayExpireRequestTx(tx *sql.Tx, requestID, reason, timestamp string) error {
	request, err := relayLoadRequestTx(tx, requestID)
	if err != nil || request == nil {
		return err
	}
	if request.State != FabricRequestOpen && request.State != FabricRequestCancelRequested {
		return nil
	}
	result, err := tx.Exec(`UPDATE relay_v2_requests SET state = ?, expired_at = ?, updated_at = ?
WHERE request_id = ? AND state IN (?, ?)`, FabricRequestExpired, timestamp, timestamp,
		requestID, FabricRequestOpen, FabricRequestCancelRequested)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed == 0 {
		return err
	}
	if _, err := tx.Exec(`UPDATE relay_v2_inbox SET state = ?, updated_at = ?
WHERE message_id = ? AND state IN ('READY', 'CLAIMED')`, RelayInboxExpired, timestamp, request.MessageID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE relay_v2_delivery_attempts SET state = ?, completed_at = ?, failure = ?
WHERE message_id = ? AND state = ?`, RelayAttemptCancelled, timestamp, reason, request.MessageID, RelayAttemptClaimed); err != nil {
		return err
	}
	return relayInsertEventTx(tx, requestID, "REQUEST_EXPIRED", request.State, FabricRequestExpired, request.MessageID, reason, timestamp)
}

// ClaimRelayInbox atomically claims a bounded batch for one target endpoint.
// SQLite's write transaction and the conditional READY update prevent two
// consumers from receiving the same row as an active attempt.
func (s *Store) ClaimRelayInbox(input RelayClaimInput) ([]RelayDeliveryAttempt, error) {
	input.RecipientEndpointID = relayString(input.RecipientEndpointID)
	input.ConsumerID = relayString(input.ConsumerID)
	input.BindingID = relayString(input.BindingID)
	if input.RecipientEndpointID == "" || input.ConsumerID == "" {
		return nil, errors.New("relay recipient endpoint and consumer are required")
	}
	input.Limit = normalizeRelayLimit(input.Limit)
	if input.Cursor != "" {
		cursor, err := relayDecodeCursor(input.Cursor)
		if err != nil || cursor.RecipientEndpointID != input.RecipientEndpointID || cursor.ConsumerID != input.ConsumerID || cursor.BindingID != input.BindingID {
			return nil, ErrRelayCursor
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT `+relayInboxColumns+` FROM relay_v2_inbox i
JOIN fabric_messages f ON f.id = i.message_id
LEFT JOIN fabric_endpoints e ON e.id = i.recipient_endpoint_id
WHERE i.recipient_endpoint_id = ? AND i.state = 'READY'
AND COALESCE((SELECT p.payload_mode FROM relay_v2_message_payloads p WHERE p.message_id = i.message_id), 'PLAINTEXT') = 'PLAINTEXT'
AND (e.id IS NULL OR e.migration_state != 'READY' OR EXISTS (
  SELECT 1 FROM endpoint_group_memberships eg
  JOIN memberships m ON m.principal_id = e.principal_id AND m.group_id = eg.group_id
  JOIN principals p ON p.id = e.principal_id
  JOIN groups g ON g.id = eg.group_id
  WHERE eg.endpoint_id = e.id AND eg.group_id = i.receiver_group_id
    AND eg.status = 'active' AND m.status = 'active' AND p.status = 'active'
    AND g.state = 'ACTIVE' AND cicada_network_expiry_allows(m.expires_at, ?) = 1))
ORDER BY i.sequence LIMIT ?`, input.RecipientEndpointID, now(), input.Limit)
	if err != nil {
		return nil, err
	}
	items := make([]*RelayInboxItem, 0, input.Limit)
	for rows.Next() {
		item, err := scanRelayInboxItem(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		if item != nil {
			items = append(items, item)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]RelayDeliveryAttempt, 0, len(items))
	for _, item := range items {
		if !relayBindingMatches(item, input.BindingID, input.BindingEpoch) {
			return nil, ErrRelayBindingMismatch
		}
		if err := networkGuardRelayMessageTx(tx, item.MessageID, item.ReceiverGroupID, time.Now().UTC()); err != nil {
			continue
		}
		if item.RequestID != "" {
			request, err := relayLoadRequestTx(tx, item.RequestID)
			if err != nil {
				return nil, err
			}
			if request != nil {
				if relayParseExpired(request.ExpiresAt, time.Now().UTC()) {
					if err := relayExpireRequestTx(tx, request.RequestID, "request deadline reached", now()); err != nil {
						return nil, err
					}
					continue
				}
				if request.State == FabricRequestCancelled || request.State == FabricRequestExpired || request.State == FabricRequestLateResult {
					continue
				}
			}
		}
		attemptID := NewID("attempt")
		timestamp := now()
		updated, err := tx.Exec(`UPDATE relay_v2_inbox SET state = ?, attempt_id = ?, updated_at = ?
WHERE recipient_endpoint_id = ? AND sequence = ? AND state = 'READY'`, RelayInboxClaimed,
			attemptID, timestamp, item.RecipientEndpointID, item.Sequence)
		if err != nil {
			return nil, err
		}
		changed, err := updated.RowsAffected()
		if err != nil {
			return nil, err
		}
		if changed == 0 {
			continue
		}
		requestID := item.RequestID
		if _, err := tx.Exec(`INSERT INTO relay_v2_delivery_attempts
(attempt_id, message_id, request_id, recipient_endpoint_id, sequence, digest,
 binding_id, binding_epoch, consumer_id, state, failure, claimed_at,
 completed_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, '', ?)`, attemptID, item.MessageID,
			requestID, item.RecipientEndpointID, item.Sequence, item.Digest, item.BindingID,
			item.BindingEpoch, input.ConsumerID, RelayAttemptClaimed, timestamp, timestamp); err != nil {
			return nil, err
		}
		message, err := relayLoadMessageTx(tx, item.MessageID)
		if err != nil {
			return nil, err
		}
		result = append(result, RelayDeliveryAttempt{
			AttemptID: attemptID, MessageID: item.MessageID, RequestID: requestID,
			Digest: item.Digest, RecipientEndpointID: item.RecipientEndpointID,
			ReceiverGroupID: item.ReceiverGroupID,
			BindingID:       item.BindingID, BindingEpoch: item.BindingEpoch,
			Sequence: item.Sequence, ConsumerID: input.ConsumerID, State: RelayAttemptClaimed,
			ClaimedAt: timestamp, CreatedAt: timestamp, Message: message,
		})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// ClaimRelaySealedV1Inbox atomically claims only SEALED_V1 inbox rows and
// returns the complete opaque BLOB with route metadata. Legacy Claim APIs
// cannot observe these rows.
func (s *Store) ClaimRelaySealedV1Inbox(input RelayClaimInput) ([]RelaySealedV1DeliveryAttempt, error) {
	input.RecipientEndpointID = relayString(input.RecipientEndpointID)
	input.ConsumerID = relayString(input.ConsumerID)
	input.BindingID = relayString(input.BindingID)
	if input.RecipientEndpointID == "" || input.ConsumerID == "" {
		return nil, errors.New("relay recipient endpoint and consumer are required")
	}
	input.Limit = normalizeRelayLimit(input.Limit)
	if input.Cursor != "" {
		cursor, err := relayDecodeCursor(input.Cursor)
		if err != nil || cursor.RecipientEndpointID != input.RecipientEndpointID || cursor.ConsumerID != input.ConsumerID || cursor.BindingID != input.BindingID {
			return nil, ErrRelayCursor
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := failStaleQueuedCommunicationLinkSendsTx(tx, input.RecipientEndpointID, time.Now().UTC(), input.Limit); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT `+relayInboxColumns+` FROM relay_v2_inbox i
JOIN fabric_messages f ON f.id = i.message_id
JOIN fabric_endpoints e ON e.id = i.recipient_endpoint_id
JOIN session_bindings sb ON sb.id = i.binding_id
WHERE i.recipient_endpoint_id = ? AND i.state = 'READY'
AND COALESCE((SELECT p.payload_mode FROM relay_v2_message_payloads p WHERE p.message_id = i.message_id), 'PLAINTEXT') = 'SEALED_V1'
AND NOT EXISTS (SELECT 1 FROM network_direct_message_routes_v2 direct WHERE direct.message_id=i.message_id)
AND NOT EXISTS (
  SELECT 1 FROM relay_v2_message_security same_group_security
  WHERE same_group_security.message_id = i.message_id
    AND same_group_security.authorization_ref GLOB 'same-group-sealed.v2:*')
AND e.migration_state = ? AND e.binding_id = i.binding_id
AND sb.endpoint_id = e.id
AND sb.epoch = i.binding_epoch AND sb.status IN ('active', 'leased', 'online', 'ready', 'acquired')
AND sb.lease_expires_at <> '' AND cicada_network_expiry_allows(sb.lease_expires_at, ?) = 1
AND EXISTS (
  SELECT 1 FROM endpoint_group_memberships eg
  JOIN memberships m ON m.principal_id = e.principal_id AND m.group_id = eg.group_id
  JOIN principals p ON p.id = e.principal_id
  JOIN groups g ON g.id = eg.group_id
  WHERE eg.endpoint_id = e.id AND eg.group_id = i.receiver_group_id
    AND eg.status = 'active' AND m.status = 'active' AND p.status = 'active'
    AND g.state = 'ACTIVE' AND cicada_network_expiry_allows(m.expires_at, ?) = 1)
ORDER BY i.sequence LIMIT ?`, input.RecipientEndpointID, EndpointMigrationReady, now(), now(), input.Limit)
	if err != nil {
		return nil, err
	}
	items := make([]*RelayInboxItem, 0, input.Limit)
	for rows.Next() {
		item, err := scanRelayInboxItem(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		if item != nil {
			items = append(items, item)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]RelaySealedV1DeliveryAttempt, 0, len(items))
	for _, item := range items {
		if !relayBindingMatches(item, input.BindingID, input.BindingEpoch) {
			return nil, ErrRelayBindingMismatch
		}
		if guardErr := networkGuardRelayMessageTx(tx, item.MessageID, item.ReceiverGroupID, time.Now().UTC()); guardErr != nil {
			continue
		}
		record, err := relaySealedV1RecordTx(tx, item.MessageID)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(record.Security.AuthorizationRef, communicationLinkAuthorizationRefPrefix) {
			if err := communicationLinkReviewGateTx(tx, record, time.Now().UTC(), false); err != nil {
				continue
			}
		}
		if record.Route.RequestID != item.RequestID {
			continue
		}
		if item.RequestID != "" {
			request, err := relayLoadRequestTx(tx, item.RequestID)
			if err != nil {
				return nil, err
			}
			if request == nil {
				continue
			}
			switch record.Route.Kind {
			case "ask":
				if request.MessageID != item.MessageID || request.State != FabricRequestOpen {
					continue
				}
				if relayParseExpired(request.ExpiresAt, time.Now().UTC()) {
					if err := relayExpireRequestTx(tx, request.RequestID, "request deadline reached", now()); err != nil {
						return nil, err
					}
					continue
				}
			case "reply":
				if request.MessageID != record.Route.ReplyTo ||
					request.State != FabricRequestReplied || request.ReplyMessageID != item.MessageID {
					continue
				}
			default:
				continue
			}
		}
		attemptID := NewID("attempt")
		timestamp := now()
		updated, err := tx.Exec(`UPDATE relay_v2_inbox SET state = ?, attempt_id = ?, updated_at = ?
WHERE recipient_endpoint_id = ? AND sequence = ? AND state = 'READY'`, RelayInboxClaimed,
			attemptID, timestamp, item.RecipientEndpointID, item.Sequence)
		if err != nil {
			return nil, err
		}
		changed, err := updated.RowsAffected()
		if err != nil {
			return nil, err
		}
		if changed == 0 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO relay_v2_delivery_attempts
(attempt_id, message_id, request_id, recipient_endpoint_id, sequence, digest,
 binding_id, binding_epoch, consumer_id, state, failure, claimed_at,
 completed_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, '', ?)`, attemptID, item.MessageID,
			item.RequestID, item.RecipientEndpointID, item.Sequence, item.Digest, item.BindingID,
			item.BindingEpoch, input.ConsumerID, RelayAttemptClaimed, timestamp, timestamp); err != nil {
			return nil, err
		}
		result = append(result, RelaySealedV1DeliveryAttempt{
			AttemptID: attemptID, MessageID: item.MessageID, RequestID: item.RequestID,
			Digest: item.Digest, RecipientEndpointID: item.RecipientEndpointID,
			ReceiverGroupID: item.ReceiverGroupID, BindingID: item.BindingID,
			BindingEpoch: item.BindingEpoch, Sequence: item.Sequence,
			ConsumerID: input.ConsumerID, State: RelayAttemptClaimed,
			ClaimedAt: timestamp, CreatedAt: timestamp, PayloadMode: RelayPayloadModeSealedV1,
			Route: record.Route, Security: record.Security, Ciphertext: record.Ciphertext,
		})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// RecoverStaleRelayClaims closes the crash window between Relay claim and the
// Node's first durable receipt. A claim with no NODE_RECEIVED evidence is safe
// to requeue. Once the Node reported durable acceptance, the injection outcome
// is uncertain and is never blindly assigned to another consumer.
func (s *Store) RecoverStaleRelayClaims(before time.Time) (requeued, uncertain int, err error) {
	if before.IsZero() {
		return 0, 0, errors.New("relay recovery cutoff is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT attempt_id, message_id, recipient_endpoint_id, sequence
FROM relay_v2_delivery_attempts
WHERE state = ? AND claimed_at < ? ORDER BY claimed_at`, RelayAttemptClaimed, before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, 0, err
	}
	type staleClaim struct {
		attemptID, messageID, endpointID string
		sequence                         int64
	}
	claims := make([]staleClaim, 0)
	for rows.Next() {
		var claim staleClaim
		if err := rows.Scan(&claim.attemptID, &claim.messageID, &claim.endpointID, &claim.sequence); err != nil {
			_ = rows.Close()
			return 0, 0, err
		}
		claims = append(claims, claim)
	}
	if err := rows.Close(); err != nil {
		return 0, 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	timestamp := now()
	for _, claim := range claims {
		var nodeReceived int
		if err := tx.QueryRow(`SELECT count(*) FROM relay_v2_receipts WHERE attempt_id = ? AND layer = ?`, claim.attemptID, RelayReceiptNodeReceived).Scan(&nodeReceived); err != nil {
			return 0, 0, err
		}
		attemptState, inboxState, failure := RelayAttemptFailed, RelayInboxReady, "relay claim expired before node durable receipt"
		if nodeReceived > 0 {
			attemptState, inboxState, failure = RelayAttemptUncertain, RelayInboxUncertain, "node accepted delivery but runtime injection outcome is unknown"
			uncertain++
		} else {
			requeued++
		}
		if _, err := tx.Exec(`UPDATE relay_v2_delivery_attempts SET state = ?, failure = ?, completed_at = ?
WHERE attempt_id = ? AND state = ?`, attemptState, failure, timestamp, claim.attemptID, RelayAttemptClaimed); err != nil {
			return 0, 0, err
		}
		if _, err := tx.Exec(`UPDATE relay_v2_inbox SET state = ?, attempt_id = CASE WHEN ? = ? THEN '' ELSE attempt_id END, updated_at = ?
WHERE recipient_endpoint_id = ? AND sequence = ? AND message_id = ? AND attempt_id = ? AND state = ?`,
			inboxState, inboxState, RelayInboxReady, timestamp, claim.endpointID, claim.sequence,
			claim.messageID, claim.attemptID, RelayInboxClaimed); err != nil {
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return requeued, uncertain, nil
}

func (s *Store) ClaimRelayDeliveries(endpointID, bindingID string, bindingEpoch uint64, consumerID string, limit int) ([]RelayDeliveryAttempt, error) {
	return s.ClaimRelayInbox(RelayClaimInput{RecipientEndpointID: endpointID, BindingID: bindingID,
		BindingEpoch: bindingEpoch, ConsumerID: consumerID, Limit: limit})
}

func (s *Store) ClaimRelayMessages(endpointID, consumerID string, limit int) ([]RelayDeliveryAttempt, error) {
	return s.ClaimRelayInbox(RelayClaimInput{RecipientEndpointID: endpointID, ConsumerID: consumerID, Limit: limit})
}

// RebindPendingRelayInbox performs the narrow recovery operation needed when
// a stable Endpoint reconnects under a new SessionBinding epoch.  It can only
// touch READY rows for the exact endpoint and old binding, and only while the
// associated Ask remains non-terminal and unexpired.  A wrong endpoint or
// stale binding therefore cannot move another recipient's pending work.
func (s *Store) RebindPendingRelayInbox(endpointID, oldBindingID string, oldBindingEpoch uint64, newBindingID string, newBindingEpoch uint64) (int, error) {
	endpointID, oldBindingID, newBindingID = relayString(endpointID), relayString(oldBindingID), relayString(newBindingID)
	if endpointID == "" || oldBindingID == "" || newBindingID == "" || oldBindingEpoch == 0 || newBindingEpoch == 0 {
		return 0, ErrRelayBindingMismatch
	}
	if oldBindingID == newBindingID && oldBindingEpoch == newBindingEpoch {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	// Resolve the endpoint first.  This makes a typo or an attacker supplied
	// endpoint fail without touching rows for any other recipient.
	var endpointExists int
	if err := tx.QueryRow(`SELECT count(*) FROM fabric_endpoints WHERE id = ?`, endpointID).Scan(&endpointExists); err != nil {
		return 0, err
	}
	if endpointExists == 0 {
		return 0, ErrEndpointNotFound
	}
	rows, err := tx.Query(`SELECT i.sequence, i.message_id, f.request_id
FROM relay_v2_inbox i JOIN fabric_messages f ON f.id = i.message_id
LEFT JOIN relay_v2_requests r ON r.request_id = f.request_id
WHERE i.recipient_endpoint_id = ? AND i.binding_id = ? AND i.binding_epoch = ?
  AND i.state = 'READY'
  AND NOT EXISTS (SELECT 1 FROM network_direct_message_routes_v2 direct WHERE direct.message_id=i.message_id)
  AND (r.request_id IS NULL OR (r.state IN (?, ?) AND cicada_network_expiry_allows(r.expires_at, ?) = 1))
ORDER BY i.sequence`, endpointID, oldBindingID, oldBindingEpoch,
		FabricRequestOpen, FabricRequestCancelRequested, now())
	if err != nil {
		return 0, err
	}
	type pending struct {
		sequence  int64
		messageID string
		requestID string
	}
	pendingRows := make([]pending, 0)
	for rows.Next() {
		var item pending
		if err := rows.Scan(&item.sequence, &item.messageID, &item.requestID); err != nil {
			_ = rows.Close()
			return 0, err
		}
		pendingRows = append(pendingRows, item)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	timestamp := now()
	// A rejoining endpoint can be the requester of an outstanding Ask even
	// when it has no pending inbound rows yet. Refresh that reply destination
	// independently so a later reply targets the same native session's new
	// fenced epoch. Historical message security remains immutable evidence of
	// the epoch which originally sent each envelope.
	senderUpdate, err := tx.Exec(`UPDATE relay_v2_requests SET sender_binding_id = ?, sender_binding_epoch = ?, updated_at = ?
WHERE sender_endpoint_id = ? AND sender_binding_id = ? AND sender_binding_epoch = ?
  AND state IN (?, ?)
  AND NOT EXISTS (SELECT 1 FROM network_direct_message_routes_v2 direct
    WHERE direct.message_id=relay_v2_requests.message_id)`, newBindingID, newBindingEpoch, timestamp, endpointID,
		oldBindingID, oldBindingEpoch, FabricRequestOpen, FabricRequestCancelRequested)
	if err != nil {
		return 0, err
	}
	senderChanged, err := senderUpdate.RowsAffected()
	if err != nil {
		return 0, err
	}
	if len(pendingRows) == 0 {
		if senderChanged == 0 {
			return 0, ErrRelayBindingMismatch
		}
		if err := tx.Commit(); err != nil {
			return 0, err
		}
		return 0, nil
	}
	for _, item := range pendingRows {
		updated, err := tx.Exec(`UPDATE relay_v2_inbox SET binding_id = ?, binding_epoch = ?, updated_at = ?
WHERE recipient_endpoint_id = ? AND sequence = ? AND message_id = ?
  AND binding_id = ? AND binding_epoch = ? AND state = 'READY'`, newBindingID, newBindingEpoch,
			timestamp, endpointID, item.sequence, item.messageID, oldBindingID, oldBindingEpoch)
		if err != nil {
			return 0, err
		}
		changed, err := updated.RowsAffected()
		if err != nil {
			return 0, err
		}
		if changed == 0 {
			continue
		}
		if _, err := tx.Exec(`UPDATE relay_v2_message_security SET receiver_binding_id = ?, receiver_binding_epoch = ?
WHERE message_id = ? AND receiver_endpoint_id = ?`, newBindingID, newBindingEpoch, item.messageID, endpointID); err != nil {
			return 0, err
		}
		if item.requestID != "" {
			if _, err := tx.Exec(`UPDATE relay_v2_requests SET receiver_binding_id = ?, receiver_binding_epoch = ?, updated_at = ?
WHERE request_id = ? AND state IN (?, ?)`, newBindingID, newBindingEpoch, timestamp,
				item.requestID, FabricRequestOpen, FabricRequestCancelRequested); err != nil {
				return 0, err
			}
		}
		if _, err := tx.Exec(`INSERT INTO relay_v2_rebind_events
(recipient_endpoint_id, message_id, old_binding_id, old_binding_epoch,
 new_binding_id, new_binding_epoch, reason, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, endpointID, item.messageID, oldBindingID, oldBindingEpoch,
			newBindingID, newBindingEpoch, "session reconnected", timestamp); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(pendingRows), nil
}

func (s *Store) RebindPendingRelayDeliveries(endpointID, oldBindingID string, oldBindingEpoch uint64, newBindingID string, newBindingEpoch uint64) (int, error) {
	return s.RebindPendingRelayInbox(endpointID, oldBindingID, oldBindingEpoch, newBindingID, newBindingEpoch)
}

func (s *Store) GetRelayDeliveryAttempt(attemptID string) (*RelayDeliveryAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt, err := scanRelayAttempt(s.db.QueryRow(`SELECT `+relayAttemptColumns+` FROM relay_v2_delivery_attempts WHERE attempt_id = ?`, relayString(attemptID)))
	if err != nil {
		return nil, err
	}
	if attempt == nil {
		return nil, ErrRelayDeliveryNotFound
	}
	var payloadMode string
	modeErr := s.db.QueryRow(`SELECT payload_mode FROM relay_v2_message_payloads WHERE message_id = ?`, attempt.MessageID).Scan(&payloadMode)
	if modeErr != nil && !errors.Is(modeErr, sql.ErrNoRows) {
		return nil, modeErr
	}
	if payloadMode == RelayPayloadModeSealedV1 {
		return nil, ErrRelayDeliveryNotFound
	}
	attempt.Message, err = s.getFabricMessageLocked(attempt.MessageID)
	return attempt, err
}

func relayReceiptRank(layer string) int {
	switch layer {
	case RelayReceiptAccepted:
		return 1
	case RelayReceiptNodeReceived:
		return 2
	case RelayReceiptCodexQueueAccepted, RelayReceiptNativeThreadResumed:
		return 3
	case RelayReceiptRuntimeInjected, RelayReceiptConsumptionUnknown, RelayReceiptInjectionUncertain:
		return 4
	case RelayReceiptApplicationAck:
		return 5
	case RelayReceiptResultAccepted:
		return 6
	case RelayReceiptFailed:
		return 0
	default:
		return -1
	}
}

func relayValidReceiptLayer(layer string) bool { return relayReceiptRank(layer) >= 0 }

func relayReceiptMatchesAttempt(receipt RelayReceipt, attempt *RelayDeliveryAttempt) bool {
	if attempt == nil {
		return false
	}
	return receipt.AttemptID == attempt.AttemptID && receipt.MessageID == attempt.MessageID &&
		receipt.Digest == attempt.Digest && receipt.TargetEndpointID == attempt.RecipientEndpointID &&
		receipt.BindingID == attempt.BindingID && receipt.BindingEpoch == attempt.BindingEpoch
}

func relayGetAttemptTx(tx *sql.Tx, attemptID string) (*RelayDeliveryAttempt, error) {
	return scanRelayAttempt(tx.QueryRow(`SELECT `+relayAttemptColumns+` FROM relay_v2_delivery_attempts WHERE attempt_id = ?`, attemptID))
}

func relayReceiptExistingTx(tx *sql.Tx, receipt RelayReceipt) (*RelayReceipt, error) {
	existing, err := scanRelayReceipt(tx.QueryRow(`SELECT `+relayReceiptColumns+`
FROM relay_v2_receipts WHERE message_id = ? AND attempt_id = ? AND layer = ?`,
		receipt.MessageID, receipt.AttemptID, receipt.Layer))
	if err != nil {
		return nil, err
	}
	return existing, nil
}

func relayAdvanceCursorTx(tx *sql.Tx, endpointID, consumerID, bindingID string, bindingEpoch uint64, timestamp string) error {
	if consumerID == "" {
		return nil
	}
	cursor, err := getRelayCursorTxForUpdate(tx, endpointID, consumerID, bindingID)
	if err != nil {
		return err
	}
	sequence := cursor.Sequence
	for {
		var state string
		err := tx.QueryRow(`SELECT state FROM relay_v2_inbox
WHERE recipient_endpoint_id = ? AND sequence = ?`, endpointID, sequence+1).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		if state != RelayInboxAcked && state != RelayInboxExpired && state != RelayInboxCancelled {
			break
		}
		sequence++
	}
	if sequence == cursor.Sequence && cursor.BindingEpoch == bindingEpoch {
		return nil
	}
	_, err = tx.Exec(`INSERT INTO relay_v2_consumer_cursors
(recipient_endpoint_id, consumer_id, binding_id, binding_epoch, sequence, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(recipient_endpoint_id, consumer_id, binding_id) DO UPDATE SET
 binding_epoch = excluded.binding_epoch,
 sequence = CASE WHEN excluded.sequence > relay_v2_consumer_cursors.sequence
                 THEN excluded.sequence ELSE relay_v2_consumer_cursors.sequence END,
 updated_at = excluded.updated_at`, endpointID, consumerID, bindingID, bindingEpoch, sequence, timestamp)
	return err
}

func getRelayCursorTxForUpdate(tx *sql.Tx, endpointID, consumerID, bindingID string) (RelayCursor, error) {
	var sequence, epoch int64
	err := tx.QueryRow(`SELECT sequence, binding_epoch FROM relay_v2_consumer_cursors
WHERE recipient_endpoint_id = ? AND consumer_id = ? AND binding_id = ?`, endpointID, consumerID, bindingID).Scan(&sequence, &epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return RelayCursor{RecipientEndpointID: endpointID, ConsumerID: consumerID, BindingID: bindingID}, nil
	}
	if err != nil {
		return RelayCursor{}, err
	}
	return RelayCursor{RecipientEndpointID: endpointID, ConsumerID: consumerID, BindingID: bindingID,
		BindingEpoch: uint64(epoch), Sequence: sequence}, nil
}

// RecordRelayReceipt validates every delivery coordinate before writing a
// receipt or advancing inbox/cursor state.  A forged receiver, digest, epoch,
// or attempt therefore has no state-changing path.
func (s *Store) RecordRelayReceipt(receipt RelayReceipt) (*RelayReceipt, error) {
	return s.recordRelayReceipt(receipt, "")
}

// RecordNetworkDirectReceipt requires the current Node credential in the same
// write transaction that advances the shared Relay attempt/receipt state.
func (s *Store) RecordNetworkDirectReceipt(credentialDigest string,
	receipt RelayReceipt) (*RelayReceipt, error) {
	if !validNodeCredentialDigest(credentialDigest) {
		return nil, ErrRelayInvalidReceipt
	}
	return s.recordRelayReceipt(receipt, credentialDigest)
}

func (s *Store) recordRelayReceipt(receipt RelayReceipt,
	credentialDigest string) (*RelayReceipt, error) {
	receipt.AttemptID = relayString(receipt.AttemptID)
	receipt.MessageID = relayString(receipt.MessageID)
	receipt.Digest = relayString(receipt.Digest)
	receipt.TargetEndpointID = relayString(receipt.TargetEndpointID)
	receipt.BindingID = relayString(receipt.BindingID)
	receipt.Layer = relayString(receipt.Layer)
	if receipt.Layer == "" {
		receipt.Layer = relayString(receipt.Status)
	}
	if receipt.MessageID == "" || receipt.AttemptID == "" || receipt.Digest == "" ||
		receipt.TargetEndpointID == "" || !relayValidReceiptLayer(receipt.Layer) {
		return nil, ErrRelayInvalidReceipt
	}
	if len(receipt.Error) > 1024 {
		receipt.Error = receipt.Error[:1024]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	attempt, err := relayGetAttemptTx(tx, receipt.AttemptID)
	if err != nil {
		return nil, err
	}
	if attempt == nil {
		return nil, ErrRelayDeliveryNotFound
	}
	if !relayReceiptMatchesAttempt(receipt, attempt) {
		return nil, ErrRelayInvalidReceipt
	}
	direct, err := isNetworkDirectMessageTx(tx, receipt.MessageID)
	if err != nil {
		return nil, err
	}
	if direct {
		if credentialDigest == "" {
			return nil, ErrRelayInvalidReceipt
		}
		if err := networkGuardDirectReceiptTx(tx, credentialDigest, receipt,
			time.Now().UTC()); err != nil {
			return nil, ErrRelayStaleReceipt
		}
	} else if credentialDigest != "" {
		return nil, ErrRelayInvalidReceipt
	}
	if existing, err := relayReceiptExistingTx(tx, receipt); err != nil {
		return nil, err
	} else if existing != nil {
		// Exact duplicate receipts are idempotent.  A unique row with a changed
		// digest/target would already have failed the attempt coordinate check.
		if existing.Digest != receipt.Digest || existing.TargetEndpointID != receipt.TargetEndpointID ||
			existing.BindingID != receipt.BindingID || existing.BindingEpoch != receipt.BindingEpoch {
			return nil, ErrRelayInvalidReceipt
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return existing, nil
	}
	if receipt.Layer != RelayReceiptNodeReceived && receipt.Layer != RelayReceiptInjectionUncertain && receipt.Layer != RelayReceiptConsumptionUnknown && receipt.Layer != RelayReceiptFailed {
		var receiverGroupID string
		if err := tx.QueryRow(`SELECT receiver_group_id FROM relay_v2_inbox WHERE recipient_endpoint_id=? AND sequence=? AND message_id=?`, attempt.RecipientEndpointID, attempt.Sequence, attempt.MessageID).Scan(&receiverGroupID); err != nil {
			return nil, ErrRelayInvalidReceipt
		}
		if err := networkGuardRelayMessageTx(tx, receipt.MessageID, receiverGroupID, time.Now().UTC()); err != nil {
			return nil, ErrRelayStaleReceipt
		}
	}
	if attempt.State == RelayAttemptCancelled || attempt.State == RelayAttemptFailed {
		return nil, ErrRelayStaleReceipt
	}
	// An exact duplicate was returned above. Any new receipt must move the
	// attempt forward; a lower-layer receipt after runtime injection or ACK
	// would otherwise regress the inbox to CLAIMED/READY and execute it again.
	switch attempt.State {
	case RelayAttemptAcked:
		if receipt.Layer != RelayReceiptResultAccepted {
			return nil, ErrRelayStaleReceipt
		}
	case RelayAttemptInjected:
		if receipt.Layer != RelayReceiptConsumptionUnknown && receipt.Layer != RelayReceiptApplicationAck && receipt.Layer != RelayReceiptResultAccepted {
			return nil, ErrRelayStaleReceipt
		}
	}
	if attempt.State == RelayAttemptUncertain && receipt.Layer != RelayReceiptRuntimeInjected && receipt.Layer != RelayReceiptConsumptionUnknown {
		return nil, ErrRelayStaleReceipt
	}
	// Fence the inbox row by its current attempt as well as by message ID.
	// A delayed receipt from an older claim must never rewrite a later claim's
	// state or advance that consumer's cursor. Application ACK is terminal for
	// transport delivery; RESULT_ACCEPTED may be recorded afterward as a higher
	// business layer, but it must leave the already-ACKED inbox untouched.
	var inboxState, inboxAttemptID string
	err = tx.QueryRow(`SELECT state, attempt_id FROM relay_v2_inbox
WHERE recipient_endpoint_id = ? AND sequence = ? AND message_id = ?`,
		attempt.RecipientEndpointID, attempt.Sequence, attempt.MessageID).Scan(&inboxState, &inboxAttemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRelayStaleReceipt
	}
	if err != nil {
		return nil, err
	}
	if attempt.State == RelayAttemptAcked {
		if receipt.Layer != RelayReceiptResultAccepted || inboxState != RelayInboxAcked || inboxAttemptID != "" {
			return nil, ErrRelayStaleReceipt
		}
	} else {
		expectedInboxState := RelayInboxClaimed
		switch attempt.State {
		case RelayAttemptInjected:
			expectedInboxState = RelayInboxInjected
		case RelayAttemptUncertain:
			expectedInboxState = RelayInboxUncertain
		}
		if inboxState != expectedInboxState || inboxAttemptID != attempt.AttemptID {
			return nil, ErrRelayStaleReceipt
		}
	}
	// Codex queue acceptance and native-thread resume are durable operational
	// milestones only. They require the exact active claim and prior durable
	// Node receipt, but must not advance delivery state or the consumer cursor.
	if receipt.Layer == RelayReceiptCodexQueueAccepted || receipt.Layer == RelayReceiptNativeThreadResumed {
		if attempt.State != RelayAttemptClaimed || inboxState != RelayInboxClaimed || inboxAttemptID != attempt.AttemptID {
			return nil, ErrRelayStaleReceipt
		}
		var nodeReceived int
		if err := tx.QueryRow(`SELECT count(*) FROM relay_v2_receipts WHERE attempt_id = ? AND layer = ?`,
			attempt.AttemptID, RelayReceiptNodeReceived).Scan(&nodeReceived); err != nil {
			return nil, err
		}
		if nodeReceived == 0 {
			return nil, ErrRelayStaleReceipt
		}
		if receipt.Layer == RelayReceiptNativeThreadResumed {
			var queueAccepted int
			if err := tx.QueryRow(`SELECT count(*) FROM relay_v2_receipts WHERE attempt_id = ? AND layer = ?`,
				attempt.AttemptID, RelayReceiptCodexQueueAccepted).Scan(&queueAccepted); err != nil {
				return nil, err
			}
			if queueAccepted == 0 {
				return nil, ErrRelayStaleReceipt
			}
		}
		timestamp := now()
		receipt.ReceiptID = relayString(receipt.ReceiptID)
		if receipt.ReceiptID == "" {
			receipt.ReceiptID = NewID("rcpt")
		}
		if _, err := tx.Exec(`INSERT INTO relay_v2_receipts
(receipt_id, attempt_id, message_id, digest, target_endpoint_id, binding_id,
 binding_epoch, layer, error, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, receipt.ReceiptID, receipt.AttemptID,
			receipt.MessageID, receipt.Digest, receipt.TargetEndpointID, receipt.BindingID,
			receipt.BindingEpoch, receipt.Layer, receipt.Error, timestamp); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		receipt.CreatedAt = timestamp
		receipt.Status = receipt.Layer
		return &receipt, nil
	}
	timestamp := now()
	receipt.ReceiptID = relayString(receipt.ReceiptID)
	if receipt.ReceiptID == "" {
		receipt.ReceiptID = NewID("rcpt")
	}
	_, err = tx.Exec(`INSERT INTO relay_v2_receipts
(receipt_id, attempt_id, message_id, digest, target_endpoint_id, binding_id,
 binding_epoch, layer, error, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, receipt.ReceiptID, receipt.AttemptID,
		receipt.MessageID, receipt.Digest, receipt.TargetEndpointID, receipt.BindingID,
		receipt.BindingEpoch, receipt.Layer, receipt.Error, timestamp)
	if err != nil {
		return nil, err
	}
	newAttemptState := attempt.State
	inboxState = RelayInboxClaimed
	completedAt := ""
	switch receipt.Layer {
	case RelayReceiptRuntimeInjected, RelayReceiptConsumptionUnknown:
		newAttemptState = RelayAttemptInjected
		inboxState = RelayInboxInjected
	case RelayReceiptApplicationAck, RelayReceiptResultAccepted:
		newAttemptState = RelayAttemptAcked
		inboxState = RelayInboxAcked
		completedAt = timestamp
	case RelayReceiptInjectionUncertain:
		newAttemptState = RelayAttemptUncertain
		inboxState = RelayInboxUncertain
	case RelayReceiptFailed:
		newAttemptState = RelayAttemptFailed
		inboxState = RelayInboxReady
		completedAt = timestamp
	}
	// A RESULT_ACCEPTED receipt can arrive after an APPLICATION_ACK. Preserve
	// the terminal delivery state and its already-advanced cursor in that case.
	if attempt.State != RelayAttemptAcked {
		updatedAttempt, err := tx.Exec(`UPDATE relay_v2_delivery_attempts SET state = ?, failure = ?, completed_at = ? WHERE attempt_id = ? AND state = ?`,
			newAttemptState, receipt.Error, completedAt, attempt.AttemptID, attempt.State)
		if err != nil {
			return nil, err
		}
		changed, err := updatedAttempt.RowsAffected()
		if err != nil {
			return nil, err
		}
		if changed != 1 {
			return nil, ErrRelayStaleReceipt
		}
	}
	if attempt.State != RelayAttemptAcked {
		updatedInbox, err := tx.Exec(`UPDATE relay_v2_inbox SET state = ?, attempt_id = CASE WHEN ? IN (?, ?) THEN '' ELSE attempt_id END, updated_at = ?
WHERE recipient_endpoint_id = ? AND sequence = ? AND message_id = ? AND attempt_id = ? AND state = ?`, inboxState,
			receipt.Layer, RelayReceiptFailed, RelayReceiptApplicationAck,
			timestamp, attempt.RecipientEndpointID, attempt.Sequence, attempt.MessageID,
			attempt.AttemptID, inboxStateForAttempt(attempt.State))
		if err != nil {
			return nil, err
		}
		changed, err := updatedInbox.RowsAffected()
		if err != nil {
			return nil, err
		}
		if changed != 1 {
			return nil, ErrRelayStaleReceipt
		}
	}
	if attempt.State == RelayAttemptAcked {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		receipt.CreatedAt = timestamp
		receipt.Status = receipt.Layer
		return &receipt, nil
	}
	if inboxState == RelayInboxAcked {
		if err := relayAdvanceCursorTx(tx, attempt.RecipientEndpointID, attempt.ConsumerID,
			attempt.BindingID, attempt.BindingEpoch, timestamp); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	receipt.CreatedAt = timestamp
	receipt.Status = receipt.Layer
	return &receipt, nil
}

func inboxStateForAttempt(attemptState string) string {
	switch attemptState {
	case RelayAttemptInjected:
		return RelayInboxInjected
	case RelayAttemptUncertain:
		return RelayInboxUncertain
	case RelayAttemptAcked:
		return RelayInboxAcked
	default:
		return RelayInboxClaimed
	}
}

func (s *Store) AcknowledgeRelayDelivery(receipt RelayReceipt) (*RelayReceipt, error) {
	return s.RecordRelayReceipt(receipt)
}

func (s *Store) AckRelayDelivery(receipt RelayReceipt) (*RelayReceipt, error) {
	return s.RecordRelayReceipt(receipt)
}

func (s *Store) RecordDeliveryReceipt(receipt RelayReceipt) (*RelayReceipt, error) {
	return s.RecordRelayReceipt(receipt)
}

func (s *Store) RequeueRelayDelivery(attemptID, reason string) (*RelayDeliveryAttempt, error) {
	attemptID = relayString(attemptID)
	if attemptID == "" {
		return nil, ErrRelayDeliveryNotFound
	}
	if len(reason) > 1024 {
		reason = reason[:1024]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	attempt, err := relayGetAttemptTx(tx, attemptID)
	if err != nil {
		return nil, err
	}
	if attempt == nil {
		return nil, ErrRelayDeliveryNotFound
	}
	if attempt.State != RelayAttemptClaimed && attempt.State != RelayAttemptInjected {
		return nil, ErrRelayStaleReceipt
	}
	timestamp := now()
	requestState := ""
	if attempt.RequestID != "" {
		var expiresAt string
		_ = tx.QueryRow(`SELECT state, expires_at FROM relay_v2_requests WHERE request_id = ?`, attempt.RequestID).Scan(&requestState, &expiresAt)
		if requestState == FabricRequestCancelled || requestState == FabricRequestExpired || requestState == FabricRequestLateResult {
			if _, err := tx.Exec(`UPDATE relay_v2_inbox SET state = ?, attempt_id = '', updated_at = ? WHERE recipient_endpoint_id = ? AND sequence = ?`,
				func() string {
					if requestState == FabricRequestCancelled {
						return RelayInboxCancelled
					}
					return RelayInboxExpired
				}(), timestamp,
				attempt.RecipientEndpointID, attempt.Sequence); err != nil {
				return nil, err
			}
		} else if _, err := tx.Exec(`UPDATE relay_v2_inbox SET state = ?, attempt_id = '', updated_at = ? WHERE recipient_endpoint_id = ? AND sequence = ?`,
			RelayInboxReady, timestamp, attempt.RecipientEndpointID, attempt.Sequence); err != nil {
			return nil, err
		}
	} else if _, err := tx.Exec(`UPDATE relay_v2_inbox SET state = ?, attempt_id = '', updated_at = ? WHERE recipient_endpoint_id = ? AND sequence = ?`,
		RelayInboxReady, timestamp, attempt.RecipientEndpointID, attempt.Sequence); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE relay_v2_delivery_attempts SET state = ?, failure = ?, completed_at = ? WHERE attempt_id = ?`,
		RelayAttemptFailed, reason, timestamp, attemptID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	attempt.State = RelayAttemptFailed
	attempt.Failure = reason
	attempt.CompletedAt = timestamp
	return attempt, nil
}

func (s *Store) FailRelayDelivery(attemptID, reason string) (*RelayDeliveryAttempt, error) {
	return s.RequeueRelayDelivery(attemptID, reason)
}

func (s *Store) GetRelayReceipt(receiptID string) (*RelayReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := scanRelayReceipt(s.db.QueryRow(`SELECT `+relayReceiptColumns+`
FROM relay_v2_receipts WHERE receipt_id = ?`, relayString(receiptID)))
	if err != nil {
		return nil, err
	}
	if receipt == nil {
		return nil, ErrRelayDeliveryNotFound
	}
	return receipt, nil
}

// HasRelayReceiptForAttempt reports whether an exact receipt layer is already
// durable for the immutable coordinates of a delivery attempt. Node recovery
// uses this only to permit a stale binding to repeat NODE_RECEIVED after the
// Hub committed it but the response/journal update was lost.
func (s *Store) HasRelayReceiptForAttempt(receipt RelayReceipt) (bool, error) {
	receipt.AttemptID = relayString(receipt.AttemptID)
	receipt.MessageID = relayString(receipt.MessageID)
	receipt.Digest = relayString(receipt.Digest)
	receipt.TargetEndpointID = relayString(receipt.TargetEndpointID)
	receipt.BindingID = relayString(receipt.BindingID)
	receipt.Layer = relayString(receipt.Layer)
	if receipt.AttemptID == "" || receipt.MessageID == "" || receipt.Digest == "" ||
		receipt.TargetEndpointID == "" || receipt.BindingID == "" || receipt.BindingEpoch == 0 || receipt.Layer == "" {
		return false, ErrRelayInvalidReceipt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM relay_v2_receipts WHERE attempt_id = ? AND message_id = ?
AND digest = ? AND target_endpoint_id = ? AND binding_id = ? AND binding_epoch = ? AND layer = ? LIMIT 1`,
		receipt.AttemptID, receipt.MessageID, receipt.Digest, receipt.TargetEndpointID,
		receipt.BindingID, receipt.BindingEpoch, receipt.Layer).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) ListRelayReceipts(messageID string, limit int) ([]RelayReceipt, error) {
	limit = normalizeRelayLimit(limit)
	query := `SELECT ` + relayReceiptColumns + ` FROM relay_v2_receipts WHERE message_id = ? ORDER BY created_at, receipt_id LIMIT ?`
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, relayString(messageID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]RelayReceipt, 0, limit)
	for rows.Next() {
		receipt, err := scanRelayReceipt(rows)
		if err != nil {
			return nil, err
		}
		if receipt != nil {
			result = append(result, *receipt)
		}
	}
	return result, rows.Err()
}

// AcknowledgeRelayInbox is the convenience path for an application that has
// already received a claimed row.  It still records a fully bound layered
// receipt; it never advances a cursor on a bare sequence number.
func (s *Store) AcknowledgeRelayInbox(endpointID, consumerID string, sequence int64, bindingID string, bindingEpoch uint64) (*RelayReceipt, error) {
	item, err := s.GetRelayInboxItem(endpointID, sequence)
	if err != nil {
		return nil, err
	}
	if item.AttemptID == "" {
		return nil, ErrRelayInvalidReceipt
	}
	if consumerID == "" {
		consumerID = "relay-consumer"
	}
	// The attempt's consumer is authoritative.  The caller's consumer value is
	// checked here before the state-changing receipt call.
	attempt, err := s.GetRelayDeliveryAttempt(item.AttemptID)
	if err != nil {
		return nil, err
	}
	if attempt.ConsumerID != consumerID || (bindingID != "" && attempt.BindingID != bindingID) ||
		(bindingEpoch != 0 && attempt.BindingEpoch != bindingEpoch) {
		return nil, ErrRelayInvalidReceipt
	}
	return s.RecordRelayReceipt(RelayReceipt{
		AttemptID: item.AttemptID, MessageID: item.MessageID, Digest: item.Digest,
		TargetEndpointID: endpointID, BindingID: attempt.BindingID,
		BindingEpoch: attempt.BindingEpoch, Layer: RelayReceiptApplicationAck,
	})
}

func (s *Store) GetRelayCursor(endpointID, consumerID, bindingID string) (*RelayCursor, error) {
	endpointID, consumerID, bindingID = relayString(endpointID), relayString(consumerID), relayString(bindingID)
	if endpointID == "" || consumerID == "" {
		return nil, ErrRelayCursor
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	cursor, err := getRelayCursorTxForUpdate(tx, endpointID, consumerID, bindingID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &cursor, nil
}

func relayMarkRequestCancellationTx(tx *sql.Tx, requestID, targetState, eventType, reason, timestamp string) (*FabricRequest, error) {
	request, err := relayLoadRequestTx(tx, requestID)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, ErrRelayRequestNotFound
	}
	if request.State == targetState {
		return request, nil
	}
	if targetState == FabricRequestCancelRequested && request.State != FabricRequestOpen {
		return nil, ErrRelayRequestTerminal
	}
	if targetState == FabricRequestCancelled && request.State != FabricRequestOpen && request.State != FabricRequestCancelRequested {
		return nil, ErrRelayRequestTerminal
	}
	if targetState != FabricRequestCancelRequested && targetState != FabricRequestCancelled {
		return nil, ErrRelayInvalidState
	}
	if targetState == FabricRequestCancelRequested {
		if _, err := tx.Exec(`UPDATE relay_v2_requests SET state = ?, cancel_requested_at = ?, updated_at = ? WHERE request_id = ? AND state = ?`,
			FabricRequestCancelRequested, timestamp, timestamp, requestID, FabricRequestOpen); err != nil {
			return nil, err
		}
		// A cancellation request prevents work which has not begun.  An active
		// attempt remains visible so its owner can report whether it stopped.
		if _, err := tx.Exec(`UPDATE relay_v2_inbox SET state = ?, attempt_id = '', updated_at = ?
WHERE message_id = ? AND state = 'READY'`, RelayInboxCancelled, timestamp, request.MessageID); err != nil {
			return nil, err
		}
	} else {
		if _, err := tx.Exec(`UPDATE relay_v2_requests SET state = ?, cancelled_at = ?, updated_at = ? WHERE request_id = ? AND state IN (?, ?)`,
			FabricRequestCancelled, timestamp, timestamp, requestID, FabricRequestOpen, FabricRequestCancelRequested); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`UPDATE relay_v2_inbox SET state = ?, attempt_id = '', updated_at = ?
WHERE message_id = ? AND state IN ('READY', 'CLAIMED', 'INJECTED')`, RelayInboxCancelled, timestamp, request.MessageID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`UPDATE relay_v2_delivery_attempts SET state = ?, completed_at = ?, failure = ?
WHERE message_id = ? AND state IN ('CLAIMED', 'INJECTED')`, RelayAttemptCancelled, timestamp, reason, request.MessageID); err != nil {
			return nil, err
		}
	}
	if err := relayInsertEventTx(tx, requestID, eventType, request.State, targetState, request.MessageID, reason, timestamp); err != nil {
		return nil, err
	}
	return relayLoadRequestTx(tx, requestID)
}

func (s *Store) RequestFabricRequestCancellation(requestID, reason string) (*FabricRequest, error) {
	requestID, reason = relayString(requestID), relayString(reason)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	request, err := relayMarkRequestCancellationTx(tx, requestID, FabricRequestCancelRequested, "REQUEST_CANCEL_REQUESTED", reason, now())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

// CancelFabricRequest finalizes cancellation atomically.  Callers that need
// an explicit two-phase observation can use RequestFabricRequestCancellation
// first and invoke this method after the runtime reports it stopped.
func (s *Store) CancelFabricRequest(requestID, reason string) (*FabricRequest, error) {
	requestID, reason = relayString(requestID), relayString(reason)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	request, err := relayMarkRequestCancellationTx(tx, requestID, FabricRequestCancelled, "REQUEST_CANCELLED", reason, now())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

func (s *Store) CompleteFabricRequestCancellation(requestID, reason string) (*FabricRequest, error) {
	return s.CancelFabricRequest(requestID, reason)
}

func (s *Store) ExpireFabricRequest(requestID, reason string) (*FabricRequest, error) {
	requestID, reason = relayString(requestID), relayString(reason)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	request, err := relayLoadRequestTx(tx, requestID)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, ErrRelayRequestNotFound
	}
	if request.State == FabricRequestExpired || request.State == FabricRequestLateResult {
		return request, nil
	}
	if request.State != FabricRequestOpen && request.State != FabricRequestCancelRequested {
		return nil, ErrRelayRequestTerminal
	}
	timestamp := now()
	if err := relayExpireRequestTx(tx, requestID, reason, timestamp); err != nil {
		return nil, err
	}
	request, err = relayLoadRequestTx(tx, requestID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

func (s *Store) SweepExpiredFabricRequests(limit int) ([]FabricRequest, error) {
	limit = normalizeRelayLimit(limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT request_id FROM relay_v2_requests
WHERE state IN (?, ?) AND expires_at <> '' AND cicada_network_expiry_allows(expires_at, ?) = 0
ORDER BY expires_at, request_id LIMIT ?`, FabricRequestOpen, FabricRequestCancelRequested, now(), limit)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	result := make([]FabricRequest, 0, len(ids))
	for _, id := range ids {
		if err := relayExpireRequestTx(tx, id, "request deadline reached", now()); err != nil {
			return nil, err
		}
		request, err := relayLoadRequestTx(tx, id)
		if err != nil {
			return nil, err
		}
		if request != nil {
			result = append(result, *request)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

type FabricReply struct {
	RequestID            string `json:"request_id"`
	MessageID            string `json:"message_id,omitempty"`
	ResponderEndpointID  string `json:"responder_endpoint_id"`
	ResponderPrincipalID string `json:"responder_principal_id"`
	ResponderGroupID     string `json:"responder_group_id"`
	// ReceiverBindingID/Epoch identify the original sender session to which
	// this reply may be delivered.  They are checked against the request's
	// persisted sender binding before the reply is accepted.
	ReceiverBindingID    string         `json:"receiver_binding_id,omitempty"`
	ReceiverBindingEpoch uint64         `json:"receiver_binding_epoch,omitempty"`
	Digest               string         `json:"digest,omitempty"`
	IdempotencyKey       string         `json:"idempotency_key,omitempty"`
	Body                 string         `json:"body,omitempty"`
	Metadata             map[string]any `json:"metadata,omitempty"`
	Message              *FabricMessage `json:"message,omitempty"`
}

func relayReplyEnvelope(reply FabricReply, request *FabricRequest) FabricMessage {
	if reply.Message != nil {
		message := *reply.Message
		if message.ID == "" {
			message.ID = reply.MessageID
		}
		if message.Body == "" {
			message.Body = reply.Body
		}
		if message.Metadata == nil {
			message.Metadata = reply.Metadata
		}
		if message.FromEndpointID == "" {
			message.FromEndpointID = reply.ResponderEndpointID
		}
		if message.ToEndpointID == "" {
			message.ToEndpointID = request.SenderEndpointID
		}
		if message.RequestID == "" {
			message.RequestID = request.RequestID
		}
		if message.ReplyTo == "" {
			message.ReplyTo = request.MessageID
		}
		if message.Kind == "" {
			message.Kind = "reply"
		}
		return message
	}
	return FabricMessage{ID: reply.MessageID, RequestID: request.RequestID,
		ReplyTo: request.MessageID, FromEndpointID: reply.ResponderEndpointID,
		ToEndpointID: request.SenderEndpointID, Kind: "reply", Body: reply.Body,
		Metadata: reply.Metadata}
}

// SubmitFabricReply atomically validates the responder and transitions the
// request.  Replies arriving after expiry/cancellation become LATE_RESULT
// evidence and never reopen the request.
func (s *Store) SubmitFabricReply(reply FabricReply) (*FabricRequest, error) {
	reply.RequestID = relayString(reply.RequestID)
	if reply.RequestID == "" {
		return nil, ErrRelayRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := relayAcquireWriteGuardTx(tx); err != nil {
		return nil, err
	}
	request, err := relayLoadRequestTx(tx, reply.RequestID)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, ErrRelayRequestNotFound
	}
	if err := networkGuardRelayMessageTx(tx, request.MessageID, request.ReceiverGroupID, time.Now().UTC()); err != nil {
		return nil, err
	}
	if relayString(reply.ResponderEndpointID) != request.ReceiverEndpointID {
		return nil, ErrRelayInvalidReceipt
	}
	if reply.ResponderGroupID != "" && reply.ResponderGroupID != request.ReceiverGroupID {
		return nil, ErrRelayInvalidReceipt
	}
	if request.ReceiverPrincipalID != "" && reply.ResponderPrincipalID != "" &&
		reply.ResponderPrincipalID != request.ReceiverPrincipalID {
		return nil, ErrRelayInvalidReceipt
	}
	if reply.ResponderGroupID == "" {
		reply.ResponderGroupID = request.ReceiverGroupID
	}
	if request.SenderBindingID != "" {
		if reply.ReceiverBindingID != request.SenderBindingID ||
			reply.ReceiverBindingEpoch != request.SenderBindingEpoch {
			return nil, ErrRelayBindingMismatch
		}
	} else if reply.ReceiverBindingID != "" || reply.ReceiverBindingEpoch != 0 {
		// A reply cannot introduce an unverified binding that was absent from
		// the original request's authenticated sender context.
		return nil, ErrRelayBindingMismatch
	}
	message := relayReplyEnvelope(reply, request)
	if message.ID == "" {
		message.ID = NewID("msg")
	}
	if message.Body == "" || message.FromEndpointID == "" || message.ToEndpointID == "" {
		return nil, errors.New("relay reply endpoint and body are required")
	}
	if message.FromEndpointID != reply.ResponderEndpointID {
		return nil, ErrRelayInvalidReceipt
	}
	if message.ToEndpointID != request.SenderEndpointID || message.ReplyTo != request.MessageID {
		return nil, ErrRelayMessageConflict
	}
	if err := rejectPlaintextSealedPeerTx(tx, request.ReceiverEndpointID, request.SenderEndpointID); err != nil {
		return nil, err
	}
	terminalMessageID := ""
	if request.State == FabricRequestReplied {
		terminalMessageID = request.ReplyMessageID
	} else if request.State == FabricRequestLateResult {
		terminalMessageID = request.LateResultMessageID
		message.Kind = "late_reply"
	}
	if terminalMessageID != "" {
		previous, err := relayLoadMessageTx(tx, terminalMessageID)
		if err != nil {
			return nil, err
		}
		security, err := relayLoadSecurityTx(tx, terminalMessageID)
		if err != nil {
			return nil, err
		}
		if previous == nil || security == nil {
			return nil, ErrRelayMessageNotFound
		}
		if reply.MessageID != "" && reply.MessageID != terminalMessageID {
			return nil, ErrRelayRequestTerminal
		}
		if reply.IdempotencyKey != "" && reply.IdempotencyKey != security.IdempotencyKey {
			return nil, ErrRelayRequestTerminal
		}
		if !relayMessageSemanticEqual(&message, previous) {
			if reply.IdempotencyKey != "" && reply.IdempotencyKey == security.IdempotencyKey {
				return nil, ErrRelayIdempotencyConflict
			}
			return nil, ErrRelayMessageConflict
		}
		if reply.Digest != "" && reply.Digest != security.Digest {
			return nil, ErrRelayIdempotencyConflict
		}
		return request, nil
	}
	late := request.State == FabricRequestExpired || request.State == FabricRequestCancelled || request.State == FabricRequestLateResult || request.State == FabricRequestCancelRequested
	if request.State != FabricRequestOpen && !late {
		return nil, ErrRelayRequestTerminal
	}
	if late {
		message.Kind = "late_reply"
	} else {
		message.Kind = "reply"
	}
	digest, err := relayCanonicalDigest(message, reply.Digest)
	if err != nil {
		return nil, err
	}
	idempotencyKey := reply.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = "reply:" + request.RequestID + ":" + digest
	}
	security := RelayMessageSecurity{
		MessageID: message.ID, Digest: digest, IdempotencyKey: idempotencyKey,
		SenderEndpointID: message.FromEndpointID, SenderPrincipalID: reply.ResponderPrincipalID,
		SenderGroupID: reply.ResponderGroupID, ReceiverEndpointID: message.ToEndpointID,
		ReceiverPrincipalID: request.SenderPrincipalID, ReceiverGroupID: request.SenderGroupID,
		ReceiverBindingID: reply.ReceiverBindingID, ReceiverBindingEpoch: reply.ReceiverBindingEpoch,
		VisibilityPolicyRef: request.VisibilityPolicyRef, AuthorizationRef: request.AuthorizationRef,
	}
	record, reused, err := relayEnqueueMessageTx(tx, RelayMessageInput{Message: message, Security: security, Digest: digest, IdempotencyKey: idempotencyKey})
	if err != nil {
		return nil, err
	}
	if reused {
		if existing, err := relayLoadRequestTx(tx, request.RequestID); err != nil {
			return nil, err
		} else if existing != nil && (existing.ReplyMessageID == record.Message.ID || existing.LateResultMessageID == record.Message.ID) {
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return existing, nil
		}
		return nil, ErrRelayMessageConflict
	}
	timestamp := now()
	if late {
		_, err = tx.Exec(`UPDATE relay_v2_requests SET state = ?, late_result_at = ?, late_result_message_id = ?, updated_at = ?
WHERE request_id = ? AND state IN (?, ?, ?)`, FabricRequestLateResult, timestamp, record.Message.ID, timestamp,
			reply.RequestID, FabricRequestExpired, FabricRequestCancelled, FabricRequestCancelRequested)
		if err != nil {
			return nil, err
		}
		if err := relayInsertEventTx(tx, request.RequestID, "LATE_RESULT", request.State, FabricRequestLateResult, record.Message.ID, "reply arrived after terminal deadline/cancel", timestamp); err != nil {
			return nil, err
		}
	} else {
		_, err = tx.Exec(`UPDATE relay_v2_requests SET state = ?, replied_at = ?, reply_message_id = ?, updated_at = ?
WHERE request_id = ? AND state = ?`, FabricRequestReplied, timestamp, record.Message.ID, timestamp,
			reply.RequestID, FabricRequestOpen)
		if err != nil {
			return nil, err
		}
		if err := relayInsertEventTx(tx, request.RequestID, "REQUEST_REPLIED", request.State, FabricRequestReplied, record.Message.ID, "", timestamp); err != nil {
			return nil, err
		}
	}
	request, err = relayLoadRequestTx(tx, reply.RequestID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

func (s *Store) ReplyFabricRequest(reply FabricReply) (*FabricRequest, error) {
	return s.SubmitFabricReply(reply)
}

func (s *Store) SubmitRelayReply(reply FabricReply) (*FabricRequest, error) {
	return s.SubmitFabricReply(reply)
}
