// Package fabric implements Cicada's autonomous collaboration data plane.
//
// It deliberately has no dependency on the control package. Control may use
// this package to manage groups, but ordinary directory, relay, and gateway
// operations never call Control's planner, scheduler, or reporting services.
package fabric

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

const (
	MaxMessageBytes = 64 * 1024

	ReceiptRelayAccepted        = "RELAY_ACCEPTED"
	ReceiptNodeReceived         = "NODE_RECEIVED"
	ReceiptCodexQueueAccepted   = "CODEX_QUEUE_ACCEPTED"
	ReceiptNativeThreadResumed  = "NATIVE_THREAD_RESUMED"
	ReceiptRuntimeInjected      = "RUNTIME_INJECTED"
	ReceiptConsumptionUncertain = "CONSUMPTION_UNCONFIRMED"
	ReceiptApplicationAcked     = "APPLICATION_ACKNOWLEDGED"
	ReceiptResultAccepted       = "RESULT_ACCEPTED"
	ReceiptInjectionUncertain   = "INJECTION_UNCERTAIN"
	ReceiptFailed               = "FAILED"
)

var (
	ErrAmbiguous                   = errors.New("endpoint address is ambiguous")
	ErrNotFoundOrNotAuthorized     = errors.New("not found or not authorized")
	ErrUnauthenticated             = errors.New("fabric session is not authenticated")
	ErrPermissionDenied            = errors.New("fabric permission denied")
	ErrConflict                    = errors.New("fabric object conflicts with existing state")
	ErrStaleBinding                = errors.New("session binding is stale")
	ErrCrossGroupDirectDenied      = errors.New("direct cross-group endpoint communication is denied")
	ErrRequestTerminal             = errors.New("request is already terminal")
	ErrRepresentativeUnavailable   = errors.New("group representative is unavailable")
	ErrFederationBodyWritesRetired = errors.New("legacy Monitor Federation body writes are retired; use an explicitly authorized sealed Communication Link")
)

// Actor is derived from a verified SessionBinding credential. Callers never
// populate this structure from model supplied sender/group/role parameters.
type Actor struct {
	PrincipalID        string `json:"principal_id"`
	EndpointID         string `json:"endpoint_id"`
	GroupID            string `json:"group_id"`
	MembershipID       string `json:"membership_id"`
	MembershipRevision int64  `json:"membership_revision"`
	BindingID          string `json:"binding_id"`
	BindingEpoch       uint64 `json:"binding_epoch"`
	LeaseOwner         string `json:"lease_owner"`
	LeaseExpiresAt     string `json:"lease_expires_at"`
}

func (a Actor) Validate() error {
	if strings.TrimSpace(a.PrincipalID) == "" || strings.TrimSpace(a.EndpointID) == "" ||
		strings.TrimSpace(a.GroupID) == "" || strings.TrimSpace(a.MembershipID) == "" ||
		strings.TrimSpace(a.BindingID) == "" || a.BindingEpoch <= 0 {
		return ErrUnauthenticated
	}
	return nil
}

type JoinInput struct {
	GroupID           string         `json:"group_id"`
	PrincipalID       string         `json:"principal_id,omitempty"`
	PrincipalName     string         `json:"principal_name,omitempty"`
	EndpointID        string         `json:"endpoint_id,omitempty"`
	EndpointName      string         `json:"endpoint_name,omitempty"`
	Harness           string         `json:"harness"`
	NativeSessionID   string         `json:"native_session_id"`
	NodeID            string         `json:"node_id"`
	Workspace         string         `json:"workspace,omitempty"`
	Capabilities      map[string]any `json:"capabilities,omitempty"`
	Tags              []string       `json:"tags,omitempty"`
	LeaseOwner        string         `json:"lease_owner"`
	LeaseSeconds      int            `json:"lease_seconds,omitempty"`
	ContextContinuity string         `json:"context_continuity,omitempty"`
}

type JoinResult struct {
	Endpoint       store.Endpoint `json:"endpoint"`
	NetworkCard    NetworkCard    `json:"network_card"`
	SessionToken   string         `json:"session_token"`
	BindingID      string         `json:"binding_id"`
	BindingEpoch   uint64         `json:"binding_epoch"`
	LeaseExpiresAt string         `json:"lease_expires_at"`
	Reused         bool           `json:"reused"`
}

type NetworkCard struct {
	PrincipalID  string `json:"principal_id"`
	EndpointID   string `json:"endpoint_id"`
	GroupID      string `json:"group_id"`
	Address      string `json:"address"`
	Name         string `json:"name"`
	Harness      string `json:"harness"`
	NodeID       string `json:"node_id"`
	Workspace    string `json:"workspace,omitempty"`
	Status       string `json:"status"`
	BindingID    string `json:"binding_id,omitempty"`
	BindingEpoch uint64 `json:"binding_epoch,omitempty"`
	// NativeSessionID is populated only by WhoAmI for the authenticated session.
	// Directory listing and resolution must not disclose another thread's ID.
	NativeSessionID   string         `json:"native_session_id,omitempty"`
	BindingStatus     string         `json:"binding_status,omitempty"`
	ContextContinuity string         `json:"context_continuity,omitempty"`
	Capabilities      map[string]any `json:"capabilities,omitempty"`
	Tags              []string       `json:"tags,omitempty"`
	LastSeen          string         `json:"last_seen"`
	Tools             []string       `json:"tools"`
}

type ResolveInput struct {
	Query     string `json:"query"`
	NodeID    string `json:"node_id,omitempty"`
	Workspace string `json:"workspace,omitempty"`
}

type AmbiguityError struct {
	Query      string        `json:"query"`
	Candidates []NetworkCard `json:"candidates"`
}

func (e *AmbiguityError) Error() string {
	addresses := make([]string, 0, len(e.Candidates))
	for _, candidate := range e.Candidates {
		addresses = append(addresses, candidate.Address)
	}
	return fmt.Sprintf("%v %q: %s", ErrAmbiguous, e.Query, strings.Join(addresses, ", "))
}

func (e *AmbiguityError) Unwrap() error { return ErrAmbiguous }

// SendInput intentionally has no sender fields. The service derives them from
// Actor after authenticating the binding token at the transport boundary.
type SendInput struct {
	Target         string         `json:"target"`
	Body           string         `json:"body"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	ExpiresAt      string         `json:"expires_at,omitempty"`
}

type AskInput struct {
	Target         string         `json:"target"`
	Question       string         `json:"question"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	ExpiresAt      string         `json:"expires_at,omitempty"`
}

type ReplyInput struct {
	RequestID      string         `json:"request_id"`
	Body           string         `json:"body"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
}

type RequestView struct {
	RequestID        string `json:"request_id"`
	MessageID        string `json:"message_id"`
	SenderEndpointID string `json:"sender_endpoint_id,omitempty"`
	SenderGroupID    string `json:"sender_group_id,omitempty"`
	State            string `json:"state"`
	Delivery         string `json:"delivery"`
	ReplyMode        string `json:"reply_mode"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	CancelledAt      string `json:"cancelled_at,omitempty"`
	ReplyMessageID   string `json:"reply_message_id,omitempty"`
	LateReply        bool   `json:"late_reply,omitempty"`
	NextAction       string `json:"next_action,omitempty"`
}

type ReceiveInput struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type ReceiveResult struct {
	Messages   []store.RelayInboxItem `json:"messages"`
	NextCursor string                 `json:"next_cursor"`
}

type RequestCancelInput struct {
	RequestID string `json:"request_id"`
	Reason    string `json:"reason,omitempty"`
}

type FederateInput struct {
	OriginRequestID                  string   `json:"origin_request_id"`
	TargetGroupID                    string   `json:"target_group_id"`
	Capability                       string   `json:"capability"`
	ContractID                       string   `json:"contract_id"`
	SourceRepresentativeAssignmentID string   `json:"source_representative_assignment_id"`
	TargetRepresentativeAssignmentID string   `json:"target_representative_assignment_id"`
	Scopes                           []string `json:"scopes,omitempty"`
	ArtifactRefs                     []string `json:"artifact_refs,omitempty"`
	Deadline                         string   `json:"deadline"`
	MaxHops                          int      `json:"max_hops,omitempty"`
}

type FederationResultInput struct {
	FederationRequestID string   `json:"federation_request_id"`
	LocalRequestID      string   `json:"local_request_id"`
	ArtifactRefs        []string `json:"artifact_refs,omitempty"`
	EvidenceRefs        []string `json:"evidence_refs,omitempty"`
	ProvenanceRefs      []string `json:"provenance_refs,omitempty"`
	VerificationLevel   string   `json:"verification_level,omitempty"`
}

// Delivery identifies one immutable relay assignment. Body is intentionally
// omitted from logs and receipts; Digest is the authenticated comparison key.
type Delivery struct {
	MessageID        string `json:"message_id"`
	RequestID        string `json:"request_id,omitempty"`
	SenderEndpointID string `json:"sender_endpoint_id"`
	ReplyTo          string `json:"reply_to,omitempty"`
	Kind             string `json:"kind"`
	Digest           string `json:"digest"`
	EndpointID       string `json:"endpoint_id"`
	GroupID          string `json:"group_id"`
	BindingID        string `json:"binding_id"`
	BindingEpoch     uint64 `json:"binding_epoch"`
	Harness          string `json:"harness"`
	NativeSessionID  string `json:"native_session_id"`
	NodeID           string `json:"node_id"`
	AttemptID        string `json:"attempt_id"`
	// PayloadMode is empty for the legacy plaintext path. A sealed delivery
	// must use a separate Node claim and decryption path; this Body field is
	// never an envelope transport.
	PayloadMode string `json:"payload_mode,omitempty"`
	Body        string `json:"body"`
}

type NodeClaimInput struct {
	ConsumerID string `json:"consumer_id"`
	Limit      int    `json:"limit,omitempty"`
}

type NodeReceiptInput struct {
	AttemptID    string `json:"attempt_id"`
	MessageID    string `json:"message_id"`
	Digest       string `json:"digest"`
	EndpointID   string `json:"endpoint_id"`
	BindingID    string `json:"binding_id"`
	BindingEpoch uint64 `json:"binding_epoch"`
	Layer        string `json:"layer"`
	Error        string `json:"error,omitempty"`
}
