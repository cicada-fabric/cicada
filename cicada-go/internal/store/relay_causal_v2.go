package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxRelayCausalAskDepth        = 4
	MaxRelayCausalRequestsPerRoot = 8
	MaxRelayCausalPendingPerRoot  = 5
)

var (
	ErrRelayCausalParentInvalid = errors.New("causal parent request is not currently eligible")
	ErrRelayCausalCycle         = errors.New("causal Ask would revisit an Endpoint in its request ancestry")
	ErrRelayCausalBudget        = errors.New("causal Ask permanent budget exhausted")
)

// RelayCausalBudgetError identifies a non-retryable lineage limit. Depth and
// lifetime-root limits cannot recover by waiting; the caller must not blindly
// retry them or silently allocate a new request ID. Concurrent pending-root
// pressure remains RelayAdmissionError so it can carry Retry-After.
type RelayCausalBudgetError struct {
	Scope string
	Limit int
	Used  int
}

func (e *RelayCausalBudgetError) Error() string {
	if e == nil {
		return ErrRelayCausalBudget.Error()
	}
	return fmt.Sprintf("%s: %s limit=%d used=%d", ErrRelayCausalBudget, e.Scope, e.Limit, e.Used)
}

func (e *RelayCausalBudgetError) Unwrap() error { return ErrRelayCausalBudget }

func validRelayCausalToken(value string) bool {
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

func relayCausalScopeMatches(parent, child *FabricRequest) bool {
	if parent == nil || child == nil {
		return false
	}
	parentLink := strings.HasPrefix(parent.AuthorizationRef, communicationLinkAuthorizationRefPrefix)
	childLink := strings.HasPrefix(child.AuthorizationRef, communicationLinkAuthorizationRefPrefix)
	if parentLink || childLink {
		return communicationLinkAskParentCompatible(parent, child)
	}
	parentDirect := strings.HasPrefix(parent.AuthorizationRef, networkDirectAuthorizationPrefix)
	childDirect := strings.HasPrefix(child.AuthorizationRef, networkDirectAuthorizationPrefix)
	if parentDirect || childDirect {
		return parentDirect && childDirect && parent.AuthorizationRef == child.AuthorizationRef &&
			parent.SenderGroupID == "" && parent.ReceiverGroupID == "" &&
			child.SenderGroupID == "" && child.ReceiverGroupID == "" &&
			parent.VisibilityPolicyRef == child.VisibilityPolicyRef
	}
	parentSameGroup := strings.HasPrefix(parent.AuthorizationRef, sameGroupSealedV1AuthorizationPrefix)
	childSameGroup := strings.HasPrefix(child.AuthorizationRef, sameGroupSealedV1AuthorizationPrefix)
	if parentSameGroup || childSameGroup {
		return parentSameGroup && childSameGroup &&
			parent.AuthorizationRef == child.AuthorizationRef &&
			parent.SenderGroupID != "" && parent.SenderGroupID == parent.ReceiverGroupID &&
			child.SenderGroupID == parent.SenderGroupID && child.ReceiverGroupID == parent.ReceiverGroupID &&
			parent.VisibilityPolicyRef == child.VisibilityPolicyRef
	}
	// Ordinary Relay requests use each sender's current membership reference,
	// so compare their current Group scope rather than the membership IDs.
	return parent.SenderGroupID != "" && parent.SenderGroupID == parent.ReceiverGroupID &&
		child.SenderGroupID == parent.SenderGroupID && child.ReceiverGroupID == parent.ReceiverGroupID &&
		parent.VisibilityPolicyRef == child.VisibilityPolicyRef
}

func relayCausalParentReceivedTx(tx *sql.Tx, parent *FabricRequest) (bool, error) {
	var received int
	err := tx.QueryRow(`SELECT EXISTS(
  SELECT 1 FROM relay_v2_receipts
  WHERE message_id=? AND target_endpoint_id=? AND binding_id=? AND binding_epoch=?
    AND layer IN (?,?,?,?,?,?,?,?))`,
		parent.MessageID, parent.ReceiverEndpointID, parent.ReceiverBindingID,
		parent.ReceiverBindingEpoch, RelayReceiptNodeReceived, RelayReceiptCodexQueueAccepted,
		RelayReceiptNativeThreadResumed, RelayReceiptRuntimeInjected, RelayReceiptConsumptionUnknown,
		RelayReceiptInjectionUncertain, RelayReceiptApplicationAck, RelayReceiptResultAccepted).Scan(&received)
	return received != 0, err
}

func relayCausalGuardParentTx(tx *sql.Tx, parent *FabricRequest, at time.Time) error {
	if strings.HasPrefix(parent.AuthorizationRef, networkDirectAuthorizationPrefix) {
		networkID := strings.TrimPrefix(parent.AuthorizationRef, networkDirectAuthorizationPrefix)
		if networkID == "" {
			return ErrRelayCausalParentInvalid
		}
		if err := networkGuardDirectMessageTx(tx, parent.MessageID, networkID, at); err != nil {
			return ErrRelayCausalParentInvalid
		}
		return nil
	}
	if err := networkGuardRelayMessageTx(tx, parent.MessageID, parent.ReceiverGroupID, at); err != nil {
		return ErrRelayCausalParentInvalid
	}
	return nil
}

// relayDeriveCausalLineageTx accepts only a currently open, finite-deadline
// request received by this sender on the exact current binding. Root, depth,
// and cycle membership are always derived from stored ancestry in this same
// admission transaction; the caller supplies no trusted depth or budget.
func relayDeriveCausalLineageTx(tx *sql.Tx, request *FabricRequest, at time.Time) error {
	if request == nil || request.RequestID == "" || request.SenderEndpointID == "" ||
		request.ReceiverEndpointID == "" {
		return ErrRelayCausalParentInvalid
	}
	if request.ParentRequestID != strings.TrimSpace(request.ParentRequestID) {
		return ErrRelayCausalParentInvalid
	}
	if request.ParentRequestID == "" {
		request.CausalRootRequestID = request.RequestID
		request.CausalDepth = 0
		return relayCheckCausalBudgetTx(tx, request.CausalRootRequestID, at)
	}
	if !validRelayCausalToken(request.ParentRequestID) || request.ParentRequestID == request.RequestID {
		return ErrRelayCausalParentInvalid
	}
	parent, err := relayLoadRequestTx(tx, request.ParentRequestID)
	if err != nil || parent == nil || parent.State != FabricRequestOpen ||
		parent.ReceiverEndpointID != request.SenderEndpointID ||
		parent.ReceiverPrincipalID != request.SenderPrincipalID ||
		parent.ReceiverBindingID == "" || parent.ReceiverBindingEpoch == 0 ||
		request.SenderBindingID == "" || request.SenderBindingEpoch == 0 ||
		parent.ReceiverBindingID != request.SenderBindingID ||
		parent.ReceiverBindingEpoch != request.SenderBindingEpoch ||
		!relayCausalScopeMatches(parent, request) {
		return ErrRelayCausalParentInvalid
	}
	expires, err := time.Parse(time.RFC3339Nano, parent.ExpiresAt)
	if err != nil || !expires.After(at) {
		return ErrRelayCausalParentInvalid
	}
	if err := relayCausalGuardParentTx(tx, parent, at); err != nil {
		return ErrRelayCausalParentInvalid
	}
	received, err := relayCausalParentReceivedTx(tx, parent)
	if err != nil {
		return err
	}
	if !received {
		return ErrRelayCausalParentInvalid
	}

	rootID := parent.CausalRootRequestID
	parentDepth := parent.CausalDepth
	if rootID == "" {
		// A pre-migration request may be the root of a new bounded chain, but
		// never infer ancestry that was not persisted before this migration.
		if parent.ParentRequestID != "" || parentDepth != 0 {
			return ErrRelayCausalParentInvalid
		}
		rootID = parent.RequestID
	}
	if parentDepth < 0 || parentDepth >= MaxRelayCausalAskDepth {
		return relayCausalLimitError("depth", MaxRelayCausalAskDepth, parentDepth+1)
	}
	childDepth := parentDepth + 1
	if childDepth > MaxRelayCausalAskDepth {
		return relayCausalLimitError("depth", MaxRelayCausalAskDepth, childDepth)
	}

	seenEndpoints := make(map[string]struct{}, childDepth+2)
	current := parent
	for traversed := 0; ; traversed++ {
		if current == nil || traversed > MaxRelayCausalAskDepth ||
			current.CausalDepth != parentDepth-traversed ||
			(current.CausalRootRequestID != "" && current.CausalRootRequestID != rootID) ||
			current.State != FabricRequestOpen {
			return ErrRelayCausalParentInvalid
		}
		// A live immediate parent is not enough: a cancelled or expired root
		// must not continue to authorize deeper work through an older child.
		// Existing descendants are not cancelled here; this only blocks new
		// admissions derived from a no-longer-live ancestry.
		currentExpiry, expiryErr := time.Parse(time.RFC3339Nano, current.ExpiresAt)
		if expiryErr != nil || !currentExpiry.After(at) {
			return ErrRelayCausalParentInvalid
		}
		if err := relayCausalGuardParentTx(tx, current, at); err != nil {
			return ErrRelayCausalParentInvalid
		}
		currentReceived, receiptErr := relayCausalParentReceivedTx(tx, current)
		if receiptErr != nil {
			return receiptErr
		}
		if !currentReceived {
			return ErrRelayCausalParentInvalid
		}
		if current.SenderEndpointID == request.ReceiverEndpointID ||
			current.ReceiverEndpointID == request.ReceiverEndpointID {
			return ErrRelayCausalCycle
		}
		seenEndpoints[current.SenderEndpointID] = struct{}{}
		seenEndpoints[current.ReceiverEndpointID] = struct{}{}
		if current.ParentRequestID == "" {
			if current.RequestID != rootID || traversed != parentDepth {
				return ErrRelayCausalParentInvalid
			}
			break
		}
		ancestor, err := relayLoadRequestTx(tx, current.ParentRequestID)
		if err != nil || ancestor == nil || ancestor.ReceiverEndpointID != current.SenderEndpointID ||
			!relayCausalScopeMatches(ancestor, current) {
			return ErrRelayCausalParentInvalid
		}
		current = ancestor
	}
	if _, cycle := seenEndpoints[request.SenderEndpointID]; !cycle {
		return ErrRelayCausalParentInvalid
	}
	request.CausalRootRequestID = rootID
	request.CausalDepth = childDepth
	return relayCheckCausalBudgetTx(tx, rootID, at)
}

func relayCausalLimitError(scope string, limit, pending int) error {
	if scope != "root_pending" {
		return &RelayCausalBudgetError{Scope: scope, Limit: limit, Used: pending}
	}
	return &RelayAdmissionError{Scope: "causal_" + scope, Limit: limit,
		Pending: pending, RetryAfter: time.Second, RetryAfterSeconds: 1}
}

// relayParentRequestForSealedRouteTx returns the causal parent bound to the
// durable request behind a sealed ASK or REPLY. Nodes receive this projection
// with their current authorization so they can compare it with their stored
// outbox/AAD before opening the message. The route never supplies a trusted
// parent value by itself.
func relayParentRequestForSealedRouteTx(tx *sql.Tx, route RelaySealedV1Route) (string, error) {
	if route.Kind != "ask" && route.Kind != "reply" {
		return "", nil
	}
	if route.RequestID == "" {
		return "", ErrRelayCausalParentInvalid
	}
	request, err := relayLoadRequestTx(tx, route.RequestID)
	if err != nil || request == nil {
		return "", ErrRelayCausalParentInvalid
	}
	switch route.Kind {
	case "ask":
		if request.MessageID != route.MessageID {
			return "", ErrRelayCausalParentInvalid
		}
	case "reply":
		if request.MessageID != route.ReplyTo || request.ReplyMessageID != route.MessageID {
			return "", ErrRelayCausalParentInvalid
		}
	}
	return request.ParentRequestID, nil
}

func (s *Store) initializeRelayCausalAskSchema() error {
	columns, err := existingColumns(s.db, "relay_v2_requests", []string{
		"parent_request_id", "causal_root_request_id", "causal_depth",
	})
	if err != nil {
		return err
	}
	present := make(map[string]bool, len(columns))
	for _, column := range columns {
		present[column] = true
	}
	if !present["parent_request_id"] {
		if _, err := s.db.Exec(`ALTER TABLE relay_v2_requests ADD COLUMN parent_request_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if !present["causal_root_request_id"] {
		if _, err := s.db.Exec(`ALTER TABLE relay_v2_requests ADD COLUMN causal_root_request_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if !present["causal_depth"] {
		if _, err := s.db.Exec(`ALTER TABLE relay_v2_requests ADD COLUMN causal_depth INTEGER NOT NULL DEFAULT 0 CHECK(causal_depth>=0)`); err != nil {
			return err
		}
	}
	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS relay_v2_requests_causal_root_idx
  ON relay_v2_requests(causal_root_request_id,state,expires_at,request_id)`)
	return err
}

func relayCheckCausalBudgetTx(tx *sql.Tx, rootID string, at time.Time) error {
	if rootID == "" {
		return ErrRelayCausalParentInvalid
	}
	var total, pending int
	if err := tx.QueryRow(`SELECT count(*) FROM relay_v2_requests
WHERE causal_root_request_id=? OR (causal_root_request_id='' AND request_id=?)`,
		rootID, rootID).Scan(&total); err != nil {
		return err
	}
	if total >= MaxRelayCausalRequestsPerRoot {
		return relayCausalLimitError("root_messages", MaxRelayCausalRequestsPerRoot, total)
	}
	if err := tx.QueryRow(`SELECT count(*) FROM relay_v2_requests
WHERE (causal_root_request_id=? OR (causal_root_request_id='' AND request_id=?))
  AND state IN (?,?) AND (expires_at='' OR expires_at>?)`, rootID, rootID,
		FabricRequestOpen, FabricRequestCancelRequested, at.UTC().Format(time.RFC3339Nano)).Scan(&pending); err != nil {
		return err
	}
	if pending >= MaxRelayCausalPendingPerRoot {
		return relayCausalLimitError("root_pending", MaxRelayCausalPendingPerRoot, pending)
	}
	return nil
}
