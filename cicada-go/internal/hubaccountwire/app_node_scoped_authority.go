package hubaccountwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// Reviewed N3 contract: these definitions do not enable an HTTP handler, modify
// the frozen Client catalog, or alter owner-activation-v1 authority.
const MaxAppNodeScopedInnerPacketBytes = 384 * 1024

const (
	AppNodeScopedContractRevision             = "app-node-authority-node-scoped-v1"
	AppNodeScopedCapabilitiesFormat           = "cicada.app-node-scoped-capabilities.v1"
	AppNodeScopedCapabilitiesPath             = "/v2/owner/app-node-scoped/capabilities"
	MaxAppNodeScopedCapabilitiesBytes         = 8 * 1024
	AppNodeScopedPrepareFormat                = "cicada.app-node-scoped-prepare.v1"
	AppNodeScopedChallengeFormat              = "cicada.app-node-scoped-challenge.v1"
	AppNodeScopedCompleteFormat               = "cicada.app-node-scoped-complete.v1"
	AppNodeScopedStatusFormat                 = "cicada.app-node-scoped-status.v1"
	AppNodeScopedCancelFormat                 = "cicada.app-node-scoped-cancel.v1"
	AppNodeScopedResultFormat                 = "cicada.app-node-scoped-result.v1"
	AppNodeScopedReconcileFormat              = "cicada.app-node-scoped-reconcile.v1"
	AppNodeScopedReconciledFormat             = "cicada.app-node-scoped-reconciled.v1"
	OperationAppNodeScopedPrepare             = "owner.app_node_scoped.prepare"
	OperationAppNodeScopedComplete            = "owner.app_node_scoped.complete"
	OperationAppNodeScopedStatus              = "owner.app_node_scoped.status"
	OperationAppNodeScopedCancel              = "owner.app_node_scoped.cancel"
	OperationAppNodeScopedReconcile           = "owner.app_node_scoped.reconcile"
	AppNodeScopedPrepared                     = "PREPARED"
	AppNodeScopedActive                       = "ACTIVE"
	AppNodeScopedExpired                      = "EXPIRED"
	AppNodeScopedCancelled                    = "CANCELLED"
	AppNodeScopedRevoked                      = "REVOKED"
	AppNodeScopedSessionEnded                 = "SESSION_ENDED"
	AppNodeScopedAbsent                       = "ABSENT"
	AppNodeScopedCompleted                    = "COMPLETED"
	AppNodeScopedRejectedFenced               = "REJECTED_FENCED"
	AppNodeScopedReadExpired                  = "READ_EXPIRED"
	AppNodeScopedOriginalAuthority            = "APP_NODE_SCOPED_AUTHORITY"
	AppNodeScopedOriginalClient               = "CLIENT_CONTROL"
	AppNodeScopedTransportHTTPS               = "HTTPS_APPLICATION_PQ"
	AppNodeScopedTransportLoopbackTest        = "LOOPBACK_HTTP_TEST_ONLY"
	AppNodeScopedConfirmationLimit            = uint64(1)
	AppNodeScopedProfileInitial               = "INITIAL_CONFIRM"
	AppNodeScopedProfileStatus                = "READ_EXISTING"
	AppNodeScopedTargetInitial                = "INITIAL_CODE"
	AppNodeScopedTargetPrevious               = "PREVIOUS_GRANT"
	MaxAppNodeScopedIntentLifetime            = time.Minute
	MaxAppNodeScopedProofLifetime             = 5 * time.Minute
	AppNodeScopedLeaseLifetime                = 15 * time.Minute
	AppNodeScopedObservationStaleAfter        = 2 * time.Minute
	MaxAppNodeScopedBodyBytes                 = 192 * 1024
	MaxAppNodeScopedProofBytes                = 32 * 1024
	MaxAppNodeScopedOriginalBytes             = 128 * 1024
	MaxAppNodeScopedMutationPacketBytes       = 128 * 1024
	MaxAppNodeScopedReceiptBytes              = 128 * 1024
	MaxAppNodeScopedPendingPerDevice          = 1
	MaxAppNodeScopedReadCacheEntriesPerDevice = 128
	AppNodeScopedReadCacheLifetime            = 5 * time.Minute
	MaxAppNodeScopedDiagnosticsPerMinute      = 128
)

// Context supplies authenticated routing and freshness. All five account
// envelopes use the fixed handshake route; these epochs are checked in Store.
// Public feature availability on a new GET path is not caller authorization.
// Existing strict health/identity JSON documents remain unchanged.
const AppNodeScopedScopeKind = "NODE_V1"
const AppNodeScopedScopeVersion = 2

// This checkpoint freezes codecs only. A later complete carrier may enable it.
const AppNodeScopedPublicAvailable = false

type AppNodeScopedCapabilities struct {
	ScopeKind           string   `json:"scope_kind"`
	ScopeVersion        int      `json:"scope_version"`
	Format              string   `json:"format"`
	ContractRevision    string   `json:"contract_revision"`
	ServeMode           string   `json:"serve_mode"`
	Available           bool     `json:"available"`
	HTTPOperations      []string `json:"http_operations"`
	Profiles            []string `json:"profiles"`
	RuntimeLeaseSeconds uint64   `json:"runtime_lease_seconds"`
	MaxOriginalBytes    uint64   `json:"max_original_bytes"`
	TransportPolicy     string   `json:"transport_policy"`
}

type AppNodeScopedPrepare struct {
	Format       string                     `json:"format"`
	Context      AppNodeRequestContext      `json:"context"`
	SessionToken []byte                     `json:"session_token"`
	Target       AppNodeScopedPrepareTarget `json:"target"`
	OwnerIntent  []byte                     `json:"owner_intent"`
}

type AppNodeScopedPrepareTarget struct {
	Kind            string `json:"kind"`
	Code            string `json:"code"`
	PreviousGrantID string `json:"previous_grant_id"`
}

type AppNodeScopedChallenge struct {
	Format              string                             `json:"format"`
	RequestID           string                             `json:"request_id"`
	RequestPacketDigest string                             `json:"request_packet_digest"`
	Claims              e2ee.OwnerAppNodeScopedGrantClaims `json:"claims"`
	ObservedAt          string                             `json:"observed_at"`
}

type AppNodeScopedComplete struct {
	Format       string                `json:"format"`
	Context      AppNodeRequestContext `json:"context"`
	SessionToken []byte                `json:"session_token"`
	OwnerGrant   []byte                `json:"owner_grant"`
}

type AppNodeScopedStatusTarget struct {
	NodeID        string `json:"node_id"`
	CandidateCode string `json:"candidate_code"`
}

type AppNodeScopedStatus struct {
	Target       AppNodeScopedStatusTarget `json:"target"`
	Format       string                    `json:"format"`
	Context      AppNodeRequestContext     `json:"context"`
	SessionToken []byte                    `json:"session_token"`
	GrantID      string                    `json:"grant_id"`
}

type AppNodeScopedCancel struct {
	AuthorityNodeID     string                `json:"authority_node_id"`
	Format              string                `json:"format"`
	Context             AppNodeRequestContext `json:"context"`
	SessionToken        []byte                `json:"session_token"`
	GrantID             string                `json:"grant_id"`
	ExpectedHeadVersion uint64                `json:"expected_head_version"`
}

// Counter values are authenticated observations, never permission to skip an
// unresolved packet, reset replay state or transplant another profile's actor.
type AppNodeScopedAuthoritySnapshot struct {
	Scope                    e2ee.OwnerAppNodeScopedScope `json:"scope"`
	GrantID                  string                       `json:"grant_id"`
	State                    string                       `json:"state"`
	Profile                  string                       `json:"profile"`
	CurrentHeadVersion       uint64                       `json:"current_head_version"`
	LatestGrantID            string                       `json:"latest_grant_id"`
	ConfirmationProvenanceID string                       `json:"confirmation_provenance_id"`
	EndReason                string                       `json:"end_reason"`
	RootState                string                       `json:"root_state"`
	LoginRequired            bool                         `json:"login_required"`
	AllowedOperations        []string                     `json:"allowed_operations"`
	RemainingConfirmations   uint64                       `json:"remaining_confirmations"`
	LeaseExpiresAt           string                       `json:"lease_expires_at"`
	Counters                 AppNodeClientCounters        `json:"client_counters"`
}

// No capability profiles, Goal/Worker/Thread metadata or general status
// snapshot is included. Missing liveness stays UNKNOWN, rather than online.
type AppNodeScopedResult struct {
	Format              string                         `json:"format"`
	Operation           string                         `json:"operation"`
	RequestID           string                         `json:"request_id"`
	RequestPacketDigest string                         `json:"request_packet_digest"`
	State               string                         `json:"state"`
	ErrorCode           string                         `json:"error_code"`
	Authority           AppNodeScopedAuthoritySnapshot `json:"authority"`
	Node                *AppNodeObservation            `json:"node"`
	ObservedAt          string                         `json:"observed_at"`
}

type AppNodeScopedReconcile struct {
	AuthorityNodeID string                `json:"authority_node_id"`
	Format          string                `json:"format"`
	Context         AppNodeRequestContext `json:"context"`
	GrantID         string                `json:"grant_id"`
	OriginalKind    string                `json:"original_kind"`
	OriginalPacket  []byte                `json:"original_packet"`
}

// Keep reconciliation compact: embedding full scope/public identities beside
// a base64 receipt can exceed the existing 192 KiB extension-body budget.
type AppNodeScopedReconciled struct {
	AuthorityNodeID      string `json:"authority_node_id"`
	Format               string `json:"format"`
	Origin               string `json:"origin"`
	HubID                string `json:"hub_id"`
	AccountID            string `json:"account_id"`
	OwnerID              string `json:"owner_id"`
	DeviceID             string `json:"device_id"`
	RequestID            string `json:"request_id"`
	RequestPacketDigest  string `json:"request_packet_digest"`
	GrantID              string `json:"grant_id"`
	OriginalKind         string `json:"original_kind"`
	OriginalOperation    string `json:"original_operation"`
	OriginalRequestID    string `json:"original_request_id"`
	OriginalPacketDigest string `json:"original_packet_digest"`
	State                string `json:"state"`
	ReceiptPacket        []byte `json:"receipt_packet"`
	AccountEpoch         uint64 `json:"account_epoch"`
	DeviceEpoch          uint64 `json:"device_epoch"`
	CurrentHeadVersion   uint64 `json:"current_head_version"`
	CurrentGrantState    string `json:"current_grant_state"`
	ObservedAt           string `json:"observed_at"`
}

func AppNodeScopedAllowedOperations() []string { return []string{"nodes.confirm"} }

func AppNodeScopedStatusAllowedOperations() []string { return []string{} }

func AppNodeScopedReconcileOriginalAllowed(kind, operation string) bool {
	switch kind {
	case AppNodeScopedOriginalAuthority:
		return operation == OperationAppNodeScopedPrepare || operation == OperationAppNodeScopedComplete || operation == OperationAppNodeScopedCancel || operation == OperationAppNodeScopedStatus
	case AppNodeScopedOriginalClient:
		return operation == "nodes.confirm"
	}
	return false
}

func AppNodeScopedHTTPPath(operation string) string {
	switch operation {
	case OperationAppNodeScopedPrepare:
		return "/v2/owner/app-node-scoped/prepare"
	case OperationAppNodeScopedComplete:
		return "/v2/owner/app-node-scoped/complete"
	case OperationAppNodeScopedStatus:
		return "/v2/owner/app-node-scoped/status"
	case OperationAppNodeScopedCancel:
		return "/v2/owner/app-node-scoped/cancel"
	case OperationAppNodeScopedReconcile:
		return "/v2/owner/app-node-scoped/reconcile"
	}
	return ""
}

func AppNodeScopedPacketDigest(raw []byte) string {
	h := sha256.Sum256(append([]byte("cicada/app-node-scoped-authority/packet/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}

func AppNodeScopedProofDigest(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func AppNodeScopedClaimsDigest(claims e2ee.OwnerAppNodeScopedGrantClaims) string {
	raw, _ := json.Marshal(claims)
	h := sha256.Sum256(append([]byte("cicada/app-node-scoped-authority/claims/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}

// The existing Client AAD authenticates OperationID. Carrying the exact grant
// ID here prevents an old delayed packet borrowing a subsequently signed grant.
func AppNodeScopedBusinessOperationID(grantID, nonce string) (string, error) {
	if !isHex(grantID, RequestIDBytes) || !isHex(nonce, RequestIDBytes) {
		return "", ErrInvalid
	}
	return "n3s." + grantID + "." + nonce, nil
}

func ParseAppNodeScopedBusinessOperationID(value string) (grantID, nonce string, err error) {
	p := strings.Split(value, ".")
	if len(p) != 3 || p[0] != "n3s" || !isHex(p[1], RequestIDBytes) || !isHex(p[2], RequestIDBytes) {
		return "", "", ErrInvalid
	}
	return p[1], p[2], nil
}
