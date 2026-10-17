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
const MaxAppNodeInnerPacketBytes = 384 * 1024

const (
	AppNodeContractRevision             = "app-node-authority-v1"
	AppNodeCapabilitiesFormat           = "cicada.app-node-capabilities.v1"
	AppNodeCapabilitiesPath             = "/v2/owner/app-node/capabilities"
	MaxAppNodeCapabilitiesBytes         = 8 * 1024
	AppNodePrepareFormat                = "cicada.app-node-prepare.v1"
	AppNodeChallengeFormat              = "cicada.app-node-challenge.v1"
	AppNodeCompleteFormat               = "cicada.app-node-complete.v1"
	AppNodeStatusFormat                 = "cicada.app-node-status.v1"
	AppNodeCancelFormat                 = "cicada.app-node-cancel.v1"
	AppNodeResultFormat                 = "cicada.app-node-result.v1"
	AppNodeReconcileFormat              = "cicada.app-node-reconcile.v1"
	AppNodeReconciledFormat             = "cicada.app-node-reconciled.v1"
	OperationAppNodePrepare             = "owner.app_node.prepare"
	OperationAppNodeComplete            = "owner.app_node.complete"
	OperationAppNodeStatus              = "owner.app_node.status"
	OperationAppNodeCancel              = "owner.app_node.cancel"
	OperationAppNodeReconcile           = "owner.app_node.reconcile"
	AppNodePrepared                     = "PREPARED"
	AppNodeActive                       = "ACTIVE"
	AppNodeExpired                      = "EXPIRED"
	AppNodeCancelled                    = "CANCELLED"
	AppNodeRevoked                      = "REVOKED"
	AppNodeSessionEnded                 = "SESSION_ENDED"
	AppNodeAbsent                       = "ABSENT"
	AppNodeCompleted                    = "COMPLETED"
	AppNodeRejectedFenced               = "REJECTED_FENCED"
	AppNodeReadExpired                  = "READ_EXPIRED"
	AppNodeOriginalAuthority            = "APP_NODE_AUTHORITY"
	AppNodeOriginalClient               = "CLIENT_CONTROL"
	AppNodeTransportHTTPS               = "HTTPS_APPLICATION_PQ"
	AppNodeTransportLoopbackTest        = "LOOPBACK_HTTP_TEST_ONLY"
	AppNodeConfirmationLimit            = uint64(1)
	AppNodeProfileInitial               = "INITIAL_CONFIRM"
	AppNodeProfileStatus                = "READ_EXISTING"
	AppNodeTargetInitial                = "INITIAL_CODE"
	AppNodeTargetPrevious               = "PREVIOUS_GRANT"
	MaxAppNodeIntentLifetime            = time.Minute
	MaxAppNodeProofLifetime             = 5 * time.Minute
	AppNodeLeaseLifetime                = 15 * time.Minute
	AppNodeObservationStaleAfter        = 2 * time.Minute
	MaxAppNodeBodyBytes                 = 192 * 1024
	MaxAppNodeProofBytes                = 32 * 1024
	MaxAppNodeOriginalBytes             = 128 * 1024
	MaxAppNodeMutationPacketBytes       = 128 * 1024
	MaxAppNodeReceiptBytes              = 128 * 1024
	MaxAppNodePendingPerDevice          = 1
	MaxAppNodeReadCacheEntriesPerDevice = 128
	AppNodeReadCacheLifetime            = 5 * time.Minute
	MaxAppNodeDiagnosticsPerMinute      = 128
)

// Context supplies authenticated routing and freshness. All five account
// envelopes use the fixed handshake route; these epochs are checked in Store.
type AppNodeRequestContext struct {
	Origin       string `json:"origin"`
	HubID        string `json:"hub_id"`
	AccountID    string `json:"account_id"`
	OwnerID      string `json:"owner_id"`
	DeviceID     string `json:"device_id"`
	AccountEpoch uint64 `json:"account_epoch"`
	DeviceEpoch  uint64 `json:"device_epoch"`
	RequestID    string `json:"request_id"`
	ClientNonce  []byte `json:"client_nonce"`
	IssuedAt     string `json:"issued_at"`
}

// Public feature availability on a new GET path is not caller authorization.
// Existing strict health/identity JSON documents remain unchanged.
type AppNodeCapabilities struct {
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

type AppNodePrepare struct {
	Format       string                `json:"format"`
	Context      AppNodeRequestContext `json:"context"`
	SessionToken []byte                `json:"session_token"`
	Target       AppNodePrepareTarget  `json:"target"`
	OwnerIntent  []byte                `json:"owner_intent"`
}

type AppNodePrepareTarget struct {
	Kind            string `json:"kind"`
	Code            string `json:"code"`
	PreviousGrantID string `json:"previous_grant_id"`
}

type AppNodeChallenge struct {
	Format              string                       `json:"format"`
	RequestID           string                       `json:"request_id"`
	RequestPacketDigest string                       `json:"request_packet_digest"`
	Claims              e2ee.OwnerAppNodeGrantClaims `json:"claims"`
	ObservedAt          string                       `json:"observed_at"`
}

type AppNodeComplete struct {
	Format       string                `json:"format"`
	Context      AppNodeRequestContext `json:"context"`
	SessionToken []byte                `json:"session_token"`
	OwnerGrant   []byte                `json:"owner_grant"`
}

type AppNodeStatusRequest struct {
	Format       string                `json:"format"`
	Context      AppNodeRequestContext `json:"context"`
	SessionToken []byte                `json:"session_token"`
	GrantID      string                `json:"grant_id"`
}

type AppNodeCancel struct {
	Format              string                `json:"format"`
	Context             AppNodeRequestContext `json:"context"`
	SessionToken        []byte                `json:"session_token"`
	GrantID             string                `json:"grant_id"`
	ExpectedHeadVersion uint64                `json:"expected_head_version"`
}

// Counter values are authenticated observations, never permission to skip an
// unresolved packet, reset replay state or transplant another profile's actor.
type AppNodeClientCounters struct {
	SessionEpoch         uint64 `json:"session_epoch"`
	LastRequestSequence  uint64 `json:"last_request_sequence"`
	NextResponseSequence uint64 `json:"next_response_sequence"`
}

type AppNodeAuthoritySnapshot struct {
	Scope                    e2ee.OwnerAppNodeScope `json:"scope"`
	GrantID                  string                 `json:"grant_id"`
	State                    string                 `json:"state"`
	Profile                  string                 `json:"profile"`
	CurrentHeadVersion       uint64                 `json:"current_head_version"`
	LatestGrantID            string                 `json:"latest_grant_id"`
	ConfirmationProvenanceID string                 `json:"confirmation_provenance_id"`
	EndReason                string                 `json:"end_reason"`
	RootState                string                 `json:"root_state"`
	LoginRequired            bool                   `json:"login_required"`
	AllowedOperations        []string               `json:"allowed_operations"`
	RemainingConfirmations   uint64                 `json:"remaining_confirmations"`
	LeaseExpiresAt           string                 `json:"lease_expires_at"`
	Counters                 AppNodeClientCounters  `json:"client_counters"`
}

// No capability profiles, Goal/Worker/Thread metadata or general status
// snapshot is included. Missing liveness stays UNKNOWN, rather than online.
type AppNodeObservation struct {
	NodeID             string `json:"node_id"`
	NodeName           string `json:"node_name"`
	BindingID          string `json:"binding_id"`
	BindingVersion     uint64 `json:"binding_version"`
	CredentialVersion  uint64 `json:"credential_version"`
	NodeKeyID          string `json:"node_key_id"`
	NodeKeyFingerprint string `json:"node_key_fingerprint"`
	NodeKeyEpoch       uint64 `json:"node_key_epoch"`
	BindingState       string `json:"binding_state"`
	Authorized         bool   `json:"authorized"`
	Connectivity       string `json:"connectivity"`
	Known              bool   `json:"known"`
	Stale              bool   `json:"stale"`
	Source             string `json:"source"`
	LastHeartbeatAt    string `json:"last_heartbeat_at"`
	ObservedAt         string `json:"observed_at"`
	FreshUntil         string `json:"fresh_until"`
}

type AppNodeResult struct {
	Format              string                   `json:"format"`
	Operation           string                   `json:"operation"`
	RequestID           string                   `json:"request_id"`
	RequestPacketDigest string                   `json:"request_packet_digest"`
	State               string                   `json:"state"`
	ErrorCode           string                   `json:"error_code"`
	Authority           AppNodeAuthoritySnapshot `json:"authority"`
	Node                *AppNodeObservation      `json:"node"`
	ObservedAt          string                   `json:"observed_at"`
}

type AppNodeReconcileRequest struct {
	Format         string                `json:"format"`
	Context        AppNodeRequestContext `json:"context"`
	GrantID        string                `json:"grant_id"`
	OriginalKind   string                `json:"original_kind"`
	OriginalPacket []byte                `json:"original_packet"`
}

// Keep reconciliation compact: embedding full scope/public identities beside
// a base64 receipt can exceed the existing 192 KiB extension-body budget.
type AppNodeReconcileResult struct {
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

func AppNodeAllowedOperations() []string { return []string{"nodes.confirm"} }

func AppNodeStatusAllowedOperations() []string { return []string{} }

func AppNodeReconcileOriginalAllowed(kind, operation string) bool {
	switch kind {
	case AppNodeOriginalAuthority:
		return operation == OperationAppNodePrepare || operation == OperationAppNodeComplete || operation == OperationAppNodeCancel || operation == OperationAppNodeStatus
	case AppNodeOriginalClient:
		return operation == "nodes.confirm"
	}
	return false
}

func AppNodeHTTPPath(operation string) string {
	switch operation {
	case OperationAppNodePrepare:
		return "/v2/owner/app-node/prepare"
	case OperationAppNodeComplete:
		return "/v2/owner/app-node/complete"
	case OperationAppNodeStatus:
		return "/v2/owner/app-node/status"
	case OperationAppNodeCancel:
		return "/v2/owner/app-node/cancel"
	case OperationAppNodeReconcile:
		return "/v2/owner/app-node/reconcile"
	}
	return ""
}

func AppNodePacketDigest(raw []byte) string {
	h := sha256.Sum256(append([]byte("cicada/app-node-authority/packet/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}

func AppNodeProofDigest(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func AppNodeClaimsDigest(claims e2ee.OwnerAppNodeGrantClaims) string {
	raw, _ := json.Marshal(claims)
	h := sha256.Sum256(append([]byte("cicada/app-node-authority/claims/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}

// The existing Client AAD authenticates OperationID. Carrying the exact grant
// ID here prevents an old delayed packet borrowing a subsequently signed grant.
func AppNodeBusinessOperationID(grantID, nonce string) (string, error) {
	if !isHex(grantID, RequestIDBytes) || !isHex(nonce, RequestIDBytes) {
		return "", ErrInvalid
	}
	return "n3." + grantID + "." + nonce, nil
}

func ParseAppNodeBusinessOperationID(value string) (grantID, nonce string, err error) {
	p := strings.Split(value, ".")
	if len(p) != 3 || p[0] != "n3" || !isHex(p[1], RequestIDBytes) || !isHex(p[2], RequestIDBytes) {
		return "", "", ErrInvalid
	}
	return p[1], p[2], nil
}
