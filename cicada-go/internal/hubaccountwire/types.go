// Package hubaccountwire defines the account-only setup and session packets.
// It reuses Client Wire v1's ML-KEM/ML-DSA/AES-GCM envelope without changing
// Client catalogs, counters, grants, or management authorization.
package hubaccountwire

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

const (
	PacketFormat            = "cicada.owner-account-packet.v1"
	PacketVersion           = 1
	ClaimCardFormat         = "cicada.hub-owner-claim.v1"
	ClaimPrepareFormat      = "cicada.owner-account-claim-prepare.v1"
	ClaimChallengeFormat    = "cicada.owner-account-claim-challenge.v1"
	ClaimCompleteFormat     = "cicada.owner-account-claim-complete.v1"
	ClaimReceiptFormat      = "cicada.owner-account-claim-receipt.v1"
	LoginPrepareFormat      = "cicada.owner-account-login-prepare.v1"
	LoginChallengeFormat    = "cicada.owner-account-login-challenge.v1"
	LoginCompleteFormat     = "cicada.owner-account-login-complete.v1"
	SessionReceiptFormat    = "cicada.owner-account-session.v1"
	SessionInspectFormat    = "cicada.owner-account-session-inspect.v1"
	SessionInspectionFormat = "cicada.owner-account-session-inspection.v1"
	LogoutFormat            = "cicada.owner-account-logout.v1"
	LogoutReceiptFormat     = "cicada.owner-account-logout-receipt.v1"

	PurposeInitialClaim   = "INITIAL_OWNER_ACCOUNT_CLAIM"
	PurposeAccountLogin   = "ACCOUNT_LOGIN"
	PurposeAccountSession = "OWNER_ACCOUNT_SESSION"

	OperationClaimPrepare   = "owner.account.claim.prepare"
	OperationClaimComplete  = "owner.account.claim.complete"
	OperationLoginPrepare   = "owner.account.login.prepare"
	OperationLoginComplete  = "owner.account.login.complete"
	OperationSessionInspect = "owner.account.session.inspect"
	OperationSessionLogout  = "owner.account.session.logout"

	ClaimPendingState    = "ACCOUNT_READY_OWNER_SIGNER_PENDING"
	RootPendingState     = "PENDING_PROOF"
	RootActiveState      = "ROOT_ACTIVE"
	RootUnavailableState = "ROOT_UNAVAILABLE"
	SessionActiveState   = "ACTIVE"
	SessionRevokedState  = "REVOKED"
	DeviceActiveState    = "ACTIVE"

	HandshakeEpoch        = uint64(1)
	PacketSequence        = uint64(1)
	DeviceKeyVersion      = uint64(1)
	AccountDeviceIDPrefix = "accountdev_"
	CodeBytes             = 32
	NonceBytes            = 32
	RequestIDBytes        = 16
	MaxPacketBytes        = 384 * 1024
	MaxInnerPacketBytes   = 256 * 1024
	MaxClaimCardBytes     = 16 * 1024
	MaxClaimBodyBytes     = 32 * 1024
	MaxBodyBytes          = 8 * 1024
	MaxUsernameBytes      = 128
	MaxPasswordBytes      = 1024
	MaxSessionTokenBytes  = 32
)

const (
	MaxClaimLifetime          = time.Hour
	MaxClaimChallengeLifetime = 10 * time.Minute
	MaxLoginChallengeLifetime = 2 * time.Minute
	MaxSessionLifetime        = 15 * time.Minute
	MaxSessionRequestLifetime = 60 * time.Second
	hubFingerprintDomain      = "cicada/owner-account/hub-identity/v1\x00"
)

var ErrInvalid = errors.New("invalid Hub account packet")

var rawURL = base64.RawURLEncoding

// HubIdentity is the existing public Client-Control Hub identity shape.
type HubIdentity = ownerbootstrap.HubIdentity

// ClaimCard is public installation metadata plus one 256-bit single-use code.
// It must be delivered through the operator's trusted local channel, not a URL.
type ClaimCard struct {
	Format            string `json:"format"`
	Version           int    `json:"version"`
	Purpose           string `json:"purpose"`
	Origin            string `json:"origin"`
	AllowLoopbackHTTP bool   `json:"allow_loopback_http"`
	HubID             string `json:"hub_id"`
	HubFingerprint    string `json:"hub_fingerprint"`
	AccountID         string `json:"account_id"`
	OwnerID           string `json:"owner_id"`
	ClaimID           string `json:"claim_id"`
	Code              string `json:"code"`
	IssuedAt          string `json:"issued_at"`
	ExpiresAt         string `json:"expires_at"`
}

// ClaimCardSummary contains only safe non-secret display fields.
type ClaimCardSummary struct {
	Origin         string `json:"origin"`
	HubID          string `json:"hub_id"`
	HubFingerprint string `json:"hub_fingerprint"`
	AccountID      string `json:"account_id"`
	OwnerID        string `json:"owner_id"`
	ExpiresAt      string `json:"expires_at"`
}

// Packet adds the sender's public identity so a first account device can be
// verified before its ciphertext is opened. The identity alone is never an
// authority; enrollment and current Store state remain authoritative.
type Packet struct {
	Format               string              `json:"format"`
	Version              int                 `json:"version"`
	SenderPublicIdentity e2ee.PublicIdentity `json:"sender_public_identity"`
	Packet               clientwire.Packet   `json:"packet"`
}

type ClaimPrepare struct {
	Format               string    `json:"format"`
	Purpose              string    `json:"purpose"`
	Claim                ClaimCard `json:"claim"`
	DeviceID             string    `json:"device_id"`
	DeviceKeyFingerprint string    `json:"device_key_fingerprint"`
	RequestID            string    `json:"request_id"`
	ClientNonce          []byte    `json:"client_nonce"`
	IssuedAt             string    `json:"issued_at"`
}

type ClaimChallenge struct {
	Format               string `json:"format"`
	Purpose              string `json:"purpose"`
	Origin               string `json:"origin"`
	HubID                string `json:"hub_id"`
	AccountID            string `json:"account_id"`
	OwnerID              string `json:"owner_id"`
	ClaimID              string `json:"claim_id"`
	AttemptID            string `json:"attempt_id"`
	DeviceID             string `json:"device_id"`
	DeviceKeyID          string `json:"device_key_id"`
	DeviceKeyFingerprint string `json:"device_key_fingerprint"`
	PrepareRequestID     string `json:"prepare_request_id"`
	ClientNonce          []byte `json:"client_nonce"`
	ServerNonce          []byte `json:"server_nonce"`
	AccountEpoch         uint64 `json:"account_epoch"`
	DeviceEpoch          uint64 `json:"device_epoch"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
}

type ClaimComplete struct {
	Format               string              `json:"format"`
	Purpose              string              `json:"purpose"`
	Origin               string              `json:"origin"`
	HubID                string              `json:"hub_id"`
	AccountID            string              `json:"account_id"`
	OwnerID              string              `json:"owner_id"`
	ClaimID              string              `json:"claim_id"`
	AttemptID            string              `json:"attempt_id"`
	DeviceID             string              `json:"device_id"`
	DeviceKeyID          string              `json:"device_key_id"`
	DeviceKeyFingerprint string              `json:"device_key_fingerprint"`
	PrepareRequestID     string              `json:"prepare_request_id"`
	PrepareClientNonce   []byte              `json:"prepare_client_nonce"`
	ServerNonce          []byte              `json:"server_nonce"`
	AccountEpoch         uint64              `json:"account_epoch"`
	DeviceEpoch          uint64              `json:"device_epoch"`
	ChallengeIssuedAt    string              `json:"challenge_issued_at"`
	ChallengeExpiresAt   string              `json:"challenge_expires_at"`
	RequestID            string              `json:"request_id"`
	ClientNonce          []byte              `json:"client_nonce"`
	Username             string              `json:"username"`
	Password             string              `json:"password"`
	OwnerPublicIdentity  e2ee.PublicIdentity `json:"owner_public_identity"`
	IssuedAt             string              `json:"issued_at"`
}

type ClaimReceipt struct {
	Format               string `json:"format"`
	Purpose              string `json:"purpose"`
	Origin               string `json:"origin"`
	HubID                string `json:"hub_id"`
	AccountID            string `json:"account_id"`
	OwnerID              string `json:"owner_id"`
	ClaimID              string `json:"claim_id"`
	AttemptID            string `json:"attempt_id"`
	RequestID            string `json:"request_id"`
	DeviceID             string `json:"device_id"`
	DeviceKeyID          string `json:"device_key_id"`
	DeviceKeyFingerprint string `json:"device_key_fingerprint"`
	AccountEpoch         uint64 `json:"account_epoch"`
	DeviceEpoch          uint64 `json:"device_epoch"`
	State                string `json:"state"`
	OwnerKeyID           string `json:"owner_key_id"`
	OwnerFingerprint     string `json:"owner_fingerprint"`
	RootState            string `json:"root_state"`
	RootActive           bool   `json:"root_active"`
	CompletedAt          string `json:"completed_at"`
}

type LoginPrepare struct {
	Format               string `json:"format"`
	Purpose              string `json:"purpose"`
	Origin               string `json:"origin"`
	HubID                string `json:"hub_id"`
	AccountID            string `json:"account_id"`
	OwnerID              string `json:"owner_id"`
	DeviceID             string `json:"device_id"`
	DeviceKeyID          string `json:"device_key_id"`
	DeviceKeyFingerprint string `json:"device_key_fingerprint"`
	Username             string `json:"username"`
	RequestID            string `json:"request_id"`
	ClientNonce          []byte `json:"client_nonce"`
	IssuedAt             string `json:"issued_at"`
}

type LoginChallenge struct {
	Format               string `json:"format"`
	Purpose              string `json:"purpose"`
	Origin               string `json:"origin"`
	HubID                string `json:"hub_id"`
	AccountID            string `json:"account_id"`
	OwnerID              string `json:"owner_id"`
	AttemptID            string `json:"attempt_id"`
	DeviceID             string `json:"device_id"`
	DeviceKeyID          string `json:"device_key_id"`
	DeviceKeyFingerprint string `json:"device_key_fingerprint"`
	Username             string `json:"username"`
	PrepareRequestID     string `json:"prepare_request_id"`
	ClientNonce          []byte `json:"client_nonce"`
	ServerNonce          []byte `json:"server_nonce"`
	AccountEpoch         uint64 `json:"account_epoch"`
	DeviceEpoch          uint64 `json:"device_epoch"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
}

type LoginComplete struct {
	Format               string `json:"format"`
	Purpose              string `json:"purpose"`
	Origin               string `json:"origin"`
	HubID                string `json:"hub_id"`
	AccountID            string `json:"account_id"`
	OwnerID              string `json:"owner_id"`
	AttemptID            string `json:"attempt_id"`
	DeviceID             string `json:"device_id"`
	DeviceKeyID          string `json:"device_key_id"`
	DeviceKeyFingerprint string `json:"device_key_fingerprint"`
	PrepareRequestID     string `json:"prepare_request_id"`
	PrepareClientNonce   []byte `json:"prepare_client_nonce"`
	ServerNonce          []byte `json:"server_nonce"`
	AccountEpoch         uint64 `json:"account_epoch"`
	DeviceEpoch          uint64 `json:"device_epoch"`
	ChallengeIssuedAt    string `json:"challenge_issued_at"`
	ChallengeExpiresAt   string `json:"challenge_expires_at"`
	RequestID            string `json:"request_id"`
	ClientNonce          []byte `json:"client_nonce"`
	Username             string `json:"username"`
	Password             string `json:"password"`
	IssuedAt             string `json:"issued_at"`
}

type SessionReceipt struct {
	Format               string `json:"format"`
	Purpose              string `json:"purpose"`
	Origin               string `json:"origin"`
	HubID                string `json:"hub_id"`
	AccountID            string `json:"account_id"`
	OwnerID              string `json:"owner_id"`
	DeviceID             string `json:"device_id"`
	DeviceKeyID          string `json:"device_key_id"`
	DeviceKeyFingerprint string `json:"device_key_fingerprint"`
	SessionToken         []byte `json:"session_token"`
	AccountEpoch         uint64 `json:"account_epoch"`
	DeviceEpoch          uint64 `json:"device_epoch"`
	RequestID            string `json:"request_id"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
}

// SessionContext is an in-memory continuation of an authenticated account
// session. Its token must not be persisted or used as Client management auth.
type SessionContext struct {
	Origin               string
	HubID                string
	AccountID            string
	OwnerID              string
	DeviceID             string
	DeviceKeyID          string
	DeviceKeyFingerprint string
	SessionToken         []byte
	AccountEpoch         uint64
	DeviceEpoch          uint64
	ExpiresAt            string
}

func (r SessionReceipt) Context() SessionContext {
	return SessionContext{Origin: r.Origin, HubID: r.HubID, AccountID: r.AccountID, OwnerID: r.OwnerID,
		DeviceID: r.DeviceID, DeviceKeyID: r.DeviceKeyID, DeviceKeyFingerprint: r.DeviceKeyFingerprint,
		SessionToken: append([]byte(nil), r.SessionToken...), AccountEpoch: r.AccountEpoch,
		DeviceEpoch: r.DeviceEpoch, ExpiresAt: r.ExpiresAt}
}

type SessionInspectRequest struct {
	Format               string `json:"format"`
	Purpose              string `json:"purpose"`
	Origin               string `json:"origin"`
	HubID                string `json:"hub_id"`
	AccountID            string `json:"account_id"`
	OwnerID              string `json:"owner_id"`
	DeviceID             string `json:"device_id"`
	DeviceKeyID          string `json:"device_key_id"`
	DeviceKeyFingerprint string `json:"device_key_fingerprint"`
	SessionToken         []byte `json:"session_token"`
	AccountEpoch         uint64 `json:"account_epoch"`
	DeviceEpoch          uint64 `json:"device_epoch"`
	RequestID            string `json:"request_id"`
	ClientNonce          []byte `json:"client_nonce"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
}

type SessionInspection struct {
	Format           string               `json:"format"`
	Purpose          string               `json:"purpose"`
	Origin           string               `json:"origin"`
	HubID            string               `json:"hub_id"`
	AccountID        string               `json:"account_id"`
	OwnerID          string               `json:"owner_id"`
	Username         string               `json:"username"`
	ActorDeviceID    string               `json:"actor_device_id"`
	ActorDeviceEpoch uint64               `json:"actor_device_epoch"`
	RequestID        string               `json:"request_id"`
	State            string               `json:"state"`
	RootState        string               `json:"root_state"`
	RootActive       bool                 `json:"root_active"`
	OwnerKeyID       string               `json:"owner_key_id"`
	OwnerFingerprint string               `json:"owner_fingerprint"`
	Devices          []LoginDeviceSummary `json:"devices"`
	InspectedAt      string               `json:"inspected_at"`
}

type LoginDeviceSummary struct {
	DeviceID             string `json:"device_id"`
	DeviceKeyID          string `json:"device_key_id"`
	DeviceKeyFingerprint string `json:"device_key_fingerprint"`
	State                string `json:"state"`
	DeviceEpoch          uint64 `json:"device_epoch"`
	CreatedAt            string `json:"created_at"`
	LastSeenAt           string `json:"last_seen_at"`
}

type LogoutRequest struct {
	Format               string `json:"format"`
	Purpose              string `json:"purpose"`
	Origin               string `json:"origin"`
	HubID                string `json:"hub_id"`
	AccountID            string `json:"account_id"`
	OwnerID              string `json:"owner_id"`
	DeviceID             string `json:"device_id"`
	DeviceKeyID          string `json:"device_key_id"`
	DeviceKeyFingerprint string `json:"device_key_fingerprint"`
	SessionToken         []byte `json:"session_token"`
	AccountEpoch         uint64 `json:"account_epoch"`
	DeviceEpoch          uint64 `json:"device_epoch"`
	RequestID            string `json:"request_id"`
	ClientNonce          []byte `json:"client_nonce"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
}

type LogoutReceipt struct {
	Format       string `json:"format"`
	Purpose      string `json:"purpose"`
	Origin       string `json:"origin"`
	HubID        string `json:"hub_id"`
	AccountID    string `json:"account_id"`
	OwnerID      string `json:"owner_id"`
	DeviceID     string `json:"device_id"`
	AccountEpoch uint64 `json:"account_epoch"`
	DeviceEpoch  uint64 `json:"device_epoch"`
	RequestID    string `json:"request_id"`
	State        string `json:"state"`
	LoggedOutAt  string `json:"logged_out_at"`
}
