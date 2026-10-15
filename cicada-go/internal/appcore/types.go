// Package appcore coordinates the native CICADA App's authenticated Hub
// connection, encrypted account protocol and local vault state. It does not
// create Manager grants or turn account login into Root activation.
package appcore

import (
	"context"
	"fmt"
)

// Controller is the narrow boundary consumed by native renderers. Implementors
// own transport, account protocol, vault access and state transitions; views
// receive only a sanitized Snapshot and dispatch closed Action values.
type Controller interface {
	Snapshot() Snapshot
	Dispatch(context.Context, Action) error
	Close() error
}

type Phase string

const (
	PhaseNeedConnection Phase = "NEED_CONNECTION"
	PhaseVerifyingHub   Phase = "VERIFYING_HUB"
	PhaseConnected      Phase = "CONNECTED"
	PhaseLocked         Phase = "LOCKED"
	PhaseClaimChallenge Phase = "CLAIM_CHALLENGE_PENDING"
	PhaseLoginChallenge Phase = "LOGIN_CHALLENGE_PENDING"
	PhaseAccountPending Phase = "ACCOUNT_READY_OWNER_SIGNER_PENDING"
	PhaseSessionCheck   Phase = "SESSION_RECHECK_REQUIRED"
	PhaseAccountSession Phase = "ACCOUNT_SESSION_PENDING_OWNER_PROOF"
	PhaseOwnerReady     Phase = "OWNER_READY"
	PhaseUnavailable    Phase = "UNAVAILABLE"
	PhaseError          Phase = "ERROR"
)

type HubHealth string

const (
	HubHealthUnknown   HubHealth = "UNKNOWN"
	HubHealthHealthy   HubHealth = "HEALTHY"
	HubHealthUnhealthy HubHealth = "UNHEALTHY"
)

type AccountState string

const (
	AccountStateUnknown       AccountState = "UNKNOWN"
	AccountStateClaimPending  AccountState = "CLAIM_PENDING"
	AccountStateLoginRequired AccountState = "LOGIN_REQUIRED"
	AccountStateSessionCheck  AccountState = "SESSION_RECHECK_REQUIRED"
	AccountStateSessionActive AccountState = "SESSION_ACTIVE"
	AccountStateOwnerProof    AccountState = "OWNER_PROOF_PENDING"
	AccountStateOwnerReady    AccountState = "OWNER_READY"
)

type RootState string

const (
	RootStateUnknown     RootState = "UNKNOWN"
	RootStateUnavailable RootState = "ROOT_UNAVAILABLE"
	RootStatePending     RootState = "PENDING_PROOF"
	RootStateActive      RootState = "ROOT_ACTIVE"
)

type ManagementState string

const (
	ManagementUnavailable ManagementState = "UNAVAILABLE"
	ManagementUnverified  ManagementState = "UNVERIFIED"
	ManagementAuthorized  ManagementState = "AUTHORIZED"
)

type HubSnapshot struct {
	Verified    bool      `json:"verified"`
	Origin      string    `json:"origin,omitempty"`
	HubID       string    `json:"hub_id,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Health      HubHealth `json:"health"`
	Service     string    `json:"service,omitempty"`
}

type AccountSnapshot struct {
	State                AccountState `json:"state"`
	AccountID            string       `json:"account_id,omitempty"`
	OwnerID              string       `json:"owner_id,omitempty"`
	Username             string       `json:"username,omitempty"`
	DeviceID             string       `json:"device_id,omitempty"`
	RootState            RootState    `json:"root_state"`
	OwnerFingerprint     string       `json:"owner_fingerprint,omitempty"`
	LocalOwnerKeyPresent bool         `json:"local_owner_key_present"`
}

type CanvasState string

const (
	CanvasUnavailable     CanvasState = "UNAVAILABLE"
	CanvasNoAuthorization CanvasState = "NO_AUTHORIZED_READ_PATH"
	CanvasEmpty           CanvasState = "EMPTY"
	CanvasAvailable       CanvasState = "AVAILABLE"
)

// CanvasObject contains only server-provided, authorized object metadata.
// N1 has no authorized canvas read operation, so Snapshots keep Objects nil.
type CanvasObject struct {
	ID     string  `json:"id"`
	Type   string  `json:"type"`
	Label  string  `json:"label"`
	X      float32 `json:"x"`
	Y      float32 `json:"y"`
	Width  float32 `json:"width"`
	Height float32 `json:"height"`
}

type CanvasSnapshot struct {
	State   CanvasState    `json:"state"`
	Objects []CanvasObject `json:"objects,omitempty"`
}

// Snapshot contains display-safe state only. It never includes passwords,
// activation codes, private keys, pending ciphertext, session tokens or proofs.
type Snapshot struct {
	Phase            Phase             `json:"phase"`
	Hub              HubSnapshot       `json:"hub"`
	Account          AccountSnapshot   `json:"account"`
	Management       ManagementState   `json:"management"`
	Canvas           CanvasSnapshot    `json:"canvas"`
	AvailableActions []ActionKind      `json:"available_actions"`
	ErrorCode        string            `json:"error_code,omitempty"`
	Profiles         []ProfileSnapshot `json:"profiles,omitempty"`
}

// ProfileSnapshot is authenticated local metadata, never evidence of current
// Hub availability, an account session, or management authorization.
type ProfileSnapshot struct {
	ID        string `json:"id"`
	Origin    string `json:"origin"`
	AccountID string `json:"account_id"`
	OwnerID   string `json:"owner_id"`
}

type ActionKind string

const (
	ActionConnect           ActionKind = "CONNECT"
	ActionDiscoverProfiles  ActionKind = "DISCOVER_LOCAL_PROFILES"
	ActionResumeProfile     ActionKind = "UNLOCK_AND_RESUME_PROFILE"
	ActionGenerateOwner     ActionKind = "GENERATE_OWNER_IDENTITY"
	ActionImportOwner       ActionKind = "IMPORT_OWNER_IDENTITY"
	ActionClaimPrepare      ActionKind = "CLAIM_PREPARE"
	ActionClaimComplete     ActionKind = "CLAIM_COMPLETE"
	ActionLoginPrepare      ActionKind = "LOGIN_PREPARE"
	ActionLoginComplete     ActionKind = "LOGIN_COMPLETE"
	ActionSessionInspect    ActionKind = "SESSION_INSPECT"
	ActionLogout            ActionKind = "LOGOUT"
	ActionRetry             ActionKind = "RECOVER_EXACT_PENDING_REQUEST"
	ActionSelectCanvas      ActionKind = "SELECT_CANVAS_OBJECT"
	ActionSetCanvasViewport ActionKind = "SET_CANVAS_VIEWPORT"
)

// Action carries one closed native interaction. Secret-bearing fields are
// deliberately omitted from its String/GoString representations.
type Action struct {
	Kind ActionKind

	// Exactly one connection material field may be set for ActionConnect.
	ConnectionCard string
	ActivationCode string
	ProfileID      string

	Username    string
	Password    string
	OwnerImport *OwnerImport

	CanvasObjectID string
	ViewportX      float32
	ViewportY      float32
	ViewportScale  float32
}

// OwnerImport wraps the existing full Owner identity import. The four PEM
// values are in-memory inputs only and never belong in a Snapshot or log.
type OwnerImport struct {
	KEMPrivatePKCS8     []byte
	SigningPrivatePKCS8 []byte
	KEMPublicSPKI       []byte
	SigningPublicSPKI   []byte
}

func (a Action) String() string   { return fmt.Sprintf("Action(%s)", a.Kind) }
func (a Action) GoString() string { return a.String() }
