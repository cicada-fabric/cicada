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
	PhaseNeedConnection    Phase = "NEED_CONNECTION"
	PhaseVerifyingHub      Phase = "VERIFYING_HUB"
	PhaseConnected         Phase = "CONNECTED"
	PhaseLocked            Phase = "LOCKED"
	PhaseClaimChallenge    Phase = "CLAIM_CHALLENGE_PENDING"
	PhaseLoginChallenge    Phase = "LOGIN_CHALLENGE_PENDING"
	PhaseAccountPending    Phase = "ACCOUNT_READY_OWNER_SIGNER_PENDING"
	PhaseSessionCheck      Phase = "SESSION_RECHECK_REQUIRED"
	PhaseAccountSession    Phase = "ACCOUNT_SESSION_PENDING_OWNER_PROOF"
	PhaseOwnerReady        Phase = "OWNER_READY"
	PhaseActivationPending Phase = "ACTIVATION_PENDING"
	PhaseUnavailable       Phase = "UNAVAILABLE"
	PhaseError             Phase = "ERROR"
)

type HubHealth string

const (
	HubHealthUnknown   HubHealth = "UNKNOWN"
	HubHealthHealthy   HubHealth = "HEALTHY"
	HubHealthUnhealthy HubHealth = "UNHEALTHY"
)

type HubTransportState string

const (
	HubTransportUnknown   HubTransportState = "UNKNOWN"
	HubTransportVerifying HubTransportState = "VERIFYING"
	HubTransportVerified  HubTransportState = "VERIFIED"
	HubTransportFailed    HubTransportState = "FAILED"
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
	Verified bool `json:"verified"`
	// Address is the selected physical dial target, independent of Origin.
	Address        string            `json:"address,omitempty"`
	TransportState HubTransportState `json:"transport_state,omitempty"`
	Origin         string            `json:"origin,omitempty"`
	HubID          string            `json:"hub_id,omitempty"`
	Fingerprint    string            `json:"fingerprint,omitempty"`
	Health         HubHealth         `json:"health"`
	Service        string            `json:"service,omitempty"`
}

type AccountSnapshot struct {
	DeviceEnrolled       bool         `json:"device_enrolled"`
	State                AccountState `json:"state"`
	AccountID            string       `json:"account_id,omitempty"`
	OwnerID              string       `json:"owner_id,omitempty"`
	Username             string       `json:"username,omitempty"`
	DeviceID             string       `json:"device_id,omitempty"`
	RootState            RootState    `json:"root_state"`
	OwnerFingerprint     string       `json:"owner_fingerprint,omitempty"`
	LocalOwnerKeyID      string       `json:"local_owner_key_id,omitempty"`
	OwnerPeerFingerprint string       `json:"owner_peer_fingerprint,omitempty"`
	LocalOwnerKeyPresent bool         `json:"local_owner_key_present"`
	SessionExpiresAt     string       `json:"session_expires_at,omitempty"`
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
	Phase            Phase                 `json:"phase"`
	Hub              HubSnapshot           `json:"hub"`
	Account          AccountSnapshot       `json:"account"`
	Management       ManagementState       `json:"management"`
	Canvas           CanvasSnapshot        `json:"canvas"`
	AvailableActions []ActionKind          `json:"available_actions"`
	ErrorCode        string                `json:"error_code,omitempty"`
	Profiles         []ProfileSnapshot     `json:"profiles,omitempty"`
	Setup            SetupSnapshot         `json:"setup"`
	Authorization    AuthorizationSnapshot `json:"authorization"`
	Node             NodeSetupSnapshot     `json:"node"`
	Pair             PairSetupSnapshot     `json:"pair"`
	Storage          StorageSnapshot       `json:"storage"`
	OwnerEndpoints   OwnerEndpointSnapshot `json:"owner_endpoints"`
	ThreadGroups     ThreadGroupsSnapshot  `json:"thread_groups"`

	LocalCollaboration LocalCollaborationSnapshot `json:"local_collaboration"`
}

// StorageSnapshot describes local file locations only. It is not Hub state or
// authorization, and renderers hide it until the account display is trusted.
type StorageSnapshot struct {
	UserRoot  string `json:"user_root,omitempty"`
	VaultRoot string `json:"vault_root,omitempty"`
	Legacy    bool   `json:"legacy"`
}

type SetupSnapshot struct {
	Purpose               string `json:"purpose,omitempty"`
	OwnerKeyStored        bool   `json:"owner_key_stored"`
	ExpectedOwnerKeyID    string `json:"expected_owner_key_id,omitempty"`
	NeedsCredentials      bool   `json:"needs_credentials"`
	ActivationPending     bool   `json:"activation_pending"`
	AuthorizationDeadline string `json:"authorization_deadline,omitempty"`
	ReplacementAllowed    bool   `json:"replacement_allowed"`
}

type AuthorizationSnapshot struct {
	State             string   `json:"state"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	AllowedOperations []string `json:"allowed_operations,omitempty"`
	Confirmed         bool     `json:"confirmed"`
}

// ProfileSnapshot is authenticated local metadata, never evidence of current
// Hub availability, an account session, or management authorization.
type ProfileSnapshot struct {
	ID        string `json:"id"`
	Origin    string `json:"origin"`
	AccountID string `json:"account_id"`
	OwnerID   string `json:"owner_id"`
	Direct    bool   `json:"direct,omitempty"`
}

type ActionKind string

const (
	ActionConnect               ActionKind = "CONNECT"
	ActionDiscoverProfiles      ActionKind = "DISCOVER_LOCAL_PROFILES"
	ActionResumeProfile         ActionKind = "UNLOCK_AND_RESUME_PROFILE"
	ActionActivateApp           ActionKind = "ACTIVATE_APP"
	ActionLogin                 ActionKind = "LOGIN"
	ActionRecover               ActionKind = "RECOVER_SAVED_OPERATION"
	ActionActivationStatus      ActionKind = "REFRESH_FINITE_AUTHORIZATION"
	ActionRefresh               ActionKind = "REFRESH_ACCOUNT_AND_AUTHORIZATION"
	ActionPreviewNode           ActionKind = "REVIEW_NODE_CONNECTION"
	ActionApproveNode           ActionKind = "APPROVE_EXACT_NODE_CONNECTION"
	ActionRefreshNode           ActionKind = "REFRESH_NODE_CONNECTION"
	ActionRecoverNode           ActionKind = "RECOVER_NODE_CONNECTION"
	ActionCancelNodeAccess      ActionKind = "END_APP_NODE_ACCESS"
	ActionReauthorizeNodeStatus ActionKind = "REAUTHORIZE_EXACT_NODE_STATUS"
	ActionSetupAccount          ActionKind = "SET_UP_ACCOUNT"
	ActionGenerateOwner         ActionKind = "GENERATE_OWNER_IDENTITY"
	ActionImportOwner           ActionKind = "IMPORT_OWNER_IDENTITY"
	ActionExportOwnerPublic     ActionKind = "EXPORT_OWNER_PUBLIC"
	ActionClaimPrepare          ActionKind = "CLAIM_PREPARE"
	ActionClaimComplete         ActionKind = "CLAIM_COMPLETE"
	ActionLoginPrepare          ActionKind = "LOGIN_PREPARE"
	ActionLoginComplete         ActionKind = "LOGIN_COMPLETE"
	ActionSessionInspect        ActionKind = "SESSION_INSPECT"
	ActionLogout                ActionKind = "LOGOUT"
	ActionRetry                 ActionKind = "RECOVER_EXACT_PENDING_REQUEST"
	ActionSelectCanvas          ActionKind = "SELECT_CANVAS_OBJECT"
	ActionSetCanvasViewport     ActionKind = "SET_CANVAS_VIEWPORT"
)

// Action carries one closed native interaction. Secret-bearing fields are
// deliberately omitted from its String/GoString representations.
type Action struct {
	Kind           ActionKind
	Pair           PairAction
	OwnerEndpoints OwnerEndpointReadAction
	ThreadGroups   ThreadGroupAction

	LocalCollaboration LocalCollaborationAction

	// ActionConnect accepts exactly one legacy material, or the direct pair below.
	ConnectionCard string
	ActivationCode string
	// Direct connections supply a physical IP:port and a secret bootstrap code.
	// They never replace the logical Origin in an existing profile or request.
	HubAddress    string
	BootstrapCode string
	// ActionResumeProfile may supply HubAddress alone to retry the saved
	// direct profile at a new address without changing its authenticated scope.
	ProfileID string
	// A native confirmation must name the exact finite scope shown to the user.
	ConfirmLimitedAuthorization bool
	// Node approval names the exact authenticated candidate displayed to the
	// user. The controller rechecks it; a UI checkbox never grants authority.
	NodeCode            string
	DevicePairingCode   string
	NodePairingReviewID string
	ConfirmNodePairing  bool
	NodeReviewID        string
	ConfirmNodeIdentity bool
	ConfirmNodeAccess   bool
	// AutoNodeStatus limits a background read to this exact current target.
	// Nil preserves the existing explicitly requested refresh/recovery flow.
	AutoNodeStatus *NodeStatusTarget

	Username         string
	Password         string
	OwnerImport      *OwnerImport
	PublicExportPath string

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
