package hubaccountwire

import "context"

// Additive draft contract. These DTOs/interfaces do not install handlers or
// activate either profile. Existing operation inventories remain unchanged.
const (
	ThreadCollaborationContractRevision            = "thread-network-group-locks-v1"
	ThreadCollaborationPhase                       = "CONTRACT_ONLY"
	ThreadCollaborationOwnerResultFormat           = "cicada.owner-thread-collaboration-result.v1"
	ThreadCollaborationCapabilitiesFormat          = "cicada.thread-collaboration-capabilities.v1"
	ThreadCollaborationCapabilitiesPath            = "/v2/thread-collaboration/capabilities"
	ThreadCollaborationOwnerFormat                 = "cicada.owner-thread-collaboration.v1"
	ThreadScopeFormat                              = "cicada.thread-scope.v1"
	GroupCoordinationPolicyFormat                  = "cicada.group-coordination-policy.v1"
	GroupSlotViewFormat                            = "cicada.group-slots.v1"
	GroupLockReceiptFormat                         = "cicada.group-lock-receipt.v1"
	ThreadClassificationWorker                     = "worker"
	ThreadClassificationAdvisor                    = "advisor"
	ThreadClassificationManager                    = "manager"
	GroupLockSlotCount                             = 8
	GroupLockDefaultTTLSeconds                     = 300
	GroupLockMinTTLSeconds                         = 1
	GroupLockMaxTTLSeconds                         = 3600
	GroupLockOriginalRecoverySeconds               = 24 * 60 * 60
	MaxGroupLockNoteBytes                          = 1024
	MaxThreadCollaborationNodeBodyBytes            = 8 << 10
	MaxThreadCollaborationViewBytes                = 32 << 10
	MaxThreadCollaborationPageRows                 = 64
	MaxThreadCollaborationPageBytes                = 128 << 10
	MaxThreadCollaborationOwnerBodyBytes           = MaxOwnerEndpointGroupsBodyBytes
	MaxThreadCollaborationOwnerPacketBytes         = MaxOwnerEndpointGroupsPacketBytes
	MaxThreadCollaborationOriginalBytes            = MaxOwnerEndpointGroupsOriginalBytes
	MaxThreadCollaborationReconcileBodyBytes       = MaxOwnerEndpointGroupsReconcileBodyBytes
	MaxThreadCollaborationReconcilePacketBytes     = MaxOwnerEndpointGroupsReconcilePacketBytes
	OperationThreadCollaborationOwnerRead          = "owner.thread_collaboration.read"
	OperationThreadCollaborationOwnerPrepare       = "owner.thread_collaboration.prepare"
	OperationThreadCollaborationOwnerApply         = "owner.thread_collaboration.apply"
	OperationThreadCollaborationOwnerStatus        = "owner.thread_collaboration.status"
	OperationThreadCollaborationOwnerReconcile     = "owner.thread_collaboration.reconcile"
	OperationThreadScopeRead                       = "thread_scope.read"
	OperationGroupLocksRead                        = "group_locks.read"
	OperationGroupLocksAcquire                     = "group_locks.acquire"
	OperationGroupLocksRenew                       = "group_locks.renew"
	OperationGroupLocksRelease                     = "group_locks.release"
	ThreadCollaborationSetClassification           = "SET_CLASSIFICATION"
	ThreadCollaborationCreateGroupWithPolicy       = "CREATE_GROUP_WITH_POLICY"
	ThreadCollaborationEnableGroupPolicy           = "ENABLE_GROUP_POLICY"
	ThreadCollaborationRevokeGroupPolicy           = "REVOKE_GROUP_POLICY"
	ThreadCollaborationClearOneSlot                = "CLEAR_ONE_SLOT"
	GroupLockDisconnectPolicyFiniteLease           = "FINITE_LEASE"
	ThreadCollaborationProfileScopeRole            = "THREAD_SCOPE_ROLE_V1"
	ThreadCollaborationProfileGroupLocks           = "GROUP_LOCKS_V1"
	ThreadCollaborationErrorUnsupported            = "UNSUPPORTED_PROFILE"
	ThreadCollaborationErrorAuthorizationRequired  = "AUTHORIZATION_REQUIRED"
	ThreadCollaborationErrorSlotInvalid            = "SLOT_INVALID"
	ThreadCollaborationErrorNetworkConflict        = "THREAD_NETWORK_CONFLICT"
	ThreadCollaborationErrorNetworkUnresolved      = "THREAD_NETWORK_UNRESOLVED"
	ThreadCollaborationErrorClassificationRequired = "THREAD_CLASSIFICATION_REQUIRED"
	ThreadCollaborationErrorWorkerGroupLimit       = "WORKER_GROUP_LIMIT"
	ThreadCollaborationErrorPolicyRequired         = "GROUP_LOCK_POLICY_REQUIRED"
	ThreadCollaborationErrorSlotBusy               = "SLOT_BUSY"
	ThreadCollaborationErrorVersionConflict        = "VERSION_CONFLICT"
	ThreadCollaborationErrorHolderMismatch         = "HOLDER_MISMATCH"
	ThreadCollaborationErrorGenerationStale        = "GENERATION_STALE"
	ThreadCollaborationErrorLeaseExpired           = "LEASE_EXPIRED"
	ThreadCollaborationErrorOriginalConflict       = "ORIGINAL_REQUEST_CONFLICT"
	ThreadCollaborationErrorOriginalUncertain      = "ORIGINAL_OUTCOME_UNCERTAIN"
	ThreadCollaborationErrorAtLimit                = "STATE_AT_LIMIT"
	ThreadCollaborationErrorReceiptUnavailable     = "ORIGINAL_RECEIPT_UNAVAILABLE"
	ThreadCollaborationOutcomeApplied              = "APPLIED"
	ThreadCollaborationOutcomeRejectedFenced       = "REJECTED_FENCED"
	ThreadCollaborationOutcomeUnknown              = "UNKNOWN"
)

// Carried only inside the authenticated Node response envelope. Transport or
// current authorization denial alone is never an original no-effect receipt.
type ThreadCollaborationNodeEvidence struct {
	Operation           string                      `json:"operation"`
	Original            ThreadCollaborationOriginal `json:"original"`
	RequestPacketDigest string                      `json:"request_packet_digest"`
	Outcome             string                      `json:"outcome"`
	ErrorCode           string                      `json:"error_code,omitempty"`
}

type ThreadCollaborationCapabilities struct {
	Format                   string `json:"format"`
	ContractRevision         string `json:"contract_revision"`
	HubID                    string `json:"hub_id"`
	HubFingerprint           string `json:"hub_fingerprint"`
	ServeMode                string `json:"serve_mode"`
	ThreadScopeRoleAvailable bool   `json:"thread_scope_role_available"`
	GroupLocksAvailable      bool   `json:"group_locks_available"`
	DisconnectPolicy         string `json:"disconnect_policy"`
	SlotCount                uint8  `json:"slot_count"`
	DefaultTTLSeconds        uint32 `json:"default_ttl_seconds"`
	MinTTLSeconds            uint32 `json:"min_ttl_seconds"`
	MaxTTLSeconds            uint32 `json:"max_ttl_seconds"`
}

// This is Hub/Network scoped, never a global native Thread identifier.
// Cold recovery preserves both fields. Another Thread taking an Endpoint must
// have a different registration/source epoch even if Principal is unchanged.
type ThreadRegistrationSource struct {
	RegistrationID string `json:"registration_id"`
	SourceEpoch    uint64 `json:"source_epoch"`
}

type ThreadScopeView struct {
	Format                 string                   `json:"format"`
	HubID                  string                   `json:"hub_id"`
	NetworkID              string                   `json:"network_id"`
	NodeID                 string                   `json:"node_id"`
	EndpointID             string                   `json:"endpoint_id"`
	Source                 ThreadRegistrationSource `json:"source"`
	ScopeRevision          uint64                   `json:"scope_revision"`
	State                  string                   `json:"state"`
	Classification         string                   `json:"classification"`
	ClassificationRevision uint64                   `json:"classification_revision"`
	RelationsRevision      uint64                   `json:"relations_revision"`
	ActiveGroupIDs         []string                 `json:"active_group_ids"`
	ActiveGroupCount       uint64                   `json:"active_group_count"`
	GroupsCursor           string                   `json:"groups_cursor,omitempty"`
	HistoryCoverage        string                   `json:"history_coverage"`
	ReservationID          string                   `json:"reservation_id,omitempty"`
	Conflict               *ThreadNetworkConflict   `json:"conflict,omitempty"`
	RegistrationDigest     string                   `json:"registration_digest,omitempty"`
}

// No chosen Hub/Network or foreign scope identifiers are needed to report a
// conflict. Counts are history observations, not a selectable winning scope.
type ThreadNetworkConflict struct {
	Kind              string `json:"kind"`
	KnownNetworkCount uint64 `json:"known_network_count"`
}

type GroupCoordinationPolicy struct {
	Format             string   `json:"format"`
	HubID              string   `json:"hub_id"`
	NetworkID          string   `json:"network_id"`
	GroupID            string   `json:"group_id"`
	PolicyID           string   `json:"policy_id"`
	Revision           uint64   `json:"revision"`
	State              string   `json:"state"`
	SlotCount          uint8    `json:"slot_count"`
	Rights             []string `json:"rights"`
	OwnerConsentDigest string   `json:"owner_consent_digest"`
}

type GroupLockScope struct {
	HubID     string `json:"hub_id"`
	NetworkID string `json:"network_id"`
	GroupID   string `json:"group_id"`
}

type GroupLockHolder struct {
	NodeID      string                   `json:"node_id"`
	EndpointID  string                   `json:"endpoint_id"`
	PrincipalID string                   `json:"principal_id"`
	Source      ThreadRegistrationSource `json:"source"`
}

type GroupLockSlot struct {
	Slot            uint8            `json:"slot"`
	State           string           `json:"state"`
	Version         uint64           `json:"version"`
	Generation      uint64           `json:"generation"`
	Holder          *GroupLockHolder `json:"holder,omitempty"`
	HolderName      string           `json:"holder_name,omitempty"`
	HolderNameState string           `json:"holder_name_state,omitempty"`
	Note            string           `json:"note,omitempty"`
	ExpiresAt       string           `json:"expires_at,omitempty"`
}

type GroupSlotView struct {
	Format         string          `json:"format"`
	Scope          GroupLockScope  `json:"scope"`
	ObservedAt     string          `json:"observed_at"`
	PolicyRevision uint64          `json:"policy_revision"`
	PolicyState    string          `json:"policy_state"`
	Slots          []GroupLockSlot `json:"slots"`
}

type ThreadCollaborationOriginal struct {
	OperationID    string `json:"operation_id"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestDigest  string `json:"request_digest"`
}

type GroupLockAcquireRequest struct {
	Scope           GroupLockScope              `json:"scope"`
	Slot            uint8                       `json:"slot"`
	ExpectedVersion uint64                      `json:"expected_version"`
	Original        ThreadCollaborationOriginal `json:"original"`
	Note            string                      `json:"note,omitempty"`
	// nil means omitted/default; an explicit zero is invalid, never default.
	TTLSeconds *uint32 `json:"ttl_seconds,omitempty"`
}

type GroupLockRenewRequest struct {
	Scope           GroupLockScope              `json:"scope"`
	Slot            uint8                       `json:"slot"`
	ExpectedVersion uint64                      `json:"expected_version"`
	Generation      uint64                      `json:"generation"`
	Original        ThreadCollaborationOriginal `json:"original"`
	TTLSeconds      *uint32                     `json:"ttl_seconds,omitempty"`
}

type GroupLockReleaseRequest struct {
	Scope           GroupLockScope              `json:"scope"`
	Slot            uint8                       `json:"slot"`
	ExpectedVersion uint64                      `json:"expected_version"`
	Generation      uint64                      `json:"generation"`
	Original        ThreadCollaborationOriginal `json:"original"`
}

type GroupLockReceipt struct {
	Format         string         `json:"format"`
	Scope          GroupLockScope `json:"scope"`
	OperationID    string         `json:"operation_id"`
	RequestDigest  string         `json:"request_digest"`
	Slot           uint8          `json:"slot"`
	AppliedVersion uint64         `json:"applied_version"`
	Generation     uint64         `json:"generation"`
	Outcome        string         `json:"outcome"`
	ObservedAt     string         `json:"observed_at"`
	ExpiresAt      string         `json:"expires_at,omitempty"`
}

// Owner read/list is independent of Node Host/native-session proof. Its outer
// authenticated Owner/device context still authorizes every returned scope.
type ThreadCollaborationOwnerReadBody struct {
	View       string `json:"view"`
	NetworkID  string `json:"network_id"`
	NodeID     string `json:"node_id,omitempty"`
	EndpointID string `json:"endpoint_id,omitempty"`
	GroupID    string `json:"group_id,omitempty"`
	Cursor     string `json:"cursor,omitempty"`
	Limit      uint16 `json:"limit,omitempty"`
}

type ThreadRoleChange struct {
	NetworkID                      string                   `json:"network_id"`
	NodeID                         string                   `json:"node_id"`
	EndpointID                     string                   `json:"endpoint_id"`
	Source                         ThreadRegistrationSource `json:"source"`
	Classification                 string                   `json:"classification"`
	ExpectedClassificationRevision uint64                   `json:"expected_classification_revision"`
	ExpectedRelationsRevision      uint64                   `json:"expected_relations_revision"`
	RegistrationDigest             string                   `json:"registration_digest"`
}

type GroupPolicyChange struct {
	NetworkID              string   `json:"network_id"`
	GroupID                string   `json:"group_id,omitempty"`
	Name                   string   `json:"name,omitempty"`
	ExpectedGroupVersion   uint64   `json:"expected_group_version"`
	ExpectedPolicyRevision uint64   `json:"expected_policy_revision"`
	SlotCount              uint8    `json:"slot_count"`
	Rights                 []string `json:"rights"`
}

type GroupLockOwnerClear struct {
	Scope           GroupLockScope  `json:"scope"`
	Slot            uint8           `json:"slot"`
	ExpectedVersion uint64          `json:"expected_version"`
	Generation      uint64          `json:"generation"`
	ExpectedHolder  GroupLockHolder `json:"expected_holder"`
}

// Closed tagged union: exactly one payload, corresponding to Action.
type ThreadCollaborationOwnerPrepareBody struct {
	Action string               `json:"action"`
	Role   *ThreadRoleChange    `json:"role,omitempty"`
	Policy *GroupPolicyChange   `json:"policy,omitempty"`
	Clear  *GroupLockOwnerClear `json:"clear,omitempty"`
}

type ThreadCollaborationOwnerReview struct {
	TargetGroupID       string                              `json:"target_group_id,omitempty"`
	HubID               string                              `json:"hub_id"`
	OwnerID             string                              `json:"owner_id"`
	DeviceID            string                              `json:"device_id"`
	PrepareRequestID    string                              `json:"prepare_request_id"`
	PreparePacketDigest string                              `json:"prepare_packet_digest"`
	ObservedAt          string                              `json:"observed_at"`
	ReviewID            string                              `json:"review_id"`
	Action              string                              `json:"action"`
	BodyDigest          string                              `json:"body_digest"`
	ExpiresAt           string                              `json:"expires_at"`
	Prepared            ThreadCollaborationOwnerPrepareBody `json:"prepared"`
}

type ThreadCollaborationOwnerApplyBody struct {
	ReviewID     string `json:"review_id"`
	ReviewDigest string `json:"review_digest"`
}

type ThreadCollaborationOwnerStatusBody struct {
	OperationID          string `json:"operation_id"`
	OriginalPacketDigest string `json:"original_packet_digest"`
}

type ThreadCollaborationOwnerReconcileBody struct {
	OriginalPacket []byte `json:"original_packet"`
}

type ThreadCollaborationOwnerRequest[T any] struct {
	Format       string                `json:"format"`
	Context      AppNodeRequestContext `json:"context"`
	SessionToken []byte                `json:"session_token"`
	OwnerProof   []byte                `json:"owner_proof"`
	Body         T                     `json:"body"`
}

type ThreadCollaborationOwnerReadRequest = ThreadCollaborationOwnerRequest[ThreadCollaborationOwnerReadBody]
type ThreadCollaborationOwnerPrepareRequest = ThreadCollaborationOwnerRequest[ThreadCollaborationOwnerPrepareBody]
type ThreadCollaborationOwnerApplyRequest = ThreadCollaborationOwnerRequest[ThreadCollaborationOwnerApplyBody]
type ThreadCollaborationOwnerStatusRequest = ThreadCollaborationOwnerRequest[ThreadCollaborationOwnerStatusBody]
type ThreadCollaborationOwnerReconcileRequest = ThreadCollaborationOwnerRequest[ThreadCollaborationOwnerReconcileBody]

type ThreadCollaborationOwnerReadResult struct {
	HubID       string                        `json:"hub_id"`
	NetworkID   string                        `json:"network_id"`
	View        string                        `json:"view"`
	ObservedAt  string                        `json:"observed_at"`
	Threads     []ThreadScopeView             `json:"threads,omitempty"`
	GroupPolicy *GroupCoordinationPolicy      `json:"group_policy,omitempty"`
	GroupSlots  *GroupSlotView                `json:"group_slots,omitempty"`
	NextCursor  string                        `json:"next_cursor,omitempty"`
	Group       *ThreadCollaborationGroupCard `json:"group,omitempty"`
}

type ThreadCollaborationGroupCard struct {
	GroupID      string `json:"group_id"`
	NetworkID    string `json:"network_id"`
	Name         string `json:"name"`
	GroupVersion uint64 `json:"group_version"`
}

// Node-Control bodies; the Node sender and current registration/Host proof are
// authenticated outside these DTOs. EndpointID is checked, never self-authority.
type ThreadScopeNodeRead struct {
	EndpointID string `json:"endpoint_id"`
	NetworkID  string `json:"network_id"`
}
type GroupLocksNodeRead struct {
	EndpointID string         `json:"endpoint_id"`
	Scope      GroupLockScope `json:"scope"`
}
type GroupLocksNodeAcquire struct {
	EndpointID string                  `json:"endpoint_id"`
	Request    GroupLockAcquireRequest `json:"request"`
}
type GroupLocksNodeRenew struct {
	EndpointID string                `json:"endpoint_id"`
	Request    GroupLockRenewRequest `json:"request"`
}
type GroupLocksNodeRelease struct {
	EndpointID string                  `json:"endpoint_id"`
	Request    GroupLockReleaseRequest `json:"request"`
}

type ThreadCollaborationOwnerResult struct {
	Format               string                              `json:"format"`
	ContractRevision     string                              `json:"contract_revision"`
	RequestID            string                              `json:"request_id"`
	RequestPacketDigest  string                              `json:"request_packet_digest"`
	HubID                string                              `json:"hub_id"`
	OwnerID              string                              `json:"owner_id"`
	DeviceID             string                              `json:"device_id"`
	ObservedAt           string                              `json:"observed_at"`
	ErrorCode            string                              `json:"error_code,omitempty"`
	OperationID          string                              `json:"operation_id"`
	OriginalPacketDigest string                              `json:"original_packet_digest"`
	State                string                              `json:"state"`
	Review               *ThreadCollaborationOwnerReview     `json:"review,omitempty"`
	Thread               *ThreadScopeView                    `json:"thread,omitempty"`
	Policy               *GroupCoordinationPolicy            `json:"policy,omitempty"`
	Lock                 *GroupLockReceipt                   `json:"lock,omitempty"`
	Read                 *ThreadCollaborationOwnerReadResult `json:"read,omitempty"`
	ReceiptPacket        []byte                              `json:"receipt_packet,omitempty"`
}

// Implementations must use existing Owner authentication; Windows never needs
// a remote Node Host ticket to read/list/review or manage these Owner objects.
type ThreadCollaborationOwnerClient interface {
	Read(context.Context, ThreadCollaborationOwnerReadRequest) (ThreadCollaborationOwnerReadResult, error)
	Prepare(context.Context, ThreadCollaborationOwnerPrepareRequest) (ThreadCollaborationOwnerReview, error)
	Apply(context.Context, ThreadCollaborationOwnerApplyRequest) (ThreadCollaborationOwnerResult, error)
	Status(context.Context, ThreadCollaborationOwnerStatusRequest) (ThreadCollaborationOwnerResult, error)
	Reconcile(context.Context, ThreadCollaborationOwnerReconcileRequest) (ThreadCollaborationOwnerResult, error)
}

// This interface is consumed only inside the verified native CLI/MCP child.
// Authentication/Host proof are supplied by that existing transport binding,
// never inferred from these request DTOs or available to the Owner read lane.
type ThreadCollaborationNativeClient interface {
	ReadScope(context.Context) (ThreadScopeView, error)
	ReadLocks(context.Context, GroupLockScope) (GroupSlotView, error)
	Acquire(context.Context, GroupLockAcquireRequest) (GroupLockReceipt, error)
	Renew(context.Context, GroupLockRenewRequest) (GroupLockReceipt, error)
	Release(context.Context, GroupLockReleaseRequest) (GroupLockReceipt, error)
}
