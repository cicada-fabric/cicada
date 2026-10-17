package hubaccountwire

import "github.com/cicada-ai/cicada/internal/e2ee"

const (
	NativePairContractRevision             = "native-pair-v1"
	NativePairImplementationPhase          = "SERVER_PREPARATION"
	NativePairCapabilitiesPath             = "/v2/owner/native-pairs/capabilities"
	NativePairFormat                       = "cicada.native-pair.v1"
	OperationNativePairBootstrapPrepare    = "owner.native_pair.bootstrap_prepare"
	OperationNativePairBootstrapComplete   = "owner.native_pair.bootstrap_complete"
	OperationNativePairSlotReject          = "owner.native_pair.slot_reject"
	OperationNativePairConsentPrepare      = "owner.native_pair.consent_prepare"
	OperationNativePairConsentComplete     = "owner.native_pair.consent_complete"
	OperationNativePairStatus              = "owner.native_pair.status"
	OperationNativePairRevoke              = "owner.native_pair.revoke"
	OperationNativePairReconcile           = "owner.native_pair.reconcile"
	OperationNativePairNodeJoin            = "node.native_pair.join"
	OperationNativePairNodeDescribe        = "node.native_pair.describe"
	OperationNativePairNodeReconcile       = "node.native_pair.reconcile"
	MaxNativePairOriginalBytes             = 128 * 1024
	MaxNativePairReceiptBytes              = 256 * 1024
	MaxNativePairBodyBytes                 = 192 * 1024
	MaxNativePairPacketBytes               = 256 * 1024
	MaxNativePairInnerPacketBytes          = 384 * 1024
	MaxNativePairPlanBytes                 = 128 * 1024
	MaxNativePairEvidenceBytes             = 256 * 1024
	MaxNativePairCarrierBytes              = 320 * 1024
	MaxNativePairReconcileBodyBytes        = 352 * 1024
	MaxNativePairReconcilePacketBytes      = 640 * 1024
	MaxNativePairReconcileInnerPacketBytes = 640 * 1024
	MaxNativePairSlotGenerations           = uint64(16)
	MaxNativePairCapabilitiesBytes         = 8 * 1024
	MaxNativePairNodeOriginalBytes         = 32 * 1024
	MaxNativePairNodeReceiptBytes          = 128 * 1024
)

type NativePairState string

const (
	NativePairPrepared       NativePairState = "PREPARED"
	NativePairWaitingJoin    NativePairState = "WAITING_JOIN"
	NativePairWaitingConsent NativePairState = "WAITING_CONSENT"
	NativePairActive         NativePairState = "ACTIVE"
	NativePairExpired        NativePairState = "EXPIRED"
	NativePairRevoked        NativePairState = "REVOKED"
)

type NativePairSlotState string

const (
	NativePairSlotReserved        NativePairSlotState = "RESERVED"
	NativePairSlotJoinedZero      NativePairSlotState = "JOINED_ZERO"
	NativePairSlotCandidateReady  NativePairSlotState = "CANDIDATE_READY"
	NativePairSlotConsentRecorded NativePairSlotState = "CONSENT_RECORDED"
	NativePairSlotActive          NativePairSlotState = "ACTIVE"
	NativePairSlotRejected        NativePairSlotState = "REJECTED"
)

type NativePairCapabilities struct {
	Format           string                    `json:"format"`
	ContractRevision string                    `json:"contract_revision"`
	Available        bool                      `json:"available"`
	ServeMode        string                    `json:"serve_mode"`
	TransportPolicy  string                    `json:"transport_policy"`
	HTTPOperations   []string                  `json:"http_operations"`
	NodeOperations   []string                  `json:"node_operations"`
	PeerTransport    string                    `json:"peer_transport"`
	Policy           e2ee.NativePairPeerPolicy `json:"policy"`
}

type NativePairRequestContext struct {
	Origin             string `json:"origin"`
	HubID              string `json:"hub_id"`
	AccountID          string `json:"account_id"`
	OwnerID            string `json:"owner_id"`
	DeviceID           string `json:"device_id"`
	AccountSessionID   string `json:"account_session_id"`
	AccountEpoch       uint64 `json:"account_epoch"`
	DeviceEpoch        uint64 `json:"device_epoch"`
	ClientSessionEpoch uint64 `json:"client_session_epoch"`
	RequestID          string `json:"request_id"`
	ClientNonce        []byte `json:"client_nonce"`
	IssuedAt           string `json:"issued_at"`
}

// Each HTTP operation has a dedicated DTO. OwnerProof is canonical
// e2ee.OwnerNativePairProof bytes with the operation's exact expected purpose.
type NativePairBootstrapPrepare struct {
	Format       string                   `json:"format"`
	Context      NativePairRequestContext `json:"context"`
	SessionToken []byte                   `json:"session_token"`
	OwnerProof   []byte                   `json:"owner_proof"`
}
type NativePairBootstrapComplete NativePairBootstrapPrepare

type NativePairConsentPrepare NativePairBootstrapPrepare
type NativePairSlotReject NativePairBootstrapPrepare
type NativePairRevoke NativePairBootstrapPrepare

type NativePairConsentComplete struct {
	Format        string                   `json:"format"`
	Context       NativePairRequestContext `json:"context"`
	SessionToken  []byte                   `json:"session_token"`
	OwnerProof    []byte                   `json:"owner_proof"`
	GroupKeyProof []byte                   `json:"group_key_proof"`
}

type NativePairStatusRequest struct {
	Format       string                   `json:"format"`
	Context      NativePairRequestContext `json:"context"`
	SessionToken []byte                   `json:"session_token,omitempty"`
	PairID       string                   `json:"pair_id"`
}

type NativePairReconcileRequest struct {
	Format         string                   `json:"format"`
	Context        NativePairRequestContext `json:"context"`
	PairID         string                   `json:"pair_id"`
	OriginalPacket []byte                   `json:"original_packet"`
}

type NativePairBootstrapChallenge struct {
	Format              string                         `json:"format"`
	RequestID           string                         `json:"request_id"`
	RequestPacketDigest string                         `json:"request_packet_digest"`
	Scope               e2ee.OwnerNativePairScope      `json:"scope"`
	Bootstrap           e2ee.NativePairBootstrapClaims `json:"bootstrap"`
	ProofExpiresAt      string                         `json:"proof_expires_at"`
	ObservedAt          string                         `json:"observed_at"`
}

// Only an unadmitted bootstrap.prepare can have no server-assigned PairID.
// This permanent authenticated fence carries no scope, authority or domain row.
type NativePairBootstrapFence struct {
	Format              string `json:"format"`
	Operation           string `json:"operation"`
	RequestID           string `json:"request_id"`
	RequestPacketDigest string `json:"request_packet_digest"`
	State               string `json:"state"`
	NoEffect            bool   `json:"no_effect"`
	ErrorCode           string `json:"error_code"`
	ObservedAt          string `json:"observed_at"`
}

// A known-pair mutation may be permanently fenced even when the target row
// is unavailable. PairID comes from the authenticated original Owner proof;
// no current domain state or permission is invented to represent rejection.
type NativePairRejectionFence struct {
	Format              string `json:"format"`
	Operation           string `json:"operation"`
	RequestID           string `json:"request_id"`
	RequestPacketDigest string `json:"request_packet_digest"`
	PairID              string `json:"pair_id"`
	State               string `json:"state"`
	NoEffect            bool   `json:"no_effect"`
	ErrorCode           string `json:"error_code"`
	ObservedAt          string `json:"observed_at"`
}

// Slot basis is immutable for one generation. LeaseCeiling bounds permission;
// legal heartbeat renewals of the same lease identity cannot extend that bound.
type NativePairSlot struct {
	Slot                      string              `json:"slot"`
	Generation                uint64              `json:"generation"`
	AttemptID                 string              `json:"attempt_id"`
	NativeSessionID           string              `json:"native_session_id"`
	Runtime                   string              `json:"runtime"`
	EndpointID                string              `json:"endpoint_id"`
	PrincipalID               string              `json:"principal_id"`
	NodeID                    string              `json:"node_id"`
	NetworkAccessBindingID    string              `json:"network_access_binding_id"`
	NetworkAccessEpoch        uint64              `json:"network_access_epoch"`
	NetworkMembershipRevision uint64              `json:"network_membership_revision"`
	EndpointNetworkRevision   uint64              `json:"endpoint_network_revision"`
	BindingID                 string              `json:"binding_id"`
	BindingEpoch              uint64              `json:"binding_epoch"`
	LeaseOwner                string              `json:"lease_owner"`
	LeaseCeiling              string              `json:"lease_ceiling"`
	MembershipRevision        uint64              `json:"membership_revision"`
	EndpointJoinRevision      uint64              `json:"endpoint_join_revision"`
	CandidateVersion          uint64              `json:"candidate_version"`
	CandidatePublic           e2ee.PublicIdentity `json:"candidate_public_identity"`
	CandidateFingerprint      string              `json:"candidate_fingerprint"`
	CandidateProofDigest      string              `json:"candidate_proof_digest"`
	CandidateAttestation      []byte              `json:"candidate_attestation"`
}

// Exact public projection of Store.GroupEndpointKeyGrantManifest. Wire code
// does not import Store; no private credential or arbitrary metadata is added.
type NativePairGroupKeyClaims struct {
	Version                 int                 `json:"version"`
	Operation               string              `json:"operation"`
	HubID                   string              `json:"hub_id"`
	OwnerID                 string              `json:"owner_id"`
	PrincipalID             string              `json:"principal_id"`
	GroupID                 string              `json:"group_id"`
	GroupRevision           int64               `json:"group_revision"`
	EndpointID              string              `json:"endpoint_id"`
	NodeID                  string              `json:"node_id"`
	BindingID               string              `json:"binding_id"`
	BindingEpoch            uint64              `json:"binding_epoch"`
	MembershipRevision      int64               `json:"membership_revision"`
	EndpointJoinRevision    int64               `json:"endpoint_join_revision"`
	CandidateVersion        int64               `json:"candidate_version"`
	CandidateKeyID          string              `json:"candidate_key_id"`
	CandidateFingerprint    string              `json:"candidate_fingerprint"`
	CandidateProofDigest    string              `json:"candidate_proof_digest"`
	CandidateBindingDigest  string              `json:"candidate_binding_digest"`
	CandidatePublicIdentity e2ee.PublicIdentity `json:"candidate_public_identity"`
	OwnerKeyID              string              `json:"owner_key_id"`
	IssuedAt                string              `json:"issued_at"`
	ExpiresAt               string              `json:"expires_at"`
}

type NativePairGroupKeyManifest struct {
	NativePairGroupKeyClaims
	CandidateAttestation []byte `json:"candidate_attestation"`
	Digest               string `json:"digest"`
}

type NativePairConsentPlan struct {
	Format                   string                     `json:"format"`
	PairID                   string                     `json:"pair_id"`
	ExpectedRevision         uint64                     `json:"expected_revision"`
	PlanID                   string                     `json:"plan_id"`
	Scope                    e2ee.OwnerNativePairScope  `json:"scope"`
	BootstrapProofDigest     string                     `json:"bootstrap_proof_digest"`
	NetworkID                string                     `json:"network_id"`
	NetworkVersion           uint64                     `json:"network_version"`
	GroupID                  string                     `json:"group_id"`
	GroupVersion             uint64                     `json:"group_version"`
	GroupRevision            uint64                     `json:"group_revision"`
	SlotA                    NativePairSlot             `json:"slot_a"`
	SlotB                    NativePairSlot             `json:"slot_b"`
	ProjectedSlotAMembership uint64                     `json:"projected_slot_a_membership_revision"`
	ProjectedSlotBMembership uint64                     `json:"projected_slot_b_membership_revision"`
	SlotAKeyManifest         NativePairGroupKeyManifest `json:"slot_a_key_manifest"`
	SlotBKeyManifest         NativePairGroupKeyManifest `json:"slot_b_key_manifest"`
	GroupGrants              []string                   `json:"group_grants"`
	Policy                   e2ee.NativePairPeerPolicy  `json:"policy"`
	PreparedAt               string                     `json:"prepared_at"`
	ExpiresAt                string                     `json:"expires_at"`
	PeerExpiresAt            string                     `json:"peer_expires_at"`
	Digest                   string                     `json:"digest"`
}

type NativePairPlanChallenge struct {
	Format              string                `json:"format"`
	RequestID           string                `json:"request_id"`
	RequestPacketDigest string                `json:"request_packet_digest"`
	Plan                NativePairConsentPlan `json:"plan"`
	ObservedAt          string                `json:"observed_at"`
}

// Mandatory signed evidence on this contract's peer-key and delivery
// authorization carriers. Omission is never a downgrade to legacy group rights.
type NativePairPeerEvidence struct {
	ContractRevision    string                `json:"contract_revision"`
	Plan                NativePairConsentPlan `json:"plan"`
	BootstrapOwnerProof []byte                `json:"bootstrap_owner_proof"`
	SlotAOwnerConsent   []byte                `json:"slot_a_owner_consent"`
	SlotBOwnerConsent   []byte                `json:"slot_b_owner_consent"`
	SlotAGroupKeyProof  []byte                `json:"slot_a_group_key_proof"`
	SlotBGroupKeyProof  []byte                `json:"slot_b_group_key_proof"`
}

type NativePairNodeJoin struct {
	ContractRevision     string `json:"contract_revision"`
	PairID               string `json:"pair_id"`
	Slot                 string `json:"slot"`
	ExpectedGeneration   uint64 `json:"expected_generation"`
	BootstrapProofDigest string `json:"bootstrap_proof_digest"`
	Runtime              string `json:"runtime"`
	NativeSessionID      string `json:"native_session_id"`
	EndpointName         string `json:"endpoint_name"`
}

type NativePairNodeDescribe struct {
	ContractRevision string `json:"contract_revision"`
	PairID           string `json:"pair_id"`
}

type NativePairNodeDescription struct {
	ContractRevision    string `json:"contract_revision"`
	PairID              string `json:"pair_id"`
	BootstrapOwnerProof []byte `json:"bootstrap_owner_proof"`
	SlotAGeneration     uint64 `json:"slot_a_generation"`
	SlotBGeneration     uint64 `json:"slot_b_generation"`
}

// Detached diagnostic read: original business sequence remains unresolved
// until its exact receipt or permanent fence is authenticated and applied.
type NativePairNodeReconcile struct {
	ContractRevision string `json:"contract_revision"`
	PairID           string `json:"pair_id"`
	Nonce            []byte `json:"nonce"`
	IssuedAt         string `json:"issued_at"`
	OriginalPacket   []byte `json:"original_packet"`
}

type NativePairNodeReconciled struct {
	ContractRevision     string `json:"contract_revision"`
	PairID               string `json:"pair_id"`
	OriginalOperation    string `json:"original_operation"`
	OriginalOperationID  string `json:"original_operation_id"`
	OriginalSequence     uint64 `json:"original_sequence"`
	OriginalPacketDigest string `json:"original_packet_digest"`
	State                string `json:"state"`
	ReceiptPacket        []byte `json:"receipt_packet,omitempty"`
	ObservedAt           string `json:"observed_at"`
}

type NativePairBudgetObservation struct {
	RootAsksUsed        uint64 `json:"root_asks_used"`
	RepliesUsed         uint64 `json:"replies_used"`
	MessagesUsed        uint64 `json:"messages_used"`
	CiphertextBytesUsed uint64 `json:"ciphertext_bytes_used"`
}

type NativePairResult struct {
	Format                   string                      `json:"format"`
	Operation                string                      `json:"operation"`
	RequestID                string                      `json:"request_id"`
	RequestPacketDigest      string                      `json:"request_packet_digest"`
	PairID                   string                      `json:"pair_id"`
	State                    NativePairState             `json:"state"`
	Outcome                  string                      `json:"outcome"`
	ErrorCode                string                      `json:"error_code,omitempty"`
	ControlRevision          uint64                      `json:"control_revision"`
	AdministrativePermission bool                        `json:"administrative_permission"`
	SlotA                    *NativePairSlot             `json:"slot_a,omitempty"`
	SlotB                    *NativePairSlot             `json:"slot_b,omitempty"`
	SlotAState               NativePairSlotState         `json:"slot_a_state"`
	SlotBState               NativePairSlotState         `json:"slot_b_state"`
	Budget                   NativePairBudgetObservation `json:"budget"`
	PeerExpiresAt            string                      `json:"peer_expires_at"`
	ObservedAt               string                      `json:"observed_at"`
}

type NativePairReconciled struct {
	Format               string `json:"format"`
	RequestID            string `json:"request_id"`
	RequestPacketDigest  string `json:"request_packet_digest"`
	PairID               string `json:"pair_id"`
	OriginalOperation    string `json:"original_operation"`
	OriginalRequestID    string `json:"original_request_id"`
	OriginalPacketDigest string `json:"original_packet_digest"`
	State                string `json:"state"`
	ReceiptPacket        []byte `json:"receipt_packet,omitempty"`
	ObservedAt           string `json:"observed_at"`
}
