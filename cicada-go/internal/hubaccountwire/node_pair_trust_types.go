package hubaccountwire

import "github.com/cicada-ai/cicada/internal/e2ee"

// This additive Node-only family does not enable installation-registration.
const (
	NodePairTrustContractRevision                = "node-pair-trust-v1"
	NodePairTrustFormat                          = "cicada.node-pair-trust.v1"
	NodePairTrustPacketFormat                    = "cicada.node-pair-trust-packet.v1"
	NodePairTrustCodePrefix                      = "cicada-npt1."
	NodePairTrustOwnerPurpose                    = "OWNER_NODE_PAIR_TRUST"
	NodePairTrustInitial                         = "INITIAL_CANDIDATE"
	NodePairTrustExisting                        = "EXISTING_BINDING"
	NodePairTrustPending                         = "PENDING"
	NodePairTrustOwnerApproved                   = "OWNER_APPROVED"
	NodePairTrustACKed                           = "ACKED"
	NodePairTrustExpired                         = "EXPIRED"
	NodePairTrustCancelled                       = "CANCELLED"
	NodePairTrustRevoked                         = "REVOKED"
	NodePairTrustFenced                          = "FENCED"
	NodePairTrustRecovered                       = "RECOVERED"
	NodePairTrustPublicAvailable                 = true
	NodePairTrustDescriptorPath                  = "/v2/hub/transport"
	NodePairTrustCapabilitiesPath                = "/v2/node/pair-trust/capabilities"
	OperationNodePairTrustStart                  = "node.pair-trust.start"
	OperationNodePairTrustExisting               = "node.pair-trust.existing"
	OperationNodePairTrustCommit                 = "node.pair-trust.commit"
	OperationNodePairTrustPoll                   = "node.pair-trust.poll"
	OperationNodePairTrustACK                    = "node.pair-trust.ack"
	OperationNodePairTrustCancel                 = "node.pair-trust.cancel"
	OperationNodePairTrustReconcile              = "node.pair-trust.reconcile"
	OperationOwnerNodePairTrustPrepare           = "owner.node-pair-trust.prepare"
	OperationOwnerNodePairTrustLookup            = "owner.node-pair-trust.lookup"
	OperationOwnerNodePairTrustComplete          = "owner.node-pair-trust.complete"
	OperationOwnerNodePairTrustStatus            = "owner.node-pair-trust.status"
	OperationOwnerNodePairTrustCancel            = "owner.node-pair-trust.cancel"
	MaxNodePairTrustCodeBytes                    = 1024
	MaxNodePairTrustProofBytes                   = 64 << 10
	MaxNodePairTrustCapsuleBytes                 = 128 << 10
	MaxNodePairTrustBodyBytes                    = 256 << 10
	MaxNodePairTrustPacketBytes                  = 512 << 10
	MaxNodePairTrustResponseBodyBytes            = 512 << 10
	MaxNodePairTrustResponsePacketBytes          = 1 << 20
	MaxNodePairTrustOriginalReceiptBytes         = MaxNodePairTrustResponsePacketBytes
	MaxNodePairTrustReconcileResponseBodyBytes   = 1536 << 10
	MaxNodePairTrustReconcileResponsePacketBytes = 3 << 20
	MaxNodePairTrustReconcileBodyBytes           = 896 << 10
	MaxNodePairTrustReconcilePacketBytes         = 2 << 20
)

type NodePairTrustCapabilities struct {
	Format           string   `json:"format"`
	ContractRevision string   `json:"contract_revision"`
	Available        bool     `json:"available"`
	CodePrefix       string   `json:"code_prefix"`
	Operations       []string `json:"operations"`
	TrustModes       []string `json:"trust_modes"`
	MaxCodeBytes     int      `json:"max_code_bytes"`
}

func NodePairTrustContractCapabilities() NodePairTrustCapabilities {
	return NodePairTrustCapabilities{NodePairTrustFormat, NodePairTrustContractRevision, NodePairTrustPublicAvailable, NodePairTrustCodePrefix,
		[]string{OperationNodePairTrustStart, OperationNodePairTrustExisting, OperationNodePairTrustCommit, OperationNodePairTrustPoll, OperationNodePairTrustACK, OperationNodePairTrustCancel, OperationNodePairTrustReconcile, OperationOwnerNodePairTrustLookup, OperationOwnerNodePairTrustPrepare, OperationOwnerNodePairTrustComplete, OperationOwnerNodePairTrustStatus, OperationOwnerNodePairTrustCancel},
		[]string{NodePairTrustInitial, NodePairTrustExisting}, MaxNodePairTrustCodeBytes}
}

// Context binds the actual original candidate or actual existing binding.
// No installation/admission identity, fake legacy tuple or new Node key exists.
type NodePairTrustContext struct {
	Format           string                      `json:"format"`
	AttemptID        string                      `json:"attempt_id"`
	Hub              HubIdentity                 `json:"hub"`
	Origin           string                      `json:"origin"`
	DescriptorDigest string                      `json:"descriptor_digest"`
	NodeNonce        string                      `json:"node_nonce"`
	Mode             string                      `json:"mode"`
	Candidate        *e2ee.OwnerAppNodeCandidate `json:"candidate,omitempty"`
	Binding          *e2ee.OwnerAppNodeBinding   `json:"binding,omitempty"`
	IssuedAt         string                      `json:"issued_at"`
	ExpiresAt        string                      `json:"expires_at"`
}

type NodePairTrustApproval struct {
	Format                   string                 `json:"format"`
	ContextDigest            string                 `json:"context_digest"`
	OOBCommitment            string                 `json:"oob_commitment"`
	Scope                    e2ee.OwnerAppNodeScope `json:"scope"`
	GrantID                  string                 `json:"grant_id"`
	GrantProofDigest         string                 `json:"grant_proof_digest"`
	ConfirmationPacketDigest string                 `json:"confirmation_packet_digest"`
	PrepareRequestID         string                 `json:"prepare_request_id"`
	PreparePacketDigest      string                 `json:"prepare_packet_digest"`
	ServerNonce              string                 `json:"server_nonce"`
	PreparedAt               string                 `json:"prepared_at"`
	AcceptBefore             string                 `json:"accept_before"`
}

type NodePairTrustOwnerClaims struct {
	Version       int                   `json:"version"`
	Purpose       string                `json:"purpose"`
	Approval      NodePairTrustApproval `json:"approval"`
	CapsuleDigest string                `json:"capsule_digest"`
	ACKCommitment string                `json:"ack_commitment"`
}

type NodePairTrustOwnerProof struct {
	Claims    NodePairTrustOwnerClaims `json:"claims"`
	Signature []byte                   `json:"signature"`
}

// Only this encrypted plaintext and the local code contain S. Neither is a
// request DTO. X is an independent random value, disclosed only by Node ACK.
type NodePairTrustCapsule struct {
	Format      string                `json:"format"`
	Approval    NodePairTrustApproval `json:"approval"`
	OwnerPublic e2ee.PublicIdentity   `json:"owner_public_identity"`
	OOBSecret   []byte                `json:"oob_secret"`
	ACKNonce    []byte                `json:"ack_nonce"`
}

func (NodePairTrustCapsule) String() string   { return "NodePairTrustCapsule[redacted]" }
func (NodePairTrustCapsule) GoString() string { return "NodePairTrustCapsule[redacted]" }

type NodePairTrustPacket struct {
	Format       string              `json:"format"`
	Version      int                 `json:"version"`
	Operation    string              `json:"operation"`
	RequestID    string              `json:"request_id"`
	AttemptID    string              `json:"attempt_id"`
	SenderPublic e2ee.PublicIdentity `json:"sender_public_identity"`
	Packet       []byte              `json:"packet"`
}

type NodePairTrustStart struct {
	Format                   string              `json:"format"`
	Hub                      HubIdentity         `json:"hub"`
	Origin                   string              `json:"origin"`
	DescriptorDigest         string              `json:"descriptor_digest"`
	NodeID                   string              `json:"node_id"`
	NodeName                 string              `json:"node_name"`
	CredentialDigest         string              `json:"credential_digest"`
	RequestNonce             []byte              `json:"request_nonce"`
	HubNodeControlPublic     e2ee.PublicIdentity `json:"hub_node_control_public_identity"`
	HubNodeControlKeyVersion uint64              `json:"hub_node_control_key_version"`
	PairingProof             []byte              `json:"pairing_proof"`
	IssuedAt                 string              `json:"issued_at"`
	ExpiresAt                string              `json:"expires_at"`
}

// Existing bindings use this strictly authenticated start instead of INITIAL.
type NodePairTrustExistingStart struct {
	Format          string                        `json:"format"`
	Context         NodePairTrustContext          `json:"context"`
	IssuedAt        string                        `json:"issued_at"`
	RetainedBinding *NodePairTrustRetainedBinding `json:"retained_binding,omitempty"`
}

// The exact subset retained by historical Node-Control local state. Unknown
// Owner/device/credential versions are read from the unchanged original Hub
// binding, never invented by the Node. CredentialDigest is not a bearer.
type NodePairTrustRetainedBinding struct {
	NodeID                    string              `json:"node_id"`
	OwnerBindingID            string              `json:"owner_binding_id"`
	BindingVersion            uint64              `json:"binding_version"`
	NodeKeyID                 string              `json:"node_key_id"`
	NodeKeyVersion            uint64              `json:"node_key_version"`
	NodeKeyEpoch              uint64              `json:"node_key_epoch"`
	NodeKeyFingerprint        string              `json:"node_key_fingerprint"`
	HubNodeControlPublic      e2ee.PublicIdentity `json:"hub_node_control_public_identity"`
	HubNodeControlKeyVersion  uint64              `json:"hub_node_control_key_version"`
	HubNodeControlFingerprint string              `json:"hub_node_control_fingerprint"`
	ApprovedRequestID         string              `json:"approved_request_id"`
	ApprovedRequestVersion    uint64              `json:"approved_request_version"`
	ApprovedCandidateDigest   string              `json:"approved_candidate_digest"`
	CredentialDigest          string              `json:"credential_digest"`
}

type NodePairTrustCommit struct {
	Format        string               `json:"format"`
	Context       NodePairTrustContext `json:"context"`
	OOBCommitment string               `json:"oob_commitment"`
	IssuedAt      string               `json:"issued_at"`
}
type NodePairTrustPoll = NodePairTrustCommit

type NodePairTrustACK struct {
	Format            string               `json:"format"`
	Context           NodePairTrustContext `json:"context"`
	OOBCommitment     string               `json:"oob_commitment"`
	PollPacketDigest  string               `json:"poll_packet_digest"`
	PollReceiptDigest string               `json:"poll_receipt_digest"`
	OwnerProofDigest  string               `json:"owner_proof_digest"`
	CapsuleDigest     string               `json:"capsule_digest"`
	ACKNonce          []byte               `json:"ack_nonce"`
	IssuedAt          string               `json:"issued_at"`
}

func (NodePairTrustACK) String() string   { return "NodePairTrustACK[redacted]" }
func (NodePairTrustACK) GoString() string { return "NodePairTrustACK[redacted]" }

type NodePairTrustCancel = NodePairTrustCommit

type NodePairTrustReconcile struct {
	Format               string `json:"format"`
	OriginalPacket       []byte `json:"original_packet"`
	OriginalPacketDigest string `json:"original_packet_digest"`
	IssuedAt             string `json:"issued_at"`
}

// Lookup is the App entry before it knows the Hub-stored Context. Only the
// locally decoded selector enters this DTO; S remains on Node and App.
type NodePairTrustOwnerLookup struct {
	Format        string                 `json:"format"`
	SessionToken  []byte                 `json:"session_token"`
	Scope         e2ee.OwnerAppNodeScope `json:"scope"`
	Selector      string                 `json:"selector"`
	ContextDigest string                 `json:"context_digest"`
	IssuedAt      string                 `json:"issued_at"`
}

type NodePairTrustOwnerPrepare struct {
	Format             string                 `json:"format"`
	SessionToken       []byte                 `json:"session_token"`
	Scope              e2ee.OwnerAppNodeScope `json:"scope"`
	Context            NodePairTrustContext   `json:"context"`
	OOBCommitment      string                 `json:"oob_commitment"`
	GrantProof         []byte                 `json:"grant_proof"`
	ConfirmationPacket []byte                 `json:"confirmation_packet"`
	IssuedAt           string                 `json:"issued_at"`
}
type NodePairTrustOwnerComplete struct {
	Format        string                 `json:"format"`
	SessionToken  []byte                 `json:"session_token"`
	Scope         e2ee.OwnerAppNodeScope `json:"scope"`
	Context       NodePairTrustContext   `json:"context"`
	OOBCommitment string                 `json:"oob_commitment"`
	OwnerProof    []byte                 `json:"owner_proof"`
	TrustCapsule  []byte                 `json:"trust_capsule"`
	IssuedAt      string                 `json:"issued_at"`
}
type NodePairTrustOwnerStatus struct {
	Format        string                 `json:"format"`
	SessionToken  []byte                 `json:"session_token"`
	Scope         e2ee.OwnerAppNodeScope `json:"scope"`
	Context       NodePairTrustContext   `json:"context"`
	OOBCommitment string                 `json:"oob_commitment"`
	IssuedAt      string                 `json:"issued_at"`
}
type NodePairTrustOwnerCancel = NodePairTrustOwnerStatus

// Result payloads are closed by operation/state. Cached data is evidence,
// never current authorization. Node receives E; only App receives its old
// exact Client confirmation response. No public inventory is exposed.
type NodePairTrustResult struct {
	Format               string                    `json:"format"`
	Operation            string                    `json:"operation"`
	RequestID            string                    `json:"request_id"`
	AttemptID            string                    `json:"attempt_id"`
	RequestPacketDigest  string                    `json:"request_packet_digest"`
	State                string                    `json:"state"`
	ErrorCode            string                    `json:"error_code"`
	Context              *NodePairTrustContext     `json:"context,omitempty"`
	OOBCommitment        string                    `json:"oob_commitment"`
	Selector             string                    `json:"selector"`
	Approval             *NodePairTrustApproval    `json:"approval,omitempty"`
	OwnerProof           []byte                    `json:"owner_proof,omitempty"`
	TrustCapsule         []byte                    `json:"trust_capsule,omitempty"`
	Binding              *e2ee.OwnerAppNodeBinding `json:"binding,omitempty"`
	ConfirmationResponse []byte                    `json:"confirmation_response,omitempty"`
	ObservedAt           string                    `json:"observed_at"`
	OriginalPacketDigest string                    `json:"original_packet_digest,omitempty"`
	OriginalReceipt      []byte                    `json:"original_receipt,omitempty"`
}
