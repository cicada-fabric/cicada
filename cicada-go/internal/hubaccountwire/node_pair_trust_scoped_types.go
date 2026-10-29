package hubaccountwire

import "github.com/cicada-ai/cicada/internal/e2ee"

// This additive Node-only family does not enable installation-registration.
const (
	NodePairTrustScopedContractRevision                = "node-pair-trust-node-scoped-v1"
	NodePairTrustScopedFormat                          = "cicada.node-pair-trust-scoped.v1"
	NodePairTrustScopedPacketFormat                    = "cicada.node-pair-trust-scoped-packet.v1"
	NodePairTrustScopedCodePrefix                      = "cicada-npts1."
	NodePairTrustScopedOwnerPurpose                    = "OWNER_NODE_PAIR_TRUST_SCOPED"
	NodePairTrustScopedInitial                         = "INITIAL_CANDIDATE"
	NodePairTrustScopedExisting                        = "EXISTING_BINDING"
	NodePairTrustScopedPending                         = "PENDING"
	NodePairTrustScopedOwnerApproved                   = "OWNER_APPROVED"
	NodePairTrustScopedACKed                           = "ACKED"
	NodePairTrustScopedExpired                         = "EXPIRED"
	NodePairTrustScopedCancelled                       = "CANCELLED"
	NodePairTrustScopedRevoked                         = "REVOKED"
	NodePairTrustScopedFenced                          = "FENCED"
	NodePairTrustScopedRecovered                       = "RECOVERED"
	NodePairTrustScopedPublicAvailable                 = false
	NodePairTrustScopedDescriptorPath                  = "/v2/hub/transport"
	NodePairTrustScopedCapabilitiesPath                = "/v2/node/pair-trust-scoped/capabilities"
	OperationNodePairTrustScopedStart                  = "node.pair-trust-scoped.start"
	OperationNodePairTrustScopedExisting               = "node.pair-trust-scoped.existing"
	OperationNodePairTrustScopedCommit                 = "node.pair-trust-scoped.commit"
	OperationNodePairTrustScopedPoll                   = "node.pair-trust-scoped.poll"
	OperationNodePairTrustScopedACK                    = "node.pair-trust-scoped.ack"
	OperationNodePairTrustScopedCancel                 = "node.pair-trust-scoped.cancel"
	OperationNodePairTrustScopedReconcile              = "node.pair-trust-scoped.reconcile"
	OperationOwnerNodePairTrustScopedPrepare           = "owner.node-pair-trust-scoped.prepare"
	OperationOwnerNodePairTrustScopedLookup            = "owner.node-pair-trust-scoped.lookup"
	OperationOwnerNodePairTrustScopedComplete          = "owner.node-pair-trust-scoped.complete"
	OperationOwnerNodePairTrustScopedStatus            = "owner.node-pair-trust-scoped.status"
	OperationOwnerNodePairTrustScopedCancel            = "owner.node-pair-trust-scoped.cancel"
	MaxNodePairTrustScopedCodeBytes                    = 1536
	MaxNodePairTrustScopedProofBytes                   = 64 << 10
	MaxNodePairTrustScopedCapsuleBytes                 = 128 << 10
	MaxNodePairTrustScopedBodyBytes                    = 256 << 10
	MaxNodePairTrustScopedPacketBytes                  = 512 << 10
	MaxNodePairTrustScopedResponseBodyBytes            = 512 << 10
	MaxNodePairTrustScopedResponsePacketBytes          = 1 << 20
	MaxNodePairTrustScopedOriginalReceiptBytes         = MaxNodePairTrustScopedResponsePacketBytes
	MaxNodePairTrustScopedReconcileResponseBodyBytes   = 1536 << 10
	MaxNodePairTrustScopedReconcileResponsePacketBytes = 3 << 20
	MaxNodePairTrustScopedReconcileBodyBytes           = 896 << 10
	MaxNodePairTrustScopedReconcilePacketBytes         = 2 << 20
)

type NodePairTrustScopedCapabilities struct {
	ScopeKind        string   `json:"scope_kind"`
	ScopeVersion     int      `json:"scope_version"`
	Format           string   `json:"format"`
	ContractRevision string   `json:"contract_revision"`
	Available        bool     `json:"available"`
	CodePrefix       string   `json:"code_prefix"`
	Operations       []string `json:"operations"`
	TrustModes       []string `json:"trust_modes"`
	MaxCodeBytes     int      `json:"max_code_bytes"`
}

func NodePairTrustScopedContractCapabilities() NodePairTrustScopedCapabilities {
	return NodePairTrustScopedCapabilities{AppNodeScopedScopeKind, AppNodeScopedScopeVersion, NodePairTrustScopedFormat, NodePairTrustScopedContractRevision, NodePairTrustScopedPublicAvailable, NodePairTrustScopedCodePrefix,
		[]string{OperationNodePairTrustScopedStart, OperationNodePairTrustScopedExisting, OperationNodePairTrustScopedCommit, OperationNodePairTrustScopedPoll, OperationNodePairTrustScopedACK, OperationNodePairTrustScopedCancel, OperationNodePairTrustScopedReconcile, OperationOwnerNodePairTrustScopedLookup, OperationOwnerNodePairTrustScopedPrepare, OperationOwnerNodePairTrustScopedComplete, OperationOwnerNodePairTrustScopedStatus, OperationOwnerNodePairTrustScopedCancel},
		[]string{NodePairTrustScopedInitial, NodePairTrustScopedExisting}, MaxNodePairTrustScopedCodeBytes}
}

// Context binds the actual original candidate or actual existing binding.
// No installation/admission identity, fake legacy tuple or new Node key exists.
type NodePairTrustScopedContext struct {
	ScopeVersion     int                         `json:"scope_version"`
	AuthorityNodeID  string                      `json:"authority_node_id"`
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

type NodePairTrustScopedApproval struct {
	Format                   string                       `json:"format"`
	ContextDigest            string                       `json:"context_digest"`
	OOBCommitment            string                       `json:"oob_commitment"`
	Scope                    e2ee.OwnerAppNodeScopedScope `json:"scope"`
	GrantID                  string                       `json:"grant_id"`
	GrantProofDigest         string                       `json:"grant_proof_digest"`
	ConfirmationPacketDigest string                       `json:"confirmation_packet_digest"`
	PrepareRequestID         string                       `json:"prepare_request_id"`
	PreparePacketDigest      string                       `json:"prepare_packet_digest"`
	ServerNonce              string                       `json:"server_nonce"`
	PreparedAt               string                       `json:"prepared_at"`
	AcceptBefore             string                       `json:"accept_before"`
}

type NodePairTrustScopedOwnerClaims struct {
	Version       int                         `json:"version"`
	Purpose       string                      `json:"purpose"`
	Approval      NodePairTrustScopedApproval `json:"approval"`
	CapsuleDigest string                      `json:"capsule_digest"`
	ACKCommitment string                      `json:"ack_commitment"`
}

type NodePairTrustScopedOwnerProof struct {
	Claims    NodePairTrustScopedOwnerClaims `json:"claims"`
	Signature []byte                         `json:"signature"`
}

// Only this encrypted plaintext and the local code contain S. Neither is a
// request DTO. X is an independent random value, disclosed only by Node ACK.
type NodePairTrustScopedCapsule struct {
	Format      string                      `json:"format"`
	Approval    NodePairTrustScopedApproval `json:"approval"`
	OwnerPublic e2ee.PublicIdentity         `json:"owner_public_identity"`
	OOBSecret   []byte                      `json:"oob_secret"`
	ACKNonce    []byte                      `json:"ack_nonce"`
}

func (NodePairTrustScopedCapsule) String() string   { return "NodePairTrustScopedCapsule[redacted]" }
func (NodePairTrustScopedCapsule) GoString() string { return "NodePairTrustScopedCapsule[redacted]" }

type NodePairTrustScopedPacket struct {
	Format       string              `json:"format"`
	Version      int                 `json:"version"`
	Operation    string              `json:"operation"`
	RequestID    string              `json:"request_id"`
	AttemptID    string              `json:"attempt_id"`
	SenderPublic e2ee.PublicIdentity `json:"sender_public_identity"`
	Packet       []byte              `json:"packet"`
}

type NodePairTrustScopedStart struct {
	ScopeVersion             int                 `json:"scope_version"`
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
type NodePairTrustScopedExistingStart struct {
	Format          string                        `json:"format"`
	Context         NodePairTrustScopedContext    `json:"context"`
	IssuedAt        string                        `json:"issued_at"`
	RetainedBinding *NodePairTrustRetainedBinding `json:"retained_binding,omitempty"`
}

// The exact subset retained by historical Node-Control local state. Unknown
// Owner/device/credential versions are read from the unchanged original Hub
// binding, never invented by the Node. CredentialDigest is not a bearer.
type NodePairTrustScopedCommit struct {
	Format        string                     `json:"format"`
	Context       NodePairTrustScopedContext `json:"context"`
	OOBCommitment string                     `json:"oob_commitment"`
	IssuedAt      string                     `json:"issued_at"`
}
type NodePairTrustScopedPoll = NodePairTrustScopedCommit

type NodePairTrustScopedACK struct {
	Format            string                     `json:"format"`
	Context           NodePairTrustScopedContext `json:"context"`
	OOBCommitment     string                     `json:"oob_commitment"`
	PollPacketDigest  string                     `json:"poll_packet_digest"`
	PollReceiptDigest string                     `json:"poll_receipt_digest"`
	OwnerProofDigest  string                     `json:"owner_proof_digest"`
	CapsuleDigest     string                     `json:"capsule_digest"`
	ACKNonce          []byte                     `json:"ack_nonce"`
	IssuedAt          string                     `json:"issued_at"`
}

func (NodePairTrustScopedACK) String() string   { return "NodePairTrustScopedACK[redacted]" }
func (NodePairTrustScopedACK) GoString() string { return "NodePairTrustScopedACK[redacted]" }

type NodePairTrustScopedCancel = NodePairTrustScopedCommit

type NodePairTrustScopedReconcile struct {
	Format               string `json:"format"`
	OriginalPacket       []byte `json:"original_packet"`
	OriginalPacketDigest string `json:"original_packet_digest"`
	IssuedAt             string `json:"issued_at"`
}

// Lookup is the App entry before it knows the Hub-stored Context. Only the
// locally decoded selector enters this DTO; S remains on Node and App.
type NodePairTrustScopedOwnerLookup struct {
	Format        string                       `json:"format"`
	SessionToken  []byte                       `json:"session_token"`
	Scope         e2ee.OwnerAppNodeScopedScope `json:"scope"`
	Selector      string                       `json:"selector"`
	ContextDigest string                       `json:"context_digest"`
	IssuedAt      string                       `json:"issued_at"`
}

type NodePairTrustScopedOwnerPrepare struct {
	Format             string                       `json:"format"`
	SessionToken       []byte                       `json:"session_token"`
	Scope              e2ee.OwnerAppNodeScopedScope `json:"scope"`
	Context            NodePairTrustScopedContext   `json:"context"`
	OOBCommitment      string                       `json:"oob_commitment"`
	GrantProof         []byte                       `json:"grant_proof"`
	ConfirmationPacket []byte                       `json:"confirmation_packet"`
	IssuedAt           string                       `json:"issued_at"`
}
type NodePairTrustScopedOwnerComplete struct {
	Format        string                       `json:"format"`
	SessionToken  []byte                       `json:"session_token"`
	Scope         e2ee.OwnerAppNodeScopedScope `json:"scope"`
	Context       NodePairTrustScopedContext   `json:"context"`
	OOBCommitment string                       `json:"oob_commitment"`
	OwnerProof    []byte                       `json:"owner_proof"`
	TrustCapsule  []byte                       `json:"trust_capsule"`
	IssuedAt      string                       `json:"issued_at"`
}
type NodePairTrustScopedOwnerStatus struct {
	Format        string                       `json:"format"`
	SessionToken  []byte                       `json:"session_token"`
	Scope         e2ee.OwnerAppNodeScopedScope `json:"scope"`
	Context       NodePairTrustScopedContext   `json:"context"`
	OOBCommitment string                       `json:"oob_commitment"`
	IssuedAt      string                       `json:"issued_at"`
}
type NodePairTrustScopedOwnerCancel = NodePairTrustScopedOwnerStatus

// Result payloads are closed by operation/state. Cached data is evidence,
// never current authorization. Node receives E; only App receives its old
// exact Client confirmation response. No public inventory is exposed.
type NodePairTrustScopedResult struct {
	Format               string                       `json:"format"`
	Operation            string                       `json:"operation"`
	RequestID            string                       `json:"request_id"`
	AttemptID            string                       `json:"attempt_id"`
	RequestPacketDigest  string                       `json:"request_packet_digest"`
	State                string                       `json:"state"`
	ErrorCode            string                       `json:"error_code"`
	Context              *NodePairTrustScopedContext  `json:"context,omitempty"`
	OOBCommitment        string                       `json:"oob_commitment"`
	Selector             string                       `json:"selector"`
	Approval             *NodePairTrustScopedApproval `json:"approval,omitempty"`
	OwnerProof           []byte                       `json:"owner_proof,omitempty"`
	TrustCapsule         []byte                       `json:"trust_capsule,omitempty"`
	Binding              *e2ee.OwnerAppNodeBinding    `json:"binding,omitempty"`
	ConfirmationResponse []byte                       `json:"confirmation_response,omitempty"`
	ObservedAt           string                       `json:"observed_at"`
	OriginalPacketDigest string                       `json:"original_packet_digest,omitempty"`
	OriginalReceipt      []byte                       `json:"original_receipt,omitempty"`
}
