package e2ee

// Independent NODE_V1 scope version 2 claims (availability is separate).
// These additive N3 claims describe an existing Owner delegating a finite
// Node operation to its existing App. They are not OwnerDeviceGrant v1 and
// cannot register, replace or reactivate an Owner or device. Signing and live
// authorization are separate from these contract-only data definitions.
const (
	OwnerAppNodeScopedPreviewPurpose       = "APP_NODE_SCOPED_INITIAL_PREVIEW"
	OwnerAppNodeScopedGrantPurpose         = "APP_NODE_SCOPED_INITIAL_CONFIRM"
	OwnerAppNodeScopedStatusPreviewPurpose = "APP_NODE_SCOPED_STATUS_PREVIEW"
	OwnerAppNodeScopedStatusGrantPurpose   = "APP_NODE_SCOPED_STATUS_READ"
	OwnerAppNodeScopedPreviewDomain        = "cicada/owner/app-node-scoped-preview/v1\x00"
	OwnerAppNodeScopedGrantDomain          = "cicada/owner/app-node-scoped-grant/v1\x00"
)

// OwnerAppNodeScopedScope binds the complete existing application identities. The
// Node-Control identity is independently bound by OwnerAppNodeCandidate.
type OwnerAppNodeScopedScope struct {
	AuthorityNodeID         string         `json:"authority_node_id"`
	Version                 int            `json:"version"`
	Origin                  string         `json:"origin"`
	HubID                   string         `json:"hub_id"`
	HubFingerprint          string         `json:"hub_fingerprint"`
	AccountID               string         `json:"account_id"`
	AccountSessionID        string         `json:"account_session_id"`
	AccountSessionExpiresAt string         `json:"account_session_expires_at"`
	OwnerID                 string         `json:"owner_id"`
	OwnerPublic             PublicIdentity `json:"owner_public_identity"`
	OwnerKeyVersion         uint64         `json:"owner_key_version"`
	DeviceID                string         `json:"device_id"`
	DevicePublic            PublicIdentity `json:"device_public_identity"`
	AccountEpoch            uint64         `json:"account_epoch"`
	DeviceEpoch             uint64         `json:"device_epoch"`
	ClientSessionEpoch      uint64         `json:"client_session_epoch"`
	HeadVersion             uint64         `json:"head_version"`
	TransportPolicy         string         `json:"transport_policy"`
}

// OwnerAppNodeScopedPreviewClaims grants only resolution of one normalized code.
// HeadVersion is the expected published head. Prepare only proposes its next
// generation; it does not publish authority. Neither signature nor code
// approves the selected Node.
type OwnerAppNodeScopedPreviewClaims struct {
	Purpose         string                  `json:"purpose"`
	Scope           OwnerAppNodeScopedScope `json:"scope"`
	GrantID         string                  `json:"grant_id"`
	CodeDigest      string                  `json:"code_digest"`
	PreviousGrantID string                  `json:"previous_grant_id"`
	RequestID       string                  `json:"request_id"`
	Nonce           string                  `json:"nonce"`
	IssuedAt        string                  `json:"issued_at"`
	ExpiresAt       string                  `json:"expires_at"`
}

type OwnerAppNodeScopedPreview struct {
	Claims    OwnerAppNodeScopedPreviewClaims `json:"claims"`
	Signature []byte                          `json:"signature"`
}

// OwnerAppNodeScopedGrantClaims is displayed before explicit approval. Its head is
// the proposed next generation. ExpectedHeadVersion is the unchanged published
// head that complete must compare and swap. Every field is signed.
type OwnerAppNodeScopedGrantClaims struct {
	Purpose                  string                  `json:"purpose"`
	Scope                    OwnerAppNodeScopedScope `json:"scope"`
	GrantID                  string                  `json:"grant_id"`
	ExpectedHeadVersion      uint64                  `json:"expected_head_version"`
	Profile                  string                  `json:"profile"`
	PreviousGrantID          string                  `json:"previous_grant_id"`
	ConfirmationProvenanceID string                  `json:"confirmation_provenance_id"`
	PrepareRequestID         string                  `json:"prepare_request_id"`
	PreparePacketDigest      string                  `json:"prepare_packet_digest"`
	PreviewProofDigest       string                  `json:"preview_proof_digest"`
	ServerNonce              string                  `json:"server_nonce"`
	Candidate                *OwnerAppNodeCandidate  `json:"candidate"`
	Binding                  *OwnerAppNodeBinding    `json:"binding"`
	AllowedOperations        []string                `json:"allowed_operations"`
	ReadNodeStatus           bool                    `json:"read_node_status"`
	ConfirmationLimit        uint64                  `json:"confirmation_limit"`
	PreparedAt               string                  `json:"prepared_at"`
	ProofExpiresAt           string                  `json:"proof_expires_at"`
	LeaseExpiresAt           string                  `json:"lease_expires_at"`
}

type OwnerAppNodeScopedGrant struct {
	Claims    OwnerAppNodeScopedGrantClaims `json:"claims"`
	Signature []byte                        `json:"signature"`
}
