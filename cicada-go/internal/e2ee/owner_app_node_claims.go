package e2ee

// These additive N3 claims describe an existing Owner delegating a finite
// Node operation to its existing App. They are not OwnerDeviceGrant v1 and
// cannot register, replace or reactivate an Owner or device. Signing and live
// authorization are separate from these contract-only data definitions.
const (
	OwnerAppNodePreviewPurpose       = "APP_NODE_INITIAL_PREVIEW"
	OwnerAppNodeGrantPurpose         = "APP_NODE_INITIAL_CONFIRM"
	OwnerAppNodeStatusPreviewPurpose = "APP_NODE_STATUS_PREVIEW"
	OwnerAppNodeStatusGrantPurpose   = "APP_NODE_STATUS_READ"
	OwnerAppNodePreviewDomain        = "cicada/owner/app-node-preview/v1\x00"
	OwnerAppNodeGrantDomain          = "cicada/owner/app-node-grant/v1\x00"
)

// OwnerAppNodeScope binds the complete existing application identities. The
// Node-Control identity is independently bound by OwnerAppNodeCandidate.
type OwnerAppNodeScope struct {
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

// OwnerAppNodePreviewClaims grants only resolution of one normalized code.
// HeadVersion is the expected published head. Prepare only proposes its next
// generation; it does not publish authority. Neither signature nor code
// approves the selected Node.
type OwnerAppNodePreviewClaims struct {
	Purpose         string            `json:"purpose"`
	Scope           OwnerAppNodeScope `json:"scope"`
	GrantID         string            `json:"grant_id"`
	CodeDigest      string            `json:"code_digest"`
	PreviousGrantID string            `json:"previous_grant_id"`
	RequestID       string            `json:"request_id"`
	Nonce           string            `json:"nonce"`
	IssuedAt        string            `json:"issued_at"`
	ExpiresAt       string            `json:"expires_at"`
}

type OwnerAppNodePreview struct {
	Claims    OwnerAppNodePreviewClaims `json:"claims"`
	Signature []byte                    `json:"signature"`
}

// OwnerAppNodeCandidate retains the existing INITIAL candidate coordinates and
// both full public identities. Fingerprints use nodewire.IdentityFingerprint's
// existing domain; CandidateDigest retains the existing Store calculation.
type OwnerAppNodeCandidate struct {
	RequestID                 string         `json:"request_id"`
	Version                   uint64         `json:"version"`
	Mode                      string         `json:"mode"`
	State                     string         `json:"state"`
	HubID                     string         `json:"hub_id"`
	NodeID                    string         `json:"node_id"`
	NodeName                  string         `json:"node_name"`
	NodePublic                PublicIdentity `json:"node_public_identity"`
	NodeKeyFingerprint        string         `json:"node_key_fingerprint"`
	NodeKeyEpoch              uint64         `json:"node_key_epoch"`
	HubNodeControlPublic      PublicIdentity `json:"hub_node_control_public_identity"`
	HubNodeControlKeyVersion  uint64         `json:"hub_node_control_key_version"`
	HubNodeControlFingerprint string         `json:"hub_node_control_fingerprint"`
	CandidateDigest           string         `json:"candidate_digest"`
	CodeDigest                string         `json:"code_digest"`
	ExpiresAt                 string         `json:"expires_at"`
}

// OwnerAppNodeGrantClaims is displayed before explicit approval. Its head is
// the proposed next generation. ExpectedHeadVersion is the unchanged published
// head that complete must compare and swap. Every field is signed.
type OwnerAppNodeGrantClaims struct {
	Purpose                  string                 `json:"purpose"`
	Scope                    OwnerAppNodeScope      `json:"scope"`
	GrantID                  string                 `json:"grant_id"`
	ExpectedHeadVersion      uint64                 `json:"expected_head_version"`
	Profile                  string                 `json:"profile"`
	PreviousGrantID          string                 `json:"previous_grant_id"`
	ConfirmationProvenanceID string                 `json:"confirmation_provenance_id"`
	PrepareRequestID         string                 `json:"prepare_request_id"`
	PreparePacketDigest      string                 `json:"prepare_packet_digest"`
	PreviewProofDigest       string                 `json:"preview_proof_digest"`
	ServerNonce              string                 `json:"server_nonce"`
	Candidate                *OwnerAppNodeCandidate `json:"candidate"`
	Binding                  *OwnerAppNodeBinding   `json:"binding"`
	AllowedOperations        []string               `json:"allowed_operations"`
	ReadNodeStatus           bool                   `json:"read_node_status"`
	ConfirmationLimit        uint64                 `json:"confirmation_limit"`
	PreparedAt               string                 `json:"prepared_at"`
	ProofExpiresAt           string                 `json:"proof_expires_at"`
	LeaseExpiresAt           string                 `json:"lease_expires_at"`
}

type OwnerAppNodeGrant struct {
	Claims    OwnerAppNodeGrantClaims `json:"claims"`
	Signature []byte                  `json:"signature"`
}

// OwnerAppNodeBinding fixes the exact already-approved binding for status-only
// reauthorization. No bearer, code, new candidate or key rotation is involved.
type OwnerAppNodeBinding struct {
	OwnerBindingID            string         `json:"owner_binding_id"`
	OwnerID                   string         `json:"owner_id"`
	HubID                     string         `json:"hub_id"`
	NodeID                    string         `json:"node_id"`
	NodeName                  string         `json:"node_name"`
	ClientDeviceID            string         `json:"client_device_id"`
	OwnerKeyID                string         `json:"owner_key_id"`
	CredentialVersion         uint64         `json:"credential_version"`
	BindingVersion            uint64         `json:"binding_version"`
	NodePublic                PublicIdentity `json:"node_public_identity"`
	NodeKeyFingerprint        string         `json:"node_key_fingerprint"`
	NodeKeyVersion            uint64         `json:"node_key_version"`
	NodeKeyEpoch              uint64         `json:"node_key_epoch"`
	HubNodeControlPublic      PublicIdentity `json:"hub_node_control_public_identity"`
	HubNodeControlFingerprint string         `json:"hub_node_control_fingerprint"`
	HubNodeControlKeyVersion  uint64         `json:"hub_node_control_key_version"`
	ApprovedRequestID         string         `json:"approved_request_id"`
	ApprovedRequestVersion    uint64         `json:"approved_request_version"`
	ApprovedCandidateDigest   string         `json:"approved_candidate_digest"`
	ApprovedAt                string         `json:"approved_at"`
	State                     string         `json:"state"`
}
