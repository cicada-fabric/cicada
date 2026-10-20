package e2ee

// Installation registration is separate from OwnerDeviceGrant v1, N2/N3 and
// peer authority. These types grant no permission without current Store Guard.
const (
	InstallationRegistrationFormat = "cicada.installation-registration.v1"
	InstallationNodeSubject        = "NODE_CONTROL"
	InstallationAppSubject         = "APP_DEVICE"
	InstallationNewSubject         = "NEW_SUBJECT"
	InstallationAdoptExisting      = "ADOPT_EXISTING"
	InstallationRegisterPurpose    = "OWNER_INSTALLATION_REGISTER"
	InstallationReadPurpose        = "OWNER_INSTALLATION_READ"
	InstallationAccessPurpose      = "OWNER_APP_ACCESS_READ"
	InstallationNodeReadProfile    = "N3_NODE_STATUS_READ"
	InstallationPairReadProfile    = "N3_PAIR_STATUS_READ"
	InstallationAdmissionKEM       = "ADMISSION_KEM"
	InstallationSubjectKEM         = "SUBJECT_KEM"
	InstallationFirstOOB           = "FIRST_OOB"
	InstallationExistingLocalPin   = "EXISTING_LOCAL_PIN"
	InstallationRegisteredParent   = "REGISTERED_PARENT"
	InstallationLegacyNode         = "LEGACY_NODE"
	MaxInstallationProofBytes      = 64 * 1024
	MaxInstallationOriginBytes     = 256
	MaxInstallationHubIDBytes      = 96
)

type InstallationHubRef struct {
	Origin          string         `json:"origin"`
	HubID           string         `json:"hub_id"`
	Public          PublicIdentity `json:"public_identity"`
	KeyVersion      uint64         `json:"key_version"`
	Fingerprint     string         `json:"fingerprint"`
	TransportPolicy string         `json:"transport_policy"`
}

type InstallationNodeRef struct {
	NodeID                    string         `json:"node_id"`
	Public                    PublicIdentity `json:"public_identity"`
	KeyVersion                uint64         `json:"key_version"`
	KeyEpoch                  uint64         `json:"key_epoch"`
	HubNodeControlPublic      PublicIdentity `json:"hub_node_control_public_identity"`
	HubNodeControlKeyVersion  uint64         `json:"hub_node_control_key_version"`
	HubNodeControlFingerprint string         `json:"hub_node_control_fingerprint"`
	CredentialCommitment      string         `json:"credential_commitment"`
	RequestID                 string         `json:"request_id"`
	RequestVersion            uint64         `json:"request_version"`
	CandidateDigest           string         `json:"candidate_digest"`
	CandidateExpiresAt        string         `json:"candidate_expires_at"`
	BindingID                 string         `json:"binding_id"`
	BindingVersion            uint64         `json:"binding_version"`
	CredentialVersion         uint64         `json:"credential_version"`
}

type InstallationAppRef struct {
	DeviceID    string         `json:"device_id"`
	Public      PublicIdentity `json:"public_identity"`
	KeyVersion  uint64         `json:"key_version"`
	DeviceEpoch uint64         `json:"device_epoch"`
}

type InstallationSubject struct {
	Kind string               `json:"kind"`
	Mode string               `json:"mode"`
	Node *InstallationNodeRef `json:"node,omitempty"`
	App  *InstallationAppRef  `json:"app,omitempty"`
}

type InstallationExistingTrust struct {
	Source                     string `json:"source"`
	ParentRegistrationID       string `json:"parent_registration_id"`
	RegistrationEpoch          uint64 `json:"registration_epoch"`
	AdmissionCredentialVersion uint64 `json:"admission_credential_version"`
	OwnerID                    string `json:"owner_id"`
	OwnerKeyID                 string `json:"owner_key_id"`
	OwnerPublicDigest          string `json:"owner_public_digest"`
	LocalTrustVersion          uint64 `json:"local_trust_version"`
}

type InstallationTrustSource struct {
	Kind     string                     `json:"kind"`
	Existing *InstallationExistingTrust `json:"existing,omitempty"`
}

// This is independent expected local state, never the Hub's claimed pin.
// Consumers populate it only from their guarded existing local trust/admission
// stores. A candidate's Existing descriptor cannot substitute for this input.
type InstallationLocalPin struct {
	Source                     string
	Hub                        InstallationHubRef
	InstallationID             string
	ParentRegistrationID       string
	RegistrationEpoch          uint64
	AdmissionCredentialVersion uint64
	AdmissionPublic            PublicIdentity
	RegistrationState          string
	OwnerID                    string
	OwnerPublic                PublicIdentity
	TrustState                 string
	TrustVersion               uint64
	LegacyNode                 *InstallationNodeRef
	LegacyNodeState            string
}

// No digest, commitment, challenge, capsule or signature derived from this
// base may be added to it. Local signed times are immutable across all retries.
type InstallationCandidateBase struct {
	Format          string                  `json:"format"`
	Hub             InstallationHubRef      `json:"hub"`
	InstallationID  string                  `json:"installation_id"`
	AttemptID       string                  `json:"attempt_id"`
	AdmissionPublic PublicIdentity          `json:"admission_public_identity"`
	Components      []string                `json:"components"`
	Subject         InstallationSubject     `json:"subject"`
	Trust           InstallationTrustSource `json:"trust"`
	IssuedAt        string                  `json:"issued_at"`
	ExpiresAt       string                  `json:"expires_at"`
}

type InstallationCandidate struct {
	Base            InstallationCandidateBase `json:"base"`
	CandidateDigest string                    `json:"candidate_digest"`
	OOBCommitment   string                    `json:"oob_commitment"`
}

// Everything in ApprovalBase precedes capsule creation. In particular, it has
// no capsule digest, ACK nonce/commitment or final Owner proof/signature.
type InstallationApprovalBase struct {
	Format                  string                   `json:"format"`
	CandidateDigest         string                   `json:"candidate_digest"`
	OOBCommitment           string                   `json:"oob_commitment"`
	InstallationID          string                   `json:"installation_id"`
	AttemptID               string                   `json:"attempt_id"`
	PossessionReceiptDigest string                   `json:"possession_receipt_digest"`
	Scope                   InstallationAccountScope `json:"scope"`
	SubjectDigest           string                   `json:"subject_digest"`
	ExpectedRevision        uint64                   `json:"expected_revision"`
	PrepareRequestID        string                   `json:"prepare_request_id"`
	PreparePacketDigest     string                   `json:"prepare_packet_digest"`
	PreviewProofDigest      string                   `json:"preview_proof_digest"`
	ServerNonce             string                   `json:"server_nonce"`
	PreparedAt              string                   `json:"prepared_at"`
	AttemptExpiresAt        string                   `json:"attempt_expires_at"`
	ProofExpiresAt          string                   `json:"proof_expires_at"`
	AcceptBefore            string                   `json:"accept_before"`
}

type InstallationOwnerClaims struct {
	Version       int                      `json:"version"`
	Purpose       string                   `json:"purpose"`
	Approval      InstallationApprovalBase `json:"approval"`
	CapsuleDigest string                   `json:"capsule_digest"`
	ACKCommitment string                   `json:"ack_commitment"`
}

type InstallationOwnerProof struct {
	Claims    InstallationOwnerClaims `json:"claims"`
	Signature []byte                  `json:"signature"`
}

// Both secret values are transient and addressed only to the local admission
// key. OOBSecret must never be echoed to Hub. ACKNonce is a separate random value.
type InstallationTrustCapsule struct {
	Format      string                   `json:"format"`
	Approval    InstallationApprovalBase `json:"approval"`
	OwnerPublic PublicIdentity           `json:"owner_public_identity"`
	OOBSecret   []byte                   `json:"oob_secret"`
	ACKNonce    []byte                   `json:"ack_nonce"`
}

type InstallationKEMChallenge struct {
	Format            string `json:"format"`
	Purpose           string `json:"purpose"`
	CandidateDigest   string `json:"candidate_digest"`
	OOBCommitment     string `json:"oob_commitment"`
	HubID             string `json:"hub_id"`
	InstallationID    string `json:"installation_id"`
	AttemptID         string `json:"attempt_id"`
	StartPacketDigest string `json:"start_packet_digest"`
	ChallengeID       string `json:"challenge_id"`
	RecipientKeyID    string `json:"recipient_key_id"`
	Nonce             []byte `json:"nonce"`
	IssuedAt          string `json:"issued_at"`
	ExpiresAt         string `json:"expires_at"`
}

// A subject receipt contains the decrypted subject challenge. The admission
// receipt additionally binds the exact subject receipt ciphertext digest.
type InstallationKEMReceipt struct {
	Format               string                   `json:"format"`
	Challenge            InstallationKEMChallenge `json:"challenge"`
	ProveRequestID       string                   `json:"prove_request_id"`
	SubjectReceiptDigest string                   `json:"subject_receipt_digest"`
}

type InstallationPossession struct {
	CandidateDigest   string `json:"candidate_digest"`
	OOBCommitment     string `json:"oob_commitment"`
	ChallengeID       string `json:"challenge_id"`
	StartPacketDigest string `json:"start_packet_digest"`
	AdmissionKeyID    string `json:"admission_key_id"`
	SubjectKeyID      string `json:"subject_key_id"`
	ProveRequestID    string `json:"prove_request_id"`
	VerifiedAt        string `json:"verified_at"`
}

type InstallationSubjectAccept struct {
	Format           string `json:"format"`
	CandidateDigest  string `json:"candidate_digest"`
	ApprovalDigest   string `json:"approval_digest"`
	CapsuleDigest    string `json:"capsule_digest"`
	OwnerProofDigest string `json:"owner_proof_digest"`
	ACKNonce         []byte `json:"ack_nonce"`
	AcceptRequestID  string `json:"accept_request_id"`
	SubjectDigest    string `json:"subject_digest"`
}

type InstallationReadQuery struct {
	HubID        string   `json:"hub_id"`
	AccountID    string   `json:"account_id"`
	OwnerID      string   `json:"owner_id"`
	DeviceID     string   `json:"device_id"`
	AccountEpoch uint64   `json:"account_epoch"`
	DeviceEpoch  uint64   `json:"device_epoch"`
	RequestID    string   `json:"request_id"`
	Nonce        string   `json:"nonce"`
	TargetKind   string   `json:"target_kind"`
	TargetIDs    []string `json:"target_ids"`
	PageSize     uint64   `json:"page_size"`
	Cursor       string   `json:"cursor"`
}

type InstallationOwnerReadClaims struct {
	Version     int                      `json:"version"`
	Purpose     string                   `json:"purpose"`
	Scope       InstallationAccountScope `json:"scope"`
	RequestID   string                   `json:"request_id"`
	Nonce       string                   `json:"nonce"`
	QueryDigest string                   `json:"query_digest"`
	IssuedAt    string                   `json:"issued_at"`
	ExpiresAt   string                   `json:"expires_at"`
}

type InstallationOwnerReadProof struct {
	Claims    InstallationOwnerReadClaims `json:"claims"`
	Signature []byte                      `json:"signature"`
}

type InstallationRecipient struct {
	SubjectRegistrationID    string         `json:"subject_registration_id"`
	SubjectRegistrationEpoch uint64         `json:"subject_registration_epoch"`
	DeviceID                 string         `json:"device_id"`
	DevicePublic             PublicIdentity `json:"device_public_identity"`
	DeviceEpoch              uint64         `json:"device_epoch"`
}

type InstallationAccessTarget struct {
	NodeBindingID      string `json:"node_binding_id"`
	NodeBindingVersion uint64 `json:"node_binding_version"`
	NodeKeyEpoch       uint64 `json:"node_key_epoch"`
	PairID             string `json:"pair_id"`
}

// Closed read profiles only. This cannot sign as Owner, mint a Pair consent,
// use old CLIENT_CONTROL or authorize Worker/Manager/native operations.
type InstallationAccessClaims struct {
	Version             int                      `json:"version"`
	Purpose             string                   `json:"purpose"`
	Scope               InstallationAccountScope `json:"scope"`
	GrantID             string                   `json:"grant_id"`
	Recipient           InstallationRecipient    `json:"recipient"`
	Profile             string                   `json:"profile"`
	Target              InstallationAccessTarget `json:"target"`
	ExpectedRevision    uint64                   `json:"expected_revision"`
	PrepareRequestID    string                   `json:"prepare_request_id"`
	PreparePacketDigest string                   `json:"prepare_packet_digest"`
	ServerNonce         string                   `json:"server_nonce"`
	PreparedAt          string                   `json:"prepared_at"`
	ProofExpiresAt      string                   `json:"proof_expires_at"`
	ExpiresAt           string                   `json:"expires_at"`
}

type InstallationAccessProof struct {
	Claims    InstallationAccessClaims `json:"claims"`
	Signature []byte                   `json:"signature"`
}
