package hubaccountwire

import "github.com/cicada-ai/cicada/internal/e2ee"

const (
	InstallationContractRevision        = "installation-registration-v1.1"
	InstallationImplementationPhase     = "CONTRACT_CANDIDATE"
	InstallationPublicAvailable         = false
	InstallationFormat                  = e2ee.InstallationRegistrationFormat
	InstallationPacketFormat            = "cicada.installation-packet.v1"
	InstallationCapabilitiesPath        = "/v2/installations/capabilities"
	OperationInstallationStart          = "installation.register.start"
	OperationInstallationProve          = "installation.register.prove"
	OperationInstallationPoll           = "installation.register.poll"
	OperationInstallationAccept         = "installation.register.accept"
	OperationInstallationSelf           = "installation.self.status"
	OperationInstallationHeartbeat      = "installation.self.heartbeat"
	OperationInstallationReconcile      = "installation.reconcile"
	OperationOwnerInstallationPrepare   = "owner.installation.prepare"
	OperationOwnerInstallationComplete  = "owner.installation.complete"
	OperationOwnerInstallationRevoke    = "owner.installation.revoke"
	OperationOwnerAppAccessPrepare      = "owner.app_access.prepare"
	OperationOwnerAppAccessComplete     = "owner.app_access.complete"
	OperationOwnerAppAccessRevoke       = "owner.app_access.revoke"
	OperationOwnerConnectionsRead       = "owner.connections.read"
	InstallationPending                 = "PENDING"
	InstallationOwnerApproved           = "OWNER_APPROVED"
	InstallationRegistered              = "REGISTERED"
	InstallationExpired                 = "EXPIRED"
	InstallationRevoked                 = "REVOKED"
	InstallationRejectedFenced          = "REJECTED_FENCED"
	InstallationCompleted               = "COMPLETED"
	InstallationReadExpired             = "READ_EXPIRED"
	InstallationOwnerReadAuth           = "OWNER_READ_PROOF"
	InstallationRecipientGrantsAuth     = "RECIPIENT_GRANTS"
	InstallationNewRegisteredOnly       = "NEW_REGISTERED_ONLY"
	InstallationLegacyAdopted           = "VERIFIED_LEGACY_ADOPTED"
	InstallationHeartbeatSource         = "store.hub_installation_subjects_v1.last_heartbeat"
	MaxInstallationTicketBytes          = 1024
	MaxInstallationBodyBytes            = 96 * 1024
	MaxInstallationPacketBytes          = 128 * 1024
	MaxInstallationOriginalBytes        = 128 * 1024
	MaxInstallationReceiptBytes         = 256 * 1024
	MaxInstallationReconcileBodyBytes   = 352 * 1024
	MaxInstallationReconcilePacketBytes = 640 * 1024
	MaxInstallationEffectiveGrants      = 16
	MaxInstallationPageSize             = 50
)

type InstallationCandidateBase = e2ee.InstallationCandidateBase
type InstallationCandidate = e2ee.InstallationCandidate
type InstallationApprovalBase = e2ee.InstallationApprovalBase
type InstallationSubject = e2ee.InstallationSubject

type InstallationCapabilities struct {
	Format           string   `json:"format"`
	ContractRevision string   `json:"contract_revision"`
	Available        bool     `json:"available"`
	ServeMode        string   `json:"serve_mode"`
	TransportPolicy  string   `json:"transport_policy"`
	Operations       []string `json:"operations"`
	TrustModes       []string `json:"trust_modes"`
	ReadProfiles     []string `json:"read_profiles"`
}

type InstallationSelfContext struct {
	HubID                      string `json:"hub_id"`
	InstallationID             string `json:"installation_id"`
	AttemptID                  string `json:"attempt_id"`
	ParentRegistrationID       string `json:"parent_registration_id"`
	RegistrationEpoch          uint64 `json:"registration_epoch"`
	AdmissionCredentialVersion uint64 `json:"admission_credential_version"`
	RequestID                  string `json:"request_id"`
	Nonce                      []byte `json:"nonce"`
	IssuedAt                   string `json:"issued_at"`
}

// Closed, purpose-specific packets, separate from all frozen account/Client/
// Node wire formats. Header authentication is key possession, never authority.
type InstallationPacket struct {
	Format       string                   `json:"format"`
	Version      int                      `json:"version"`
	Operation    string                   `json:"operation"`
	SenderPublic e2ee.PublicIdentity      `json:"sender_public_identity"`
	Self         *InstallationSelfContext `json:"self,omitempty"`
	Account      *AppNodeRequestContext   `json:"account,omitempty"`
	Packet       []byte                   `json:"packet"`
}

type InstallationResponsePacket struct {
	Format              string `json:"format"`
	Version             int    `json:"version"`
	Operation           string `json:"operation"`
	RequestID           string `json:"request_id"`
	RequestPacketDigest string `json:"request_packet_digest"`
	ReceiverKeyID       string `json:"receiver_key_id"`
	Packet              []byte `json:"packet"`
}

// Authentication of an immutable old original is not a fresh admission.
// This distinct result must only enter receipt recovery or permanent fencing.
type InstallationHistoricalOriginal struct {
	Header       InstallationPacket
	PacketDigest string
}

type InstallationAccessChallenge struct {
	Format              string                        `json:"format"`
	RequestID           string                        `json:"request_id"`
	RequestPacketDigest string                        `json:"request_packet_digest"`
	Claims              e2ee.InstallationAccessClaims `json:"claims"`
}

type InstallationAccessResult struct {
	Format              string               `json:"format"`
	Operation           string               `json:"operation"`
	RequestID           string               `json:"request_id"`
	RequestPacketDigest string               `json:"request_packet_digest"`
	Grant               InstallationGrantRef `json:"grant"`
	Outcome             string               `json:"outcome"`
	ErrorCode           string               `json:"error_code"`
	ObservedAt          string               `json:"observed_at"`
}

type InstallationStart struct {
	Format                string                `json:"format"`
	Candidate             InstallationCandidate `json:"candidate"`
	SubjectSignatureProof []byte                `json:"subject_signature_proof"`
	// ADOPT_EXISTING Node only; NEW_SUBJECT and App require nil. Encrypted
	// to Hub only, never Candidate, Owner challenge, ticket or diagnostics.
	NodeCredential []byte `json:"node_credential,omitempty"`
}

// Independent current Store data, not a candidate's authentication claim.
type InstallationLegacyCurrent struct {
	OwnerID          string
	BindingState     string
	CredentialState  string
	CredentialDigest string
	Node             e2ee.InstallationNodeRef
}

type InstallationChallengeEnvelope struct {
	Header e2ee.InstallationKEMChallenge `json:"header"`
	Packet []byte                        `json:"packet"`
}

type InstallationStartResult struct {
	Format              string                        `json:"format"`
	RequestID           string                        `json:"request_id"`
	RequestPacketDigest string                        `json:"request_packet_digest"`
	CandidateDigest     string                        `json:"candidate_digest"`
	AttemptID           string                        `json:"attempt_id"`
	Selector            string                        `json:"selector"`
	State               string                        `json:"state"`
	ExpiresAt           string                        `json:"expires_at"`
	AdmissionChallenge  InstallationChallengeEnvelope `json:"admission_challenge"`
	SubjectChallenge    InstallationChallengeEnvelope `json:"subject_challenge"`
}

type InstallationProve struct {
	Format            string `json:"format"`
	ChallengeID       string `json:"challenge_id"`
	StartPacketDigest string `json:"start_packet_digest"`
	AdmissionReceipt  []byte `json:"admission_receipt"`
	SubjectReceipt    []byte `json:"subject_receipt"`
}

type InstallationPoll struct {
	Format          string `json:"format"`
	CandidateDigest string `json:"candidate_digest"`
}

type InstallationAccept struct {
	Format                string `json:"format"`
	ApprovalReceiptDigest string `json:"approval_receipt_digest"`
	ApprovalDigest        string `json:"approval_digest"`
	CapsuleDigest         string `json:"capsule_digest"`
	OwnerProofDigest      string `json:"owner_proof_digest"`
	ACKNonce              []byte `json:"ack_nonce"`
	SubjectAcceptance     []byte `json:"subject_acceptance"`
}

type InstallationSelfRequest struct {
	Format string `json:"format"`
}

type InstallationHeartbeat struct {
	Format string `json:"format"`
}

type InstallationOwnerPrepare struct {
	Format          string `json:"format"`
	SessionToken    []byte `json:"session_token"`
	AttemptID       string `json:"attempt_id"`
	CandidateDigest string `json:"candidate_digest"`
	OwnerIntent     []byte `json:"owner_intent"`
}

type InstallationOwnerChallenge struct {
	Format              string                   `json:"format"`
	RequestID           string                   `json:"request_id"`
	RequestPacketDigest string                   `json:"request_packet_digest"`
	Candidate           InstallationCandidate    `json:"candidate"`
	Approval            InstallationApprovalBase `json:"approval"`
}

type InstallationOwnerComplete struct {
	Format       string `json:"format"`
	SessionToken []byte `json:"session_token"`
	OwnerProof   []byte `json:"owner_proof"`
	TrustCapsule []byte `json:"trust_capsule"`
}

type InstallationOwnerRevoke struct {
	Format                string `json:"format"`
	SessionToken          []byte `json:"session_token"`
	ParentRegistrationID  string `json:"parent_registration_id"`
	SubjectRegistrationID string `json:"subject_registration_id"`
	ExpectedRevision      uint64 `json:"expected_revision"`
	OwnerProof            []byte `json:"owner_proof"`
}

type InstallationGrantTarget struct {
	Recipient        e2ee.InstallationRecipient    `json:"recipient"`
	Profile          string                        `json:"profile"`
	Target           e2ee.InstallationAccessTarget `json:"target"`
	ExpectedRevision uint64                        `json:"expected_revision"`
}

type InstallationAccessPrepare struct {
	Format       string                  `json:"format"`
	SessionToken []byte                  `json:"session_token"`
	GrantID      string                  `json:"grant_id"`
	Target       InstallationGrantTarget `json:"target"`
	OwnerIntent  []byte                  `json:"owner_intent"`
}

type InstallationAccessComplete struct {
	Format       string `json:"format"`
	SessionToken []byte `json:"session_token"`
	OwnerProof   []byte `json:"owner_proof"`
}

type InstallationAccessRevoke struct {
	Format           string `json:"format"`
	SessionToken     []byte `json:"session_token"`
	GrantID          string `json:"grant_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
	OwnerProof       []byte `json:"owner_proof"`
}

type InstallationReadAuthorization struct {
	Kind           string   `json:"kind"`
	OwnerReadProof []byte   `json:"owner_read_proof,omitempty"`
	GrantIDs       []string `json:"grant_ids,omitempty"`
}

type InstallationConnectionsRead struct {
	Format        string                        `json:"format"`
	SessionToken  []byte                        `json:"session_token"`
	Query         e2ee.InstallationReadQuery    `json:"query"`
	Authorization InstallationReadAuthorization `json:"authorization"`
}

type InstallationGrantRef struct {
	GrantID               string                        `json:"grant_id"`
	OriginContract        string                        `json:"origin_contract"`
	Profile               string                        `json:"profile"`
	SubjectRegistrationID string                        `json:"subject_registration_id"`
	RecipientDeviceID     string                        `json:"recipient_device_id"`
	Target                e2ee.InstallationAccessTarget `json:"target"`
	State                 string                        `json:"state"`
	Revision              uint64                        `json:"revision"`
	ExpiresAt             string                        `json:"expires_at"`
}

// A parent remains REGISTERED while another subject attempt is PENDING.
// Inventory relationships never imply auth provenance or grant inheritance.
type InstallationParent struct {
	InstallationID             string `json:"installation_id"`
	RegistrationID             string `json:"registration_id"`
	RegistrationEpoch          uint64 `json:"registration_epoch"`
	AdmissionCredentialVersion uint64 `json:"admission_credential_version"`
	OwnerID                    string `json:"owner_id"`
	State                      string `json:"state"`
	Revision                   uint64 `json:"revision"`
}

type InstallationSubjectBinding struct {
	SubjectRegistrationID    string                    `json:"subject_registration_id"`
	SubjectRegistrationEpoch uint64                    `json:"subject_registration_epoch"`
	ParentRegistrationID     string                    `json:"parent_registration_id"`
	InstallationID           string                    `json:"installation_id"`
	OwnerID                  string                    `json:"owner_id"`
	Kind                     string                    `json:"kind"`
	InstanceID               string                    `json:"instance_id"`
	Public                   e2ee.PublicIdentity       `json:"public_identity"`
	State                    string                    `json:"state"`
	Revision                 uint64                    `json:"revision"`
	AuthProvenance           string                    `json:"auth_provenance"`
	NodeBinding              *e2ee.OwnerAppNodeBinding `json:"node_binding,omitempty"`
}

// Owner inventory references disclose no secret or fabricated legacy candidate.
// The full candidate is returned only by the authenticated Owner preview.
type InstallationPendingAttemptRef struct {
	AttemptID          string `json:"attempt_id"`
	CandidateDigest    string `json:"candidate_digest"`
	InstallationID     string `json:"installation_id"`
	SubjectKind        string `json:"subject_kind"`
	SubjectFingerprint string `json:"subject_fingerprint"`
	State              string `json:"state"`
	Revision           uint64 `json:"revision"`
	ExpiresAt          string `json:"expires_at"`
}

type InstallationResult struct {
	Format              string                      `json:"format"`
	Operation           string                      `json:"operation"`
	RequestID           string                      `json:"request_id"`
	RequestPacketDigest string                      `json:"request_packet_digest"`
	AttemptID           string                      `json:"attempt_id"`
	AttemptState        string                      `json:"attempt_state"`
	Revision            uint64                      `json:"revision"`
	Parent              *InstallationParent         `json:"parent,omitempty"`
	Subject             *InstallationSubjectBinding `json:"subject,omitempty"`
	Outcome             string                      `json:"outcome"`
	ErrorCode           string                      `json:"error_code"`
	Grants              []InstallationGrantRef      `json:"grants"`
	ObservedAt          string                      `json:"observed_at"`
}

type InstallationApproved struct {
	Result       InstallationResult `json:"result"`
	OwnerProof   []byte             `json:"owner_proof"`
	TrustCapsule []byte             `json:"trust_capsule"`
}

type InstallationConnectionsSnapshot struct {
	Format              string                          `json:"format"`
	RequestID           string                          `json:"request_id"`
	RequestPacketDigest string                          `json:"request_packet_digest"`
	SnapshotRevision    uint64                          `json:"snapshot_revision"`
	ActorScope          e2ee.InstallationAccountScope   `json:"actor_scope"`
	OwnParent           *InstallationParent             `json:"own_parent,omitempty"`
	OwnSubject          *InstallationSubjectBinding     `json:"own_subject,omitempty"`
	Grants              []InstallationGrantRef          `json:"grants"`
	Parents             []InstallationParent            `json:"parents"`
	Subjects            []InstallationSubjectBinding    `json:"subjects"`
	PendingAttempts     []InstallationPendingAttemptRef `json:"pending_attempts"`
	Nodes               []AppNodeObservation            `json:"nodes"`
	Pairs               []NativePairResult              `json:"pairs"`
	NextCursor          string                          `json:"next_cursor"`
	Truncated           bool                            `json:"truncated"`
	ObservedAt          string                          `json:"observed_at"`
}

type InstallationReconcile struct {
	Format               string `json:"format"`
	OriginalOperation    string `json:"original_operation"`
	OriginalRequestID    string `json:"original_request_id"`
	OriginalPacketDigest string `json:"original_packet_digest"`
	OriginalPacket       []byte `json:"original_packet"`
}

type InstallationReconciled struct {
	Format               string `json:"format"`
	RequestID            string `json:"request_id"`
	RequestPacketDigest  string `json:"request_packet_digest"`
	OriginalOperation    string `json:"original_operation"`
	OriginalRequestID    string `json:"original_request_id"`
	OriginalPacketDigest string `json:"original_packet_digest"`
	State                string `json:"state"`
	ReceiptPacket        []byte `json:"receipt_packet"`
	ObservedAt           string `json:"observed_at"`
}
