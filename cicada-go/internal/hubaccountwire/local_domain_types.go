package hubaccountwire

import (
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

const (
	LocalDomainContractRevision             = "native-local-domain-v1"
	LocalDomainFormat                       = "cicada.native-local-domain.v1"
	LocalDomainCapabilitiesPath             = "/v2/owner/local-domains/capabilities"
	OperationLocalDomainPrepare             = "owner.local_domain.prepare"
	OperationLocalDomainActivate            = "owner.local_domain.activate"
	OperationLocalDomainStatus              = "owner.local_domain.status"
	OperationLocalDomainRevoke              = "owner.local_domain.revoke"
	OperationLocalDomainReconcile           = "owner.local_domain.reconcile"
	OperationLocalDomainNodeAvailable       = "node.local_domain.available"
	OperationLocalDomainNodeJoin            = "node.local_domain.join"
	OperationLocalDomainNodeKeyPrepare      = "node.local_domain.key_prepare"
	OperationLocalDomainNodeKeyComplete     = "node.local_domain.key_complete"
	OperationLocalDomainNodeDescribe        = "node.local_domain.describe"
	OperationLocalDomainNodeReconcile       = "node.local_domain.reconcile"
	MaxLocalDomainCapabilitiesBytes         = 4096
	MaxLocalDomainBodyBytes                 = 192 << 10
	MaxLocalDomainPageBytes                 = 128 << 10
	MaxLocalDomainOriginalBytes             = 256 << 10
	MaxLocalDomainPacketBytes               = 384 << 10
	MaxLocalDomainInnerPacketBytes          = 384 << 10
	MaxLocalDomainReconcileBodyBytes        = 640 << 10
	MaxLocalDomainReconcilePacketBytes      = 896 << 10
	MaxLocalDomainReconcileInnerPacketBytes = 896 << 10
	MaxLocalDomainNodeOriginalBytes         = 64 << 10
	MaxLocalDomainNodeReceiptBytes          = 192 << 10
	MaxLocalDomainNodeReconcilePacketBytes  = 384 << 10
	LocalDomainPrepared                     = "PREPARED"
	LocalDomainActive                       = "ACTIVE"
	LocalDomainRevoked                      = "REVOKED"
	LocalDomainExpired                      = "EXPIRED"
	LocalDomainMemberJoinedZero             = "JOINED_ZERO"
	LocalDomainMemberActive                 = "ACTIVE"
	LocalDomainMemberLeft                   = "LEFT"
	LocalDomainMemberRevoked                = "REVOKED"
	LocalDomainMemberExpired                = "EXPIRED"
)

type LocalDomainCapabilities struct {
	Format                       string   `json:"format"`
	ContractRevision             string   `json:"contract_revision"`
	Available                    bool     `json:"available"`
	ServeMode                    string   `json:"serve_mode"`
	TransportPolicy              string   `json:"transport_policy"`
	HTTPOperations               []string `json:"http_operations"`
	NodeOperations               []string `json:"node_operations"`
	Rights                       []string `json:"rights"`
	MaxActivePoliciesPerNodeUser int      `json:"max_active_policies_per_node_user"`
	OptionalPolicyExpiry         bool     `json:"optional_policy_expiry"`
}

type LocalDomainPrepare struct {
	Format       string                `json:"format"`
	Context      AppNodeRequestContext `json:"context"`
	SessionToken []byte                `json:"session_token"`
	OwnerProof   []byte                `json:"owner_proof"`
}

type LocalDomainActivate struct {
	Format       string                `json:"format"`
	Context      AppNodeRequestContext `json:"context"`
	SessionToken []byte                `json:"session_token"`
	OwnerProof   []byte                `json:"owner_proof"`
	PolicyProof  []byte                `json:"policy_proof"`
}

type LocalDomainStatusRequest LocalDomainPrepare
type LocalDomainRevoke LocalDomainPrepare

type LocalDomainReconcileRequest struct {
	Format         string                `json:"format"`
	Context        AppNodeRequestContext `json:"context"`
	OriginalPacket []byte                `json:"original_packet"`
}

type LocalDomainChallenge struct {
	Format              string                 `json:"format"`
	RequestID           string                 `json:"request_id"`
	RequestPacketDigest string                 `json:"request_packet_digest"`
	PrepareProofDigest  string                 `json:"prepare_proof_digest"`
	LocalUserReport     []byte                 `json:"local_user_report"`
	Policy              e2ee.LocalDomainPolicy `json:"policy"`
	Revision            uint64                 `json:"revision"`
	ProofExpiresAt      string                 `json:"proof_expires_at"`
	ObservedAt          string                 `json:"observed_at"`
}

type LocalDomainDescription struct {
	ContractRevision string                 `json:"contract_revision"`
	Policy           e2ee.LocalDomainPolicy `json:"policy"`
	PolicyProof      []byte                 `json:"policy_proof,omitempty"`
	State            string                 `json:"state"`
	Revision         uint64                 `json:"revision"`
	MemberCount      uint64                 `json:"member_count"`
	ObservedAt       string                 `json:"observed_at"`
}

// Result describes a durable operation outcome. Its historical description is
// never authority for a subsequent action or a renewable data-plane lease.
type LocalDomainResult struct {
	Format              string                   `json:"format"`
	Operation           string                   `json:"operation"`
	RequestID           string                   `json:"request_id"`
	RequestPacketDigest string                   `json:"request_packet_digest"`
	HubID               string                   `json:"hub_id"`
	OwnerID             string                   `json:"owner_id"`
	DeviceID            string                   `json:"device_id"`
	PolicyID            string                   `json:"policy_id"`
	PolicyEpoch         uint64                   `json:"policy_epoch"`
	State               string                   `json:"state"`
	NoEffect            bool                     `json:"no_effect"`
	ErrorCode           string                   `json:"error_code,omitempty"`
	Description         *LocalDomainDescription  `json:"description,omitempty"`
	NodeID              string                   `json:"node_id,omitempty"`
	Policies            []LocalDomainDescription `json:"policies,omitempty"`
	NextCursor          string                   `json:"next_cursor,omitempty"`
	ObservedAt          string                   `json:"observed_at"`
}

type LocalDomainReconciled struct {
	Format               string `json:"format"`
	RequestID            string `json:"request_id"`
	RequestPacketDigest  string `json:"request_packet_digest"`
	HubID                string `json:"hub_id"`
	OwnerID              string `json:"owner_id"`
	DeviceID             string `json:"device_id"`
	OriginalOperation    string `json:"original_operation"`
	OriginalRequestID    string `json:"original_request_id"`
	OriginalPacketDigest string `json:"original_packet_digest"`
	State                string `json:"state"`
	ReceiptPacket        []byte `json:"receipt_packet"`
	ObservedAt           string `json:"observed_at"`
}

type LocalDomainSelection struct {
	PolicyID     string `json:"policy_id"`
	PolicyEpoch  uint64 `json:"policy_epoch"`
	PolicyDigest string `json:"policy_digest"`
}

type LocalDomainNodeAvailable struct {
	ContractRevision string `json:"contract_revision"`
	LocalUserScope   string `json:"local_user_scope"`
	LocalUserReport  []byte `json:"local_user_report"`
}

type LocalDomainNodeAvailableResult struct {
	ContractRevision string                   `json:"contract_revision"`
	LocalUserScope   string                   `json:"local_user_scope"`
	Policies         []LocalDomainDescription `json:"policies"`
	ObservedAt       string                   `json:"observed_at"`
}

type LocalDomainNodeJoin struct {
	ContractRevision string               `json:"contract_revision"`
	Selection        LocalDomainSelection `json:"selection"`
	LocalUserScope   string               `json:"local_user_scope"`
	AttemptID        string               `json:"attempt_id"`
	Runtime          string               `json:"runtime"`
	NativeSessionID  string               `json:"native_session_id"`
	Workspace        string               `json:"workspace"`
	EndpointName     string               `json:"endpoint_name"`
}

type LocalDomainMember struct {
	MemberID                  string               `json:"member_id"`
	Selection                 LocalDomainSelection `json:"selection"`
	Revision                  uint64               `json:"revision"`
	State                     string               `json:"state"`
	NodeID                    string               `json:"node_id"`
	LocalUserScope            string               `json:"local_user_scope"`
	NativeSessionID           string               `json:"native_session_id"`
	Runtime                   string               `json:"runtime"`
	Workspace                 string               `json:"workspace"`
	EndpointID                string               `json:"endpoint_id"`
	PrincipalID               string               `json:"principal_id"`
	BindingID                 string               `json:"binding_id"`
	BindingEpoch              uint64               `json:"binding_epoch"`
	NetworkAccessBindingID    string               `json:"network_access_binding_id"`
	NetworkAccessEpoch        uint64               `json:"network_access_epoch"`
	NetworkMembershipRevision uint64               `json:"network_membership_revision"`
	EndpointNetworkRevision   uint64               `json:"endpoint_network_revision"`
	MembershipRevision        uint64               `json:"membership_revision"`
	EndpointJoinRevision      uint64               `json:"endpoint_join_revision"`
	LeaseOwner                string               `json:"lease_owner"`
	CandidateVersion          uint64               `json:"candidate_version"`
	CandidateKeyID            string               `json:"candidate_key_id"`
	CandidateFingerprint      string               `json:"candidate_fingerprint"`
	CandidateProofDigest      string               `json:"candidate_proof_digest"`
}

// Join returns the original native identity and scope, not another synthetic
// Thread. Candidate publication follows this zero-right binding allocation.
type LocalDomainNodeJoinResult struct {
	ContractRevision   string                              `json:"contract_revision"`
	Description        LocalDomainDescription              `json:"description"`
	Member             LocalDomainMember                   `json:"member"`
	Endpoint           nodewire.EndpointRegistrationResult `json:"endpoint"`
	NativeContextScope LocalDomainContextScope             `json:"native_context_scope"`
	SessionToken       string                              `json:"session_token"`
	LeaseExpiresAt     string                              `json:"lease_expires_at"`
	Reused             bool                                `json:"reused"`
}

type LocalDomainContextScope struct {
	HubID                string `json:"hub_id"`
	NetworkID            string `json:"network_id"`
	GroupID              string `json:"group_id"`
	GroupContextPolicy   string `json:"group_context_policy"`
	NetworkContextPolicy string `json:"network_context_policy"`
}

type LocalDomainNodeKeyResult struct {
	ContractRevision string                      `json:"contract_revision"`
	Description      LocalDomainDescription      `json:"description"`
	Member           LocalDomainMember           `json:"member"`
	Grant            LocalDomainEndpointKeyGrant `json:"grant"`
}

// These fields are identical to the complete generic Group Endpoint manifest.
// The domain evidence variant permits an empty expiry only under its verified
// persistent policy; existing Owner/Pair manifest interval rules stay strict.
type LocalDomainKeyManifest struct {
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
	CandidateAttestation    []byte              `json:"candidate_attestation"`
	OwnerKeyID              string              `json:"owner_key_id"`
	IssuedAt                string              `json:"issued_at"`
	ExpiresAt               string              `json:"expires_at"`
	Digest                  string              `json:"digest"`
}

type LocalDomainKeyChallenge struct {
	ContractRevision string                            `json:"contract_revision"`
	ChallengeID      string                            `json:"challenge_id"`
	ExpectedRevision uint64                            `json:"expected_revision"`
	Member           LocalDomainMember                 `json:"member"`
	Manifest         LocalDomainKeyManifest            `json:"manifest"`
	Claims           e2ee.LocalDomainEndpointKeyClaims `json:"claims"`
	ExpiresAt        string                            `json:"expires_at"`
}

type LocalDomainNodeKeyPrepare struct {
	ContractRevision string               `json:"contract_revision"`
	Selection        LocalDomainSelection `json:"selection"`
	MemberID         string               `json:"member_id"`
	ExpectedRevision uint64               `json:"expected_revision"`
}

type LocalDomainNodeKeyComplete struct {
	ContractRevision string               `json:"contract_revision"`
	Selection        LocalDomainSelection `json:"selection"`
	ChallengeID      string               `json:"challenge_id"`
	MemberID         string               `json:"member_id"`
	ExpectedRevision uint64               `json:"expected_revision"`
	NodeProof        []byte               `json:"node_proof"`
}

type LocalDomainNodeDescribe struct {
	ContractRevision string               `json:"contract_revision"`
	Selection        LocalDomainSelection `json:"selection"`
	LocalUserScope   string               `json:"local_user_scope"`
}

type LocalDomainNodeReconcile struct {
	ContractRevision string `json:"contract_revision"`
	Nonce            []byte `json:"nonce"`
	IssuedAt         string `json:"issued_at"`
	OriginalPacket   []byte `json:"original_packet"`
}

type LocalDomainNodeReconciled struct {
	ContractRevision     string `json:"contract_revision"`
	OriginalOperation    string `json:"original_operation"`
	OriginalOperationID  string `json:"original_operation_id"`
	OriginalSequence     uint64 `json:"original_sequence"`
	OriginalPacketDigest string `json:"original_packet_digest"`
	State                string `json:"state"`
	ReceiptPacket        []byte `json:"receipt_packet"`
	ObservedAt           string `json:"observed_at"`
}

type LocalDomainEndpointKeyGrant struct {
	ContractRevision string                 `json:"contract_revision"`
	Member           LocalDomainMember      `json:"member"`
	Manifest         LocalDomainKeyManifest `json:"manifest"`
	PolicyProof      []byte                 `json:"policy_proof"`
	NodeProof        []byte                 `json:"node_proof"`
}

type LocalDomainCurrent struct {
	ContractRevision string               `json:"contract_revision"`
	Selection        LocalDomainSelection `json:"selection"`
	Revision         uint64               `json:"revision"`
	State            string               `json:"state"`
	Operation        string               `json:"operation"`
	AttemptID        string               `json:"attempt_id"`
	Sender           LocalDomainMember    `json:"sender"`
	Receiver         LocalDomainMember    `json:"receiver"`
	ObservedAt       string               `json:"observed_at"`
	ExpiresAt        string               `json:"expires_at"`
}

func LocalDomainHTTPOperations() []string {
	return []string{OperationLocalDomainPrepare, OperationLocalDomainActivate, OperationLocalDomainStatus, OperationLocalDomainRevoke, OperationLocalDomainReconcile}
}

func LocalDomainNodeOperations() []string {
	return []string{OperationLocalDomainNodeAvailable, OperationLocalDomainNodeJoin, OperationLocalDomainNodeKeyPrepare, OperationLocalDomainNodeKeyComplete, OperationLocalDomainNodeDescribe, OperationLocalDomainNodeReconcile}
}

func LocalDomainHTTPPath(operation string) string {
	switch operation {
	case OperationLocalDomainPrepare:
		return "/v2/owner/local-domains/prepare"
	case OperationLocalDomainActivate:
		return "/v2/owner/local-domains/activate"
	case OperationLocalDomainStatus:
		return "/v2/owner/local-domains/status"
	case OperationLocalDomainRevoke:
		return "/v2/owner/local-domains/revoke"
	case OperationLocalDomainReconcile:
		return "/v2/owner/local-domains/reconcile"
	}
	return ""
}

func LocalDomainOwnerPurpose(operation string) string {
	switch operation {
	case OperationLocalDomainPrepare:
		return e2ee.OwnerLocalDomainPreparePurpose
	case OperationLocalDomainActivate:
		return e2ee.OwnerLocalDomainActivatePurpose
	case OperationLocalDomainStatus:
		return e2ee.OwnerLocalDomainStatusPurpose
	case OperationLocalDomainRevoke:
		return e2ee.OwnerLocalDomainRevokePurpose
	}
	return ""
}
