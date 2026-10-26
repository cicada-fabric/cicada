package hubaccountwire

import "github.com/cicada-ai/cicada/internal/e2ee"

const (
	OwnerEndpointGroupsContractRevision        = "owner-endpoint-groups-v1"
	OwnerEndpointGroupsImplementationPhase     = "INTEGRATED_CANDIDATE"
	OwnerEndpointGroupsFormat                  = "cicada.owner-endpoint-groups.v1"
	OwnerEndpointGroupsResultFormat            = "cicada.owner-endpoint-groups-result.v1"
	OwnerEndpointGroupsCapabilitiesFormat      = "cicada.owner-endpoint-groups-capabilities.v1"
	OwnerEndpointGroupsCapabilitiesPath        = "/v2/owner/endpoint-groups/capabilities"
	EndpointGroupCurrentFormat                 = "cicada.endpoint-group-current.v1"
	OperationOwnerEndpointGroupsRead           = "owner.endpoint_groups.read"
	OperationOwnerEndpointGroupsPrepare        = "owner.endpoint_groups.prepare"
	OperationOwnerEndpointGroupsApply          = "owner.endpoint_groups.apply"
	OperationOwnerEndpointGroupsStatus         = "owner.endpoint_groups.status"
	OperationOwnerEndpointGroupsReconcile      = "owner.endpoint_groups.reconcile"
	OwnerEndpointGroupsCreateGroup             = "CREATE_GROUP"
	OwnerEndpointGroupsAddEndpoint             = "ADD_ENDPOINT"
	OwnerEndpointGroupsRemoveEndpoint          = "REMOVE_ENDPOINT"
	OwnerEndpointGroupsOriginalNotAdmitted     = "ORIGINAL_NOT_ADMITTED"
	MaxOwnerEndpointGroupsBodyBytes            = 192 << 10
	MaxOwnerEndpointGroupsPageBytes            = 128 << 10
	MaxOwnerEndpointGroupsOriginalBytes        = 256 << 10
	MaxOwnerEndpointGroupsPacketBytes          = 384 << 10
	MaxOwnerEndpointGroupsReconcileBodyBytes   = 640 << 10
	MaxOwnerEndpointGroupsReconcilePacketBytes = 896 << 10
	MaxEndpointGroupCarrierBytes               = 320 << 10
)

type OwnerEndpointGroupsCapabilities struct {
	Format                     string   `json:"format"`
	ContractRevision           string   `json:"contract_revision"`
	Available                  bool     `json:"available"`
	HubID                      string   `json:"hub_id"`
	HubFingerprint             string   `json:"hub_fingerprint"`
	MaxPageRows                int      `json:"max_page_rows"`
	MaxPageCanonicalBytes      int      `json:"max_page_canonical_bytes"`
	MaxActiveGroupsPerEndpoint int      `json:"max_active_groups_per_endpoint"`
	DurationValues             []string `json:"duration_values"`
	NativeSelfGroups           bool     `json:"native_self_groups"`
}

type OwnerEndpointGroupsReadBody struct {
	View       string `json:"view"`
	NodeID     string `json:"node_id"`
	NetworkID  string `json:"network_id"`
	EndpointID string `json:"endpoint_id,omitempty"`
	Cursor     string `json:"cursor,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

// The closed action union is validated before hashing, signing or opening.
type OwnerEndpointGroupsPrepareBody struct {
	Action     string `json:"action"`
	NodeID     string `json:"node_id"`
	NetworkID  string `json:"network_id"`
	Name       string `json:"name,omitempty"`
	GroupID    string `json:"group_id,omitempty"`
	EndpointID string `json:"endpoint_id,omitempty"`
	Duration   string `json:"duration,omitempty"`
}

type OwnerEndpointGroupsApplyBody struct {
	ReviewID            string `json:"review_id"`
	ReviewDigest        string `json:"review_digest"`
	PreparePacketDigest string `json:"prepare_packet_digest"`
	PolicyProof         []byte `json:"policy_proof,omitempty"`
}

type OwnerEndpointGroupsStatusBody struct {
	OperationID          string `json:"operation_id"`
	OriginalPacketDigest string `json:"original_packet_digest"`
}

type OwnerEndpointGroupsReconcileBody struct {
	OriginalPacket []byte `json:"original_packet"`
}

type OwnerEndpointGroupsReadRequest struct {
	Format       string                      `json:"format"`
	Context      AppNodeRequestContext       `json:"context"`
	SessionToken []byte                      `json:"session_token"`
	OwnerProof   []byte                      `json:"owner_proof"`
	Body         OwnerEndpointGroupsReadBody `json:"body"`
}

type OwnerEndpointGroupsPrepareRequest struct {
	Format       string                         `json:"format"`
	Context      AppNodeRequestContext          `json:"context"`
	SessionToken []byte                         `json:"session_token"`
	OwnerProof   []byte                         `json:"owner_proof"`
	Body         OwnerEndpointGroupsPrepareBody `json:"body"`
}

type OwnerEndpointGroupsApplyRequest struct {
	Format       string                       `json:"format"`
	Context      AppNodeRequestContext        `json:"context"`
	SessionToken []byte                       `json:"session_token"`
	OwnerProof   []byte                       `json:"owner_proof"`
	Body         OwnerEndpointGroupsApplyBody `json:"body"`
}

type OwnerEndpointGroupsStatusRequest struct {
	Format       string                        `json:"format"`
	Context      AppNodeRequestContext         `json:"context"`
	SessionToken []byte                        `json:"session_token"`
	OwnerProof   []byte                        `json:"owner_proof"`
	Body         OwnerEndpointGroupsStatusBody `json:"body"`
}

type OwnerEndpointGroupsReconcileRequest struct {
	Format       string                           `json:"format"`
	Context      AppNodeRequestContext            `json:"context"`
	SessionToken []byte                           `json:"session_token"`
	OwnerProof   []byte                           `json:"owner_proof"`
	Body         OwnerEndpointGroupsReconcileBody `json:"body"`
}

type OwnerEndpointGroupsCAS struct {
	OwnerKeyVersion         uint64 `json:"owner_key_version"`
	NodeOwnerBindingID      string `json:"node_owner_binding_id"`
	NodeOwnerBindingVersion uint64 `json:"node_owner_binding_version"`
	NodeKeyEpoch            uint64 `json:"node_key_epoch"`
	NetworkVersion          uint64 `json:"network_version"`
	GroupVersion            uint64 `json:"group_version"`
	RegistrationDigest      string `json:"registration_digest"`
	RegistrationRevision    uint64 `json:"registration_revision"`
	BindingID               string `json:"binding_id"`
	BindingEpoch            uint64 `json:"binding_epoch"`
	CandidateVersion        uint64 `json:"candidate_version"`
	CandidateProofDigest    string `json:"candidate_proof_digest"`
	CandidateFingerprint    string `json:"candidate_fingerprint"`
	MembershipRevision      uint64 `json:"membership_revision"`
	EndpointJoinRevision    uint64 `json:"endpoint_join_revision"`
	RelationRevision        uint64 `json:"relation_revision"`
	DecisionRevision        uint64 `json:"decision_revision"`
	OwnerControlDigest      string `json:"owner_control_digest"`
	PolicyEpoch             uint64 `json:"policy_epoch"`
}

// Unused fields of the selected action must be absent; validators reject mixed
// targets. The JSON order matches both action variants in the inventory.
type OwnerEndpointGroupsTarget struct {
	HubID              string `json:"hub_id"`
	OwnerID            string `json:"owner_id"`
	NodeID             string `json:"node_id"`
	LocalUserScope     string `json:"local_user_scope,omitempty"`
	NetworkID          string `json:"network_id"`
	GroupID            string `json:"group_id"`
	Name               string `json:"name,omitempty"`
	ContextPolicy      string `json:"context_policy,omitempty"`
	EndpointID         string `json:"endpoint_id,omitempty"`
	PrincipalID        string `json:"principal_id,omitempty"`
	RegistrationDigest string `json:"registration_digest,omitempty"`
}

type OwnerEndpointGroupsProjection struct {
	GroupID                string                          `json:"group_id,omitempty"`
	Name                   string                          `json:"name,omitempty"`
	ContextPolicy          string                          `json:"context_policy,omitempty"`
	OwnerManagementOnly    *bool                           `json:"owner_management_only,omitempty"`
	Source                 string                          `json:"source,omitempty"`
	ContributionState      string                          `json:"contribution_state,omitempty"`
	EffectiveRelationState string                          `json:"effective_relation_state,omitempty"`
	Grants                 *[]string                       `json:"grants,omitempty"`
	ProjectedRights        []string                        `json:"projected_rights,omitempty"`
	Duration               string                          `json:"duration,omitempty"`
	ExpectedOwnerControl   *e2ee.EndpointGroupOwnerControl `json:"expected_owner_control,omitempty"`
	CompletionOwnerControl *e2ee.EndpointGroupOwnerControl `json:"completion_owner_control,omitempty"`
	PolicyCore             *e2ee.EndpointGroupPolicyCore   `json:"policy_core,omitempty"`
	RelationState          string                          `json:"relation_state,omitempty"`
	ManualDeny             *bool                           `json:"manual_deny,omitempty"`
	WithdrawScope          string                          `json:"withdraw_scope,omitempty"`
}

type OwnerEndpointGroupsReview struct {
	ReviewID            string                        `json:"review_id"`
	RequestID           string                        `json:"request_id"`
	RequestPacketDigest string                        `json:"request_packet_digest"`
	Action              string                        `json:"action"`
	Target              OwnerEndpointGroupsTarget     `json:"target"`
	Expected            OwnerEndpointGroupsCAS        `json:"expected"`
	Projection          OwnerEndpointGroupsProjection `json:"projection"`
	Policy              *e2ee.EndpointGroupPolicy     `json:"policy,omitempty"`
	KeyManifest         *LocalDomainKeyManifest       `json:"key_manifest,omitempty"`
	ObservedAt          string                        `json:"observed_at"`
	ExpiresAt           string                        `json:"expires_at"`
	ReviewDigest        string                        `json:"review_digest"`
}

type EndpointGroupRelation struct {
	HubID                string `json:"hub_id"`
	OwnerID              string `json:"owner_id"`
	NodeID               string `json:"node_id"`
	LocalUserScope       string `json:"local_user_scope"`
	NetworkID            string `json:"network_id"`
	GroupID              string `json:"group_id"`
	EndpointID           string `json:"endpoint_id"`
	PrincipalID          string `json:"principal_id"`
	RegistrationDigest   string `json:"registration_digest"`
	RegistrationRevision uint64 `json:"registration_revision"`
	Source               string `json:"source"`
	AuthorityID          string `json:"authority_id"`
	AuthorityEpoch       uint64 `json:"authority_epoch"`
	ContributionRevision uint64 `json:"contribution_revision"`
	State                string `json:"state"`
	DecisionRevision     uint64 `json:"decision_revision"`
	OwnerControlDigest   string `json:"owner_control_digest"`
	PolicyID             string `json:"policy_id"`
	PolicyEpoch          uint64 `json:"policy_epoch"`
	BindingID            string `json:"binding_id"`
	BindingEpoch         uint64 `json:"binding_epoch"`
	MembershipRevision   uint64 `json:"membership_revision"`
	EndpointJoinRevision uint64 `json:"endpoint_join_revision"`
	CandidateVersion     uint64 `json:"candidate_version"`
	CandidateKeyID       string `json:"candidate_key_id"`
	CandidateFingerprint string `json:"candidate_fingerprint"`
	CandidateProofDigest string `json:"candidate_proof_digest"`
	ExpiresAt            string `json:"expires_at"`
}

type EndpointGroupDelegatedGrant struct {
	Manifest    LocalDomainKeyManifest `json:"manifest"`
	Relation    EndpointGroupRelation  `json:"relation"`
	PolicyProof []byte                 `json:"policy_proof"`
	NodeProof   []byte                 `json:"node_proof"`
}

type EndpointGroupCurrentEndpoint struct {
	OwnerControl e2ee.EndpointGroupOwnerControl `json:"owner_control"`
	Relation     EndpointGroupRelation          `json:"relation"`
}

type EndpointGroupCurrent struct {
	Format     string                       `json:"format"`
	HubID      string                       `json:"hub_id"`
	GroupID    string                       `json:"group_id"`
	Sender     EndpointGroupCurrentEndpoint `json:"sender"`
	Receiver   EndpointGroupCurrentEndpoint `json:"receiver"`
	Operation  string                       `json:"operation"`
	AttemptID  string                       `json:"attempt_id"`
	ObservedAt string                       `json:"observed_at"`
	ExpiresAt  string                       `json:"expires_at"`
}
