package hubaccountwire

import "github.com/cicada-ai/cicada/internal/e2ee"

type EndpointGroupSourceReference struct {
	Source               string `json:"source"`
	AuthorityID          string `json:"authority_id"`
	AuthorityEpoch       uint64 `json:"authority_epoch"`
	ContributionRevision uint64 `json:"contribution_revision"`
}

type OwnerEndpointGroupsContributionCard struct {
	Source               string `json:"source"`
	AuthorityID          string `json:"authority_id"`
	AuthorityEpoch       uint64 `json:"authority_epoch"`
	ContributionRevision uint64 `json:"contribution_revision"`
	State                string `json:"state"`
	ExpiresAt            string `json:"expires_at"`
	KeyState             string `json:"key_state"`
	Effective            bool   `json:"effective"`
	UnavailableReason    string `json:"unavailable_reason"`
}

type OwnerEndpointGroupsRelationCard struct {
	GroupID           string                                `json:"group_id"`
	GroupName         string                                `json:"group_name"`
	NetworkID         string                                `json:"network_id"`
	State             string                                `json:"state"`
	RelationRevision  uint64                                `json:"relation_revision"`
	DecisionRevision  uint64                                `json:"decision_revision"`
	ManualDeny        bool                                  `json:"manual_deny"`
	OwnerControl      e2ee.EndpointGroupOwnerControl        `json:"owner_control"`
	Contributions     []OwnerEndpointGroupsContributionCard `json:"contributions"`
	SelectedSource    *EndpointGroupSourceReference         `json:"selected_source"`
	ExpiresAt         string                                `json:"expires_at"`
	KeyState          string                                `json:"key_state"`
	AllowedActions    []string                              `json:"allowed_actions"`
	UnavailableReason string                                `json:"unavailable_reason"`
}

type OwnerEndpointGroupsThreadCard struct {
	EndpointID           string                            `json:"endpoint_id"`
	PrincipalID          string                            `json:"principal_id"`
	NodeID               string                            `json:"node_id"`
	NetworkID            string                            `json:"network_id"`
	Name                 string                            `json:"name"`
	Workspace            string                            `json:"workspace"`
	Harness              string                            `json:"harness"`
	RegistrationDigest   string                            `json:"registration_digest"`
	RegistrationRevision uint64                            `json:"registration_revision"`
	Presence             string                            `json:"presence"`
	Relations            []OwnerEndpointGroupsRelationCard `json:"relations"`
	RelationStates       []string                          `json:"relation_states"`
	RelationsRevision    uint64                            `json:"relations_revision"`
	RelationsComplete    bool                              `json:"relations_complete"`
	RelationsNextCursor  string                            `json:"relations_next_cursor"`
}

type OwnerEndpointGroupsGroupCard struct {
	GroupID           string   `json:"group_id"`
	Name              string   `json:"name"`
	NetworkID         string   `json:"network_id"`
	GroupVersion      uint64   `json:"group_version"`
	ContextPolicy     string   `json:"context_policy"`
	AllowedActions    []string `json:"allowed_actions"`
	UnavailableReason string   `json:"unavailable_reason"`
}

type OwnerEndpointGroupsScopeActions struct {
	NodeID            string   `json:"node_id"`
	NetworkID         string   `json:"network_id"`
	AllowedActions    []string `json:"allowed_actions"`
	UnavailableReason string   `json:"unavailable_reason"`
}

type OwnerEndpointGroupsRelationPage struct {
	EndpointID        string   `json:"endpoint_id"`
	NetworkID         string   `json:"network_id"`
	States            []string `json:"states"`
	RelationsRevision uint64   `json:"relations_revision"`
	Complete          bool     `json:"complete"`
	NextCursor        string   `json:"next_cursor"`
}

type OwnerEndpointGroupsEffect struct {
	GroupID                string                          `json:"group_id"`
	Created                *bool                           `json:"created,omitempty"`
	EndpointID             string                          `json:"endpoint_id,omitempty"`
	RelationRevision       *uint64                         `json:"relation_revision,omitempty"`
	DecisionRevision       *uint64                         `json:"decision_revision,omitempty"`
	PolicyID               string                          `json:"policy_id,omitempty"`
	PolicyEpoch            uint64                          `json:"policy_epoch,omitempty"`
	ContributionRevision   uint64                          `json:"contribution_revision,omitempty"`
	ContributionState      string                          `json:"contribution_state,omitempty"`
	EffectiveRelationState string                          `json:"effective_relation_state,omitempty"`
	WithdrawnContributions *[]EndpointGroupSourceReference `json:"withdrawn_contributions,omitempty"`
	ManualDeny             *bool                           `json:"manual_deny,omitempty"`
	RelationState          string                          `json:"relation_state,omitempty"`
	OwnerControl           *e2ee.EndpointGroupOwnerControl `json:"owner_control,omitempty"`
}

type OwnerEndpointGroupsOperation struct {
	OperationID          string                     `json:"operation_id"`
	OriginalPacketDigest string                     `json:"original_packet_digest"`
	Action               string                     `json:"action"`
	State                string                     `json:"state"`
	ErrorCode            string                     `json:"error_code"`
	ReviewID             string                     `json:"review_id"`
	Target               OwnerEndpointGroupsTarget  `json:"target"`
	CommittedAt          string                     `json:"committed_at"`
	Effect               *OwnerEndpointGroupsEffect `json:"effect"`
}

type OwnerEndpointGroupsResult struct {
	Format              string                            `json:"format"`
	ContractRevision    string                            `json:"contract_revision"`
	RequestID           string                            `json:"request_id"`
	RequestPacketDigest string                            `json:"request_packet_digest"`
	HubID               string                            `json:"hub_id"`
	OwnerID             string                            `json:"owner_id"`
	DeviceID            string                            `json:"device_id"`
	NodeID              string                            `json:"node_id"`
	State               string                            `json:"state"`
	ErrorCode           string                            `json:"error_code"`
	CapturedAt          string                            `json:"captured_at"`
	Freshness           string                            `json:"freshness"`
	Threads             []OwnerEndpointGroupsThreadCard   `json:"threads"`
	Groups              []OwnerEndpointGroupsGroupCard    `json:"groups"`
	Relations           []OwnerEndpointGroupsRelationCard `json:"relations"`
	ScopeActions        *OwnerEndpointGroupsScopeActions  `json:"scope_actions"`
	RelationPage        *OwnerEndpointGroupsRelationPage  `json:"relation_page"`
	NextCursor          string                            `json:"next_cursor"`
	Review              *OwnerEndpointGroupsReview        `json:"review"`
	Operation           *OwnerEndpointGroupsOperation     `json:"operation"`
	CurrentRelation     *OwnerEndpointGroupsRelationCard  `json:"current_relation"`
	CurrentGroup        *OwnerEndpointGroupsGroupCard     `json:"current_group"`
	ReceiptPacket       []byte                            `json:"receipt_packet"`
}
