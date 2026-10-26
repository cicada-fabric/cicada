package hubaccountwire

import "github.com/cicada-ai/cicada/internal/e2ee"

const (
	EndpointGroupsNativeProfile               = "OWNER_ENDPOINT_GROUPS_V1"
	EndpointGroupsRegistrationSource          = "CODEX_LOCAL_DOMAIN"
	OperationEndpointGroupsNodeDescribe       = "node.endpoint_groups.describe"
	OperationEndpointGroupsNodeKeyPrepare     = "node.endpoint_groups.key_prepare"
	OperationEndpointGroupsNodeKeyComplete    = "node.endpoint_groups.key_complete"
	OperationEndpointGroupsNodeRenew          = "node.endpoint_groups.renew"
	OperationEndpointGroupsNodeReconcile      = "node.endpoint_groups.reconcile"
	MaxEndpointGroupsNodeOriginalBytes        = 64 << 10
	MaxEndpointGroupsNodeReceiptBytes         = 224 << 10
	MaxEndpointGroupsNodeReconcileBodyBytes   = 128 << 10
	MaxEndpointGroupsNodeReconcilePacketBytes = 560 << 10
)

// A private identity/liveness snapshot, never a Group grant. The receiving Node
// must independently compare it to the original protected native record, UID,
// encrypted join receipt and key custody before selecting this explicit profile.
type EndpointGroupsRegistrationAnchor struct {
	Profile                   string                         `json:"profile"`
	RegistrationSource        string                         `json:"registration_source"`
	Registration              e2ee.EndpointGroupRegistration `json:"registration"`
	RegistrationDigest        string                         `json:"registration_digest"`
	RegistrationRevision      uint64                         `json:"registration_revision"`
	LocalUserScope            string                         `json:"local_user_scope"`
	NetworkID                 string                         `json:"network_id"`
	BindingID                 string                         `json:"binding_id"`
	BindingEpoch              uint64                         `json:"binding_epoch"`
	NodeKeyEpoch              uint64                         `json:"node_key_epoch"`
	LeaseOwner                string                         `json:"lease_owner"`
	NetworkAccessBindingID    string                         `json:"network_access_binding_id"`
	NetworkAccessEpoch        uint64                         `json:"network_access_epoch"`
	NetworkMembershipRevision uint64                         `json:"network_membership_revision"`
	EndpointNetworkRevision   uint64                         `json:"endpoint_network_revision"`
	CandidateVersion          uint64                         `json:"candidate_version"`
	CandidateKeyID            string                         `json:"candidate_key_id"`
	CandidatePublic           e2ee.PublicIdentity            `json:"candidate_public_identity"`
	CandidateFingerprint      string                         `json:"candidate_fingerprint"`
	CandidateProofDigest      string                         `json:"candidate_proof_digest"`
	State                     string                         `json:"state"`
	LeaseExpiresAt            string                         `json:"lease_expires_at"`
}

type EndpointGroupsNodeDescribe struct {
	EndpointID string `json:"endpoint_id"`
	NetworkID  string `json:"network_id"`
	Cursor     string `json:"cursor,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

type EndpointGroupsNodeKeyPrepare struct {
	PolicyID                 string `json:"policy_id"`
	PolicyEpoch              uint64 `json:"policy_epoch"`
	EndpointID               string `json:"endpoint_id"`
	GroupID                  string `json:"group_id"`
	ExpectedRelationRevision uint64 `json:"expected_relation_revision"`
}

type EndpointGroupsNodeKeyComplete struct {
	PolicyID                 string `json:"policy_id"`
	PolicyEpoch              uint64 `json:"policy_epoch"`
	EndpointID               string `json:"endpoint_id"`
	GroupID                  string `json:"group_id"`
	ExpectedRelationRevision uint64 `json:"expected_relation_revision"`
	ChallengeID              string `json:"challenge_id"`
	NodeProof                []byte `json:"node_proof"`
}

type EndpointGroupsNodeRenew struct {
	EndpointID           string `json:"endpoint_id"`
	RegistrationDigest   string `json:"registration_digest"`
	ExpectedBindingID    string `json:"expected_binding_id"`
	ExpectedBindingEpoch uint64 `json:"expected_binding_epoch"`
}

type EndpointGroupsNodeReconcile struct {
	OriginalPacket []byte `json:"original_packet"`
}

type EndpointGroupsNodeDescribeResult struct {
	ContractRevision  string                            `json:"contract_revision"`
	Registration      EndpointGroupsRegistrationAnchor  `json:"registration"`
	Relations         []OwnerEndpointGroupsRelationCard `json:"relations"`
	Authorities       []EndpointGroupCurrentEndpoint    `json:"authorities"`
	RelationsRevision uint64                            `json:"relations_revision"`
	Complete          bool                              `json:"complete"`
	NextCursor        string                            `json:"next_cursor"`
	ObservedAt        string                            `json:"observed_at"`
}

type EndpointGroupKeyPrepareResult struct {
	ChallengeID           string                         `json:"challenge_id"`
	PolicyID              string                         `json:"policy_id"`
	PolicyEpoch           uint64                         `json:"policy_epoch"`
	Expected              OwnerEndpointGroupsCAS         `json:"expected"`
	ProjectedOwnerControl e2ee.EndpointGroupOwnerControl `json:"projected_owner_control"`
	ProjectedRelation     EndpointGroupRelation          `json:"projected_relation"`
	ProjectedKeyManifest  LocalDomainKeyManifest         `json:"projected_key_manifest"`
	ObservedAt            string                         `json:"observed_at"`
	ExpiresAt             string                         `json:"expires_at"`
	ChallengeDigest       string                         `json:"challenge_digest"`
}

type EndpointGroupsNodeKeyResult struct {
	ContractRevision string                           `json:"contract_revision"`
	Registration     EndpointGroupsRegistrationAnchor `json:"registration"`
	PolicyProof      []byte                           `json:"policy_proof"`
	Challenge        *EndpointGroupKeyPrepareResult   `json:"challenge,omitempty"`
	Grant            *EndpointGroupDelegatedGrant     `json:"grant,omitempty"`
	OwnerControl     e2ee.EndpointGroupOwnerControl   `json:"owner_control"`
	ObservedAt       string                           `json:"observed_at"`
}

type EndpointGroupsNodeRenewResult struct {
	ContractRevision string                           `json:"contract_revision"`
	Registration     EndpointGroupsRegistrationAnchor `json:"registration"`
	ObservedAt       string                           `json:"observed_at"`
}

// Same response fields, existing Node packet digest and replay ledger. The
// contract_revision and exact outer operation distinguish this profile.
type EndpointGroupsNodeReconciled = LocalDomainNodeReconciled

// Exactly one source is allowed per Endpoint. This independent selector does
// not reinterpret a legacy Owner/Pair proof or blend authority across sources.
type EndpointGroupPeerSource struct {
	LocalDomainGrant   *LocalDomainEndpointKeyGrant `json:"local_domain_grant,omitempty"`
	EndpointGroupGrant *EndpointGroupDelegatedGrant `json:"endpoint_group_grant,omitempty"`
}

func EndpointGroupsNodeOperations() []string {
	return []string{OperationEndpointGroupsNodeDescribe, OperationEndpointGroupsNodeKeyPrepare, OperationEndpointGroupsNodeKeyComplete, OperationEndpointGroupsNodeRenew, OperationEndpointGroupsNodeReconcile}
}
