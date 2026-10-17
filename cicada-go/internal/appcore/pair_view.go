package appcore

// PairSetupSnapshot contains public setup metadata for one exact native pair.
// It contains no Owner proofs, private keys, join credentials or peer bodies.
// An ACTIVE pair is historical metadata until a current observation confirms
// its state; account logout alone does not revoke peer permission.
type PairSetupSnapshot struct {
	Available                bool                `json:"available"`
	Pending                  bool                `json:"pending"`
	PairID                   string              `json:"pair_id,omitempty"`
	NodeID                   string              `json:"node_id,omitempty"`
	Label                    string              `json:"label,omitempty"`
	State                    string              `json:"state,omitempty"`
	ControlRevision          uint64              `json:"control_revision,omitempty"`
	AdministrativePermission bool                `json:"administrative_permission"`
	Current                  bool                `json:"current"`
	ReviewID                 string              `json:"review_id,omitempty"`
	StateReviewID            string              `json:"state_review_id,omitempty"`
	ReviewExpiresAt          string              `json:"review_expires_at,omitempty"`
	JoinUntil                string              `json:"join_until,omitempty"`
	PeerExpiresAt            string              `json:"peer_expires_at,omitempty"`
	ObservedAt               string              `json:"observed_at,omitempty"`
	Slots                    [2]PairSlotSnapshot `json:"slots"`
	ErrorCode                string              `json:"error_code,omitempty"`
}

type PairSlotSnapshot struct {
	Slot                 string `json:"slot,omitempty"`
	State                string `json:"state,omitempty"`
	Generation           uint64 `json:"generation,omitempty"`
	NativeSessionID      string `json:"native_session_id,omitempty"`
	PeerNativeSessionID  string `json:"peer_native_session_id,omitempty"`
	CandidateFingerprint string `json:"candidate_fingerprint,omitempty"`
	CandidateKeyID       string `json:"candidate_key_id,omitempty"`
	CandidateVersion     uint64 `json:"candidate_version,omitempty"`
	EndpointID           string `json:"endpoint_id,omitempty"`
	PrincipalID          string `json:"principal_id,omitempty"`
	AttemptID            string `json:"attempt_id,omitempty"`
	BindingID            string `json:"binding_id,omitempty"`
	BindingEpoch         uint64 `json:"binding_epoch,omitempty"`
	NetworkBindingID     string `json:"network_binding_id,omitempty"`
	NetworkEpoch         uint64 `json:"network_epoch,omitempty"`
	NetworkMembership    uint64 `json:"network_membership_revision,omitempty"`
	EndpointNetwork      uint64 `json:"endpoint_network_revision,omitempty"`
	MembershipRevision   uint64 `json:"membership_revision,omitempty"`
	EndpointJoinRevision uint64 `json:"endpoint_join_revision,omitempty"`
	LeaseOwner           string `json:"lease_owner,omitempty"`
	LeaseCeiling         string `json:"lease_ceiling,omitempty"`
	TargetDigest         string `json:"target_digest,omitempty"`
	ConsentRecorded      bool   `json:"consent_recorded"`
}

const (
	ActionPreparePair        ActionKind = "PREPARE_NATIVE_PAIR"
	ActionCompletePair       ActionKind = "APPROVE_EXACT_NATIVE_PAIR_BOOTSTRAP"
	ActionRefreshPair        ActionKind = "REFRESH_EXACT_NATIVE_PAIR"
	ActionPreparePairConsent ActionKind = "REVIEW_EXACT_NATIVE_PAIR_SLOTS"
	ActionApprovePairSlot    ActionKind = "APPROVE_EXACT_NATIVE_PAIR_SLOT"
	ActionRejectPairSlot     ActionKind = "REJECT_EXACT_NATIVE_PAIR_SLOT"
	ActionRevokePair         ActionKind = "REVOKE_EXACT_NATIVE_PAIR"
	ActionRecoverPair        ActionKind = "RECOVER_EXACT_NATIVE_PAIR_OPERATION"
)

// PairAction is local UI input, never a wire DTO. The core must independently
// match ReviewID, slot and current retained target before signing anything.
type PairAction struct {
	Label            string
	PairID           string
	ReviewID         string
	Slot             string
	ConfirmBootstrap bool
	ConfirmSlot      bool
	ConfirmRevoke    bool
}
