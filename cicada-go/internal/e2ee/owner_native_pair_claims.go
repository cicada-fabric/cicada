package e2ee

// Contract-only native-pair authority. None of these types activates an Owner,
// enrolls a device, creates membership, or permits a Runtime invocation.
const (
	OwnerNativePairBootstrapPreview = "NATIVE_PAIR_BOOTSTRAP_PREVIEW"
	OwnerNativePairBootstrapCommit  = "NATIVE_PAIR_BOOTSTRAP_COMMIT"
	OwnerNativePairConsentPreview   = "NATIVE_PAIR_CONSENT_PREVIEW"
	OwnerNativePairSlotConsent      = "NATIVE_PAIR_SLOT_CONSENT"
	OwnerNativePairSlotReject       = "NATIVE_PAIR_SLOT_REJECT"
	OwnerNativePairRevoke           = "NATIVE_PAIR_REVOKE"

	OwnerNativePairBootstrapPreviewDomain = "cicada/owner/native-pair/v1/bootstrap-preview\x00"
	OwnerNativePairBootstrapCommitDomain  = "cicada/owner/native-pair/v1/bootstrap-commit\x00"
	OwnerNativePairConsentPreviewDomain   = "cicada/owner/native-pair/v1/consent-preview\x00"
	OwnerNativePairSlotConsentDomain      = "cicada/owner/native-pair/v1/slot-consent\x00"
	OwnerNativePairSlotRejectDomain       = "cicada/owner/native-pair/v1/slot-reject\x00"
	OwnerNativePairRevokeDomain           = "cicada/owner/native-pair/v1/revoke\x00"
)

// Actor.HeadVersion is exactly zero: the native pair has its own control
// revision and never consumes or borrows the old N3 grant head.
type OwnerNativePairScope struct {
	Actor                     OwnerAppNodeScope   `json:"actor"`
	Node                      OwnerAppNodeBinding `json:"node"`
	NodeControlBindingVersion uint64              `json:"node_control_binding_version"`
	CredentialCommitment      string              `json:"credential_commitment"`
	NodeTupleDigest           string              `json:"node_tuple_digest"`
}

// These are distinct business delivery limits, never provider HTTP/cost counts.
type NativePairPeerPolicy struct {
	MaxRootAsks         uint64 `json:"max_root_asks"`
	MaxReplies          uint64 `json:"max_replies"`
	MaxRepliesPerAsk    uint64 `json:"max_replies_per_ask"`
	MaxOutstandingAsks  uint64 `json:"max_outstanding_asks"`
	MaxCausalDepth      uint64 `json:"max_causal_depth"`
	MaxMessages         uint64 `json:"max_messages"`
	MaxPlaintextBytes   uint64 `json:"max_plaintext_bytes"`
	MaxTotalPlaintext   uint64 `json:"max_total_plaintext_bytes"`
	MaxCiphertextBytes  uint64 `json:"max_ciphertext_bytes"`
	MaxTotalCiphertext  uint64 `json:"max_total_ciphertext_bytes"`
	MaxNativeDeliveries uint64 `json:"max_native_deliveries"`
}

func NativePairFixedPeerPolicy() NativePairPeerPolicy {
	return NativePairPeerPolicy{MaxRootAsks: 4, MaxReplies: 4, MaxRepliesPerAsk: 1,
		MaxOutstandingAsks: 1, MaxMessages: 8, MaxPlaintextBytes: 8 * 1024,
		MaxTotalPlaintext: 64 * 1024, MaxCiphertextBytes: 128 * 1024,
		MaxTotalCiphertext: 1024 * 1024, MaxNativeDeliveries: 8}
}

type NativePairBootstrapClaims struct {
	PairID              string               `json:"pair_id"`
	NetworkID           string               `json:"network_id"`
	GroupID             string               `json:"group_id"`
	GroupLabel          string               `json:"group_label"`
	Runtime             string               `json:"runtime"`
	SlotCount           uint64               `json:"slot_count"`
	Policy              NativePairPeerPolicy `json:"policy"`
	PreparedAt          string               `json:"prepared_at"`
	JoinUntil           string               `json:"join_until"`
	PeerExpiresAt       string               `json:"peer_expires_at"`
	PrepareRequestID    string               `json:"prepare_request_id"`
	PreparePacketDigest string               `json:"prepare_packet_digest"`
	ServerNonce         string               `json:"server_nonce"`
}

// Digests commit to the canonical full public Slot/Plan DTOs. Actual SID and
// slot generations are explicit, so initial empty-slot consent is insufficient.
type NativePairConsentClaims struct {
	PairID              string `json:"pair_id"`
	ExpectedRevision    uint64 `json:"expected_revision"`
	PlanID              string `json:"plan_id"`
	PlanDigest          string `json:"plan_digest"`
	SlotADigest         string `json:"slot_a_digest"`
	SlotBDigest         string `json:"slot_b_digest"`
	Slot                string `json:"slot"`
	SlotGeneration      uint64 `json:"slot_generation"`
	SlotAttemptID       string `json:"slot_attempt_id"`
	NativeSessionID     string `json:"native_session_id"`
	PeerNativeSessionID string `json:"peer_native_session_id"`
	ActivateWhenBoth    bool   `json:"activate_when_both"`
	PlanExpiresAt       string `json:"plan_expires_at"`
	PeerExpiresAt       string `json:"peer_expires_at"`
}

type NativePairRejectClaims struct {
	PairID           string `json:"pair_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
	Slot             string `json:"slot"`
	SlotGeneration   uint64 `json:"slot_generation"`
	SlotAttemptID    string `json:"slot_attempt_id"`
	SlotDigest       string `json:"slot_digest"`
}

type NativePairRevokeClaims struct {
	PairID           string `json:"pair_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
	PairTargetDigest string `json:"pair_target_digest"`
}

// Exactly one payload is present and its shape must match Purpose. No map,
// generic action array, wildcard native SID, or substituted proof purpose exists.
type OwnerNativePairClaims struct {
	Version   int                        `json:"version"`
	Purpose   string                     `json:"purpose"`
	Scope     OwnerNativePairScope       `json:"scope"`
	RequestID string                     `json:"request_id"`
	Nonce     string                     `json:"nonce"`
	IssuedAt  string                     `json:"issued_at"`
	ExpiresAt string                     `json:"expires_at"`
	Bootstrap *NativePairBootstrapClaims `json:"bootstrap,omitempty"`
	Consent   *NativePairConsentClaims   `json:"consent,omitempty"`
	Reject    *NativePairRejectClaims    `json:"reject,omitempty"`
	Revoke    *NativePairRevokeClaims    `json:"revoke,omitempty"`
}

type OwnerNativePairProof struct {
	Claims    OwnerNativePairClaims `json:"claims"`
	Signature []byte                `json:"signature"`
}
