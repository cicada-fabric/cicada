package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	OwnerLocalDomainPolicyPurpose   = "local-domain-policy:v1"
	OwnerLocalDomainPreparePurpose  = "local-domain-prepare:v1"
	OwnerLocalDomainActivatePurpose = "local-domain-activate:v1"
	OwnerLocalDomainStatusPurpose   = "local-domain-status:v1"
	OwnerLocalDomainRevokePurpose   = "local-domain-revoke:v1"
	LocalDomainEndpointKeyPurpose   = "local-domain-endpoint-key-grant:v1"
	LocalDomainUserReportPurpose    = "local-domain-user-report:v1"
	MaxLocalDomainProofBytes        = 32 << 10
	LocalDomainRequestLifetime      = 5 * time.Minute
)

// LocalDomainTarget is an explicit choice, not a search for an existing
// Network. Exactly one of NetworkID and NewNetworkName must be nonempty.
type LocalDomainTarget struct {
	Node           OwnerAppNodeBinding `json:"node"`
	LocalUserScope string              `json:"local_user_scope"`
	NetworkID      string              `json:"network_id"`
	NewNetworkName string              `json:"new_network_name"`
	GroupName      string              `json:"group_name"`
	ExpiresAt      string              `json:"expires_at"`
}

// LocalDomainUserReport is signed by the actual Node's protected Control key.
// The App must never substitute its own user ID for a remote Node's writer.
type LocalDomainUserReport struct {
	Version        int    `json:"version"`
	Purpose        string `json:"purpose"`
	HubID          string `json:"hub_id"`
	OwnerID        string `json:"owner_id"`
	NodeID         string `json:"node_id"`
	OwnerBindingID string `json:"owner_binding_id"`
	NodeKeyEpoch   uint64 `json:"node_key_epoch"`
	LocalUserScope string `json:"local_user_scope"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at"`
	Nonce          string `json:"nonce"`
}

type LocalDomainUserReportProof struct {
	Report    LocalDomainUserReport `json:"report"`
	Signature []byte                `json:"signature"`
}

// LocalDomainPolicy is the persistent Owner delegation. It deliberately has
// no account session or App-device lease. Node.ClientDeviceID records the
// original Node approval provenance, not a continuing device dependency.
// Version is the format; Epoch is a monotonic authority generation. A separate
// Store state revision controls revoke CAS. Empty ExpiresAt means until revoke.
type LocalDomainPolicy struct {
	Version                   int                 `json:"version"`
	PolicyID                  string              `json:"policy_id"`
	Epoch                     uint64              `json:"epoch"`
	Origin                    string              `json:"origin"`
	HubID                     string              `json:"hub_id"`
	HubFingerprint            string              `json:"hub_fingerprint"`
	OwnerID                   string              `json:"owner_id"`
	OwnerPublic               PublicIdentity      `json:"owner_public_identity"`
	OwnerKeyVersion           uint64              `json:"owner_key_version"`
	Node                      OwnerAppNodeBinding `json:"node"`
	NodeControlBindingVersion uint64              `json:"node_control_binding_version"`
	CredentialCommitment      string              `json:"credential_commitment"`
	LocalUserScope            string              `json:"local_user_scope"`
	NetworkID                 string              `json:"network_id"`
	NetworkName               string              `json:"network_name"`
	CreateNetwork             bool                `json:"create_network"`
	GroupID                   string              `json:"group_id"`
	GroupName                 string              `json:"group_name"`
	Rights                    []string            `json:"rights"`
	IssuedAt                  string              `json:"issued_at"`
	ExpiresAt                 string              `json:"expires_at"`
	PrepareRequestID          string              `json:"prepare_request_id"`
	PreparePacketDigest       string              `json:"prepare_packet_digest"`
	ServerNonce               string              `json:"server_nonce"`
}

type OwnerLocalDomainPolicyProof struct {
	Purpose   string            `json:"purpose"`
	Policy    LocalDomainPolicy `json:"policy"`
	Signature []byte            `json:"signature"`
}

// OwnerLocalDomainRequestClaims is a short request authorization. Activation
// binds the persistent delegation's digest; the two validity periods differ.
type OwnerLocalDomainRequestClaims struct {
	Version          int                `json:"version"`
	Purpose          string             `json:"purpose"`
	Scope            OwnerAppNodeScope  `json:"scope"`
	RequestID        string             `json:"request_id"`
	Nonce            string             `json:"nonce"`
	IssuedAt         string             `json:"issued_at"`
	ExpiresAt        string             `json:"expires_at"`
	Target           *LocalDomainTarget `json:"target,omitempty"`
	PolicyID         string             `json:"policy_id"`
	PolicyEpoch      uint64             `json:"policy_epoch"`
	PolicyDigest     string             `json:"policy_digest"`
	ExpectedRevision uint64             `json:"expected_revision"`
	NodeID           string             `json:"node_id"`
	Cursor           string             `json:"cursor"`
}

type OwnerLocalDomainRequestProof struct {
	Claims    OwnerLocalDomainRequestClaims `json:"claims"`
	Signature []byte                        `json:"signature"`
}

// LocalDomainEndpointKeyClaims authenticates a complete existing Endpoint key
// manifest by its canonical digest. The receiving Node must independently
// compare the manifest, candidate attestation, live route and Owner policy.
type LocalDomainEndpointKeyClaims struct {
	Version                int    `json:"version"`
	Purpose                string `json:"purpose"`
	PolicyID               string `json:"policy_id"`
	PolicyEpoch            uint64 `json:"policy_epoch"`
	PolicyDigest           string `json:"policy_digest"`
	MemberID               string `json:"member_id"`
	MemberRevision         uint64 `json:"member_revision"`
	ManifestDigest         string `json:"manifest_digest"`
	CandidateBindingDigest string `json:"candidate_binding_digest"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
}

type LocalDomainEndpointKeyProof struct {
	Claims    LocalDomainEndpointKeyClaims `json:"claims"`
	Signature []byte                       `json:"signature"`
}

func LocalDomainRights() []string {
	return []string{"REGISTER", "DIRECTORY", "SEND", "ASK", "REPLY"}
}

func localDomainRevision(n uint64) bool { return n > 0 && n < math.MaxInt64 }

func localDomainName(s string) bool {
	return s != "" && len(s) <= 128 && strings.TrimSpace(s) == s && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

// v1 implements the existing Unix Node writer scope only. Other platforms need
// an authenticated native-user/IPC profile before advertising availability.
func ValidLocalDomainUserScope(s string) bool {
	if !strings.HasPrefix(s, "uid:") {
		return false
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "uid:"), 10, 32)
	return err == nil && s == "uid:"+strconv.FormatUint(n, 10)
}

func validateLocalDomainNode(n OwnerAppNodeBinding, owner, hub, ownerKey string) bool {
	if n.OwnerID != owner || n.HubID != hub || n.OwnerKeyID != ownerKey || n.State != "ACTIVE" ||
		!nativePairToken(n.OwnerBindingID) || !nativePairToken(n.NodeID) || n.NodeID == "control-local" || n.NodeID == "worker-local" ||
		!localDomainName(n.NodeName) || !nativePairToken(n.ClientDeviceID) || !nativePairToken(n.ApprovedRequestID) ||
		!canonicalSHA256Hex(n.ApprovedCandidateDigest) || !canonicalSHA256Hex(n.NodeKeyFingerprint) || !canonicalSHA256Hex(n.HubNodeControlFingerprint) ||
		ValidatePublicIdentity(n.NodePublic) != nil || ValidatePublicIdentity(n.HubNodeControlPublic) != nil || n.NodePublic.ID == n.HubNodeControlPublic.ID {
		return false
	}
	for _, r := range []uint64{n.BindingVersion, n.CredentialVersion, n.NodeKeyVersion, n.NodeKeyEpoch, n.HubNodeControlKeyVersion, n.ApprovedRequestVersion} {
		if !localDomainRevision(r) {
			return false
		}
	}
	_, err := parseCanonicalUTC(n.ApprovedAt)
	return err == nil
}

func ValidateLocalDomainTarget(t LocalDomainTarget, owner, hub, ownerKey string, now time.Time) error {
	if !validateLocalDomainNode(t.Node, owner, hub, ownerKey) || (t.LocalUserScope != "" && !ValidLocalDomainUserScope(t.LocalUserScope)) || !localDomainName(t.GroupName) ||
		(t.NetworkID == "") == (t.NewNetworkName == "") || (t.NetworkID != "" && !nativePairToken(t.NetworkID)) ||
		(t.NewNetworkName != "" && !localDomainName(t.NewNetworkName)) {
		return ErrInvalidEnvelope
	}
	if t.ExpiresAt != "" {
		end, err := parseCanonicalUTC(t.ExpiresAt)
		if err != nil || (!now.IsZero() && !now.Before(end)) {
			return ErrInvalidEnvelope
		}
	}
	return nil
}

func ValidateLocalDomainPolicy(p LocalDomainPolicy, now time.Time) error {
	u, err := url.Parse(p.Origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != p.Origin ||
		p.Version != 1 || !appNodeProofID(p.PolicyID) || !localDomainRevision(p.Epoch) || !nativePairToken(p.HubID) || !nativePairToken(p.OwnerID) ||
		!canonicalSHA256Hex(p.HubFingerprint) || ValidatePublicIdentity(p.OwnerPublic) != nil || !localDomainRevision(p.OwnerKeyVersion) ||
		!validateLocalDomainNode(p.Node, p.OwnerID, p.HubID, p.OwnerPublic.ID) || !localDomainRevision(p.NodeControlBindingVersion) ||
		!canonicalSHA256Hex(p.CredentialCommitment) || !ValidLocalDomainUserScope(p.LocalUserScope) ||
		!nativePairToken(p.NetworkID) || !nativePairToken(p.GroupID) || !localDomainName(p.NetworkName) || !localDomainName(p.GroupName) ||
		!reflect.DeepEqual(p.Rights, LocalDomainRights()) || !appNodeProofID(p.PrepareRequestID) || !canonicalSHA256Hex(p.PreparePacketDigest) || !canonicalSHA256Hex(p.ServerNonce) {
		return ErrInvalidEnvelope
	}
	issued, err := parseCanonicalUTC(p.IssuedAt)
	if err != nil || (!now.IsZero() && issued.After(now)) {
		return ErrInvalidEnvelope
	}
	if p.ExpiresAt != "" {
		end, err := parseCanonicalUTC(p.ExpiresAt)
		if err != nil || !end.After(issued) || (!now.IsZero() && !now.Before(end)) {
			return ErrInvalidEnvelope
		}
	}
	return nil
}

func LocalDomainPolicyDigest(p LocalDomainPolicy) (string, error) {
	if ValidateLocalDomainPolicy(p, time.Time{}) != nil {
		return "", ErrInvalidEnvelope
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("cicada/local-domain-policy-digest/v1\x00"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

func localDomainRequestDomain(purpose string) string {
	switch purpose {
	case OwnerLocalDomainPreparePurpose, OwnerLocalDomainActivatePurpose, OwnerLocalDomainStatusPurpose, OwnerLocalDomainRevokePurpose:
		return "cicada/owner/" + purpose + "\x00"
	}
	return ""
}

func ValidateOwnerLocalDomainRequest(c OwnerLocalDomainRequestClaims, now time.Time) error {
	if c.Version != 1 || localDomainRequestDomain(c.Purpose) == "" || appNodeProofScope(c.Scope) != nil || c.Scope.HeadVersion != 0 ||
		!appNodeProofID(c.RequestID) || !canonicalSHA256Hex(c.Nonce) || appNodeProofWindow(c.IssuedAt, c.ExpiresAt, LocalDomainRequestLifetime, now) != nil {
		return ErrInvalidEnvelope
	}
	end, _ := parseCanonicalUTC(c.ExpiresAt)
	sessionEnd, _ := parseCanonicalUTC(c.Scope.AccountSessionExpiresAt)
	if end.After(sessionEnd) {
		return ErrInvalidEnvelope
	}
	switch c.Purpose {
	case OwnerLocalDomainPreparePurpose:
		if c.Target == nil || c.PolicyID != "" || c.PolicyEpoch != 0 || c.PolicyDigest != "" || c.ExpectedRevision != 0 || c.NodeID != "" || c.Cursor != "" ||
			ValidateLocalDomainTarget(*c.Target, c.Scope.OwnerID, c.Scope.HubID, c.Scope.OwnerPublic.ID, now) != nil {
			return ErrInvalidEnvelope
		}
	case OwnerLocalDomainActivatePurpose, OwnerLocalDomainRevokePurpose:
		if c.Target != nil || !appNodeProofID(c.PolicyID) || !localDomainRevision(c.PolicyEpoch) || !canonicalSHA256Hex(c.PolicyDigest) || !localDomainRevision(c.ExpectedRevision) || c.NodeID != "" || c.Cursor != "" {
			return ErrInvalidEnvelope
		}
	case OwnerLocalDomainStatusPurpose:
		if c.Target != nil || (c.PolicyID == "") == (c.NodeID == "") || (c.PolicyID != "" && (!appNodeProofID(c.PolicyID) || c.Cursor != "")) ||
			(c.NodeID != "" && !nativePairToken(c.NodeID)) || (c.Cursor != "" && !appNodeProofID(c.Cursor)) || c.PolicyEpoch != 0 || c.PolicyDigest != "" || c.ExpectedRevision != 0 {
			return ErrInvalidEnvelope
		}
	}
	return nil
}

func marshalLocalDomainProof(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxLocalDomainProofBytes {
		return nil, ErrInvalidEnvelope
	}
	return raw, nil
}

func SignOwnerLocalDomainPolicy(owner *Identity, p LocalDomainPolicy) ([]byte, error) {
	if owner == nil || !reflect.DeepEqual(owner.Public(), p.OwnerPublic) || ValidateLocalDomainPolicy(p, time.Time{}) != nil {
		return nil, ErrInvalidEnvelope
	}
	claims := struct {
		Purpose string            `json:"purpose"`
		Policy  LocalDomainPolicy `json:"policy"`
	}{OwnerLocalDomainPolicyPurpose, p}
	sig, err := tlsProofSignature(owner, p.OwnerPublic.ID, "cicada/owner/local-domain-policy/v1\x00", claims)
	if err != nil {
		return nil, err
	}
	return marshalLocalDomainProof(OwnerLocalDomainPolicyProof{claims.Purpose, p, sig})
}

// A zero now authenticates retained history only. Store and Node must separately
// check the current Owner root, Node binding/key, policy state/epoch and route.
func VerifyOwnerLocalDomainPolicy(owner PublicIdentity, raw []byte, now time.Time) (LocalDomainPolicy, error) {
	var p OwnerLocalDomainPolicyProof
	if len(raw) > MaxLocalDomainProofBytes || tlsProofRead(raw, &p) != nil || p.Purpose != OwnerLocalDomainPolicyPurpose || !reflect.DeepEqual(owner, p.Policy.OwnerPublic) || ValidateLocalDomainPolicy(p.Policy, now) != nil {
		return LocalDomainPolicy{}, ErrInvalidEnvelope
	}
	claims := struct {
		Purpose string            `json:"purpose"`
		Policy  LocalDomainPolicy `json:"policy"`
	}{p.Purpose, p.Policy}
	if verifyAppNodeSignature(owner, "cicada/owner/local-domain-policy/v1\x00", claims, p.Signature) != nil {
		return LocalDomainPolicy{}, ErrInvalidEnvelope
	}
	return p.Policy, nil
}

func SignOwnerLocalDomainRequest(owner *Identity, c OwnerLocalDomainRequestClaims) ([]byte, error) {
	if owner == nil || !reflect.DeepEqual(owner.Public(), c.Scope.OwnerPublic) || ValidateOwnerLocalDomainRequest(c, time.Time{}) != nil {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, owner.Public().ID, localDomainRequestDomain(c.Purpose), c)
	if err != nil {
		return nil, err
	}
	return marshalLocalDomainProof(OwnerLocalDomainRequestProof{c, sig})
}

func VerifyOwnerLocalDomainRequest(owner PublicIdentity, raw []byte, purpose string, now time.Time) (OwnerLocalDomainRequestClaims, error) {
	var p OwnerLocalDomainRequestProof
	if len(raw) > MaxLocalDomainProofBytes || tlsProofRead(raw, &p) != nil || p.Claims.Purpose != purpose || localDomainRequestDomain(purpose) == "" ||
		!reflect.DeepEqual(owner, p.Claims.Scope.OwnerPublic) || ValidateOwnerLocalDomainRequest(p.Claims, now) != nil ||
		verifyAppNodeSignature(owner, localDomainRequestDomain(purpose), p.Claims, p.Signature) != nil {
		return OwnerLocalDomainRequestClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}

func validateLocalDomainEndpointKey(c LocalDomainEndpointKeyClaims, p LocalDomainPolicy, now time.Time) error {
	digest, err := LocalDomainPolicyDigest(p)
	if err != nil || ValidateLocalDomainPolicy(p, now) != nil || c.Version != 1 || c.Purpose != LocalDomainEndpointKeyPurpose ||
		c.PolicyID != p.PolicyID || c.PolicyEpoch != p.Epoch || c.PolicyDigest != digest || !nativePairToken(c.MemberID) || !localDomainRevision(c.MemberRevision) ||
		!canonicalSHA256Hex(c.ManifestDigest) || !canonicalSHA256Hex(c.CandidateBindingDigest) {
		return ErrInvalidEnvelope
	}
	issued, err := parseCanonicalUTC(c.IssuedAt)
	policyIssued, _ := parseCanonicalUTC(p.IssuedAt)
	if err != nil || issued.Before(policyIssued) || (!now.IsZero() && issued.After(now)) || c.ExpiresAt != p.ExpiresAt {
		return ErrInvalidEnvelope
	}
	if c.ExpiresAt != "" {
		end, err := parseCanonicalUTC(c.ExpiresAt)
		if err != nil || !end.After(issued) || (!now.IsZero() && !now.Before(end)) {
			return ErrInvalidEnvelope
		}
	}
	return nil
}

func SignLocalDomainEndpointKey(node *Identity, p LocalDomainPolicy, c LocalDomainEndpointKeyClaims) ([]byte, error) {
	if node == nil || !reflect.DeepEqual(node.Public(), p.Node.NodePublic) || validateLocalDomainEndpointKey(c, p, time.Time{}) != nil {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(node, node.Public().ID, "cicada/node/local-domain-endpoint-key/v1\x00", c)
	if err != nil {
		return nil, err
	}
	return marshalLocalDomainProof(LocalDomainEndpointKeyProof{c, sig})
}

func VerifyLocalDomainEndpointKey(p LocalDomainPolicy, raw []byte, now time.Time) (LocalDomainEndpointKeyClaims, error) {
	var proof LocalDomainEndpointKeyProof
	if len(raw) > MaxLocalDomainProofBytes || tlsProofRead(raw, &proof) != nil || validateLocalDomainEndpointKey(proof.Claims, p, now) != nil ||
		verifyAppNodeSignature(p.Node.NodePublic, "cicada/node/local-domain-endpoint-key/v1\x00", proof.Claims, proof.Signature) != nil {
		return LocalDomainEndpointKeyClaims{}, ErrInvalidEnvelope
	}
	return proof.Claims, nil
}

func validateLocalDomainUserReport(r LocalDomainUserReport, now time.Time) error {
	if r.Version != 1 || r.Purpose != LocalDomainUserReportPurpose || !nativePairToken(r.HubID) || !nativePairToken(r.OwnerID) || !nativePairToken(r.NodeID) ||
		!nativePairToken(r.OwnerBindingID) || !localDomainRevision(r.NodeKeyEpoch) || !ValidLocalDomainUserScope(r.LocalUserScope) || !canonicalSHA256Hex(r.Nonce) ||
		appNodeProofWindow(r.IssuedAt, r.ExpiresAt, LocalDomainRequestLifetime, now) != nil {
		return ErrInvalidEnvelope
	}
	return nil
}

func SignLocalDomainUserReport(node *Identity, r LocalDomainUserReport) ([]byte, error) {
	if node == nil || validateLocalDomainUserReport(r, time.Time{}) != nil {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(node, node.Public().ID, "cicada/node/local-domain-user-report/v1\x00", r)
	if err != nil {
		return nil, err
	}
	return marshalLocalDomainProof(LocalDomainUserReportProof{r, sig})
}

func VerifyLocalDomainUserReport(node OwnerAppNodeBinding, raw []byte, now time.Time) (LocalDomainUserReport, error) {
	var p LocalDomainUserReportProof
	if len(raw) > MaxLocalDomainProofBytes || tlsProofRead(raw, &p) != nil || validateLocalDomainUserReport(p.Report, now) != nil ||
		p.Report.HubID != node.HubID || p.Report.OwnerID != node.OwnerID || p.Report.NodeID != node.NodeID || p.Report.OwnerBindingID != node.OwnerBindingID || p.Report.NodeKeyEpoch != node.NodeKeyEpoch ||
		verifyAppNodeSignature(node.NodePublic, "cicada/node/local-domain-user-report/v1\x00", p.Report, p.Signature) != nil {
		return LocalDomainUserReport{}, ErrInvalidEnvelope
	}
	return p.Report, nil
}
