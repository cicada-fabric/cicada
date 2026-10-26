package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	OwnerEndpointGroupsPolicyPurpose = "endpoint-group-policy:v1"
	EndpointGroupKeyPurpose          = "endpoint-group-key-grant:v1"
	OwnerEndpointGroupsRequestDomain = "cicada/owner/endpoint-groups/request/v1\x00"
	OwnerEndpointGroupsPolicyDomain  = "cicada/owner/endpoint-groups/policy/v1\x00"
	EndpointGroupKeyDomain           = "cicada/node/endpoint-groups/key-grant/v1\x00"
	MaxEndpointGroupProofBytes       = 32 << 10
	EndpointGroupsRequestLifetime    = 5 * time.Minute
)

// These are communication rights, not Principal-wide grants or management
// rights. Every actual actor Guard must also enforce this per-source ceiling.
func EndpointGroupRights() []string {
	return []string{"directory.read", "message.ask", "message.receive", "message.reply", "message.send"}
}

type EndpointGroupOwnerControl struct {
	Mode        string `json:"mode"`
	Revision    uint64 `json:"revision"`
	DenyReason  string `json:"deny_reason"`
	PolicyID    string `json:"policy_id"`
	PolicyEpoch uint64 `json:"policy_epoch"`
}

func ValidateEndpointGroupOwnerControl(h EndpointGroupOwnerControl) error {
	if h.Mode == "DEFAULT" && h.Revision == 0 && h.DenyReason == "NONE" && h.PolicyID == "" && h.PolicyEpoch == 0 {
		return nil
	}
	if h.Mode != "OWNER" || !localDomainRevision(h.Revision) ||
		(h.DenyReason != "NONE" && h.DenyReason != "REMOVED" && h.DenyReason != "EXPIRED") {
		return ErrInvalidEnvelope
	}
	if h.PolicyID == "" && h.PolicyEpoch == 0 && h.DenyReason == "REMOVED" {
		return nil // Owner can remove an untouched default relation.
	}
	if !appNodeProofID(h.PolicyID) || !localDomainRevision(h.PolicyEpoch) {
		return ErrInvalidEnvelope
	}
	return nil
}

// EndpointGroupNativeIdentity is private server/Node input, never an App selector.
// Tokens, Endpoint IDs, keys and epochs are deliberately absent from the deny key.
type EndpointGroupNativeIdentity struct {
	HubID           string `json:"hub_id"`
	OwnerID         string `json:"owner_id"`
	NodeID          string `json:"node_id"`
	LocalUserScope  string `json:"local_user_scope"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	Workspace       string `json:"workspace"`
}

type EndpointGroupRegistration struct {
	HubID           string `json:"hub_id"`
	OwnerID         string `json:"owner_id"`
	NodeID          string `json:"node_id"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	Workspace       string `json:"workspace"`
	EndpointID      string `json:"endpoint_id"`
	PrincipalID     string `json:"principal_id"`
}

func endpointGroupNativeCoordinates(hub, owner, node, harness, sid, workspace string) bool {
	return nativePairToken(hub) && nativePairToken(owner) && nativePairToken(node) && harness == "codex" && nativePairToken(sid) &&
		strings.HasPrefix(workspace, "/") && path.Clean(workspace) == workspace && len(workspace) <= 1024 && utf8.ValidString(workspace) && strings.IndexFunc(workspace, unicode.IsControl) < 0
}

func EndpointGroupNativeIdentityDigest(n EndpointGroupNativeIdentity) (string, error) {
	if !endpointGroupNativeCoordinates(n.HubID, n.OwnerID, n.NodeID, n.Harness, n.NativeSessionID, n.Workspace) || !ValidLocalDomainUserScope(n.LocalUserScope) {
		return "", ErrInvalidEnvelope
	}
	return endpointGroupsDigest("cicada/owner/endpoint-groups/native-identity/v1\x00", n)
}

func EndpointGroupRegistrationDigest(n EndpointGroupRegistration) (string, error) {
	if !endpointGroupNativeCoordinates(n.HubID, n.OwnerID, n.NodeID, n.Harness, n.NativeSessionID, n.Workspace) || !nativePairToken(n.EndpointID) || !nativePairToken(n.PrincipalID) {
		return "", ErrInvalidEnvelope
	}
	return endpointGroupsDigest("cicada/owner/endpoint-groups/registration/v1\x00", n)
}

func EndpointGroupOwnerControlDigest(nativeDigest, groupID string, h EndpointGroupOwnerControl) (string, error) {
	if !canonicalSHA256Hex(nativeDigest) || !nativePairToken(groupID) || ValidateEndpointGroupOwnerControl(h) != nil {
		return "", ErrInvalidEnvelope
	}
	return endpointGroupsDigest("cicada/owner/endpoint-groups/owner-control/v1\x00", struct {
		NativeIdentityDigest string                    `json:"native_identity_digest"`
		GroupID              string                    `json:"group_id"`
		Head                 EndpointGroupOwnerControl `json:"head"`
	}{nativeDigest, groupID, h})
}

func endpointGroupsDigest(domain string, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", ErrInvalidEnvelope
	}
	sum := sha256.Sum256(append([]byte(domain), raw...))
	return hex.EncodeToString(sum[:]), nil
}

type OwnerEndpointGroupsRequestClaims struct {
	Version    int               `json:"version"`
	Purpose    string            `json:"purpose"`
	Scope      OwnerAppNodeScope `json:"scope"`
	RequestID  string            `json:"request_id"`
	Nonce      string            `json:"nonce"`
	IssuedAt   string            `json:"issued_at"`
	ExpiresAt  string            `json:"expires_at"`
	BodyDigest string            `json:"body_digest"`
}

type OwnerEndpointGroupsRequestProof struct {
	Claims    OwnerEndpointGroupsRequestClaims `json:"claims"`
	Signature []byte                           `json:"signature"`
}

func ValidOwnerEndpointGroupsPurpose(purpose string) bool {
	switch purpose {
	case "owner-endpoint-groups-read:v1", "owner-endpoint-groups-prepare:v1", "owner-endpoint-groups-apply:v1", "owner-endpoint-groups-status:v1", "owner-endpoint-groups-reconcile:v1":
		return true
	}
	return false
}

func ValidateOwnerEndpointGroupsRequest(c OwnerEndpointGroupsRequestClaims, now time.Time) error {
	if c.Version != 1 || !ValidOwnerEndpointGroupsPurpose(c.Purpose) || appNodeProofScope(c.Scope) != nil || c.Scope.HeadVersion != 0 ||
		!appNodeProofID(c.RequestID) || !canonicalSHA256Hex(c.Nonce) || !canonicalSHA256Hex(c.BodyDigest) ||
		appNodeProofWindow(c.IssuedAt, c.ExpiresAt, EndpointGroupsRequestLifetime, now) != nil {
		return ErrInvalidEnvelope
	}
	end, _ := parseCanonicalUTC(c.ExpiresAt)
	sessionEnd, _ := parseCanonicalUTC(c.Scope.AccountSessionExpiresAt)
	if end.After(sessionEnd) {
		return ErrInvalidEnvelope
	}
	return nil
}

func marshalEndpointGroupProof(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxEndpointGroupProofBytes {
		return nil, ErrInvalidEnvelope
	}
	return raw, nil
}

func SignOwnerEndpointGroupsRequest(owner *Identity, c OwnerEndpointGroupsRequestClaims) ([]byte, error) {
	if owner == nil || !reflect.DeepEqual(owner.Public(), c.Scope.OwnerPublic) || ValidateOwnerEndpointGroupsRequest(c, time.Time{}) != nil {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, owner.Public().ID, OwnerEndpointGroupsRequestDomain, c)
	if err != nil {
		return nil, err
	}
	return marshalEndpointGroupProof(OwnerEndpointGroupsRequestProof{c, sig})
}

func VerifyOwnerEndpointGroupsRequest(owner PublicIdentity, raw []byte, purpose string, now time.Time) (OwnerEndpointGroupsRequestClaims, error) {
	var p OwnerEndpointGroupsRequestProof
	if len(raw) > MaxEndpointGroupProofBytes || tlsProofRead(raw, &p) != nil || p.Claims.Purpose != purpose || !reflect.DeepEqual(owner, p.Claims.Scope.OwnerPublic) ||
		ValidateOwnerEndpointGroupsRequest(p.Claims, now) != nil || verifyAppNodeSignature(owner, OwnerEndpointGroupsRequestDomain, p.Claims, p.Signature) != nil {
		return OwnerEndpointGroupsRequestClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}

// EndpointGroupPolicy has no App-session lifetime. Current Store authority,
// Owner control and exact native registration remain independent requirements.
type EndpointGroupPolicy struct {
	Version                    int                 `json:"version"`
	Purpose                    string              `json:"purpose"`
	PolicyID                   string              `json:"policy_id"`
	Epoch                      uint64              `json:"epoch"`
	Origin                     string              `json:"origin"`
	HubID                      string              `json:"hub_id"`
	HubFingerprint             string              `json:"hub_fingerprint"`
	OwnerID                    string              `json:"owner_id"`
	OwnerPublic                PublicIdentity      `json:"owner_public_identity"`
	OwnerKeyVersion            uint64              `json:"owner_key_version"`
	Node                       OwnerAppNodeBinding `json:"node"`
	LocalUserScope             string              `json:"local_user_scope"`
	NetworkID                  string              `json:"network_id"`
	GroupID                    string              `json:"group_id"`
	EndpointID                 string              `json:"endpoint_id"`
	PrincipalID                string              `json:"principal_id"`
	RegistrationDigest         string              `json:"registration_digest"`
	RegistrationRevision       uint64              `json:"registration_revision"`
	BindingID                  string              `json:"binding_id"`
	BindingEpoch               uint64              `json:"binding_epoch"`
	EndpointKeyID              string              `json:"endpoint_key_id"`
	EndpointPublic             PublicIdentity      `json:"endpoint_public_identity"`
	EndpointFingerprint        string              `json:"endpoint_fingerprint"`
	CandidateVersion           uint64              `json:"candidate_version"`
	CandidateProofDigest       string              `json:"candidate_proof_digest"`
	ExpectedOwnerControlDigest string              `json:"expected_owner_control_digest"`
	ExpectedDecisionRevision   uint64              `json:"expected_decision_revision"`
	Rights                     []string            `json:"rights"`
	IssuedAt                   string              `json:"issued_at"`
	ExpiresAt                  string              `json:"expires_at"`
	ReviewID                   string              `json:"review_id"`
	ReviewDigest               string              `json:"review_digest"`
	ServerNonce                string              `json:"server_nonce"`
}

type OwnerEndpointGroupPolicyProof struct {
	Purpose   string              `json:"purpose"`
	Policy    EndpointGroupPolicy `json:"policy"`
	Signature []byte              `json:"signature"`
}

func ValidateEndpointGroupPolicy(p EndpointGroupPolicy, now time.Time) error {
	u, err := url.Parse(p.Origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != p.Origin ||
		p.Version != 1 || p.Purpose != OwnerEndpointGroupsPolicyPurpose || !appNodeProofID(p.PolicyID) || !nativePairToken(p.HubID) || !nativePairToken(p.OwnerID) ||
		ValidatePublicIdentity(p.OwnerPublic) != nil || !canonicalSHA256Hex(p.HubFingerprint) || !validateLocalDomainNode(p.Node, p.OwnerID, p.HubID, p.OwnerPublic.ID) ||
		!ValidLocalDomainUserScope(p.LocalUserScope) || !nativePairToken(p.NetworkID) || !nativePairToken(p.GroupID) || !nativePairToken(p.EndpointID) || !nativePairToken(p.PrincipalID) ||
		!nativePairToken(p.BindingID) || !canonicalSHA256Hex(p.RegistrationDigest) || !canonicalSHA256Hex(p.CandidateProofDigest) || !canonicalSHA256Hex(p.ExpectedOwnerControlDigest) ||
		p.ExpectedDecisionRevision >= 1<<63-1 || !appNodeProofID(p.ReviewID) || !canonicalSHA256Hex(p.ReviewDigest) || !canonicalSHA256Hex(p.ServerNonce) ||
		!reflect.DeepEqual(p.Rights, EndpointGroupRights()) || ValidatePublicIdentity(p.EndpointPublic) != nil || p.EndpointKeyID != p.EndpointPublic.ID {
		return ErrInvalidEnvelope
	}
	for _, n := range []uint64{p.Epoch, p.OwnerKeyVersion, p.RegistrationRevision, p.BindingEpoch, p.CandidateVersion} {
		if !localDomainRevision(n) {
			return ErrInvalidEnvelope
		}
	}
	if p.EndpointFingerprint != endpointGroupPeerFingerprint(p.EndpointPublic) {
		return ErrInvalidEnvelope
	}
	issued, err := parseCanonicalUTC(p.IssuedAt)
	if err != nil || (!now.IsZero() && issued.After(now.Add(30*time.Second))) {
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

// Existing Node peer-key fingerprint, including its historical sha256: prefix.
func endpointGroupPeerFingerprint(p PublicIdentity) string {
	h := sha256.New()
	h.Write([]byte("cicada/nodekeys/peer-key-fingerprint/v1\x00"))
	h.Write(p.KEMPublic)
	h.Write(p.SigningPublic)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// PolicyDigest hashes exactly the typed policy signature input, not its proof.
func EndpointGroupPolicyDigest(p EndpointGroupPolicy) (string, error) {
	if ValidateEndpointGroupPolicy(p, time.Time{}) != nil {
		return "", ErrInvalidEnvelope
	}
	return endpointGroupsDigest(OwnerEndpointGroupsPolicyDomain, p)
}

func SignOwnerEndpointGroupPolicy(owner *Identity, p EndpointGroupPolicy) ([]byte, error) {
	if owner == nil || !reflect.DeepEqual(owner.Public(), p.OwnerPublic) || ValidateEndpointGroupPolicy(p, time.Time{}) != nil {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, owner.Public().ID, OwnerEndpointGroupsPolicyDomain, p)
	if err != nil {
		return nil, err
	}
	return marshalEndpointGroupProof(OwnerEndpointGroupPolicyProof{OwnerEndpointGroupsPolicyPurpose, p, sig})
}

// Zero time authenticates retained history only, never current authority.
func VerifyOwnerEndpointGroupPolicy(owner PublicIdentity, raw []byte, now time.Time) (EndpointGroupPolicy, error) {
	var p OwnerEndpointGroupPolicyProof
	if len(raw) > MaxEndpointGroupProofBytes || tlsProofRead(raw, &p) != nil || p.Purpose != OwnerEndpointGroupsPolicyPurpose || !reflect.DeepEqual(owner, p.Policy.OwnerPublic) ||
		ValidateEndpointGroupPolicy(p.Policy, now) != nil || verifyAppNodeSignature(owner, OwnerEndpointGroupsPolicyDomain, p.Policy, p.Signature) != nil {
		return EndpointGroupPolicy{}, ErrInvalidEnvelope
	}
	return p.Policy, nil
}

type EndpointGroupKeyClaims struct {
	Version                int    `json:"version"`
	Purpose                string `json:"purpose"`
	HubID                  string `json:"hub_id"`
	NodeID                 string `json:"node_id"`
	NodeKeyEpoch           uint64 `json:"node_key_epoch"`
	PolicyID               string `json:"policy_id"`
	PolicyEpoch            uint64 `json:"policy_epoch"`
	PolicyDigest           string `json:"policy_digest"`
	RegistrationDigest     string `json:"registration_digest"`
	OwnerControlDigest     string `json:"owner_control_digest"`
	RelationDigest         string `json:"relation_digest"`
	ManifestDigest         string `json:"manifest_digest"`
	CandidateBindingDigest string `json:"candidate_binding_digest"`
	ChallengeID            string `json:"challenge_id"`
	ChallengeDigest        string `json:"challenge_digest"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
}

type EndpointGroupKeyProof struct {
	Claims    EndpointGroupKeyClaims `json:"claims"`
	Signature []byte                 `json:"signature"`
}

func ValidateEndpointGroupKeyClaims(c EndpointGroupKeyClaims, p EndpointGroupPolicy, now time.Time) error {
	digest, err := EndpointGroupPolicyDigest(p)
	if err != nil || ValidateEndpointGroupPolicy(p, now) != nil || c.Version != 1 || c.Purpose != EndpointGroupKeyPurpose ||
		c.HubID != p.HubID || c.NodeID != p.Node.NodeID || c.NodeKeyEpoch != p.Node.NodeKeyEpoch || c.PolicyID != p.PolicyID || c.PolicyEpoch != p.Epoch ||
		c.PolicyDigest != digest || c.RegistrationDigest != p.RegistrationDigest || !canonicalSHA256Hex(c.OwnerControlDigest) ||
		!canonicalSHA256Hex(c.RelationDigest) || !canonicalSHA256Hex(c.ManifestDigest) || !canonicalSHA256Hex(c.CandidateBindingDigest) ||
		!appNodeProofID(c.ChallengeID) || !canonicalSHA256Hex(c.ChallengeDigest) || c.ExpiresAt != p.ExpiresAt {
		return ErrInvalidEnvelope
	}
	issued, err := parseCanonicalUTC(c.IssuedAt)
	policyIssued, _ := parseCanonicalUTC(p.IssuedAt)
	if err != nil || issued.Before(policyIssued) || (!now.IsZero() && issued.After(now.Add(30*time.Second))) {
		return ErrInvalidEnvelope
	}
	if c.ExpiresAt != "" {
		end, _ := parseCanonicalUTC(c.ExpiresAt)
		if !end.After(issued) {
			return ErrInvalidEnvelope
		}
	}
	return nil
}

// This signs a previously validated projection. It cannot change Owner scope.
func SignEndpointGroupKey(node *Identity, p EndpointGroupPolicy, c EndpointGroupKeyClaims) ([]byte, error) {
	if node == nil || !reflect.DeepEqual(node.Public(), p.Node.NodePublic) || ValidateEndpointGroupKeyClaims(c, p, time.Time{}) != nil {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(node, node.Public().ID, EndpointGroupKeyDomain, c)
	if err != nil {
		return nil, err
	}
	return marshalEndpointGroupProof(EndpointGroupKeyProof{c, sig})
}

func VerifyEndpointGroupKey(p EndpointGroupPolicy, raw []byte, now time.Time) (EndpointGroupKeyClaims, error) {
	var proof EndpointGroupKeyProof
	if len(raw) > MaxEndpointGroupProofBytes || tlsProofRead(raw, &proof) != nil || ValidateEndpointGroupKeyClaims(proof.Claims, p, now) != nil ||
		verifyAppNodeSignature(p.Node.NodePublic, EndpointGroupKeyDomain, proof.Claims, proof.Signature) != nil {
		return EndpointGroupKeyClaims{}, ErrInvalidEnvelope
	}
	return proof.Claims, nil
}
