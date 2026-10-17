package hubaccountwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func NativePairHTTPPath(operation string) string {
	switch operation {
	case OperationNativePairBootstrapPrepare:
		return "/v2/owner/native-pairs/bootstrap/prepare"
	case OperationNativePairBootstrapComplete:
		return "/v2/owner/native-pairs/bootstrap/complete"
	case OperationNativePairSlotReject:
		return "/v2/owner/native-pairs/slots/reject"
	case OperationNativePairConsentPrepare:
		return "/v2/owner/native-pairs/consent/prepare"
	case OperationNativePairConsentComplete:
		return "/v2/owner/native-pairs/consent/complete"
	case OperationNativePairStatus:
		return "/v2/owner/native-pairs/status"
	case OperationNativePairRevoke:
		return "/v2/owner/native-pairs/revoke"
	case OperationNativePairReconcile:
		return "/v2/owner/native-pairs/reconcile"
	}
	return ""
}

func NativePairOwnerPurpose(operation string) string {
	switch operation {
	case OperationNativePairBootstrapPrepare:
		return e2ee.OwnerNativePairBootstrapPreview
	case OperationNativePairBootstrapComplete:
		return e2ee.OwnerNativePairBootstrapCommit
	case OperationNativePairConsentPrepare:
		return e2ee.OwnerNativePairConsentPreview
	case OperationNativePairConsentComplete:
		return e2ee.OwnerNativePairSlotConsent
	case OperationNativePairSlotReject:
		return e2ee.OwnerNativePairSlotReject
	case OperationNativePairRevoke:
		return e2ee.OwnerNativePairRevoke
	}
	return ""
}

func NativePairGroupGrants() []string {
	return []string{"directory.read", "message.ask", "message.receive", "message.reply"}
}

func nativePairDigest(domain string, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalid
	}
	h := sha256.Sum256(append([]byte(domain), raw...))
	return hex.EncodeToString(h[:]), nil
}

func NativePairProofDigest(raw []byte) string {
	h := sha256.Sum256(append([]byte("cicada/native-pair/owner-proof/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}

// Call on the complete authorization response before sealing it. Evidence has
// its own stricter bound; neither check changes legacy peer ciphertext limits.
func ValidateNativePairCarrierSize(carrier any) error {
	raw, err := json.Marshal(carrier)
	if err != nil || len(raw) > MaxNativePairCarrierBytes {
		return ErrInvalid
	}
	return nil
}

// Only authority fields: no actor login, Node label, heartbeat or observed time.
func NativePairNodeTupleDigest(s e2ee.OwnerNativePairScope) (string, error) {
	n := s.Node
	n.NodeName = ""
	return nativePairDigest("cicada/native-pair/node-tuple/v1\x00", struct {
		Node           e2ee.OwnerAppNodeBinding `json:"node"`
		ControlVersion uint64                   `json:"node_control_binding_version"`
		Credential     string                   `json:"credential_commitment"`
	}{n, s.NodeControlBindingVersion, s.CredentialCommitment})
}

func NativePairSlotDigest(s NativePairSlot) (string, error) {
	return nativePairDigest("cicada/native-pair/slot/v1\x00", s)
}

func NativePairPlanDigest(p NativePairConsentPlan) (string, error) {
	p.Digest = ""
	return nativePairDigest("cicada/native-pair/consent-plan/v1\x00", p)
}

func NativePairGroupManifestDigest(m NativePairGroupKeyManifest) (string, error) {
	return nativePairDigest("cicada/group/endpoint-key-grant-manifest/v1\x00", m.NativePairGroupKeyClaims)
}

func NativePairGroupBindingDigest(m NativePairGroupKeyManifest) (string, error) {
	return nativePairDigest("cicada/group/endpoint-key-binding/v1\x00", struct {
		Operation            string              `json:"operation"`
		OwnerID              string              `json:"owner_id"`
		PrincipalID          string              `json:"principal_id"`
		GroupID              string              `json:"group_id"`
		EndpointID           string              `json:"endpoint_id"`
		NodeID               string              `json:"node_id"`
		BindingID            string              `json:"binding_id"`
		BindingEpoch         uint64              `json:"binding_epoch"`
		MembershipRevision   int64               `json:"membership_revision"`
		EndpointJoinRevision int64               `json:"endpoint_join_revision"`
		CandidateVersion     int64               `json:"candidate_version"`
		CandidateKeyID       string              `json:"candidate_key_id"`
		Fingerprint          string              `json:"candidate_fingerprint"`
		ProofDigest          string              `json:"candidate_proof_digest"`
		PublicIdentity       e2ee.PublicIdentity `json:"candidate_public_identity"`
	}{m.Operation, m.OwnerID, m.PrincipalID, m.GroupID, m.EndpointID, m.NodeID, m.BindingID, m.BindingEpoch,
		m.MembershipRevision, m.EndpointJoinRevision, m.CandidateVersion, m.CandidateKeyID, m.CandidateFingerprint, m.CandidateProofDigest, m.CandidatePublicIdentity})
}

func nativePairPositive(n uint64) bool { return n > 0 && n < math.MaxInt64 }

func nativePairToken(s string) bool {
	if s == "" || len(s) > 128 || s == "." || s == ".." {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':')
	}) == -1
}

func ValidateNativePairScope(s e2ee.OwnerNativePairScope, hub HubIdentity) error {
	if validateNativePairKnownScope(s, hub) != nil || !isHex(s.CredentialCommitment, 32) || !nativePairPositive(s.NodeControlBindingVersion) {
		return ErrInvalid
	}
	digest, err := NativePairNodeTupleDigest(s)
	if err != nil || digest != s.NodeTupleDigest {
		return ErrInvalid
	}
	return nil
}

// Only BootstrapPreview has this exact all-empty Store-field shape. Other
// purpose validators always require ValidateNativePairScope.
func ValidateNativePairBootstrapPreviewScope(s e2ee.OwnerNativePairScope, hub HubIdentity) error {
	if validateNativePairKnownScope(s, hub) != nil || s.NodeControlBindingVersion != 0 || s.CredentialCommitment != "" || s.NodeTupleDigest != "" {
		return ErrInvalid
	}
	return nil
}

func validateNativePairKnownScope(s e2ee.OwnerNativePairScope, hub HubIdentity) error {
	if ValidateAppNodeScope(s.Actor, hub) != nil || s.Actor.HeadVersion != 0 || len(s.Actor.Origin) > 512 || !utf8.ValidString(s.Node.NodeName) || len(s.Node.NodeName) > 128 || strings.ContainsAny(s.Node.NodeName, "\x00\r\n") {
		return ErrInvalid
	}
	for _, id := range []string{s.Actor.HubID, s.Actor.AccountID, s.Actor.AccountSessionID, s.Actor.OwnerID, s.Actor.DeviceID} {
		if !nativePairToken(id) {
			return ErrInvalid
		}
	}
	// Reuse the cryptographic structure validator without inventing authority.
	n := s.Node
	if n.OwnerID != s.Actor.OwnerID || n.HubID != hub.HubID || n.ClientDeviceID != s.Actor.DeviceID || n.OwnerKeyID != s.Actor.OwnerPublic.ID || n.State != "ACTIVE" ||
		!nativePairToken(n.OwnerBindingID) || !nativePairToken(n.NodeID) || n.NodeID == "control-local" || n.NodeID == "worker-local" ||
		e2ee.ValidatePublicIdentity(n.NodePublic) != nil || e2ee.ValidatePublicIdentity(n.HubNodeControlPublic) != nil || n.NodePublic.ID == n.HubNodeControlPublic.ID ||
		n.NodeKeyFingerprint != nodewire.IdentityFingerprint(n.NodePublic) || n.HubNodeControlFingerprint != nodewire.IdentityFingerprint(n.HubNodeControlPublic) ||
		!nativePairToken(n.ApprovedRequestID) || !isHex(n.ApprovedCandidateDigest, 32) || validateCanonicalTime(n.ApprovedAt) != nil {
		return ErrInvalid
	}
	for _, v := range []uint64{n.BindingVersion, n.CredentialVersion, n.NodeKeyEpoch, n.NodeKeyVersion, n.HubNodeControlKeyVersion, n.ApprovedRequestVersion} {
		if !nativePairPositive(v) {
			return ErrInvalid
		}
	}
	return nil
}

func nativePairPeerFingerprint(p e2ee.PublicIdentity) string {
	h := sha256.New()
	_, _ = h.Write([]byte("cicada/nodekeys/peer-key-fingerprint/v1\x00"))
	_, _ = h.Write(p.KEMPublic)
	_, _ = h.Write(p.SigningPublic)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func ValidateNativePairSlot(s NativePairSlot, scope e2ee.OwnerNativePairScope, peerEnd string) error {
	if (s.Slot != "A" && s.Slot != "B") || s.Generation == 0 || s.Generation > MaxNativePairSlotGenerations || !isHex(s.AttemptID, RequestIDBytes) || s.Runtime != "codex" ||
		!nativePairToken(s.NativeSessionID) || !nativePairToken(s.EndpointID) || !nativePairToken(s.PrincipalID) || s.NodeID != scope.Node.NodeID ||
		!nativePairToken(s.NetworkAccessBindingID) || !nativePairToken(s.BindingID) || !nativePairToken(s.LeaseOwner) || s.LeaseCeiling != peerEnd ||
		e2ee.ValidatePublicIdentity(s.CandidatePublic) != nil || s.CandidateFingerprint != nativePairPeerFingerprint(s.CandidatePublic) || !isHex(s.CandidateProofDigest, 32) || len(s.CandidateAttestation) > 16*1024 {
		return ErrInvalid
	}
	for _, n := range []uint64{s.NetworkAccessEpoch, s.NetworkMembershipRevision, s.EndpointNetworkRevision, s.BindingEpoch, s.MembershipRevision, s.EndpointJoinRevision, s.CandidateVersion} {
		if !nativePairPositive(n) {
			return ErrInvalid
		}
	}
	h := sha256.Sum256(s.CandidateAttestation)
	verified, err := e2ee.VerifyEndpointKeyAttestation(s.CandidateAttestation, s.EndpointID, s.PrincipalID, s.NodeID, s.BindingID, s.BindingEpoch)
	if err != nil || !reflect.DeepEqual(verified, s.CandidatePublic) || s.CandidateProofDigest != hex.EncodeToString(h[:]) {
		return ErrInvalid
	}
	return nil
}

func validateNativePairManifest(m NativePairGroupKeyManifest, s NativePairSlot, p NativePairConsentPlan, projected uint64) error {
	if !nativePairPositive(projected) || projected != s.MembershipRevision+1 || m.Version != 1 || m.Operation != "group-endpoint-key-grant:v1" || m.HubID != p.Scope.Actor.HubID || m.OwnerID != p.Scope.Actor.OwnerID ||
		m.GroupID != p.GroupID || m.GroupRevision != int64(p.GroupRevision) || m.PrincipalID != s.PrincipalID || m.EndpointID != s.EndpointID || m.NodeID != s.NodeID || m.BindingID != s.BindingID || m.BindingEpoch != s.BindingEpoch ||
		m.MembershipRevision != int64(projected) || m.EndpointJoinRevision != int64(s.EndpointJoinRevision) || m.CandidateVersion != int64(s.CandidateVersion) || m.CandidateKeyID != s.CandidatePublic.ID ||
		m.CandidateFingerprint != s.CandidateFingerprint || m.CandidateProofDigest != s.CandidateProofDigest || !reflect.DeepEqual(m.CandidatePublicIdentity, s.CandidatePublic) || !bytes.Equal(m.CandidateAttestation, s.CandidateAttestation) ||
		m.OwnerKeyID != p.Scope.Actor.OwnerPublic.ID || m.IssuedAt != p.PreparedAt || m.ExpiresAt != p.PeerExpiresAt {
		return ErrInvalid
	}
	d, e := NativePairGroupManifestDigest(m)
	b, be := NativePairGroupBindingDigest(m)
	if e != nil || be != nil || d != m.Digest || b != m.CandidateBindingDigest {
		return ErrInvalid
	}
	return nil
}

// A plan remains inspectable after its administration window. This structural
// helper never confers live administration or current peer authority.
func ValidateNativePairPlan(p NativePairConsentPlan, hub HubIdentity) error {
	if p.Format != NativePairFormat || !isHex(p.PairID, RequestIDBytes) || !isHex(p.PlanID, RequestIDBytes) || !nativePairPositive(p.ExpectedRevision) || ValidateNativePairScope(p.Scope, hub) != nil ||
		!isHex(p.BootstrapProofDigest, 32) || !nativePairToken(p.NetworkID) || !nativePairToken(p.GroupID) || !nativePairPositive(p.NetworkVersion) || !nativePairPositive(p.GroupVersion) || !nativePairPositive(p.GroupRevision) ||
		p.Policy != e2ee.NativePairFixedPeerPolicy() || !reflect.DeepEqual(p.GroupGrants, NativePairGroupGrants()) || p.SlotA.Slot != "A" || p.SlotB.Slot != "B" ||
		p.SlotA.NativeSessionID == p.SlotB.NativeSessionID || p.SlotA.EndpointID == p.SlotB.EndpointID || p.SlotA.PrincipalID == p.SlotB.PrincipalID || p.SlotA.BindingID == p.SlotB.BindingID || p.SlotA.CandidatePublic.ID == p.SlotB.CandidatePublic.ID ||
		ValidateNativePairSlot(p.SlotA, p.Scope, p.PeerExpiresAt) != nil || ValidateNativePairSlot(p.SlotB, p.Scope, p.PeerExpiresAt) != nil {
		return ErrInvalid
	}
	prepared, e := parseCanonicalUTC(p.PreparedAt)
	end, ee := parseCanonicalUTC(p.ExpiresAt)
	peer, pe := parseCanonicalUTC(p.PeerExpiresAt)
	session, se := parseCanonicalUTC(p.Scope.Actor.AccountSessionExpiresAt)
	if e != nil || ee != nil || pe != nil || se != nil || !end.After(prepared) || end.After(prepared.Add(5*time.Minute)) || end.After(peer) || end.After(session) {
		return ErrInvalid
	}
	if validateNativePairManifest(p.SlotAKeyManifest, p.SlotA, p, p.ProjectedSlotAMembership) != nil || validateNativePairManifest(p.SlotBKeyManifest, p.SlotB, p, p.ProjectedSlotBMembership) != nil {
		return ErrInvalid
	}
	d, e := NativePairPlanDigest(p)
	raw, re := json.Marshal(p)
	if e != nil || re != nil || len(raw) > MaxNativePairPlanBytes || d != p.Digest {
		return ErrInvalid
	}
	return nil
}

func ValidateNativePairPlanForConsent(p NativePairConsentPlan, hub HubIdentity, now time.Time) error {
	if now.IsZero() || ValidateNativePairPlan(p, hub) != nil {
		return ErrInvalid
	}
	start, _ := parseCanonicalUTC(p.PreparedAt)
	end, _ := parseCanonicalUTC(p.ExpiresAt)
	if start.After(now.Add(30*time.Second)) || !now.Before(end) {
		return ErrInvalid
	}
	return nil
}

// The caller supplies its trusted profile/required-policy marker and independent
// Owner pin. Expired admin signatures are history; only signed PeerExpiresAt
// bounds this evidence. Current Store/Node Guards and durable budgets are separate.
func VerifyNativePairPeerEvidence(e NativePairPeerEvidence, hub HubIdentity, trustedOwner e2ee.PublicIdentity, expectedNodeTupleDigest string, now time.Time) error {
	if now.IsZero() || e.ContractRevision != NativePairContractRevision || ValidateNativePairPlan(e.Plan, hub) != nil || e.Plan.Scope.NodeTupleDigest != expectedNodeTupleDigest {
		return ErrInvalid
	}
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > MaxNativePairEvidenceBytes {
		return ErrInvalid
	}
	p := e.Plan
	peer, _ := parseCanonicalUTC(p.PeerExpiresAt)
	if !now.Before(peer) {
		return ErrInvalid
	}
	b, err := e2ee.VerifyOwnerNativePair(trustedOwner, e.BootstrapOwnerProof, e2ee.OwnerNativePairBootstrapCommit, time.Time{})
	if err != nil || b.Bootstrap.PairID != p.PairID || b.Bootstrap.NetworkID != p.NetworkID || b.Bootstrap.GroupID != p.GroupID || b.Bootstrap.PeerExpiresAt != p.PeerExpiresAt || b.Bootstrap.Policy != p.Policy || NativePairProofDigest(e.BootstrapOwnerProof) != p.BootstrapProofDigest {
		return ErrInvalid
	}
	if !nativePairSameStableScope(b.Scope, p.Scope) {
		return ErrInvalid
	}
	for i, rawProof := range [][]byte{e.SlotAOwnerConsent, e.SlotBOwnerConsent} {
		c, ce := e2ee.VerifyOwnerNativePair(trustedOwner, rawProof, e2ee.OwnerNativePairSlotConsent, time.Time{})
		if ce != nil || ValidateNativePairConsentTarget(c, p) != nil || (i == 0 && c.Consent.Slot != "A") || (i == 1 && c.Consent.Slot != "B") {
			return ErrInvalid
		}
	}
	for i, m := range []NativePairGroupKeyManifest{p.SlotAKeyManifest, p.SlotBKeyManifest} {
		proof := e.SlotAGroupKeyProof
		if i == 1 {
			proof = e.SlotBGroupKeyProof
		}
		if len(proof) > 16*1024 {
			return ErrInvalid
		}
		if _, err := e2ee.VerifyOwnerLinkKeyGrant(proof, trustedOwner, p.Scope.Actor.OwnerID, "group-endpoint-key-grant:v1", m.Digest, m.CandidateBindingDigest, uint64(m.CandidateVersion), e2ee.OwnerLinkGrantSideSource, now); err != nil {
			return ErrInvalid
		}
	}
	return nil
}

func ValidateNativePairConsentTarget(c e2ee.OwnerNativePairClaims, p NativePairConsentPlan) error {
	d, de := NativePairPlanDigest(p)
	if de != nil || d != p.Digest || c.Purpose != e2ee.OwnerNativePairSlotConsent || e2ee.ValidateOwnerNativePairClaims(c, time.Time{}) != nil || !reflect.DeepEqual(c.Scope, p.Scope) {
		return ErrInvalid
	}
	v := c.Consent
	a, ae := NativePairSlotDigest(p.SlotA)
	b, be := NativePairSlotDigest(p.SlotB)
	s, other := p.SlotA, p.SlotB
	if v.Slot == "B" {
		s, other = other, s
	}
	if ae != nil || be != nil || v.PairID != p.PairID || v.ExpectedRevision != p.ExpectedRevision || v.PlanID != p.PlanID || v.PlanDigest != p.Digest || v.SlotADigest != a || v.SlotBDigest != b ||
		v.SlotGeneration != s.Generation || v.SlotAttemptID != s.AttemptID || v.NativeSessionID != s.NativeSessionID || v.PeerNativeSessionID != other.NativeSessionID || v.PlanExpiresAt != p.ExpiresAt || v.PeerExpiresAt != p.PeerExpiresAt {
		return ErrInvalid
	}
	return nil
}

// Full immutable scope, except the two explicitly replaceable administration
// session fields. Used both before consent and in independent peer verification.
func nativePairSameStableScope(a, b e2ee.OwnerNativePairScope) bool {
	a.Actor.AccountSessionID, b.Actor.AccountSessionID = "", ""
	a.Actor.AccountSessionExpiresAt, b.Actor.AccountSessionExpiresAt = "", ""
	return reflect.DeepEqual(a, b)
}

func NativePairRevokeTargetDigest(scope e2ee.OwnerNativePairScope, pairID string, expectedRevision uint64) (string, error) {
	if !isHex(pairID, RequestIDBytes) || !nativePairPositive(expectedRevision) {
		return "", ErrInvalid
	}
	return nativePairDigest("cicada/native-pair/revoke-target/v1\x00", struct {
		Scope            e2ee.OwnerNativePairScope `json:"scope"`
		PairID           string                    `json:"pair_id"`
		ExpectedRevision uint64                    `json:"expected_revision"`
	}{scope, pairID, expectedRevision})
}

func ValidateNativePairRevokeTarget(c e2ee.OwnerNativePairClaims) error {
	if c.Purpose != e2ee.OwnerNativePairRevoke || e2ee.ValidateOwnerNativePairClaims(c, time.Time{}) != nil {
		return ErrInvalid
	}
	d, err := NativePairRevokeTargetDigest(c.Scope, c.Revoke.PairID, c.Revoke.ExpectedRevision)
	if err != nil || c.Revoke.PairTargetDigest != d {
		return ErrInvalid
	}
	return nil
}
