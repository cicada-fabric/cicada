package hubaccountwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// The complete typed member has no optional maps or signatures. Field order,
// JSON escaping and UTF-8 encoding are the canonical Go DTO representation.
// This separate domain binds SID/cwd/access/lease coordinates which are absent
// from the legacy generic Group key manifest and its binding digest.
func LocalDomainMemberDigest(m LocalDomainMember) (string, error) {
	if ValidateLocalDomainSelection(m.Selection) != nil {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", ErrInvalid
	}
	hash := sha256.Sum256(append([]byte("cicada/local-domain/member/v1\x00"), raw...))
	return hex.EncodeToString(hash[:]), nil
}

// The manifest/binding digest algorithms are the existing generic Group key
// contract. Reusing their canonical claims does not reuse Pair authorization.
func LocalDomainGroupManifestDigest(m LocalDomainKeyManifest) (string, error) {
	var existing NativePairGroupKeyManifest
	raw, err := json.Marshal(m)
	if err != nil {
		return "", ErrInvalid
	}
	if json.Unmarshal(raw, &existing) != nil {
		return "", ErrInvalid
	}
	return NativePairGroupManifestDigest(existing)
}

func LocalDomainGroupBindingDigest(m LocalDomainKeyManifest) (string, error) {
	var existing NativePairGroupKeyManifest
	raw, err := json.Marshal(m)
	if err != nil {
		return "", ErrInvalid
	}
	if json.Unmarshal(raw, &existing) != nil {
		return "", ErrInvalid
	}
	return NativePairGroupBindingDigest(existing)
}

// trustedOwner must come from the existing independent Node-local Owner pin.
// This authenticates a delegated key; it does not assert live server authority.
func VerifyLocalDomainEndpointKeyGrant(g LocalDomainEndpointKeyGrant, hub HubIdentity, expectedOwnerID string, trustedOwner e2ee.PublicIdentity, now time.Time) (e2ee.LocalDomainPolicy, error) {
	invalid := func() (e2ee.LocalDomainPolicy, error) { return e2ee.LocalDomainPolicy{}, ErrInvalid }
	p, err := e2ee.VerifyOwnerLocalDomainPolicy(trustedOwner, g.PolicyProof, now)
	if err != nil || g.ContractRevision != LocalDomainContractRevision || p.OwnerID != expectedOwnerID || ValidateLocalDomainPolicy(p, hub, now) != nil {
		return invalid()
	}
	selection, err := LocalDomainSelectionForPolicy(p)
	if err != nil {
		return invalid()
	}
	m, k := g.Member, g.Manifest
	if m.Selection != selection || m.State != LocalDomainMemberActive || m.Revision < 2 || !nativePairPositive(m.Revision) || m.NodeID != p.Node.NodeID || m.LocalUserScope != p.LocalUserScope ||
		m.Runtime != "codex" || !nativePairToken(m.NativeSessionID) || m.Workspace == "" || len(m.Workspace) > 1024 || !nativePairToken(m.MemberID) || !nativePairToken(m.EndpointID) || !nativePairToken(m.PrincipalID) || !nativePairToken(m.BindingID) || !nativePairToken(m.NetworkAccessBindingID) || !nativePairToken(m.LeaseOwner) {
		return invalid()
	}
	for _, n := range []uint64{m.BindingEpoch, m.NetworkAccessEpoch, m.NetworkMembershipRevision, m.EndpointNetworkRevision, m.MembershipRevision, m.EndpointJoinRevision, m.CandidateVersion} {
		if !nativePairPositive(n) {
			return invalid()
		}
	}
	if k.Version != 1 || k.Operation != "group-endpoint-key-grant:v1" || k.HubID != p.HubID || k.OwnerID != expectedOwnerID || k.OwnerKeyID != trustedOwner.ID || k.GroupID != p.GroupID || k.GroupRevision <= 0 ||
		k.NodeID != m.NodeID || k.EndpointID != m.EndpointID || k.PrincipalID != m.PrincipalID || k.BindingID != m.BindingID || k.BindingEpoch != m.BindingEpoch ||
		k.MembershipRevision != int64(m.MembershipRevision) || k.EndpointJoinRevision != int64(m.EndpointJoinRevision) || k.CandidateVersion != int64(m.CandidateVersion) ||
		k.CandidateKeyID != m.CandidateKeyID || k.CandidateFingerprint != m.CandidateFingerprint || k.CandidateProofDigest != m.CandidateProofDigest || k.ExpiresAt != p.ExpiresAt || len(k.CandidateAttestation) > 16<<10 {
		return invalid()
	}
	if e2ee.ValidatePublicIdentity(k.CandidatePublicIdentity) != nil || k.CandidatePublicIdentity.ID != k.CandidateKeyID || k.CandidateFingerprint != nativePairPeerFingerprint(k.CandidatePublicIdentity) {
		return invalid()
	}
	hash := sha256.Sum256(k.CandidateAttestation)
	verified, err := e2ee.VerifyEndpointKeyAttestation(k.CandidateAttestation, k.EndpointID, k.PrincipalID, k.NodeID, k.BindingID, k.BindingEpoch)
	if err != nil || !reflect.DeepEqual(verified, k.CandidatePublicIdentity) || hex.EncodeToString(hash[:]) != k.CandidateProofDigest {
		return invalid()
	}
	binding, err := LocalDomainGroupBindingDigest(k)
	if err != nil || binding != k.CandidateBindingDigest {
		return invalid()
	}
	digest, err := LocalDomainGroupManifestDigest(k)
	if err != nil || digest != k.Digest {
		return invalid()
	}
	claims, err := e2ee.VerifyLocalDomainEndpointKey(p, g.NodeProof, now)
	memberDigest, mdErr := LocalDomainMemberDigest(m)
	if err != nil || claims.PolicyID != p.PolicyID || claims.PolicyEpoch != p.Epoch || claims.PolicyDigest != selection.PolicyDigest || claims.MemberID != m.MemberID || claims.MemberRevision != m.Revision ||
		mdErr != nil || claims.MemberDigest != memberDigest || claims.ManifestDigest != k.Digest || claims.CandidateBindingDigest != k.CandidateBindingDigest || claims.IssuedAt != k.IssuedAt || claims.ExpiresAt != k.ExpiresAt {
		return invalid()
	}
	return p, nil
}

// Current is authenticated by the containing Hub route. It authorizes exactly
// this operation/attempt; a Node still fetches it afresh immediately before
// each final native attempt rather than treating its TTL as a reusable lease.
func ValidateLocalDomainCurrent(c LocalDomainCurrent, p e2ee.LocalDomainPolicy, sender, receiver LocalDomainMember, operation, attempt string, now time.Time) error {
	selection, err := LocalDomainSelectionForPolicy(p)
	if err != nil || now.IsZero() || c.ContractRevision != LocalDomainContractRevision || c.Selection != selection || c.State != "CURRENT" || c.Revision < 2 || !nativePairPositive(c.Revision) ||
		c.Operation != operation || c.AttemptID != attempt || operation == "" || attempt == "" || !reflect.DeepEqual(c.Sender, sender) || !reflect.DeepEqual(c.Receiver, receiver) || sender.EndpointID == receiver.EndpointID ||
		sender.Selection != selection || receiver.Selection != selection || sender.NodeID != p.Node.NodeID || receiver.NodeID != p.Node.NodeID || sender.LocalUserScope != p.LocalUserScope || receiver.LocalUserScope != p.LocalUserScope ||
		sender.State != LocalDomainMemberActive || receiver.State != LocalDomainMemberActive || validateTimeWindowNow(c.ObservedAt, c.ExpiresAt, 30*time.Second, now) != nil || e2ee.ValidateLocalDomainPolicy(p, now) != nil {
		return ErrInvalid
	}
	if p.ExpiresAt != "" {
		end, _ := parseCanonicalUTC(c.ExpiresAt)
		policyEnd, _ := parseCanonicalUTC(p.ExpiresAt)
		if end.After(policyEnd) {
			return ErrInvalid
		}
	}
	return nil
}
