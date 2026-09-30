package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	crossOwnerGroupSpaceEvidenceProtocol = "cross-owner-group-key-v2"
	crossOwnerGroupKeyOperation          = "group-endpoint-key-grant:v2:cross-owner"
	crossOwnerGroupKeyManifestDomain     = "cicada/group/cross-owner-key-manifest/v2\x00"
	crossOwnerGroupKeyBindingDomain      = "cicada/group/cross-owner-key-binding/v2\x00"
)

// These JSON projections deliberately match Store's signed public evidence
// without importing Store into Node's independent trust verifier.
type CrossOwnerGroupKeyManifest struct {
	Version                 int                 `json:"version"`
	Operation               string              `json:"operation"`
	HubID                   string              `json:"hub_id"`
	NetworkID               string              `json:"network_id"`
	GroupID                 string              `json:"group_id"`
	GroupRevision           int64               `json:"group_revision"`
	EndpointID              string              `json:"endpoint_id"`
	PrincipalID             string              `json:"principal_id"`
	EndpointOwnerID         string              `json:"endpoint_owner_id"`
	GroupOwnerID            string              `json:"group_owner_id"`
	NodeID                  string              `json:"node_id"`
	BindingID               string              `json:"binding_id"`
	BindingEpoch            uint64              `json:"binding_epoch"`
	MembershipRevision      int64               `json:"membership_revision"`
	EndpointJoinRevision    int64               `json:"endpoint_join_revision"`
	CandidateVersion        int64               `json:"candidate_version"`
	CandidateKeyID          string              `json:"candidate_key_id"`
	CandidateFingerprint    string              `json:"candidate_fingerprint"`
	CandidateProofDigest    string              `json:"candidate_proof_digest"`
	CandidatePublicIdentity e2ee.PublicIdentity `json:"candidate_public_identity"`
	CandidateAttestation    []byte              `json:"candidate_attestation"`
	CandidateBindingDigest  string              `json:"candidate_binding_digest"`
	Capabilities            []string            `json:"capabilities"`
	CrossOwnerContextShared bool                `json:"cross_owner_context_shared"`
	HistoryIncluded         bool                `json:"history_included"`
	ExpiresAt               string              `json:"expires_at"`
	Digest                  string              `json:"digest"`
}

type CrossOwnerGroupKeyProof struct {
	ID             string `json:"proof_id"`
	GroupID        string `json:"group_id"`
	EndpointID     string `json:"endpoint_id"`
	SignerOwnerID  string `json:"signer_owner_id"`
	SignerSide     string `json:"signer_side"`
	OwnerKeyID     string `json:"owner_key_id"`
	ManifestDigest string `json:"manifest_digest"`
	AcceptedAt     string `json:"accepted_at"`
	CurrentStatus  string `json:"current_status"`
	SignedProof    []byte `json:"signed_proof,omitempty"`
}

type CrossOwnerGroupKeyStatus struct {
	Manifest        CrossOwnerGroupKeyManifest `json:"manifest"`
	EndpointConsent *CrossOwnerGroupKeyProof   `json:"endpoint_consent,omitempty"`
	GroupAdmission  *CrossOwnerGroupKeyProof   `json:"group_admission,omitempty"`
	Current         bool                       `json:"current"`
}

func crossOwnerGroupManifestDigest(m CrossOwnerGroupKeyManifest) string {
	m.Digest = ""
	encoded, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte(crossOwnerGroupKeyManifestDomain), encoded...))
	return hex.EncodeToString(sum[:])
}

func crossOwnerGroupBindingDigest(m CrossOwnerGroupKeyManifest) string {
	claims, err := json.Marshal(struct {
		HubID            string `json:"hub_id"`
		NetworkID        string `json:"network_id"`
		GroupID          string `json:"group_id"`
		EndpointID       string `json:"endpoint_id"`
		BindingID        string `json:"binding_id"`
		BindingEpoch     uint64 `json:"binding_epoch"`
		CandidateKeyID   string `json:"candidate_key_id"`
		CandidateVersion int64  `json:"candidate_version"`
		Fingerprint      string `json:"fingerprint"`
		ProofDigest      string `json:"proof_digest"`
	}{m.HubID, m.NetworkID, m.GroupID, m.EndpointID, m.BindingID, m.BindingEpoch,
		m.CandidateKeyID, m.CandidateVersion, m.CandidateFingerprint, m.CandidateProofDigest})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte(crossOwnerGroupKeyBindingDomain), claims...))
	return hex.EncodeToString(sum[:])
}

func (s *CryptoState) verifyCrossOwnerGroupSpaceEndpointKey(ctx context.Context,
	hubID, groupID string, evidence GroupSpaceEndpointEvidence, at time.Time) (e2ee.PublicIdentity, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || at.IsZero() || evidence.CrossOwnerKeyStatus == nil {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
	}
	status := evidence.CrossOwnerKeyStatus
	m := status.Manifest
	if !status.Current || status.EndpointConsent == nil || status.GroupAdmission == nil ||
		m.Version != 2 || m.Operation != crossOwnerGroupKeyOperation ||
		m.HubID != hubID || m.NetworkID == "" || m.GroupID != groupID || m.GroupRevision <= 0 ||
		m.EndpointID != evidence.EndpointID || m.PrincipalID != evidence.PrincipalID ||
		m.EndpointOwnerID != evidence.OwnerID || m.GroupOwnerID == "" || m.GroupOwnerID == m.EndpointOwnerID ||
		m.NodeID != evidence.NodeID || m.BindingID != evidence.BindingID ||
		m.BindingEpoch != evidence.BindingEpoch || m.MembershipRevision != evidence.MembershipRevision ||
		m.EndpointJoinRevision != evidence.JoinRevision || m.CandidateVersion <= 0 ||
		m.CandidateKeyID != evidence.KeyID || !samePublicIdentity(m.CandidatePublicIdentity, evidence.PublicIdentity) ||
		!m.CrossOwnerContextShared || m.HistoryIncluded || m.Digest == "" ||
		m.Digest != crossOwnerGroupManifestDigest(m) ||
		m.CandidateBindingDigest != crossOwnerGroupBindingDigest(m) {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
	}
	read := false
	for _, capability := range m.Capabilities {
		if capability == "space.read" {
			read = true
		}
	}
	if !read {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
	}
	candidate := evidence.Candidate
	if candidate.State != "CANDIDATE" || candidate.EndpointID != evidence.EndpointID ||
		candidate.PrincipalID != evidence.PrincipalID || candidate.OwnerID != evidence.OwnerID ||
		candidate.NodeID != evidence.NodeID || candidate.BindingID != evidence.BindingID ||
		candidate.BindingEpoch != evidence.BindingEpoch || candidate.Version != m.CandidateVersion ||
		candidate.KeyID != evidence.KeyID || candidate.ProofDigest != m.CandidateProofDigest ||
		!samePublicIdentity(candidate.Public, evidence.PublicIdentity) ||
		!bytes.Equal(candidate.Proof, m.CandidateAttestation) {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
	}
	proofDigest := sha256.Sum256(candidate.Proof)
	if hex.EncodeToString(proofDigest[:]) != m.CandidateProofDigest {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
	}
	fingerprint, err := PeerKeyFingerprint(evidence.PublicIdentity)
	if err != nil || fingerprint != m.CandidateFingerprint {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
	}
	public, err := e2ee.VerifyEndpointKeyAttestation(candidate.Proof, evidence.EndpointID,
		evidence.PrincipalID, evidence.NodeID, evidence.BindingID, evidence.BindingEpoch)
	if err != nil || !samePublicIdentity(public, evidence.PublicIdentity) {
		return e2ee.PublicIdentity{}, ErrPeerPinUnverified
	}
	expires, err := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	if err != nil || m.ExpiresAt != expires.UTC().Format(time.RFC3339Nano) || !expires.After(at) {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantExpired
	}
	for _, side := range []struct {
		proof          *CrossOwnerGroupKeyProof
		ownerID, label string
		wireSide       e2ee.OwnerLinkGrantSide
	}{{status.EndpointConsent, m.EndpointOwnerID, "ENDPOINT", e2ee.OwnerLinkGrantSideSource},
		{status.GroupAdmission, m.GroupOwnerID, "GROUP", e2ee.OwnerLinkGrantSideTarget}} {
		p := side.proof
		if p.ID == "" || p.GroupID != groupID || p.EndpointID != evidence.EndpointID ||
			p.SignerOwnerID != side.ownerID || p.SignerSide != side.label || p.OwnerKeyID == "" ||
			p.ManifestDigest != m.Digest || p.CurrentStatus != "CURRENT" || len(p.SignedProof) == 0 {
			return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
		}
		trust, err := s.nodeOwnerTrustForGroupEndpointGrant(side.ownerID, p.OwnerKeyID)
		if err != nil || trust.State != NodeOwnerKeyTrustActive {
			return e2ee.PublicIdentity{}, ErrPeerPinOwnerTrustRequired
		}
		verified, err := e2ee.VerifyOwnerLinkKeyGrant(p.SignedProof, trust.PublicIdentity,
			side.ownerID, crossOwnerGroupKeyOperation, m.Digest, m.CandidateBindingDigest,
			uint64(m.CandidateVersion), side.wireSide, at)
		if err != nil {
			return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
		}
		proofExpiry, err := time.Parse(time.RFC3339Nano, verified.ExpiresAt)
		if err != nil || proofExpiry.After(expires) {
			return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
		}
	}
	if err := ctx.Err(); err != nil {
		return e2ee.PublicIdentity{}, err
	}
	return public, nil
}
