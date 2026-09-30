package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// GroupSpaceEndpointEvidence mirrors the public Store projection without
// importing Store (which itself uses nodekeys for existing key manifests).
type GroupSpaceEndpointEvidence struct {
	EndpointID         string                 `json:"endpoint_id"`
	PrincipalID        string                 `json:"principal_id"`
	OwnerID            string                 `json:"owner_id"`
	NodeID             string                 `json:"node_id"`
	BindingID          string                 `json:"binding_id"`
	BindingEpoch       uint64                 `json:"binding_epoch"`
	MembershipRevision int64                  `json:"membership_revision"`
	JoinRevision       int64                  `json:"join_revision"`
	KeyID              string                 `json:"key_id"`
	PublicIdentity     e2ee.PublicIdentity    `json:"public_identity"`
	Grant              GroupEndpointKeyGrant  `json:"grant"`
	Candidate          GroupSpaceKeyCandidate `json:"candidate"`
}

// GroupSpaceKeyCandidate matches Store's JSON projection exactly, including
// its original attestation field names.
type GroupSpaceKeyCandidate struct {
	EndpointID   string              `json:"endpoint_id"`
	PrincipalID  string              `json:"principal_id"`
	OwnerID      string              `json:"owner_id"`
	NodeID       string              `json:"node_id"`
	Public       e2ee.PublicIdentity `json:"public_identity"`
	KeyID        string              `json:"key_id"`
	BindingID    string              `json:"binding_id"`
	BindingEpoch uint64              `json:"binding_epoch"`
	Proof        []byte              `json:"proof"`
	ProofDigest  string              `json:"proof_digest"`
	State        string              `json:"state"`
	Version      int64               `json:"version"`
}

// VerifyGroupSpaceEndpointKey checks the Owner-signed Group key grant against
// Node-local Owner trust. It accepts self and same-Node readers, unlike the
// peer routing pin API. The caller must separately check current Hub Guard;
// at is now for a new write or the signed reservation time for historical
// producer verification.
func (s *CryptoState) VerifyGroupSpaceEndpointKey(ctx context.Context,
	hubID, groupID string, evidence GroupSpaceEndpointEvidence,
	at time.Time) (e2ee.PublicIdentity, error) {
	if evidence.Grant.CurrentStatus != groupEndpointKeyGrantCurrent ||
		evidence.Candidate.State != "CANDIDATE" {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantStale
	}
	return s.verifyGroupSpaceEndpointKeyAt(ctx, hubID, groupID, evidence, at)
}

// VerifyGroupSpaceHistoricalProducerKey checks the original Owner proof at
// its producer-signed reservation time. It never authorizes a new write.
// Revoked local Owner trust remains a hard failure under current policy.
func (s *CryptoState) VerifyGroupSpaceHistoricalProducerKey(ctx context.Context,
	hubID, groupID string, evidence GroupSpaceEndpointEvidence,
	reservedAt time.Time) (e2ee.PublicIdentity, error) {
	return s.verifyGroupSpaceEndpointKeyAt(ctx, hubID, groupID, evidence, reservedAt)
}

// VerifyGroupSpaceHistoricalEndpointKey also applies to the original reader
// key snapshot; the current Hub read Guard remains independent.
func (s *CryptoState) VerifyGroupSpaceHistoricalEndpointKey(ctx context.Context,
	hubID, groupID string, evidence GroupSpaceEndpointEvidence,
	reservedAt time.Time) (e2ee.PublicIdentity, error) {
	return s.verifyGroupSpaceEndpointKeyAt(ctx, hubID, groupID, evidence, reservedAt)
}

func (s *CryptoState) verifyGroupSpaceEndpointKeyAt(ctx context.Context,
	hubID, groupID string, evidence GroupSpaceEndpointEvidence,
	at time.Time) (e2ee.PublicIdentity, error) {
	if ctx == nil || ctx.Err() != nil || at.IsZero() || hubID == "" || groupID == "" {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
	}
	grant := evidence.Grant
	m := grant.Manifest
	if grant.ID == "" || grant.OwnerID != evidence.OwnerID || grant.GroupID != groupID ||
		grant.EndpointID != evidence.EndpointID || grant.OwnerKeyID != m.OwnerKeyID ||
		m.Version != groupEndpointKeyGrantVersion || m.Operation != groupEndpointKeyGrantOperation ||
		m.HubID != hubID || m.GroupID != groupID || m.EndpointID != evidence.EndpointID ||
		m.PrincipalID != evidence.PrincipalID || m.OwnerID != evidence.OwnerID ||
		m.NodeID != evidence.NodeID || m.BindingID != evidence.BindingID ||
		m.BindingEpoch != evidence.BindingEpoch || m.MembershipRevision != evidence.MembershipRevision ||
		m.EndpointJoinRevision != evidence.JoinRevision || m.CandidateKeyID != evidence.KeyID ||
		!samePublicIdentity(m.CandidatePublicIdentity, evidence.PublicIdentity) ||
		!samePublicIdentity(evidence.Candidate.Public, evidence.PublicIdentity) ||
		evidence.Candidate.EndpointID != evidence.EndpointID ||
		evidence.Candidate.PrincipalID != evidence.PrincipalID ||
		evidence.Candidate.OwnerID != evidence.OwnerID ||
		evidence.Candidate.NodeID != evidence.NodeID ||
		evidence.Candidate.BindingID != evidence.BindingID ||
		evidence.Candidate.BindingEpoch != evidence.BindingEpoch ||
		evidence.Candidate.KeyID != evidence.KeyID ||
		evidence.Candidate.Version != m.CandidateVersion ||
		evidence.Candidate.ProofDigest != m.CandidateProofDigest ||
		m.Digest != groupEndpointKeyManifestDigest(m) ||
		m.CandidateBindingDigest != groupEndpointKeyBindingDigest(m) {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
	}
	if err := e2ee.ValidatePublicIdentity(evidence.PublicIdentity); err != nil {
		return e2ee.PublicIdentity{}, err
	}
	fingerprint, err := PeerKeyFingerprint(evidence.PublicIdentity)
	if err != nil || fingerprint != m.CandidateFingerprint {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
	}
	proofDigest := sha256.Sum256(evidence.Candidate.Proof)
	if !bytes.Equal(evidence.Candidate.Proof, m.CandidateAttestation) ||
		hex.EncodeToString(proofDigest[:]) != m.CandidateProofDigest {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
	}
	public, err := e2ee.VerifyEndpointKeyAttestation(evidence.Candidate.Proof,
		evidence.EndpointID, evidence.PrincipalID, evidence.NodeID,
		evidence.BindingID, evidence.BindingEpoch)
	if err != nil || !samePublicIdentity(public, evidence.PublicIdentity) {
		return e2ee.PublicIdentity{}, ErrPeerPinUnverified
	}
	trust, err := s.nodeOwnerTrustForGroupEndpointGrant(m.OwnerID, m.OwnerKeyID)
	if err != nil || trust.State != NodeOwnerKeyTrustActive {
		return e2ee.PublicIdentity{}, ErrPeerPinOwnerTrustRequired
	}
	if _, err := e2ee.VerifyOwnerLinkKeyGrant(grant.SignedProof, trust.PublicIdentity,
		m.OwnerID, groupEndpointKeyGrantOperation, m.Digest,
		m.CandidateBindingDigest, uint64(m.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, at); err != nil {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantInvalid
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, m.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	if issueErr != nil || expiryErr != nil || issued.After(at) || !expires.After(at) ||
		!expires.After(issued) || m.IssuedAt != issued.UTC().Format(time.RFC3339Nano) ||
		m.ExpiresAt != expires.UTC().Format(time.RFC3339Nano) {
		return e2ee.PublicIdentity{}, ErrGroupEndpointKeyGrantExpired
	}
	if ctx.Err() != nil {
		return e2ee.PublicIdentity{}, ctx.Err()
	}
	return public, nil
}
