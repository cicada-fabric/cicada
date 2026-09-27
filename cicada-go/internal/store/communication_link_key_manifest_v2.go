package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

const communicationLinkKeyManifestDomain = "cicada/communication-link/key-manifest/v2\x00"

var ErrCommunicationLinkKeyCandidate = errors.New("current Endpoint key candidate is unavailable or stale")

// CommunicationLinkKeySide binds the public-key candidate to the current
// Endpoint/Group/Principal/Owner/Node and exact native SessionBinding. Both
// public identities and self-attestations are inspectable by the approving
// owner, but neither is independently trusted until owner consent is checked.
type CommunicationLinkKeySide struct {
	EndpointID       string              `json:"endpoint_id"`
	GroupID          string              `json:"group_id"`
	PrincipalID      string              `json:"principal_id"`
	OwnerID          string              `json:"owner_id"`
	NodeID           string              `json:"node_id"`
	BindingID        string              `json:"binding_id"`
	BindingEpoch     uint64              `json:"binding_epoch"`
	CandidateVersion int64               `json:"candidate_version"`
	KeyID            string              `json:"key_id"`
	KeyFingerprint   string              `json:"key_fingerprint"`
	ProofDigest      string              `json:"proof_digest"`
	PublicIdentity   e2ee.PublicIdentity `json:"public_identity"`
	Attestation      []byte              `json:"attestation"`
}

type CommunicationLinkKeyManifest struct {
	Version           int                      `json:"version"`
	LinkID            string                   `json:"link_id"`
	LinkVersion       int64                    `json:"link_version"`
	ContractDigest    string                   `json:"contract_digest"`
	ContractCanonical []byte                   `json:"contract_canonical"`
	Source            CommunicationLinkKeySide `json:"source"`
	Target            CommunicationLinkKeySide `json:"target"`
	Digest            string                   `json:"digest"`
}

type communicationLinkKeyManifestClaims struct {
	Version           int                      `json:"version"`
	LinkID            string                   `json:"link_id"`
	LinkVersion       int64                    `json:"link_version"`
	ContractDigest    string                   `json:"contract_digest"`
	ContractCanonical []byte                   `json:"contract_canonical"`
	Source            CommunicationLinkKeySide `json:"source"`
	Target            CommunicationLinkKeySide `json:"target"`
}

// GetCommunicationLinkKeyManifest returns only an owner-authorized current
// manifest. No caller-supplied fingerprint or candidate version enters this
// digest; all claims are read and verified in one Store transaction.
func (s *Store) GetCommunicationLinkKeyManifest(linkID, requesterOwnerID string) (*CommunicationLinkKeyManifest, error) {
	if strings.TrimSpace(linkID) == "" || len(linkID) > 256 || strings.TrimSpace(linkID) != linkID ||
		validateOwnerApprovalID(requesterOwnerID) != nil {
		return nil, ErrCommunicationLinkNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+` FROM communication_links_v2 WHERE id=?`, linkID))
	if err != nil {
		return nil, err
	}
	if requesterOwnerID != link.SourceOwnerID && requesterOwnerID != link.TargetOwnerID {
		return nil, ErrCommunicationLinkNotFound
	}
	manifest, err := readCommunicationLinkKeyManifest(tx, *link, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return manifest, nil
}

func readCommunicationLinkKeyManifest(tx *sql.Tx, link CommunicationLink, at time.Time) (*CommunicationLinkKeyManifest, error) {
	if err := validateCurrentCommunicationLinkScope(tx, &link, at); err != nil {
		return nil, err
	}
	contractCanonical, err := canonicalCommunicationLinkContract(link)
	if err != nil || digestCommunicationLinkContract(contractCanonical) != link.ContractDigest {
		return nil, ErrCommunicationLinkScope
	}
	bindings, err := readCommunicationLinkGrantBindingSnapshot(tx, link, at)
	if err != nil {
		return nil, err
	}
	source, err := readCommunicationLinkKeySide(tx, link.SourceEndpointID,
		link.SourceGroupID, link.SourcePrincipalID, link.SourceOwnerID, link.SourceNodeID,
		bindings.sourceBindingID, bindings.sourceBindingEpoch)
	if err != nil {
		return nil, err
	}
	target, err := readCommunicationLinkKeySide(tx, link.TargetEndpointID,
		link.TargetGroupID, link.TargetPrincipalID, link.TargetOwnerID, link.TargetNodeID,
		bindings.targetBindingID, bindings.targetBindingEpoch)
	if err != nil {
		return nil, err
	}
	claims := communicationLinkKeyManifestClaims{
		Version: 2, LinkID: link.ID, LinkVersion: link.Version,
		ContractDigest: link.ContractDigest, ContractCanonical: contractCanonical,
		Source: source, Target: target,
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte(communicationLinkKeyManifestDomain), encoded...))
	return &CommunicationLinkKeyManifest{
		Version: claims.Version, LinkID: claims.LinkID, LinkVersion: claims.LinkVersion,
		ContractDigest: claims.ContractDigest, ContractCanonical: contractCanonical,
		Source: source, Target: target,
		Digest: hex.EncodeToString(sum[:]),
	}, nil
}

func readCommunicationLinkKeySide(tx *sql.Tx, endpointID, groupID, principalID,
	ownerID, nodeID, bindingID string, bindingEpoch uint64) (CommunicationLinkKeySide, error) {
	candidate, err := scanEndpointKeyCandidate(tx.QueryRow(`SELECT `+endpointKeyCandidateColumns+`
FROM endpoint_key_candidates_v2 WHERE endpoint_id=?`, endpointID))
	if errors.Is(err, sql.ErrNoRows) {
		return CommunicationLinkKeySide{}, ErrCommunicationLinkKeyCandidate
	}
	if err != nil {
		return CommunicationLinkKeySide{}, err
	}
	if candidate.State != EndpointKeyCandidateStateCandidate || candidate.Version <= 0 ||
		candidate.EndpointID != endpointID || candidate.PrincipalID != principalID ||
		candidate.OwnerID != ownerID || candidate.NodeID != nodeID ||
		candidate.BindingID != bindingID || candidate.BindingEpoch != bindingEpoch {
		return CommunicationLinkKeySide{}, ErrCommunicationLinkKeyCandidate
	}
	verified, err := e2ee.VerifyEndpointKeyAttestation(candidate.Proof, endpointID,
		principalID, nodeID, bindingID, bindingEpoch)
	proofHash := sha256.Sum256(candidate.Proof)
	if err != nil || verified.ID != candidate.Public.ID ||
		candidate.KeyID != candidate.Public.ID ||
		candidate.ProofDigest != hex.EncodeToString(proofHash[:]) ||
		!bytes.Equal(verified.KEMPublic, candidate.Public.KEMPublic) ||
		!bytes.Equal(verified.SigningPublic, candidate.Public.SigningPublic) {
		return CommunicationLinkKeySide{}, ErrCommunicationLinkKeyCandidate
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(candidate.Public)
	if err != nil {
		return CommunicationLinkKeySide{}, fmt.Errorf("fingerprint Endpoint key candidate: %w", err)
	}
	return CommunicationLinkKeySide{
		EndpointID: endpointID, GroupID: groupID, PrincipalID: principalID,
		OwnerID: ownerID, NodeID: nodeID, BindingID: bindingID,
		BindingEpoch: bindingEpoch, CandidateVersion: candidate.Version,
		KeyID: candidate.KeyID, KeyFingerprint: fingerprint,
		ProofDigest: candidate.ProofDigest, PublicIdentity: candidate.Public,
		Attestation: append([]byte(nil), candidate.Proof...),
	}, nil
}
