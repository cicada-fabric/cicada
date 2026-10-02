package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	CommunicationLinkReviewNone                = "NONE"
	CommunicationLinkReviewMetadata            = "METADATA"
	communicationLinkReviewMaxReviewers        = 8
	communicationLinkReviewMaxPending          = 256
	communicationLinkReviewMaxPolicyCandidates = 8
	communicationLinkReviewMaxOwnerProofs      = 4
)

var (
	ErrCommunicationLinkReviewPolicy   = errors.New("communication link review policy is not authorized")
	ErrCommunicationLinkReviewConflict = errors.New("communication link review policy version conflicts")
	ErrCommunicationLinkReviewPending  = errors.New("communication link message is waiting for metadata review")
	ErrCommunicationLinkReviewExpired  = errors.New("communication link message review expired")
	ErrCommunicationLinkReviewRejected = errors.New("communication link message was rejected by metadata review")
)

// CommunicationLinkReviewer names one exact, existing Endpoint in one of the
// Link's two Groups. Its current SessionBinding and link.review grant are
// rechecked for every queue read, failover, and decision.
type CommunicationLinkReviewer struct {
	EndpointID string `json:"endpoint_id"`
	GroupID    string `json:"group_id"`
}

// CommunicationLinkReviewPolicy is owner-approved metadata-only review
// policy. The reviewers and operational bounds are committed by a separate
// purpose/version proof; they do not extend the v1 Link contract signature.
type CommunicationLinkReviewPolicy struct {
	Mode                 string                      `json:"mode"`
	Reviewers            []CommunicationLinkReviewer `json:"reviewers"`
	MaxFailovers         int                         `json:"max_failovers"`
	ReviewerLeaseSeconds int                         `json:"reviewer_lease_seconds"`
	MaxReviewAgeSeconds  int                         `json:"max_review_age_seconds"`
}

// Qualification is a current Hub snapshot, never a durable signing credential.
type CommunicationLinkReviewerQualification struct {
	EndpointID         string `json:"endpoint_id"`
	GroupID            string `json:"group_id"`
	MembershipRevision int64  `json:"membership_revision"`
	JoinRevision       int64  `json:"join_revision"`
	GroupVersion       int64  `json:"group_version"`
	BindingID          string `json:"binding_id"`
	BindingEpoch       uint64 `json:"binding_epoch"`
	LeaseExpiresAt     string `json:"lease_expires_at"`
	Action             string `json:"action"`
}

type CommunicationLinkReviewOwnerEvidence struct {
	OwnerKeyID          string              `json:"owner_key_id"`
	OwnerPublicIdentity e2ee.PublicIdentity `json:"owner_public_identity"`
	OwnerKeyState       string              `json:"owner_key_state"`
	OwnerKeyVersion     int64               `json:"owner_key_version"`
	SignedProof         []byte              `json:"signed_proof"`
	AcceptedAt          string              `json:"accepted_at"`
}

type CommunicationLinkReviewOwnerApproval struct {
	Side          string                                `json:"side"`
	OwnerID       string                                `json:"owner_id"`
	CurrentStatus string                                `json:"current_status"`
	Evidence      *CommunicationLinkReviewOwnerEvidence `json:"evidence,omitempty"`
}

type CommunicationLinkReviewPolicyStatus struct {
	ContractDigest string                                 `json:"contract_digest"`
	VerifiedAt     string                                 `json:"verified_at"`
	OwnerApprovals []CommunicationLinkReviewOwnerApproval `json:"owner_approvals"`
	LinkID         string                                 `json:"link_id"`
	LinkVersion    int64                                  `json:"link_version"`
	PolicyVersion  int64                                  `json:"policy_version"`
	PolicyDigest   string                                 `json:"policy_digest"`
	Policy         CommunicationLinkReviewPolicy          `json:"policy"`
	Current        bool                                   `json:"current"`
	AcceptedSides  []string                               `json:"accepted_sides"`
	ExpiresAt      string                                 `json:"expires_at,omitempty"`
}

type CommunicationLinkReviewPolicyPreview struct {
	VerifiedAt             string                                   `json:"verified_at"`
	ReviewerQualifications []CommunicationLinkReviewerQualification `json:"reviewer_qualifications"`
	LinkID                 string                                   `json:"link_id"`
	Side                   string                                   `json:"side"`
	OwnerID                string                                   `json:"owner_id"`
	ContractDigest         string                                   `json:"contract_digest"`
	LinkVersion            int64                                    `json:"link_version"`
	ExpectedPolicyVersion  int64                                    `json:"expected_policy_version"`
	PolicyVersion          int64                                    `json:"policy_version"`
	PolicyDigest           string                                   `json:"policy_digest"`
	Policy                 CommunicationLinkReviewPolicy            `json:"policy"`
	MaximumProofExpiresAt  string                                   `json:"maximum_proof_expires_at"`
}

func (s *Store) initializeCommunicationLinkReviewSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS communication_link_review_policy_heads_v2 (
  link_id TEXT PRIMARY KEY,
  policy_version INTEGER NOT NULL CHECK(policy_version > 0),
  policy_digest TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(link_id) REFERENCES communication_links_v2(id)
);
CREATE TABLE IF NOT EXISTS communication_link_review_policy_grants_v2 (
  id TEXT PRIMARY KEY,
  link_id TEXT NOT NULL,
  policy_version INTEGER NOT NULL CHECK(policy_version > 0),
  policy_digest TEXT NOT NULL,
  policy_json TEXT NOT NULL,
  link_version INTEGER NOT NULL CHECK(link_version > 0),
  contract_digest TEXT NOT NULL,
  side TEXT NOT NULL CHECK(side IN ('SOURCE', 'TARGET')),
  owner_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  proof_expires_at TEXT NOT NULL,
  signed_proof BLOB NOT NULL CHECK(length(signed_proof) > 0),
  accepted_at TEXT NOT NULL,
  UNIQUE(owner_id, key_id, nonce),
  FOREIGN KEY(link_id) REFERENCES communication_links_v2(id),
  FOREIGN KEY(owner_id, key_id) REFERENCES owner_approval_keys_v2(owner_id, key_id)
);
CREATE INDEX IF NOT EXISTS communication_link_review_policy_grants_v2_lookup_idx
  ON communication_link_review_policy_grants_v2(link_id, policy_version, policy_digest, side, accepted_at DESC);
CREATE TABLE IF NOT EXISTS communication_link_message_reviews_v2 (
  message_id TEXT PRIMARY KEY,
  link_id TEXT NOT NULL,
  link_version INTEGER NOT NULL CHECK(link_version > 0),
  policy_version INTEGER NOT NULL CHECK(policy_version > 0),
  policy_digest TEXT NOT NULL,
  route_kind TEXT NOT NULL CHECK(route_kind IN ('send', 'ask', 'reply')),
  request_id TEXT NOT NULL DEFAULT '',
  sender_endpoint_id TEXT NOT NULL,
  sender_group_id TEXT NOT NULL,
  receiver_endpoint_id TEXT NOT NULL,
  receiver_group_id TEXT NOT NULL,
  message_digest TEXT NOT NULL,
  reviewers_json TEXT NOT NULL,
  reviewer_index INTEGER NOT NULL CHECK(reviewer_index >= 0),
  owner_epoch INTEGER NOT NULL CHECK(owner_epoch > 0),
  lease_expires_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('WAITING_REVIEW', 'APPROVED', 'REJECTED', 'EXPIRED', 'STALE')),
  version INTEGER NOT NULL CHECK(version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  decided_at TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(link_id) REFERENCES communication_links_v2(id),
  FOREIGN KEY(message_id) REFERENCES fabric_messages(id)
);
CREATE INDEX IF NOT EXISTS communication_link_message_reviews_v2_assignee_idx
  ON communication_link_message_reviews_v2(status, expires_at, updated_at);
CREATE INDEX IF NOT EXISTS communication_link_message_reviews_v2_link_idx
  ON communication_link_message_reviews_v2(link_id, status, message_id);
CREATE TABLE IF NOT EXISTS communication_link_message_review_candidates_v2 (
  message_id TEXT NOT NULL,
  reviewer_endpoint_id TEXT NOT NULL,
  reviewer_group_id TEXT NOT NULL,
  reviewer_index INTEGER NOT NULL CHECK(reviewer_index >= 0),
  PRIMARY KEY(message_id, reviewer_index),
  UNIQUE(message_id, reviewer_endpoint_id),
  FOREIGN KEY(message_id) REFERENCES communication_link_message_reviews_v2(message_id)
);
CREATE INDEX IF NOT EXISTS communication_link_review_candidates_actor_idx
  ON communication_link_message_review_candidates_v2(reviewer_endpoint_id, reviewer_group_id, message_id);
CREATE TABLE IF NOT EXISTS communication_link_review_events_v2 (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  prior_status TEXT NOT NULL,
  next_status TEXT NOT NULL,
  reviewer_endpoint_id TEXT NOT NULL DEFAULT '',
  owner_epoch INTEGER NOT NULL,
  version INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(message_id) REFERENCES communication_link_message_reviews_v2(message_id)
);
CREATE INDEX IF NOT EXISTS communication_link_review_events_v2_message_idx
  ON communication_link_review_events_v2(message_id, sequence);`)
	if err != nil {
		return fmt.Errorf("initialize communication link review schema: %w", err)
	}
	return nil
}

func normalizeCommunicationLinkReviewPolicy(input CommunicationLinkReviewPolicy) (CommunicationLinkReviewPolicy, []byte, string, error) {
	input.Mode = strings.ToUpper(strings.TrimSpace(input.Mode))
	if input.Mode == "" {
		input.Mode = CommunicationLinkReviewNone
	}
	if input.Reviewers == nil {
		input.Reviewers = []CommunicationLinkReviewer{}
	}
	if input.Mode == CommunicationLinkReviewNone {
		if len(input.Reviewers) != 0 || input.MaxFailovers != 0 || input.ReviewerLeaseSeconds != 0 || input.MaxReviewAgeSeconds != 0 {
			return CommunicationLinkReviewPolicy{}, nil, "", ErrCommunicationLinkReviewPolicy
		}
	} else if input.Mode == CommunicationLinkReviewMetadata {
		if len(input.Reviewers) == 0 || len(input.Reviewers) > communicationLinkReviewMaxReviewers ||
			input.MaxFailovers < 0 || input.MaxFailovers > len(input.Reviewers)-1 ||
			input.ReviewerLeaseSeconds < 30 || input.ReviewerLeaseSeconds > 3600 ||
			input.MaxReviewAgeSeconds < 60 || input.MaxReviewAgeSeconds > 86400 {
			return CommunicationLinkReviewPolicy{}, nil, "", ErrCommunicationLinkReviewPolicy
		}
		for i := range input.Reviewers {
			input.Reviewers[i].EndpointID = strings.TrimSpace(input.Reviewers[i].EndpointID)
			input.Reviewers[i].GroupID = strings.TrimSpace(input.Reviewers[i].GroupID)
			if input.Reviewers[i].EndpointID == "" || len(input.Reviewers[i].EndpointID) > 256 ||
				input.Reviewers[i].GroupID == "" || len(input.Reviewers[i].GroupID) > 256 {
				return CommunicationLinkReviewPolicy{}, nil, "", ErrCommunicationLinkReviewPolicy
			}
		}
		for i := 1; i < len(input.Reviewers); i++ {
			for j := i; j > 0 && (input.Reviewers[j].EndpointID < input.Reviewers[j-1].EndpointID ||
				(input.Reviewers[j].EndpointID == input.Reviewers[j-1].EndpointID && input.Reviewers[j].GroupID < input.Reviewers[j-1].GroupID)); j-- {
				input.Reviewers[j], input.Reviewers[j-1] = input.Reviewers[j-1], input.Reviewers[j]
			}
		}
		for i := 1; i < len(input.Reviewers); i++ {
			if input.Reviewers[i].EndpointID == input.Reviewers[i-1].EndpointID {
				return CommunicationLinkReviewPolicy{}, nil, "", ErrCommunicationLinkReviewPolicy
			}
		}
	} else {
		return CommunicationLinkReviewPolicy{}, nil, "", ErrCommunicationLinkReviewPolicy
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return CommunicationLinkReviewPolicy{}, nil, "", err
	}
	digest := sha256.Sum256(encoded)
	return input, encoded, hex.EncodeToString(digest[:]), nil
}

func qualifyCommunicationLinkReviewersTx(tx *sql.Tx, link *CommunicationLink,
	policy CommunicationLinkReviewPolicy, now time.Time) ([]CommunicationLinkReviewerQualification, error) {
	result := make([]CommunicationLinkReviewerQualification, 0, len(policy.Reviewers))
	for _, reviewer := range policy.Reviewers {
		if reviewer.GroupID != link.SourceGroupID && reviewer.GroupID != link.TargetGroupID {
			return nil, ErrCommunicationLinkReviewPolicy
		}
		if reviewer.EndpointID == link.SourceEndpointID || reviewer.EndpointID == link.TargetEndpointID {
			return nil, ErrCommunicationLinkReviewPolicy
		}
		current, err := readLinkEndpointScope(tx, reviewer.EndpointID, reviewer.GroupID, now)
		if err != nil {
			return nil, ErrCommunicationLinkReviewPolicy
		}
		binding, err := readCommunicationLinkGrantBinding(tx, reviewer.EndpointID,
			current.principalID, current.nodeID, now)
		if err != nil {
			return nil, ErrCommunicationLinkReviewPolicy
		}
		scope := NativeActorScope{PrincipalID: current.principalID,
			EndpointID: reviewer.EndpointID, GroupID: reviewer.GroupID,
			MembershipRevision: current.membershipRevision,
			BindingID:          binding.ID, BindingEpoch: binding.Epoch, LeaseOwner: binding.LeaseOwner}
		if err := tx.QueryRow(`SELECT m.id,g.network_id FROM memberships m
JOIN groups g ON g.id=m.group_id WHERE m.principal_id=? AND m.group_id=?`,
			current.principalID, reviewer.GroupID).Scan(&scope.MembershipID, &scope.NetworkID); err != nil {
			return nil, ErrCommunicationLinkReviewPolicy
		}
		if err := guardNativeActorTx(tx, scope, "link.review", now); err != nil {
			return nil, ErrCommunicationLinkReviewPolicy
		}
		result = append(result, CommunicationLinkReviewerQualification{EndpointID: reviewer.EndpointID,
			GroupID: reviewer.GroupID, MembershipRevision: current.membershipRevision,
			JoinRevision: current.joinRevision, GroupVersion: current.groupVersion,
			BindingID: binding.ID, BindingEpoch: binding.Epoch, LeaseExpiresAt: binding.LeaseExpiresAt,
			Action: "link.review"})
	}
	return result, nil
}

func validateCommunicationLinkReviewersTx(tx *sql.Tx, link *CommunicationLink,
	policy CommunicationLinkReviewPolicy, now time.Time) error {
	_, err := qualifyCommunicationLinkReviewersTx(tx, link, policy, now)
	return err
}

// PreviewCommunicationLinkReviewPolicyForOwner returns the exact canonical
// candidate both Owner proofs must sign. It has no policy effect; when expired
// queue entries exist, successful preview records their required terminal
// expiry cleanup before permitting a new version.
func (s *Store) PreviewCommunicationLinkReviewPolicyForOwner(linkID, ownerID string,
	candidate CommunicationLinkReviewPolicy) (*CommunicationLinkReviewPolicyPreview, error) {
	linkID, ownerID = strings.TrimSpace(linkID), strings.TrimSpace(ownerID)
	policy, _, digest, err := normalizeCommunicationLinkReviewPolicy(candidate)
	if err != nil || linkID == "" || validateOwnerApprovalID(ownerID) != nil {
		return nil, ErrCommunicationLinkReviewPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+` FROM communication_links_v2 WHERE id=?`, linkID))
	if err != nil || link == nil || link.State != CommunicationLinkProposed {
		return nil, ErrCommunicationLinkNotFound
	}
	side := ""
	if ownerID == link.SourceOwnerID {
		side = CommunicationLinkGrantSource
	} else if ownerID == link.TargetOwnerID {
		side = CommunicationLinkGrantTarget
	} else {
		return nil, ErrCommunicationLinkNotFound
	}
	if err := validateCurrentCommunicationLinkScope(tx, link, now); err != nil {
		return nil, err
	}
	qualifications, err := qualifyCommunicationLinkReviewersTx(tx, link, policy, now)
	if err != nil {
		return nil, err
	}
	if err := communicationLinkReviewPolicyNoInflightTx(tx, linkID, now); err != nil {
		return nil, err
	}
	version, _, err := communicationLinkReviewHeadTx(tx, linkID)
	if err != nil || version == int64(^uint64(0)>>1) {
		return nil, ErrCommunicationLinkReviewConflict
	}
	preview := &CommunicationLinkReviewPolicyPreview{VerifiedAt: now.Format(time.RFC3339Nano), ReviewerQualifications: qualifications, LinkID: link.ID, Side: side, OwnerID: ownerID,
		ContractDigest: link.ContractDigest, LinkVersion: link.Version,
		ExpectedPolicyVersion: version, PolicyVersion: version + 1,
		PolicyDigest: digest, Policy: policy, MaximumProofExpiresAt: link.ExpiresAt}
	if err := validateCommunicationLinkReviewEvidenceResultSize(preview); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return preview, nil
}

// RecordCommunicationLinkReviewPolicyForOwner stores one distinct-purpose
// owner proof. Both sides must sign the same exact version and digest before
// the active policy head changes. Policy updates require no in-flight Link
// messages so queued bytes cannot move between old/new review requirements.
func (s *Store) RecordCommunicationLinkReviewPolicyForOwner(linkID, side, keyID string,
	expectedPolicyVersion int64, input CommunicationLinkReviewPolicy, signedProof []byte) (*CommunicationLinkReviewPolicyStatus, error) {
	linkID, side, keyID = strings.TrimSpace(linkID), strings.TrimSpace(side), strings.TrimSpace(keyID)
	if linkID == "" || len(linkID) > 256 || side != CommunicationLinkGrantSource && side != CommunicationLinkGrantTarget ||
		keyID == "" || len(keyID) > 256 || expectedPolicyVersion < 0 || expectedPolicyVersion == math.MaxInt64 || len(signedProof) == 0 || len(signedProof) > 16*1024 {
		return nil, ErrCommunicationLinkReviewPolicy
	}
	policy, policyJSON, policyDigest, err := normalizeCommunicationLinkReviewPolicy(input)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+` FROM communication_links_v2 WHERE id=?`, linkID))
	if err != nil || link == nil || link.State != CommunicationLinkProposed ||
		communicationLinkGrantOwner(*link, side) == "" {
		return nil, ErrCommunicationLinkNotFound
	}
	if err := validateCurrentCommunicationLinkScope(tx, link, now); err != nil {
		return nil, err
	}
	currentVersion, _, err := communicationLinkReviewHeadTx(tx, linkID)
	if err != nil {
		return nil, err
	}
	if err := validateCommunicationLinkReviewersTx(tx, link, policy, now); err != nil {
		return nil, err
	}
	ownerID := communicationLinkGrantOwner(*link, side)
	ownerKey, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, ownerID, keyID))
	if err != nil || ownerKey.State != OwnerApprovalKeyActive {
		return nil, ErrOwnerApprovalKeyConflict
	}
	policyVersion := uint64(expectedPolicyVersion + 1)
	verified, err := e2ee.VerifyOwnerLinkReviewPolicy(signedProof, ownerKey.Public,
		ownerID, link.ID, link.ContractDigest, policyDigest, uint64(link.Version), policyVersion,
		e2ee.OwnerLinkGrantSide(side), now)
	if err != nil {
		if currentVersion != expectedPolicyVersion {
			return nil, ErrCommunicationLinkReviewConflict
		}
		return nil, fmt.Errorf("verify communication link review policy proof: %w", err)
	}
	linkExpiry, err := time.Parse(time.RFC3339, link.ExpiresAt)
	proofExpiryTime, expiryErr := time.Parse(time.RFC3339Nano, verified.ExpiresAt)
	if err != nil || expiryErr != nil || proofExpiryTime.After(linkExpiry) {
		return nil, ErrCommunicationLinkReviewPolicy
	}
	if currentVersion != expectedPolicyVersion {
		// A lost response after the second Owner advanced the head is recoverable
		// only with the byte-identical proof that performed that exact transition.
		if currentVersion != expectedPolicyVersion+1 {
			return nil, ErrCommunicationLinkReviewConflict
		}
		var activeDigest string
		if _, activeDigest, err = communicationLinkReviewHeadTx(tx, linkID); err != nil || activeDigest != policyDigest {
			return nil, ErrCommunicationLinkReviewConflict
		}
		var existing []byte
		if err := tx.QueryRow(`SELECT signed_proof FROM communication_link_review_policy_grants_v2
WHERE link_id=? AND policy_version=? AND policy_digest=? AND side=? AND owner_id=? AND key_id=? AND nonce=?`,
			link.ID, currentVersion, policyDigest, side, ownerID, keyID, verified.Nonce).Scan(&existing); err != nil || !bytes.Equal(existing, signedProof) {
			return nil, ErrCommunicationLinkReviewConflict
		}
		status, err := readCommunicationLinkReviewPolicyEvidenceTx(tx, *link, currentVersion, policyDigest, now, true)
		if err != nil {
			return nil, err
		}
		if !status.Current {
			return nil, ErrCommunicationLinkReviewConflict
		}
		if err := validateCommunicationLinkReviewEvidenceResultSize(status); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return status, nil
	}
	if err := communicationLinkReviewPolicyNoInflightTx(tx, linkID, now); err != nil {
		return nil, err
	}
	var candidateCount int
	if err := tx.QueryRow(`SELECT count(DISTINCT policy_digest) FROM communication_link_review_policy_grants_v2 WHERE link_id=? AND policy_version=?`, link.ID, policyVersion).Scan(&candidateCount); err != nil {
		return nil, err
	}
	if candidateCount >= communicationLinkReviewMaxPolicyCandidates {
		var already int
		if err := tx.QueryRow(`SELECT count(*) FROM communication_link_review_policy_grants_v2 WHERE link_id=? AND policy_version=? AND policy_digest=?`, link.ID, policyVersion, policyDigest).Scan(&already); err != nil {
			return nil, err
		}
		if already == 0 {
			return nil, ErrCommunicationLinkReviewConflict
		}
	}
	var existing []byte
	lookupErr := tx.QueryRow(`SELECT signed_proof FROM communication_link_review_policy_grants_v2 WHERE link_id=? AND policy_version=? AND policy_digest=? AND side=? AND nonce=?`,
		link.ID, policyVersion, policyDigest, side, verified.Nonce).Scan(&existing)
	if lookupErr == nil {
		if !bytes.Equal(existing, signedProof) {
			return nil, ErrCommunicationLinkReviewConflict
		}
	} else if !errors.Is(lookupErr, sql.ErrNoRows) {
		return nil, lookupErr
	} else {
		var proofCount int
		if err := tx.QueryRow(`SELECT count(*) FROM communication_link_review_policy_grants_v2
WHERE link_id=? AND policy_version=? AND policy_digest=? AND side=?`,
			link.ID, policyVersion, policyDigest, side).Scan(&proofCount); err != nil {
			return nil, err
		}
		if proofCount >= communicationLinkReviewMaxOwnerProofs {
			return nil, ErrCommunicationLinkReviewConflict
		}
		stamp := now.Format(time.RFC3339Nano)
		if _, err := tx.Exec(`INSERT INTO communication_link_review_policy_grants_v2
(id,link_id,policy_version,policy_digest,policy_json,link_version,contract_digest,side,owner_id,key_id,nonce,proof_expires_at,signed_proof,accepted_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, NewID("linkreviewgrant"), link.ID, policyVersion, policyDigest,
			string(policyJSON), link.Version, link.ContractDigest, side, ownerID, keyID, verified.Nonce,
			verified.ExpiresAt, append([]byte(nil), signedProof...), stamp); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
				return nil, ErrCommunicationLinkGrantReplay
			}
			return nil, err
		}
	}
	status, err := readCommunicationLinkReviewPolicyEvidenceTx(tx, *link, int64(policyVersion), policyDigest, now, true)
	if err != nil {
		return nil, err
	}
	if len(status.AcceptedSides) == 2 {
		stamp := now.Format(time.RFC3339Nano)
		result, err := tx.Exec(`INSERT INTO communication_link_review_policy_heads_v2(link_id,policy_version,policy_digest,updated_at)
VALUES(?,?,?,?) ON CONFLICT(link_id) DO UPDATE SET policy_version=excluded.policy_version,
policy_digest=excluded.policy_digest,updated_at=excluded.updated_at
WHERE communication_link_review_policy_heads_v2.policy_version=?`,
			link.ID, policyVersion, policyDigest, stamp, expectedPolicyVersion)
		if err != nil {
			return nil, err
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return nil, ErrCommunicationLinkReviewConflict
		}
		status.Current = true
	}
	if err := validateCommunicationLinkReviewEvidenceResultSize(status); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return status, nil
}

func (s *Store) GetCommunicationLinkReviewPolicyForOwner(linkID, ownerID string) (*CommunicationLinkReviewPolicyStatus, error) {
	linkID, ownerID = strings.TrimSpace(linkID), strings.TrimSpace(ownerID)
	if linkID == "" || validateOwnerApprovalID(ownerID) != nil {
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
	if err != nil || link == nil || ownerID != link.SourceOwnerID && ownerID != link.TargetOwnerID {
		return nil, ErrCommunicationLinkNotFound
	}
	version, digest, err := communicationLinkReviewHeadTx(tx, linkID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	status, err := readCommunicationLinkReviewPolicyEvidenceTx(tx, *link, version, digest, now, true)
	if err != nil {
		return nil, err
	}
	if err := validateCommunicationLinkReviewEvidenceResultSize(status); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return status, nil
}

func communicationLinkReviewHeadTx(tx *sql.Tx, linkID string) (int64, string, error) {
	var version int64
	var digest string
	err := tx.QueryRow(`SELECT policy_version,policy_digest FROM communication_link_review_policy_heads_v2 WHERE link_id=?`, linkID).Scan(&version, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	return version, digest, err
}

func communicationLinkReviewPolicyNoInflightTx(tx *sql.Tx, linkID string, at time.Time) error {
	if err := expireCommunicationLinkReviewQueueTx(tx, linkID, at); err != nil {
		return err
	}
	var pending int
	err := tx.QueryRow(`SELECT count(*) FROM communication_link_message_reviews_v2
WHERE link_id=? AND status='WAITING_REVIEW'`, linkID).Scan(&pending)
	if err != nil {
		return err
	}
	var ready int
	err = tx.QueryRow(`SELECT count(*) FROM relay_v2_inbox i JOIN relay_v2_message_security sec ON sec.message_id=i.message_id
WHERE sec.authorization_ref=? AND i.state IN ('READY','CLAIMED','UNCERTAIN')`, communicationLinkAuthorizationRefPrefix+linkID).Scan(&ready)
	if err != nil {
		return err
	}
	if pending != 0 || ready != 0 {
		return ErrCommunicationLinkReviewConflict
	}
	return nil
}

// This tuple-scoped reader selects at most four retained rows per side. Both
// presentation and runtime use the same verified rows; signed bytes are copied
// unchanged, and public key discovery never supplies an independent Owner pin.
func readCommunicationLinkReviewPolicyEvidenceTx(tx *sql.Tx, link CommunicationLink,
	version int64, digest string, now time.Time, checkScope bool) (*CommunicationLinkReviewPolicyStatus, error) {
	status := &CommunicationLinkReviewPolicyStatus{LinkID: link.ID, LinkVersion: link.Version,
		ContractDigest: link.ContractDigest, PolicyVersion: version, PolicyDigest: digest,
		VerifiedAt: now.Format(time.RFC3339Nano), AcceptedSides: []string{},
		OwnerApprovals: []CommunicationLinkReviewOwnerApproval{}}
	var scopeErr error
	if checkScope {
		if err := networkGuardCommunicationLinkTx(tx, &link, now); err != nil && !errors.Is(err, ErrNetworkPermission) {
			return nil, err
		}
		scopeErr = validateCurrentCommunicationLinkScope(tx, &link, now)
		if scopeErr != nil && !errors.Is(scopeErr, ErrCommunicationLinkScope) && !errors.Is(scopeErr, ErrCommunicationLinkNotFound) {
			return nil, scopeErr
		}
	}
	if version == 0 {
		status.Policy = CommunicationLinkReviewPolicy{Mode: CommunicationLinkReviewNone, Reviewers: []CommunicationLinkReviewer{}}
		status.Current = scopeErr == nil
		return status, nil
	}
	var policyJSON string
	if err := tx.QueryRow(`SELECT policy_json FROM communication_link_review_policy_grants_v2
WHERE link_id=? AND policy_version=? AND policy_digest=? ORDER BY accepted_at DESC,id DESC LIMIT 1`,
		link.ID, version, digest).Scan(&policyJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCommunicationLinkReviewPolicy
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(policyJSON), &status.Policy); err != nil {
		return nil, ErrCommunicationLinkReviewPolicy
	}
	_, canonical, checkDigest, err := normalizeCommunicationLinkReviewPolicy(status.Policy)
	if err != nil || checkDigest != digest || string(canonical) != policyJSON {
		return nil, ErrCommunicationLinkReviewPolicy
	}
	linkExpiry, err := time.Parse(time.RFC3339Nano, link.ExpiresAt)
	if err != nil {
		return nil, ErrCommunicationLinkReviewPolicy
	}
	type grant struct {
		ownerID, keyID, policyJSON, contractDigest, expires, acceptedAt string
		linkVersion                                                     int64
		proof                                                           []byte
	}
	for _, side := range []string{CommunicationLinkGrantSource, CommunicationLinkGrantTarget} {
		approval := CommunicationLinkReviewOwnerApproval{Side: side, OwnerID: communicationLinkGrantOwner(link, side), CurrentStatus: "MISSING"}
		rows, err := tx.Query(`SELECT owner_id,key_id,policy_json,link_version,contract_digest,proof_expires_at,signed_proof,accepted_at
FROM communication_link_review_policy_grants_v2 WHERE link_id=? AND policy_version=? AND policy_digest=? AND side=?
ORDER BY accepted_at DESC,id DESC LIMIT ?`, link.ID, version, digest, side, communicationLinkReviewMaxOwnerProofs)
		if err != nil {
			return nil, err
		}
		grants := []grant{}
		for rows.Next() {
			var row grant
			if err := rows.Scan(&row.ownerID, &row.keyID, &row.policyJSON, &row.linkVersion, &row.contractDigest, &row.expires, &row.proof, &row.acceptedAt); err != nil {
				rows.Close()
				return nil, err
			}
			grants = append(grants, row)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		for _, row := range grants {
			// The first diagnostic is deterministic; a later valid row may supersede it.
			reason := "INVALID"
			if row.linkVersion != link.Version || row.contractDigest != link.ContractDigest || row.ownerID != approval.OwnerID {
				reason = "SCOPE_STALE"
			} else if row.policyJSON == policyJSON {
				key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, row.ownerID, row.keyID))
				if err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, ErrOwnerApprovalKeyNotFound) && !errors.Is(err, ErrOwnerApprovalKeyConflict) {
					return nil, err
				}
				if err == nil && key.OwnerID == row.ownerID && key.KeyID == row.keyID && key.Public.ID == row.keyID && key.Version > 0 {
					if key.State != OwnerApprovalKeyActive {
						reason = "OWNER_KEY_REVOKED"
					} else {
						verifyAt := now
						// Authenticate expired proofs before classifying them; never expose them.
						var claims e2ee.OwnerLinkReviewPolicyProof
						if json.Unmarshal(row.proof, &claims) == nil {
							if expiry, e := time.Parse(time.RFC3339Nano, claims.ExpiresAt); e == nil && !expiry.After(now) {
								verifyAt = expiry.Add(-time.Nanosecond)
							}
						}
						proof, err := e2ee.VerifyOwnerLinkReviewPolicy(row.proof, key.Public, row.ownerID, link.ID, link.ContractDigest, digest, uint64(link.Version), uint64(version), e2ee.OwnerLinkGrantSide(side), verifyAt)
						proofExpiry, expiryErr := time.Parse(time.RFC3339Nano, proof.ExpiresAt)
						acceptedAt, acceptedErr := time.Parse(time.RFC3339Nano, row.acceptedAt)
						if err == nil && expiryErr == nil && proof.ExpiresAt == row.expires && !proofExpiry.After(linkExpiry) && acceptedErr == nil && acceptedAt.UTC().Format(time.RFC3339Nano) == row.acceptedAt && !acceptedAt.After(now) {
							if !proofExpiry.After(now) {
								reason = "PROOF_EXPIRED"
							} else if scopeErr == nil {
								approval.CurrentStatus = "VERIFIED"
								approval.Evidence = &CommunicationLinkReviewOwnerEvidence{OwnerKeyID: key.KeyID, OwnerPublicIdentity: key.Public,
									OwnerKeyState: key.State, OwnerKeyVersion: key.Version, SignedProof: append([]byte(nil), row.proof...), AcceptedAt: row.acceptedAt}
								status.AcceptedSides = append(status.AcceptedSides, side)
								if status.ExpiresAt == "" {
									status.ExpiresAt = proof.ExpiresAt
								} else {
									prior, _ := time.Parse(time.RFC3339Nano, status.ExpiresAt)
									if proofExpiry.Before(prior) {
										status.ExpiresAt = proof.ExpiresAt
									}
								}
								break
							}
						}
					}
				}
			}
			if approval.CurrentStatus == "MISSING" {
				approval.CurrentStatus = reason
			}
		}
		if scopeErr != nil {
			approval.CurrentStatus = "SCOPE_STALE"
			approval.Evidence = nil
		}
		status.OwnerApprovals = append(status.OwnerApprovals, approval)
	}
	headVersion, headDigest, err := communicationLinkReviewHeadTx(tx, link.ID)
	if err != nil {
		return nil, err
	}
	status.Current = scopeErr == nil && len(status.AcceptedSides) == 2 && headVersion == version && headDigest == digest
	return status, nil
}

func readCurrentCommunicationLinkReviewPolicyTx(tx *sql.Tx, link CommunicationLink, now time.Time) (CommunicationLinkReviewPolicy, string, error) {
	version, digest, err := communicationLinkReviewHeadTx(tx, link.ID)
	if err != nil {
		return CommunicationLinkReviewPolicy{}, "", err
	}
	status, err := readCommunicationLinkReviewPolicyEvidenceTx(tx, link, version, digest, now, false)
	if err != nil {
		return CommunicationLinkReviewPolicy{}, "", err
	}
	if !status.Current {
		return CommunicationLinkReviewPolicy{}, "", ErrCommunicationLinkReviewPolicy
	}
	return status.Policy, status.ExpiresAt, nil
}

// The existing encrypted Client serializer limits plaintext to 64 KiB. Reserve
// the exact RPC wrapper plus worst-case HTML escaping for both correlation
// tokens (wire tokens are at most 256 bytes). This is a public projection check,
// never a runtime policy rule; grant failures roll back all writes and CAS.
func validateCommunicationLinkReviewEvidenceResultSize(result any) error {
	encoded, err := json.Marshal(map[string]any{"request_id": strings.Repeat("<", 256),
		"operation_id": strings.Repeat("<", 256), "ok": true, "result": result})
	if err != nil {
		return err
	}
	if len(encoded) > 64*1024 {
		return ErrCommunicationLinkReviewPolicy
	}
	return nil
}
