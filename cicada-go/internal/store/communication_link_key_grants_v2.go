package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	CommunicationLinkKeyGrantMissing         = "MISSING"
	CommunicationLinkKeyGrantLegacyUnbound   = "LEGACY_KEY_UNBOUND"
	CommunicationLinkKeyGrantAccepted        = "ACCEPTED"
	CommunicationLinkKeyGrantBindingStale    = "KEY_BINDING_STALE"
	CommunicationLinkKeyGrantOwnerKeyRevoked = "OWNER_KEY_REVOKED"
	CommunicationLinkKeyGrantProofExpired    = "PROOF_EXPIRED"
	CommunicationLinkKeyGrantInvalid         = "INVALID"
)

type CommunicationLinkKeyGrantStatus struct {
	LinkID         string `json:"link_id"`
	Side           string `json:"side"`
	OwnerID        string `json:"owner_id"`
	KeyID          string `json:"key_id,omitempty"`
	ManifestDigest string `json:"manifest_digest,omitempty"`
	Accepted       bool   `json:"accepted"`
	AcceptedAt     string `json:"accepted_at,omitempty"`
	CurrentStatus  string `json:"current_status"`
}

type storedCommunicationLinkKeyGrant struct {
	linkID, side, ownerID, keyID, contractDigest, manifestDigest, nonce, acceptedAt string
	linkVersion                                                                     int64
	proof                                                                           []byte
}

func (s *Store) initializeCommunicationLinkKeyGrantsV2Schema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS communication_link_key_grants_v2 (
  link_id TEXT NOT NULL,
  side TEXT NOT NULL CHECK(side IN ('SOURCE', 'TARGET')),
  owner_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  link_version INTEGER NOT NULL CHECK(link_version > 0),
  contract_digest TEXT NOT NULL,
  manifest_digest TEXT NOT NULL,
  nonce TEXT NOT NULL,
  signed_proof BLOB NOT NULL CHECK(length(signed_proof) > 0),
  accepted_at TEXT NOT NULL,
  PRIMARY KEY(link_id, side),
  UNIQUE(owner_id, key_id, nonce),
  FOREIGN KEY(link_id) REFERENCES communication_links_v2(id),
  FOREIGN KEY(owner_id, key_id) REFERENCES owner_approval_keys_v2(owner_id, key_id)
);
CREATE INDEX IF NOT EXISTS communication_link_key_grants_v2_owner_idx
  ON communication_link_key_grants_v2(owner_id, accepted_at, link_id);`)
	if err != nil {
		return fmt.Errorf("initialize key-bound communication link grants: %w", err)
	}
	return nil
}

// RecordCommunicationLinkKeyGrant records explicit owner consent to the exact
// current contract, native bindings, and both Endpoint key candidates. It does
// not activate a route. Owner authority must come from the authenticated
// caller, never a field in the submitted proof.
func (s *Store) RecordCommunicationLinkKeyGrant(ownerID, linkID, side, keyID string,
	signedProof []byte) (*CommunicationLinkKeyGrantStatus, error) {
	if validateOwnerApprovalID(ownerID) != nil || linkID == "" || len(linkID) > 256 ||
		strings.TrimSpace(linkID) != linkID || keyID == "" || len(keyID) > 256 ||
		strings.TrimSpace(keyID) != keyID ||
		(side != CommunicationLinkGrantSource && side != CommunicationLinkGrantTarget) ||
		len(signedProof) == 0 || len(signedProof) > 16*1024 {
		return nil, errors.New("communication link key grant request is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id = ?`, linkID))
	if err != nil {
		return nil, err
	}
	if communicationLinkGrantOwner(*link, side) != ownerID {
		return nil, ErrCommunicationLinkNotFound
	}
	now := time.Now().UTC()
	manifest, err := readCommunicationLinkKeyManifest(tx, *link, now)
	if err != nil {
		return nil, err
	}
	key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id, key_id, public_identity_json,
state, version, created_at, updated_at, revoked_at FROM owner_approval_keys_v2
WHERE owner_id = ? AND key_id = ?`, ownerID, keyID))
	if err != nil {
		return nil, err
	}
	if key.State != OwnerApprovalKeyActive {
		return nil, ErrOwnerApprovalKeyConflict
	}
	verified, err := e2ee.VerifyOwnerLinkKeyGrant(signedProof, key.Public, ownerID,
		link.ID, link.ContractDigest, manifest.Digest, uint64(link.Version),
		e2ee.OwnerLinkGrantSide(side), now)
	if err != nil {
		return nil, fmt.Errorf("verify communication link key grant: %w", err)
	}
	linkExpiry, err := time.Parse(time.RFC3339, link.ExpiresAt)
	if err != nil {
		return nil, ErrCommunicationLinkScope
	}
	grantExpiry, err := time.Parse(time.RFC3339Nano, verified.ExpiresAt)
	if err != nil || grantExpiry.After(linkExpiry) {
		return nil, errors.New("communication link key grant exceeds link expiry")
	}
	prior, err := readStoredCommunicationLinkKeyGrant(tx, link.ID, side)
	if err == nil {
		if prior.ownerID != ownerID || prior.keyID != keyID ||
			prior.linkVersion != link.Version || prior.contractDigest != link.ContractDigest ||
			prior.manifestDigest != manifest.Digest || prior.nonce != verified.Nonce ||
			!bytes.Equal(prior.proof, signedProof) {
			return nil, ErrCommunicationLinkGrantConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return keyGrantStatus(prior, CommunicationLinkKeyGrantAccepted), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	stamp := now.Format(time.RFC3339Nano)
	_, err = tx.Exec(`INSERT INTO communication_link_key_grants_v2
(link_id, side, owner_id, key_id, link_version, contract_digest,
 manifest_digest, nonce, signed_proof, accepted_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, link.ID, side, ownerID, keyID, link.Version,
		link.ContractDigest, manifest.Digest, verified.Nonce, append([]byte(nil), signedProof...), stamp)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			return nil, ErrCommunicationLinkGrantReplay
		}
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return keyGrantStatus(storedCommunicationLinkKeyGrant{
		linkID: link.ID, side: side, ownerID: ownerID, keyID: keyID,
		manifestDigest: manifest.Digest, acceptedAt: stamp,
	}, CommunicationLinkKeyGrantAccepted), nil
}

func (s *Store) GetCommunicationLinkKeyGrantStatuses(linkID, requesterOwnerID string) ([]CommunicationLinkKeyGrantStatus, error) {
	if linkID == "" || len(linkID) > 256 || strings.TrimSpace(linkID) != linkID ||
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
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id = ?`, linkID))
	if err != nil {
		return nil, err
	}
	if requesterOwnerID != link.SourceOwnerID && requesterOwnerID != link.TargetOwnerID {
		return nil, ErrCommunicationLinkNotFound
	}
	now := time.Now().UTC()
	manifest, manifestErr := readCommunicationLinkKeyManifest(tx, *link, now)
	if manifestErr != nil && !errors.Is(manifestErr, ErrCommunicationLinkKeyCandidate) &&
		!errors.Is(manifestErr, ErrCommunicationLinkScope) &&
		!errors.Is(manifestErr, ErrCommunicationLinkNotFound) &&
		!errors.Is(manifestErr, ErrSessionBindingNotFound) &&
		!errors.Is(manifestErr, ErrSessionBindingLeaseExpired) &&
		!errors.Is(manifestErr, ErrSessionBindingInactive) {
		return nil, manifestErr
	}
	statuses := make([]CommunicationLinkKeyGrantStatus, 0, 2)
	for _, side := range []string{CommunicationLinkGrantSource, CommunicationLinkGrantTarget} {
		ownerID := communicationLinkGrantOwner(*link, side)
		grant, err := readStoredCommunicationLinkKeyGrant(tx, linkID, side)
		if errors.Is(err, sql.ErrNoRows) {
			status := CommunicationLinkKeyGrantStatus{LinkID: linkID, Side: side, OwnerID: ownerID,
				CurrentStatus: CommunicationLinkKeyGrantMissing}
			var legacy int
			if err := tx.QueryRow(`SELECT 1 FROM communication_link_grants_v2 WHERE link_id=? AND side=?`,
				linkID, side).Scan(&legacy); err == nil {
				status.CurrentStatus = CommunicationLinkKeyGrantLegacyUnbound
			} else if !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
			statuses = append(statuses, status)
			continue
		}
		if err != nil {
			return nil, err
		}
		status := keyGrantStatus(grant, CommunicationLinkKeyGrantAccepted)
		if manifestErr != nil || grant.linkVersion != link.Version ||
			grant.contractDigest != link.ContractDigest || grant.manifestDigest != manifest.Digest {
			status.CurrentStatus = CommunicationLinkKeyGrantBindingStale
			statuses = append(statuses, *status)
			continue
		}
		key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id, key_id, public_identity_json,
state, version, created_at, updated_at, revoked_at FROM owner_approval_keys_v2
WHERE owner_id = ? AND key_id = ?`, grant.ownerID, grant.keyID))
		if errors.Is(err, ErrOwnerApprovalKeyNotFound) {
			status.CurrentStatus = CommunicationLinkKeyGrantOwnerKeyRevoked
			statuses = append(statuses, *status)
			continue
		}
		if err != nil {
			return nil, err
		}
		if key.State != OwnerApprovalKeyActive {
			status.CurrentStatus = CommunicationLinkKeyGrantOwnerKeyRevoked
			statuses = append(statuses, *status)
			continue
		}
		var claims e2ee.OwnerLinkKeyGrant
		if err := json.Unmarshal(grant.proof, &claims); err != nil {
			status.CurrentStatus = CommunicationLinkKeyGrantInvalid
			statuses = append(statuses, *status)
			continue
		}
		if expires, err := time.Parse(time.RFC3339Nano, claims.ExpiresAt); err == nil && !expires.After(now) {
			status.CurrentStatus = CommunicationLinkKeyGrantProofExpired
			statuses = append(statuses, *status)
			continue
		}
		_, err = e2ee.VerifyOwnerLinkKeyGrant(grant.proof, key.Public,
			ownerID, link.ID, link.ContractDigest, manifest.Digest, uint64(link.Version),
			e2ee.OwnerLinkGrantSide(side), now)
		if err != nil {
			status.CurrentStatus = CommunicationLinkKeyGrantInvalid
		}
		statuses = append(statuses, *status)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return statuses, nil
}

func readStoredCommunicationLinkKeyGrant(tx *sql.Tx, linkID, side string) (storedCommunicationLinkKeyGrant, error) {
	var grant storedCommunicationLinkKeyGrant
	err := tx.QueryRow(`SELECT link_id, side, owner_id, key_id, link_version,
contract_digest, manifest_digest, nonce, signed_proof, accepted_at
FROM communication_link_key_grants_v2 WHERE link_id=? AND side=?`, linkID, side).Scan(
		&grant.linkID, &grant.side, &grant.ownerID, &grant.keyID, &grant.linkVersion,
		&grant.contractDigest, &grant.manifestDigest, &grant.nonce, &grant.proof, &grant.acceptedAt)
	return grant, err
}

func keyGrantStatus(grant storedCommunicationLinkKeyGrant, current string) *CommunicationLinkKeyGrantStatus {
	return &CommunicationLinkKeyGrantStatus{
		LinkID: grant.linkID, Side: grant.side, OwnerID: grant.ownerID, KeyID: grant.keyID,
		ManifestDigest: grant.manifestDigest, Accepted: true,
		AcceptedAt: grant.acceptedAt, CurrentStatus: current,
	}
}
