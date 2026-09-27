package store

import (
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

const EndpointKeyCandidateStateCandidate = "CANDIDATE"

var (
	ErrEndpointKeyNotFound = errors.New("Endpoint key candidate not found")
	ErrEndpointKeyConflict = errors.New("Endpoint already has a different public key candidate")
)

// EndpointKeyCandidate is a self-attested public identity associated with the
// Endpoint's current leased SessionBinding. CANDIDATE does not mean trusted or
// routable; a receiving Node must establish its own group-scoped pin first.
// Proof contains only the signed public-key attestation, never private key
// material.
type EndpointKeyCandidate struct {
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
	CreatedAt    string              `json:"created_at"`
	UpdatedAt    string              `json:"updated_at"`
}

func (s *Store) initializeEndpointKeyCandidateSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS endpoint_key_candidates_v2 (
  endpoint_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  public_identity_json TEXT NOT NULL,
  key_id TEXT NOT NULL,
  binding_id TEXT NOT NULL,
  binding_epoch INTEGER NOT NULL CHECK(binding_epoch > 0),
  proof BLOB NOT NULL,
  proof_digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state = 'CANDIDATE'),
  version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(endpoint_id) REFERENCES fabric_endpoints(id)
);
CREATE INDEX IF NOT EXISTS endpoint_key_candidates_v2_owner_idx
  ON endpoint_key_candidates_v2(owner_id, state, endpoint_id);
CREATE INDEX IF NOT EXISTS endpoint_key_candidates_v2_node_idx
  ON endpoint_key_candidates_v2(node_id, state, endpoint_id);
`)
	if err != nil {
		return fmt.Errorf("initialize Endpoint key candidate schema: %w", err)
	}
	return nil
}

// RegisterEndpointKeyCandidate verifies a current SessionBinding proof and
// stores one public-key candidate for a stable Endpoint. The Principal, owner,
// and Node are read from the database in the same transaction as the write.
// Rejoining with the same public identity refreshes its proof and binding
// coordinates; a different key requires an explicit, separate rotation flow.
func (s *Store) RegisterEndpointKeyCandidate(endpointID, principalID, bindingID string, epoch uint64, attestation []byte) (*EndpointKeyCandidate, error) {
	endpointID = strings.TrimSpace(endpointID)
	principalID = strings.TrimSpace(principalID)
	bindingID = strings.TrimSpace(bindingID)
	if endpointID == "" || principalID == "" || bindingID == "" || epoch == 0 || len(attestation) == 0 {
		return nil, errors.New("Endpoint, Principal, binding, epoch and attestation are required")
	}
	if epoch > math.MaxInt64 {
		return nil, ErrSessionBindingStaleEpoch
	}
	proof := append([]byte(nil), attestation...)

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(cause error) (*EndpointKeyCandidate, error) {
		_ = tx.Rollback()
		return nil, cause
	}

	var dbPrincipalID, ownerID, endpointNodeID, endpointStatus, migrationState, currentEndpointBindingID, principalStatus string
	err = tx.QueryRow(`SELECT COALESCE(e.principal_id, ''), COALESCE(p.owner_id, ''),
COALESCE(e.machine_id, ''), e.status, COALESCE(e.migration_state, ''),
COALESCE(e.binding_id, ''), COALESCE(p.status, '')
FROM fabric_endpoints e LEFT JOIN principals p ON p.id = e.principal_id
WHERE e.id = ?`, endpointID).Scan(&dbPrincipalID, &ownerID, &endpointNodeID,
		&endpointStatus, &migrationState, &currentEndpointBindingID, &principalStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrEndpointNotFound)
	}
	if err != nil {
		return rollback(err)
	}
	if migrationState != EndpointMigrationReady || dbPrincipalID == "" {
		return rollback(ErrEndpointMigrationRequired)
	}
	if dbPrincipalID != principalID {
		return rollback(ErrSessionBindingConflict)
	}
	if endpointStatus == "left" || principalStatus != PrincipalStatusActive {
		return rollback(ErrMembershipNotActive)
	}
	if ownerID == "" || endpointNodeID == "" {
		return rollback(ErrMembershipNotActive)
	}
	var activeJoin int
	if err := tx.QueryRow(`SELECT EXISTS (
  SELECT 1 FROM endpoint_group_memberships eg
  JOIN memberships m ON m.principal_id = ? AND m.group_id = eg.group_id
  JOIN groups g ON g.id = eg.group_id
  WHERE eg.endpoint_id = ? AND eg.status = 'active' AND m.status = 'active'
    AND g.state = 'ACTIVE' AND (m.effective_at = '' OR m.effective_at <= ?)
    AND (m.expires_at = '' OR m.expires_at > ?)
)`, dbPrincipalID, endpointID, now(), now()).Scan(&activeJoin); err != nil {
		return rollback(err)
	}
	if activeJoin != 1 {
		return rollback(ErrMembershipNotActive)
	}

	var bindingEndpointID, bindingPrincipalID, bindingNodeID, bindingStatus, leaseOwner, leaseExpiresAt string
	var bindingEpoch uint64
	err = tx.QueryRow(`SELECT endpoint_id, principal_id, node_id, epoch, status,
lease_owner, lease_expires_at FROM session_bindings WHERE id = ?`, bindingID).Scan(
		&bindingEndpointID, &bindingPrincipalID, &bindingNodeID, &bindingEpoch,
		&bindingStatus, &leaseOwner, &leaseExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrSessionBindingNotFound)
	}
	if err != nil {
		return rollback(err)
	}
	if currentEndpointBindingID != bindingID || bindingEndpointID != endpointID || bindingPrincipalID != dbPrincipalID {
		return rollback(ErrSessionBindingStaleEpoch)
	}
	if bindingEpoch != epoch {
		return rollback(ErrSessionBindingStaleEpoch)
	}
	if bindingStatus != SessionBindingStatusLeased || !isActiveBindingStatus(bindingStatus) || leaseOwner == "" {
		return rollback(ErrSessionBindingInactive)
	}
	leaseDeadline, parseErr := time.Parse(time.RFC3339Nano, leaseExpiresAt)
	if parseErr != nil || !leaseDeadline.After(time.Now().UTC()) {
		return rollback(ErrSessionBindingLeaseExpired)
	}
	if bindingNodeID == "" || bindingNodeID != endpointNodeID {
		return rollback(ErrSessionBindingConflict)
	}

	public, err := e2ee.VerifyEndpointKeyAttestation(proof, endpointID, dbPrincipalID,
		bindingNodeID, bindingID, bindingEpoch)
	if err != nil {
		return rollback(fmt.Errorf("verify Endpoint key candidate: %w", err))
	}
	publicJSON, err := json.Marshal(public)
	if err != nil {
		return rollback(fmt.Errorf("encode Endpoint public identity: %w", err))
	}
	proofDigestBytes := sha256.Sum256(proof)
	proofDigest := hex.EncodeToString(proofDigestBytes[:])
	timestamp := now()

	var previousKeyID, previousPublicJSON string
	err = tx.QueryRow(`SELECT key_id, public_identity_json FROM endpoint_key_candidates_v2
WHERE endpoint_id = ?`, endpointID).Scan(&previousKeyID, &previousPublicJSON)
	if err == nil {
		if previousKeyID != public.ID || previousPublicJSON != string(publicJSON) {
			return rollback(ErrEndpointKeyConflict)
		}
		var previousBindingID, previousOwnerID, previousNodeID, previousPrincipalID string
		var previousEpoch uint64
		if err := tx.QueryRow(`SELECT binding_id, binding_epoch, principal_id, owner_id, node_id
FROM endpoint_key_candidates_v2 WHERE endpoint_id = ?`, endpointID).Scan(
			&previousBindingID, &previousEpoch, &previousPrincipalID, &previousOwnerID, &previousNodeID); err != nil {
			return rollback(err)
		}
		if previousBindingID != bindingID || previousEpoch != bindingEpoch ||
			previousPrincipalID != dbPrincipalID || previousOwnerID != ownerID || previousNodeID != bindingNodeID {
			if _, err := tx.Exec(`UPDATE endpoint_key_candidates_v2 SET principal_id = ?, owner_id = ?,
node_id = ?, binding_id = ?, binding_epoch = ?, proof = ?, proof_digest = ?,
version = version + 1, updated_at = ? WHERE endpoint_id = ?`, dbPrincipalID, ownerID,
				bindingNodeID, bindingID, bindingEpoch, proof, proofDigest, timestamp, endpointID); err != nil {
				return rollback(err)
			}
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.Exec(`INSERT INTO endpoint_key_candidates_v2
(endpoint_id, principal_id, owner_id, node_id, public_identity_json, key_id,
 binding_id, binding_epoch, proof, proof_digest, state, version, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`, endpointID, dbPrincipalID,
			ownerID, bindingNodeID, string(publicJSON), public.ID, bindingID, bindingEpoch,
			proof, proofDigest, EndpointKeyCandidateStateCandidate, timestamp, timestamp); err != nil {
			return rollback(err)
		}
	} else {
		return rollback(err)
	}

	candidate, err := scanEndpointKeyCandidate(tx.QueryRow(`SELECT `+endpointKeyCandidateColumns+
		` FROM endpoint_key_candidates_v2 WHERE endpoint_id = ?`, endpointID))
	if err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return candidate, nil
}

// GetEndpointKeyCandidate reads exactly one candidate by stable Endpoint ID.
// Fabric callers must authorize the relevant Group before returning it.
func (s *Store) GetEndpointKeyCandidate(endpointID string) (*EndpointKeyCandidate, error) {
	endpointID = strings.TrimSpace(endpointID)
	if endpointID == "" {
		return nil, ErrEndpointKeyNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate, err := scanEndpointKeyCandidate(s.db.QueryRow(`SELECT `+endpointKeyCandidateColumns+
		` FROM endpoint_key_candidates_v2 WHERE endpoint_id = ?`, endpointID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEndpointKeyNotFound
	}
	return candidate, err
}

const endpointKeyCandidateColumns = `endpoint_id, principal_id, owner_id, node_id,
public_identity_json, key_id, binding_id, binding_epoch, proof, proof_digest,
state, version, created_at, updated_at`

func scanEndpointKeyCandidate(row v2Scanner) (*EndpointKeyCandidate, error) {
	var candidate EndpointKeyCandidate
	var publicJSON string
	err := row.Scan(&candidate.EndpointID, &candidate.PrincipalID, &candidate.OwnerID,
		&candidate.NodeID, &publicJSON, &candidate.KeyID, &candidate.BindingID,
		&candidate.BindingEpoch, &candidate.Proof, &candidate.ProofDigest,
		&candidate.State, &candidate.Version, &candidate.CreatedAt, &candidate.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(publicJSON), &candidate.Public); err != nil {
		return nil, fmt.Errorf("decode Endpoint public identity: %w", err)
	}
	if candidate.Public.ID != candidate.KeyID {
		return nil, errors.New("Endpoint key candidate identity does not match key ID")
	}
	if err := e2ee.ValidatePublicIdentity(candidate.Public); err != nil {
		return nil, fmt.Errorf("validate Endpoint public identity: %w", err)
	}
	digest := sha256.Sum256(candidate.Proof)
	if hex.EncodeToString(digest[:]) != candidate.ProofDigest {
		return nil, errors.New("Endpoint key candidate proof digest mismatch")
	}
	return &candidate, nil
}
