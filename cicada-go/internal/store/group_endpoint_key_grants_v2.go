package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	GroupEndpointKeyGrantVersion   = 1
	GroupEndpointKeyGrantOperation = "group-endpoint-key-grant:v1"
	GroupEndpointKeyGrantCurrent   = "CURRENT"
	GroupEndpointKeyGrantStale     = "STALE"
	GroupEndpointKeyGrantExpired   = "PROOF_EXPIRED"
	GroupEndpointKeyGrantRevoked   = "OWNER_KEY_REVOKED"
	GroupEndpointKeyGrantInvalid   = "INVALID"
	groupEndpointKeyGrantDomain    = "cicada/group/endpoint-key-grant-manifest/v1\x00"
	groupEndpointKeyBindingDomain  = "cicada/group/endpoint-key-binding/v1\x00"
)

var (
	ErrGroupEndpointKeyGrantNotFound = errors.New("Group Endpoint key grant not found")
	ErrGroupEndpointKeyGrantScope    = errors.New("Endpoint is not currently authorized in this owner Group")
	ErrGroupEndpointKeyGrantConflict = errors.New("Group Endpoint key grant conflicts with an accepted grant")
	ErrGroupEndpointKeyGrantReplay   = errors.New("Group Endpoint key grant nonce was already used")
	ErrGroupEndpointKeyGrantStale    = errors.New("Group Endpoint key grant is not current")
	ErrGroupEndpointKeyGrantExpired  = errors.New("Group Endpoint key grant has expired")
)

// GroupEndpointKeyGrantManifest is the deterministic, public statement an
// owner reviews before signing. CandidatePublicIdentity is public key material;
// the Hub never receives the corresponding Endpoint or owner private key.
type GroupEndpointKeyGrantManifest struct {
	Version                 int                 `json:"version"`
	Operation               string              `json:"operation"`
	HubID                   string              `json:"hub_id"`
	OwnerID                 string              `json:"owner_id"`
	PrincipalID             string              `json:"principal_id"`
	GroupID                 string              `json:"group_id"`
	GroupRevision           int64               `json:"group_revision"`
	EndpointID              string              `json:"endpoint_id"`
	NodeID                  string              `json:"node_id"`
	BindingID               string              `json:"binding_id"`
	BindingEpoch            uint64              `json:"binding_epoch"`
	MembershipRevision      int64               `json:"membership_revision"`
	EndpointJoinRevision    int64               `json:"endpoint_join_revision"`
	CandidateVersion        int64               `json:"candidate_version"`
	CandidateKeyID          string              `json:"candidate_key_id"`
	CandidateFingerprint    string              `json:"candidate_fingerprint"`
	CandidateProofDigest    string              `json:"candidate_proof_digest"`
	CandidateBindingDigest  string              `json:"candidate_binding_digest"`
	CandidatePublicIdentity e2ee.PublicIdentity `json:"candidate_public_identity"`
	// The complete self-attestation lets an independent Client verify the
	// candidate signature. CandidateProofDigest already binds these bytes in
	// the signed manifest claims, so this additive evidence field does not
	// change existing grant digests or stored historical grants.
	CandidateAttestation []byte `json:"candidate_attestation"`
	OwnerKeyID           string `json:"owner_key_id"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
	Digest               string `json:"digest"`
}

type groupEndpointKeyGrantManifestClaims struct {
	Version                 int                 `json:"version"`
	Operation               string              `json:"operation"`
	HubID                   string              `json:"hub_id"`
	OwnerID                 string              `json:"owner_id"`
	PrincipalID             string              `json:"principal_id"`
	GroupID                 string              `json:"group_id"`
	GroupRevision           int64               `json:"group_revision"`
	EndpointID              string              `json:"endpoint_id"`
	NodeID                  string              `json:"node_id"`
	BindingID               string              `json:"binding_id"`
	BindingEpoch            uint64              `json:"binding_epoch"`
	MembershipRevision      int64               `json:"membership_revision"`
	EndpointJoinRevision    int64               `json:"endpoint_join_revision"`
	CandidateVersion        int64               `json:"candidate_version"`
	CandidateKeyID          string              `json:"candidate_key_id"`
	CandidateFingerprint    string              `json:"candidate_fingerprint"`
	CandidateProofDigest    string              `json:"candidate_proof_digest"`
	CandidateBindingDigest  string              `json:"candidate_binding_digest"`
	CandidatePublicIdentity e2ee.PublicIdentity `json:"candidate_public_identity"`
	OwnerKeyID              string              `json:"owner_key_id"`
	IssuedAt                string              `json:"issued_at"`
	ExpiresAt               string              `json:"expires_at"`
}

type groupEndpointKeyBindingClaims struct {
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
}

type OwnerGroupEndpointKeyGrant struct {
	ID            string                        `json:"grant_id"`
	OwnerID       string                        `json:"owner_id"`
	GroupID       string                        `json:"group_id"`
	EndpointID    string                        `json:"endpoint_id"`
	OwnerKeyID    string                        `json:"owner_key_id"`
	Manifest      GroupEndpointKeyGrantManifest `json:"manifest"`
	SignedProof   []byte                        `json:"signed_proof"`
	AcceptedAt    string                        `json:"accepted_at"`
	CurrentStatus string                        `json:"current_status"`
}

func (s *Store) initializeGroupEndpointKeyGrantsV2Schema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS group_endpoint_key_grants_v2 (
  id TEXT PRIMARY KEY,
  hub_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  owner_key_id TEXT NOT NULL,
  manifest_digest TEXT NOT NULL CHECK(length(manifest_digest) = 64),
  manifest_json TEXT NOT NULL,
  nonce TEXT NOT NULL,
  signed_proof BLOB NOT NULL CHECK(length(signed_proof) > 0),
  accepted_at TEXT NOT NULL,
  UNIQUE(owner_id, owner_key_id, nonce),
  FOREIGN KEY(owner_id, owner_key_id) REFERENCES owner_approval_keys_v2(owner_id, key_id)
);
CREATE INDEX IF NOT EXISTS group_endpoint_key_grants_v2_scope_idx
  ON group_endpoint_key_grants_v2(owner_id, group_id, endpoint_id, accepted_at DESC);`)
	if err != nil {
		return fmt.Errorf("initialize Group Endpoint key grants: %w", err)
	}
	return nil
}

// PreviewGroupEndpointKeyGrant returns the current public-key snapshot that an
// owner must review and sign. The caller supplies only the owner key selection
// and desired validity interval; every identity, revision, binding and
// candidate claim is derived from Store records in one read transaction.
//
// The existing Client signer can sign this preview with
// SignOwnerLinkKeyGrant(manifest.OwnerID, GroupEndpointKeyGrantOperation,
// manifest.Digest, manifest.CandidateBindingDigest,
// uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issuedAt,
// expiresAt). The operation token and manifest digest make this distinct from
// an ordinary Link approval at the Store boundary.
func (s *Store) PreviewGroupEndpointKeyGrant(ownerID, groupID, endpointID, ownerKeyID string,
	issuedAt, expiresAt time.Time) (*GroupEndpointKeyGrantManifest, error) {
	if err := validateGroupEndpointKeyGrantRequest(ownerID, groupID, endpointID, ownerKeyID); err != nil ||
		issuedAt.IsZero() || expiresAt.IsZero() {
		return nil, errors.New("Group Endpoint key grant preview request is invalid")
	}
	nowAt := time.Now().UTC()
	issuedAt, expiresAt = issuedAt.UTC(), expiresAt.UTC()
	if issuedAt.After(nowAt) || !expiresAt.After(nowAt) || !expiresAt.After(issuedAt) {
		return nil, errors.New("Group Endpoint key grant interval is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	manifest, err := readGroupEndpointKeyGrantManifest(tx, ownerID, groupID, endpointID,
		ownerKeyID, issuedAt.Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano), nowAt)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return manifest, nil
}

// AcceptGroupEndpointKeyGrant verifies the owner's real ML-DSA signature over
// the latest Store-derived manifest and consumes its nonce transactionally.
// AuthenticatedOwnerID comes from the trusted caller; a proof's self-reported
// owner or a model approval claim never supplies authority.
func (s *Store) AcceptGroupEndpointKeyGrant(authenticatedOwnerID, groupID, endpointID,
	ownerKeyID string, signedProof []byte) (*OwnerGroupEndpointKeyGrant, error) {
	if err := validateGroupEndpointKeyGrantRequest(authenticatedOwnerID, groupID, endpointID, ownerKeyID); err != nil ||
		len(signedProof) == 0 || len(signedProof) > 16*1024 {
		return nil, errors.New("Group Endpoint key grant request is invalid")
	}
	var submitted e2ee.OwnerLinkKeyGrant
	if err := json.Unmarshal(signedProof, &submitted); err != nil {
		return nil, fmt.Errorf("decode Group Endpoint key grant: %w", err)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, submitted.IssuedAt)
	if err != nil || issuedAt.UTC().Format(time.RFC3339Nano) != submitted.IssuedAt {
		return nil, errors.New("Group Endpoint key grant issue time is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, submitted.ExpiresAt)
	if err != nil || expiresAt.UTC().Format(time.RFC3339Nano) != submitted.ExpiresAt {
		return nil, errors.New("Group Endpoint key grant expiry is invalid")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(cause error) (*OwnerGroupEndpointKeyGrant, error) {
		_ = tx.Rollback()
		return nil, cause
	}
	nowAt := time.Now().UTC()
	manifest, err := readGroupEndpointKeyGrantManifest(tx, authenticatedOwnerID, groupID,
		endpointID, ownerKeyID, submitted.IssuedAt, submitted.ExpiresAt, nowAt)
	if err != nil {
		return rollback(err)
	}
	ownerKey, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id, key_id, public_identity_json,
state, version, created_at, updated_at, revoked_at FROM owner_approval_keys_v2
WHERE owner_id = ? AND key_id = ?`, authenticatedOwnerID, ownerKeyID))
	if err != nil {
		return rollback(err)
	}
	if ownerKey.State != OwnerApprovalKeyActive {
		return rollback(ErrOwnerApprovalKeyConflict)
	}
	verified, err := e2ee.VerifyOwnerLinkKeyGrant(signedProof, ownerKey.Public,
		authenticatedOwnerID, GroupEndpointKeyGrantOperation, manifest.Digest,
		manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, nowAt)
	if err != nil {
		return rollback(fmt.Errorf("verify Group Endpoint key grant signature: %w", err))
	}
	var existingID, existingManifestDigest string
	var existingProof []byte
	err = tx.QueryRow(`SELECT id, manifest_digest, signed_proof
FROM group_endpoint_key_grants_v2 WHERE owner_id = ? AND owner_key_id = ? AND nonce = ?`,
		authenticatedOwnerID, ownerKeyID, verified.Nonce).Scan(&existingID, &existingManifestDigest, &existingProof)
	if err == nil {
		if existingManifestDigest != manifest.Digest || string(existingProof) != string(signedProof) {
			return rollback(ErrGroupEndpointKeyGrantReplay)
		}
		record, err := scanGroupEndpointKeyGrant(tx.QueryRow(`SELECT id, owner_id, group_id,
endpoint_id, owner_key_id, manifest_json, signed_proof, accepted_at
FROM group_endpoint_key_grants_v2 WHERE id = ?`, existingID))
		if err != nil {
			return rollback(err)
		}
		if record.OwnerID != authenticatedOwnerID || record.GroupID != groupID ||
			record.EndpointID != endpointID || record.OwnerKeyID != ownerKeyID ||
			groupEndpointKeyManifestDigest(record.Manifest) != manifest.Digest {
			return rollback(ErrGroupEndpointKeyGrantConflict)
		}
		record.Manifest = *manifest
		record.CurrentStatus = GroupEndpointKeyGrantCurrent
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return record, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return rollback(err)
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return rollback(err)
	}
	acceptedAt := nowAt.Format(time.RFC3339Nano)
	id := NewID("gkg")
	_, err = tx.Exec(`INSERT INTO group_endpoint_key_grants_v2
(id, hub_id, owner_id, group_id, endpoint_id, owner_key_id, manifest_digest,
 manifest_json, nonce, signed_proof, accepted_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, manifest.HubID, authenticatedOwnerID,
		groupID, endpointID, ownerKeyID, manifest.Digest, string(manifestJSON),
		verified.Nonce, append([]byte(nil), signedProof...), acceptedAt)
	if err != nil {
		if isSQLiteConstraint(err) {
			return rollback(ErrGroupEndpointKeyGrantReplay)
		}
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &OwnerGroupEndpointKeyGrant{ID: id, OwnerID: authenticatedOwnerID,
		GroupID: groupID, EndpointID: endpointID, OwnerKeyID: ownerKeyID,
		Manifest: *manifest, SignedProof: append([]byte(nil), signedProof...),
		AcceptedAt: acceptedAt, CurrentStatus: GroupEndpointKeyGrantCurrent,
	}, nil
}

// GetGroupEndpointKeyGrant returns the newest public grant record in this
// owner scope and evaluates it against current Group, membership, Endpoint,
// binding, candidate and owner-key state. A retained signature remains
// inspectable after it becomes stale or is revoked.
func (s *Store) GetGroupEndpointKeyGrant(ownerID, groupID, endpointID string) (*OwnerGroupEndpointKeyGrant, error) {
	if validateOwnerApprovalID(ownerID) != nil || strings.TrimSpace(groupID) == "" ||
		strings.TrimSpace(endpointID) == "" || strings.TrimSpace(groupID) != groupID ||
		strings.TrimSpace(endpointID) != endpointID {
		return nil, ErrGroupEndpointKeyGrantNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var endpointOwner string
	err = tx.QueryRow(`SELECT p.owner_id FROM fabric_endpoints e
JOIN principals p ON p.id = e.principal_id WHERE e.id = ?`, endpointID).Scan(&endpointOwner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGroupEndpointKeyGrantNotFound
	}
	if err != nil {
		return nil, err
	}
	if endpointOwner != ownerID {
		return nil, ErrGroupEndpointKeyGrantNotFound
	}
	record, err := readLatestGroupEndpointKeyGrant(tx, ownerID, groupID, endpointID)
	if err != nil {
		return nil, err
	}
	record.CurrentStatus = evaluateGroupEndpointKeyGrant(tx, record, time.Now().UTC())
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

// VerifyCurrentGroupEndpointKeyGrant returns public key material only when
// the owner's signature and the complete grant snapshot are still current.
func (s *Store) VerifyCurrentGroupEndpointKeyGrant(ownerID, groupID,
	endpointID string) (*OwnerGroupEndpointKeyGrant, error) {
	record, err := s.GetGroupEndpointKeyGrant(ownerID, groupID, endpointID)
	if err != nil {
		return nil, err
	}
	if record.CurrentStatus != GroupEndpointKeyGrantCurrent {
		return nil, ErrGroupEndpointKeyGrantStale
	}
	return record, nil
}

func validateGroupEndpointKeyGrantRequest(ownerID, groupID, endpointID, ownerKeyID string) error {
	if validateOwnerApprovalID(ownerID) != nil || groupID == "" || len(groupID) > 256 ||
		strings.TrimSpace(groupID) != groupID || endpointID == "" || len(endpointID) > 256 ||
		strings.TrimSpace(endpointID) != endpointID || ownerKeyID == "" || len(ownerKeyID) > 256 ||
		strings.TrimSpace(ownerKeyID) != ownerKeyID {
		return errors.New("Group Endpoint key grant scope is invalid")
	}
	return nil
}

func readGroupEndpointKeyGrantManifest(tx *sql.Tx, ownerID, groupID, endpointID,
	ownerKeyID, issuedAt, expiresAt string, at time.Time) (*GroupEndpointKeyGrantManifest, error) {
	issued, err := time.Parse(time.RFC3339Nano, issuedAt)
	if err != nil || issued.UTC().Format(time.RFC3339Nano) != issuedAt || issued.After(at) {
		return nil, errors.New("Group Endpoint key grant issue time is invalid")
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return nil, errors.New("Group Endpoint key grant has an invalid expiry")
	}
	if !expires.After(at) {
		return nil, ErrGroupEndpointKeyGrantExpired
	}
	if expires.UTC().Format(time.RFC3339Nano) != expiresAt || !expires.After(issued) {
		return nil, errors.New("Group Endpoint key grant has an invalid interval")
	}
	ownerKey, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id, key_id, public_identity_json,
state, version, created_at, updated_at, revoked_at FROM owner_approval_keys_v2
WHERE owner_id = ? AND key_id = ?`, ownerID, ownerKeyID))
	if err != nil {
		return nil, err
	}
	if ownerKey.State != OwnerApprovalKeyActive {
		return nil, ErrOwnerApprovalKeyConflict
	}
	var hubID string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id = 1`).Scan(&hubID); err != nil || hubID == "" {
		if err == nil {
			err = errors.New("stable Hub ID is empty")
		}
		return nil, fmt.Errorf("load authoritative Hub ID: %w", err)
	}

	var snapshot struct {
		principalID, endpointOwnerID, principalStatus                                  string
		endpointNodeID, endpointStatus, migrationState, endpointBindingID              string
		membershipStatus, membershipEffectiveAt, membershipExpiresAt                   string
		joinStatus, groupState, groupOwnerPrincipalID, groupOwnerID, groupOwnerStatus  string
		bindingID, bindingEndpointID, bindingPrincipalID, bindingNodeID, bindingStatus string
		leaseOwner, leaseExpiresAt                                                     string
		bindingEpoch                                                                   uint64
		membershipRevision, joinRevision, groupRevision                                int64
	}
	err = tx.QueryRow(`SELECT COALESCE(e.principal_id, ''), COALESCE(p.owner_id, ''),
COALESCE(p.status, ''), COALESCE(e.machine_id, ''), COALESCE(e.status, ''),
COALESCE(e.migration_state, ''), COALESCE(e.binding_id, ''),
COALESCE(m.status, ''), COALESCE(m.effective_at, ''), COALESCE(m.expires_at, ''),
COALESCE(eg.status, ''), COALESCE(g.state, ''), COALESCE(g.owner_principal_id, ''),
COALESCE(gp.owner_id, ''), COALESCE(gp.status, ''), COALESCE(b.id, ''),
COALESCE(b.endpoint_id, ''), COALESCE(b.principal_id, ''), COALESCE(b.node_id, ''),
COALESCE(b.status, ''), COALESCE(b.lease_owner, ''), COALESCE(b.lease_expires_at, ''),
COALESCE(b.epoch, 0), COALESCE(m.revision, 0), COALESCE(eg.revision, 0), COALESCE(g.revision, 0)
FROM fabric_endpoints e
LEFT JOIN principals p ON p.id = e.principal_id
LEFT JOIN memberships m ON m.principal_id = e.principal_id AND m.group_id = ?
LEFT JOIN endpoint_group_memberships eg ON eg.endpoint_id = e.id AND eg.group_id = ?
LEFT JOIN groups g ON g.id = ?
LEFT JOIN principals gp ON gp.id = g.owner_principal_id
LEFT JOIN session_bindings b ON b.id = e.binding_id
WHERE e.id = ?`, groupID, groupID, groupID, endpointID).Scan(
		&snapshot.principalID, &snapshot.endpointOwnerID, &snapshot.principalStatus,
		&snapshot.endpointNodeID, &snapshot.endpointStatus, &snapshot.migrationState,
		&snapshot.endpointBindingID, &snapshot.membershipStatus, &snapshot.membershipEffectiveAt,
		&snapshot.membershipExpiresAt, &snapshot.joinStatus, &snapshot.groupState,
		&snapshot.groupOwnerPrincipalID, &snapshot.groupOwnerID, &snapshot.groupOwnerStatus,
		&snapshot.bindingID, &snapshot.bindingEndpointID, &snapshot.bindingPrincipalID,
		&snapshot.bindingNodeID, &snapshot.bindingStatus, &snapshot.leaseOwner,
		&snapshot.leaseExpiresAt, &snapshot.bindingEpoch, &snapshot.membershipRevision,
		&snapshot.joinRevision, &snapshot.groupRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGroupEndpointKeyGrantScope
	}
	if err != nil {
		return nil, err
	}
	if snapshot.endpointOwnerID != ownerID || snapshot.principalID == "" ||
		snapshot.principalStatus != PrincipalStatusActive || snapshot.endpointStatus == "left" ||
		snapshot.migrationState != EndpointMigrationReady || snapshot.endpointNodeID == "" ||
		snapshot.groupState != GroupStateActive || snapshot.groupOwnerPrincipalID == "" ||
		snapshot.groupOwnerID != ownerID || snapshot.groupOwnerStatus != PrincipalStatusActive ||
		snapshot.membershipStatus != MembershipStatusActive || snapshot.joinStatus != "active" ||
		snapshot.membershipRevision <= 0 || snapshot.joinRevision <= 0 || snapshot.groupRevision <= 0 ||
		snapshot.bindingID == "" || snapshot.bindingID != snapshot.endpointBindingID ||
		snapshot.bindingEndpointID != endpointID || snapshot.bindingPrincipalID != snapshot.principalID ||
		snapshot.bindingNodeID == "" || snapshot.bindingNodeID != snapshot.endpointNodeID ||
		snapshot.bindingStatus != SessionBindingStatusLeased || snapshot.bindingEpoch == 0 ||
		snapshot.leaseOwner == "" {
		return nil, ErrGroupEndpointKeyGrantScope
	}
	if snapshot.membershipEffectiveAt != "" {
		effective, err := time.Parse(time.RFC3339Nano, snapshot.membershipEffectiveAt)
		if err != nil || effective.After(at) {
			return nil, ErrGroupEndpointKeyGrantScope
		}
	}
	if snapshot.membershipExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339Nano, snapshot.membershipExpiresAt)
		if err != nil || !expires.After(at) {
			return nil, ErrGroupEndpointKeyGrantScope
		}
	}
	if err := requireCurrentOwnerBoundGroupNodeTx(tx, snapshot.endpointNodeID, ownerID, hubID); err != nil {
		return nil, err
	}
	leaseDeadline, err := time.Parse(time.RFC3339Nano, snapshot.leaseExpiresAt)
	if err != nil || !leaseDeadline.After(at) {
		return nil, ErrSessionBindingLeaseExpired
	}

	side, err := readCommunicationLinkKeySide(tx, endpointID, groupID, snapshot.principalID,
		ownerID, snapshot.endpointNodeID, snapshot.bindingID, snapshot.bindingEpoch)
	if err != nil {
		return nil, err
	}
	bindingClaims := groupEndpointKeyBindingClaims{
		Operation: GroupEndpointKeyGrantOperation, OwnerID: ownerID, PrincipalID: snapshot.principalID,
		GroupID: groupID, EndpointID: endpointID, NodeID: snapshot.endpointNodeID,
		BindingID: snapshot.bindingID, BindingEpoch: snapshot.bindingEpoch,
		MembershipRevision: snapshot.membershipRevision, EndpointJoinRevision: snapshot.joinRevision,
		CandidateVersion: side.CandidateVersion, CandidateKeyID: side.KeyID,
		Fingerprint: side.KeyFingerprint, ProofDigest: side.ProofDigest,
		PublicIdentity: side.PublicIdentity,
	}
	bindingJSON, err := json.Marshal(bindingClaims)
	if err != nil {
		return nil, err
	}
	bindingHash := sha256.Sum256(append([]byte(groupEndpointKeyBindingDomain), bindingJSON...))
	manifest := GroupEndpointKeyGrantManifest{
		Version: GroupEndpointKeyGrantVersion, Operation: GroupEndpointKeyGrantOperation,
		HubID: hubID, OwnerID: ownerID, PrincipalID: snapshot.principalID,
		GroupID: groupID, GroupRevision: snapshot.groupRevision,
		EndpointID: endpointID, NodeID: snapshot.endpointNodeID,
		BindingID: snapshot.bindingID, BindingEpoch: snapshot.bindingEpoch,
		MembershipRevision: snapshot.membershipRevision, EndpointJoinRevision: snapshot.joinRevision,
		CandidateVersion: side.CandidateVersion, CandidateKeyID: side.KeyID,
		CandidateFingerprint: side.KeyFingerprint, CandidateProofDigest: side.ProofDigest,
		CandidateBindingDigest:  hex.EncodeToString(bindingHash[:]),
		CandidatePublicIdentity: side.PublicIdentity,
		CandidateAttestation:    append([]byte(nil), side.Attestation...), OwnerKeyID: ownerKeyID,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}
	manifest.Digest = groupEndpointKeyManifestDigest(manifest)
	if manifest.Digest == "" {
		return nil, errors.New("encode Group Endpoint key grant manifest")
	}
	return &manifest, nil
}

// requireCurrentOwnerBoundGroupNodeTx ensures the Endpoint's Node still has
// the exact active owner/Hub/credential binding. A public candidate alone
// cannot establish that the Node publishing it is currently owner-authorized.
func requireCurrentOwnerBoundGroupNodeTx(tx *sql.Tx, nodeID, ownerID, hubID string) error {
	var authorized int
	err := tx.QueryRow(`SELECT EXISTS (
  SELECT 1 FROM node_owner_bindings_v2 binding
  JOIN fabric_node_credentials credential ON credential.node_id = binding.node_id
    AND credential.credential_hash = binding.node_credential_digest
    AND credential.version = binding.node_credential_version
    AND credential.status = 'active'
  JOIN client_device_hub_config_v2 hub ON hub.id = 1 AND hub.hub_id = binding.hub_id
  JOIN principals owner_principal ON owner_principal.id = binding.owner_id
    AND owner_principal.kind = 'human' AND owner_principal.status = 'active'
  JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id = binding.owner_id
    AND owner_key.key_id = binding.owner_key_id AND owner_key.state = 'ACTIVE'
  JOIN machines machine ON machine.id = binding.node_id AND machine.owner_id = binding.owner_id
  WHERE binding.node_id = ? AND binding.owner_id = ? AND binding.hub_id = ?
    AND binding.state = 'ACTIVE'
)`, nodeID, ownerID, hubID).Scan(&authorized)
	if err != nil {
		return err
	}
	if authorized != 1 {
		return ErrGroupEndpointKeyGrantScope
	}
	return nil
}

func manifestClaims(manifest GroupEndpointKeyGrantManifest) groupEndpointKeyGrantManifestClaims {
	return groupEndpointKeyGrantManifestClaims{
		Version: manifest.Version, Operation: manifest.Operation, HubID: manifest.HubID,
		OwnerID: manifest.OwnerID, PrincipalID: manifest.PrincipalID,
		GroupID: manifest.GroupID, GroupRevision: manifest.GroupRevision,
		EndpointID: manifest.EndpointID, NodeID: manifest.NodeID,
		BindingID: manifest.BindingID, BindingEpoch: manifest.BindingEpoch,
		MembershipRevision:   manifest.MembershipRevision,
		EndpointJoinRevision: manifest.EndpointJoinRevision,
		CandidateVersion:     manifest.CandidateVersion, CandidateKeyID: manifest.CandidateKeyID,
		CandidateFingerprint:    manifest.CandidateFingerprint,
		CandidateProofDigest:    manifest.CandidateProofDigest,
		CandidateBindingDigest:  manifest.CandidateBindingDigest,
		CandidatePublicIdentity: manifest.CandidatePublicIdentity,
		OwnerKeyID:              manifest.OwnerKeyID, IssuedAt: manifest.IssuedAt,
		ExpiresAt: manifest.ExpiresAt,
	}
}

func scanGroupEndpointKeyGrant(row v2Scanner) (*OwnerGroupEndpointKeyGrant, error) {
	var record OwnerGroupEndpointKeyGrant
	var manifestJSON string
	err := row.Scan(&record.ID, &record.OwnerID, &record.GroupID, &record.EndpointID,
		&record.OwnerKeyID, &manifestJSON, &record.SignedProof, &record.AcceptedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGroupEndpointKeyGrantNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(manifestJSON), &record.Manifest); err != nil ||
		record.Manifest.OwnerID != record.OwnerID || record.Manifest.GroupID != record.GroupID ||
		record.Manifest.EndpointID != record.EndpointID || record.Manifest.OwnerKeyID != record.OwnerKeyID {
		return nil, ErrGroupEndpointKeyGrantConflict
	}
	canonical, err := json.Marshal(record.Manifest)
	if err != nil || string(canonical) != manifestJSON {
		return nil, ErrGroupEndpointKeyGrantConflict
	}
	return &record, nil
}

func readLatestGroupEndpointKeyGrant(tx *sql.Tx, ownerID, groupID, endpointID string) (*OwnerGroupEndpointKeyGrant, error) {
	return scanGroupEndpointKeyGrant(tx.QueryRow(`SELECT id, owner_id, group_id, endpoint_id,
owner_key_id, manifest_json, signed_proof, accepted_at
FROM group_endpoint_key_grants_v2
WHERE owner_id = ? AND group_id = ? AND endpoint_id = ?
ORDER BY accepted_at DESC, id DESC LIMIT 1`, ownerID, groupID, endpointID))
}

func evaluateGroupEndpointKeyGrant(tx *sql.Tx, record *OwnerGroupEndpointKeyGrant, at time.Time) string {
	if record == nil || record.Manifest.Operation != GroupEndpointKeyGrantOperation ||
		record.Manifest.Version != GroupEndpointKeyGrantVersion ||
		record.Manifest.Digest == "" {
		return GroupEndpointKeyGrantInvalid
	}
	if groupEndpointKeyManifestDigest(record.Manifest) != record.Manifest.Digest {
		return GroupEndpointKeyGrantInvalid
	}
	ownerKey, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id, key_id, public_identity_json,
state, version, created_at, updated_at, revoked_at FROM owner_approval_keys_v2
WHERE owner_id = ? AND key_id = ?`, record.OwnerID, record.OwnerKeyID))
	if err != nil || ownerKey.State != OwnerApprovalKeyActive {
		return GroupEndpointKeyGrantRevoked
	}
	manifest, err := readGroupEndpointKeyGrantManifest(tx, record.OwnerID, record.GroupID,
		record.EndpointID, record.OwnerKeyID, record.Manifest.IssuedAt,
		record.Manifest.ExpiresAt, at)
	if err != nil {
		if errors.Is(err, ErrGroupEndpointKeyGrantExpired) {
			return GroupEndpointKeyGrantExpired
		}
		return GroupEndpointKeyGrantStale
	}
	if manifest.Digest != record.Manifest.Digest ||
		manifest.CandidateBindingDigest != record.Manifest.CandidateBindingDigest {
		return GroupEndpointKeyGrantStale
	}
	var storedDigest string
	err = tx.QueryRow(`SELECT manifest_digest FROM group_endpoint_key_grants_v2 WHERE id = ?`, record.ID).Scan(&storedDigest)
	if err != nil || storedDigest != manifest.Digest {
		return GroupEndpointKeyGrantInvalid
	}
	if _, err := e2ee.VerifyOwnerLinkKeyGrant(record.SignedProof, ownerKey.Public,
		record.OwnerID, GroupEndpointKeyGrantOperation, manifest.Digest,
		manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, at); err != nil {
		return GroupEndpointKeyGrantInvalid
	}
	return GroupEndpointKeyGrantCurrent
}

func groupEndpointKeyManifestDigest(manifest GroupEndpointKeyGrantManifest) string {
	encoded, err := json.Marshal(manifestClaims(manifest))
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(append([]byte(groupEndpointKeyGrantDomain), encoded...))
	return hex.EncodeToString(digest[:])
}
