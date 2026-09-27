package store

// Artifact v2 deliberately lives beside the legacy Artifact implementation.
// The old row is an audit record and keeps its stable ID; a v2 reference adds
// immutable version metadata and an explicit, revocable read grant.  Nothing
// in this file treats an Artifact.Path as a caller supplied path.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	ArtifactRefV2ScopeMetadata = "metadata"
	ArtifactRefV2ScopeSummary  = "summary"
	ArtifactRefV2ScopeDigest   = "digest"
	ArtifactRefV2ScopeContent  = "content"

	ArtifactRefV2StatusAvailable = "available"
	ArtifactRefV2StatusRevoked   = "revoked"
)

var (
	ErrArtifactRefV2NotFound        = errors.New("artifact ref v2 not found")
	ErrArtifactRefV2Denied          = errors.New("artifact ref v2 access denied")
	ErrArtifactRefV2Revoked         = errors.New("artifact ref v2 is revoked")
	ErrArtifactRefV2Invalid         = errors.New("invalid artifact ref v2")
	ErrArtifactRefV2Immutable       = errors.New("artifact ref v2 is immutable")
	ErrArtifactRefV2DigestMismatch  = errors.New("artifact ref v2 digest mismatch")
	ErrArtifactRefV2UnsafePath      = errors.New("artifact ref v2 path is unsafe")
	ErrArtifactRefV2ScopeDenied     = errors.New("artifact ref v2 scope denied")
	ErrArtifactRefV2GrantNotFound   = errors.New("artifact ref v2 grant not found")
	ErrArtifactRefV2GrantRevoked    = errors.New("artifact ref v2 grant is revoked")
	ErrArtifactRefV2GrantInvalid    = errors.New("invalid artifact ref v2 grant")
	ErrArtifactRefV2VersionConflict = errors.New("artifact ref v2 version conflict")
)

// ArtifactRefV2 is a versioned reference to one legacy Artifact row.  Path is
// intentionally absent: callers receive only the opaque ref ID and approved
// metadata/scopes.  RelativePath stays private to the service layer through
// the unexported storage projection below.
type ArtifactRefV2 struct {
	ID                  string   `json:"artifact_ref_id"`
	ArtifactID          string   `json:"artifact_id"`
	Version             int64    `json:"version"`
	GroupID             string   `json:"group_id"`
	WorkspaceID         string   `json:"workspace_id,omitempty"`
	ProducerPrincipalID string   `json:"producer_principal_id,omitempty"`
	ProducerEndpointID  string   `json:"producer_endpoint_id,omitempty"`
	Name                string   `json:"name"`
	Kind                string   `json:"kind"`
	Summary             string   `json:"summary,omitempty"`
	Digest              string   `json:"digest"`
	Size                int64    `json:"size,omitempty"`
	MIMEType            string   `json:"mime_type,omitempty"`
	Scopes              []string `json:"scopes"`
	Status              string   `json:"status"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
}

// ArtifactVersionV2 and ArtifactRef are compatibility spellings used by
// integrations while the protocol migrates from the legacy Artifact name.
type ArtifactVersionV2 = ArtifactRefV2
type ArtifactRef = ArtifactRefV2

// ArtifactRefV2Input is accepted by the store and service.  ArtifactID is
// required and points at the existing legacy row; callers cannot create a v2
// reference from an arbitrary filesystem path.
type ArtifactRefV2Input struct {
	ID                  string   `json:"artifact_ref_id,omitempty"`
	ArtifactID          string   `json:"artifact_id"`
	Version             int64    `json:"version,omitempty"`
	GroupID             string   `json:"group_id"`
	WorkspaceID         string   `json:"workspace_id,omitempty"`
	ProducerPrincipalID string   `json:"producer_principal_id,omitempty"`
	ProducerEndpointID  string   `json:"producer_endpoint_id,omitempty"`
	Summary             string   `json:"summary,omitempty"`
	Digest              string   `json:"digest,omitempty"`
	Size                int64    `json:"size,omitempty"`
	MIMEType            string   `json:"mime_type,omitempty"`
	Scopes              []string `json:"scopes,omitempty"`
	RelativePath        string   `json:"relative_path,omitempty"`
}

type ArtifactRefV2Grant struct {
	ID                 string   `json:"grant_id"`
	ArtifactRefID      string   `json:"artifact_ref_id"`
	GranteeGroupID     string   `json:"grantee_group_id,omitempty"`
	GranteePrincipalID string   `json:"grantee_principal_id,omitempty"`
	GrantorPrincipalID string   `json:"grantor_principal_id,omitempty"`
	Scopes             []string `json:"scopes"`
	Status             string   `json:"status"`
	ExpiresAt          string   `json:"expires_at,omitempty"`
	RevokedAt          string   `json:"revoked_at,omitempty"`
	RevocationReason   string   `json:"revocation_reason,omitempty"`
	Revision           int64    `json:"revision"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
}

type ArtifactRefV2GrantInput struct {
	ID                 string   `json:"grant_id,omitempty"`
	ArtifactRefID      string   `json:"artifact_ref_id"`
	GranteeGroupID     string   `json:"grantee_group_id,omitempty"`
	GranteePrincipalID string   `json:"grantee_principal_id,omitempty"`
	GrantorPrincipalID string   `json:"grantor_principal_id,omitempty"`
	Scopes             []string `json:"scopes"`
	ExpiresAt          string   `json:"expires_at,omitempty"`
}

// ArtifactRefV2Authorized is the result of a point-in-time authorization
// check.  Content is filled by the fabric service only when content scope was
// requested and the stored path passed its containment checks.
type ArtifactRefV2Authorized struct {
	Ref     ArtifactRefV2 `json:"ref"`
	Scopes  []string      `json:"scopes"`
	Content []byte        `json:"content,omitempty"`
}

// artifactRefV2PathProjection is kept out of ArtifactRefV2 JSON.  It is used
// by internal/fabric to resolve the already persisted workspace-relative path.
type artifactRefV2PathProjection struct {
	WorkspacePath string
	RelativePath  string
}

const artifactV2Schema = `
CREATE TABLE IF NOT EXISTS artifact_v2_refs (
  id TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK(version > 0),
  group_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL DEFAULT '',
  producer_principal_id TEXT NOT NULL DEFAULT '',
  producer_endpoint_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  digest TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0 CHECK(size >= 0),
  mime_type TEXT NOT NULL DEFAULT '',
  scopes_json TEXT NOT NULL DEFAULT '[]',
  relative_path TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'available',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(artifact_id, version)
);
CREATE INDEX IF NOT EXISTS artifact_v2_refs_group_idx
  ON artifact_v2_refs(group_id, status, updated_at);
CREATE INDEX IF NOT EXISTS artifact_v2_refs_artifact_idx
  ON artifact_v2_refs(artifact_id, version DESC);
CREATE TABLE IF NOT EXISTS artifact_v2_grants (
  id TEXT PRIMARY KEY,
  artifact_ref_id TEXT NOT NULL,
  grantee_group_id TEXT NOT NULL DEFAULT '',
  grantee_principal_id TEXT NOT NULL DEFAULT '',
  grantor_principal_id TEXT NOT NULL DEFAULT '',
  scopes_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active',
  expires_at TEXT NOT NULL DEFAULT '',
  revoked_at TEXT NOT NULL DEFAULT '',
  revocation_reason TEXT NOT NULL DEFAULT '',
  revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(artifact_ref_id) REFERENCES artifact_v2_refs(id) ON DELETE CASCADE,
  CHECK(grantee_group_id <> '' OR grantee_principal_id <> '')
);
CREATE INDEX IF NOT EXISTS artifact_v2_grants_ref_idx
  ON artifact_v2_grants(artifact_ref_id, status, expires_at);
CREATE INDEX IF NOT EXISTS artifact_v2_grants_subject_idx
  ON artifact_v2_grants(grantee_group_id, grantee_principal_id, status);
`

// InitializeArtifactV2Schema is intentionally explicit so older databases can
// be rolled out before callers start publishing v2 references.  It is
// idempotent and may safely be called by Store.New's migration v6.
func (s *Store) InitializeArtifactV2Schema() error {
	if s == nil || s.db == nil {
		return errors.New("store is not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initializeArtifactV2SchemaLocked()
}

func (s *Store) initializeArtifactV2SchemaLocked() error {
	if _, err := s.db.Exec(artifactV2Schema); err != nil {
		return fmt.Errorf("initialize artifact v2 schema: %w", err)
	}
	return nil
}

func artifactV2JSON(value []string) (string, error) {
	if value == nil {
		value = []string{}
	}
	b, err := json.Marshal(value)
	return string(b), err
}

func artifactV2DecodeStrings(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return []string{}, nil
	}
	var value []string
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, err
	}
	return artifactV2Scopes(value)
}

func artifactV2Scopes(scopes []string) ([]string, error) {
	seen := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope == "" {
			continue
		}
		switch scope {
		case ArtifactRefV2ScopeMetadata, ArtifactRefV2ScopeSummary,
			ArtifactRefV2ScopeDigest, ArtifactRefV2ScopeContent:
		default:
			return nil, fmt.Errorf("%w: unknown scope %q", ErrArtifactRefV2ScopeDenied, scope)
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	if len(result) == 0 {
		result = []string{ArtifactRefV2ScopeMetadata, ArtifactRefV2ScopeSummary, ArtifactRefV2ScopeDigest}
	}
	return result, nil
}

func artifactV2Digest(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "sha256:") {
		value = value[len("sha256:"):]
	}
	return strings.ToLower(value)
}

func artifactV2DigestValid(value string) bool {
	value = artifactV2Digest(value)
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func artifactV2RelativePathSafe(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.IndexByte(value, 0) >= 0 || filepath.IsAbs(value) || strings.HasPrefix(value, `\`) {
		return false
	}
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return false
		}
	}
	clean := filepath.Clean(filepath.FromSlash(strings.ReplaceAll(value, `\`, "/")))
	return clean != "." && clean != "" && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator)) && !filepath.IsAbs(clean)
}

func normalizeArtifactRefV2(input ArtifactRefV2Input) (ArtifactRefV2Input, error) {
	input.ID = strings.TrimSpace(input.ID)
	input.ArtifactID = strings.TrimSpace(input.ArtifactID)
	input.GroupID = strings.TrimSpace(input.GroupID)
	input.WorkspaceID = strings.TrimSpace(input.WorkspaceID)
	input.ProducerPrincipalID = strings.TrimSpace(input.ProducerPrincipalID)
	input.ProducerEndpointID = strings.TrimSpace(input.ProducerEndpointID)
	input.Summary = strings.TrimSpace(input.Summary)
	input.Digest = artifactV2Digest(input.Digest)
	input.MIMEType = strings.TrimSpace(input.MIMEType)
	input.RelativePath = strings.TrimSpace(input.RelativePath)
	if input.ArtifactID == "" || input.GroupID == "" {
		return input, fmt.Errorf("%w: artifact_id and group_id are required", ErrArtifactRefV2Invalid)
	}
	// An empty digest is filled from the immutable legacy row below.  It is
	// still rejected before insertion when neither source has a valid SHA-256.
	if input.Size < 0 {
		return input, fmt.Errorf("%w: negative size", ErrArtifactRefV2Invalid)
	}
	scopes, err := artifactV2Scopes(input.Scopes)
	if err != nil {
		return input, err
	}
	input.Scopes = scopes
	return input, nil
}

func scanArtifactRefV2(row interface{ Scan(...any) error }) (*ArtifactRefV2, string, error) {
	var ref ArtifactRefV2
	var scopesJSON, relativePath string
	err := row.Scan(&ref.ID, &ref.ArtifactID, &ref.Version, &ref.GroupID,
		&ref.WorkspaceID, &ref.ProducerPrincipalID, &ref.ProducerEndpointID,
		&ref.Name, &ref.Kind, &ref.Summary, &ref.Digest, &ref.Size,
		&ref.MIMEType, &scopesJSON, &relativePath, &ref.Status,
		&ref.CreatedAt, &ref.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	ref.Scopes, err = artifactV2DecodeStrings(scopesJSON)
	if err != nil {
		return nil, "", err
	}
	return &ref, relativePath, nil
}

func (s *Store) createArtifactRefV2Locked(input ArtifactRefV2Input) (*ArtifactRefV2, error) {
	if err := s.initializeArtifactV2SchemaLocked(); err != nil {
		return nil, err
	}
	input, err := normalizeArtifactRefV2(input)
	if err != nil {
		return nil, err
	}
	var legacy Artifact
	var goalID, workerID, workspaceID, digest, evidence sql.NullString
	err = s.db.QueryRow(`SELECT id, goal_id, worker_id, workspace_id, name, path, kind, digest, evidence, status, created_at FROM artifacts WHERE id = ?`, input.ArtifactID).
		Scan(&legacy.ID, &goalID, &workerID, &workspaceID, &legacy.Name, &legacy.Path, &legacy.Kind, &digest, &evidence, &legacy.Status, &legacy.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrArtifactRefV2NotFound
	}
	if err != nil {
		return nil, err
	}
	legacy.WorkerID, legacy.WorkspaceID, legacy.Digest = workerID.String, workspaceID.String, digest.String
	if input.Digest == "" {
		input.Digest = artifactV2Digest(legacy.Digest)
	}
	if !artifactV2DigestValid(input.Digest) {
		return nil, fmt.Errorf("%w: sha256 digest is required", ErrArtifactRefV2Invalid)
	}
	if input.WorkspaceID != "" && legacy.WorkspaceID != "" && input.WorkspaceID != legacy.WorkspaceID {
		return nil, fmt.Errorf("%w: workspace does not own artifact", ErrArtifactRefV2UnsafePath)
	}
	input.WorkspaceID = legacy.WorkspaceID
	if input.ProducerPrincipalID == "" {
		input.ProducerPrincipalID = strings.TrimSpace(legacy.WorkerID)
	}
	if input.Summary == "" {
		input.Summary = strings.TrimSpace(legacy.Evidence)
	}
	legacyRelativePath := ""
	if legacy.Path != "" && !strings.HasPrefix(legacy.Path, "/") {
		legacyRelativePath = legacy.Path
	}
	if input.RelativePath != "" && legacyRelativePath == "" {
		return nil, fmt.Errorf("%w: caller cannot attach a path to an unscoped legacy artifact", ErrArtifactRefV2UnsafePath)
	}
	if input.RelativePath != "" && input.RelativePath != legacyRelativePath {
		return nil, fmt.Errorf("%w: path is taken from the legacy artifact", ErrArtifactRefV2UnsafePath)
	}
	input.RelativePath = legacyRelativePath
	if input.RelativePath != "" && !artifactV2RelativePathSafe(input.RelativePath) {
		return nil, ErrArtifactRefV2UnsafePath
	}
	if input.Version <= 0 {
		if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) + 1 FROM artifact_v2_refs WHERE artifact_id = ?`, input.ArtifactID).Scan(&input.Version); err != nil {
			return nil, err
		}
	}
	if input.Version <= 0 {
		return nil, ErrArtifactRefV2Invalid
	}
	if input.ID == "" {
		input.ID = NewID("artifact-ref")
	}
	if input.Summary == "" {
		input.Summary = strings.TrimSpace(legacy.Name)
	}
	name, kind := strings.TrimSpace(legacy.Name), strings.TrimSpace(legacy.Kind)
	if name == "" || kind == "" {
		return nil, ErrArtifactRefV2Invalid
	}
	timestamp := now()
	scopesJSON, err := artifactV2JSON(input.Scopes)
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(`INSERT INTO artifact_v2_refs
(id, artifact_id, version, group_id, workspace_id, producer_principal_id, producer_endpoint_id,
 name, kind, summary, digest, size, mime_type, scopes_json, relative_path, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.ID, input.ArtifactID, input.Version, input.GroupID, input.WorkspaceID,
		input.ProducerPrincipalID, input.ProducerEndpointID, name, kind, input.Summary,
		input.Digest, input.Size, input.MIMEType, scopesJSON, input.RelativePath,
		ArtifactRefV2StatusAvailable, timestamp, timestamp)
	if err != nil {
		var existing ArtifactRefV2
		var existingScopes, existingPath string
		lookupErr := s.db.QueryRow(`SELECT id, artifact_id, version, group_id, workspace_id, producer_principal_id, producer_endpoint_id,
 name, kind, summary, digest, size, mime_type, scopes_json, relative_path, status, created_at, updated_at
 FROM artifact_v2_refs WHERE artifact_id = ? AND version = ?`, input.ArtifactID, input.Version).Scan(
			&existing.ID, &existing.ArtifactID, &existing.Version, &existing.GroupID, &existing.WorkspaceID,
			&existing.ProducerPrincipalID, &existing.ProducerEndpointID, &existing.Name, &existing.Kind,
			&existing.Summary, &existing.Digest, &existing.Size, &existing.MIMEType, &existingScopes,
			&existingPath, &existing.Status, &existing.CreatedAt, &existing.UpdatedAt)
		if lookupErr == nil && artifactV2Digest(existing.Digest) == input.Digest && existing.GroupID == input.GroupID && existing.ID == input.ID {
			existing.Scopes, _ = artifactV2DecodeStrings(existingScopes)
			return &existing, nil
		}
		if lookupErr == nil {
			return nil, ErrArtifactRefV2Immutable
		}
		return nil, fmt.Errorf("create artifact ref v2: %w", err)
	}
	ref, _, err := scanArtifactRefV2(s.db.QueryRow(`SELECT id, artifact_id, version, group_id, workspace_id, producer_principal_id, producer_endpoint_id,
 name, kind, summary, digest, size, mime_type, scopes_json, relative_path, status, created_at, updated_at
 FROM artifact_v2_refs WHERE id = ?`, input.ID))
	return ref, err
}

func (s *Store) CreateArtifactRefV2(input ArtifactRefV2Input) (*ArtifactRefV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createArtifactRefV2Locked(input)
}

// CreateArtifactV2 is a concise compatibility alias.
func (s *Store) CreateArtifactV2(input ArtifactRefV2Input) (*ArtifactRefV2, error) {
	return s.CreateArtifactRefV2(input)
}

func (s *Store) getArtifactRefV2Locked(id string) (*ArtifactRefV2, string, error) {
	if err := s.initializeArtifactV2SchemaLocked(); err != nil {
		return nil, "", err
	}
	return scanArtifactRefV2(s.db.QueryRow(`SELECT id, artifact_id, version, group_id, workspace_id, producer_principal_id, producer_endpoint_id,
 name, kind, summary, digest, size, mime_type, scopes_json, relative_path, status, created_at, updated_at
 FROM artifact_v2_refs WHERE id = ?`, strings.TrimSpace(id)))
}

func (s *Store) GetArtifactRefV2(id string) (*ArtifactRefV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, _, err := s.getArtifactRefV2Locked(id)
	if err != nil {
		return nil, err
	}
	if ref == nil {
		return nil, ErrArtifactRefV2NotFound
	}
	return ref, nil
}

func (s *Store) GetArtifactRefV2Version(artifactID string, version int64) (*ArtifactRefV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.initializeArtifactV2SchemaLocked(); err != nil {
		return nil, err
	}
	ref, _, err := scanArtifactRefV2(s.db.QueryRow(`SELECT id, artifact_id, version, group_id, workspace_id, producer_principal_id, producer_endpoint_id,
 name, kind, summary, digest, size, mime_type, scopes_json, relative_path, status, created_at, updated_at
 FROM artifact_v2_refs WHERE artifact_id = ? AND version = ?`, strings.TrimSpace(artifactID), version))
	if err != nil {
		return nil, err
	}
	if ref == nil {
		return nil, ErrArtifactRefV2NotFound
	}
	return ref, nil
}

// ArtifactRefV2Path returns a private path projection for the fabric package.
// It never accepts a path argument and therefore cannot be used to turn an
// HTTP/MCP string into a local file read.
func (s *Store) ArtifactRefV2Path(id string) (workspacePath, relativePath string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, relativePath, err := s.getArtifactRefV2Locked(id)
	if err != nil {
		return "", "", err
	}
	if ref == nil {
		return "", "", ErrArtifactRefV2NotFound
	}
	if ref.WorkspaceID == "" || relativePath == "" {
		return "", "", nil
	}
	var path string
	err = s.db.QueryRow(`SELECT path FROM workspaces WHERE id = ?`, ref.WorkspaceID).Scan(&path)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrArtifactRefV2NotFound
	}
	return path, relativePath, err
}

func (s *Store) ListArtifactRefsV2(groupID string, limit int) ([]ArtifactRefV2, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.initializeArtifactV2SchemaLocked(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT id, artifact_id, version, group_id, workspace_id, producer_principal_id, producer_endpoint_id,
 name, kind, summary, digest, size, mime_type, scopes_json, relative_path, status, created_at, updated_at
 FROM artifact_v2_refs WHERE group_id = ? ORDER BY updated_at DESC, id LIMIT ?`, strings.TrimSpace(groupID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ArtifactRefV2, 0)
	for rows.Next() {
		ref, _, err := scanArtifactRefV2(rows)
		if err != nil {
			return nil, err
		}
		if ref != nil {
			result = append(result, *ref)
		}
	}
	return result, rows.Err()
}

func normalizeArtifactGrant(input ArtifactRefV2GrantInput) (ArtifactRefV2GrantInput, error) {
	input.ID = strings.TrimSpace(input.ID)
	input.ArtifactRefID = strings.TrimSpace(input.ArtifactRefID)
	input.GranteeGroupID = strings.TrimSpace(input.GranteeGroupID)
	input.GranteePrincipalID = strings.TrimSpace(input.GranteePrincipalID)
	input.GrantorPrincipalID = strings.TrimSpace(input.GrantorPrincipalID)
	if input.ArtifactRefID == "" || (input.GranteeGroupID == "" && input.GranteePrincipalID == "") {
		return input, ErrArtifactRefV2GrantInvalid
	}
	var err error
	input.Scopes, err = artifactV2Scopes(input.Scopes)
	if err != nil {
		return input, err
	}
	if input.ExpiresAt != "" {
		parsed, parseErr := time.Parse(time.RFC3339Nano, input.ExpiresAt)
		if parseErr != nil || !parsed.After(time.Now().UTC()) {
			return input, fmt.Errorf("%w: expires_at", ErrArtifactRefV2GrantInvalid)
		}
		input.ExpiresAt = parsed.UTC().Format(time.RFC3339Nano)
	}
	return input, nil
}

func scanArtifactRefV2Grant(row interface{ Scan(...any) error }) (*ArtifactRefV2Grant, error) {
	var grant ArtifactRefV2Grant
	var scopesJSON string
	err := row.Scan(&grant.ID, &grant.ArtifactRefID, &grant.GranteeGroupID,
		&grant.GranteePrincipalID, &grant.GrantorPrincipalID, &scopesJSON,
		&grant.Status, &grant.ExpiresAt, &grant.RevokedAt, &grant.RevocationReason,
		&grant.Revision, &grant.CreatedAt, &grant.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	grant.Scopes, err = artifactV2DecodeStrings(scopesJSON)
	return &grant, err
}

func (s *Store) CreateArtifactRefV2Grant(input ArtifactRefV2GrantInput) (*ArtifactRefV2Grant, error) {
	input, err := normalizeArtifactGrant(input)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.initializeArtifactV2SchemaLocked(); err != nil {
		return nil, err
	}
	ref, _, err := s.getArtifactRefV2Locked(input.ArtifactRefID)
	if err != nil {
		return nil, err
	}
	if ref == nil {
		return nil, ErrArtifactRefV2NotFound
	}
	allowed := make(map[string]struct{}, len(ref.Scopes))
	for _, scope := range ref.Scopes {
		allowed[scope] = struct{}{}
	}
	for _, scope := range input.Scopes {
		if _, ok := allowed[scope]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrArtifactRefV2ScopeDenied, scope)
		}
	}
	if input.ID == "" {
		input.ID = NewID("artifact-grant")
	}
	nowValue := now()
	scopesJSON, err := artifactV2JSON(input.Scopes)
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(`INSERT INTO artifact_v2_grants
(id, artifact_ref_id, grantee_group_id, grantee_principal_id, grantor_principal_id, scopes_json,
 status, expires_at, revoked_at, revocation_reason, revision, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, 'active', ?, '', '', 1, ?, ?)`, input.ID, input.ArtifactRefID,
		input.GranteeGroupID, input.GranteePrincipalID, input.GrantorPrincipalID, scopesJSON,
		input.ExpiresAt, nowValue, nowValue)
	if err != nil {
		return nil, fmt.Errorf("create artifact ref v2 grant: %w", err)
	}
	return scanArtifactRefV2Grant(s.db.QueryRow(`SELECT id, artifact_ref_id, grantee_group_id, grantee_principal_id,
 grantor_principal_id, scopes_json, status, expires_at, revoked_at, revocation_reason, revision, created_at, updated_at
 FROM artifact_v2_grants WHERE id = ?`, input.ID))
}

func (s *Store) GrantArtifactRefV2(input ArtifactRefV2GrantInput) (*ArtifactRefV2Grant, error) {
	return s.CreateArtifactRefV2Grant(input)
}

func (s *Store) RevokeArtifactRefV2Grant(id, reason string) (*ArtifactRefV2Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.initializeArtifactV2SchemaLocked(); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	var exists string
	if err := s.db.QueryRow(`SELECT id FROM artifact_v2_grants WHERE id = ?`, id).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrArtifactRefV2GrantNotFound
	} else if err != nil {
		return nil, err
	}
	timestamp := now()
	if _, err := s.db.Exec(`UPDATE artifact_v2_grants SET status = 'revoked', revoked_at = ?, revocation_reason = ?, revision = revision + 1, updated_at = ? WHERE id = ?`, timestamp, strings.TrimSpace(reason), timestamp, id); err != nil {
		return nil, err
	}
	return scanArtifactRefV2Grant(s.db.QueryRow(`SELECT id, artifact_ref_id, grantee_group_id, grantee_principal_id,
 grantor_principal_id, scopes_json, status, expires_at, revoked_at, revocation_reason, revision, created_at, updated_at
 FROM artifact_v2_grants WHERE id = ?`, id))
}

func (s *Store) GetArtifactRefV2Grant(id string) (*ArtifactRefV2Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.initializeArtifactV2SchemaLocked(); err != nil {
		return nil, err
	}
	grant, err := scanArtifactRefV2Grant(s.db.QueryRow(`SELECT id, artifact_ref_id, grantee_group_id, grantee_principal_id,
 grantor_principal_id, scopes_json, status, expires_at, revoked_at, revocation_reason, revision, created_at, updated_at
 FROM artifact_v2_grants WHERE id = ?`, strings.TrimSpace(id)))
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return nil, ErrArtifactRefV2GrantNotFound
	}
	return grant, nil
}

// RequireArtifactRefV2GroupGrant is used when a Gateway persists a cross
// group reference.  The target member is still checked at read time; this
// method only proves that a concrete, currently active, scope-limited grant
// exists for that target group.
func (s *Store) RequireArtifactRefV2GroupGrant(refID, groupID string, requestedScopes []string, at time.Time) error {
	refID, groupID = strings.TrimSpace(refID), strings.TrimSpace(groupID)
	if refID == "" || groupID == "" {
		return ErrArtifactRefV2Denied
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	requested, err := artifactV2Scopes(requestedScopes)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.initializeArtifactV2SchemaLocked(); err != nil {
		return err
	}
	ref, _, err := s.getArtifactRefV2Locked(refID)
	if err != nil {
		return err
	}
	if ref == nil {
		return ErrArtifactRefV2NotFound
	}
	if ref.Status != ArtifactRefV2StatusAvailable || !artifactV2ScopesAllowed(requested, ref.Scopes) {
		return ErrArtifactRefV2Denied
	}
	rows, err := s.db.Query(`SELECT scopes_json, status, expires_at FROM artifact_v2_grants WHERE artifact_ref_id = ? AND grantee_group_id = ?`, refID, groupID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var scopesJSON, status, expiresAt string
		if err := rows.Scan(&scopesJSON, &status, &expiresAt); err != nil {
			return err
		}
		if status != "active" {
			continue
		}
		if expiresAt != "" {
			expires, parseErr := time.Parse(time.RFC3339Nano, expiresAt)
			if parseErr != nil || !expires.After(at) {
				continue
			}
		}
		grantScopes, decodeErr := artifactV2DecodeStrings(scopesJSON)
		if decodeErr == nil && artifactV2ScopesAllowed(requested, grantScopes) {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return ErrArtifactRefV2Denied
}

func (s *Store) RevokeArtifactRefV2(id, reason string) (*ArtifactRefV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.initializeArtifactV2SchemaLocked(); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	result, err := s.db.Exec(`UPDATE artifact_v2_refs SET status = ?, updated_at = ? WHERE id = ? AND status <> ?`, ArtifactRefV2StatusRevoked, now(), id, ArtifactRefV2StatusRevoked)
	if err != nil {
		return nil, err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return nil, ErrArtifactRefV2NotFound
	}
	_ = reason // the immutable ref remains auditable; grants are denied by status.
	ref, _, scanErr := scanArtifactRefV2(s.db.QueryRow(`SELECT id, artifact_id, version, group_id, workspace_id, producer_principal_id, producer_endpoint_id,
 name, kind, summary, digest, size, mime_type, scopes_json, relative_path, status, created_at, updated_at
 FROM artifact_v2_refs WHERE id = ?`, id))
	return ref, scanErr
}

func artifactV2MembershipAllows(membership *Membership, action string) bool {
	if membership == nil || membership.Status != MembershipStatusActive {
		return false
	}
	if membership.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339Nano, membership.ExpiresAt)
		if err != nil || !expires.After(time.Now().UTC()) {
			return false
		}
	}
	for _, grant := range membership.Grants {
		grant = strings.TrimSpace(strings.ToLower(grant))
		if grant == "*" || grant == action {
			return true
		}
	}
	if allowed, ok := membership.Authorization[action].(bool); ok {
		return allowed
	}
	return false
}

func artifactV2ScopesAllowed(requested, allowed []string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		set[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := set[scope]; !ok {
			return false
		}
	}
	return true
}

// AuthorizeArtifactRefV2 is the single storage guard used by Service, HTTP,
// and MCP callers.  It queries Membership on every call and then checks the
// exact ref/grant/scope; no workspace-wide or path-wide permission is inferred.
func (s *Store) AuthorizeArtifactRefV2(principalID, groupID, refID string, requestedScopes []string, at time.Time) (*ArtifactRefV2, error) {
	principalID, groupID, refID = strings.TrimSpace(principalID), strings.TrimSpace(groupID), strings.TrimSpace(refID)
	if principalID == "" || groupID == "" || refID == "" {
		return nil, ErrArtifactRefV2Denied
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	requested, err := artifactV2Scopes(requestedScopes)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := networkGuardPrincipalGroupLocked(s.db, principalID, groupID); err != nil {
		return nil, ErrArtifactRefV2Denied
	}
	if err := s.initializeArtifactV2SchemaLocked(); err != nil {
		return nil, err
	}
	membership, err := scanMembership(s.db.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE principal_id = ? AND group_id = ?`, principalID, groupID))
	if err != nil || !artifactV2MembershipAllows(membership, "artifact.read") {
		return nil, ErrArtifactRefV2Denied
	}
	ref, _, err := scanArtifactRefV2(s.db.QueryRow(`SELECT id, artifact_id, version, group_id, workspace_id, producer_principal_id, producer_endpoint_id,
 name, kind, summary, digest, size, mime_type, scopes_json, relative_path, status, created_at, updated_at
 FROM artifact_v2_refs WHERE id = ?`, refID))
	if err != nil {
		return nil, err
	}
	if ref == nil {
		return nil, ErrArtifactRefV2NotFound
	}
	var refNetwork, readerNetwork string
	if err := s.db.QueryRow(`SELECT network_id FROM groups WHERE id=?`, ref.GroupID).Scan(&refNetwork); err != nil {
		return nil, ErrArtifactRefV2Denied
	}
	if err := s.db.QueryRow(`SELECT network_id FROM groups WHERE id=?`, groupID).Scan(&readerNetwork); err != nil {
		return nil, ErrArtifactRefV2Denied
	}
	if refNetwork != readerNetwork {
		return nil, ErrArtifactRefV2Denied
	}
	if ref.Status != ArtifactRefV2StatusAvailable {
		return nil, ErrArtifactRefV2Revoked
	}
	if !artifactV2ScopesAllowed(requested, ref.Scopes) {
		return nil, ErrArtifactRefV2ScopeDenied
	}
	if groupID == ref.GroupID {
		return ref, nil
	}
	rows, err := s.db.Query(`SELECT scopes_json, status, expires_at FROM artifact_v2_grants
 WHERE artifact_ref_id = ? AND (grantee_group_id = ? OR grantee_principal_id = ?)`, refID, groupID, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var scopesJSON, status, expiresAt string
		if err := rows.Scan(&scopesJSON, &status, &expiresAt); err != nil {
			return nil, err
		}
		if status != "active" {
			continue
		}
		if expiresAt != "" {
			expires, parseErr := time.Parse(time.RFC3339Nano, expiresAt)
			if parseErr != nil || !expires.After(at) {
				continue
			}
		}
		grantScopes, decodeErr := artifactV2DecodeStrings(scopesJSON)
		if decodeErr == nil && artifactV2ScopesAllowed(requested, grantScopes) {
			return ref, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nil, ErrArtifactRefV2Denied
}

// CheckArtifactRefV2 is a compatibility spelling for read-side callers.
func (s *Store) CheckArtifactRefV2(principalID, groupID, refID string, scopes []string, at time.Time) (*ArtifactRefV2, error) {
	return s.AuthorizeArtifactRefV2(principalID, groupID, refID, scopes, at)
}
