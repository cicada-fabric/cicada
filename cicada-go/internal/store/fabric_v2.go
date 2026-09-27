package store

// This file contains the additive v2 identity and binding store.  The legacy
// Fabric tables and APIs remain authoritative for their existing rows; v2
// records are associated with those rows only by explicit enrollment or
// migration.  In particular, startup never guesses a Group for an old
// Endpoint.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	EndpointMigrationPendingGroup = "MIGRATION_PENDING_GROUP"
	EndpointMigrationReady        = "READY"

	PrincipalKindHuman   = "human"
	PrincipalKindAgent   = "agent"
	PrincipalKindService = "service"

	PrincipalStatusActive  = "active"
	PrincipalStatusRevoked = "revoked"

	GroupStateDraft     = "DRAFT"
	GroupStateActive    = "ACTIVE"
	GroupStatePaused    = "PAUSED"
	GroupStateQuiescing = "QUIESCING"
	GroupStateArchived  = "ARCHIVED"

	MembershipStatusActive    = "active"
	MembershipStatusRevoked   = "revoked"
	MembershipStatusSuspended = "suspended"

	SessionBindingStatusPending    = "pending"
	SessionBindingStatusActive     = "active"
	SessionBindingStatusLeased     = "leased"
	SessionBindingStatusReleased   = "released"
	SessionBindingStatusExpired    = "expired"
	SessionBindingStatusRevoked    = "revoked"
	SessionBindingStatusSuperseded = "superseded"
)

var (
	ErrPrincipalNotFound          = errors.New("principal not found")
	ErrGroupNotFound              = errors.New("group not found")
	ErrMembershipNotFound         = errors.New("membership not found")
	ErrMembershipNotActive        = errors.New("membership is not active")
	ErrSessionBindingNotFound     = errors.New("session binding not found")
	ErrSessionBindingConflict     = errors.New("active session binding already exists")
	ErrSessionBindingInactive     = errors.New("session binding is not active")
	ErrSessionBindingStaleEpoch   = errors.New("stale session binding epoch")
	ErrSessionBindingLeaseHeld    = errors.New("session binding lease is held by another owner")
	ErrSessionBindingLeaseExpired = errors.New("session binding lease has expired")
	ErrSessionBindingLeaseOwner   = errors.New("session binding lease owner mismatch")
	ErrSessionBindingVersion      = errors.New("session binding version conflict")
	ErrEndpointNotFound           = errors.New("endpoint not found")
	ErrEndpointMigrationRequired  = errors.New("endpoint requires explicit migration")
)

// Compatibility aliases keep the error vocabulary usable by the directory
// and node layers without creating a second error contract.
var (
	ErrStaleBinding    = ErrSessionBindingStaleEpoch
	ErrStaleLease      = ErrSessionBindingStaleEpoch
	ErrLeaseHeld       = ErrSessionBindingLeaseHeld
	ErrLeaseOwner      = ErrSessionBindingLeaseOwner
	ErrVersionConflict = ErrSessionBindingVersion
)

// Principal is a durable authenticated subject.  CredentialHash is a
// fingerprint supplied by the authentication/enrollment layer; this store
// never accepts or writes a plaintext credential.
type Principal struct {
	ID             string `json:"principal_id"`
	Kind           string `json:"kind"`
	OwnerID        string `json:"owner_id,omitempty"`
	TrustDomainID  string `json:"trust_domain_id,omitempty"`
	Name           string `json:"name,omitempty"`
	DisplayName    string `json:"display_name,omitempty"`
	Status         string `json:"status"`
	CredentialHash string `json:"credential_hash,omitempty"`
	Version        int64  `json:"version"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type PrincipalFilter struct {
	Kind   string
	Status string
	Limit  int
}

// Group is a persistent collaboration and authorization scope.  Revision is
// the policy/topology revision, while Version tracks row updates.
type Group struct {
	ID               string `json:"group_id"`
	ParentGroupID    string `json:"parent_group_id,omitempty"`
	OwnerPrincipalID string `json:"owner_principal_id,omitempty"`
	TrustDomainID    string `json:"trust_domain_id,omitempty"`
	Name             string `json:"name"`
	State            string `json:"state"`
	Purpose          string `json:"purpose,omitempty"`
	Revision         int64  `json:"revision"`
	PolicyRef        string `json:"policy_ref,omitempty"`
	ContextPolicy    string `json:"context_policy,omitempty"`
	IsolationProfile string `json:"isolation_profile,omitempty"`
	ExternalMode     string `json:"external_mode,omitempty"`
	Version          int64  `json:"version"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

type GroupFilter struct {
	State string
	Owner string
	Limit int
}

// Membership is the principal's scoped authorization in a Group.  Role is a
// convenient primary role; Roles and Grants preserve richer policy without
// making a role name an implicit administrator relationship.
type Membership struct {
	ID               string         `json:"membership_id"`
	PrincipalID      string         `json:"principal_id"`
	GroupID          string         `json:"group_id"`
	Role             string         `json:"role"`
	Roles            []string       `json:"roles,omitempty"`
	Grants           []string       `json:"grants,omitempty"`
	Authorization    map[string]any `json:"authorization,omitempty"`
	Status           string         `json:"status"`
	EffectiveAt      string         `json:"effective_at,omitempty"`
	ExpiresAt        string         `json:"expires_at,omitempty"`
	RevokedAt        string         `json:"revoked_at,omitempty"`
	RevocationReason string         `json:"revocation_reason,omitempty"`
	Revision         int64          `json:"revision"`
	Version          int64          `json:"version"`
	CreatedAt        string         `json:"created_at"`
	UpdatedAt        string         `json:"updated_at"`
}

type MembershipFilter struct {
	PrincipalID string
	GroupID     string
	Status      string
	Role        string
	Limit       int
}

// SessionBinding gives one stable Endpoint a precise native session and
// delivery owner.  Epoch is the fencing token; Version is the row revision.
// GroupContextID and Workspace are compatibility aliases for callers that use
// the architecture document's names instead of GroupID/WorkspaceID.
type SessionBinding struct {
	ID                    string         `json:"binding_id"`
	EndpointID            string         `json:"endpoint_id"`
	PrincipalID           string         `json:"principal_id"`
	GroupID               string         `json:"group_id"`
	GroupContextID        string         `json:"group_context_id,omitempty"`
	NativeSessionID       string         `json:"native_session_id"`
	NodeID                string         `json:"node_id,omitempty"`
	WorkspaceID           string         `json:"workspace_id,omitempty"`
	Workspace             string         `json:"workspace,omitempty"`
	Epoch                 uint64         `json:"epoch"`
	LeaseOwner            string         `json:"lease_owner,omitempty"`
	LeaseExpiresAt        string         `json:"lease_expires_at,omitempty"`
	Status                string         `json:"status"`
	CredentialHash        string         `json:"credential_hash,omitempty"`
	CredentialHashVersion int64          `json:"credential_hash_version"`
	Version               int64          `json:"version"`
	Mode                  string         `json:"mode,omitempty"`
	ContextContinuity     string         `json:"context_continuity,omitempty"`
	Capabilities          map[string]any `json:"capabilities,omitempty"`
	ReplacesBindingID     string         `json:"replaces_binding_id,omitempty"`
	RevocationReason      string         `json:"revocation_reason,omitempty"`
	CreatedAt             string         `json:"created_at"`
	UpdatedAt             string         `json:"updated_at"`
}

type SessionBindingFilter struct {
	EndpointID  string
	PrincipalID string
	GroupID     string
	NodeID      string
	Status      string
	Limit       int
}

// EndpointV2Filter is evaluated in SQLite before rows are returned.  This is
// intentional: a caller must be able to request one Group's visible
// endpoints without first reading a global endpoint list and filtering it in
// application memory.
type EndpointV2Filter struct {
	GroupID        string
	OwnerID        string
	PrincipalID    string
	Status         string
	NodeID         string
	Harness        string
	MigrationState string
	Limit          int
}

// HashCredential returns a storage-safe credential fingerprint.  Callers
// should pass the enrollment credential bytes and persist only this result in
// Principal.CredentialHash or SessionBinding.CredentialHash.
func HashCredential(credential []byte) string {
	digest := sha256.Sum256(credential)
	return hex.EncodeToString(digest[:])
}

func (s *Store) initializeFabricV2Schema() error {
	// These columns are additive so opening a database created by the original
	// Fabric cannot discard Endpoint IDs, native sessions, or old relations.
	for _, column := range []struct {
		table string
		name  string
		ddl   string
	}{
		{"fabric_endpoints", "principal_id", `ALTER TABLE fabric_endpoints ADD COLUMN principal_id TEXT NOT NULL DEFAULT ''`},
		{"fabric_endpoints", "group_id", `ALTER TABLE fabric_endpoints ADD COLUMN group_id TEXT NOT NULL DEFAULT ''`},
		{"fabric_endpoints", "binding_id", `ALTER TABLE fabric_endpoints ADD COLUMN binding_id TEXT NOT NULL DEFAULT ''`},
		{"fabric_endpoints", "migration_state", `ALTER TABLE fabric_endpoints ADD COLUMN migration_state TEXT NOT NULL DEFAULT 'MIGRATION_PENDING_GROUP'`},
	} {
		if err := s.ensureColumn(column.table, column.name, column.ddl); err != nil {
			return err
		}
	}

	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS principals (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  owner_id TEXT NOT NULL DEFAULT '',
  trust_domain_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  display_name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  credential_hash TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  owner_principal_id TEXT NOT NULL DEFAULT '',
  trust_domain_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'DRAFT',
  purpose TEXT NOT NULL DEFAULT '',
  revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
  policy_ref TEXT NOT NULL DEFAULT '',
  context_policy TEXT NOT NULL DEFAULT '',
  isolation_profile TEXT NOT NULL DEFAULT '',
  external_mode TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  roles_json TEXT NOT NULL DEFAULT '[]',
  grants_json TEXT NOT NULL DEFAULT '[]',
  authorization_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active',
  effective_at TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL DEFAULT '',
  revoked_at TEXT NOT NULL DEFAULT '',
  revocation_reason TEXT NOT NULL DEFAULT '',
  revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
  version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(principal_id) REFERENCES principals(id),
  FOREIGN KEY(group_id) REFERENCES groups(id),
  UNIQUE(principal_id, group_id)
);
CREATE TABLE IF NOT EXISTS session_bindings (
  id TEXT PRIMARY KEY,
  endpoint_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  native_session_id TEXT NOT NULL,
  node_id TEXT NOT NULL DEFAULT '',
  workspace_id TEXT NOT NULL DEFAULT '',
  epoch INTEGER NOT NULL DEFAULT 1 CHECK(epoch > 0),
  lease_owner TEXT NOT NULL DEFAULT '',
  lease_expires_at TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  credential_hash TEXT NOT NULL DEFAULT '',
  credential_hash_version INTEGER NOT NULL DEFAULT 1 CHECK(credential_hash_version > 0),
  version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
  mode TEXT NOT NULL DEFAULT '',
  context_continuity TEXT NOT NULL DEFAULT '',
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  replaces_binding_id TEXT NOT NULL DEFAULT '',
  revocation_reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(endpoint_id) REFERENCES fabric_endpoints(id),
  FOREIGN KEY(principal_id) REFERENCES principals(id),
  FOREIGN KEY(group_id) REFERENCES groups(id)
);
CREATE INDEX IF NOT EXISTS principals_status_idx ON principals(status, updated_at);
CREATE INDEX IF NOT EXISTS groups_state_idx ON groups(state, updated_at);
CREATE INDEX IF NOT EXISTS memberships_group_idx ON memberships(group_id, status, updated_at);
CREATE INDEX IF NOT EXISTS memberships_principal_idx ON memberships(principal_id, status, updated_at);
CREATE INDEX IF NOT EXISTS session_bindings_endpoint_idx ON session_bindings(endpoint_id, updated_at);
CREATE INDEX IF NOT EXISTS session_bindings_group_idx ON session_bindings(group_id, status, updated_at);
CREATE INDEX IF NOT EXISTS session_bindings_credential_idx ON session_bindings(credential_hash, status) WHERE credential_hash <> '';
CREATE INDEX IF NOT EXISTS fabric_endpoints_v2_scope_idx
ON fabric_endpoints(group_id, principal_id, migration_state, status, updated_at);
CREATE UNIQUE INDEX IF NOT EXISTS session_bindings_active_endpoint_idx
ON session_bindings(endpoint_id)
WHERE status IN ('active', 'leased', 'online', 'ready', 'acquired');
CREATE UNIQUE INDEX IF NOT EXISTS session_bindings_active_native_idx
ON session_bindings(native_session_id)
WHERE native_session_id <> '' AND status IN ('active', 'leased', 'online', 'ready', 'acquired');
`)
	if err != nil {
		return fmt.Errorf("initialize v2 identity schema: %w", err)
	}
	// Existing rows are intentionally left unassociated.  This update only
	// repairs empty markers; it never creates a Principal, Group, Membership,
	// or Binding and therefore cannot grant a guessed global authorization.
	if _, err := s.db.Exec(`UPDATE fabric_endpoints
SET migration_state = ?
WHERE migration_state = '' OR migration_state IS NULL`, EndpointMigrationPendingGroup); err != nil {
		return fmt.Errorf("mark legacy endpoints for explicit migration: %w", err)
	}
	return nil
}

type v2Scanner interface {
	Scan(...any) error
}

func scanPrincipal(row v2Scanner) (*Principal, error) {
	var principal Principal
	err := row.Scan(&principal.ID, &principal.Kind, &principal.OwnerID,
		&principal.TrustDomainID, &principal.Name, &principal.DisplayName,
		&principal.Status, &principal.CredentialHash, &principal.Version,
		&principal.CreatedAt, &principal.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &principal, nil
}

func scanGroup(row v2Scanner) (*Group, error) {
	var group Group
	err := row.Scan(&group.ID, &group.ParentGroupID, &group.OwnerPrincipalID, &group.TrustDomainID,
		&group.Name, &group.State, &group.Purpose, &group.Revision,
		&group.PolicyRef, &group.ContextPolicy, &group.IsolationProfile,
		&group.ExternalMode, &group.Version, &group.CreatedAt, &group.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &group, nil
}

func scanMembership(row v2Scanner) (*Membership, error) {
	var membership Membership
	var rolesJSON, grantsJSON, authorizationJSON string
	err := row.Scan(&membership.ID, &membership.PrincipalID, &membership.GroupID,
		&membership.Role, &rolesJSON, &grantsJSON, &authorizationJSON,
		&membership.Status, &membership.EffectiveAt, &membership.ExpiresAt,
		&membership.RevokedAt, &membership.RevocationReason, &membership.Revision,
		&membership.Version, &membership.CreatedAt, &membership.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(rolesJSON), &membership.Roles); err != nil {
		return nil, fmt.Errorf("decode membership roles: %w", err)
	}
	if err := json.Unmarshal([]byte(grantsJSON), &membership.Grants); err != nil {
		return nil, fmt.Errorf("decode membership grants: %w", err)
	}
	if err := json.Unmarshal([]byte(authorizationJSON), &membership.Authorization); err != nil {
		return nil, fmt.Errorf("decode membership authorization: %w", err)
	}
	if membership.Roles == nil {
		membership.Roles = []string{}
	}
	if membership.Grants == nil {
		membership.Grants = []string{}
	}
	if membership.Authorization == nil {
		membership.Authorization = map[string]any{}
	}
	return &membership, nil
}

func scanSessionBinding(row v2Scanner) (*SessionBinding, error) {
	var binding SessionBinding
	var capabilitiesJSON string
	err := row.Scan(&binding.ID, &binding.EndpointID, &binding.PrincipalID,
		&binding.GroupID, &binding.NativeSessionID, &binding.NodeID,
		&binding.WorkspaceID, &binding.Epoch, &binding.LeaseOwner,
		&binding.LeaseExpiresAt, &binding.Status, &binding.CredentialHash,
		&binding.CredentialHashVersion, &binding.Version, &binding.Mode,
		&binding.ContextContinuity, &capabilitiesJSON, &binding.ReplacesBindingID,
		&binding.RevocationReason, &binding.CreatedAt, &binding.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(capabilitiesJSON), &binding.Capabilities); err != nil {
		return nil, fmt.Errorf("decode session binding capabilities: %w", err)
	}
	if binding.Capabilities == nil {
		binding.Capabilities = map[string]any{}
	}
	binding.GroupContextID = binding.GroupID
	binding.Workspace = binding.WorkspaceID
	return &binding, nil
}

const principalColumns = `id, kind, owner_id, trust_domain_id, name, display_name,
status, credential_hash, version, created_at, updated_at`

const groupColumns = `id, parent_group_id, owner_principal_id, trust_domain_id, name, state,
purpose, revision, policy_ref, context_policy, isolation_profile, external_mode,
version, created_at, updated_at`

const membershipColumns = `id, principal_id, group_id, role, roles_json,
grants_json, authorization_json, status, effective_at, expires_at, revoked_at,
revocation_reason, revision, version, created_at, updated_at`

const sessionBindingColumns = `id, endpoint_id, principal_id, group_id,
native_session_id, node_id, workspace_id, epoch, lease_owner, lease_expires_at,
status, credential_hash, credential_hash_version, version, mode,
context_continuity, capabilities_json, replaces_binding_id, revocation_reason,
created_at, updated_at`

func (s *Store) UpsertPrincipal(principal Principal) (*Principal, error) {
	principal.ID = strings.TrimSpace(principal.ID)
	principal.Kind = strings.TrimSpace(principal.Kind)
	principal.OwnerID = strings.TrimSpace(principal.OwnerID)
	principal.TrustDomainID = strings.TrimSpace(principal.TrustDomainID)
	principal.Name = strings.TrimSpace(principal.Name)
	principal.DisplayName = strings.TrimSpace(principal.DisplayName)
	if principal.ID == "" {
		principal.ID = NewID("pr")
	}
	if principal.Kind == "" {
		principal.Kind = PrincipalKindAgent
	}
	if principal.Status == "" {
		principal.Status = PrincipalStatusActive
	}
	if principal.Name == "" && principal.DisplayName == "" {
		return nil, errors.New("principal name or display name is required")
	}
	if principal.Version <= 0 {
		principal.Version = 1
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO principals
(id, kind, owner_id, trust_domain_id, name, display_name, status,
 credential_hash, version, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
 kind=excluded.kind, owner_id=excluded.owner_id,
 trust_domain_id=excluded.trust_domain_id, name=excluded.name,
 display_name=excluded.display_name, status=excluded.status,
 credential_hash=CASE WHEN excluded.credential_hash <> ''
   THEN excluded.credential_hash ELSE principals.credential_hash END,
 version=principals.version + 1, updated_at=excluded.updated_at`,
		principal.ID, principal.Kind, principal.OwnerID, principal.TrustDomainID,
		principal.Name, principal.DisplayName, principal.Status,
		principal.CredentialHash, principal.Version, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("upsert principal: %w", err)
	}
	return scanPrincipal(s.db.QueryRow(`SELECT `+principalColumns+` FROM principals WHERE id = ?`, principal.ID))
}

func (s *Store) CreatePrincipal(principal Principal) (*Principal, error) {
	return s.UpsertPrincipal(principal)
}

func (s *Store) GetPrincipal(id string) (*Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	principal, err := scanPrincipal(s.db.QueryRow(`SELECT `+principalColumns+` FROM principals WHERE id = ?`, strings.TrimSpace(id)))
	if err != nil {
		return nil, err
	}
	if principal == nil {
		return nil, ErrPrincipalNotFound
	}
	return principal, nil
}

func (s *Store) ListPrincipals(filter PrincipalFilter) ([]Principal, error) {
	limit := normalizeV2Limit(filter.Limit)
	query := `SELECT ` + principalColumns + ` FROM principals WHERE 1=1`
	args := make([]any, 0, 3)
	if kind := strings.TrimSpace(filter.Kind); kind != "" {
		query += ` AND kind = ?`
		args = append(args, kind)
	}
	if status := strings.TrimSpace(filter.Status); status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY updated_at DESC, id LIMIT ?`
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Principal, 0)
	for rows.Next() {
		principal, err := scanPrincipal(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *principal)
	}
	return result, rows.Err()
}

func (s *Store) RevokePrincipal(id, reason string) (*Principal, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrPrincipalNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	timestamp := now()
	if _, err := tx.Exec(`UPDATE principals SET status = ?, version = version + 1, updated_at = ? WHERE id = ?`, PrincipalStatusRevoked, timestamp, id); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE memberships SET status = ?, revoked_at = ?, revocation_reason = ?, revision = revision + 1, version = version + 1, updated_at = ? WHERE principal_id = ? AND status <> ?`, MembershipStatusRevoked, timestamp, reason, timestamp, id, MembershipStatusRevoked); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE session_bindings SET status = ?, lease_owner = '', lease_expires_at = '', epoch = epoch + 1, version = version + 1, revocation_reason = ?, updated_at = ? WHERE principal_id = ? AND status IN ('active', 'leased', 'online', 'ready', 'acquired')`, SessionBindingStatusRevoked, reason, timestamp, id); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	principal, err := scanPrincipal(s.db.QueryRow(`SELECT `+principalColumns+` FROM principals WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	if principal == nil {
		return nil, ErrPrincipalNotFound
	}
	return principal, nil
}

func (s *Store) UpsertGroup(group Group) (*Group, error) {
	group.ID = strings.TrimSpace(group.ID)
	if strings.TrimSpace(group.ParentGroupID) != "" {
		return nil, errors.New("group parent must be set through versioned SetGroupParent")
	}
	group.OwnerPrincipalID = strings.TrimSpace(group.OwnerPrincipalID)
	group.TrustDomainID = strings.TrimSpace(group.TrustDomainID)
	group.Name = strings.TrimSpace(group.Name)
	if group.ID == "" {
		group.ID = NewID("grp")
	}
	if group.Name == "" {
		return nil, errors.New("group name is required")
	}
	if group.State == "" {
		group.State = GroupStateActive
	}
	if group.Revision <= 0 {
		group.Revision = 1
	}
	if group.Version <= 0 {
		group.Version = 1
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO groups
(id, owner_principal_id, trust_domain_id, name, state, purpose, revision,
 policy_ref, context_policy, isolation_profile, external_mode, version,
 created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET owner_principal_id=excluded.owner_principal_id,
 trust_domain_id=excluded.trust_domain_id, name=excluded.name,
 state=excluded.state, purpose=excluded.purpose, revision=excluded.revision,
 policy_ref=excluded.policy_ref, context_policy=excluded.context_policy,
 isolation_profile=excluded.isolation_profile, external_mode=excluded.external_mode,
 version=groups.version + 1, updated_at=excluded.updated_at`,
		group.ID, group.OwnerPrincipalID, group.TrustDomainID, group.Name,
		group.State, group.Purpose, group.Revision, group.PolicyRef,
		group.ContextPolicy, group.IsolationProfile, group.ExternalMode,
		group.Version, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("upsert group: %w", err)
	}
	return scanGroup(s.db.QueryRow(`SELECT `+groupColumns+` FROM groups WHERE id = ?`, group.ID))
}

func (s *Store) CreateGroup(group Group) (*Group, error) {
	return s.UpsertGroup(group)
}

func (s *Store) GetGroup(id string) (*Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, err := scanGroup(s.db.QueryRow(`SELECT `+groupColumns+` FROM groups WHERE id = ?`, strings.TrimSpace(id)))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, ErrGroupNotFound
	}
	return group, nil
}

func (s *Store) ListGroups(filter GroupFilter) ([]Group, error) {
	limit := normalizeV2Limit(filter.Limit)
	query := `SELECT ` + groupColumns + ` FROM groups WHERE 1=1`
	args := make([]any, 0, 3)
	if state := strings.TrimSpace(filter.State); state != "" {
		query += ` AND state = ?`
		args = append(args, state)
	}
	if owner := strings.TrimSpace(filter.Owner); owner != "" {
		query += ` AND owner_principal_id = ?`
		args = append(args, owner)
	}
	query += ` ORDER BY updated_at DESC, id LIMIT ?`
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Group, 0)
	for rows.Next() {
		group, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *group)
	}
	return result, rows.Err()
}

func normalizeMembership(membership Membership) (Membership, string, string, string, error) {
	membership.PrincipalID = strings.TrimSpace(membership.PrincipalID)
	membership.GroupID = strings.TrimSpace(membership.GroupID)
	membership.Role = strings.TrimSpace(membership.Role)
	if membership.ID == "" {
		membership.ID = NewID("mem")
	}
	if membership.PrincipalID == "" || membership.GroupID == "" {
		return membership, "", "", "", errors.New("membership principal and group are required")
	}
	if membership.Role == "" && len(membership.Roles) > 0 {
		membership.Role = strings.TrimSpace(membership.Roles[0])
	}
	if membership.Role == "" {
		membership.Role = "member"
	}
	if len(membership.Roles) == 0 {
		membership.Roles = []string{membership.Role}
	}
	if membership.Grants == nil {
		membership.Grants = []string{}
	}
	if membership.Authorization == nil {
		membership.Authorization = map[string]any{}
	}
	if membership.Status == "" {
		membership.Status = MembershipStatusActive
	}
	if membership.EffectiveAt == "" {
		membership.EffectiveAt = now()
	}
	if membership.Revision <= 0 {
		membership.Revision = 1
	}
	if membership.Version <= 0 {
		membership.Version = 1
	}
	rolesJSON, err := json.Marshal(membership.Roles)
	if err != nil {
		return membership, "", "", "", err
	}
	grantsJSON, err := json.Marshal(membership.Grants)
	if err != nil {
		return membership, "", "", "", err
	}
	authorizationJSON, err := json.Marshal(membership.Authorization)
	if err != nil {
		return membership, "", "", "", err
	}
	return membership, string(rolesJSON), string(grantsJSON), string(authorizationJSON), nil
}

func (s *Store) UpsertMembership(membership Membership) (*Membership, error) {
	membership, rolesJSON, grantsJSON, authorizationJSON, err := normalizeMembership(membership)
	if err != nil {
		return nil, err
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var principalStatus, groupState string
	if err := s.db.QueryRow(`SELECT p.status, g.state FROM principals p CROSS JOIN groups g WHERE p.id = ? AND g.id = ?`, membership.PrincipalID, membership.GroupID).Scan(&principalStatus, &groupState); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMembershipNotActive
	} else if err != nil {
		return nil, err
	}
	if principalStatus != PrincipalStatusActive || groupState == GroupStateArchived {
		return nil, ErrMembershipNotActive
	}
	_, err = s.db.Exec(`INSERT INTO memberships
(id, principal_id, group_id, role, roles_json, grants_json, authorization_json,
 status, effective_at, expires_at, revoked_at, revocation_reason, revision,
 version, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(principal_id, group_id) DO UPDATE SET
 role=excluded.role, roles_json=excluded.roles_json, grants_json=excluded.grants_json,
 authorization_json=excluded.authorization_json, status=excluded.status,
 effective_at=excluded.effective_at, expires_at=excluded.expires_at,
 revoked_at=CASE WHEN excluded.status = 'active' THEN '' ELSE excluded.revoked_at END,
 revocation_reason=CASE WHEN excluded.status = 'active' THEN '' ELSE excluded.revocation_reason END,
 revision=memberships.revision + 1, version=memberships.version + 1,
 updated_at=excluded.updated_at`, membership.ID, membership.PrincipalID,
		membership.GroupID, membership.Role, rolesJSON, grantsJSON,
		authorizationJSON, membership.Status, membership.EffectiveAt,
		membership.ExpiresAt, membership.RevokedAt, membership.RevocationReason,
		membership.Revision, membership.Version, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("upsert membership: %w", err)
	}
	return scanMembership(s.db.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE principal_id = ? AND group_id = ?`, membership.PrincipalID, membership.GroupID))
}

func (s *Store) CreateMembership(membership Membership) (*Membership, error) {
	return s.UpsertMembership(membership)
}

func (s *Store) GetMembership(id string) (*Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	membership, err := scanMembership(s.db.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE id = ?`, strings.TrimSpace(id)))
	if err != nil {
		return nil, err
	}
	if membership == nil {
		return nil, ErrMembershipNotFound
	}
	return membership, nil
}

func (s *Store) GetMembershipByPrincipalGroup(principalID, groupID string) (*Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	membership, err := scanMembership(s.db.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE principal_id = ? AND group_id = ?`, strings.TrimSpace(principalID), strings.TrimSpace(groupID)))
	if err != nil {
		return nil, err
	}
	if membership == nil {
		return nil, ErrMembershipNotFound
	}
	return membership, nil
}

func (s *Store) IsMembershipActive(principalID, groupID string) (bool, error) {
	membership, err := s.GetMembershipByPrincipalGroup(principalID, groupID)
	if errors.Is(err, ErrMembershipNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if membership.Status != MembershipStatusActive {
		return false, nil
	}
	if membership.ExpiresAt != "" && membership.ExpiresAt <= now() {
		return false, nil
	}
	return true, nil
}

// MembershipAllows is a small read-side authorization helper.  Roles do not
// imply grants; only an explicit grant or an authorization entry can satisfy
// the requested action.
func (s *Store) MembershipAllows(principalID, groupID, grant string) (bool, error) {
	membership, err := s.GetMembershipByPrincipalGroup(principalID, groupID)
	if errors.Is(err, ErrMembershipNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if membership.Status != MembershipStatusActive || (membership.ExpiresAt != "" && membership.ExpiresAt <= now()) {
		return false, nil
	}
	grant = strings.TrimSpace(grant)
	for _, candidate := range membership.Grants {
		if candidate == grant {
			return true, nil
		}
	}
	if value, ok := membership.Authorization[grant]; ok {
		if allowed, ok := value.(bool); ok {
			return allowed, nil
		}
	}
	return false, nil
}

func (s *Store) ListMemberships(filter MembershipFilter) ([]Membership, error) {
	limit := normalizeV2Limit(filter.Limit)
	query := `SELECT ` + membershipColumns + ` FROM memberships WHERE 1=1`
	args := make([]any, 0, 5)
	for _, item := range []struct{ value, column string }{
		{filter.PrincipalID, "principal_id"}, {filter.GroupID, "group_id"},
		{filter.Status, "status"}, {filter.Role, "role"},
	} {
		if value := strings.TrimSpace(item.value); value != "" {
			query += ` AND ` + item.column + ` = ?`
			args = append(args, value)
		}
	}
	query += ` ORDER BY updated_at DESC, id LIMIT ?`
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Membership, 0)
	for rows.Next() {
		membership, err := scanMembership(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *membership)
	}
	return result, rows.Err()
}

func (s *Store) RevokeMembership(id, reason string) (*Membership, error) {
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	timestamp := now()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	var principalID, groupID, status string
	if err := tx.QueryRow(`SELECT principal_id, group_id, status FROM memberships WHERE id = ?`, id).Scan(&principalID, &groupID, &status); errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		return nil, ErrMembershipNotFound
	} else if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if status != MembershipStatusRevoked {
		if _, err := tx.Exec(`UPDATE memberships SET status = ?, revoked_at = ?, revocation_reason = ?, revision = revision + 1, version = version + 1, updated_at = ? WHERE id = ?`, MembershipStatusRevoked, timestamp, reason, timestamp, id); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	if _, err := tx.Exec(`UPDATE endpoint_group_memberships SET status = 'revoked', revision = revision + 1, updated_at = ?
WHERE group_id = ? AND status = 'active' AND endpoint_id IN
  (SELECT id FROM fabric_endpoints WHERE principal_id = ?)`, timestamp, groupID, principalID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	// The native binding can serve several independently authorized Groups.
	// Fence it only when no active Endpoint+Principal Group membership remains.
	// The Group scope itself is denied by the relation/membership checks in the
	// same committed transaction, including during Relay claim and delivery.
	if _, err := tx.Exec(`UPDATE session_bindings
SET status = ?, lease_owner = '', lease_expires_at = '', epoch = epoch + 1,
    version = version + 1, revocation_reason = ?, updated_at = ?
WHERE principal_id = ?
  AND status IN ('active', 'leased', 'online', 'ready', 'acquired')
  AND NOT EXISTS (
    SELECT 1 FROM endpoint_group_memberships eg
    JOIN memberships active_m ON active_m.principal_id = session_bindings.principal_id
      AND active_m.group_id = eg.group_id
    JOIN groups active_g ON active_g.id = eg.group_id
    WHERE eg.endpoint_id = session_bindings.endpoint_id AND eg.status = 'active'
      AND active_m.status = 'active' AND active_g.state = 'ACTIVE'
      AND (active_m.expires_at = '' OR active_m.expires_at > ?)
  )`, SessionBindingStatusRevoked, reason, timestamp, principalID, timestamp); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return scanMembership(s.db.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE id = ?`, id))
}

func (s *Store) RevokeMembershipForPrincipalGroup(principalID, groupID, reason string) (*Membership, error) {
	membership, err := s.GetMembershipByPrincipalGroup(principalID, groupID)
	if err != nil {
		return nil, err
	}
	return s.RevokeMembership(membership.ID, reason)
}

func (s *Store) RestoreMembership(id string) (*Membership, error) {
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	timestamp := now()
	result, err := s.db.Exec(`UPDATE memberships SET status = ?, revoked_at = '', revocation_reason = '', effective_at = CASE WHEN effective_at = '' THEN ? ELSE effective_at END, revision = revision + 1, version = version + 1, updated_at = ? WHERE id = ?`, MembershipStatusActive, timestamp, timestamp, id)
	if err != nil {
		return nil, err
	}
	if count, err := result.RowsAffected(); err != nil {
		return nil, err
	} else if count == 0 {
		return nil, ErrMembershipNotFound
	}
	return scanMembership(s.db.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE id = ?`, id))
}

func (s *Store) UpdateMembershipAuthorization(id string, roles, grants []string, authorization map[string]any, expectedVersion int64) (*Membership, error) {
	if roles == nil {
		roles = []string{}
	}
	if grants == nil {
		grants = []string{}
	}
	if authorization == nil {
		authorization = map[string]any{}
	}
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return nil, err
	}
	grantsJSON, err := json.Marshal(grants)
	if err != nil {
		return nil, err
	}
	authorizationJSON, err := json.Marshal(authorization)
	if err != nil {
		return nil, err
	}
	role := "member"
	if len(roles) > 0 && strings.TrimSpace(roles[0]) != "" {
		role = strings.TrimSpace(roles[0])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `UPDATE memberships SET role = ?, roles_json = ?, grants_json = ?, authorization_json = ?, revision = revision + 1, version = version + 1, updated_at = ? WHERE id = ?`
	args := []any{role, string(rolesJSON), string(grantsJSON), string(authorizationJSON), now(), id}
	if expectedVersion > 0 {
		query += ` AND version = ?`
		args = append(args, expectedVersion)
	}
	result, err := s.db.Exec(query, args...)
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		membership, getErr := scanMembership(s.db.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE id = ?`, id))
		if getErr != nil {
			return nil, getErr
		}
		if membership == nil {
			return nil, ErrMembershipNotFound
		}
		return nil, ErrVersionConflict
	}
	return scanMembership(s.db.QueryRow(`SELECT `+membershipColumns+` FROM memberships WHERE id = ?`, id))
}

func (s *Store) getEndpointV2Locked(id string) (*Endpoint, error) {
	endpoint, err := s.getEndpointLocked(strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	if endpoint == nil {
		return nil, ErrEndpointNotFound
	}
	err = s.db.QueryRow(`SELECT principal_id, group_id, binding_id, migration_state FROM fabric_endpoints WHERE id = ?`, id).Scan(&endpoint.PrincipalID, &endpoint.GroupID, &endpoint.BindingID, &endpoint.MigrationState)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEndpointNotFound
	}
	if err != nil {
		return nil, err
	}
	endpoint.MigrationStatus = endpoint.MigrationState
	return endpoint, nil
}

// GetEndpointV2 reads the old Endpoint fields plus additive identity and
// migration associations.  GetEndpoint remains untouched for legacy callers.
func (s *Store) GetEndpointV2(id string) (*Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getEndpointV2Locked(id)
}

func (s *Store) GetEndpointWithIdentity(id string) (*Endpoint, error) {
	return s.GetEndpointV2(id)
}

// UpsertEndpointV2 keeps the legacy Endpoint writer as the source of stable
// ID/native-session data, then applies an explicit v2 identity association.
// An endpoint without PrincipalID/GroupID remains MIGRATION_PENDING_GROUP.
func (s *Store) UpsertEndpointV2(endpoint Endpoint) (*Endpoint, error) {
	base, err := s.UpsertEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(endpoint.PrincipalID) == "" || strings.TrimSpace(endpoint.GroupID) == "" {
		return s.GetEndpointV2(base.ID)
	}
	return s.AssociateEndpoint(base.ID, endpoint.PrincipalID, endpoint.GroupID, endpoint.BindingID)
}

func (s *Store) CreateEndpointV2(endpoint Endpoint) (*Endpoint, error) {
	return s.UpsertEndpointV2(endpoint)
}

// ListEndpointsV2 applies the v2 scope predicates in the database.  An empty
// MigrationState intentionally does not imply READY: callers that need only
// explicitly migrated rows pass EndpointMigrationReady, while migration and
// audit callers can request EndpointMigrationPendingGroup.
func (s *Store) ListEndpointsV2(filter EndpointV2Filter) ([]Endpoint, error) {
	limit := normalizeV2Limit(filter.Limit)
	query := `SELECT id FROM fabric_endpoints WHERE 1=1`
	args := make([]any, 0, 8)
	if groupID := strings.TrimSpace(filter.GroupID); groupID != "" {
		query += ` AND EXISTS (
SELECT 1 FROM endpoint_group_memberships eg
JOIN memberships m ON m.principal_id = fabric_endpoints.principal_id AND m.group_id = eg.group_id
JOIN principals p ON p.id = fabric_endpoints.principal_id
JOIN groups g ON g.id = eg.group_id
WHERE eg.endpoint_id = fabric_endpoints.id AND eg.group_id = ? AND eg.status = 'active'
  AND m.status = 'active' AND p.status = 'active' AND g.state = 'ACTIVE'
  AND (m.expires_at = '' OR m.expires_at > ?))`
		args = append(args, groupID, now())
	}
	if ownerID := strings.TrimSpace(filter.OwnerID); ownerID != "" {
		query += ` AND EXISTS (SELECT 1 FROM principals p
WHERE p.id = fabric_endpoints.principal_id AND p.owner_id = ? AND p.status = 'active')`
		args = append(args, ownerID)
	}
	for _, item := range []struct{ value, column string }{
		{filter.PrincipalID, "principal_id"},
		{filter.Status, "status"}, {filter.NodeID, "machine_id"},
		{filter.Harness, "harness"}, {filter.MigrationState, "migration_state"},
	} {
		if value := strings.TrimSpace(item.value); value != "" {
			query += ` AND ` + item.column + ` = ?`
			args = append(args, value)
		}
	}
	query += ` ORDER BY updated_at DESC, id LIMIT ?`
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]Endpoint, 0, len(ids))
	for _, id := range ids {
		endpoint, err := s.getEndpointV2Locked(id)
		if err != nil {
			return nil, err
		}
		result = append(result, *endpoint)
	}
	return result, nil
}

func (s *Store) AssociateEndpoint(endpointID, principalID, groupID, bindingID string) (*Endpoint, error) {
	endpointID = strings.TrimSpace(endpointID)
	principalID = strings.TrimSpace(principalID)
	groupID = strings.TrimSpace(groupID)
	bindingID = strings.TrimSpace(bindingID)
	if endpointID == "" || principalID == "" || groupID == "" {
		return nil, errors.New("endpoint, principal, and group are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(cause error) (*Endpoint, error) {
		_ = tx.Rollback()
		return nil, cause
	}
	var previousPrincipal, previousGroup, previousState string
	if err := tx.QueryRow(`SELECT principal_id, group_id, migration_state FROM fabric_endpoints WHERE id = ?`, endpointID).
		Scan(&previousPrincipal, &previousGroup, &previousState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrEndpointNotFound)
		}
		return rollback(err)
	}
	if previousState == EndpointMigrationReady &&
		(previousPrincipal != principalID || previousGroup != groupID) {
		return rollback(ErrSessionBindingConflict)
	}
	if err := s.requireActiveMembershipTx(tx, principalID, groupID); err != nil {
		return rollback(err)
	}
	if bindingID != "" {
		var bindingEndpoint, bindingPrincipal, bindingGroup, bindingStatus string
		err := tx.QueryRow(`SELECT endpoint_id, principal_id, group_id, status FROM session_bindings WHERE id = ?`, bindingID).Scan(&bindingEndpoint, &bindingPrincipal, &bindingGroup, &bindingStatus)
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrSessionBindingNotFound)
		}
		if err != nil {
			return rollback(err)
		}
		if bindingEndpoint != endpointID {
			return rollback(errors.New("session binding belongs to another endpoint"))
		}
		if bindingPrincipal != principalID || bindingGroup != groupID {
			return rollback(errors.New("session binding identity does not match endpoint association"))
		}
		if !isActiveBindingStatus(bindingStatus) {
			return rollback(ErrSessionBindingInactive)
		}
	}
	result, err := tx.Exec(`UPDATE fabric_endpoints SET principal_id = ?, group_id = ?, binding_id = ?, migration_state = ?, updated_at = ? WHERE id = ?`, principalID, groupID, bindingID, EndpointMigrationReady, now(), endpointID)
	if err != nil {
		return rollback(err)
	}
	if count, err := result.RowsAffected(); err != nil {
		return rollback(err)
	} else if count == 0 {
		return rollback(ErrEndpointNotFound)
	}
	if err := upsertEndpointGroupMembershipTx(tx, endpointID, groupID); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getEndpointV2Locked(endpointID)
}

func (s *Store) ExplicitlyMigrateEndpoint(endpointID, principalID, groupID, bindingID string) (*Endpoint, error) {
	return s.AssociateEndpoint(endpointID, principalID, groupID, bindingID)
}

func (s *Store) MigrateEndpoint(endpointID, principalID, groupID, bindingID string) (*Endpoint, error) {
	return s.AssociateEndpoint(endpointID, principalID, groupID, bindingID)
}

func (s *Store) ListPendingEndpointMigrations(limit int) ([]Endpoint, error) {
	limit = normalizeV2Limit(limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id FROM fabric_endpoints WHERE migration_state = ? ORDER BY updated_at, id LIMIT ?`, EndpointMigrationPendingGroup, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]Endpoint, 0, len(ids))
	for _, id := range ids {
		endpoint, err := s.getEndpointV2Locked(id)
		if err != nil {
			return nil, err
		}
		result = append(result, *endpoint)
	}
	return result, nil
}

func (s *Store) MarkEndpointMigrationPending(endpointID string) (*Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	endpointID = strings.TrimSpace(endpointID)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	var bindingID string
	if err := tx.QueryRow(`SELECT binding_id FROM fabric_endpoints WHERE id = ?`, endpointID).Scan(&bindingID); errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		return nil, ErrEndpointNotFound
	} else if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if bindingID != "" {
		if _, err := tx.Exec(`UPDATE session_bindings SET status = ?, lease_owner = '', lease_expires_at = '', epoch = epoch + 1, version = version + 1, updated_at = ? WHERE id = ? AND status IN ('active', 'leased', 'online', 'ready', 'acquired')`, SessionBindingStatusSuperseded, now(), bindingID); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	if _, err := tx.Exec(`UPDATE fabric_endpoints SET principal_id = '', group_id = '', binding_id = '', migration_state = ?, updated_at = ? WHERE id = ?`, EndpointMigrationPendingGroup, now(), endpointID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE endpoint_group_memberships SET status = 'revoked', revision = revision + 1, updated_at = ? WHERE endpoint_id = ? AND status = 'active'`, now(), endpointID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getEndpointV2Locked(endpointID)
}

func (s *Store) requireActiveMembershipLocked(principalID, groupID string) error {
	var status, expiresAt, principalStatus, groupState string
	err := s.db.QueryRow(`SELECT m.status, m.expires_at, p.status, g.state
FROM memberships m JOIN principals p ON p.id = m.principal_id
JOIN groups g ON g.id = m.group_id
WHERE m.principal_id = ? AND m.group_id = ?`, principalID, groupID).Scan(&status, &expiresAt, &principalStatus, &groupState)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMembershipNotActive
	}
	if err != nil {
		return err
	}
	if status != MembershipStatusActive || principalStatus != PrincipalStatusActive || groupState != GroupStateActive || (expiresAt != "" && expiresAt <= now()) {
		return ErrMembershipNotActive
	}
	return nil
}

func (s *Store) requireActiveMembershipTx(tx *sql.Tx, principalID, groupID string) error {
	var status, expiresAt, principalStatus, groupState string
	err := tx.QueryRow(`SELECT m.status, m.expires_at, p.status, g.state
FROM memberships m JOIN principals p ON p.id = m.principal_id
JOIN groups g ON g.id = m.group_id
WHERE m.principal_id = ? AND m.group_id = ?`, principalID, groupID).Scan(&status, &expiresAt, &principalStatus, &groupState)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMembershipNotActive
	}
	if err != nil {
		return err
	}
	if status != MembershipStatusActive || principalStatus != PrincipalStatusActive || groupState != GroupStateActive || (expiresAt != "" && expiresAt <= now()) {
		return ErrMembershipNotActive
	}
	return nil
}

func normalizeBinding(binding SessionBinding) (SessionBinding, string, error) {
	binding.ID = strings.TrimSpace(binding.ID)
	binding.EndpointID = strings.TrimSpace(binding.EndpointID)
	binding.PrincipalID = strings.TrimSpace(binding.PrincipalID)
	binding.GroupID = strings.TrimSpace(binding.GroupID)
	if binding.GroupID == "" {
		binding.GroupID = strings.TrimSpace(binding.GroupContextID)
	}
	binding.GroupContextID = binding.GroupID
	binding.NativeSessionID = strings.TrimSpace(binding.NativeSessionID)
	binding.NodeID = strings.TrimSpace(binding.NodeID)
	binding.WorkspaceID = strings.TrimSpace(binding.WorkspaceID)
	if binding.WorkspaceID == "" {
		binding.WorkspaceID = strings.TrimSpace(binding.Workspace)
	}
	binding.Workspace = binding.WorkspaceID
	binding.LeaseOwner = strings.TrimSpace(binding.LeaseOwner)
	binding.LeaseExpiresAt = strings.TrimSpace(binding.LeaseExpiresAt)
	binding.Status = strings.TrimSpace(binding.Status)
	switch strings.ToLower(binding.Status) {
	case SessionBindingStatusPending:
		binding.Status = SessionBindingStatusPending
	case SessionBindingStatusActive:
		binding.Status = SessionBindingStatusActive
	case SessionBindingStatusLeased:
		binding.Status = SessionBindingStatusLeased
	case SessionBindingStatusReleased:
		binding.Status = SessionBindingStatusReleased
	case SessionBindingStatusExpired:
		binding.Status = SessionBindingStatusExpired
	case SessionBindingStatusRevoked:
		binding.Status = SessionBindingStatusRevoked
	case SessionBindingStatusSuperseded:
		binding.Status = SessionBindingStatusSuperseded
	}
	binding.CredentialHash = strings.TrimSpace(binding.CredentialHash)
	binding.Mode = strings.TrimSpace(binding.Mode)
	binding.ContextContinuity = strings.TrimSpace(binding.ContextContinuity)
	binding.ReplacesBindingID = strings.TrimSpace(binding.ReplacesBindingID)
	if binding.ID == "" {
		binding.ID = NewID("bind")
	}
	if binding.EndpointID == "" || binding.NativeSessionID == "" {
		return binding, "", errors.New("session binding endpoint and native session are required")
	}
	if binding.Status == "" {
		if binding.PrincipalID == "" || binding.GroupID == "" {
			binding.Status = SessionBindingStatusPending
		} else {
			binding.Status = SessionBindingStatusActive
		}
	}
	if binding.Epoch == 0 {
		binding.Epoch = 1
	}
	if binding.CredentialHashVersion <= 0 {
		binding.CredentialHashVersion = 1
	}
	if binding.Version <= 0 {
		binding.Version = 1
	}
	if binding.Capabilities == nil {
		binding.Capabilities = map[string]any{}
	}
	capabilitiesJSON, err := json.Marshal(binding.Capabilities)
	if err != nil {
		return binding, "", err
	}
	return binding, string(capabilitiesJSON), nil
}

func (s *Store) CreateSessionBinding(binding SessionBinding) (*SessionBinding, error) {
	var capabilitiesJSON string
	var err error
	binding, capabilitiesJSON, err = normalizeBinding(binding)
	if err != nil {
		return nil, err
	}
	if binding.PrincipalID == "" || binding.GroupID == "" {
		return nil, errors.New("session binding principal and group are required")
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(e error) (*SessionBinding, error) {
		_ = tx.Rollback()
		return nil, e
	}
	var endpointNative string
	err = tx.QueryRow(`SELECT native_session_id FROM fabric_endpoints WHERE id = ?`, binding.EndpointID).Scan(&endpointNative)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrEndpointNotFound)
	}
	if err != nil {
		return rollback(err)
	}
	if endpointNative != "" && endpointNative != binding.NativeSessionID {
		return rollback(errors.New("session binding native session does not match endpoint"))
	}
	if binding.Status != SessionBindingStatusPending {
		if err := s.requireActiveMembershipTx(tx, binding.PrincipalID, binding.GroupID); err != nil {
			return rollback(err)
		}
	}
	// Repeated Join/Adopt of the same verified session is idempotent.  A
	// different identity cannot take over the active binding through an insert.
	var existing SessionBinding
	var existingCapabilities string
	err = tx.QueryRow(`SELECT `+sessionBindingColumns+` FROM session_bindings WHERE endpoint_id = ? AND native_session_id = ? AND status IN ('active', 'leased', 'online', 'ready', 'acquired') LIMIT 1`, binding.EndpointID, binding.NativeSessionID).Scan(
		&existing.ID, &existing.EndpointID, &existing.PrincipalID, &existing.GroupID,
		&existing.NativeSessionID, &existing.NodeID, &existing.WorkspaceID,
		&existing.Epoch, &existing.LeaseOwner, &existing.LeaseExpiresAt,
		&existing.Status, &existing.CredentialHash, &existing.CredentialHashVersion,
		&existing.Version, &existing.Mode, &existing.ContextContinuity,
		&existingCapabilities, &existing.ReplacesBindingID, &existing.RevocationReason,
		&existing.CreatedAt, &existing.UpdatedAt)
	if err == nil {
		if existing.PrincipalID != binding.PrincipalID || existing.GroupID != binding.GroupID {
			return rollback(ErrSessionBindingConflict)
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return s.getSessionBindingLocked(existing.ID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return rollback(err)
	}
	if _, err := tx.Exec(`INSERT INTO session_bindings
(id, endpoint_id, principal_id, group_id, native_session_id, node_id,
 workspace_id, epoch, lease_owner, lease_expires_at, status, credential_hash,
 credential_hash_version, version, mode, context_continuity, capabilities_json,
 replaces_binding_id, revocation_reason, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		binding.ID, binding.EndpointID, binding.PrincipalID, binding.GroupID,
		binding.NativeSessionID, binding.NodeID, binding.WorkspaceID, binding.Epoch,
		binding.LeaseOwner, binding.LeaseExpiresAt, binding.Status,
		binding.CredentialHash, binding.CredentialHashVersion, binding.Version,
		binding.Mode, binding.ContextContinuity, capabilitiesJSON,
		binding.ReplacesBindingID, binding.RevocationReason, timestamp, timestamp); err != nil {
		if isSQLiteConstraint(err) {
			return rollback(ErrSessionBindingConflict)
		}
		return rollback(fmt.Errorf("create session binding: %w", err))
	}
	if binding.Status != SessionBindingStatusPending {
		if _, err := tx.Exec(`UPDATE fabric_endpoints SET principal_id = ?, group_id = ?, binding_id = ?, migration_state = ?, updated_at = ? WHERE id = ?`, binding.PrincipalID, binding.GroupID, binding.ID, EndpointMigrationReady, timestamp, binding.EndpointID); err != nil {
			return rollback(err)
		}
		if err := upsertEndpointGroupMembershipTx(tx, binding.EndpointID, binding.GroupID); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getSessionBindingLocked(binding.ID)
}

func (s *Store) UpsertSessionBinding(binding SessionBinding) (*SessionBinding, error) {
	return s.CreateSessionBinding(binding)
}

func (s *Store) BindSession(binding SessionBinding) (*SessionBinding, error) {
	return s.CreateSessionBinding(binding)
}

func (s *Store) getSessionBindingLocked(id string) (*SessionBinding, error) {
	binding, err := scanSessionBinding(s.db.QueryRow(`SELECT `+sessionBindingColumns+` FROM session_bindings WHERE id = ?`, strings.TrimSpace(id)))
	if err != nil {
		return nil, err
	}
	if binding == nil {
		return nil, ErrSessionBindingNotFound
	}
	return binding, nil
}

func (s *Store) GetSessionBinding(id string) (*SessionBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getSessionBindingLocked(id)
}

func (s *Store) GetBinding(id string) (*SessionBinding, error) {
	return s.GetSessionBinding(id)
}

func (s *Store) GetSessionBindingForEndpoint(endpointID string) (*SessionBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := scanSessionBinding(s.db.QueryRow(`SELECT `+sessionBindingColumns+` FROM session_bindings WHERE endpoint_id = ? ORDER BY CASE WHEN status IN ('active', 'leased', 'online', 'ready', 'acquired') THEN 0 ELSE 1 END, updated_at DESC LIMIT 1`, strings.TrimSpace(endpointID)))
	if err != nil {
		return nil, err
	}
	if binding == nil {
		return nil, ErrSessionBindingNotFound
	}
	return binding, nil
}

func (s *Store) GetActiveSessionBinding(endpointID string) (*SessionBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := scanSessionBinding(s.db.QueryRow(`SELECT `+sessionBindingColumns+` FROM session_bindings WHERE endpoint_id = ? AND status IN ('active', 'leased', 'online', 'ready', 'acquired') ORDER BY epoch DESC LIMIT 1`, strings.TrimSpace(endpointID)))
	if err != nil {
		return nil, err
	}
	if binding == nil {
		return nil, ErrSessionBindingNotFound
	}
	return binding, nil
}

func (s *Store) GetSessionBindingByNativeSession(nativeSessionID string) (*SessionBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := scanSessionBinding(s.db.QueryRow(`SELECT `+sessionBindingColumns+` FROM session_bindings WHERE native_session_id = ? ORDER BY CASE WHEN status IN ('active', 'leased', 'online', 'ready', 'acquired') THEN 0 ELSE 1 END, updated_at DESC LIMIT 1`, strings.TrimSpace(nativeSessionID)))
	if err != nil {
		return nil, err
	}
	if binding == nil {
		return nil, ErrSessionBindingNotFound
	}
	return binding, nil
}

func (s *Store) GetSessionBindingByCredentialHash(credentialHash string) (*SessionBinding, error) {
	credentialHash = strings.TrimSpace(credentialHash)
	if credentialHash == "" {
		return nil, ErrSessionBindingNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := scanSessionBinding(s.db.QueryRow(`SELECT `+sessionBindingColumns+` FROM session_bindings WHERE credential_hash = ? AND status IN ('active', 'leased', 'online', 'ready', 'acquired') ORDER BY updated_at DESC LIMIT 1`, credentialHash))
	if err != nil {
		return nil, err
	}
	if binding == nil {
		return nil, ErrSessionBindingNotFound
	}
	return binding, nil
}

func (s *Store) LookupSessionBindingByCredentialHash(credentialHash string) (*SessionBinding, error) {
	return s.GetSessionBindingByCredentialHash(credentialHash)
}

func (s *Store) ListSessionBindings(filter SessionBindingFilter) ([]SessionBinding, error) {
	limit := normalizeV2Limit(filter.Limit)
	query := `SELECT ` + sessionBindingColumns + ` FROM session_bindings WHERE 1=1`
	args := make([]any, 0, 6)
	for _, item := range []struct{ value, column string }{
		{filter.EndpointID, "endpoint_id"}, {filter.PrincipalID, "principal_id"},
		{filter.GroupID, "group_id"}, {filter.NodeID, "node_id"}, {filter.Status, "status"},
	} {
		if value := strings.TrimSpace(item.value); value != "" {
			query += ` AND ` + item.column + ` = ?`
			args = append(args, value)
		}
	}
	query += ` ORDER BY updated_at DESC, id LIMIT ?`
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]SessionBinding, 0)
	for rows.Next() {
		binding, err := scanSessionBinding(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *binding)
	}
	return result, rows.Err()
}

func (s *Store) AcquireSessionBindingLease(bindingID, leaseOwner string, expectedEpoch uint64, leaseExpiresAt string) (*SessionBinding, error) {
	bindingID = strings.TrimSpace(bindingID)
	leaseOwner = strings.TrimSpace(leaseOwner)
	leaseExpiresAt = strings.TrimSpace(leaseExpiresAt)
	if bindingID == "" || leaseOwner == "" || leaseExpiresAt == "" {
		return nil, errors.New("binding, lease owner, and lease expiry are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := s.getSessionBindingLocked(bindingID)
	if err != nil {
		return nil, err
	}
	if !isActiveBindingStatus(binding.Status) {
		return nil, ErrSessionBindingInactive
	}
	if binding.Epoch != expectedEpoch {
		return nil, ErrSessionBindingStaleEpoch
	}
	currentNow := now()
	if binding.LeaseOwner != "" && binding.LeaseOwner != leaseOwner && binding.LeaseExpiresAt > currentNow {
		return nil, ErrSessionBindingLeaseHeld
	}
	result, err := s.db.Exec(`UPDATE session_bindings SET lease_owner = ?, lease_expires_at = ?, status = ?, epoch = CASE WHEN lease_owner = ? THEN epoch ELSE epoch + 1 END, version = version + 1, updated_at = ? WHERE id = ? AND epoch = ? AND status IN ('active', 'leased', 'online', 'ready', 'acquired') AND (lease_owner = '' OR lease_owner = ? OR lease_expires_at <= ?)`, leaseOwner, leaseExpiresAt, SessionBindingStatusLeased, leaseOwner, currentNow, bindingID, expectedEpoch, leaseOwner, currentNow)
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, ErrSessionBindingStaleEpoch
	}
	return s.getSessionBindingLocked(bindingID)
}

// AcquireBindingLease is a short alias used by node implementations.
func (s *Store) AcquireBindingLease(bindingID, leaseOwner string, expectedEpoch uint64, leaseExpiresAt string) (*SessionBinding, error) {
	return s.AcquireSessionBindingLease(bindingID, leaseOwner, expectedEpoch, leaseExpiresAt)
}

func (s *Store) AcquireSessionBinding(bindingID, leaseOwner string, expectedEpoch uint64, leaseExpiresAt string) (*SessionBinding, error) {
	return s.AcquireSessionBindingLease(bindingID, leaseOwner, expectedEpoch, leaseExpiresAt)
}

// AcquireSessionBindingLeaseUntil keeps the expiry-before-epoch argument order
// used by a few older adapters while retaining the strict compare semantics.
func (s *Store) AcquireSessionBindingLeaseUntil(bindingID, leaseOwner, leaseExpiresAt string, expectedEpoch uint64) (*SessionBinding, error) {
	return s.AcquireSessionBindingLease(bindingID, leaseOwner, expectedEpoch, leaseExpiresAt)
}

func (s *Store) RenewSessionBindingLease(bindingID, leaseOwner string, expectedEpoch uint64, leaseExpiresAt string) (*SessionBinding, error) {
	bindingID = strings.TrimSpace(bindingID)
	leaseOwner = strings.TrimSpace(leaseOwner)
	leaseExpiresAt = strings.TrimSpace(leaseExpiresAt)
	if bindingID == "" || leaseOwner == "" || leaseExpiresAt == "" {
		return nil, errors.New("binding, lease owner, and lease expiry are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := s.getSessionBindingLocked(bindingID)
	if err != nil {
		return nil, err
	}
	if !isActiveBindingStatus(binding.Status) {
		return nil, ErrSessionBindingInactive
	}
	if binding.Epoch != expectedEpoch {
		return nil, ErrSessionBindingStaleEpoch
	}
	if binding.LeaseOwner != leaseOwner {
		return nil, ErrSessionBindingLeaseOwner
	}
	if binding.LeaseExpiresAt != "" && binding.LeaseExpiresAt <= now() {
		return nil, ErrSessionBindingLeaseExpired
	}
	result, err := s.db.Exec(`UPDATE session_bindings SET lease_expires_at = ?, status = ?, version = version + 1, updated_at = ? WHERE id = ? AND epoch = ? AND lease_owner = ? AND status IN ('active', 'leased', 'online', 'ready', 'acquired')`, leaseExpiresAt, SessionBindingStatusLeased, now(), bindingID, expectedEpoch, leaseOwner)
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, ErrSessionBindingStaleEpoch
	}
	return s.getSessionBindingLocked(bindingID)
}

func (s *Store) RenewBindingLease(bindingID, leaseOwner string, expectedEpoch uint64, leaseExpiresAt string) (*SessionBinding, error) {
	return s.RenewSessionBindingLease(bindingID, leaseOwner, expectedEpoch, leaseExpiresAt)
}

func (s *Store) RenewSessionBinding(bindingID, leaseOwner string, expectedEpoch uint64, leaseExpiresAt string) (*SessionBinding, error) {
	return s.RenewSessionBindingLease(bindingID, leaseOwner, expectedEpoch, leaseExpiresAt)
}

func (s *Store) RenewSessionBindingLeaseUntil(bindingID, leaseOwner, leaseExpiresAt string, expectedEpoch uint64) (*SessionBinding, error) {
	return s.RenewSessionBindingLease(bindingID, leaseOwner, expectedEpoch, leaseExpiresAt)
}

// RotateSessionBindingCredential atomically replaces the binding credential
// fingerprint and fences every adapter holding the previous epoch.  The
// endpoint/native session association is left untouched, while the new lease
// owner receives the next epoch.  Only a hash is accepted and persisted.
func (s *Store) RotateSessionBindingCredential(bindingID string, expectedEpoch uint64, newCredentialHash, leaseOwner, leaseExpiresAt string) (*SessionBinding, error) {
	bindingID = strings.TrimSpace(bindingID)
	newCredentialHash = strings.TrimSpace(newCredentialHash)
	leaseOwner = strings.TrimSpace(leaseOwner)
	leaseExpiresAt = strings.TrimSpace(leaseExpiresAt)
	if bindingID == "" || newCredentialHash == "" || leaseOwner == "" || leaseExpiresAt == "" {
		return nil, errors.New("binding, new credential hash, lease owner, and lease expiry are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := s.getSessionBindingLocked(bindingID)
	if err != nil {
		return nil, err
	}
	if !isActiveBindingStatus(binding.Status) {
		return nil, ErrSessionBindingInactive
	}
	if binding.Epoch != expectedEpoch {
		return nil, ErrSessionBindingStaleEpoch
	}
	currentNow := now()
	if binding.LeaseOwner != "" && binding.LeaseOwner != leaseOwner && binding.LeaseExpiresAt > currentNow {
		return nil, ErrSessionBindingLeaseHeld
	}
	result, err := s.db.Exec(`UPDATE session_bindings SET credential_hash = ?, credential_hash_version = credential_hash_version + 1, lease_owner = ?, lease_expires_at = ?, status = ?, epoch = epoch + 1, version = version + 1, updated_at = ? WHERE id = ? AND epoch = ? AND status IN ('active', 'leased', 'online', 'ready', 'acquired') AND (lease_owner = '' OR lease_owner = ? OR lease_expires_at <= ?)`, newCredentialHash, leaseOwner, leaseExpiresAt, SessionBindingStatusLeased, currentNow, bindingID, expectedEpoch, leaseOwner, currentNow)
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, ErrSessionBindingStaleEpoch
	}
	return s.getSessionBindingLocked(bindingID)
}

func (s *Store) RotateBindingCredential(bindingID string, expectedEpoch uint64, newCredentialHash, leaseOwner, leaseExpiresAt string) (*SessionBinding, error) {
	return s.RotateSessionBindingCredential(bindingID, expectedEpoch, newCredentialHash, leaseOwner, leaseExpiresAt)
}

func (s *Store) ReleaseSessionBindingLease(bindingID, leaseOwner string, expectedEpoch uint64) (*SessionBinding, error) {
	bindingID = strings.TrimSpace(bindingID)
	leaseOwner = strings.TrimSpace(leaseOwner)
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := s.getSessionBindingLocked(bindingID)
	if err != nil {
		return nil, err
	}
	if binding.Epoch != expectedEpoch {
		return nil, ErrSessionBindingStaleEpoch
	}
	if binding.LeaseOwner != leaseOwner {
		return nil, ErrSessionBindingLeaseOwner
	}
	result, err := s.db.Exec(`UPDATE session_bindings SET lease_owner = '', lease_expires_at = '', status = ?, epoch = epoch + 1, version = version + 1, updated_at = ? WHERE id = ? AND epoch = ? AND lease_owner = ? AND status IN ('active', 'leased', 'online', 'ready', 'acquired')`, SessionBindingStatusActive, now(), bindingID, expectedEpoch, leaseOwner)
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, ErrSessionBindingStaleEpoch
	}
	return s.getSessionBindingLocked(bindingID)
}

func (s *Store) ReleaseBindingLease(bindingID, leaseOwner string, expectedEpoch uint64) (*SessionBinding, error) {
	return s.ReleaseSessionBindingLease(bindingID, leaseOwner, expectedEpoch)
}

func (s *Store) ReleaseSessionBinding(bindingID, leaseOwner string, expectedEpoch uint64) (*SessionBinding, error) {
	return s.ReleaseSessionBindingLease(bindingID, leaseOwner, expectedEpoch)
}

// FenceSessionBinding atomically changes the status and advances the epoch.
// Any adapter still holding the old epoch is therefore unable to renew,
// release, or report delivery for this binding.
func (s *Store) FenceSessionBinding(bindingID string, expectedEpoch uint64, status string) (*SessionBinding, error) {
	bindingID = strings.TrimSpace(bindingID)
	status = strings.TrimSpace(status)
	if status == "" {
		status = SessionBindingStatusSuperseded
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := s.getSessionBindingLocked(bindingID)
	if err != nil {
		return nil, err
	}
	if binding.Epoch != expectedEpoch {
		return nil, ErrSessionBindingStaleEpoch
	}
	result, err := s.db.Exec(`UPDATE session_bindings SET status = ?, lease_owner = '', lease_expires_at = '', epoch = epoch + 1, version = version + 1, updated_at = ? WHERE id = ? AND epoch = ?`, status, now(), bindingID, expectedEpoch)
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, ErrSessionBindingStaleEpoch
	}
	return s.getSessionBindingLocked(bindingID)
}

func (s *Store) CompareAndSwapSessionBindingEpoch(bindingID string, expectedEpoch uint64, status string) (*SessionBinding, error) {
	return s.FenceSessionBinding(bindingID, expectedEpoch, status)
}

func (s *Store) RevokeSessionBinding(bindingID string, expectedEpoch uint64, reason string) (*SessionBinding, error) {
	bindingID = strings.TrimSpace(bindingID)
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := s.getSessionBindingLocked(bindingID)
	if err != nil {
		return nil, err
	}
	if binding.Epoch != expectedEpoch {
		return nil, ErrSessionBindingStaleEpoch
	}
	result, err := s.db.Exec(`UPDATE session_bindings SET status = ?, lease_owner = '', lease_expires_at = '', epoch = epoch + 1, version = version + 1, revocation_reason = ?, updated_at = ? WHERE id = ? AND epoch = ?`, SessionBindingStatusRevoked, reason, now(), bindingID, expectedEpoch)
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, ErrSessionBindingStaleEpoch
	}
	return s.getSessionBindingLocked(bindingID)
}

func (s *Store) RevokeSessionBindingUnfenced(bindingID, reason string) (*SessionBinding, error) {
	binding, err := s.GetSessionBinding(bindingID)
	if err != nil {
		return nil, err
	}
	return s.RevokeSessionBinding(bindingID, binding.Epoch, reason)
}

func (s *Store) RevokeBinding(bindingID string, expectedEpoch uint64, reason string) (*SessionBinding, error) {
	return s.RevokeSessionBinding(bindingID, expectedEpoch, reason)
}

func (s *Store) ValidateSessionBindingLease(bindingID, leaseOwner string, epoch uint64) error {
	bindingID = strings.TrimSpace(bindingID)
	leaseOwner = strings.TrimSpace(leaseOwner)
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := s.getSessionBindingLocked(bindingID)
	if err != nil {
		return err
	}
	if !isActiveBindingStatus(binding.Status) {
		return ErrSessionBindingInactive
	}
	if binding.Epoch != epoch {
		return ErrSessionBindingStaleEpoch
	}
	if binding.LeaseOwner != leaseOwner {
		return ErrSessionBindingLeaseOwner
	}
	if binding.LeaseExpiresAt == "" || binding.LeaseExpiresAt <= now() {
		return ErrSessionBindingLeaseExpired
	}
	return nil
}

func (s *Store) CheckSessionBindingLease(bindingID, leaseOwner string, epoch uint64) error {
	return s.ValidateSessionBindingLease(bindingID, leaseOwner, epoch)
}

func normalizeV2Limit(limit int) int {
	if limit <= 0 || limit > 1000 {
		return 200
	}
	return limit
}

func isActiveBindingStatus(status string) bool {
	switch status {
	case SessionBindingStatusActive, SessionBindingStatusLeased, "online", "ready", "acquired":
		return true
	default:
		return false
	}
}

func isSQLiteConstraint(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "constraint") || strings.Contains(message, "unique")
}
