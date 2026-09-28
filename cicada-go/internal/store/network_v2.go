package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	NetworkModePreparing = "PREPARING"
	NetworkModeActive    = "ACTIVE"
	NetworkStateActive   = "ACTIVE"
	NetworkStatePaused   = "PAUSED"
	NetworkMapPending    = "PENDING"
	NetworkMapApproved   = "APPROVED"
)

var (
	ErrNetworkNotFound   = errors.New("network not found")
	ErrNetworkPermission = errors.New("network permission denied")
	ErrNetworkConflict   = errors.New("network version or scope conflict")
	ErrNetworkMigration  = errors.New("network migration is not ready")
	ErrNetworkConsent    = errors.New("network join requires current invitation and owner consent")
)

type Network struct {
	ID        string `json:"network_id"`
	HubID     string `json:"hub_id"`
	Name      string `json:"name"`
	OwnerID   string `json:"owner_id"`
	State     string `json:"state"`
	Version   int64  `json:"version"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type NetworkMembership struct {
	ID          string   `json:"membership_id"`
	NetworkID   string   `json:"network_id"`
	PrincipalID string   `json:"principal_id"`
	Grants      []string `json:"grants"`
	Status      string   `json:"status"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	Revision    int64    `json:"revision"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type EndpointNetworkMembership struct {
	NetworkID    string `json:"network_id"`
	EndpointID   string `json:"endpoint_id"`
	Status       string `json:"status"`
	Revision     int64  `json:"revision"`
	Nickname     string `json:"nickname"`
	Discoverable bool   `json:"discoverable"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type NetworkAccessSession struct {
	ID              string `json:"binding_id"`
	NetworkID       string `json:"network_id"`
	EndpointID      string `json:"endpoint_id"`
	PrincipalID     string `json:"principal_id"`
	NativeSessionID string `json:"native_session_id"`
	NodeID          string `json:"node_id"`
	Epoch           uint64 `json:"epoch"`
	LeaseOwner      string `json:"lease_owner"`
	LeaseExpiresAt  string `json:"lease_expires_at"`
	Status          string `json:"status"`
	CredentialHash  string `json:"-"`
	OwnerKeyID      string `json:"owner_key_id"`
}

type NetworkDirectoryEntry struct {
	NetworkID    string
	EndpointID   string
	Nickname     string
	Availability string
}

// NetworkAccessScope is derived from an authenticated access session. It is a
// directory credential, not a native writer lease. Every directory read checks
// these revisions and the current owner/Node binding in its own transaction.
type NetworkAccessScope struct {
	NetworkID                  string
	PrincipalID                string
	EndpointID                 string
	AccessSessionID            string
	AccessEpoch                uint64
	LeaseOwner                 string
	MembershipID               string
	MembershipRevision         int64
	EndpointMembershipRevision int64
}

// GroupNetworkMapping is an explicit operator decision. A pending row is a
// quarantine marker, not a usable tenant assignment.
type GroupNetworkMapping struct {
	GroupID      string `json:"group_id"`
	NetworkID    string `json:"network_id,omitempty"`
	State        string `json:"state"`
	GroupVersion int64  `json:"group_version"`
	Reason       string `json:"reason,omitempty"`
	UpdatedAt    string `json:"updated_at"`
}

type NetworkMigrationReport struct {
	Phase             string                `json:"phase"`
	Groups            []GroupNetworkMapping `json:"groups"`
	UnmappedCount     int64                 `json:"unmapped_count"`
	PendingCount      int64                 `json:"pending_count"`
	ApprovedCount     int64                 `json:"approved_count"`
	ActiveMemberships int64                 `json:"active_memberships"`
	CrossOwnerGroups  int64                 `json:"cross_owner_groups"`
	Links             int64                 `json:"links"`
	KeyGrants         int64                 `json:"key_grants"`
	PendingReceipts   int64                 `json:"pending_receipts"`
}

func (s *Store) DryRunNetworkMigration() (*NetworkMigrationReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return dryRunNetworkMigrationDB(s.db)
}

// InspectNetworkMigrationReadOnly opens an existing v35 database without
// initializing or migrating it. The report never writes to the source DB.
func InspectNetworkMigrationReadOnly(dbPath string) (*NetworkMigrationReport, error) {
	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNetworkMigration
	}
	uri := (&url.URL{Scheme: "file", Path: absPath, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var state string
	if err := db.QueryRow(`SELECT state FROM schema_migrations_v2 WHERE version=?`, CurrentV2SchemaVersion).Scan(&state); err != nil || state != v2MigrationApplied {
		return nil, fmt.Errorf("network migration inventory requires applied v%d schema: %w", CurrentV2SchemaVersion, ErrNetworkMigration)
	}
	return dryRunNetworkMigrationDB(db)
}

func dryRunNetworkMigrationDB(db *sql.DB) (*NetworkMigrationReport, error) {
	var report NetworkMigrationReport
	if err := db.QueryRow(`SELECT phase FROM network_mode_v2 WHERE id=1`).Scan(&report.Phase); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT g.id,g.network_id,g.version,COALESCE(m.network_id,''),COALESCE(m.state,''),COALESCE(m.reason,''),COALESCE(m.updated_at,'') FROM groups g LEFT JOIN network_group_mappings_v2 m ON m.group_id=g.id ORDER BY g.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var g GroupNetworkMapping
		var assigned, candidate string
		if err := rows.Scan(&g.GroupID, &assigned, &g.GroupVersion, &candidate, &g.State, &g.Reason, &g.UpdatedAt); err != nil {
			return nil, err
		}
		g.NetworkID = candidate
		if g.State == "" && assigned != "" {
			g.NetworkID = assigned
			g.State = NetworkMapApproved
		}
		switch g.State {
		case NetworkMapPending:
			report.PendingCount++
		case NetworkMapApproved:
			report.ApprovedCount++
		default:
			report.UnmappedCount++
		}
		report.Groups = append(report.Groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, item := range []struct {
		dest  *int64
		query string
	}{
		{&report.ActiveMemberships, `SELECT COUNT(*) FROM memberships WHERE status='active'`},
		{&report.CrossOwnerGroups, `SELECT COUNT(DISTINCT g.id) FROM groups g JOIN memberships m ON m.group_id=g.id JOIN principals p ON p.id=m.principal_id WHERE m.status='active' AND p.owner_id<>g.owner_principal_id`},
		{&report.Links, `SELECT COUNT(*) FROM communication_links_v2 WHERE state='PROPOSED'`},
		{&report.KeyGrants, `SELECT COUNT(*) FROM group_endpoint_key_grants_v2`},
		{&report.PendingReceipts, `SELECT COUNT(*) FROM relay_v2_inbox WHERE state IN ('READY','CLAIMED','INJECTION_UNCERTAIN')`},
	} {
		if err := db.QueryRow(item.query).Scan(item.dest); err != nil {
			return nil, err
		}
	}
	return &report, nil
}

func (s *Store) QuarantineGroupNetwork(groupID, reason string, expectedVersion int64) error {
	if groupID == "" || expectedVersion <= 0 {
		return ErrNetworkConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var version int64
	var mapped string
	if err := s.db.QueryRow(`SELECT version,network_id FROM groups WHERE id=?`, groupID).Scan(&version, &mapped); err != nil {
		return err
	}
	if version != expectedVersion || mapped != "" {
		return ErrNetworkConflict
	}
	_, err := s.db.Exec(`INSERT INTO network_group_mappings_v2(group_id,network_id,state,group_version,reason,updated_at) VALUES(?,'','PENDING',?,?,?) ON CONFLICT(group_id) DO UPDATE SET network_id='',group_version=excluded.group_version,reason=excluded.reason,updated_at=excluded.updated_at WHERE network_group_mappings_v2.state='PENDING'`, groupID, expectedVersion, reason, now())
	return err
}

func (s *Store) initializeNetworkSchema() error {
	if err := s.ensureColumn("groups", "network_id", `ALTER TABLE groups ADD COLUMN network_id TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS network_mode_v2 (
 id INTEGER PRIMARY KEY CHECK(id = 1), phase TEXT NOT NULL CHECK(phase IN ('PREPARING','ACTIVE')),
 activated_at TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO network_mode_v2(id,phase) VALUES(1,'PREPARING');
CREATE TABLE IF NOT EXISTS networks_v2 (
 id TEXT PRIMARY KEY, hub_id TEXT NOT NULL, name TEXT NOT NULL,
 owner_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('ACTIVE','PAUSED')),
 version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0), created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS network_invitations_v2 (
 token_hash TEXT PRIMARY KEY, network_id TEXT NOT NULL, target_owner_id TEXT NOT NULL,
 grants_json TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT NOT NULL DEFAULT '',
 issued_by TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(network_id) REFERENCES networks_v2(id)
);
CREATE INDEX IF NOT EXISTS network_invitations_pending_idx ON network_invitations_v2(network_id,consumed_at,expires_at);
CREATE TABLE IF NOT EXISTS network_join_consents_v2 (
 token_hash TEXT PRIMARY KEY, network_id TEXT NOT NULL, owner_id TEXT NOT NULL,
 native_session_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
 consumed_at TEXT NOT NULL DEFAULT '', endpoint_id TEXT NOT NULL DEFAULT '',
 proof_digest TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
 FOREIGN KEY(network_id) REFERENCES networks_v2(id)
);
CREATE TABLE IF NOT EXISTS network_memberships_v2 (
 id TEXT PRIMARY KEY, network_id TEXT NOT NULL, principal_id TEXT NOT NULL,
 grants_json TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL CHECK(status IN ('active','revoked')),
 expires_at TEXT NOT NULL DEFAULT '', revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(network_id,principal_id), FOREIGN KEY(network_id) REFERENCES networks_v2(id),
 FOREIGN KEY(principal_id) REFERENCES principals(id)
);
CREATE INDEX IF NOT EXISTS network_memberships_principal_idx ON network_memberships_v2(principal_id,network_id,status);
CREATE TABLE IF NOT EXISTS endpoint_network_memberships_v2 (
 network_id TEXT NOT NULL, endpoint_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('active','revoked')),
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0), nickname TEXT NOT NULL,
 discoverable INTEGER NOT NULL DEFAULT 0 CHECK(discoverable IN (0,1)),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 PRIMARY KEY(network_id,endpoint_id), FOREIGN KEY(network_id) REFERENCES networks_v2(id),
 FOREIGN KEY(endpoint_id) REFERENCES fabric_endpoints(id)
);
CREATE INDEX IF NOT EXISTS endpoint_network_directory_idx ON endpoint_network_memberships_v2(network_id,status,discoverable,nickname COLLATE NOCASE,endpoint_id);
CREATE TABLE IF NOT EXISTS network_access_sessions_v2 (
 id TEXT PRIMARY KEY, network_id TEXT NOT NULL, endpoint_id TEXT NOT NULL,
 principal_id TEXT NOT NULL, native_session_id TEXT NOT NULL, node_id TEXT NOT NULL,
 epoch INTEGER NOT NULL DEFAULT 1 CHECK(epoch > 0), lease_owner TEXT NOT NULL,
 lease_expires_at TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','revoked')),
 credential_hash TEXT NOT NULL UNIQUE, owner_key_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(network_id,endpoint_id), FOREIGN KEY(network_id) REFERENCES networks_v2(id),
 FOREIGN KEY(endpoint_id) REFERENCES fabric_endpoints(id), FOREIGN KEY(principal_id) REFERENCES principals(id)
);
CREATE TABLE IF NOT EXISTS network_message_enrollment_v2 (
 message_id TEXT PRIMARY KEY, network_id TEXT NOT NULL,
 sender_membership_revision INTEGER NOT NULL CHECK(sender_membership_revision > 0),
 sender_endpoint_revision INTEGER NOT NULL CHECK(sender_endpoint_revision > 0),
 receiver_membership_revision INTEGER NOT NULL CHECK(receiver_membership_revision > 0),
 receiver_endpoint_revision INTEGER NOT NULL CHECK(receiver_endpoint_revision > 0),
 FOREIGN KEY(message_id) REFERENCES fabric_messages(id),
 FOREIGN KEY(network_id) REFERENCES networks_v2(id)
);
CREATE TABLE IF NOT EXISTS network_group_mappings_v2 (
 group_id TEXT PRIMARY KEY, network_id TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL CHECK(state IN ('PENDING','APPROVED')),
 group_version INTEGER NOT NULL, reason TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
 FOREIGN KEY(group_id) REFERENCES groups(id)
);
CREATE INDEX IF NOT EXISTS groups_network_idx ON groups(network_id,state,id);
`)
	if err != nil {
		return fmt.Errorf("initialize network schema: %w", err)
	}
	return nil
}

func tokenDigest(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

// NetworkInvitationDigest is the canonical digest committed in a signed
// owner Join grant. The raw bearer is never persisted in Network tables.
func NetworkInvitationDigest(raw string) string { return tokenDigest(raw) }

func isCanonicalDigest(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(raw)
	return err == nil && hex.EncodeToString(decoded) == raw
}

func (s *Store) NetworkMode() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var phase string
	err := s.db.QueryRow(`SELECT phase FROM network_mode_v2 WHERE id=1`).Scan(&phase)
	return phase, err
}

func (s *Store) CreateNetwork(network Network) (*Network, error) {
	network.ID, network.HubID = strings.TrimSpace(network.ID), strings.TrimSpace(network.HubID)
	network.Name, network.OwnerID = strings.TrimSpace(network.Name), strings.TrimSpace(network.OwnerID)
	if network.HubID == "" || network.Name == "" || network.OwnerID == "" {
		return nil, errors.New("hub, network name and owner are required")
	}
	if network.ID == "" {
		network.ID = NewID("net")
	}
	if network.State == "" {
		network.State = NetworkStateActive
	}
	if network.State != NetworkStateActive && network.State != NetworkStatePaused {
		return nil, ErrNetworkConflict
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var localHubID string
	if err := s.db.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&localHubID); err != nil || localHubID != network.HubID {
		return nil, ErrNetworkPermission
	}
	var ownerKind, ownerStatus string
	if err := s.db.QueryRow(`SELECT kind,status FROM principals WHERE id=?`, network.OwnerID).Scan(&ownerKind, &ownerStatus); err != nil || ownerKind != PrincipalKindHuman || ownerStatus != PrincipalStatusActive {
		return nil, ErrNetworkPermission
	}
	_, err := s.db.Exec(`INSERT INTO networks_v2(id,hub_id,name,owner_id,state,version,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?)`, network.ID, network.HubID, network.Name, network.OwnerID, network.State, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create network: %w", err)
	}
	network.Version, network.CreatedAt, network.UpdatedAt = 1, timestamp, timestamp
	return &network, nil
}

func (s *Store) GetNetwork(id string) (*Network, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n Network
	err := s.db.QueryRow(`SELECT id,hub_id,name,owner_id,state,version,created_at,updated_at FROM networks_v2 WHERE id=?`, strings.TrimSpace(id)).Scan(&n.ID, &n.HubID, &n.Name, &n.OwnerID, &n.State, &n.Version, &n.CreatedAt, &n.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetworkNotFound
	}
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func (s *Store) ListNetworks() ([]Network, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id,hub_id,name,owner_id,state,version,created_at,updated_at FROM networks_v2 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Network
	for rows.Next() {
		var n Network
		if err := rows.Scan(&n.ID, &n.HubID, &n.Name, &n.OwnerID, &n.State, &n.Version, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// PrepareGroupNetworkMapping records a candidate without changing Group
// authority. Approval requires separate explicit verification.
func (s *Store) PrepareGroupNetworkMapping(groupID, networkID, reason string, expectedVersion int64) (*GroupNetworkMapping, error) {
	groupID, networkID = strings.TrimSpace(groupID), strings.TrimSpace(networkID)
	if groupID == "" || networkID == "" || expectedVersion <= 0 {
		return nil, ErrNetworkConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var version int64
	var current string
	if err := s.db.QueryRow(`SELECT version,network_id FROM groups WHERE id=?`, groupID).Scan(&version, &current); err != nil {
		return nil, err
	}
	if version != expectedVersion || (current != "" && current != networkID) {
		return nil, ErrNetworkConflict
	}
	var state string
	if err := s.db.QueryRow(`SELECT state FROM networks_v2 WHERE id=?`, networkID).Scan(&state); err != nil || state != NetworkStateActive {
		return nil, ErrNetworkNotFound
	}
	timestamp := now()
	result, err := s.db.Exec(`INSERT INTO network_group_mappings_v2(group_id,network_id,state,group_version,reason,updated_at) VALUES(?,?,'PENDING',?,?,?)
ON CONFLICT(group_id) DO UPDATE SET network_id=excluded.network_id,group_version=excluded.group_version,reason=excluded.reason,updated_at=excluded.updated_at
WHERE network_group_mappings_v2.state='PENDING'`, groupID, networkID, expectedVersion, reason, timestamp)
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, ErrNetworkConflict
	}
	return &GroupNetworkMapping{GroupID: groupID, NetworkID: networkID, State: NetworkMapPending, GroupVersion: expectedVersion, Reason: reason, UpdatedAt: timestamp}, nil
}

// ApproveGroupNetworkMapping only assigns the exact candidate on the exact
// Group version. Once assigned, a Group can never be silently moved.
func (s *Store) ApproveGroupNetworkMapping(groupID, networkID string, expectedVersion int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var candidate, state, parent, current string
	var version, mappingVersion int64
	if err := tx.QueryRow(`SELECT m.network_id,m.state,g.parent_group_id,g.network_id,g.version,m.group_version FROM network_group_mappings_v2 m JOIN groups g ON g.id=m.group_id WHERE m.group_id=?`, groupID).Scan(&candidate, &state, &parent, &current, &version, &mappingVersion); err != nil {
		return err
	}
	if candidate != networkID || state != NetworkMapPending || version != expectedVersion || mappingVersion != expectedVersion || current != "" {
		return ErrNetworkConflict
	}
	if parent != "" {
		var parentNetwork string
		if err := tx.QueryRow(`SELECT network_id FROM groups WHERE id=?`, parent).Scan(&parentNetwork); err != nil {
			return err
		}
		if parentNetwork != networkID {
			return ErrNetworkConflict
		}
	}
	var childCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM groups WHERE parent_group_id=? AND network_id NOT IN ('',?)`, groupID, networkID).Scan(&childCount); err != nil {
		return err
	}
	if childCount != 0 {
		return ErrNetworkConflict
	}
	timestamp := now()
	// Network mapping changes the signed Group key-grant scope. Advancing the
	// existing GroupRevision fences both accepted and not-yet-accepted proofs
	// prepared against the legacy unscoped Group.
	if _, err := tx.Exec(`UPDATE groups SET network_id=?,revision=revision+1,version=version+1,updated_at=? WHERE id=? AND network_id='' AND version=?`, networkID, timestamp, groupID, expectedVersion); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE network_group_mappings_v2 SET state='APPROVED',group_version=?,updated_at=? WHERE group_id=?`, expectedVersion+1, timestamp, groupID); err != nil {
		return err
	}
	return tx.Commit()
}

// ActivateNetworkMode is a one-way persisted transition. Every preexisting
// Group must be accounted for by an approved assignment or explicit pending
// quarantine marker; the caller reviews dry-run evidence before this call.
func (s *Store) ActivateNetworkMode() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM groups g LEFT JOIN network_group_mappings_v2 m ON m.group_id=g.id
WHERE (g.network_id='' AND (m.group_id IS NULL OR m.state!='PENDING'))
OR (g.network_id!='' AND m.group_id IS NOT NULL AND (m.state!='APPROVED' OR m.network_id!=g.network_id))`).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrNetworkMigration
	}
	if _, err := tx.Exec(`UPDATE network_mode_v2 SET phase='ACTIVE',activated_at=? WHERE id=1 AND phase='PREPARING'`, now()); err != nil {
		return err
	}
	return tx.Commit()
}

// NetworkGuardGroup checks tenant identity at the Store boundary so callers
// outside Fabric cannot treat a Group ID as a bearer permission.
func (s *Store) NetworkGuardGroup(principalID, endpointID, groupID, networkID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var phase, mapped string
	if err := s.db.QueryRow(`SELECT phase FROM network_mode_v2 WHERE id=1`).Scan(&phase); err != nil {
		return err
	}
	if err := s.db.QueryRow(`SELECT network_id FROM groups WHERE id=?`, groupID).Scan(&mapped); err != nil {
		return ErrNetworkPermission
	}
	if mapped == "" && phase == NetworkModePreparing {
		return nil
	}
	if networkID == "" || mapped != networkID {
		return ErrNetworkPermission
	}
	var ok int
	err := s.db.QueryRow(`SELECT 1 FROM groups g
JOIN networks_v2 n ON n.id=g.network_id AND n.state='ACTIVE'
JOIN network_memberships_v2 m ON m.network_id=n.id AND m.principal_id=? AND m.status='active'
JOIN principals p ON p.id=m.principal_id AND p.status='active'
JOIN endpoint_network_memberships_v2 e ON e.network_id=n.id AND e.endpoint_id=? AND e.status='active'
JOIN fabric_endpoints f ON f.id=e.endpoint_id AND f.principal_id=p.id AND f.status!='left'
WHERE g.id=? AND g.network_id=? AND (m.expires_at='' OR m.expires_at>?)`, principalID, endpointID, groupID, networkID, now()).Scan(&ok)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNetworkPermission
	}
	return err
}

func networkGuardPrincipalGroupLocked(db *sql.DB, principalID, groupID string) error {
	var phase, networkID string
	if err := db.QueryRow(`SELECT phase FROM network_mode_v2 WHERE id=1`).Scan(&phase); err != nil {
		return err
	}
	if err := db.QueryRow(`SELECT network_id FROM groups WHERE id=?`, groupID).Scan(&networkID); err != nil {
		return ErrNetworkPermission
	}
	if networkID == "" && phase == NetworkModePreparing {
		return nil
	}
	if networkID == "" {
		return ErrNetworkPermission
	}
	var active int
	err := db.QueryRow(`SELECT 1 FROM networks_v2 n JOIN network_memberships_v2 nm ON nm.network_id=n.id AND nm.principal_id=? AND nm.status='active' JOIN principals p ON p.id=nm.principal_id AND p.status='active' WHERE n.id=? AND n.state='ACTIVE' AND (nm.expires_at='' OR nm.expires_at>?)`, principalID, networkID, now()).Scan(&active)
	if err != nil {
		return ErrNetworkPermission
	}
	return nil
}

func networkGuardCommunicationLinkTx(tx *sql.Tx, link *CommunicationLink, at time.Time) error {
	var sourceNetwork, targetNetwork, phase string
	if err := tx.QueryRow(`SELECT network_id FROM groups WHERE id=?`, link.SourceGroupID).Scan(&sourceNetwork); err != nil {
		return ErrNetworkPermission
	}
	if err := tx.QueryRow(`SELECT network_id FROM groups WHERE id=?`, link.TargetGroupID).Scan(&targetNetwork); err != nil {
		return ErrNetworkPermission
	}
	if err := tx.QueryRow(`SELECT phase FROM network_mode_v2 WHERE id=1`).Scan(&phase); err != nil {
		return err
	}
	if sourceNetwork == "" && targetNetwork == "" && phase == NetworkModePreparing {
		return nil
	}
	if sourceNetwork == "" || sourceNetwork != targetNetwork {
		return ErrNetworkPermission
	}
	var hubID, networkState string
	if err := tx.QueryRow(`SELECT hub_id,state FROM networks_v2 WHERE id=?`, sourceNetwork).Scan(&hubID, &networkState); err != nil || networkState != NetworkStateActive || hubID != link.TransportHubID {
		return ErrNetworkPermission
	}
	for _, side := range []struct{ principalID, endpointID, action string }{
		{link.SourcePrincipalID, link.SourceEndpointID, "direct.send"},
		{link.TargetPrincipalID, link.TargetEndpointID, "direct.receive"},
	} {
		var active int
		query := `SELECT 1 FROM network_memberships_v2 m JOIN endpoint_network_memberships_v2 e ON e.network_id=m.network_id AND e.endpoint_id=? AND e.status='active'
		JOIN fabric_endpoints f ON f.id=e.endpoint_id AND f.principal_id=m.principal_id AND f.status!='left'
		JOIN principals p ON p.id=m.principal_id AND p.status='active'
		WHERE m.network_id=? AND m.principal_id=? AND m.status='active' AND (m.expires_at='' OR m.expires_at>?)`
		args := []any{side.endpointID, sourceNetwork, side.principalID, at.UTC().Format(time.RFC3339Nano)}
		if link.SourceGroupID != link.TargetGroupID {
			query += ` AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value=?)`
			args = append(args, side.action)
		}
		if err := tx.QueryRow(query, args...).Scan(&active); err != nil {
			return ErrNetworkPermission
		}
	}
	return nil
}

func networkGuardRelaySecurityTx(tx *sql.Tx, security *RelayMessageSecurity, receiverGroupID string, at time.Time) error {
	var phase string
	if err := tx.QueryRow(`SELECT phase FROM network_mode_v2 WHERE id=1`).Scan(&phase); err != nil {
		return err
	}
	if receiverGroupID == "" {
		if phase == NetworkModePreparing {
			return nil
		}
		return ErrNetworkPermission
	}
	var receiverNetwork string
	if err := tx.QueryRow(`SELECT network_id FROM groups WHERE id=?`, receiverGroupID).Scan(&receiverNetwork); err != nil {
		if errors.Is(err, sql.ErrNoRows) && phase == NetworkModePreparing {
			return nil
		}
		return ErrNetworkPermission
	}
	if security == nil {
		if phase == NetworkModePreparing && receiverNetwork == "" {
			return nil
		}
		return ErrNetworkPermission
	}
	var senderNetwork string
	if err := tx.QueryRow(`SELECT network_id FROM groups WHERE id=?`, security.SenderGroupID).Scan(&senderNetwork); err != nil {
		if errors.Is(err, sql.ErrNoRows) && phase == NetworkModePreparing && receiverNetwork == "" {
			return nil
		}
		return ErrNetworkPermission
	}
	if senderNetwork == "" && receiverNetwork == "" && phase == NetworkModePreparing {
		return nil
	}
	if senderNetwork == "" || senderNetwork != receiverNetwork || security.ReceiverGroupID != receiverGroupID {
		return ErrNetworkPermission
	}
	var hubID string
	if err := tx.QueryRow(`SELECT hub_id FROM networks_v2 WHERE id=? AND state='ACTIVE'`, senderNetwork).Scan(&hubID); err != nil {
		return ErrNetworkPermission
	}
	for _, side := range []struct{ principalID, endpointID, groupID, action string }{
		{security.SenderPrincipalID, security.SenderEndpointID, security.SenderGroupID, "direct.send"},
		{security.ReceiverPrincipalID, security.ReceiverEndpointID, security.ReceiverGroupID, "direct.receive"},
	} {
		query := `SELECT 1 FROM network_memberships_v2 nm
		JOIN endpoint_network_memberships_v2 en ON en.network_id=nm.network_id AND en.endpoint_id=? AND en.status='active'
		JOIN fabric_endpoints e ON e.id=en.endpoint_id AND e.principal_id=nm.principal_id AND e.status!='left'
		JOIN principals p ON p.id=nm.principal_id AND p.status='active'
		JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=? AND eg.status='active'
		JOIN memberships gm ON gm.group_id=eg.group_id AND gm.principal_id=p.id AND gm.status='active'
		JOIN groups g ON g.id=eg.group_id AND g.network_id=nm.network_id AND g.state='ACTIVE'
		WHERE nm.network_id=? AND nm.principal_id=? AND nm.status='active'
		AND (nm.expires_at='' OR nm.expires_at>?) AND (gm.expires_at='' OR gm.expires_at>?)`
		stamp := at.UTC().Format(time.RFC3339Nano)
		args := []any{side.endpointID, side.groupID, senderNetwork, side.principalID, stamp, stamp}
		if security.SenderGroupID != security.ReceiverGroupID {
			query += ` AND EXISTS(SELECT 1 FROM json_each(nm.grants_json) WHERE value=?)`
			args = append(args, side.action)
		}
		var active int
		if err := tx.QueryRow(query, args...).Scan(&active); err != nil {
			return ErrNetworkPermission
		}
		var ownerID, nodeID string
		if err := tx.QueryRow(`SELECT owner,machine_id FROM fabric_endpoints
WHERE id=? AND principal_id=?`, side.endpointID, side.principalID).Scan(&ownerID, &nodeID); err != nil {
			return ErrNetworkPermission
		}
		if err := requireCurrentOwnerBoundGroupNodeTx(tx, nodeID, ownerID, hubID); err != nil {
			return ErrNetworkPermission
		}
	}
	return nil
}

func networkGuardGroupEndpointTx(tx *sql.Tx, principalID, endpointID, groupID string, at time.Time) error {
	security := &RelayMessageSecurity{
		SenderPrincipalID: principalID, SenderEndpointID: endpointID, SenderGroupID: groupID,
		ReceiverPrincipalID: principalID, ReceiverEndpointID: endpointID, ReceiverGroupID: groupID,
	}
	return networkGuardRelaySecurityTx(tx, security, groupID, at)
}

func networkGuardTaskPrincipalTx(tx *sql.Tx, principalID, groupID string, at time.Time) error {
	var phase, networkID string
	if err := tx.QueryRow(`SELECT phase FROM network_mode_v2 WHERE id=1`).Scan(&phase); err != nil {
		return err
	}
	if err := tx.QueryRow(`SELECT network_id FROM groups WHERE id=?`, groupID).Scan(&networkID); err != nil {
		return ErrNetworkPermission
	}
	if networkID == "" && phase == NetworkModePreparing {
		return nil
	}
	if networkID == "" {
		return ErrNetworkPermission
	}
	var active int
	err := tx.QueryRow(`SELECT 1 FROM networks_v2 n
		JOIN network_memberships_v2 nm ON nm.network_id=n.id AND nm.principal_id=? AND nm.status='active'
		JOIN principals p ON p.id=nm.principal_id AND p.status='active'
		JOIN memberships gm ON gm.principal_id=p.id AND gm.group_id=? AND gm.status='active'
		WHERE n.id=? AND n.state='ACTIVE' AND (nm.expires_at='' OR nm.expires_at>?)
		AND (gm.expires_at='' OR gm.expires_at>?)`,
		principalID, groupID, networkID, at.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano)).Scan(&active)
	if err != nil {
		return ErrNetworkPermission
	}
	return nil
}

func networkGuardRelayMessageTx(tx *sql.Tx, messageID, receiverGroupID string, at time.Time) error {
	security, err := relayLoadSecurityTx(tx, messageID)
	if err != nil {
		return err
	}
	if err := networkGuardRelaySecurityTx(tx, security, receiverGroupID, at); err != nil {
		return err
	}
	networkID, err := networkRelayGroupIDTx(tx, security.SenderGroupID)
	if err != nil || networkID == "" {
		// The compatible PREPARING path is handled by the current-scope guard.
		return nil
	}
	var expected [4]int64
	err = tx.QueryRow(`SELECT sender_membership_revision,sender_endpoint_revision,
		receiver_membership_revision,receiver_endpoint_revision
		FROM network_message_enrollment_v2 WHERE message_id=? AND network_id=?`, messageID, networkID).
		Scan(&expected[0], &expected[1], &expected[2], &expected[3])
	if err != nil {
		// A message queued before explicit mapping has no Network authority.
		return ErrNetworkPermission
	}
	senderMembership, senderEndpoint, err := networkEnrollmentRevisionTx(tx, networkID, security.SenderPrincipalID, security.SenderEndpointID)
	if err != nil || senderMembership != expected[0] || senderEndpoint != expected[1] {
		return ErrNetworkPermission
	}
	receiverMembership, receiverEndpoint, err := networkEnrollmentRevisionTx(tx, networkID, security.ReceiverPrincipalID, security.ReceiverEndpointID)
	if err != nil || receiverMembership != expected[2] || receiverEndpoint != expected[3] {
		return ErrNetworkPermission
	}
	return nil
}

func networkRelayGroupIDTx(tx *sql.Tx, groupID string) (string, error) {
	var networkID string
	err := tx.QueryRow(`SELECT network_id FROM groups WHERE id=?`, groupID).Scan(&networkID)
	return networkID, err
}

func networkEnrollmentRevisionTx(tx *sql.Tx, networkID, principalID, endpointID string) (int64, int64, error) {
	var membershipRevision, endpointRevision int64
	err := tx.QueryRow(`SELECT nm.revision,en.revision FROM network_memberships_v2 nm
		JOIN endpoint_network_memberships_v2 en ON en.network_id=nm.network_id AND en.endpoint_id=? AND en.status='active'
		JOIN fabric_endpoints e ON e.id=en.endpoint_id AND e.principal_id=nm.principal_id AND e.status!='left'
		WHERE nm.network_id=? AND nm.principal_id=? AND nm.status='active'`,
		endpointID, networkID, principalID).Scan(&membershipRevision, &endpointRevision)
	return membershipRevision, endpointRevision, err
}

func networkCaptureRelayMessageEnrollmentTx(tx *sql.Tx, security *RelayMessageSecurity) error {
	networkID, err := networkRelayGroupIDTx(tx, security.SenderGroupID)
	if err != nil || networkID == "" {
		return nil
	}
	senderMembership, senderEndpoint, err := networkEnrollmentRevisionTx(tx, networkID, security.SenderPrincipalID, security.SenderEndpointID)
	if err != nil {
		return ErrNetworkPermission
	}
	receiverMembership, receiverEndpoint, err := networkEnrollmentRevisionTx(tx, networkID, security.ReceiverPrincipalID, security.ReceiverEndpointID)
	if err != nil {
		return ErrNetworkPermission
	}
	_, err = tx.Exec(`INSERT INTO network_message_enrollment_v2
		(message_id,network_id,sender_membership_revision,sender_endpoint_revision,receiver_membership_revision,receiver_endpoint_revision)
		VALUES(?,?,?,?,?,?)`, security.MessageID, networkID, senderMembership, senderEndpoint, receiverMembership, receiverEndpoint)
	return err
}

type NetworkInvitation struct {
	NetworkID     string
	TargetOwnerID string
	IssuerID      string
	Grants        []string
	ExpiresAt     string
	ConsumedAt    string
}

func (s *Store) GetNetworkInvitation(token string) (*NetworkInvitation, error) {
	if len(token) < 32 {
		return nil, ErrNetworkConsent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var v NetworkInvitation
	var grantsJSON string
	err := s.db.QueryRow(`SELECT network_id,target_owner_id,issued_by,grants_json,expires_at,consumed_at
FROM network_invitations_v2 WHERE token_hash=?`, tokenDigest(token)).Scan(&v.NetworkID, &v.TargetOwnerID, &v.IssuerID, &grantsJSON, &v.ExpiresAt, &v.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetworkConsent
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(grantsJSON), &v.Grants); err != nil {
		return nil, err
	}
	return &v, nil
}

type AcceptNetworkJoinInput struct {
	NetworkID          string
	OwnerID            string
	TrustDomainID      string
	NodeID             string
	NativeSessionID    string
	Harness            string
	EndpointName       string
	InvitationToken    string
	ProofNonce         string
	ProofDigest        string
	ProofExpiresAt     string
	OwnerKeyID         string
	OwnerJoinProof     string
	NodeCredentialHash string
	Grants             []string
	Discoverable       bool
	CredentialHash     string
	LeaseOwner         string
	LeaseExpiresAt     string
}

type AcceptedNetworkJoin struct {
	EndpointID         string
	PrincipalID        string
	MembershipID       string
	MembershipRevision int64
	EndpointRevision   int64
	AccessSessionID    string
	AccessSessionEpoch uint64
}

// AcceptNetworkJoin rechecks the signed proof's trusted inputs and consumes
// the invitation and nonce in the same transaction as the scoped membership.
// A retry with the same exact proof keeps the stable Endpoint and Principal.
func (s *Store) AcceptNetworkJoin(input AcceptNetworkJoinInput) (*AcceptedNetworkJoin, error) {
	if input.NetworkID == "" || input.OwnerID == "" || input.TrustDomainID == "" || input.NodeID == "" || input.NativeSessionID == "" || input.Harness == "" || input.EndpointName == "" || input.OwnerKeyID == "" || input.CredentialHash == "" || input.NodeCredentialHash == "" || input.LeaseOwner == "" || input.LeaseExpiresAt <= now() || input.ProofExpiresAt <= now() || !validNetworkGrants(input.Grants) || !isCanonicalDigest(input.ProofNonce) || !isCanonicalDigest(input.ProofDigest) {
		return nil, ErrNetworkConsent
	}
	grantsJSON, err := json.Marshal(input.Grants)
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
	var networkState, hubID string
	if err := tx.QueryRow(`SELECT state,hub_id FROM networks_v2 WHERE id=?`, input.NetworkID).Scan(&networkState, &hubID); err != nil || networkState != NetworkStateActive {
		return nil, ErrNetworkNotFound
	}
	var nodeOwner, nodeState, nodeHubID string
	if err := tx.QueryRow(`SELECT b.owner_id,b.state,b.hub_id FROM node_owner_bindings_v2 b JOIN fabric_node_credentials c ON c.node_id=b.node_id AND c.credential_hash=b.node_credential_digest AND c.status='active' WHERE b.node_id=? AND b.node_credential_digest=? AND b.state='ACTIVE'`, input.NodeID, input.NodeCredentialHash).Scan(&nodeOwner, &nodeState, &nodeHubID); err != nil || nodeOwner != input.OwnerID || nodeState != "ACTIVE" || nodeHubID != hubID {
		return nil, ErrNetworkConsent
	}
	var keyState, ownerPublicJSON string
	if err := tx.QueryRow(`SELECT state,public_identity_json FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, input.OwnerID, input.OwnerKeyID).Scan(&keyState, &ownerPublicJSON); err != nil || keyState != OwnerApprovalKeyActive {
		return nil, ErrNetworkConsent
	}
	var ownerTrust, ownerKind, ownerStatus string
	if err := tx.QueryRow(`SELECT trust_domain_id,kind,status FROM principals WHERE id=?`, input.OwnerID).Scan(&ownerTrust, &ownerKind, &ownerStatus); err != nil || ownerTrust != input.TrustDomainID || ownerKind != PrincipalKindHuman || ownerStatus != PrincipalStatusActive {
		return nil, ErrNetworkConsent
	}
	var targetOwner, invitationGrants, invitationExpiry, consumed string
	if err := tx.QueryRow(`SELECT target_owner_id,grants_json,expires_at,consumed_at FROM network_invitations_v2 WHERE token_hash=? AND network_id=?`, tokenDigest(input.InvitationToken), input.NetworkID).Scan(&targetOwner, &invitationGrants, &invitationExpiry, &consumed); err != nil {
		return nil, ErrNetworkConsent
	}
	if targetOwner != input.OwnerID || invitationGrants != string(grantsJSON) || invitationExpiry <= now() {
		return nil, ErrNetworkConsent
	}
	if input.Discoverable && !slices.Contains(input.Grants, "directory.publish") {
		return nil, ErrNetworkConsent
	}
	var trustedOwner e2ee.PublicIdentity
	if err := json.Unmarshal([]byte(ownerPublicJSON), &trustedOwner); err != nil {
		return nil, ErrNetworkConsent
	}
	expected := e2ee.OwnerNetworkJoinGrant{HubID: hubID, NetworkID: input.NetworkID, OwnerID: input.OwnerID, NodeID: input.NodeID, NativeSessionID: input.NativeSessionID, InvitationDigest: tokenDigest(input.InvitationToken), Grants: input.Grants, Discoverable: input.Discoverable}
	verified, err := e2ee.VerifyOwnerNetworkJoinGrant([]byte(input.OwnerJoinProof), trustedOwner, expected, time.Now().UTC())
	if err != nil || verified.Nonce != input.ProofNonce || verified.ExpiresAt != input.ProofExpiresAt || tokenDigest(input.OwnerJoinProof) != input.ProofDigest {
		return nil, ErrNetworkConsent
	}
	var previousEndpoint, previousDigest string
	err = tx.QueryRow(`SELECT endpoint_id,proof_digest FROM network_join_consents_v2 WHERE token_hash=?`, input.ProofNonce).Scan(&previousEndpoint, &previousDigest)
	if err == nil && previousDigest != input.ProofDigest {
		return nil, ErrNetworkConsent
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if consumed != "" && previousEndpoint == "" {
		return nil, ErrNetworkConsent
	}
	var endpointID, principalID, existingOwner, existingNode, existingStatus string
	err = tx.QueryRow(`SELECT id,principal_id,owner,machine_id,status FROM fabric_endpoints WHERE harness=? AND native_session_id=?`, input.Harness, input.NativeSessionID).Scan(&endpointID, &principalID, &existingOwner, &existingNode, &existingStatus)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		if existingOwner != input.OwnerID || existingNode != input.NodeID || existingStatus == "left" || principalID == "" {
			return nil, ErrNetworkConsent
		}
	} else {
		principalID = NewID("principal")
		endpointID = NewID("ep")
		timestamp := now()
		if _, err := tx.Exec(`INSERT INTO principals(id,kind,owner_id,trust_domain_id,name,display_name,status,version,created_at,updated_at) VALUES(?,'agent',?,?,?,?,'active',1,?,?)`, principalID, input.OwnerID, input.TrustDomainID, input.EndpointName, input.EndpointName, timestamp, timestamp); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO fabric_endpoints(id,name,role,harness,native_session_id,machine_id,workspace,goal_id,status,capabilities_json,tags_json,owner,visibility,joined_at,last_seen,created_at,updated_at,principal_id,migration_state) VALUES(?,?,'thread',?,? ,?,'','','online','{}','[]',?,'private',?,?,?,?,?,'MIGRATION_PENDING_GROUP')`, endpointID, input.EndpointName, input.Harness, input.NativeSessionID, input.NodeID, input.OwnerID, timestamp, timestamp, timestamp, timestamp, principalID); err != nil {
			return nil, err
		}
	}
	if previousEndpoint != "" && previousEndpoint != endpointID {
		return nil, ErrNetworkConsent
	}
	var principalOwner, principalStatus string
	if err := tx.QueryRow(`SELECT owner_id,status FROM principals WHERE id=?`, principalID).Scan(&principalOwner, &principalStatus); err != nil || principalOwner != input.OwnerID || principalStatus != PrincipalStatusActive {
		return nil, ErrNetworkConsent
	}
	timestamp := now()
	if previousEndpoint == "" {
		if _, err := tx.Exec(`INSERT INTO network_join_consents_v2(token_hash,network_id,owner_id,native_session_hash,expires_at,consumed_at,endpoint_id,proof_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, input.ProofNonce, input.NetworkID, input.OwnerID, tokenDigest(input.NativeSessionID), input.ProofExpiresAt, timestamp, endpointID, input.ProofDigest, timestamp); err != nil {
			return nil, err
		}
	}
	if consumed == "" {
		if _, err := tx.Exec(`UPDATE network_invitations_v2 SET consumed_at=? WHERE token_hash=? AND consumed_at=''`, timestamp, tokenDigest(input.InvitationToken)); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(`INSERT INTO network_memberships_v2(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at) VALUES(?,?,?,?, 'active','',1,?,?) ON CONFLICT(network_id,principal_id) DO UPDATE SET grants_json=excluded.grants_json,status='active',expires_at='',revision=network_memberships_v2.revision+1,updated_at=excluded.updated_at WHERE network_memberships_v2.status='revoked' AND ?=''`, NewID("netmem"), input.NetworkID, principalID, string(grantsJSON), timestamp, timestamp, previousEndpoint); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO endpoint_network_memberships_v2(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at) VALUES(?,?,'active',1,?,?,?,?) ON CONFLICT(network_id,endpoint_id) DO UPDATE SET status='active',revision=endpoint_network_memberships_v2.revision+1,nickname=excluded.nickname,discoverable=excluded.discoverable,updated_at=excluded.updated_at WHERE endpoint_network_memberships_v2.status='revoked' AND ?=''`, input.NetworkID, endpointID, input.EndpointName, input.Discoverable, timestamp, timestamp, previousEndpoint); err != nil {
		return nil, err
	}
	var result AcceptedNetworkJoin
	result.EndpointID, result.PrincipalID = endpointID, principalID
	var memberGrants, memberStatus, memberExpiry, endpointStatus string
	if err := tx.QueryRow(`SELECT id,grants_json,status,expires_at,revision FROM network_memberships_v2 WHERE network_id=? AND principal_id=?`, input.NetworkID, principalID).Scan(&result.MembershipID, &memberGrants, &memberStatus, &memberExpiry, &result.MembershipRevision); err != nil {
		return nil, err
	}
	if memberStatus != "active" || memberExpiry != "" && memberExpiry <= timestamp || memberGrants != string(grantsJSON) {
		return nil, ErrNetworkConsent
	}
	if err := tx.QueryRow(`SELECT status,revision FROM endpoint_network_memberships_v2 WHERE network_id=? AND endpoint_id=?`, input.NetworkID, endpointID).Scan(&endpointStatus, &result.EndpointRevision); err != nil || endpointStatus != "active" {
		return nil, ErrNetworkConsent
	}
	var existingBindingID string
	var existingEpoch uint64
	err = tx.QueryRow(`SELECT id,epoch FROM network_access_sessions_v2 WHERE network_id=? AND endpoint_id=?`, input.NetworkID, endpointID).Scan(&existingBindingID, &existingEpoch)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		result.AccessSessionID = existingBindingID
		result.AccessSessionEpoch = existingEpoch + 1
		if _, err := tx.Exec(`UPDATE network_access_sessions_v2 SET epoch=epoch+1,lease_owner=?,lease_expires_at=?,credential_hash=?,owner_key_id=?,status='active',updated_at=? WHERE id=?`, input.LeaseOwner, input.LeaseExpiresAt, input.CredentialHash, input.OwnerKeyID, timestamp, existingBindingID); err != nil {
			return nil, err
		}
	} else {
		result.AccessSessionID = NewID("netaccess")
		result.AccessSessionEpoch = 1
		if _, err := tx.Exec(`INSERT INTO network_access_sessions_v2(id,network_id,endpoint_id,principal_id,native_session_id,node_id,epoch,lease_owner,lease_expires_at,status,credential_hash,owner_key_id,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?,'active',?,?,?,?)`, result.AccessSessionID, input.NetworkID, endpointID, principalID, input.NativeSessionID, input.NodeID, input.LeaseOwner, input.LeaseExpiresAt, input.CredentialHash, input.OwnerKeyID, timestamp, timestamp); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *Store) GetNetworkAccessSessionByHash(digest string) (*NetworkAccessSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var a NetworkAccessSession
	err := s.db.QueryRow(`SELECT id,network_id,endpoint_id,principal_id,native_session_id,node_id,epoch,lease_owner,lease_expires_at,status,credential_hash,owner_key_id
FROM network_access_sessions_v2 WHERE credential_hash=?`, digest).Scan(&a.ID, &a.NetworkID, &a.EndpointID, &a.PrincipalID, &a.NativeSessionID, &a.NodeID, &a.Epoch, &a.LeaseOwner, &a.LeaseExpiresAt, &a.Status, &a.CredentialHash, &a.OwnerKeyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetworkPermission
	}
	return &a, err
}

func (s *Store) GetNetworkAccessSessionByID(id string) (*NetworkAccessSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var a NetworkAccessSession
	err := s.db.QueryRow(`SELECT id,network_id,endpoint_id,principal_id,native_session_id,node_id,epoch,lease_owner,lease_expires_at,status,credential_hash,owner_key_id FROM network_access_sessions_v2 WHERE id=?`, id).Scan(&a.ID, &a.NetworkID, &a.EndpointID, &a.PrincipalID, &a.NativeSessionID, &a.NodeID, &a.Epoch, &a.LeaseOwner, &a.LeaseExpiresAt, &a.Status, &a.CredentialHash, &a.OwnerKeyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetworkPermission
	}
	return &a, err
}

type RenewNetworkAccessInput struct {
	NetworkID          string
	EndpointID         string
	OwnerID            string
	NodeID             string
	Harness            string
	NativeSessionID    string
	NodeCredentialHash string
	CredentialHash     string
	LeaseOwner         string
	LeaseExpiresAt     string
}

// RenewNetworkAccess refreshes a directory-only credential. It never touches
// SessionBinding, native lease epoch, receipt replay state, or writer ownership.
func (s *Store) RenewNetworkAccess(input RenewNetworkAccessInput) (*AcceptedNetworkJoin, error) {
	if input.NetworkID == "" || input.EndpointID == "" || input.OwnerID == "" || input.NodeID == "" || input.Harness == "" || input.NativeSessionID == "" || input.NodeCredentialHash == "" || input.CredentialHash == "" || input.LeaseOwner == "" || input.LeaseExpiresAt <= now() {
		return nil, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var hubID, networkState string
	if err := tx.QueryRow(`SELECT hub_id,state FROM networks_v2 WHERE id=?`, input.NetworkID).Scan(&hubID, &networkState); err != nil || networkState != NetworkStateActive {
		return nil, ErrNetworkPermission
	}
	var nodeOwner, nodeHub string
	if err := tx.QueryRow(`SELECT b.owner_id,b.hub_id FROM node_owner_bindings_v2 b JOIN fabric_node_credentials c ON c.node_id=b.node_id AND c.credential_hash=b.node_credential_digest AND c.status='active' WHERE b.node_id=? AND b.node_credential_digest=? AND b.state='ACTIVE'`, input.NodeID, input.NodeCredentialHash).Scan(&nodeOwner, &nodeHub); err != nil || nodeOwner != input.OwnerID || nodeHub != hubID {
		return nil, ErrNetworkPermission
	}
	var principalID, ownerID, nodeID, harnessName, nativeID, status string
	if err := tx.QueryRow(`SELECT principal_id,owner,machine_id,harness,native_session_id,status FROM fabric_endpoints WHERE id=?`, input.EndpointID).Scan(&principalID, &ownerID, &nodeID, &harnessName, &nativeID, &status); err != nil || principalID == "" || ownerID != input.OwnerID || nodeID != input.NodeID || harnessName != input.Harness || nativeID != input.NativeSessionID || status == "left" {
		return nil, ErrNetworkPermission
	}
	var result AcceptedNetworkJoin
	result.EndpointID, result.PrincipalID = input.EndpointID, principalID
	var memberStatus, expiry, principalStatus string
	if err := tx.QueryRow(`SELECT m.id,m.revision,m.status,m.expires_at,p.status FROM network_memberships_v2 m JOIN principals p ON p.id=m.principal_id WHERE m.network_id=? AND m.principal_id=?`, input.NetworkID, principalID).Scan(&result.MembershipID, &result.MembershipRevision, &memberStatus, &expiry, &principalStatus); err != nil || memberStatus != "active" || principalStatus != "active" || expiry != "" && expiry <= now() {
		return nil, ErrNetworkPermission
	}
	var endpointStatus string
	if err := tx.QueryRow(`SELECT status,revision FROM endpoint_network_memberships_v2 WHERE network_id=? AND endpoint_id=?`, input.NetworkID, input.EndpointID).Scan(&endpointStatus, &result.EndpointRevision); err != nil || endpointStatus != "active" {
		return nil, ErrNetworkPermission
	}
	var accessOwnerKey string
	if err := tx.QueryRow(`SELECT id,epoch,owner_key_id FROM network_access_sessions_v2 WHERE network_id=? AND endpoint_id=? AND principal_id=? AND node_id=? AND native_session_id=? AND status='active'`, input.NetworkID, input.EndpointID, principalID, input.NodeID, input.NativeSessionID).Scan(&result.AccessSessionID, &result.AccessSessionEpoch, &accessOwnerKey); err != nil {
		return nil, ErrNetworkPermission
	}
	var keyState string
	if err := tx.QueryRow(`SELECT state FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, input.OwnerID, accessOwnerKey).Scan(&keyState); err != nil || keyState != OwnerApprovalKeyActive {
		return nil, ErrNetworkPermission
	}
	result.AccessSessionEpoch++
	if _, err := tx.Exec(`UPDATE network_access_sessions_v2 SET epoch=epoch+1,lease_owner=?,lease_expires_at=?,credential_hash=?,updated_at=? WHERE id=?`, input.LeaseOwner, input.LeaseExpiresAt, input.CredentialHash, now(), result.AccessSessionID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *Store) GetNetworkMembership(networkID, principalID string) (*NetworkMembership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m NetworkMembership
	var grantsJSON string
	err := s.db.QueryRow(`SELECT id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at FROM network_memberships_v2 WHERE network_id=? AND principal_id=?`, networkID, principalID).Scan(&m.ID, &m.NetworkID, &m.PrincipalID, &grantsJSON, &m.Status, &m.ExpiresAt, &m.Revision, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetworkPermission
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(grantsJSON), &m.Grants); err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) GetEndpointNetworkMembership(networkID, endpointID string) (*EndpointNetworkMembership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m EndpointNetworkMembership
	var discoverable int
	err := s.db.QueryRow(`SELECT network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at FROM endpoint_network_memberships_v2 WHERE network_id=? AND endpoint_id=?`, networkID, endpointID).Scan(&m.NetworkID, &m.EndpointID, &m.Status, &m.Revision, &m.Nickname, &discoverable, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetworkPermission
	}
	if err != nil {
		return nil, err
	}
	m.Discoverable = discoverable == 1
	return &m, nil
}

func (s *Store) NetworkAllows(networkID, principalID, endpointID, action string) (bool, error) {
	if networkID == "" || principalID == "" || endpointID == "" || action == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var allowed int
	err := s.db.QueryRow(`SELECT 1 FROM networks_v2 n
JOIN network_memberships_v2 m ON m.network_id=n.id AND m.principal_id=? AND m.status='active'
JOIN endpoint_network_memberships_v2 e ON e.network_id=n.id AND e.endpoint_id=? AND e.status='active'
JOIN fabric_endpoints f ON f.id=e.endpoint_id AND f.principal_id=m.principal_id AND f.status!='left'
JOIN principals p ON p.id=m.principal_id AND p.status='active'
WHERE n.id=? AND n.state='ACTIVE' AND (m.expires_at='' OR m.expires_at>?)
AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value=?)`, principalID, endpointID, networkID, now(), action).Scan(&allowed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && allowed == 1, err
}

func (s *Store) RevokeNetworkMembership(networkID, principalID string, expectedRevision int64) error {
	if networkID == "" || principalID == "" || expectedRevision <= 0 {
		return ErrNetworkConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE network_memberships_v2 SET status='revoked',revision=revision+1,updated_at=? WHERE network_id=? AND principal_id=? AND revision=? AND status='active'`, now(), networkID, principalID, expectedRevision)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrNetworkConflict
	}
	// Group relationships and grants remain intact. Only their authorization
	// generation advances, so native actors and Owner-signed key proofs from
	// before Network revocation cannot become current after a fresh Join.
	timestamp := now()
	if _, err := tx.Exec(`UPDATE memberships SET revision=revision+1,version=version+1,updated_at=?
WHERE principal_id=? AND group_id IN (SELECT id FROM groups WHERE network_id=?)`,
		timestamp, principalID, networkID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE endpoint_group_memberships SET revision=revision+1,updated_at=?
WHERE endpoint_id IN (SELECT id FROM fabric_endpoints WHERE principal_id=?)
AND group_id IN (SELECT id FROM groups WHERE network_id=?)`, timestamp, principalID, networkID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE endpoint_network_memberships_v2 SET status='revoked',revision=revision+1,updated_at=? WHERE network_id=? AND endpoint_id IN (SELECT id FROM fabric_endpoints WHERE principal_id=?)`, now(), networkID, principalID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE network_access_sessions_v2 SET status='revoked',updated_at=? WHERE network_id=? AND principal_id=?`, now(), networkID, principalID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LeaveEndpointNetwork(networkID, endpointID string, expectedRevision int64) error {
	if networkID == "" || endpointID == "" || expectedRevision <= 0 {
		return ErrNetworkConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE endpoint_network_memberships_v2 SET status='revoked',revision=revision+1,updated_at=? WHERE network_id=? AND endpoint_id=? AND revision=? AND status='active'`, now(), networkID, endpointID, expectedRevision)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrNetworkConflict
	}
	if _, err := tx.Exec(`UPDATE endpoint_group_memberships SET revision=revision+1,updated_at=?
WHERE endpoint_id=? AND group_id IN (SELECT id FROM groups WHERE network_id=?)`,
		now(), endpointID, networkID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE network_access_sessions_v2 SET status='revoked',updated_at=? WHERE network_id=? AND endpoint_id=?`, now(), networkID, endpointID); err != nil {
		return err
	}
	return tx.Commit()
}

// networkGuardAccessTx and the directory query share one SQLite snapshot.
// Revocation committed by another Store instance before this read begins is
// therefore observed before any card can be returned.
func networkGuardAccessTx(tx *sql.Tx, scope NetworkAccessScope, action string, at time.Time) error {
	if scope.NetworkID == "" || scope.PrincipalID == "" || scope.EndpointID == "" ||
		scope.AccessSessionID == "" || scope.AccessEpoch == 0 || scope.LeaseOwner == "" ||
		scope.MembershipID == "" || scope.MembershipRevision <= 0 ||
		scope.EndpointMembershipRevision <= 0 || action == "" {
		return ErrNetworkPermission
	}
	var leaseExpiry, membershipExpiry string
	err := tx.QueryRow(`SELECT a.lease_expires_at,m.expires_at
FROM network_access_sessions_v2 a
JOIN networks_v2 n ON n.id=a.network_id AND n.state='ACTIVE'
JOIN network_memberships_v2 m ON m.network_id=n.id AND m.principal_id=a.principal_id AND m.status='active'
JOIN endpoint_network_memberships_v2 en ON en.network_id=n.id AND en.endpoint_id=a.endpoint_id AND en.status='active'
JOIN fabric_endpoints f ON f.id=en.endpoint_id AND f.principal_id=m.principal_id
  AND f.machine_id=a.node_id AND f.native_session_id=a.native_session_id AND f.status!='left'
JOIN principals p ON p.id=m.principal_id AND p.status='active' AND p.owner_id=f.owner
JOIN node_owner_bindings_v2 b ON b.node_id=a.node_id AND b.owner_id=f.owner
  AND b.hub_id=n.hub_id AND b.state='ACTIVE'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=b.hub_id
JOIN fabric_node_credentials c ON c.node_id=b.node_id
  AND c.credential_hash=b.node_credential_digest
  AND c.version=b.node_credential_version AND c.status='active'
JOIN owner_approval_keys_v2 nk ON nk.owner_id=b.owner_id
  AND nk.key_id=b.owner_key_id AND nk.state='ACTIVE'
JOIN owner_approval_keys_v2 ak ON ak.owner_id=f.owner
  AND ak.key_id=a.owner_key_id AND ak.state='ACTIVE'
WHERE a.id=? AND a.network_id=? AND a.principal_id=? AND a.endpoint_id=?
  AND a.epoch=? AND a.lease_owner=? AND a.status='active'
  AND m.id=? AND m.revision=? AND en.revision=?
  AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value=?)`,
		scope.AccessSessionID, scope.NetworkID, scope.PrincipalID, scope.EndpointID,
		scope.AccessEpoch, scope.LeaseOwner, scope.MembershipID,
		scope.MembershipRevision, scope.EndpointMembershipRevision, action).
		Scan(&leaseExpiry, &membershipExpiry)
	if err != nil {
		return ErrNetworkPermission
	}
	leaseDeadline, err := time.Parse(time.RFC3339Nano, leaseExpiry)
	if err != nil || !leaseDeadline.After(at) {
		return ErrNetworkPermission
	}
	if membershipExpiry != "" {
		membershipDeadline, err := time.Parse(time.RFC3339Nano, membershipExpiry)
		if err != nil || !membershipDeadline.After(at) {
			return ErrNetworkPermission
		}
	}
	return nil
}

// ListNetworkDirectory runs caller and publisher checks in one transaction.
// It never loads private Group names, workspace paths, native IDs or keys.
func (s *Store) ListNetworkDirectory(scope NetworkAccessScope, limit int) ([]NetworkDirectoryEntry, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	if err := networkGuardAccessTx(tx, scope, "directory.discover", at); err != nil {
		return nil, err
	}
	stamp := at.Format(time.RFC3339)
	rows, err := tx.Query(`SELECT e.network_id,e.endpoint_id,e.nickname,
CASE WHEN f.status!='offline' AND a.status='active' AND a.lease_expires_at>? THEN 'ACCESS_RECENT' ELSE 'UNKNOWN' END
FROM endpoint_network_memberships_v2 e
JOIN fabric_endpoints f ON f.id=e.endpoint_id AND f.status!='left'
JOIN principals p ON p.id=f.principal_id AND p.status='active'
JOIN network_memberships_v2 m ON m.network_id=e.network_id AND m.principal_id=f.principal_id AND m.status='active'
JOIN networks_v2 n ON n.id=e.network_id AND n.state='ACTIVE'
LEFT JOIN network_access_sessions_v2 a ON a.network_id=e.network_id AND a.endpoint_id=e.endpoint_id
WHERE e.network_id=? AND e.status='active' AND e.discoverable=1
AND (m.expires_at='' OR m.expires_at>?)
AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value='directory.publish')
ORDER BY e.nickname COLLATE NOCASE,e.endpoint_id LIMIT ?`, stamp, scope.NetworkID, stamp, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []NetworkDirectoryEntry
	for rows.Next() {
		var e NetworkDirectoryEntry
		if err := rows.Scan(&e.NetworkID, &e.EndpointID, &e.Nickname, &e.Availability); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ResolveNetworkDirectory scans at most two matching authorized rows. The
// ambiguity check is independent of the directory page size.
func (s *Store) ResolveNetworkDirectory(scope NetworkAccessScope, query string) ([]NetworkDirectoryEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	if err := networkGuardAccessTx(tx, scope, "directory.discover", at); err != nil {
		return nil, err
	}
	stamp := at.Format(time.RFC3339)
	rows, err := tx.Query(`SELECT e.network_id,e.endpoint_id,e.nickname,
CASE WHEN f.status!='offline' AND a.status='active' AND a.lease_expires_at>? THEN 'ACCESS_RECENT' ELSE 'UNKNOWN' END
FROM endpoint_network_memberships_v2 e
JOIN fabric_endpoints f ON f.id=e.endpoint_id AND f.status!='left'
JOIN principals p ON p.id=f.principal_id AND p.status='active'
JOIN network_memberships_v2 m ON m.network_id=e.network_id AND m.principal_id=f.principal_id AND m.status='active'
JOIN networks_v2 n ON n.id=e.network_id AND n.state='ACTIVE'
LEFT JOIN network_access_sessions_v2 a ON a.network_id=e.network_id AND a.endpoint_id=e.endpoint_id
WHERE e.network_id=? AND e.status='active' AND e.discoverable=1
AND (m.expires_at='' OR m.expires_at>?)
AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value='directory.publish')
AND ((substr(?,1,3)='ep_' AND e.endpoint_id=?) OR (substr(?,1,3)!='ep_' AND e.nickname=? COLLATE NOCASE))
ORDER BY e.endpoint_id LIMIT 2`, stamp, scope.NetworkID, stamp, query, query, query, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []NetworkDirectoryEntry
	for rows.Next() {
		var e NetworkDirectoryEntry
		if err := rows.Scan(&e.NetworkID, &e.EndpointID, &e.Nickname, &e.Availability); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return entries, nil
}

func validNetworkGrants(grants []string) bool {
	if len(grants) > 32 {
		return false
	}
	allowed := map[string]bool{"directory.discover": true, "directory.publish": true, "direct.send": true, "direct.receive": true, "task.offer.list": true, "task.offer.claim": true, "broadcast.publish": true, "broadcast.receive": true, "network.admin.invite": true, "network.admin.directory_policy": true, "network.admin.task_policy": true, "network.admin.broadcast_policy": true}
	for i, g := range grants {
		if !allowed[g] {
			return false
		}
		if i > 0 && grants[i-1] >= g {
			return false
		}
	}
	return true
}

func (s *Store) IssueNetworkInvitation(networkID, targetOwnerID, issuerID, token, expiresAt string, grants []string) error {
	grants = slices.Clone(grants)
	slices.Sort(grants)
	expiry, parseErr := time.Parse(time.RFC3339Nano, expiresAt)
	if !validNetworkGrants(grants) || networkID == "" || len(networkID) > 256 || targetOwnerID == "" || len(targetOwnerID) > 256 || issuerID == "" || len(issuerID) > 256 || len(token) < 32 || len(token) > 256 || parseErr != nil || expiresAt != expiry.UTC().Format(time.RFC3339Nano) || !expiry.After(time.Now().UTC()) || expiry.After(time.Now().UTC().Add(24*time.Hour)) {
		return ErrNetworkPermission
	}
	encoded, _ := json.Marshal(grants)
	s.mu.Lock()
	defer s.mu.Unlock()
	// This primitive requires its caller to authenticate issuerID; the Store
	// still enforces that an Agent issuer has the narrow invite grant.
	var ownerID string
	if err := s.db.QueryRow(`SELECT owner_id FROM networks_v2 WHERE id=? AND state='ACTIVE'`, networkID).Scan(&ownerID); err != nil {
		return ErrNetworkNotFound
	}
	if issuerID != ownerID {
		var grantsJSON, status, memberExpiry, principalStatus string
		err := s.db.QueryRow(`SELECT m.grants_json,m.status,m.expires_at,p.status FROM network_memberships_v2 m JOIN principals p ON p.id=m.principal_id WHERE m.network_id=? AND m.principal_id=?`, networkID, issuerID).Scan(&grantsJSON, &status, &memberExpiry, &principalStatus)
		if err != nil || status != "active" || principalStatus != PrincipalStatusActive || memberExpiry != "" && memberExpiry <= now() {
			return ErrNetworkPermission
		}
		var issuerGrants []string
		if json.Unmarshal([]byte(grantsJSON), &issuerGrants) != nil {
			return ErrNetworkPermission
		}
		found := false
		for _, g := range issuerGrants {
			if g == "network.admin.invite" {
				found = true
			}
		}
		if !found {
			return ErrNetworkPermission
		}
		for _, grant := range grants {
			if strings.HasPrefix(grant, "network.admin.") || strings.HasPrefix(grant, "broadcast.") || !slices.Contains(issuerGrants, grant) {
				return ErrNetworkPermission
			}
		}
	}
	var pending int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM network_invitations_v2 WHERE network_id=? AND consumed_at='' AND expires_at>?`, networkID, now()).Scan(&pending); err != nil {
		return err
	}
	if pending >= 256 {
		return ErrNetworkPermission
	}
	_, err := s.db.Exec(`INSERT INTO network_invitations_v2(token_hash,network_id,target_owner_id,grants_json,expires_at,issued_by,created_at) VALUES(?,?,?,?,?,?,?)`, tokenDigest(token), networkID, targetOwnerID, string(encoded), expiresAt, issuerID, now())
	return err
}

func (s *Store) RevokeNetworkInvitation(token string) error {
	if len(token) < 32 {
		return ErrNetworkConsent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE network_invitations_v2 SET consumed_at=? WHERE token_hash=? AND consumed_at=''`, now(), tokenDigest(token))
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrNetworkConsent
	}
	return nil
}
