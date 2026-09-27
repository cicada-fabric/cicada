package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// EndpointGroupMembership records which Groups a single stable Endpoint has
// explicitly joined. Principal Membership remains the authorization source;
// this relation never grants a role or a permission by itself.
type EndpointGroupMembership struct {
	EndpointID string `json:"endpoint_id"`
	GroupID    string `json:"group_id"`
	Status     string `json:"status"`
	Revision   int64  `json:"revision"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

var ErrEndpointGroupNotFound = errors.New("endpoint group membership not found")

const endpointGroupColumns = "endpoint_id, group_id, status, revision, created_at, updated_at"

func (s *Store) initializeEndpointGroupMembershipSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS endpoint_group_memberships (
  endpoint_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
  revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(endpoint_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_group_memberships_group
  ON endpoint_group_memberships(group_id, status, endpoint_id);
INSERT INTO endpoint_group_memberships(endpoint_id, group_id, status, revision, created_at, updated_at)
SELECT e.id, e.group_id,
       CASE WHEN e.status = 'left' OR m.status != 'active' OR p.status != 'active'
                 OR g.state != 'ACTIVE' OR (m.expires_at != '' AND m.expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            THEN 'revoked' ELSE 'active' END,
       1, e.created_at, e.updated_at
FROM fabric_endpoints e
JOIN memberships m ON m.principal_id = e.principal_id AND m.group_id = e.group_id
JOIN principals p ON p.id = e.principal_id
JOIN groups g ON g.id = e.group_id
WHERE e.migration_state = 'READY' AND e.group_id != ''
ON CONFLICT(endpoint_id, group_id) DO NOTHING;
`)
	if err != nil {
		return fmt.Errorf("initialize endpoint group memberships: %w", err)
	}
	return nil
}

func upsertEndpointGroupMembershipTx(tx *sql.Tx, endpointID, groupID string) error {
	timestamp := now()
	_, err := tx.Exec(`INSERT INTO endpoint_group_memberships
  (endpoint_id, group_id, status, revision, created_at, updated_at)
VALUES (?, ?, 'active', 1, ?, ?)
ON CONFLICT(endpoint_id, group_id) DO UPDATE SET
  status = 'active', revision = endpoint_group_memberships.revision + 1,
  updated_at = excluded.updated_at
WHERE endpoint_group_memberships.status != 'active'`, endpointID, groupID, timestamp, timestamp)
	return err
}

func scanEndpointGroupMembership(row v2Scanner) (*EndpointGroupMembership, error) {
	var membership EndpointGroupMembership
	if err := row.Scan(&membership.EndpointID, &membership.GroupID, &membership.Status,
		&membership.Revision, &membership.CreatedAt, &membership.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEndpointGroupNotFound
		}
		return nil, err
	}
	return &membership, nil
}

func (s *Store) GetEndpointGroupMembership(endpointID, groupID string) (*EndpointGroupMembership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanEndpointGroupMembership(s.db.QueryRow(`SELECT `+endpointGroupColumns+
		` FROM endpoint_group_memberships WHERE endpoint_id = ? AND group_id = ?`,
		strings.TrimSpace(endpointID), strings.TrimSpace(groupID)))
}

// IsEndpointGroupActive checks both the Endpoint join and its Principal's
// current authorization. Callers use this at routing/delivery boundaries;
// reading the relation alone is insufficient after Principal revocation.
func (s *Store) IsEndpointGroupActive(endpointID, groupID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var active int
	err := s.db.QueryRow(`SELECT 1 FROM fabric_endpoints e
JOIN endpoint_group_memberships eg ON eg.endpoint_id = e.id AND eg.group_id = ?
JOIN memberships m ON m.principal_id = e.principal_id AND m.group_id = eg.group_id
JOIN principals p ON p.id = e.principal_id
JOIN groups g ON g.id = eg.group_id
JOIN network_mode_v2 nm ON nm.id = 1
WHERE e.id = ? AND e.migration_state = 'READY' AND e.status != 'left'
  AND eg.status = 'active' AND m.status = 'active' AND p.status = 'active'
	AND g.state = 'ACTIVE' AND (m.expires_at = '' OR m.expires_at > ?)
	AND ((g.network_id = '' AND nm.phase = 'PREPARING') OR
	 (g.network_id <> '' AND EXISTS (
	   SELECT 1 FROM networks_v2 n
	   JOIN network_memberships_v2 nm2 ON nm2.network_id=n.id AND nm2.principal_id=e.principal_id AND nm2.status='active'
	   JOIN endpoint_network_memberships_v2 en ON en.network_id=n.id AND en.endpoint_id=e.id AND en.status='active'
	   WHERE n.id=g.network_id AND n.state='ACTIVE' AND (nm2.expires_at='' OR nm2.expires_at>?))))`,
		strings.TrimSpace(groupID), strings.TrimSpace(endpointID), now(), now()).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && active == 1, err
}

func (s *Store) ListEndpointGroupMemberships(endpointID string) ([]EndpointGroupMembership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT `+endpointGroupColumns+
		` FROM endpoint_group_memberships WHERE endpoint_id = ? ORDER BY group_id`, strings.TrimSpace(endpointID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]EndpointGroupMembership, 0)
	for rows.Next() {
		membership, err := scanEndpointGroupMembership(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *membership)
	}
	return result, rows.Err()
}

// JoinEndpointGroup records a second (or subsequent) explicit Group join for
// an already bound Endpoint. It does not mutate the native SessionBinding or
// legacy primary group projection. Callers must authenticate the enrollment
// action before invoking this store method.
func (s *Store) JoinEndpointGroup(endpointID, groupID string) (*EndpointGroupMembership, error) {
	endpointID, groupID = strings.TrimSpace(endpointID), strings.TrimSpace(groupID)
	if endpointID == "" || groupID == "" {
		return nil, errors.New("endpoint and group are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(cause error) (*EndpointGroupMembership, error) {
		_ = tx.Rollback()
		return nil, cause
	}
	var principalID, migrationState, endpointStatus, bindingID, nativeSessionID string
	if err := tx.QueryRow(`SELECT principal_id, migration_state, status, binding_id, native_session_id FROM fabric_endpoints WHERE id = ?`, endpointID).
		Scan(&principalID, &migrationState, &endpointStatus, &bindingID, &nativeSessionID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrEndpointNotFound)
		}
		return rollback(err)
	}
	if migrationState != EndpointMigrationReady || principalID == "" || endpointStatus == "left" || bindingID == "" {
		return rollback(ErrEndpointMigrationRequired)
	}
	var bindingPrincipal, bindingNative, bindingStatus string
	if err := tx.QueryRow(`SELECT principal_id, native_session_id, status FROM session_bindings WHERE id = ? AND endpoint_id = ?`, bindingID, endpointID).
		Scan(&bindingPrincipal, &bindingNative, &bindingStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrSessionBindingNotFound)
		}
		return rollback(err)
	}
	if bindingPrincipal != principalID || bindingNative != nativeSessionID || !isActiveBindingStatus(bindingStatus) {
		return rollback(ErrSessionBindingInactive)
	}
	if err := s.requireActiveMembershipTx(tx, principalID, groupID); err != nil {
		return rollback(err)
	}
	if err := upsertEndpointGroupMembershipTx(tx, endpointID, groupID); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return scanEndpointGroupMembership(s.db.QueryRow(`SELECT `+endpointGroupColumns+
		` FROM endpoint_group_memberships WHERE endpoint_id = ? AND group_id = ?`, endpointID, groupID))
}

// LeaveEndpointGroup removes only the selected Group from this native
// Endpoint. The binding is fenced and the Endpoint marked left atomically
// only when no other authorized Group remains.
func (s *Store) LeaveEndpointGroup(endpointID, groupID, bindingID string, expectedEpoch uint64, reason string) (string, error) {
	endpointID, groupID, bindingID = strings.TrimSpace(endpointID), strings.TrimSpace(groupID), strings.TrimSpace(bindingID)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	rollback := func(cause error) (string, error) {
		_ = tx.Rollback()
		return "", cause
	}
	var principalID, status string
	var epoch uint64
	if err := tx.QueryRow(`SELECT principal_id, status, epoch FROM session_bindings
WHERE id = ? AND endpoint_id = ?`, bindingID, endpointID).Scan(&principalID, &status, &epoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrSessionBindingNotFound)
		}
		return rollback(err)
	}
	if epoch != expectedEpoch || !isActiveBindingStatus(status) {
		return rollback(ErrSessionBindingStaleEpoch)
	}
	timestamp := now()
	result, err := tx.Exec(`UPDATE endpoint_group_memberships
SET status = 'revoked', revision = revision + 1, updated_at = ?
WHERE endpoint_id = ? AND group_id = ? AND status = 'active'`, timestamp, endpointID, groupID)
	if err != nil {
		return rollback(err)
	}
	if changed, err := result.RowsAffected(); err != nil {
		return rollback(err)
	} else if changed != 1 {
		return rollback(ErrEndpointGroupNotFound)
	}
	var remaining string
	err = tx.QueryRow(`SELECT eg.group_id FROM endpoint_group_memberships eg
JOIN memberships m ON m.principal_id = ? AND m.group_id = eg.group_id
JOIN groups g ON g.id = eg.group_id
WHERE eg.endpoint_id = ? AND eg.status = 'active' AND m.status = 'active'
  AND g.state = 'ACTIVE' AND (m.expires_at = '' OR m.expires_at > ?)
ORDER BY eg.group_id LIMIT 1`, principalID, endpointID, timestamp).Scan(&remaining)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return rollback(err)
	}
	if remaining == "" {
		result, err = tx.Exec(`UPDATE session_bindings
SET status = ?, lease_owner = '', lease_expires_at = '', epoch = epoch + 1,
    version = version + 1, revocation_reason = ?, updated_at = ?
WHERE id = ? AND endpoint_id = ? AND epoch = ?`, SessionBindingStatusRevoked,
			reason, timestamp, bindingID, endpointID, expectedEpoch)
		if err != nil {
			return rollback(err)
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			if err != nil {
				return rollback(err)
			}
			return rollback(ErrSessionBindingStaleEpoch)
		}
		if _, err := tx.Exec(`UPDATE fabric_endpoints SET status = 'left', updated_at = ?
WHERE id = ? AND binding_id = ?`, timestamp, endpointID, bindingID); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return remaining, nil
}

// LeaveEndpointAllGroups atomically withdraws every address of one native
// Endpoint and fences its exact SessionBinding epoch.
func (s *Store) LeaveEndpointAllGroups(endpointID, bindingID string, expectedEpoch uint64, reason string) error {
	endpointID, bindingID = strings.TrimSpace(endpointID), strings.TrimSpace(bindingID)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		_ = tx.Rollback()
		return cause
	}
	timestamp := now()
	result, err := tx.Exec(`UPDATE session_bindings
SET status = ?, lease_owner = '', lease_expires_at = '', epoch = epoch + 1,
    version = version + 1, revocation_reason = ?, updated_at = ?
WHERE id = ? AND endpoint_id = ? AND epoch = ?
  AND status IN ('active', 'leased', 'online', 'ready', 'acquired')`,
		SessionBindingStatusRevoked, reason, timestamp, bindingID, endpointID, expectedEpoch)
	if err != nil {
		return rollback(err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		if err != nil {
			return rollback(err)
		}
		return rollback(ErrSessionBindingStaleEpoch)
	}
	if _, err := tx.Exec(`UPDATE endpoint_group_memberships
SET status = 'revoked', revision = revision + 1, updated_at = ?
WHERE endpoint_id = ? AND status = 'active'`, timestamp, endpointID); err != nil {
		return rollback(err)
	}
	if _, err := tx.Exec(`UPDATE fabric_endpoints SET status = 'left', updated_at = ?
WHERE id = ? AND binding_id = ?`, timestamp, endpointID, bindingID); err != nil {
		return rollback(err)
	}
	return tx.Commit()
}
