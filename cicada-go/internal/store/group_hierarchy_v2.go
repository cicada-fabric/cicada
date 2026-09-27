package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrGroupHierarchyCycle   = errors.New("group hierarchy cycle")
	ErrGroupParentOwnerScope = errors.New("parent group belongs to another owner or trust domain")
)

func (s *Store) initializeGroupHierarchyV2Schema() error {
	if err := s.ensureColumn("groups", "parent_group_id", `ALTER TABLE groups ADD COLUMN parent_group_id TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	_, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS groups_parent_idx ON groups(parent_group_id, id)`)
	return err
}

// SetGroupParent edits only the management topology. It deliberately does not
// change Memberships, Endpoint joins, message visibility, or encryption keys.
// Both groups must be owned within the same trust domain; a future cross-owner
// hierarchy requires a separate bilateral management contract.
func (s *Store) SetGroupParent(childID, parentID string, expectedVersion int64) (*Group, error) {
	childID, parentID = strings.TrimSpace(childID), strings.TrimSpace(parentID)
	if childID == "" {
		return nil, ErrGroupNotFound
	}
	if expectedVersion <= 0 {
		return nil, errors.New("expected group version is required")
	}
	if parentID == childID {
		return nil, ErrGroupHierarchyCycle
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var owner, trustDomain, currentParent string
	var version int64
	err = tx.QueryRow(`SELECT owner_principal_id, trust_domain_id, parent_group_id, version FROM groups WHERE id = ?`, childID).
		Scan(&owner, &trustDomain, &currentParent, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGroupNotFound
	}
	if err != nil {
		return nil, err
	}
	if version != expectedVersion {
		return nil, ErrVersionConflict
	}
	if parentID != "" {
		var parentOwner, parentDomain string
		err = tx.QueryRow(`SELECT owner_principal_id, trust_domain_id FROM groups WHERE id = ?`, parentID).
			Scan(&parentOwner, &parentDomain)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrGroupNotFound
		}
		if err != nil {
			return nil, err
		}
		if owner == "" || trustDomain == "" || owner != parentOwner || trustDomain != parentDomain {
			return nil, ErrGroupParentOwnerScope
		}
		var cycle int
		err = tx.QueryRow(`WITH RECURSIVE ancestors(id) AS (
  SELECT ?
  UNION
  SELECT g.parent_group_id FROM groups g JOIN ancestors a ON g.id = a.id
  WHERE g.parent_group_id <> ''
)
SELECT 1 FROM ancestors WHERE id = ? LIMIT 1`, parentID, childID).Scan(&cycle)
		if err == nil {
			return nil, ErrGroupHierarchyCycle
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("inspect group ancestors: %w", err)
		}
	}
	if currentParent == parentID {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return scanGroup(s.db.QueryRow(`SELECT `+groupColumns+` FROM groups WHERE id = ?`, childID))
	}
	result, err := tx.Exec(`UPDATE groups SET parent_group_id = ?, version = version + 1,
revision = revision + 1, updated_at = ? WHERE id = ? AND version = ?`, parentID, now(), childID, expectedVersion)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, ErrVersionConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return scanGroup(s.db.QueryRow(`SELECT `+groupColumns+` FROM groups WHERE id = ?`, childID))
}
