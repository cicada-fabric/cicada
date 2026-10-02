package store

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
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
	return s.setGroupParent(childID, parentID, expectedVersion, "", "")
}

// SetGroupParentForClientRequest fences placement against the accepted
// topology.apply request's current device, Owner key and epoch.
func (s *Store) SetGroupParentForClientRequest(requestID, ownerID, childID, parentID string, expectedVersion int64) (*Group, error) {
	if strings.TrimSpace(requestID) == "" || strings.TrimSpace(ownerID) == "" {
		return nil, ErrNetworkPermission
	}
	if expectedVersion == math.MaxInt64 {
		return nil, ErrVersionConflict
	}
	return s.setGroupParent(childID, parentID, expectedVersion, requestID, ownerID)
}

func (s *Store) setGroupParent(childID, parentID string, expectedVersion int64, requestID, ownerID string) (*Group, error) {
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
	if requestID != "" {
		actor, err := trustedClientTopologyMutationTx(tx, requestID, ownerID)
		if err != nil {
			return nil, err
		}
		if err := guardClientTopologyGroupTx(tx, actor, childID); err != nil {
			return nil, err
		}
		if parentID != "" {
			if err := guardClientTopologyGroupTx(tx, actor, parentID); err != nil {
				return nil, err
			}
		}
	}
	var owner, trustDomain, currentParent, childNetwork string
	var version, revision int64
	err = tx.QueryRow(`SELECT owner_principal_id, trust_domain_id, parent_group_id, network_id, version, revision FROM groups WHERE id = ?`, childID).
		Scan(&owner, &trustDomain, &currentParent, &childNetwork, &version, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGroupNotFound
	}
	if err != nil {
		return nil, err
	}
	if version != expectedVersion {
		return nil, ErrVersionConflict
	}
	if requestID != "" && (version == math.MaxInt64 || revision <= 0 || revision == math.MaxInt64) {
		return nil, ErrVersionConflict
	}
	if parentID != "" {
		var parentOwner, parentDomain, parentNetwork string
		err = tx.QueryRow(`SELECT owner_principal_id, trust_domain_id, network_id FROM groups WHERE id = ?`, parentID).
			Scan(&parentOwner, &parentDomain, &parentNetwork)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrGroupNotFound
		}
		if err != nil {
			return nil, err
		}
		if owner == "" || trustDomain == "" || owner != parentOwner || trustDomain != parentDomain || childNetwork != parentNetwork {
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
