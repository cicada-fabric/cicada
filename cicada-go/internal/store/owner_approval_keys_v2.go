package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	OwnerApprovalKeyActive  = "ACTIVE"
	OwnerApprovalKeyRevoked = "REVOKED"
)

var (
	ErrOwnerApprovalKeyNotFound = errors.New("owner approval key not found")
	ErrOwnerApprovalKeyConflict = errors.New("owner approval key conflicts with existing or revoked trust")
)

// OwnerApprovalKey is public material for a user-held signing identity. It
// must be registered by an independently trusted local bootstrap, never by a
// Node credential, Fabric session, model tool, or the manager bearer alone.
// The Hub holds no owner signing private key.
type OwnerApprovalKey struct {
	OwnerID   string              `json:"owner_id"`
	KeyID     string              `json:"key_id"`
	Public    e2ee.PublicIdentity `json:"public_identity"`
	State     string              `json:"state"`
	Version   int64               `json:"version"`
	CreatedAt string              `json:"created_at"`
	UpdatedAt string              `json:"updated_at"`
	RevokedAt string              `json:"revoked_at,omitempty"`
}

func (s *Store) initializeOwnerApprovalKeySchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS owner_approval_keys_v2 (
  owner_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  public_identity_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'REVOKED')),
  version INTEGER NOT NULL CHECK(version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(owner_id, key_id)
);
CREATE INDEX IF NOT EXISTS owner_approval_keys_v2_owner_state_idx
  ON owner_approval_keys_v2(owner_id, state, key_id);`)
	if err != nil {
		return fmt.Errorf("initialize owner approval keys: %w", err)
	}
	return nil
}

func validateOwnerApprovalID(ownerID string) error {
	if ownerID == "" || len(ownerID) > 256 || !utf8.ValidString(ownerID) ||
		strings.ContainsAny(ownerID, "/\\") {
		return errors.New("owner approval identity is invalid")
	}
	for _, char := range ownerID {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return errors.New("owner approval identity is invalid")
		}
	}
	return nil
}

// RegisterOwnerApprovalKeyLocal is an offline trust-root operation. Its caller
// must have direct local authority over the Hub state database and must verify
// the owner/key association out of band. Do not expose it behind the manager
// bearer or any Node/Fabric HTTP credential. It never rotates or reactivates a
// key: those require a separate explicitly authorized ceremony.
func (s *Store) RegisterOwnerApprovalKeyLocal(ownerID string, public e2ee.PublicIdentity) (*OwnerApprovalKey, error) {
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	if err := e2ee.ValidatePublicIdentity(public); err != nil {
		return nil, fmt.Errorf("validate owner approval public identity: %w", err)
	}
	encoded, err := json.Marshal(public)
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
	var storedPublic, state string
	err = tx.QueryRow(`SELECT public_identity_json, state FROM owner_approval_keys_v2
WHERE owner_id = ? AND key_id = ?`, ownerID, public.ID).Scan(&storedPublic, &state)
	if err == nil {
		if storedPublic != string(encoded) || state != OwnerApprovalKeyActive {
			return nil, ErrOwnerApprovalKeyConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return s.getOwnerApprovalKeyLocked(ownerID, public.ID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	stamp := now()
	_, err = tx.Exec(`INSERT INTO owner_approval_keys_v2
(owner_id, key_id, public_identity_json, state, version, created_at, updated_at)
VALUES (?, ?, ?, 'ACTIVE', 1, ?, ?)`, ownerID, public.ID, string(encoded), stamp, stamp)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getOwnerApprovalKeyLocked(ownerID, public.ID)
}

func scanOwnerApprovalKey(row v2Scanner) (*OwnerApprovalKey, error) {
	var key OwnerApprovalKey
	var encoded string
	err := row.Scan(&key.OwnerID, &key.KeyID, &encoded, &key.State,
		&key.Version, &key.CreatedAt, &key.UpdatedAt, &key.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOwnerApprovalKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(encoded), &key.Public); err != nil {
		return nil, err
	}
	if err := e2ee.ValidatePublicIdentity(key.Public); err != nil || key.KeyID != key.Public.ID {
		return nil, ErrOwnerApprovalKeyConflict
	}
	return &key, nil
}

func (s *Store) getOwnerApprovalKeyLocked(ownerID, keyID string) (*OwnerApprovalKey, error) {
	return scanOwnerApprovalKey(s.db.QueryRow(`SELECT owner_id, key_id, public_identity_json,
state, version, created_at, updated_at, revoked_at FROM owner_approval_keys_v2
WHERE owner_id = ? AND key_id = ?`, ownerID, keyID))
}

func (s *Store) GetOwnerApprovalKey(ownerID, keyID string) (*OwnerApprovalKey, error) {
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(keyID) == "" {
		return nil, ErrOwnerApprovalKeyNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getOwnerApprovalKeyLocked(ownerID, keyID)
}

// RevokeOwnerApprovalKeyLocal permanently fences a user-held approval key.
// Retaining the row prevents a stale backup or replayed registration from
// silently turning a revoked public key back into a trusted key.
func (s *Store) RevokeOwnerApprovalKeyLocal(ownerID, keyID string, expectedVersion int64) (*OwnerApprovalKey, error) {
	if err := validateOwnerApprovalID(ownerID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(keyID) == "" || expectedVersion <= 0 {
		return nil, ErrOwnerApprovalKeyNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var version int64
	var state string
	err = tx.QueryRow(`SELECT version, state FROM owner_approval_keys_v2
WHERE owner_id = ? AND key_id = ?`, ownerID, keyID).Scan(&version, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOwnerApprovalKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if version != expectedVersion || state != OwnerApprovalKeyActive {
		return nil, ErrVersionConflict
	}
	stamp := now()
	result, err := tx.Exec(`UPDATE owner_approval_keys_v2
SET state = 'REVOKED', version = version + 1, updated_at = ?, revoked_at = ?
WHERE owner_id = ? AND key_id = ? AND version = ? AND state = 'ACTIVE'`,
		stamp, stamp, ownerID, keyID, expectedVersion)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, ErrVersionConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getOwnerApprovalKeyLocked(ownerID, keyID)
}
