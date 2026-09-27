package store

import (
	"database/sql"
	"errors"
	"strings"
)

const (
	NodeCredentialActive  = "active"
	NodeCredentialRevoked = "revoked"
)

var ErrNodeCredentialNotFound = errors.New("node credential not found")

// NodeCredential stores only a digest of the machine-side Relay credential.
// The plaintext credential is returned once by the management plane and is
// never part of a Machine capability document or a Node delivery envelope.
type NodeCredential struct {
	NodeID         string `json:"node_id"`
	CredentialHash string `json:"-"`
	Version        int64  `json:"version"`
	Status         string `json:"status"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

func (s *Store) initializeNodeCredentialSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS fabric_node_credentials (
  node_id TEXT PRIMARY KEY,
  credential_hash TEXT NOT NULL UNIQUE,
  version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
  status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS fabric_node_credentials_hash_idx
  ON fabric_node_credentials(credential_hash, status);
`)
	return err
}

func scanNodeCredential(row *sql.Row) (*NodeCredential, error) {
	var credential NodeCredential
	err := row.Scan(&credential.NodeID, &credential.CredentialHash, &credential.Version,
		&credential.Status, &credential.CreatedAt, &credential.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeCredentialNotFound
	}
	if err != nil {
		return nil, err
	}
	return &credential, nil
}

// RotateNodeCredential replaces the only active credential for a Node. It is
// a management-plane operation; callers must authenticate the operator before
// invoking it and must persist only the supplied digest.
func (s *Store) RotateNodeCredential(nodeID, credentialHash string) (*NodeCredential, error) {
	nodeID = strings.TrimSpace(nodeID)
	credentialHash = strings.TrimSpace(credentialHash)
	if nodeID == "" || credentialHash == "" {
		return nil, errors.New("node_id and credential hash are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	timestamp := now()
	_, err := s.db.Exec(`INSERT INTO fabric_node_credentials
(node_id, credential_hash, version, status, created_at, updated_at)
VALUES (?, ?, 1, ?, ?, ?)
ON CONFLICT(node_id) DO UPDATE SET
 credential_hash = excluded.credential_hash,
 version = fabric_node_credentials.version + 1,
 status = excluded.status,
 updated_at = excluded.updated_at`, nodeID, credentialHash, NodeCredentialActive, timestamp, timestamp)
	if err != nil {
		return nil, err
	}
	return scanNodeCredential(s.db.QueryRow(`SELECT node_id, credential_hash, version, status, created_at, updated_at
FROM fabric_node_credentials WHERE node_id = ?`, nodeID))
}

func (s *Store) GetNodeCredentialByHash(credentialHash string) (*NodeCredential, error) {
	credentialHash = strings.TrimSpace(credentialHash)
	if credentialHash == "" {
		return nil, ErrNodeCredentialNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanNodeCredential(s.db.QueryRow(`SELECT node_id, credential_hash, version, status, created_at, updated_at
FROM fabric_node_credentials WHERE credential_hash = ? AND status = ?`, credentialHash, NodeCredentialActive))
}
