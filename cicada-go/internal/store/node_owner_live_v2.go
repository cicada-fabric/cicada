package store

import (
	"database/sql"
	"errors"
	"strings"
)

// CurrentBoundNodeOwner reports the owner of a currently authorized Node
// credential without exposing that credential. Guest Fabric sessions use it
// on every access so revoking or rebinding the Node fences their Session
// tokens as well as the Node transport bearer.
func (s *Store) CurrentBoundNodeOwner(nodeID string) (string, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return "", ErrNodeCredentialNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var ownerID string
	err := s.db.QueryRow(`SELECT binding.owner_id
FROM node_owner_bindings_v2 binding
JOIN fabric_node_credentials credential ON credential.node_id=binding.node_id
  AND credential.credential_hash=binding.node_credential_digest
  AND credential.version=binding.node_credential_version AND credential.status='active'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN principals principal ON principal.id=binding.owner_id
  AND principal.kind='human' AND principal.status='active'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
  AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
WHERE binding.node_id=? AND binding.state='ACTIVE'`, nodeID).Scan(&ownerID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNodeCredentialNotFound
	}
	return ownerID, err
}
