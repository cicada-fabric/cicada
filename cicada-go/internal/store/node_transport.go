package store

import (
	"database/sql"
	"errors"
)

// NodeTransportBinding is a current authorization snapshot, not a TLS epoch,
// native SessionBinding epoch, Network access epoch or Node-Control key version.
type NodeTransportBinding struct {
	HubID, NodeID, OwnerID, OwnerKeyID, BindingID string
	BindingVersion, CredentialVersion             int64
}

func (s *Store) CurrentNodeTransportBinding(nodeID string) (*NodeTransportBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b NodeTransportBinding
	err := s.db.QueryRow(`SELECT binding.hub_id,binding.node_id,binding.owner_id,
binding.owner_key_id,binding.id,binding.version,credential.version
FROM node_owner_bindings_v2 binding
JOIN fabric_node_credentials credential ON credential.node_id=binding.node_id
 AND credential.credential_hash=binding.node_credential_digest
 AND credential.version=binding.node_credential_version AND credential.status='active'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN principals principal ON principal.id=binding.owner_id
 AND principal.kind='human' AND principal.status='active'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
 AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
WHERE binding.node_id=? AND binding.state='ACTIVE'`, nodeID).Scan(&b.HubID, &b.NodeID, &b.OwnerID, &b.OwnerKeyID, &b.BindingID, &b.BindingVersion, &b.CredentialVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeCredentialNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}
