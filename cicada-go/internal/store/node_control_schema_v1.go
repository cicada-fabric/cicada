package store

import "fmt"

// InitializeNodeControlV1Schema adds the independent Node-to-Control key,
// pairing, and exact-retry state. The versioned migration runner calls this
// only after the existing Hub, Client-device, and Node-owner tables exist.
// It does not rewrite or delete any legacy Node credential or replay state.
func (s *Store) InitializeNodeControlV1Schema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS node_control_key_requests_v1 (
  id TEXT PRIMARY KEY,
  mode TEXT NOT NULL CHECK(mode IN ('INITIAL','UPGRADE')),
  hub_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  node_name TEXT NOT NULL,
  node_credential_digest TEXT NOT NULL CHECK(length(node_credential_digest)=43),
  code_digest TEXT NOT NULL UNIQUE CHECK(length(code_digest)=64),
  node_key_id TEXT NOT NULL,
  node_public_identity_json TEXT NOT NULL,
  node_fingerprint TEXT NOT NULL CHECK(length(node_fingerprint)=64),
  node_proof_packet BLOB NOT NULL CHECK(length(node_proof_packet)>0),
  hub_key_id TEXT NOT NULL,
  hub_public_identity_json TEXT NOT NULL,
  hub_key_version INTEGER NOT NULL CHECK(hub_key_version>0),
  hub_fingerprint TEXT NOT NULL CHECK(length(hub_fingerprint)=64),
  candidate_digest TEXT NOT NULL CHECK(length(candidate_digest)=64),
  target_binding_id TEXT NOT NULL DEFAULT '',
  node_key_epoch INTEGER NOT NULL CHECK(node_key_epoch>0),
  state TEXT NOT NULL CHECK(state IN ('PENDING','CONFIRMED','EXPIRED','CANCELLED')),
  version INTEGER NOT NULL CHECK(version>0),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  confirmed_at TEXT NOT NULL DEFAULT '',
  approved_owner_id TEXT NOT NULL DEFAULT '',
  approved_client_device_id TEXT NOT NULL DEFAULT '',
  approved_owner_key_id TEXT NOT NULL DEFAULT '',
  approved_binding_id TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS node_control_key_requests_v1_pending_node_idx
  ON node_control_key_requests_v1(node_id) WHERE state='PENDING';
CREATE INDEX IF NOT EXISTS node_control_key_requests_v1_expiry_idx
  ON node_control_key_requests_v1(state,expires_at);
CREATE TRIGGER IF NOT EXISTS node_control_key_request_candidate_immutable_v1
BEFORE UPDATE OF mode,hub_id,node_id,node_name,node_credential_digest,code_digest,node_key_id,
  node_public_identity_json,node_fingerprint,node_proof_packet,hub_key_id,hub_public_identity_json,
  hub_key_version,hub_fingerprint,candidate_digest,target_binding_id,node_key_epoch,expires_at
ON node_control_key_requests_v1
BEGIN
  SELECT RAISE(ABORT,'Node-Control candidate is immutable');
END;

CREATE TABLE IF NOT EXISTS node_control_key_bindings_v1 (
  id TEXT PRIMARY KEY,
  owner_binding_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  hub_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  node_credential_digest TEXT NOT NULL CHECK(length(node_credential_digest)=43),
  node_credential_version INTEGER NOT NULL CHECK(node_credential_version>0),
  client_device_id TEXT NOT NULL,
  owner_key_id TEXT NOT NULL,
  node_key_id TEXT NOT NULL,
  node_public_identity_json TEXT NOT NULL,
  node_fingerprint TEXT NOT NULL CHECK(length(node_fingerprint)=64),
  node_key_version INTEGER NOT NULL CHECK(node_key_version>0),
  node_key_epoch INTEGER NOT NULL CHECK(node_key_epoch>0),
  hub_key_id TEXT NOT NULL,
  hub_public_identity_json TEXT NOT NULL,
  hub_fingerprint TEXT NOT NULL CHECK(length(hub_fingerprint)=64),
  hub_key_version INTEGER NOT NULL CHECK(hub_key_version>0),
  approved_request_id TEXT NOT NULL,
  approved_request_version INTEGER NOT NULL CHECK(approved_request_version>0),
  approved_candidate_digest TEXT NOT NULL CHECK(length(approved_candidate_digest)=64),
  approved_owner_device_id TEXT NOT NULL,
  approved_owner_key_id TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('ACTIVE','REVOKED')),
  version INTEGER NOT NULL CHECK(version>0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(owner_binding_id) REFERENCES node_owner_bindings_v2(id),
  FOREIGN KEY(approved_request_id) REFERENCES node_control_key_requests_v1(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS node_control_key_bindings_v1_epoch_idx
  ON node_control_key_bindings_v1(node_id,node_key_epoch);
CREATE UNIQUE INDEX IF NOT EXISTS node_control_key_bindings_v1_active_node_idx
  ON node_control_key_bindings_v1(node_id) WHERE state='ACTIVE';
CREATE INDEX IF NOT EXISTS node_control_key_bindings_v1_credential_idx
  ON node_control_key_bindings_v1(node_credential_digest,state);
CREATE TRIGGER IF NOT EXISTS node_control_key_binding_immutable_v1
BEFORE UPDATE OF owner_binding_id,owner_id,hub_id,node_id,node_credential_digest,node_credential_version,
  client_device_id,owner_key_id,node_key_id,node_public_identity_json,node_fingerprint,node_key_version,
  node_key_epoch,hub_key_id,hub_public_identity_json,hub_fingerprint,hub_key_version,approved_request_id,
  approved_request_version,approved_candidate_digest,approved_owner_device_id,approved_owner_key_id,approved_at
ON node_control_key_bindings_v1
BEGIN
  SELECT RAISE(ABORT,'Node-Control key binding is immutable');
END;
CREATE TRIGGER IF NOT EXISTS node_control_owner_binding_revoke_v1
AFTER UPDATE OF state ON node_owner_bindings_v2
WHEN OLD.state='ACTIVE' AND NEW.state='REVOKED'
BEGIN
  UPDATE node_control_key_bindings_v1 SET state='REVOKED',version=version+1,
    updated_at=NEW.updated_at,revoked_at=NEW.revoked_at
  WHERE owner_binding_id=NEW.id AND state='ACTIVE';
  UPDATE node_control_key_requests_v1 SET state='CANCELLED',version=version+1
  WHERE target_binding_id=NEW.id AND mode='UPGRADE' AND state='PENDING';
END;

CREATE TABLE IF NOT EXISTS node_control_rpc_sequences_v1 (
  owner_binding_id TEXT NOT NULL,
  node_key_epoch INTEGER NOT NULL CHECK(node_key_epoch>0),
  last_sequence INTEGER NOT NULL CHECK(last_sequence>=0),
  PRIMARY KEY(owner_binding_id,node_key_epoch),
  FOREIGN KEY(owner_binding_id) REFERENCES node_owner_bindings_v2(id)
);
CREATE TABLE IF NOT EXISTS node_control_rpc_inbox_v1 (
  owner_binding_id TEXT NOT NULL,
  node_key_epoch INTEGER NOT NULL CHECK(node_key_epoch>0),
  sequence INTEGER NOT NULL CHECK(sequence>0),
  operation_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
  response_packet BLOB NOT NULL DEFAULT X'',
  state TEXT NOT NULL CHECK(state IN ('PROCESSING','COMPLETE','UNCERTAIN')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(owner_binding_id,node_key_epoch,sequence),
  UNIQUE(owner_binding_id,node_key_epoch,operation_id),
  FOREIGN KEY(owner_binding_id) REFERENCES node_owner_bindings_v2(id)
);
CREATE INDEX IF NOT EXISTS node_control_rpc_read_retention_v1_idx
  ON node_control_rpc_inbox_v1(created_at)
  WHERE operation IN ('node.binding.status','node.heartbeat','node.jobs.list','node.approvals.status');
CREATE INDEX IF NOT EXISTS node_control_rpc_action_count_v1_idx
  ON node_control_rpc_inbox_v1(owner_binding_id,node_key_epoch)
  WHERE operation IN ('node.jobs.claim','node.jobs.result','node.approvals.create');
CREATE INDEX IF NOT EXISTS node_control_rpc_response_cache_v1_idx
  ON node_control_rpc_inbox_v1(created_at DESC,owner_binding_id,node_key_epoch,sequence)
  WHERE state='COMPLETE' AND response_packet<>X'';
CREATE TRIGGER IF NOT EXISTS node_control_rpc_request_immutable_v1
BEFORE UPDATE OF owner_binding_id,node_key_epoch,sequence,operation_id,operation,request_digest,created_at
ON node_control_rpc_inbox_v1
BEGIN
  SELECT RAISE(ABORT,'Node-Control RPC request is immutable');
END;
`)
	if err != nil {
		return fmt.Errorf("initialize Node-Control v1 schema: %w", err)
	}
	return nil
}
