package store

import "fmt"

// InitializeNodeControlSnapshotV1Schema installs the retention indexes for
// the two streamed workspace snapshot operations. Uploads are action
// tombstones and therefore share the bounded action ledger; downloads are
// read-only and use the existing 24-hour retention policy.
func (s *Store) InitializeNodeControlSnapshotV1Schema() error {
	_, err := s.db.Exec(`
CREATE INDEX IF NOT EXISTS node_control_rpc_snapshot_read_v1_idx
  ON node_control_rpc_inbox_v1(created_at)
  WHERE operation='node.workspace.snapshot.download';
CREATE INDEX IF NOT EXISTS node_control_rpc_snapshot_action_v1_idx
  ON node_control_rpc_inbox_v1(owner_binding_id,node_key_epoch)
  WHERE operation='node.workspace.snapshot.upload';
`)
	if err != nil {
		return fmt.Errorf("initialize Node-Control workspace snapshot schema: %w", err)
	}
	return nil
}

// InitializeNodeControlSnapshotRPCProjectionV1Schema adds the durable server
// projection needed to replay completed download responses without asking the
// Hub to decrypt its own Hub-to-Node packet. The inbox foreign key makes the
// projection follow the same bounded read-record retention as its request.
func (s *Store) InitializeNodeControlSnapshotRPCProjectionV1Schema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS node_control_snapshot_rpc_responses_v1 (
  owner_binding_id TEXT NOT NULL,
  node_key_epoch INTEGER NOT NULL CHECK(node_key_epoch>0),
  sequence INTEGER NOT NULL CHECK(sequence>0),
  operation_id TEXT NOT NULL,
  request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
  request_route_digest TEXT NOT NULL CHECK(length(request_route_digest)=64),
  manifest_json TEXT NOT NULL DEFAULT '',
  error_code TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(owner_binding_id,node_key_epoch,sequence,operation_id),
  CHECK((manifest_json<>'' AND error_code='') OR (manifest_json='' AND error_code<>'')),
  FOREIGN KEY(owner_binding_id,node_key_epoch,sequence)
    REFERENCES node_control_rpc_inbox_v1(owner_binding_id,node_key_epoch,sequence) ON DELETE CASCADE
);
CREATE TRIGGER IF NOT EXISTS node_control_snapshot_rpc_response_guard_v1
BEFORE INSERT ON node_control_snapshot_rpc_responses_v1
WHEN NOT EXISTS (
  SELECT 1 FROM node_control_rpc_inbox_v1 AS inbox
  WHERE inbox.owner_binding_id=NEW.owner_binding_id
    AND inbox.node_key_epoch=NEW.node_key_epoch
    AND inbox.sequence=NEW.sequence
    AND inbox.operation_id=NEW.operation_id
    AND inbox.operation='node.workspace.snapshot.download'
    AND inbox.request_digest=NEW.request_digest
    AND inbox.state='COMPLETE'
)
BEGIN
  SELECT RAISE(ABORT,'Node-Control snapshot projection has no matching completed download');
END;`)
	if err != nil {
		return fmt.Errorf("initialize Node-Control snapshot response projection: %w", err)
	}
	return nil
}
