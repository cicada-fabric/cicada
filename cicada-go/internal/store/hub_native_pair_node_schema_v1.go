package store

// v64 is retained verbatim. Old opaque Node receipts have no trustworthy Hub
// outcome projection; UNKNOWN stays unresolved instead of guessing from slots.
func (s *Store) initializeHubNativePairNodeSchema() error {
	_, err := s.db.Exec(`
ALTER TABLE hub_native_pairs_v1 ADD COLUMN account_hub_identity_json TEXT NOT NULL DEFAULT '';
CREATE TRIGGER hub_native_pairs_v1_account_hub BEFORE UPDATE ON hub_native_pairs_v1 WHEN OLD.account_hub_identity_json!='' AND NEW.account_hub_identity_json!=OLD.account_hub_identity_json BEGIN SELECT RAISE(ABORT,'native pair Hub public identity is immutable'); END;
CREATE INDEX hub_native_pairs_v1_node_history ON hub_native_pairs_v1(hub_id,node_id);
ALTER TABLE hub_native_pair_node_operations_v1 ADD COLUMN outcome TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK(outcome IN('UNKNOWN','COMPLETED','REJECTED_FENCED'));
CREATE TABLE hub_native_pair_node_reads_v1(
 owner_binding_id TEXT NOT NULL,node_key_epoch INTEGER NOT NULL,operation_id TEXT NOT NULL,
 operation TEXT NOT NULL,sequence INTEGER NOT NULL,pair_id TEXT NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN('COMPLETED','REJECTED_FENCED','READ_EXPIRED')),
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),nonce_digest TEXT NOT NULL CHECK(length(nonce_digest)=64),
 response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=393216),created_at TEXT NOT NULL,
 PRIMARY KEY(owner_binding_id,node_key_epoch,operation_id),UNIQUE(owner_binding_id,node_key_epoch,nonce_digest));
CREATE TABLE hub_native_pair_node_rates_v1(
 owner_binding_id TEXT NOT NULL,node_key_epoch INTEGER NOT NULL,window_start TEXT NOT NULL,
 requests INTEGER NOT NULL CHECK(requests>=0 AND requests<=128),PRIMARY KEY(owner_binding_id,node_key_epoch));`)
	return err
}
