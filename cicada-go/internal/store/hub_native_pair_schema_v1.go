package store

// Pair history is independent of login leases and the old N2/N3 grant heads.
// Receipt/fence, slot-generation and message ledgers are never read caches.
func (s *Store) initializeHubNativePairSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE hub_native_pair_guard_v1(id INTEGER PRIMARY KEY CHECK(id=1),touched_at TEXT NOT NULL);
INSERT INTO hub_native_pair_guard_v1 VALUES(1,'');
CREATE TABLE hub_native_pairs_v1(
 pair_id TEXT PRIMARY KEY,hub_id TEXT NOT NULL,account_id TEXT NOT NULL,owner_id TEXT NOT NULL,device_id TEXT NOT NULL,node_id TEXT NOT NULL,
 network_id TEXT NOT NULL UNIQUE,group_id TEXT NOT NULL UNIQUE,scope_json TEXT NOT NULL,bootstrap_json TEXT NOT NULL,
 bootstrap_owner_proof BLOB,state TEXT NOT NULL CHECK(state IN('PREPARED','WAITING_JOIN','WAITING_CONSENT','ACTIVE','EXPIRED','REVOKED')),
 control_revision INTEGER NOT NULL CHECK(control_revision>0),plan_id TEXT NOT NULL DEFAULT '',
 prepare_operation_id TEXT NOT NULL,proof_expires_at TEXT NOT NULL,join_until TEXT NOT NULL,peer_expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL,terminal_reason TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX hub_native_pairs_v1_nonterminal ON hub_native_pairs_v1(owner_id,hub_id,node_id) WHERE state IN('PREPARED','WAITING_JOIN','WAITING_CONSENT','ACTIVE');
CREATE TABLE hub_native_pair_slots_v1(
 pair_id TEXT NOT NULL,slot TEXT NOT NULL CHECK(slot IN('A','B')),generation INTEGER NOT NULL CHECK(generation>=1 AND generation<=16),
 state TEXT NOT NULL CHECK(state IN('RESERVED','JOINED_ZERO','ACTIVE','REJECTED')),
 attempt_id TEXT NOT NULL DEFAULT '',native_session_id TEXT NOT NULL DEFAULT '',endpoint_id TEXT NOT NULL DEFAULT '',principal_id TEXT NOT NULL DEFAULT '',
 network_access_binding_id TEXT NOT NULL DEFAULT '',binding_id TEXT NOT NULL DEFAULT '',lease_owner TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,
 PRIMARY KEY(pair_id,slot,generation),FOREIGN KEY(pair_id) REFERENCES hub_native_pairs_v1(pair_id));
CREATE UNIQUE INDEX hub_native_pair_slots_v1_current ON hub_native_pair_slots_v1(pair_id,slot) WHERE state!='REJECTED';
CREATE UNIQUE INDEX hub_native_pair_slots_v1_native ON hub_native_pair_slots_v1(pair_id,native_session_id) WHERE native_session_id!='' AND state!='REJECTED';
CREATE TABLE hub_native_pair_plans_v1(plan_id TEXT PRIMARY KEY,pair_id TEXT NOT NULL,plan_json TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('PREPARED','ACTIVE','INVALIDATED','EXPIRED')),created_at TEXT NOT NULL,FOREIGN KEY(pair_id) REFERENCES hub_native_pairs_v1(pair_id));
CREATE UNIQUE INDEX hub_native_pair_plans_v1_current ON hub_native_pair_plans_v1(pair_id) WHERE state='PREPARED';
CREATE TABLE hub_native_pair_consents_v1(plan_id TEXT NOT NULL,slot TEXT NOT NULL CHECK(slot IN('A','B')),owner_proof BLOB NOT NULL,group_key_proof BLOB NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(plan_id,slot),FOREIGN KEY(plan_id) REFERENCES hub_native_pair_plans_v1(plan_id));
CREATE TABLE hub_native_pair_operations_v1(owner_id TEXT NOT NULL,device_id TEXT NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,pair_id TEXT NOT NULL DEFAULT '',request_digest TEXT NOT NULL CHECK(length(request_digest)=64),state TEXT NOT NULL CHECK(state IN('COMPLETED','REJECTED_FENCED')),nonce_digest TEXT NOT NULL DEFAULT '' CHECK(length(nonce_digest) IN(0,64)),response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=262144),created_at TEXT NOT NULL,PRIMARY KEY(owner_id,device_id,operation_id));
CREATE UNIQUE INDEX hub_native_pair_operations_v1_nonce ON hub_native_pair_operations_v1(owner_id,device_id,nonce_digest) WHERE nonce_digest!='';
CREATE TABLE hub_native_pair_reads_v1(owner_id TEXT NOT NULL,device_id TEXT NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,pair_id TEXT NOT NULL DEFAULT '',request_digest TEXT NOT NULL CHECK(length(request_digest)=64),state TEXT NOT NULL CHECK(state IN('COMPLETED','REJECTED_FENCED','READ_EXPIRED')),response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=655360),created_at TEXT NOT NULL,PRIMARY KEY(owner_id,device_id,operation_id));
CREATE TABLE hub_native_pair_rates_v1(owner_id TEXT NOT NULL,device_id TEXT NOT NULL,window_start TEXT NOT NULL,requests INTEGER NOT NULL CHECK(requests>=0 AND requests<=128),PRIMARY KEY(owner_id,device_id));
CREATE TABLE hub_native_pair_messages_v1(pair_id TEXT NOT NULL,message_id TEXT NOT NULL,request_id TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN('ASK','REPLY')),ciphertext_digest TEXT NOT NULL CHECK(length(ciphertext_digest)=64),ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes>0 AND ciphertext_bytes<=131072),sender_endpoint_id TEXT NOT NULL,receiver_endpoint_id TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(pair_id,message_id),FOREIGN KEY(pair_id) REFERENCES hub_native_pairs_v1(pair_id));
CREATE TABLE hub_native_pair_node_operations_v1(owner_binding_id TEXT NOT NULL,node_key_epoch INTEGER NOT NULL,sequence INTEGER NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,pair_id TEXT NOT NULL,request_digest TEXT NOT NULL CHECK(length(request_digest)=64),response_packet BLOB NOT NULL CHECK(length(response_packet)>0),created_at TEXT NOT NULL,PRIMARY KEY(owner_binding_id,node_key_epoch,sequence),UNIQUE(owner_binding_id,node_key_epoch,operation_id));
CREATE TRIGGER hub_native_pairs_v1_no_delete BEFORE DELETE ON hub_native_pairs_v1 BEGIN SELECT RAISE(ABORT,'native pair history is permanent');END;
CREATE TRIGGER hub_native_pairs_v1_coordinates BEFORE UPDATE ON hub_native_pairs_v1 WHEN NEW.pair_id!=OLD.pair_id OR NEW.hub_id!=OLD.hub_id OR NEW.account_id!=OLD.account_id OR NEW.owner_id!=OLD.owner_id OR NEW.device_id!=OLD.device_id OR NEW.node_id!=OLD.node_id OR NEW.network_id!=OLD.network_id OR NEW.group_id!=OLD.group_id OR NEW.scope_json!=OLD.scope_json OR NEW.bootstrap_json!=OLD.bootstrap_json OR NEW.prepare_operation_id!=OLD.prepare_operation_id OR NEW.proof_expires_at!=OLD.proof_expires_at OR NEW.join_until!=OLD.join_until OR NEW.peer_expires_at!=OLD.peer_expires_at OR NEW.created_at!=OLD.created_at OR NEW.control_revision<OLD.control_revision OR (OLD.bootstrap_owner_proof IS NOT NULL AND NEW.bootstrap_owner_proof IS NOT OLD.bootstrap_owner_proof) OR (OLD.state IN('REVOKED','EXPIRED') AND (NEW.state!=OLD.state OR NEW.control_revision!=OLD.control_revision OR NEW.plan_id!=OLD.plan_id)) OR (OLD.state='ACTIVE' AND NEW.state IN('PREPARED','WAITING_JOIN','WAITING_CONSENT')) BEGIN SELECT RAISE(ABORT,'native pair coordinates/deadlines cannot roll back');END;
CREATE TRIGGER hub_native_pair_slots_v1_no_delete BEFORE DELETE ON hub_native_pair_slots_v1 BEGIN SELECT RAISE(ABORT,'native pair slot history is permanent');END;
CREATE TRIGGER hub_native_pair_slots_v1_coordinates BEFORE UPDATE ON hub_native_pair_slots_v1 WHEN NEW.pair_id!=OLD.pair_id OR NEW.slot!=OLD.slot OR NEW.generation!=OLD.generation OR NEW.created_at!=OLD.created_at OR (OLD.attempt_id!='' AND (NEW.attempt_id!=OLD.attempt_id OR NEW.native_session_id!=OLD.native_session_id OR NEW.endpoint_id!=OLD.endpoint_id OR NEW.principal_id!=OLD.principal_id OR NEW.network_access_binding_id!=OLD.network_access_binding_id OR NEW.binding_id!=OLD.binding_id OR NEW.lease_owner!=OLD.lease_owner)) OR (OLD.state='REJECTED' AND NEW.state!='REJECTED') OR (OLD.state='ACTIVE' AND NEW.state!='ACTIVE') BEGIN SELECT RAISE(ABORT,'native pair slot cannot be replaced');END;
CREATE TRIGGER hub_native_pair_plans_v1_no_delete BEFORE DELETE ON hub_native_pair_plans_v1 BEGIN SELECT RAISE(ABORT,'native pair plan history is permanent');END;
CREATE TRIGGER hub_native_pair_plans_v1_coordinates BEFORE UPDATE ON hub_native_pair_plans_v1 WHEN NEW.plan_id!=OLD.plan_id OR NEW.pair_id!=OLD.pair_id OR NEW.plan_json!=OLD.plan_json OR NEW.created_at!=OLD.created_at OR (OLD.state!='PREPARED' AND NEW.state!=OLD.state) BEGIN SELECT RAISE(ABORT,'native pair plan coordinates are immutable');END;
CREATE TRIGGER hub_native_pair_consents_v1_no_delete BEFORE DELETE ON hub_native_pair_consents_v1 BEGIN SELECT RAISE(ABORT,'native pair consent history is permanent');END;
CREATE TRIGGER hub_native_pair_consents_v1_no_update BEFORE UPDATE ON hub_native_pair_consents_v1 BEGIN SELECT RAISE(ABORT,'native pair consent is immutable');END;
CREATE TRIGGER hub_native_pair_operations_v1_no_delete BEFORE DELETE ON hub_native_pair_operations_v1 BEGIN SELECT RAISE(ABORT,'native pair receipts and fences are permanent');END;
CREATE TRIGGER hub_native_pair_operations_v1_no_update BEFORE UPDATE ON hub_native_pair_operations_v1 BEGIN SELECT RAISE(ABORT,'native pair receipts and fences are immutable');END;
CREATE TRIGGER hub_native_pair_messages_v1_no_delete BEFORE DELETE ON hub_native_pair_messages_v1 BEGIN SELECT RAISE(ABORT,'native pair message budget cannot reset');END;
CREATE TRIGGER hub_native_pair_messages_v1_no_update BEFORE UPDATE ON hub_native_pair_messages_v1 BEGIN SELECT RAISE(ABORT,'native pair message budget is immutable');END;
CREATE TRIGGER hub_native_pair_node_operations_v1_no_delete BEFORE DELETE ON hub_native_pair_node_operations_v1 BEGIN SELECT RAISE(ABORT,'native pair Node receipts are permanent');END;
CREATE TRIGGER hub_native_pair_node_operations_v1_no_update BEFORE UPDATE ON hub_native_pair_node_operations_v1 BEGIN SELECT RAISE(ABORT,'native pair Node receipts are immutable');END;`)
	return err
}
