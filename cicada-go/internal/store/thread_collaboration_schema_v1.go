package store

import "fmt"

var threadCollaborationSchemaObjects = []string{"thread_collaboration_guard_v1", "thread_classifications_v1", "group_coordination_policies_v1", "group_lock_slots_v1", "group_lock_originals_v1", "thread_collaboration_owner_reviews_v1", "thread_collaboration_owner_originals_v1", "thread_collaboration_node_originals_v1", "group_lock_originals_v1_no_update", "thread_collaboration_owner_originals_v1_no_update", "thread_collaboration_node_originals_v1_no_update"}

func (s *Store) initializeThreadCollaborationSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE thread_collaboration_guard_v1(id INTEGER PRIMARY KEY CHECK(id=1),touched_at TEXT NOT NULL);
INSERT INTO thread_collaboration_guard_v1 VALUES(1,'');
CREATE TABLE thread_classifications_v1(
 registration_id TEXT PRIMARY KEY,source_epoch INTEGER NOT NULL CHECK(source_epoch>0),endpoint_id TEXT NOT NULL UNIQUE,owner_id TEXT NOT NULL,node_id TEXT NOT NULL,network_id TEXT NOT NULL,
 classification TEXT NOT NULL CHECK(classification IN('worker','advisor','manager')),revision INTEGER NOT NULL CHECK(revision>0),created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE group_coordination_policies_v1(
 group_id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,network_id TEXT NOT NULL,policy_id TEXT NOT NULL UNIQUE,revision INTEGER NOT NULL CHECK(revision>0),
 state TEXT NOT NULL CHECK(state IN('ENABLED','REVOKED')),policy_json TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE group_lock_slots_v1(
 group_id TEXT NOT NULL,slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 8),state TEXT NOT NULL CHECK(state IN('FREE','HELD')),version INTEGER NOT NULL CHECK(version>0),generation INTEGER NOT NULL CHECK(generation>=0),holder_json TEXT NOT NULL,note TEXT NOT NULL,expires_at TEXT NOT NULL,
 PRIMARY KEY(group_id,slot),FOREIGN KEY(group_id) REFERENCES group_coordination_policies_v1(group_id),
 CHECK((state='FREE' AND holder_json='' AND note='' AND expires_at='') OR(state='HELD' AND generation>0 AND holder_json!='' AND expires_at!='')));
CREATE TABLE group_lock_originals_v1(
 group_id TEXT NOT NULL,registration_id TEXT NOT NULL,source_epoch INTEGER NOT NULL,operation_id TEXT NOT NULL,idempotency_key TEXT NOT NULL,operation TEXT NOT NULL,request_digest TEXT NOT NULL,request_json TEXT NOT NULL,caller_json TEXT NOT NULL,receipt_json TEXT NOT NULL,error_code TEXT NOT NULL,created_at TEXT NOT NULL,
 PRIMARY KEY(group_id,registration_id,source_epoch,operation_id),UNIQUE(group_id,registration_id,source_epoch,idempotency_key));
CREATE TABLE thread_collaboration_owner_reviews_v1(
 review_id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,account_id TEXT NOT NULL,device_id TEXT NOT NULL,account_epoch INTEGER NOT NULL,device_epoch INTEGER NOT NULL,owner_key_version INTEGER NOT NULL,
 review_json TEXT NOT NULL,prepare_proof BLOB NOT NULL,expires_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('PREPARED','CONSUMED')),consumed_id TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL);
CREATE TABLE thread_collaboration_owner_originals_v1(
 owner_id TEXT NOT NULL,device_id TEXT NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,request_digest TEXT NOT NULL,account_id TEXT NOT NULL,account_epoch INTEGER NOT NULL,device_epoch INTEGER NOT NULL,owner_key_version INTEGER NOT NULL,nonce_digest TEXT NOT NULL,response_packet BLOB NOT NULL,created_at TEXT NOT NULL,
 PRIMARY KEY(owner_id,device_id,operation_id),UNIQUE(owner_id,device_id,account_epoch,device_epoch,owner_key_version,nonce_digest));
CREATE TABLE thread_collaboration_node_originals_v1(
 owner_binding_id TEXT NOT NULL,node_key_epoch INTEGER NOT NULL,sequence INTEGER NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,request_digest TEXT NOT NULL,response_packet BLOB NOT NULL,created_at TEXT NOT NULL,
 PRIMARY KEY(owner_binding_id,node_key_epoch,operation_id),UNIQUE(owner_binding_id,node_key_epoch,sequence));`)
	if err != nil {
		return err
	}
	for _, table := range []string{"group_lock_originals_v1", "thread_collaboration_owner_originals_v1", "thread_collaboration_node_originals_v1"} {
		for _, verb := range []string{"UPDATE"} {
			name := table + "_no_" + map[string]string{"UPDATE": "update", "DELETE": "delete"}[verb]
			if _, err = s.db.Exec(fmt.Sprintf(`CREATE TRIGGER %s BEFORE %s ON %s BEGIN SELECT RAISE(ABORT,'original collaboration receipt is immutable');END;`, name, verb, table)); err != nil {
				return err
			}
		}
	}
	return nil
}
