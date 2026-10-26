package store

import "fmt"

// The core initializer owns the shared writer row and calls this initializer
// in the same migration. These tables contain no identity or private key.
var endpointGroupsOwnerSchemaObjects = []string{
	"hub_endpoint_groups_reviews_v1", "hub_endpoint_groups_reviews_v1_actor",
	"hub_endpoint_groups_owner_operations_v1", "hub_endpoint_groups_owner_reads_v1",
	"hub_endpoint_groups_owner_rates_v1", "hub_endpoint_groups_owner_nonces_v1",
	"hub_endpoint_groups_owner_nonces_v1_nonce",
	"hub_endpoint_groups_reviews_v1_coordinates", "hub_endpoint_groups_reviews_v1_no_delete",
	"hub_endpoint_groups_owner_operations_v1_no_update", "hub_endpoint_groups_owner_operations_v1_no_delete",
	"hub_endpoint_groups_owner_nonces_v1_no_update", "hub_endpoint_groups_owner_nonces_v1_no_delete",
}

func (s *Store) initializeHubEndpointGroupsOwnerSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE hub_endpoint_groups_reviews_v1(
 review_id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,account_id TEXT NOT NULL,device_id TEXT NOT NULL,
 account_epoch INTEGER NOT NULL CHECK(account_epoch>0),device_epoch INTEGER NOT NULL CHECK(device_epoch>0),owner_key_version INTEGER NOT NULL CHECK(owner_key_version>0),
 prepare_request_id TEXT NOT NULL,prepare_packet_digest TEXT NOT NULL CHECK(length(prepare_packet_digest)=64),
 prepare_proof BLOB NOT NULL CHECK(length(prepare_proof)>0 AND length(prepare_proof)<=32768),
 review_json TEXT NOT NULL CHECK(length(review_json)>0 AND length(CAST(review_json AS BLOB))<=196608),
 expires_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('PREPARED','CONSUMED','EXPIRED')),
 consumed_operation_id TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,
 UNIQUE(owner_id,device_id,prepare_request_id),
 CHECK((state='CONSUMED' AND consumed_operation_id!='') OR (state!='CONSUMED' AND consumed_operation_id='')));
CREATE INDEX hub_endpoint_groups_reviews_v1_actor ON hub_endpoint_groups_reviews_v1(owner_id,device_id,account_epoch,device_epoch,owner_key_version,state);
CREATE TABLE hub_endpoint_groups_owner_operations_v1(
 owner_id TEXT NOT NULL,device_id TEXT NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,
 account_id TEXT NOT NULL,account_epoch INTEGER NOT NULL CHECK(account_epoch>0),device_epoch INTEGER NOT NULL CHECK(device_epoch>0),owner_key_version INTEGER NOT NULL CHECK(owner_key_version>0),
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),nonce_digest TEXT NOT NULL CHECK(length(nonce_digest) IN(0,64)),
 state TEXT NOT NULL CHECK(state IN('PREPARED','COMPLETED','REJECTED_FENCED','READ_EXPIRED')),
 operation_json TEXT NOT NULL DEFAULT '',response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=393216),
 created_at TEXT NOT NULL,PRIMARY KEY(owner_id,device_id,operation_id));
CREATE TABLE hub_endpoint_groups_owner_reads_v1(
 owner_id TEXT NOT NULL,device_id TEXT NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,
 account_id TEXT NOT NULL,account_epoch INTEGER NOT NULL CHECK(account_epoch>0),device_epoch INTEGER NOT NULL CHECK(device_epoch>0),owner_key_version INTEGER NOT NULL CHECK(owner_key_version>0),
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),nonce_digest TEXT NOT NULL CHECK(length(nonce_digest) IN(0,64)),
 state TEXT NOT NULL CHECK(state IN('PREPARED','COMPLETED','REJECTED_FENCED','READ_EXPIRED')),
 response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=917504),created_at TEXT NOT NULL,
 PRIMARY KEY(owner_id,device_id,operation_id));
CREATE TABLE hub_endpoint_groups_owner_rates_v1(
 owner_id TEXT NOT NULL,device_id TEXT NOT NULL,account_epoch INTEGER NOT NULL CHECK(account_epoch>0),device_epoch INTEGER NOT NULL CHECK(device_epoch>0),owner_key_version INTEGER NOT NULL CHECK(owner_key_version>0),
 window_start TEXT NOT NULL,requests INTEGER NOT NULL CHECK(requests>=0 AND requests<=128),
 PRIMARY KEY(owner_id,device_id,account_epoch,device_epoch,owner_key_version));
CREATE TABLE hub_endpoint_groups_owner_nonces_v1(
 owner_id TEXT NOT NULL,device_id TEXT NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,
 account_id TEXT NOT NULL,account_epoch INTEGER NOT NULL CHECK(account_epoch>0),device_epoch INTEGER NOT NULL CHECK(device_epoch>0),owner_key_version INTEGER NOT NULL CHECK(owner_key_version>0),
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),nonce_digest TEXT NOT NULL CHECK(length(nonce_digest) IN(0,64)),created_at TEXT NOT NULL,
 PRIMARY KEY(owner_id,device_id,operation_id));
CREATE UNIQUE INDEX hub_endpoint_groups_owner_nonces_v1_nonce ON hub_endpoint_groups_owner_nonces_v1(owner_id,device_id,account_epoch,device_epoch,owner_key_version,nonce_digest) WHERE nonce_digest!='';
CREATE TRIGGER hub_endpoint_groups_reviews_v1_coordinates BEFORE UPDATE ON hub_endpoint_groups_reviews_v1 WHEN
 NEW.review_id!=OLD.review_id OR NEW.owner_id!=OLD.owner_id OR NEW.account_id!=OLD.account_id OR NEW.device_id!=OLD.device_id OR
 NEW.account_epoch!=OLD.account_epoch OR NEW.device_epoch!=OLD.device_epoch OR NEW.owner_key_version!=OLD.owner_key_version OR
 NEW.prepare_request_id!=OLD.prepare_request_id OR NEW.prepare_packet_digest!=OLD.prepare_packet_digest OR NEW.prepare_proof IS NOT OLD.prepare_proof OR
 NEW.review_json!=OLD.review_json OR NEW.expires_at!=OLD.expires_at OR NEW.created_at!=OLD.created_at OR
 (OLD.state!='PREPARED' AND (NEW.state!=OLD.state OR NEW.consumed_operation_id!=OLD.consumed_operation_id))
 BEGIN SELECT RAISE(ABORT,'endpoint group review is immutable and single-use');END;
CREATE TRIGGER hub_endpoint_groups_reviews_v1_no_delete BEFORE DELETE ON hub_endpoint_groups_reviews_v1 BEGIN SELECT RAISE(ABORT,'endpoint group review history is permanent');END;`)
	if err != nil {
		return err
	}
	for _, table := range []string{"hub_endpoint_groups_owner_operations_v1", "hub_endpoint_groups_owner_nonces_v1"} {
		for _, verb := range []string{"UPDATE", "DELETE"} {
			name := table + "_no_" + map[string]string{"UPDATE": "update", "DELETE": "delete"}[verb]
			if _, err = s.db.Exec(fmt.Sprintf(`CREATE TRIGGER %s BEFORE %s ON %s BEGIN SELECT RAISE(ABORT,'endpoint group exact history is immutable');END;`, name, verb, table)); err != nil {
				return err
			}
		}
	}
	return nil
}
