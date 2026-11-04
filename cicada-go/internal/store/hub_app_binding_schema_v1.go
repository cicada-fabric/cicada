package store

var appBindingSchemaObjects = []string{
	"hub_app_binding_guard_v1", "hub_app_binding_prepares_v1", "hub_app_binding_prepares_v1_nonce",
	"hub_app_binding_operations_v1", "hub_app_binding_operations_v1_nonce",
	"hub_app_binding_operations_v1_binding",
	"hub_app_unbound_v1", "hub_app_rebound_v1",
	"hub_app_binding_operations_v1_no_delete", "hub_app_binding_operations_v1_no_update",
	"hub_app_unbound_v1_no_delete", "hub_app_unbound_v1_coordinates", "hub_app_rebound_v1_no_delete", "hub_app_rebound_v1_no_update",
}

func (s *Store) initializeHubAppBindingSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE hub_app_binding_guard_v1(id INTEGER PRIMARY KEY CHECK(id=1),touched INTEGER NOT NULL);
INSERT INTO hub_app_binding_guard_v1 VALUES(1,1);
CREATE TABLE hub_app_binding_prepares_v1(owner_id TEXT NOT NULL,device_id TEXT NOT NULL,prepare_id TEXT NOT NULL,operation TEXT NOT NULL,request_digest TEXT NOT NULL,nonce_digest TEXT NOT NULL,device_public_json TEXT NOT NULL,binding_digest TEXT NOT NULL UNIQUE,binding_json TEXT NOT NULL,pairing_json TEXT NOT NULL,owner_nonce_digest TEXT NOT NULL,device_nonce_digest TEXT NOT NULL,response_packet BLOB NOT NULL,expires_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('PREPARED','CONSUMED','REJECTED')),PRIMARY KEY(owner_id,device_id,prepare_id));
CREATE UNIQUE INDEX hub_app_binding_prepares_v1_nonce ON hub_app_binding_prepares_v1(owner_id,device_id,nonce_digest);
CREATE TABLE hub_app_binding_operations_v1(owner_id TEXT NOT NULL,device_id TEXT NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,request_digest TEXT NOT NULL,nonce_digest TEXT NOT NULL,device_public_json TEXT NOT NULL,binding_digest TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('UNBOUND','BOUND_ZERO','REJECTED')),response_packet BLOB NOT NULL,PRIMARY KEY(owner_id,device_id,operation_id));
CREATE UNIQUE INDEX hub_app_binding_operations_v1_nonce ON hub_app_binding_operations_v1(owner_id,device_id,nonce_digest);
CREATE UNIQUE INDEX hub_app_binding_operations_v1_binding ON hub_app_binding_operations_v1(binding_digest);
CREATE TABLE hub_app_unbound_v1(owner_id TEXT NOT NULL,device_id TEXT NOT NULL,binding_digest TEXT NOT NULL UNIQUE,binding_json TEXT NOT NULL,owner_proof BLOB NOT NULL,restore_receipt TEXT NOT NULL,post_device_epoch INTEGER NOT NULL,post_client_version INTEGER NOT NULL,post_client_epoch INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN('UNBOUND','SECURITY_REVOKED')),replacement_device_id TEXT NOT NULL DEFAULT '',PRIMARY KEY(owner_id,device_id));
CREATE TABLE hub_app_rebound_v1(owner_id TEXT NOT NULL,device_id TEXT NOT NULL,unbind_binding_digest TEXT NOT NULL UNIQUE,binding_json TEXT NOT NULL,owner_proof BLOB NOT NULL,restore_receipt TEXT NOT NULL,PRIMARY KEY(owner_id,device_id));
CREATE TRIGGER hub_app_binding_operations_v1_no_delete BEFORE DELETE ON hub_app_binding_operations_v1 BEGIN SELECT RAISE(ABORT,'App completion floor is permanent');END;
CREATE TRIGGER hub_app_binding_operations_v1_no_update BEFORE UPDATE ON hub_app_binding_operations_v1 BEGIN SELECT RAISE(ABORT,'App completion receipt is immutable');END;
CREATE TRIGGER hub_app_unbound_v1_no_delete BEFORE DELETE ON hub_app_unbound_v1 BEGIN SELECT RAISE(ABORT,'App unbind history is permanent');END;
CREATE TRIGGER hub_app_unbound_v1_coordinates BEFORE UPDATE ON hub_app_unbound_v1 WHEN NEW.owner_id!=OLD.owner_id OR NEW.device_id!=OLD.device_id OR NEW.binding_digest!=OLD.binding_digest OR NEW.binding_json!=OLD.binding_json OR NEW.owner_proof!=OLD.owner_proof OR NEW.restore_receipt!=OLD.restore_receipt OR NEW.post_device_epoch!=OLD.post_device_epoch OR NEW.post_client_version!=OLD.post_client_version OR NEW.post_client_epoch!=OLD.post_client_epoch OR (NEW.state!=OLD.state AND (OLD.state!='UNBOUND' OR NEW.state!='SECURITY_REVOKED')) OR (NEW.replacement_device_id!=OLD.replacement_device_id AND (OLD.replacement_device_id!='' OR NEW.replacement_device_id='')) BEGIN SELECT RAISE(ABORT,'App unbind coordinates are immutable');END;
CREATE TRIGGER hub_app_rebound_v1_no_delete BEFORE DELETE ON hub_app_rebound_v1 BEGIN SELECT RAISE(ABORT,'App replacement history is permanent');END;
CREATE TRIGGER hub_app_rebound_v1_no_update BEFORE UPDATE ON hub_app_rebound_v1 BEGIN SELECT RAISE(ABORT,'App replacement source is immutable');END;`)
	return err
}
