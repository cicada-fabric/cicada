package store

// Scope namespaces share the original grant, nonce, operation, provenance and
// NPT slot ledgers. Only published authority heads are per Node. No legacy
// claim, proof, receipt, provenance pointer, identity or epoch is backfilled.
var appNodeScopedSchemaObjects = []string{
	"hub_app_node_scoped_heads_v1", "hub_app_node_scoped_heads_v1_no_delete", "hub_app_node_scoped_heads_v1_monotone",
	"hub_app_node_grants_v1_active", "hub_app_node_grants_v1_namespace", "hub_app_node_grants_v1_scoped_claims",
	"hub_node_pair_trust_v1_namespace", "hub_app_node_scoped_guard_v1",
}

func (s *Store) initializeHubAppNodeScopedSchema() error {
	_, err := s.db.Exec(`
ALTER TABLE hub_app_node_grants_v1 ADD COLUMN authority_kind TEXT NOT NULL DEFAULT 'LEGACY_V1' CHECK(authority_kind IN('LEGACY_V1','NODE_V1'));
ALTER TABLE hub_app_node_grants_v1 ADD COLUMN authority_node_id TEXT NOT NULL DEFAULT '' CHECK((authority_kind='LEGACY_V1' AND authority_node_id='') OR (authority_kind='NODE_V1' AND length(authority_node_id)>0));
DROP INDEX hub_app_node_grants_v1_active;
CREATE UNIQUE INDEX hub_app_node_grants_v1_active ON hub_app_node_grants_v1(owner_id,device_id,authority_kind,authority_node_id) WHERE state='ACTIVE';
CREATE TRIGGER hub_app_node_grants_v1_namespace BEFORE UPDATE ON hub_app_node_grants_v1 WHEN NEW.authority_kind!=OLD.authority_kind OR NEW.authority_node_id!=OLD.authority_node_id BEGIN SELECT RAISE(ABORT,'App Node authority namespace is immutable');END;
CREATE TRIGGER hub_app_node_grants_v1_scoped_claims BEFORE INSERT ON hub_app_node_grants_v1 WHEN NEW.authority_kind='NODE_V1' AND (coalesce(json_extract(NEW.claims_json,'$.scope.version'),0)!=2 OR coalesce(json_extract(NEW.claims_json,'$.scope.authority_node_id'),'')!=NEW.authority_node_id OR coalesce(json_extract(NEW.claims_json,'$.candidate.node_id'),json_extract(NEW.claims_json,'$.binding.node_id'),'')!=NEW.authority_node_id) BEGIN SELECT RAISE(ABORT,'Scoped grant must bind the actual Node');END;
CREATE TABLE hub_app_node_scoped_heads_v1(owner_id TEXT NOT NULL,device_id TEXT NOT NULL,authority_node_id TEXT NOT NULL CHECK(length(authority_node_id)>0),head_version INTEGER NOT NULL CHECK(head_version>=0),latest_grant_id TEXT NOT NULL DEFAULT '',provenance_id TEXT NOT NULL DEFAULT '',PRIMARY KEY(owner_id,device_id,authority_node_id));
CREATE TRIGGER hub_app_node_scoped_heads_v1_no_delete BEFORE DELETE ON hub_app_node_scoped_heads_v1 BEGIN SELECT RAISE(ABORT,'Scoped App Node head history is permanent');END;
CREATE TRIGGER hub_app_node_scoped_heads_v1_monotone BEFORE UPDATE ON hub_app_node_scoped_heads_v1 WHEN NEW.owner_id!=OLD.owner_id OR NEW.device_id!=OLD.device_id OR NEW.authority_node_id!=OLD.authority_node_id OR NEW.head_version<OLD.head_version OR (NEW.head_version=OLD.head_version AND NEW.latest_grant_id!=OLD.latest_grant_id) OR (OLD.provenance_id!='' AND NEW.provenance_id!=OLD.provenance_id) BEGIN SELECT RAISE(ABORT,'Scoped App Node head/provenance cannot roll back');END;
ALTER TABLE hub_node_pair_trust_v1 ADD COLUMN authority_kind TEXT NOT NULL DEFAULT 'LEGACY_V1' CHECK(authority_kind IN('LEGACY_V1','NODE_V1'));
CREATE TRIGGER hub_node_pair_trust_v1_namespace BEFORE UPDATE ON hub_node_pair_trust_v1 WHEN NEW.authority_kind!=OLD.authority_kind BEGIN SELECT RAISE(ABORT,'Node pairing authority namespace is immutable');END;
CREATE TABLE hub_app_node_scoped_guard_v1(id INTEGER PRIMARY KEY CHECK(id=1),touched INTEGER NOT NULL);
INSERT INTO hub_app_node_scoped_guard_v1 VALUES(1,0);
`)
	return err
}
