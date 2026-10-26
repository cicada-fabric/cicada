package store

import "fmt"

var endpointGroupsCoreSchemaObjects = []string{
	"hub_endpoint_groups_guard_v1", "hub_endpoint_groups_registrations_v1", "hub_endpoint_groups_registrations_v1_scope", "hub_endpoint_groups_registrations_v1_coordinates", "hub_endpoint_groups_registrations_v1_no_delete",
	"hub_endpoint_groups_listings_v1", "hub_endpoint_groups_heads_v1", "hub_endpoint_groups_heads_v1_monotone", "hub_endpoint_groups_heads_v1_initial_authority", "hub_endpoint_groups_heads_v1_no_delete",
	"hub_endpoint_groups_relations_v1", "hub_endpoint_groups_relations_v1_coordinates", "hub_endpoint_groups_relations_v1_no_delete",
	"hub_endpoint_groups_policies_v1", "hub_endpoint_groups_policies_v1_epoch", "hub_endpoint_groups_policies_v1_current", "hub_endpoint_groups_policies_v1_coordinates", "hub_endpoint_groups_policies_v1_no_delete",
	"hub_endpoint_groups_key_challenges_v1", "hub_endpoint_groups_key_challenges_v1_coordinates", "hub_endpoint_groups_key_challenges_v1_no_delete",
	"hub_endpoint_groups_node_operations_v1", "hub_endpoint_groups_node_operations_v1_no_update", "hub_endpoint_groups_node_operations_v1_no_delete", "hub_endpoint_groups_node_reads_v1", "hub_endpoint_groups_node_rates_v1",
}

func endpointGroupsSchemaObjects() []string {
	return append(append([]string(nil), endpointGroupsCoreSchemaObjects...), endpointGroupsOwnerSchemaObjects...)
}

// References and immutable snapshots of existing identities; this migration
// never creates/replaces a Principal, Endpoint, Owner, Node, key or epoch.
func (s *Store) initializeHubEndpointGroupsSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE hub_endpoint_groups_guard_v1(id INTEGER PRIMARY KEY CHECK(id=1),touched_at TEXT NOT NULL);
INSERT INTO hub_endpoint_groups_guard_v1 VALUES(1,'');
CREATE TABLE hub_endpoint_groups_registrations_v1(
 endpoint_id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,node_id TEXT NOT NULL,network_id TEXT NOT NULL,
 native_digest TEXT NOT NULL CHECK(length(native_digest)=64),registration_digest TEXT NOT NULL CHECK(length(registration_digest)=64),registration_revision INTEGER NOT NULL CHECK(registration_revision>0),
 binding_id TEXT NOT NULL,binding_epoch INTEGER NOT NULL CHECK(binding_epoch>0),origin_policy_id TEXT NOT NULL,origin_member_id TEXT NOT NULL,
 anchor_json TEXT NOT NULL,hub_identity_json TEXT NOT NULL,relations_revision INTEGER NOT NULL CHECK(relations_revision>=0),created_at TEXT NOT NULL,
 FOREIGN KEY(endpoint_id) REFERENCES fabric_endpoints(id));
CREATE INDEX hub_endpoint_groups_registrations_v1_scope ON hub_endpoint_groups_registrations_v1(owner_id,node_id,network_id,endpoint_id);
CREATE TABLE hub_endpoint_groups_listings_v1(owner_id TEXT NOT NULL,node_id TEXT NOT NULL,network_id TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>=0),PRIMARY KEY(owner_id,node_id,network_id));
CREATE TABLE hub_endpoint_groups_heads_v1(
 native_digest TEXT NOT NULL CHECK(length(native_digest)=64),group_id TEXT NOT NULL,mode TEXT NOT NULL CHECK(mode IN('DEFAULT','OWNER')),revision INTEGER NOT NULL CHECK(revision>=0),
 deny_reason TEXT NOT NULL CHECK(deny_reason IN('NONE','REMOVED','EXPIRED')),policy_id TEXT NOT NULL,policy_epoch INTEGER NOT NULL CHECK(policy_epoch>=0),updated_at TEXT NOT NULL,
 PRIMARY KEY(native_digest,group_id),
 CHECK((mode='DEFAULT' AND revision=0 AND deny_reason='NONE' AND policy_id='' AND policy_epoch=0) OR (mode='OWNER' AND revision>0)),
 CHECK((policy_id='' AND policy_epoch=0 AND deny_reason IN('NONE','REMOVED')) OR (policy_id!='' AND policy_epoch>0)));
CREATE TABLE hub_endpoint_groups_relations_v1(
 endpoint_id TEXT NOT NULL,group_id TEXT NOT NULL,native_digest TEXT NOT NULL CHECK(length(native_digest)=64),revision INTEGER NOT NULL CHECK(revision>0),
 default_stamp TEXT NOT NULL DEFAULT '',default_withdrawn INTEGER NOT NULL DEFAULT 0 CHECK(default_withdrawn IN(0,1)),created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
 PRIMARY KEY(endpoint_id,group_id),FOREIGN KEY(endpoint_id) REFERENCES hub_endpoint_groups_registrations_v1(endpoint_id));
CREATE TABLE hub_endpoint_groups_policies_v1(
 policy_id TEXT PRIMARY KEY,native_digest TEXT NOT NULL CHECK(length(native_digest)=64),endpoint_id TEXT NOT NULL,group_id TEXT NOT NULL,epoch INTEGER NOT NULL CHECK(epoch>0),
 policy_json TEXT NOT NULL,policy_proof BLOB NOT NULL CHECK(length(policy_proof)>0 AND length(policy_proof)<=32768),state TEXT NOT NULL CHECK(state IN('PENDING_KEY','ACTIVE','REVOKED','EXPIRED')),
 contribution_revision INTEGER NOT NULL CHECK(contribution_revision>0),grant_json TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
 FOREIGN KEY(endpoint_id) REFERENCES hub_endpoint_groups_registrations_v1(endpoint_id));
CREATE UNIQUE INDEX hub_endpoint_groups_policies_v1_epoch ON hub_endpoint_groups_policies_v1(native_digest,group_id,epoch);
CREATE UNIQUE INDEX hub_endpoint_groups_policies_v1_current ON hub_endpoint_groups_policies_v1(native_digest,group_id) WHERE state IN('PENDING_KEY','ACTIVE');
CREATE TABLE hub_endpoint_groups_key_challenges_v1(
 challenge_id TEXT PRIMARY KEY,policy_id TEXT NOT NULL,endpoint_id TEXT NOT NULL,group_id TEXT NOT NULL,expected_relation_revision INTEGER NOT NULL CHECK(expected_relation_revision>0),
 challenge_json TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('PREPARED','COMPLETED','INVALIDATED','EXPIRED')),expires_at TEXT NOT NULL,created_at TEXT NOT NULL,
 FOREIGN KEY(policy_id) REFERENCES hub_endpoint_groups_policies_v1(policy_id));
CREATE TABLE hub_endpoint_groups_node_operations_v1(
 owner_binding_id TEXT NOT NULL,node_key_epoch INTEGER NOT NULL CHECK(node_key_epoch>0),sequence INTEGER NOT NULL CHECK(sequence>0),operation_id TEXT NOT NULL,operation TEXT NOT NULL,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),state TEXT NOT NULL CHECK(state IN('COMPLETED','REJECTED_FENCED','READ_EXPIRED')),
 response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=573440),created_at TEXT NOT NULL,
 PRIMARY KEY(owner_binding_id,node_key_epoch,sequence),UNIQUE(owner_binding_id,node_key_epoch,operation_id));
CREATE TABLE hub_endpoint_groups_node_reads_v1(
 owner_binding_id TEXT NOT NULL,node_key_epoch INTEGER NOT NULL,sequence INTEGER NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),state TEXT NOT NULL,response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=573440),created_at TEXT NOT NULL,
 PRIMARY KEY(owner_binding_id,node_key_epoch,operation_id));
CREATE TABLE hub_endpoint_groups_node_rates_v1(owner_binding_id TEXT NOT NULL,node_key_epoch INTEGER NOT NULL,window_start TEXT NOT NULL,requests INTEGER NOT NULL CHECK(requests>=0 AND requests<=128),PRIMARY KEY(owner_binding_id,node_key_epoch));
CREATE TRIGGER hub_endpoint_groups_registrations_v1_coordinates BEFORE UPDATE ON hub_endpoint_groups_registrations_v1 WHEN
 NEW.endpoint_id!=OLD.endpoint_id OR NEW.owner_id!=OLD.owner_id OR NEW.node_id!=OLD.node_id OR NEW.network_id!=OLD.network_id OR NEW.native_digest!=OLD.native_digest OR NEW.registration_digest!=OLD.registration_digest OR
 NEW.registration_revision!=OLD.registration_revision OR NEW.binding_id!=OLD.binding_id OR NEW.binding_epoch!=OLD.binding_epoch OR NEW.origin_policy_id!=OLD.origin_policy_id OR NEW.origin_member_id!=OLD.origin_member_id OR
 NEW.anchor_json!=OLD.anchor_json OR NEW.hub_identity_json!=OLD.hub_identity_json OR NEW.created_at!=OLD.created_at OR NEW.relations_revision<OLD.relations_revision
 BEGIN SELECT RAISE(ABORT,'original endpoint registration cannot be replaced');END;
CREATE TRIGGER hub_endpoint_groups_heads_v1_initial_authority BEFORE INSERT ON hub_endpoint_groups_heads_v1 WHEN
 NEW.mode='OWNER' AND NEW.deny_reason='NONE' AND NOT EXISTS(SELECT 1 FROM hub_endpoint_groups_policies_v1 p WHERE p.native_digest=NEW.native_digest AND p.group_id=NEW.group_id AND p.policy_id=NEW.policy_id AND p.epoch=NEW.policy_epoch AND p.state='ACTIVE')
 BEGIN SELECT RAISE(ABORT,'initial Owner control requires exact active delegation');END;
CREATE TRIGGER hub_endpoint_groups_heads_v1_monotone BEFORE UPDATE ON hub_endpoint_groups_heads_v1 WHEN
 NEW.native_digest!=OLD.native_digest OR NEW.group_id!=OLD.group_id OR NEW.revision!=OLD.revision+1 OR (OLD.mode='OWNER' AND NEW.mode!='OWNER') OR
 (NEW.deny_reason='NONE' AND NEW.mode='OWNER' AND NOT EXISTS(SELECT 1 FROM hub_endpoint_groups_policies_v1 p WHERE p.native_digest=NEW.native_digest AND p.group_id=NEW.group_id AND p.policy_id=NEW.policy_id AND p.epoch=NEW.policy_epoch AND p.state='ACTIVE'))
 BEGIN SELECT RAISE(ABORT,'Owner control cannot roll back or clear without exact active delegation');END;
CREATE TRIGGER hub_endpoint_groups_relations_v1_coordinates BEFORE UPDATE ON hub_endpoint_groups_relations_v1 WHEN
 NEW.endpoint_id!=OLD.endpoint_id OR NEW.group_id!=OLD.group_id OR NEW.native_digest!=OLD.native_digest OR NEW.revision!=OLD.revision+1 OR NEW.default_withdrawn<OLD.default_withdrawn OR NEW.created_at!=OLD.created_at
 BEGIN SELECT RAISE(ABORT,'endpoint relation history cannot roll back');END;
CREATE TRIGGER hub_endpoint_groups_policies_v1_coordinates BEFORE UPDATE ON hub_endpoint_groups_policies_v1 WHEN
 NEW.policy_id!=OLD.policy_id OR NEW.native_digest!=OLD.native_digest OR NEW.endpoint_id!=OLD.endpoint_id OR NEW.group_id!=OLD.group_id OR NEW.epoch!=OLD.epoch OR NEW.policy_json!=OLD.policy_json OR NEW.policy_proof IS NOT OLD.policy_proof OR NEW.created_at!=OLD.created_at OR
 NEW.contribution_revision!=OLD.contribution_revision+1 OR (OLD.state IN('REVOKED','EXPIRED')) OR (OLD.grant_json!='' AND NEW.grant_json!=OLD.grant_json) OR (OLD.state='ACTIVE' AND NEW.state='PENDING_KEY')
 BEGIN SELECT RAISE(ABORT,'delegation cannot be replaced or revived');END;
CREATE TRIGGER hub_endpoint_groups_key_challenges_v1_coordinates BEFORE UPDATE ON hub_endpoint_groups_key_challenges_v1 WHEN
 NEW.challenge_id!=OLD.challenge_id OR NEW.policy_id!=OLD.policy_id OR NEW.endpoint_id!=OLD.endpoint_id OR NEW.group_id!=OLD.group_id OR NEW.expected_relation_revision!=OLD.expected_relation_revision OR NEW.challenge_json!=OLD.challenge_json OR NEW.expires_at!=OLD.expires_at OR NEW.created_at!=OLD.created_at OR
 (OLD.state!='PREPARED' AND NEW.state!=OLD.state)
 BEGIN SELECT RAISE(ABORT,'key projection is immutable');END;`)
	if err != nil {
		return err
	}
	for _, table := range []string{"hub_endpoint_groups_registrations_v1", "hub_endpoint_groups_heads_v1", "hub_endpoint_groups_relations_v1", "hub_endpoint_groups_policies_v1", "hub_endpoint_groups_key_challenges_v1", "hub_endpoint_groups_node_operations_v1"} {
		if _, err = s.db.Exec(fmt.Sprintf(`CREATE TRIGGER %s_no_delete BEFORE DELETE ON %s BEGIN SELECT RAISE(ABORT,'endpoint group authority history is permanent');END;`, table, table)); err != nil {
			return err
		}
	}
	if _, err = s.db.Exec(`CREATE TRIGGER hub_endpoint_groups_node_operations_v1_no_update BEFORE UPDATE ON hub_endpoint_groups_node_operations_v1 BEGIN SELECT RAISE(ABORT,'original Node receipt is immutable');END;`); err != nil {
		return err
	}
	return s.initializeHubEndpointGroupsOwnerSchema()
}
