package store

import "fmt"

var localDomainSchemaObjects = []string{
	"hub_local_domain_guard_v1", "hub_local_domain_epochs_v1", "hub_local_domain_user_reports_v1",
	"hub_local_domains_v1", "hub_local_domains_v1_nonterminal", "hub_local_domains_v1_epoch",
	"hub_local_domain_members_v1", "hub_local_domain_members_v1_native", "hub_local_domain_members_v1_endpoint", "hub_local_domain_challenges_v1",
	"hub_local_domain_members_v1_access_epoch",
	"hub_local_domain_owner_operations_v1", "hub_local_domain_owner_operations_v1_nonce", "hub_local_domain_node_operations_v1",
	"hub_local_domain_owner_reads_v1", "hub_local_domain_node_reads_v1", "hub_local_domain_rates_v1",
	"hub_local_domains_v1_coordinates", "hub_local_domain_members_v1_coordinates", "hub_local_domain_challenges_v1_coordinates",
	"hub_local_domains_v1_no_delete", "hub_local_domain_members_v1_no_delete", "hub_local_domain_challenges_v1_no_delete",
	"hub_local_domain_owner_operations_v1_no_delete", "hub_local_domain_owner_operations_v1_no_update",
	"hub_local_domain_node_operations_v1_no_delete", "hub_local_domain_node_operations_v1_no_update",
}

func (s *Store) initializeHubLocalDomainSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE hub_local_domain_guard_v1(id INTEGER PRIMARY KEY CHECK(id=1),touched_at TEXT NOT NULL);
INSERT INTO hub_local_domain_guard_v1 VALUES(1,'');
CREATE TABLE hub_local_domain_epochs_v1(owner_id TEXT NOT NULL,node_id TEXT NOT NULL,local_user_scope TEXT NOT NULL,epoch INTEGER NOT NULL CHECK(epoch>0),PRIMARY KEY(owner_id,node_id,local_user_scope));
CREATE TABLE hub_local_domain_user_reports_v1(owner_binding_id TEXT NOT NULL,node_key_epoch INTEGER NOT NULL CHECK(node_key_epoch>0),local_user_scope TEXT NOT NULL,report BLOB NOT NULL,issued_at TEXT NOT NULL,expires_at TEXT NOT NULL,observed_at TEXT NOT NULL,PRIMARY KEY(owner_binding_id,node_key_epoch));
CREATE TABLE hub_local_domains_v1(
 policy_id TEXT PRIMARY KEY,hub_id TEXT NOT NULL,owner_id TEXT NOT NULL,node_id TEXT NOT NULL,local_user_scope TEXT NOT NULL,
 network_id TEXT NOT NULL,group_id TEXT NOT NULL UNIQUE,epoch INTEGER NOT NULL CHECK(epoch>0),policy_json TEXT NOT NULL,hub_identity_json TEXT NOT NULL,
 policy_proof BLOB,state TEXT NOT NULL CHECK(state IN('PREPARED','ACTIVE','REVOKED','EXPIRED')),revision INTEGER NOT NULL CHECK(revision>0),
 creator_account_id TEXT NOT NULL,creator_device_id TEXT NOT NULL,prepare_proof BLOB NOT NULL,user_report BLOB NOT NULL,
 proof_expires_at TEXT NOT NULL,created_at TEXT NOT NULL,terminal_reason TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX hub_local_domains_v1_nonterminal ON hub_local_domains_v1(owner_id,node_id,local_user_scope) WHERE state IN('PREPARED','ACTIVE');
CREATE UNIQUE INDEX hub_local_domains_v1_epoch ON hub_local_domains_v1(owner_id,node_id,local_user_scope,epoch);
CREATE TABLE hub_local_domain_members_v1(
 member_id TEXT PRIMARY KEY,policy_id TEXT NOT NULL,owner_id TEXT NOT NULL,node_id TEXT NOT NULL,native_session_id TEXT NOT NULL,
 endpoint_id TEXT NOT NULL,principal_id TEXT NOT NULL,binding_id TEXT NOT NULL UNIQUE,access_id TEXT NOT NULL,
 runtime TEXT NOT NULL,workspace TEXT NOT NULL,member_json TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN('JOINED_ZERO','ACTIVE','LEFT','REVOKED','EXPIRED')),revision INTEGER NOT NULL CHECK(revision>0),
 attempt_id TEXT NOT NULL,join_operation_id TEXT NOT NULL,join_sequence INTEGER NOT NULL CHECK(join_sequence>0),key_grant_json TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,
 UNIQUE(policy_id,attempt_id),
 FOREIGN KEY(policy_id) REFERENCES hub_local_domains_v1(policy_id));
CREATE UNIQUE INDEX hub_local_domain_members_v1_native ON hub_local_domain_members_v1(policy_id,native_session_id) WHERE state IN('JOINED_ZERO','ACTIVE');
CREATE UNIQUE INDEX hub_local_domain_members_v1_endpoint ON hub_local_domain_members_v1(endpoint_id) WHERE state IN('JOINED_ZERO','ACTIVE');
CREATE UNIQUE INDEX hub_local_domain_members_v1_access_epoch ON hub_local_domain_members_v1(access_id,json_extract(member_json,'$.network_access_epoch'));
CREATE TABLE hub_local_domain_challenges_v1(challenge_id TEXT PRIMARY KEY,policy_id TEXT NOT NULL,member_id TEXT NOT NULL,expected_revision INTEGER NOT NULL CHECK(expected_revision>0),challenge_json TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('PREPARED','COMPLETED','INVALIDATED','EXPIRED')),expires_at TEXT NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(member_id) REFERENCES hub_local_domain_members_v1(member_id));
CREATE TABLE hub_local_domain_owner_operations_v1(owner_id TEXT NOT NULL,device_id TEXT NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,policy_id TEXT NOT NULL DEFAULT '',request_digest TEXT NOT NULL CHECK(length(request_digest)=64),nonce_digest TEXT NOT NULL CHECK(length(nonce_digest) IN(0,64)),state TEXT NOT NULL CHECK(state IN('COMPLETED','REJECTED_FENCED','READ_EXPIRED')),response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=917504),created_at TEXT NOT NULL,PRIMARY KEY(owner_id,device_id,operation_id));
CREATE UNIQUE INDEX hub_local_domain_owner_operations_v1_nonce ON hub_local_domain_owner_operations_v1(owner_id,device_id,nonce_digest) WHERE nonce_digest!='';
CREATE TABLE hub_local_domain_node_operations_v1(owner_binding_id TEXT NOT NULL,node_key_epoch INTEGER NOT NULL CHECK(node_key_epoch>0),sequence INTEGER NOT NULL CHECK(sequence>0),operation_id TEXT NOT NULL,operation TEXT NOT NULL,policy_id TEXT NOT NULL DEFAULT '',request_digest TEXT NOT NULL CHECK(length(request_digest)=64),state TEXT NOT NULL CHECK(state IN('COMPLETED','REJECTED_FENCED','READ_EXPIRED')),response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=573440),created_at TEXT NOT NULL,PRIMARY KEY(owner_binding_id,node_key_epoch,sequence),UNIQUE(owner_binding_id,node_key_epoch,operation_id));
CREATE TABLE hub_local_domain_owner_reads_v1(owner_id TEXT NOT NULL,device_id TEXT NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,request_digest TEXT NOT NULL CHECK(length(request_digest)=64),nonce_digest TEXT NOT NULL CHECK(length(nonce_digest)=64),state TEXT NOT NULL,response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=917504),created_at TEXT NOT NULL,PRIMARY KEY(owner_id,device_id,operation_id));
CREATE TABLE hub_local_domain_node_reads_v1(owner_binding_id TEXT NOT NULL,node_key_epoch INTEGER NOT NULL,sequence INTEGER NOT NULL,operation_id TEXT NOT NULL,operation TEXT NOT NULL,request_digest TEXT NOT NULL CHECK(length(request_digest)=64),state TEXT NOT NULL,response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=573440),created_at TEXT NOT NULL,PRIMARY KEY(owner_binding_id,node_key_epoch,operation_id));
CREATE TABLE hub_local_domain_rates_v1(actor_kind TEXT NOT NULL,actor_id TEXT NOT NULL,epoch INTEGER NOT NULL,window_start TEXT NOT NULL,requests INTEGER NOT NULL CHECK(requests>=0 AND requests<=128),PRIMARY KEY(actor_kind,actor_id,epoch));
CREATE TRIGGER hub_local_domains_v1_coordinates BEFORE UPDATE ON hub_local_domains_v1 WHEN NEW.policy_id!=OLD.policy_id OR NEW.hub_id!=OLD.hub_id OR NEW.owner_id!=OLD.owner_id OR NEW.node_id!=OLD.node_id OR NEW.local_user_scope!=OLD.local_user_scope OR NEW.network_id!=OLD.network_id OR NEW.group_id!=OLD.group_id OR NEW.epoch!=OLD.epoch OR NEW.policy_json!=OLD.policy_json OR NEW.hub_identity_json!=OLD.hub_identity_json OR NEW.creator_account_id!=OLD.creator_account_id OR NEW.creator_device_id!=OLD.creator_device_id OR NEW.prepare_proof IS NOT OLD.prepare_proof OR NEW.user_report IS NOT OLD.user_report OR NEW.proof_expires_at!=OLD.proof_expires_at OR NEW.created_at!=OLD.created_at OR NEW.revision<OLD.revision OR (OLD.policy_proof IS NOT NULL AND NEW.policy_proof IS NOT OLD.policy_proof) OR (OLD.state IN('REVOKED','EXPIRED') AND (NEW.state!=OLD.state OR NEW.revision!=OLD.revision)) OR (OLD.state='ACTIVE' AND NEW.state='PREPARED') BEGIN SELECT RAISE(ABORT,'local domain authority cannot be replaced or revived');END;
CREATE TRIGGER hub_local_domain_members_v1_coordinates BEFORE UPDATE ON hub_local_domain_members_v1 WHEN NEW.member_id!=OLD.member_id OR NEW.policy_id!=OLD.policy_id OR NEW.owner_id!=OLD.owner_id OR NEW.node_id!=OLD.node_id OR NEW.native_session_id!=OLD.native_session_id OR NEW.endpoint_id!=OLD.endpoint_id OR NEW.principal_id!=OLD.principal_id OR NEW.binding_id!=OLD.binding_id OR NEW.access_id!=OLD.access_id OR NEW.runtime!=OLD.runtime OR NEW.workspace!=OLD.workspace OR NEW.attempt_id!=OLD.attempt_id OR NEW.join_operation_id!=OLD.join_operation_id OR NEW.join_sequence!=OLD.join_sequence OR NEW.created_at!=OLD.created_at OR NEW.revision<OLD.revision OR (OLD.state IN('LEFT','REVOKED','EXPIRED') AND (NEW.state!=OLD.state OR NEW.revision!=OLD.revision OR NEW.member_json!=OLD.member_json)) OR (OLD.state='ACTIVE' AND NEW.state='JOINED_ZERO') BEGIN SELECT RAISE(ABORT,'local domain member identity cannot be replaced or revived');END;
CREATE TRIGGER hub_local_domain_challenges_v1_coordinates BEFORE UPDATE ON hub_local_domain_challenges_v1 WHEN NEW.challenge_id!=OLD.challenge_id OR NEW.policy_id!=OLD.policy_id OR NEW.member_id!=OLD.member_id OR NEW.expected_revision!=OLD.expected_revision OR NEW.challenge_json!=OLD.challenge_json OR NEW.expires_at!=OLD.expires_at OR NEW.created_at!=OLD.created_at OR (OLD.state!='PREPARED' AND NEW.state!=OLD.state) BEGIN SELECT RAISE(ABORT,'local domain challenge is immutable');END;`)
	if err != nil {
		return err
	}
	for _, table := range []string{"hub_local_domains_v1", "hub_local_domain_members_v1", "hub_local_domain_challenges_v1", "hub_local_domain_owner_operations_v1", "hub_local_domain_node_operations_v1"} {
		if _, err = s.db.Exec(fmt.Sprintf(`CREATE TRIGGER %s_no_delete BEFORE DELETE ON %s BEGIN SELECT RAISE(ABORT,'local domain history is permanent');END;`, table, table)); err != nil {
			return err
		}
	}
	for _, table := range []string{"hub_local_domain_owner_operations_v1", "hub_local_domain_node_operations_v1"} {
		if _, err = s.db.Exec(fmt.Sprintf(`CREATE TRIGGER %s_no_update BEFORE UPDATE ON %s BEGIN SELECT RAISE(ABORT,'local domain exact receipt is immutable');END;`, table, table)); err != nil {
			return err
		}
	}
	return nil
}
