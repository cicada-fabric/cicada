package n3_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

// Audit only: no write connection, Store initializer, enrollment or key creation.
// Registration and original key custody must survive removing the last Group,
// even when no business tool is authorized to return a positive whoami card.
func ownerGroupsStoredIdentities(t *testing.T, v *codexProductFixture, actors nativePeerActors, sids []string) []ownerGroupsIdentity {
	t.Helper()
	return ownerGroupsStoredIdentitiesAt(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"),
		v.actualNode.id, v.actualNode.state, v.f.cfg.Material.OwnerID, actors.workspaces, sids)
}

// Read-only audit against the actual shared NPT Hub and one exact Node root.
// The original caller retains its same four-actor oracle and SQL predicates.
func ownerGroupsStoredIdentitiesAt(t *testing.T, database, nodeID, nodeState, ownerID string, workspaces, sids []string) []ownerGroupsIdentity {
	t.Helper()
	if len(sids) != 4 || len(workspaces) != 4 {
		t.Fatal("identity audit needs the four actual original native Threads")
	}
	db := nodePairReadOnlyDB(t, database)
	defer db.Close()
	tx := must(db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true}))
	defer tx.Rollback()
	var result []ownerGroupsIdentity
	for index, sid := range sids {
		rows := must(tx.Query(`SELECT e.id,e.principal_id,e.machine_id,e.workspace,c.binding_id,c.binding_epoch,c.public_identity_json
FROM fabric_endpoints e JOIN endpoint_key_candidates_v2 c ON c.endpoint_id=e.id
WHERE e.native_session_id=? AND e.machine_id=? AND e.harness='codex' AND c.owner_id=? AND c.node_id=e.machine_id`,
			sid, nodeID, ownerID))
		var identities []ownerGroupsIdentity
		for rows.Next() {
			identity := ownerGroupsIdentity{SID: sid}
			var publicJSON []byte
			if rows.Scan(&identity.Endpoint, &identity.Principal, &identity.NodeID, &identity.Workspace,
				&identity.BindingID, &identity.BindingEpoch, &publicJSON) != nil {
				t.Fatal("actual native registration/key audit failed")
			}
			var public e2ee.PublicIdentity
			if len(publicJSON) > 64<<10 || json.Unmarshal(publicJSON, &public) != nil || e2ee.ValidatePublicIdentity(public) != nil {
				t.Fatal("actual enrolled Endpoint public identity is malformed")
			}
			clear(publicJSON)
			identity.PublicKeySHA256 = hash(must(json.Marshal(public)))
			keyRoot := filepath.Join(nodeState, "nodes", "node-"+url.PathEscape(nodeID))
			original, err := nodekeys.LoadExisting(keyRoot, identity.Endpoint)
			if err != nil || !reflect.DeepEqual(original.Public(), public) {
				t.Fatal("actual Node lost or replaced its original enrolled Endpoint key")
			}
			identities = append(identities, identity)
		}
		if rows.Err() != nil || rows.Close() != nil || len(identities) != 1 {
			t.Fatal("original SID no longer has exactly one native registration and enrolled key")
		}
		identity := identities[0]
		if identity.Workspace != workspaces[index] || identity.Endpoint == "" || identity.Principal == "" || identity.BindingID == "" || identity.BindingEpoch == 0 {
			t.Fatal("actual native registration changed its original workspace or binding")
		}
		result = append(result, identity)
	}
	return result
}

func ownerGroupsOriginalActors(t *testing.T, v *codexProductFixture, actors nativePeerActors, host *ownerGroupsHost) []ownerGroupsIdentity {
	t.Helper()
	identities := ownerGroupsStoredIdentities(t, v, actors, host.originalSIDs)
	for index, identity := range identities {
		label := "original-" + string(rune('a'+index))
		// External Join registers the native anchor without choosing business
		// authority. Inspect actual available rights, then explicitly select G1.
		host.groups(t, index, label+"-unselected", actors.active.NetworkID, "", map[string]string{actors.active.GroupID: "DEFAULT_POLICY"})
		selected := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: index, Label: label + "-select", Tool: "cicada_use_group",
			Arguments: map[string]any{"group_id": actors.active.GroupID}, ObserveFields: []string{"group_id"}})
		if selected.Public["group_id"] != actors.active.GroupID {
			t.Fatal("actual original actor could not explicitly select its authorized default Group")
		}
		observed := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: index, Label: "original-" + string(rune('a'+index)), Tool: "cicada_whoami",
			Arguments: map[string]any{}, ObserveFields: []string{"endpoint_id", "native_session_id", "node_id", "workspace", "group_id"}})
		if observed.Public["endpoint_id"] != identity.Endpoint || observed.Public["native_session_id"] != identity.SID ||
			observed.Public["node_id"] != identity.NodeID || observed.Public["workspace"] != identity.Workspace || observed.Public["group_id"] != actors.active.GroupID {
			t.Fatal("actual Host/Hook actor does not match its original native registration and default Group")
		}
	}
	return identities
}

func ownerGroupsNamedGroupCount(t *testing.T, v *codexProductFixture, network, name string) int {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"))
	defer db.Close()
	var count int
	if db.QueryRow(`SELECT count(*) FROM groups WHERE network_id=? AND name=?`, network, name).Scan(&count) != nil {
		t.Fatal("actual isolated Group effect audit failed")
	}
	return count
}

func ownerGroupsRelationCount(t *testing.T, v *codexProductFixture, endpoint, group string) int {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"))
	defer db.Close()
	var count int
	if db.QueryRow(`SELECT count(*) FROM endpoint_group_memberships WHERE endpoint_id=? AND group_id=? AND status='active'`, endpoint, group).Scan(&count) != nil {
		t.Fatal("actual exact Endpoint/Group relation audit failed")
	}
	return count
}

// Ignore routine heartbeat timestamps/version, retain all authorization fields
// of the ORIGINAL Group. Adding another Group cannot rotate this credential or
// broaden/narrow its Principal grants and exact Endpoint admission as a side effect.
func ownerGroupsRelationAuthorityHash(t *testing.T, v *codexProductFixture, endpoint, group string) string {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"))
	defer db.Close()
	rows := must(db.Query(`SELECT json_object('binding_id',b.id,'principal',b.principal_id,'endpoint',b.endpoint_id,
'enrolled_group_id',b.group_id,'selected_group_id',m.group_id,'native',b.native_session_id,'node',b.node_id,'workspace',b.workspace_id,'epoch',b.epoch,
'lease_owner',b.lease_owner,'credential_hash',b.credential_hash,'status',b.status,'mode',b.mode,'caps',b.capabilities_json,
'membership_id',m.id,'membership_status',m.status,'membership_revision',m.revision,'grants',m.grants_json,
'endpoint_status',eg.status,'endpoint_revision',eg.revision)
FROM session_bindings b JOIN memberships m ON m.principal_id=b.principal_id AND m.group_id=?
JOIN endpoint_group_memberships eg ON eg.endpoint_id=b.endpoint_id AND eg.group_id=m.group_id
WHERE b.endpoint_id=? AND b.id=(SELECT binding_id FROM endpoint_key_candidates_v2 WHERE endpoint_id=b.endpoint_id)
ORDER BY b.id`, group, endpoint))
	defer rows.Close()
	var values []json.RawMessage
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil || len(raw) > 64<<10 || !json.Valid(raw) || len(values) > 8 {
			clear(raw)
			t.Fatal("actual original Group authority audit exceeded its bounded projection")
		}
		values = append(values, raw)
	}
	defer func() {
		for _, value := range values {
			clear(value)
		}
	}()
	if rows.Err() != nil || len(values) != 1 {
		t.Fatal("actual original Group lacks one exact existing binding/Principal/Endpoint relation")
	}
	raw := must(json.Marshal(values))
	defer clear(raw)
	return hash(raw)
}
