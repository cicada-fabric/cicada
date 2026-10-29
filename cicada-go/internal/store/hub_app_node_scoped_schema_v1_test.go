package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
)

// Only disposable test databases use this helper. It reconstructs v69 DDL for
// a real upgrade/restore-boundary check without changing historical migrations.
func dropSyntheticAppNodeScopedMigration70(t *testing.T, db *Store) {
	t.Helper()
	for i := len(appNodeScopedSchemaObjects) - 1; i >= 0; i-- {
		dropSyntheticMigrationObject(t, db.db, appNodeScopedSchemaObjects[i])
	}
	for _, query := range []string{
		`ALTER TABLE hub_app_node_grants_v1 DROP COLUMN authority_node_id`,
		`ALTER TABLE hub_app_node_grants_v1 DROP COLUMN authority_kind`,
		`ALTER TABLE hub_node_pair_trust_v1 DROP COLUMN authority_kind`,
		`CREATE UNIQUE INDEX hub_app_node_grants_v1_active ON hub_app_node_grants_v1(owner_id,device_id) WHERE state='ACTIVE'`,
		`DELETE FROM schema_migrations_v2 WHERE version=70`,
	} {
		if _, err := db.db.Exec(query); err != nil {
			t.Fatal("historical synthetic v69 schema", err)
		}
	}
}

func syntheticScopedSchemaGrant(t *testing.T, db *sql.DB, id, kind, node, state string) error {
	t.Helper()
	claims := `{"scope":{"version":2,"authority_node_id":"` + node + `"},"candidate":{"node_id":"` + node + `"}}`
	if kind == "LEGACY_V1" {
		claims = `{"scope":{"version":1}}`
	}
	_, err := db.Exec(`INSERT INTO hub_app_node_grants_v1(grant_id,account_id,owner_id,device_id,claims_json,state,remaining,created_at,authority_kind,authority_node_id) VALUES(?,'SYNTHETIC-account','SYNTHETIC-owner','SYNTHETIC-device',?,?,1,'SYNTHETIC-no-proof',?,?)`, id, claims, state, kind, node)
	return err
}

func TestAppNodeScopedSchemaPreservesLegacyUpgradeBytes(t *testing.T) {
	f := n3Fixture(t, true)
	g := f.activate(t)
	client := f.client(t, g, 1, f.now)
	if _, err := f.db.ProcessHubAppNodeClient(client); err != nil {
		t.Fatal(err)
	}
	snapshot := func() []byte {
		var claims string
		var proof, receipt []byte
		var head, prov string
		if f.db.db.QueryRow(`SELECT claims_json,owner_proof,provenance_id FROM hub_app_node_grants_v1 WHERE grant_id=?`, g.GrantID).Scan(&claims, &proof, &prov) != nil {
			t.Fatal("original grant")
		}
		if f.db.db.QueryRow(`SELECT json_array(head_version,latest_grant_id,provenance_id) FROM hub_app_node_heads_v1 WHERE owner_id=? AND device_id=?`, f.scope.OwnerID, f.scope.DeviceID).Scan(&head) != nil {
			t.Fatal("original head")
		}
		if f.db.db.QueryRow(`SELECT response_packet FROM hub_app_node_operations_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, f.scope.OwnerID, f.scope.DeviceID, client.Route.OperationID).Scan(&receipt) != nil {
			t.Fatal("original receipt")
		}
		raw, err := json.Marshal([]any{claims, proof, head, prov, receipt})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := snapshot()
	dropSyntheticAppNodeScopedMigration70(t, f.db)
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.db, err = New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("migration rewrote legacy claims/proof/head/provenance/receipt")
	}
	var kind, node string
	if f.db.db.QueryRow(`SELECT authority_kind,authority_node_id FROM hub_app_node_grants_v1 WHERE grant_id=?`, g.GrantID).Scan(&kind, &node) != nil || kind != "LEGACY_V1" || node != "" {
		t.Fatal("legacy namespace backfill invented Node authority")
	}
	var count int
	if f.db.db.QueryRow(`SELECT count(*) FROM hub_app_node_scoped_heads_v1`).Scan(&count) != nil || count != 0 {
		t.Fatal("legacy head/provenance copied into new scope")
	}
}

func TestAppNodeScopedSchemaGlobalPendingAndIndependentActiveHeads(t *testing.T) {
	f := n3Fixture(t, true)
	if err := syntheticScopedSchemaGrant(t, f.db.db, "SYNTHETIC-legacy", "LEGACY_V1", "", "PREPARED"); err != nil {
		t.Fatal(err)
	}
	if err := syntheticScopedSchemaGrant(t, f.db.db, "SYNTHETIC-B", "NODE_V1", "SYNTHETIC-node-B", "PREPARED"); err == nil {
		t.Fatal("new namespace bypassed whole-App PREPARED uniqueness")
	}
	if _, err := f.db.db.Exec(`UPDATE hub_app_node_grants_v1 SET state='ACTIVE' WHERE grant_id='SYNTHETIC-legacy'`); err != nil {
		t.Fatal(err)
	}
	if err := syntheticScopedSchemaGrant(t, f.db.db, "SYNTHETIC-B", "NODE_V1", "SYNTHETIC-node-B", "ACTIVE"); err != nil {
		t.Fatal(err)
	}
	if err := syntheticScopedSchemaGrant(t, f.db.db, "SYNTHETIC-C", "NODE_V1", "SYNTHETIC-node-C", "ACTIVE"); err != nil {
		t.Fatal(err)
	}
	if err := syntheticScopedSchemaGrant(t, f.db.db, "SYNTHETIC-B-again", "NODE_V1", "SYNTHETIC-node-B", "ACTIVE"); err == nil {
		t.Fatal("two ACTIVE grants for one exact scope")
	}
	if _, err := f.db.db.Exec(`UPDATE hub_app_node_grants_v1 SET authority_node_id='SYNTHETIC-node-C' WHERE grant_id='SYNTHETIC-B'`); err == nil {
		t.Fatal("grant namespace moved")
	}
	if _, err := f.db.db.Exec(`INSERT INTO hub_app_node_scoped_heads_v1 VALUES('SYNTHETIC-owner','SYNTHETIC-device','SYNTHETIC-node-B',1,'SYNTHETIC-B','SYNTHETIC-permanent-prov')`); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{`UPDATE hub_app_node_scoped_heads_v1 SET head_version=0`, `UPDATE hub_app_node_scoped_heads_v1 SET provenance_id=''`, `UPDATE hub_app_node_scoped_heads_v1 SET authority_node_id='SYNTHETIC-node-C'`, `DELETE FROM hub_app_node_scoped_heads_v1`} {
		if _, err := f.db.db.Exec(query); err == nil {
			t.Fatal("scoped head/provenance history changed")
		}
	}
}

func TestAppNodeScopedSchema70RestoreRemainsUnsupported(t *testing.T) {
	if CurrentV2SchemaVersion != 70 || hubRestoreReviewedSchemaVersion != 67 {
		t.Fatal("unreviewed restore boundary changed")
	}
	_, root, _, _ := nativeTLSStoreFixture(t)
	if _, err := InspectHubRestoreCheckpointReadOnly(root); !errors.Is(err, ErrHubRestoreCoverage) {
		t.Fatal("schema70 gained restore authority without inventory/floors", err)
	}
}
