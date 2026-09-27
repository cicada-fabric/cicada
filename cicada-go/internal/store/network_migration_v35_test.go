package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// These are existing v34 authorities, including opaque signed and sealed
// bytes. Only their digests and row counts enter test failures.
var networkV35PreservedTables = []string{
	"owner_approval_keys_v2",
	"client_devices_v2",
	"client_device_requests_v2",
	"client_device_grant_nonces_v2",
	"user_monitor_broadcast_v2",
	"group_endpoint_key_grants_v2",
	"principals",
	"groups",
	"memberships",
	"endpoint_group_memberships",
	"fabric_endpoints",
	"session_bindings",
}

type networkV35TableSnapshot struct {
	Count  int
	Digest string
}

func snapshotNetworkV35PreservedTables(t *testing.T, db *sql.DB) map[string]networkV35TableSnapshot {
	t.Helper()
	snapshots := make(map[string]networkV35TableSnapshot, len(networkV35PreservedTables))
	for _, table := range networkV35PreservedTables {
		query := `SELECT * FROM ` + table + ` ORDER BY rowid`
		if table == "groups" {
			// v35 appends network_id; compare the complete v34 projection.
			info, err := db.Query(`PRAGMA table_info(groups)`)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for info.Next() {
				var sequence, notNull, primaryKey int
				var name, kind string
				var defaultValue any
				if err := info.Scan(&sequence, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
					info.Close()
					t.Fatal(err)
				}
				if name != "network_id" {
					names = append(names, name)
				}
			}
			if err := info.Err(); err != nil {
				info.Close()
				t.Fatal(err)
			}
			info.Close()
			query = `SELECT ` + strings.Join(names, ",") + ` FROM groups ORDER BY rowid`
		}
		rows, err := db.Query(query)
		if err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		hash := sha256.New()
		encodedColumns, _ := json.Marshal(columns)
		hash.Write(encodedColumns)
		count := 0
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			encoded, err := json.Marshal(values)
			if err != nil {
				rows.Close()
				t.Fatal(err)
			}
			hash.Write(encoded)
			count++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
		snapshots[table] = networkV35TableSnapshot{Count: count, Digest: hex.EncodeToString(hash.Sum(nil))}
	}
	return snapshots
}

func TestNetworkV35UpgradePreservesV34ClientAndMonitorState(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("synthetic historical approved Monitor payload")
	prepared, _ := f.prepare(t, body)
	approved, confirmRequestID := f.confirm(t, prepared, body, 1)
	s := f.sealed.store

	// Reconstruct the exact additive v34 schema boundary from a current test
	// fixture: retain all historical rows, remove only v35 objects and ledger.
	for _, ddl := range []string{
		`DROP TABLE network_message_enrollment_v2`,
		`DROP TABLE network_access_sessions_v2`,
		`DROP TABLE network_join_consents_v2`,
		`DROP TABLE network_invitations_v2`,
		`DROP TABLE endpoint_network_memberships_v2`,
		`DROP TABLE network_memberships_v2`,
		`DROP TABLE network_group_mappings_v2`,
		`DROP TABLE networks_v2`,
		`DROP TABLE network_mode_v2`,
		`DROP INDEX groups_network_idx`,
		`ALTER TABLE groups DROP COLUMN network_id`,
		`DELETE FROM schema_migrations_v2 WHERE version=35`,
	} {
		if _, err := s.db.Exec(ddl); err != nil {
			t.Fatalf("form v34 schema: %v", err)
		}
	}
	var highest int
	if err := s.db.QueryRow(`SELECT max(version) FROM schema_migrations_v2 WHERE state='applied'`).Scan(&highest); err != nil || highest != 34 {
		t.Fatalf("not a v34 ledger: version=%d err=%v", highest, err)
	}
	before := snapshotNetworkV35PreservedTables(t, s.db)
	for _, table := range networkV35PreservedTables {
		if before[table].Count == 0 {
			t.Fatalf("v34 fixture has no %s evidence", table)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatalf("upgrade v34 to v35: %v", err)
	}
	f.sealed.store = reopened
	defer reopened.Close()
	after := snapshotNetworkV35PreservedTables(t, reopened.db)
	for _, table := range networkV35PreservedTables {
		if before[table] != after[table] {
			t.Errorf("v35 changed %s: before=%+v after=%+v", table, before[table], after[table])
		}
	}
	entry, err := reopened.readV2Migration(35)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 1 {
		t.Fatalf("v35 ledger not applied exactly once: %+v %v", entry, err)
	}
	var groupNetwork, phase string
	if err := reopened.db.QueryRow(`SELECT network_id FROM groups WHERE id=?`, f.sealed.groupID).Scan(&groupNetwork); err != nil || groupNetwork != "" {
		t.Fatalf("legacy Group was auto-mapped: %q %v", groupNetwork, err)
	}
	if err := reopened.db.QueryRow(`SELECT phase FROM network_mode_v2 WHERE id=1`).Scan(&phase); err != nil || phase != NetworkModePreparing {
		t.Fatalf("Network mode after upgrade: %q %v", phase, err)
	}
	for _, table := range []string{"networks_v2", "network_memberships_v2", "endpoint_network_memberships_v2", "network_access_sessions_v2", "network_message_enrollment_v2"} {
		var count int
		if err := reopened.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Errorf("v35 invented %s rows: count=%d err=%v", table, count, err)
		}
	}
	status, err := reopened.GetUserMonitorBroadcastV2Status(confirmRequestID, approved.PreviewID)
	if err != nil || status.Status != UserMonitorBroadcastV2Approved {
		t.Fatalf("approved Monitor state was not readable after upgrade: %v %v", status, err)
	}
	delivery, err := reopened.AuthorizeUserMonitorBroadcastV2Delivery(f.consumeInput(approved))
	if err != nil || delivery == nil || len(delivery.SealedPayload) == 0 {
		t.Fatalf("historical sealed Monitor delivery was lost: %v", err)
	}
}
