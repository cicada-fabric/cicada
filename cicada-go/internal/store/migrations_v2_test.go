package store

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestV2MigrationsUpgradeLegacyStateAndRemainRepeatable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)

	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	assertLegacyStatePreserved(t, store)
	assertV2Ledger(t, store, map[int]string{
		1:  v2MigrationApplied,
		2:  v2MigrationApplied,
		3:  v2MigrationApplied,
		4:  v2MigrationApplied,
		5:  v2MigrationApplied,
		6:  v2MigrationApplied,
		7:  v2MigrationApplied,
		8:  v2MigrationApplied,
		9:  v2MigrationApplied,
		10: v2MigrationApplied,
		11: v2MigrationApplied,
		12: v2MigrationApplied,
		13: v2MigrationApplied,
		14: v2MigrationApplied,
		15: v2MigrationApplied,
		16: v2MigrationApplied,
		17: v2MigrationApplied,
		18: v2MigrationApplied,
		19: v2MigrationApplied,
		20: v2MigrationApplied,
		21: v2MigrationApplied,
		22: v2MigrationApplied,
		23: v2MigrationApplied,
		24: v2MigrationApplied,
		25: v2MigrationApplied,
		26: v2MigrationApplied,
		27: v2MigrationApplied,
		28: v2MigrationApplied,
		29: v2MigrationApplied,
		30: v2MigrationApplied,
		31: v2MigrationApplied,
		32: v2MigrationApplied,
		33: v2MigrationApplied,
		34: v2MigrationApplied,
		35: v2MigrationApplied,
		36: v2MigrationApplied,
		37: v2MigrationApplied, 38: v2MigrationApplied, 39: v2MigrationApplied, 40: v2MigrationApplied,
		41: v2MigrationApplied,
		42: v2MigrationApplied,
		43: v2MigrationApplied,
		44: v2MigrationApplied, 45: v2MigrationApplied, 46: v2MigrationApplied, 47: v2MigrationApplied,
		48: v2MigrationApplied,
		49: v2MigrationApplied,
		50: v2MigrationApplied,
		51: v2MigrationApplied,
		52: v2MigrationApplied,
		53: v2MigrationApplied,
		54: v2MigrationApplied,
		55: v2MigrationApplied,
		56: v2MigrationApplied,
		57: v2MigrationApplied,
		58: v2MigrationApplied,
		59: v2MigrationApplied,
		60: v2MigrationApplied, 61: v2MigrationApplied, 62: v2MigrationApplied, 63: v2MigrationApplied, 64: v2MigrationApplied, 65: v2MigrationApplied, 66: v2MigrationApplied, 67: v2MigrationApplied, 68: v2MigrationApplied,
	})
	for _, migration := range v2Migrations {
		entry, err := store.readV2Migration(migration.Version)
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil || entry.Attempts != 1 || entry.SourceCount != entry.TargetCount || entry.LastError != "" {
			t.Fatalf("unexpected first-run ledger entry for %s: %#v", migration.ID, entry)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// A second process startup observes applied rows and verifies them without
	// re-running any migration or changing its attempt count.
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	assertV2Ledger(t, reopened, map[int]string{
		1:  v2MigrationApplied,
		2:  v2MigrationApplied,
		3:  v2MigrationApplied,
		4:  v2MigrationApplied,
		5:  v2MigrationApplied,
		6:  v2MigrationApplied,
		7:  v2MigrationApplied,
		8:  v2MigrationApplied,
		9:  v2MigrationApplied,
		10: v2MigrationApplied,
		11: v2MigrationApplied,
		12: v2MigrationApplied,
		13: v2MigrationApplied,
		14: v2MigrationApplied,
		15: v2MigrationApplied,
		16: v2MigrationApplied,
		17: v2MigrationApplied,
		18: v2MigrationApplied,
		19: v2MigrationApplied,
		20: v2MigrationApplied,
		21: v2MigrationApplied,
		22: v2MigrationApplied,
		23: v2MigrationApplied,
		24: v2MigrationApplied,
		25: v2MigrationApplied,
		26: v2MigrationApplied,
		27: v2MigrationApplied,
		28: v2MigrationApplied,
		29: v2MigrationApplied,
		30: v2MigrationApplied,
		31: v2MigrationApplied,
		32: v2MigrationApplied,
		33: v2MigrationApplied,
		34: v2MigrationApplied,
		35: v2MigrationApplied,
		36: v2MigrationApplied,
		37: v2MigrationApplied, 38: v2MigrationApplied, 39: v2MigrationApplied, 40: v2MigrationApplied,
		41: v2MigrationApplied,
		42: v2MigrationApplied,
		43: v2MigrationApplied,
		44: v2MigrationApplied, 45: v2MigrationApplied, 46: v2MigrationApplied, 47: v2MigrationApplied,
		48: v2MigrationApplied,
		49: v2MigrationApplied,
		50: v2MigrationApplied,
		51: v2MigrationApplied,
		52: v2MigrationApplied,
		53: v2MigrationApplied,
		54: v2MigrationApplied,
		55: v2MigrationApplied,
		56: v2MigrationApplied,
		57: v2MigrationApplied,
		58: v2MigrationApplied,
		59: v2MigrationApplied,
		60: v2MigrationApplied, 61: v2MigrationApplied, 62: v2MigrationApplied, 63: v2MigrationApplied, 64: v2MigrationApplied, 65: v2MigrationApplied, 66: v2MigrationApplied, 67: v2MigrationApplied, 68: v2MigrationApplied,
	})
	for _, migration := range v2Migrations {
		entry, err := reopened.readV2Migration(migration.Version)
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil || entry.Attempts != 1 {
			t.Fatalf("repeated startup re-applied %s: %#v", migration.ID, entry)
		}
	}

	var latest int
	if err := reopened.db.QueryRow(`SELECT max(version) FROM schema_migrations_v2 WHERE state = ?`, v2MigrationApplied).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if latest != CurrentV2SchemaVersion {
		t.Fatalf("unexpected current v2 schema version: got %d want %d", latest, CurrentV2SchemaVersion)
	}
}

func TestRelayAskExpiryIndexMigrationPreservesRowsAndRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic Relay Ask expiry index interruption")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == relayAskExpiryOrderMigrationID && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatalf("v59 interruption was not reported: %v", err)
	}

	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	check.SetMaxOpenConns(1)
	var appliedMax, failedCount, indexCount int
	var hubIDBefore string
	if err := check.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubIDBefore); err != nil {
		t.Fatal(err)
	}
	if err := check.QueryRow(`SELECT coalesce(max(version),0) FROM schema_migrations_v2 WHERE state='applied'`).Scan(&appliedMax); err != nil || appliedMax != 58 {
		t.Fatalf("interrupted v59 advanced applied schema: max=%d err=%v", appliedMax, err)
	}
	if err := check.QueryRow(`SELECT count(*) FROM schema_migrations_v2 WHERE version=59 AND state='failed' AND attempts=1`).Scan(&failedCount); err != nil || failedCount != 1 {
		t.Fatalf("interrupted v59 ledger row count=%d err=%v", failedCount, err)
	}
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name=?`, relayAskExpiryOrderIndex).Scan(&indexCount); err != nil || indexCount != 0 {
		t.Fatalf("interrupted v59 left index count=%d err=%v", indexCount, err)
	}
	seedRelayAskExpiryMigrationRows(t, check)
	beforeRequests := sqliteRowsForTest(t, check, `SELECT * FROM relay_v2_requests WHERE request_id LIKE 'synthetic_v59_%' ORDER BY request_id`)
	beforeMessages := sqliteRowsForTest(t, check, `SELECT * FROM fabric_messages WHERE id LIKE 'synthetic_v59_%' ORDER BY id`)
	if len(beforeRequests) != 3 || len(beforeMessages) != 3 {
		t.Fatalf("synthetic v58 fixture rows=%d requests/%d messages", len(beforeRequests), len(beforeMessages))
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	hubIDAfter, err := reopened.GetClientHubID()
	if err != nil || hubIDAfter != hubIDBefore {
		t.Fatalf("v59 changed stable Hub identity: before=%q after=%q err=%v", hubIDBefore, hubIDAfter, err)
	}
	entry, err := reopened.readV2Migration(59)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v59 retry ledger=%+v err=%v", entry, err)
	}
	if err := verifyRelayAskExpiryOrderIndex(reopened.db); err != nil {
		t.Fatalf("v59 index definition was not installed: %v", err)
	}
	if after := sqliteRowsForTest(t, reopened.db, `SELECT * FROM relay_v2_requests WHERE request_id LIKE 'synthetic_v59_%' ORDER BY request_id`); !reflect.DeepEqual(beforeRequests, after) {
		t.Fatalf("v59 changed existing Relay request rows: before=%v after=%v", beforeRequests, after)
	}
	if after := sqliteRowsForTest(t, reopened.db, `SELECT * FROM fabric_messages WHERE id LIKE 'synthetic_v59_%' ORDER BY id`); !reflect.DeepEqual(beforeMessages, after) {
		t.Fatalf("v59 changed existing Relay message rows: before=%v after=%v", beforeMessages, after)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	repeated, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer repeated.Close()
	entry, err = repeated.readV2Migration(59)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v59 repeated startup changed ledger attempts: entry=%+v err=%v", entry, err)
	}
	if err := verifyRelayAskExpiryOrderIndex(repeated.db); err != nil {
		t.Fatalf("v59 index definition failed on reopen: %v", err)
	}

	// An index with the right name but wrong target expression must not pass
	// migration verification on a later startup.
	if _, err := repeated.db.Exec(`DROP INDEX ` + relayAskExpiryOrderIndex); err != nil {
		t.Fatal(err)
	}
	if _, err := repeated.db.Exec(`CREATE INDEX ` + relayAskExpiryOrderIndex + ` ON relay_v2_requests (state, expires_at)`); err != nil {
		t.Fatal(err)
	}
	if err := repeated.initializeRelayAskExpiryOrderIndex(); err != nil {
		t.Fatalf("idempotent v59 initializer rejected same-name index: %v", err)
	}
	for _, migration := range v2Migrations {
		if migration.ID == relayAskExpiryOrderMigrationID {
			if err := repeated.verifyV2Migration(migration, nil); err == nil {
				t.Fatal("v59 accepted a same-name index with the wrong table expression")
			}
			return
		}
	}
	t.Fatal("v59 migration definition is missing")
}

func seedRelayAskExpiryMigrationRows(t *testing.T, db *sql.DB) {
	t.Helper()
	rows := []struct{ id, state, expires string }{
		{"synthetic_v59_open", FabricRequestOpen, "2026-10-09T00:00:00Z"},
		{"synthetic_v59_unbounded", FabricRequestCancelRequested, ""},
		{"synthetic_v59_invalid", FabricRequestOpen, "synthetic-invalid-time"},
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, row := range rows {
		messageID := "synthetic_v59_message_" + row.id
		if _, err := tx.Exec(`INSERT INTO fabric_messages(id,from_endpoint_id,to_endpoint_id,kind,body,created_at)
VALUES(?,?,?,?,?,?)`, messageID, "synthetic_sender", "synthetic_receiver", "ask", "synthetic body", "2026-10-08T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO relay_v2_requests
(request_id,message_id,sender_endpoint_id,sender_principal_id,sender_group_id,receiver_endpoint_id,receiver_group_id,digest,state,expires_at,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, row.id, messageID, "synthetic_sender", "synthetic_principal", "synthetic_group", "synthetic_receiver", "synthetic_receiver_group", "synthetic_digest", row.state, row.expires, "2026-10-08T00:00:00Z", "2026-10-08T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func sqliteRowsForTest(t *testing.T, db *sql.DB, query string) [][]any {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var result [][]any
	for rows.Next() {
		dest := make([]any, len(columns))
		for i := range dest {
			dest[i] = new(any)
		}
		if err := rows.Scan(dest...); err != nil {
			t.Fatal(err)
		}
		row := make([]any, len(dest))
		for i := range dest {
			value := *(dest[i].(*any))
			if blob, ok := value.([]byte); ok {
				value = append([]byte(nil), blob...)
			}
			row[i] = value
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestClientTopologyV41MigrationInterruptionRollsBackAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic v41 interruption")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.client.atomic_topology_group_create" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatalf("v41 interruption was not reported: %v", err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table'
AND name IN ('client_topology_group_create_guard_v2','client_topology_group_creates_v2')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("interrupted v41 left %d tables", count)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(41)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v41 retry ledger=%+v err=%v", entry, err)
	}
	if err := reopened.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table'
AND name IN ('client_topology_group_create_guard_v2','client_topology_group_creates_v2')`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("v41 tables after restart=%d err=%v", count, err)
	}
}

func TestNetworkTaskV42UpgradeInterruptionAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic v42 interruption")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.fabric.network_task_offers" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatalf("v42 interruption was not reported: %v", err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var latest int
	if err := check.QueryRow(`SELECT max(version) FROM schema_migrations_v2 WHERE state=?`, v2MigrationApplied).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if latest != 41 {
		t.Fatalf("interrupted v42 advanced applied ledger to %d", latest)
	}
	var taskTables int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN
('network_task_offers_v2','network_task_readers_v2','network_task_results_v2')`).Scan(&taskTables); err != nil {
		t.Fatal(err)
	}
	if taskTables != 0 {
		t.Fatalf("interrupted v42 left %d task tables", taskTables)
	}
	var askIndexCount int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='relay_v2_requests_sender_endpoint_idx'`).Scan(&askIndexCount); err != nil {
		t.Fatal(err)
	}
	if askIndexCount != 0 {
		t.Fatalf("interrupted v42 left sender endpoint index installed: %d", askIndexCount)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(42)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v42 retry ledger=%+v err=%v", entry, err)
	}
	var latestObjects int
	if err := reopened.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN
('network_task_offers_v2','network_task_readers_v2','network_task_results_v2')`).Scan(&latestObjects); err != nil || latestObjects != 3 {
		t.Fatalf("v42 tables after upgrade=%d err=%v", latestObjects, err)
	}
	if err := reopened.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='relay_v2_requests_sender_endpoint_idx'`).Scan(&askIndexCount); err != nil || askIndexCount != 1 {
		t.Fatalf("v43 sender endpoint index after upgrade=%d err=%v", askIndexCount, err)
	}
	taskBudgetMigration, err := reopened.readV2Migration(43)
	if err != nil || taskBudgetMigration == nil || taskBudgetMigration.State != v2MigrationApplied || taskBudgetMigration.Attempts != 1 {
		t.Fatalf("v43 retry ledger=%+v err=%v", taskBudgetMigration, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	assertLegacyStatePreserved(t, restarted)
	entry, err = restarted.readV2Migration(42)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v42 restart changed migration ledger=%+v err=%v", entry, err)
	}
	taskBudgetMigration, err = restarted.readV2Migration(43)
	if err != nil || taskBudgetMigration == nil || taskBudgetMigration.State != v2MigrationApplied || taskBudgetMigration.Attempts != 1 {
		t.Fatalf("v43 restart changed migration ledger=%+v err=%v", taskBudgetMigration, err)
	}
}

func TestRelayAskSenderEndpointV43UpgradeInterruptionPreservesPendingAsk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic v43 interruption")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.relay.ask_sender_endpoint_budget" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatalf("v43 interruption was not reported: %v", err)
	}

	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := check.QueryRow(`SELECT max(version) FROM schema_migrations_v2 WHERE state=?`, v2MigrationApplied).Scan(&applied); err != nil || applied != 42 {
		t.Fatalf("v43 interruption applied version=%d err=%v", applied, err)
	}
	var indexCount int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='relay_v2_requests_sender_endpoint_idx'`).Scan(&indexCount); err != nil || indexCount != 0 {
		t.Fatalf("interrupted v43 left index count=%d err=%v", indexCount, err)
	}
	created := now()
	if _, err := check.Exec(`INSERT INTO fabric_messages(id,from_endpoint_id,to_endpoint_id,kind,body,created_at)
VALUES('legacy_pending_ask_message','legacy_sender','legacy_receiver','ask','synthetic legacy body',?)`, created); err != nil {
		check.Close()
		t.Fatal(err)
	}
	if _, err := check.Exec(`INSERT INTO relay_v2_requests
(request_id,message_id,sender_endpoint_id,sender_principal_id,sender_group_id,receiver_endpoint_id,receiver_group_id,digest,state,created_at,updated_at)
VALUES('legacy_pending_ask','legacy_pending_ask_message','legacy_sender','legacy_principal','legacy_group','legacy_receiver','legacy_receiver_group','synthetic-digest','OPEN',?,?)`, created, created); err != nil {
		check.Close()
		t.Fatal(err)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var expiry string
	if err := reopened.db.QueryRow(`SELECT expires_at FROM relay_v2_requests WHERE request_id='legacy_pending_ask'`).Scan(&expiry); err != nil || expiry != "" {
		t.Fatalf("v43 changed unbounded historical request expiry=%q err=%v", expiry, err)
	}
	var pending int
	tx, err := reopened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	pending, err = relayPendingAskCountTx(tx, RelayAdmissionScopeSenderEndpoint,
		"legacy_sender", "", "", "", now())
	_ = tx.Rollback()
	if err != nil || pending != 1 {
		t.Fatalf("legacy pending Ask was not preserved as pending: count=%d err=%v", pending, err)
	}
	entry, err := reopened.readV2Migration(43)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v43 retry ledger=%+v err=%v", entry, err)
	}
}

func TestRelayLinkNetworkEnrollmentV44UpgradeInterruptionAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic v44 interruption")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.relay.link_network_enrollment" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatalf("v44 interruption was not reported: %v", err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := check.QueryRow(`SELECT max(version) FROM schema_migrations_v2 WHERE state=?`, v2MigrationApplied).Scan(&applied); err != nil || applied != 43 {
		t.Fatalf("v44 interruption applied version=%d err=%v", applied, err)
	}
	columns, err := existingColumns(check, "network_message_enrollment_v2", []string{"receiver_network_id"})
	if err != nil || len(columns) != 0 {
		t.Fatalf("interrupted v44 left receiver Network column: columns=%v err=%v", columns, err)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	columns, err = existingColumns(reopened.db, "network_message_enrollment_v2", []string{"receiver_network_id"})
	if err != nil || len(columns) != 1 {
		t.Fatalf("v44 retry did not install receiver Network column: columns=%v err=%v", columns, err)
	}
	entry, err := reopened.readV2Migration(44)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v44 retry ledger=%+v err=%v", entry, err)
	}
}

func TestV2MigrationFailureRollsBackSchemaAndResumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("simulated process interruption")

	failed, err := openStoreWithMigrationHook(path, func(migrationID, phase string) error {
		if migrationID == "v2.relay.delivery" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if err == nil {
		failed.Close()
		t.Fatal("expected injected migration failure")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("migration failure did not preserve injected cause: %v", err)
	}

	// The savepoint includes every relay DDL statement and the running ledger
	// row, so a failed version leaves no partially-created relay schema.
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var relayTables int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'relay_v2_%'`).Scan(&relayTables); err != nil {
		t.Fatal(err)
	}
	if relayTables != 0 {
		t.Fatalf("failed relay migration left %d tables", relayTables)
	}
	var state string
	var attempts int
	if err := check.QueryRow(`SELECT state, attempts FROM schema_migrations_v2 WHERE version = 3`).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != v2MigrationFailed || attempts != 1 {
		t.Fatalf("failed migration was not recorded for retry: state=%q attempts=%d", state, attempts)
	}
	var identityTables int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN ('principals', 'groups', 'session_bindings')`).Scan(&identityTables); err != nil {
		t.Fatal(err)
	}
	if identityTables != 3 {
		t.Fatalf("earlier committed migration was unexpectedly rolled back: %d tables", identityTables)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}

	// A normal restart retries the failed version exactly once, then proceeds
	// to the gateway version.  Legacy rows and opaque key/replay state survive
	// both the failed and successful attempts.
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	assertV2Ledger(t, reopened, map[int]string{
		1:  v2MigrationApplied,
		2:  v2MigrationApplied,
		3:  v2MigrationApplied,
		4:  v2MigrationApplied,
		5:  v2MigrationApplied,
		6:  v2MigrationApplied,
		7:  v2MigrationApplied,
		8:  v2MigrationApplied,
		9:  v2MigrationApplied,
		10: v2MigrationApplied,
		11: v2MigrationApplied,
		12: v2MigrationApplied,
		13: v2MigrationApplied,
		14: v2MigrationApplied,
		15: v2MigrationApplied,
		16: v2MigrationApplied,
		17: v2MigrationApplied,
		18: v2MigrationApplied,
		19: v2MigrationApplied,
		20: v2MigrationApplied,
		21: v2MigrationApplied,
		22: v2MigrationApplied,
		23: v2MigrationApplied,
		24: v2MigrationApplied,
		25: v2MigrationApplied,
		26: v2MigrationApplied,
		27: v2MigrationApplied,
		28: v2MigrationApplied,
		29: v2MigrationApplied,
		30: v2MigrationApplied,
		31: v2MigrationApplied,
		32: v2MigrationApplied,
		33: v2MigrationApplied,
		34: v2MigrationApplied,
		35: v2MigrationApplied,
		36: v2MigrationApplied,
		37: v2MigrationApplied, 38: v2MigrationApplied, 39: v2MigrationApplied, 40: v2MigrationApplied,
		41: v2MigrationApplied,
		42: v2MigrationApplied,
		43: v2MigrationApplied,
		44: v2MigrationApplied, 45: v2MigrationApplied, 46: v2MigrationApplied, 47: v2MigrationApplied,
		48: v2MigrationApplied,
		49: v2MigrationApplied,
		50: v2MigrationApplied,
		51: v2MigrationApplied,
		52: v2MigrationApplied,
		53: v2MigrationApplied,
		54: v2MigrationApplied,
		55: v2MigrationApplied,
		56: v2MigrationApplied,
		57: v2MigrationApplied,
		58: v2MigrationApplied,
		59: v2MigrationApplied,
		60: v2MigrationApplied, 61: v2MigrationApplied, 62: v2MigrationApplied, 63: v2MigrationApplied, 64: v2MigrationApplied, 65: v2MigrationApplied, 66: v2MigrationApplied, 67: v2MigrationApplied, 68: v2MigrationApplied,
	})
	entry, err := reopened.readV2Migration(3)
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil || entry.Attempts != 2 || entry.LastError != "" {
		t.Fatalf("failed migration did not resume cleanly: %#v", entry)
	}
}

func TestTypedNetworkCollaborationMigrationRollsBackAndResumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic typed Network migration interruption")
	failed, err := openStoreWithMigrationHook(path, func(migrationID, phase string) error {
		if migrationID == "v2.fabric.typed_network_collaboration_keys" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		failed.Close()
	}
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("expected typed collaboration migration interruption, got store=%v err=%v", failed, err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"network_collaboration_key_grants_v2", "network_collaboration_key_grant_nonces_v2"} {
		var count int
		if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			check.Close()
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("failed migration retained partial table %s", table)
		}
	}
	columns, err := existingColumns(check, "network_direct_message_routes_v2", []string{"key_purpose"})
	if err != nil || len(columns) != 0 {
		check.Close()
		t.Fatalf("failed migration retained purpose column: %v %v", columns, err)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(47)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("typed migration retry did not apply exactly once: entry=%+v err=%v", entry, err)
	}
	columns, err = existingColumns(reopened.db, "network_direct_message_routes_v2", []string{"key_purpose"})
	if err != nil || len(columns) != 1 {
		t.Fatalf("typed migration retry omitted route purpose: %v %v", columns, err)
	}
}

func TestNetworkBroadcastMigrationRollsBackAndResumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic Network Broadcast migration interruption")
	failed, err := openStoreWithMigrationHook(path, func(migrationID, phase string) error {
		if migrationID == "v2.fabric.network_broadcast_metadata" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		failed.Close()
	}
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("expected Broadcast migration interruption, got store=%v err=%v", failed, err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"network_broadcasts_v2", "network_broadcast_recipients_v2"} {
		var count int
		if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			check.Close()
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("failed migration retained partial table %s", table)
		}
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(48)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("Broadcast migration retry did not apply exactly once: entry=%+v err=%v", entry, err)
	}
}

func TestNodeControlPQSchemaMigrationRollsBackAndResumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic Node-Control PQ migration interruption")
	failed, err := openStoreWithMigrationHook(path, func(migrationID, phase string) error {
		if migrationID == "v2.node.control_pq_bindings" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		failed.Close()
	}
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("expected Node-Control migration interruption, got store=%v err=%v", failed, err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	for _, name := range []string{
		"node_control_key_requests_v1", "node_control_key_requests_v1_pending_node_idx",
		"node_control_key_requests_v1_expiry_idx", "node_control_key_request_candidate_immutable_v1",
		"node_control_key_bindings_v1", "node_control_key_bindings_v1_epoch_idx",
		"node_control_key_bindings_v1_active_node_idx", "node_control_key_bindings_v1_credential_idx",
		"node_control_key_binding_immutable_v1", "node_control_rpc_sequences_v1",
		"node_control_rpc_inbox_v1", "node_control_rpc_request_immutable_v1",
	} {
		var count int
		if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name=?`, name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("failed Node-Control migration retained partial object %s", name)
		}
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(49)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("Node-Control migration retry did not apply exactly once: entry=%+v err=%v", entry, err)
	}
}

func TestRelayCausalAskMigrationRollsBackAndResumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic causal Ask migration interruption")
	failed, err := openStoreWithMigrationHook(path, func(migrationID, phase string) error {
		if migrationID == "v2.relay.causal_ask_budget" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		failed.Close()
	}
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("expected causal Ask migration interruption, got store=%v err=%v", failed, err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	columns, err := existingColumns(check, "relay_v2_requests", []string{
		"parent_request_id", "causal_root_request_id", "causal_depth",
	})
	if err != nil {
		check.Close()
		t.Fatal(err)
	}
	if len(columns) != 0 {
		check.Close()
		t.Fatalf("failed migration retained causal columns: %v", columns)
	}
	var indexCount int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='relay_v2_requests_causal_root_idx'`).Scan(&indexCount); err != nil {
		check.Close()
		t.Fatal(err)
	}
	if indexCount != 0 {
		check.Close()
		t.Fatalf("failed migration retained causal index: count=%d", indexCount)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(50)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("causal Ask migration retry did not apply exactly once: entry=%+v err=%v", entry, err)
	}
	columns, err = existingColumns(reopened.db, "relay_v2_requests", []string{
		"parent_request_id", "causal_root_request_id", "causal_depth",
	})
	if err != nil || len(columns) != 3 {
		t.Fatalf("causal Ask retry omitted lineage columns: %v %v", columns, err)
	}
}

func TestEndpointKeyCandidateMigrationRollsBackAndReopensWithLegacyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("interrupt Endpoint key candidate migration")

	_, err := openStoreWithMigrationHook(path, func(migrationID, phase string) error {
		if migrationID == "v2.fabric.endpoint_key_candidates" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if !errors.Is(err, injected) {
		t.Fatalf("expected Endpoint key candidate migration failure, got %v", err)
	}

	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var tableCount int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'endpoint_key_candidates_v2'`).Scan(&tableCount); err != nil {
		t.Fatal(err)
	}
	if tableCount != 0 {
		t.Fatalf("rolled-back migration left %d candidate tables", tableCount)
	}
	var state string
	var attempts int
	if err := check.QueryRow(`SELECT state, attempts FROM schema_migrations_v2 WHERE version = 14`).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != v2MigrationFailed || attempts != 1 {
		t.Fatalf("failed candidate migration was not recorded for retry: state=%q attempts=%d", state, attempts)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	assertV2Ledger(t, reopened, map[int]string{
		1: v2MigrationApplied, 2: v2MigrationApplied, 3: v2MigrationApplied,
		4: v2MigrationApplied, 5: v2MigrationApplied, 6: v2MigrationApplied,
		7: v2MigrationApplied, 8: v2MigrationApplied, 9: v2MigrationApplied,
		10: v2MigrationApplied, 11: v2MigrationApplied, 12: v2MigrationApplied,
		13: v2MigrationApplied, 14: v2MigrationApplied,
		15: v2MigrationApplied, 16: v2MigrationApplied,
		17: v2MigrationApplied, 18: v2MigrationApplied,
		19: v2MigrationApplied,
		20: v2MigrationApplied,
		21: v2MigrationApplied,
		22: v2MigrationApplied,
		23: v2MigrationApplied,
		24: v2MigrationApplied,
		25: v2MigrationApplied,
		26: v2MigrationApplied,
		27: v2MigrationApplied,
		28: v2MigrationApplied,
		29: v2MigrationApplied,
		30: v2MigrationApplied,
		31: v2MigrationApplied,
		32: v2MigrationApplied,
		33: v2MigrationApplied,
		34: v2MigrationApplied,
		35: v2MigrationApplied,
		36: v2MigrationApplied,
		37: v2MigrationApplied, 38: v2MigrationApplied, 39: v2MigrationApplied, 40: v2MigrationApplied,
		41: v2MigrationApplied,
		42: v2MigrationApplied,
		43: v2MigrationApplied,
		44: v2MigrationApplied, 45: v2MigrationApplied, 46: v2MigrationApplied, 47: v2MigrationApplied,
		48: v2MigrationApplied,
		49: v2MigrationApplied,
		50: v2MigrationApplied,
		51: v2MigrationApplied,
		52: v2MigrationApplied,
		53: v2MigrationApplied,
		54: v2MigrationApplied,
		55: v2MigrationApplied,
		56: v2MigrationApplied,
		57: v2MigrationApplied,
		58: v2MigrationApplied,
		59: v2MigrationApplied,
		60: v2MigrationApplied, 61: v2MigrationApplied, 62: v2MigrationApplied, 63: v2MigrationApplied, 64: v2MigrationApplied, 65: v2MigrationApplied, 66: v2MigrationApplied, 67: v2MigrationApplied, 68: v2MigrationApplied,
	})
	entry, err := reopened.readV2Migration(14)
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil || entry.Attempts != 2 || entry.LastError != "" {
		t.Fatalf("candidate migration did not resume cleanly: %#v", entry)
	}
	var tableCountAfterReopen int
	if err := reopened.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'endpoint_key_candidates_v2'`).Scan(&tableCountAfterReopen); err != nil {
		t.Fatal(err)
	}
	if tableCountAfterReopen != 1 {
		t.Fatalf("reopened database is missing candidate table: count=%d", tableCountAfterReopen)
	}
}

func TestV2MigrationsConcurrentOpenSerializesLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			store, err := New(path)
			if err == nil {
				err = store.Close()
			}
			results <- err
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent Store open failed: %v", err)
		}
	}
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assertV2Ledger(t, store, map[int]string{
		1:  v2MigrationApplied,
		2:  v2MigrationApplied,
		3:  v2MigrationApplied,
		4:  v2MigrationApplied,
		5:  v2MigrationApplied,
		6:  v2MigrationApplied,
		7:  v2MigrationApplied,
		8:  v2MigrationApplied,
		9:  v2MigrationApplied,
		10: v2MigrationApplied,
		11: v2MigrationApplied,
		12: v2MigrationApplied,
		13: v2MigrationApplied,
		14: v2MigrationApplied,
		15: v2MigrationApplied,
		16: v2MigrationApplied,
		17: v2MigrationApplied,
		18: v2MigrationApplied,
		19: v2MigrationApplied,
		20: v2MigrationApplied,
		21: v2MigrationApplied,
		22: v2MigrationApplied,
		23: v2MigrationApplied,
		24: v2MigrationApplied,
		25: v2MigrationApplied,
		26: v2MigrationApplied,
		27: v2MigrationApplied,
		28: v2MigrationApplied,
		29: v2MigrationApplied,
		30: v2MigrationApplied,
		31: v2MigrationApplied,
		32: v2MigrationApplied,
		33: v2MigrationApplied,
		34: v2MigrationApplied,
		35: v2MigrationApplied,
		36: v2MigrationApplied,
		37: v2MigrationApplied, 38: v2MigrationApplied, 39: v2MigrationApplied, 40: v2MigrationApplied,
		41: v2MigrationApplied,
		42: v2MigrationApplied,
		43: v2MigrationApplied,
		44: v2MigrationApplied, 45: v2MigrationApplied, 46: v2MigrationApplied, 47: v2MigrationApplied,
		48: v2MigrationApplied,
		49: v2MigrationApplied,
		50: v2MigrationApplied,
		51: v2MigrationApplied,
		52: v2MigrationApplied,
		53: v2MigrationApplied,
		54: v2MigrationApplied,
		55: v2MigrationApplied,
		56: v2MigrationApplied,
		57: v2MigrationApplied,
		58: v2MigrationApplied,
		59: v2MigrationApplied,
		60: v2MigrationApplied, 61: v2MigrationApplied, 62: v2MigrationApplied, 63: v2MigrationApplied, 64: v2MigrationApplied, 65: v2MigrationApplied, 66: v2MigrationApplied, 67: v2MigrationApplied, 68: v2MigrationApplied,
	})
	for _, migration := range v2Migrations {
		entry, err := store.readV2Migration(migration.Version)
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil || entry.Attempts != 1 {
			t.Fatalf("concurrent startup duplicated %s: %#v", migration.ID, entry)
		}
	}
}

func TestClientDeviceV18MigrationFailureRollsBackAndRetriesWithStableHubID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("interrupt Client device migration")
	if _, err := openStoreWithMigrationHook(path, func(migrationID, phase string) error {
		if migrationID == "v2.client.device_identity_and_replay" && phase == "after_apply" {
			return injected
		}
		return nil
	}); !errors.Is(err, injected) {
		t.Fatalf("expected v18 migration failure, got %v", err)
	}

	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var newTables int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN
('client_device_hub_config_v2', 'client_devices_v2', 'client_device_grant_nonces_v2', 'client_device_requests_v2')`).Scan(&newTables); err != nil {
		t.Fatal(err)
	}
	if newTables != 0 {
		t.Fatalf("failed v18 migration left %d new tables", newTables)
	}
	var state string
	var attempts int
	if err := check.QueryRow(`SELECT state, attempts FROM schema_migrations_v2 WHERE version = 18`).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != v2MigrationFailed || attempts != 1 {
		t.Fatalf("failed v18 migration was not recorded for retry: state=%q attempts=%d", state, attempts)
	}
	var relayPayloadTables int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'relay_v2_message_payloads'`).Scan(&relayPayloadTables); err != nil {
		t.Fatal(err)
	}
	if relayPayloadTables != 1 {
		t.Fatalf("failed v18 migration rolled back earlier v17 state: table count=%d", relayPayloadTables)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}

	retried, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	assertLegacyStatePreserved(t, retried)
	hubID, err := retried.GetClientHubID()
	if err != nil || hubID == "" {
		t.Fatalf("v18 retry did not persist a stable Hub ID: %q %v", hubID, err)
	}
	entry, err := retried.readV2Migration(18)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v18 retry did not finish exactly once: entry=%+v err=%v", entry, err)
	}
	if err := retried.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	secondHubID, err := reopened.GetClientHubID()
	if err != nil || secondHubID != hubID {
		t.Fatalf("stable Hub ID changed after restart: first=%q second=%q err=%v", hubID, secondHubID, err)
	}
	assertLegacyStatePreserved(t, reopened)
}

func openStoreWithMigrationHook(path string, hook func(string, string) error) (*Store, error) {
	if err := ensureParentDir(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, migrationHook: hook}
	if err := store.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func ensureParentDir(path string) error {
	// New creates this directory for normal callers.  The injected-hook helper
	// mirrors that behavior while allowing tests to install the hook before
	// initialization begins.
	return os.MkdirAll(filepath.Dir(path), 0o755)
}

func seedLegacyV1State(t *testing.T, path string) {
	t.Helper()
	if err := ensureParentDir(path); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	_, err = db.Exec(`
PRAGMA foreign_keys = ON;
CREATE TABLE machines (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  last_seen TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE goals (
  id TEXT PRIMARY KEY,
  objective TEXT NOT NULL,
  success_criteria TEXT NOT NULL DEFAULT '',
  constraints TEXT NOT NULL DEFAULT '',
  priority INTEGER NOT NULL DEFAULT 50,
  status TEXT NOT NULL,
  machine_id TEXT,
  monitor_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(machine_id) REFERENCES machines(id)
);
CREATE TABLE workers (
  id TEXT PRIMARY KEY,
  goal_id TEXT NOT NULL,
  machine_id TEXT NOT NULL,
  harness TEXT NOT NULL,
  status TEXT NOT NULL,
  pid INTEGER,
  thread_id TEXT,
  attempt INTEGER NOT NULL DEFAULT 0,
  started_at TEXT,
  ended_at TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  response_file TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(goal_id) REFERENCES goals(id),
  FOREIGN KEY(machine_id) REFERENCES machines(id)
);
CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  goal_id TEXT NOT NULL,
  worker_id TEXT NOT NULL,
  method TEXT NOT NULL,
  request_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  decision TEXT,
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  FOREIGN KEY(goal_id) REFERENCES goals(id),
  FOREIGN KEY(worker_id) REFERENCES workers(id)
);
CREATE TABLE contacts (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  identity_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'trusted',
  send_sequence INTEGER NOT NULL DEFAULT 0,
  received_sequences_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE peer_sessions (
  contact_id TEXT PRIMARY KEY,
  epoch INTEGER NOT NULL,
  root_key BLOB NOT NULL,
  send_chain_key BLOB NOT NULL,
  receive_chain_key BLOB NOT NULL,
  send_count INTEGER NOT NULL DEFAULT 0,
  receive_count INTEGER NOT NULL DEFAULT 0,
  pending_offer BLOB,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);
CREATE TABLE peer_messages (
  id TEXT PRIMARY KEY,
  contact_id TEXT NOT NULL,
  direction TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  envelope_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  FOREIGN KEY(contact_id) REFERENCES contacts(id)
);
CREATE TABLE fabric_endpoints (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'thread',
  harness TEXT NOT NULL DEFAULT 'codex',
  native_session_id TEXT NOT NULL DEFAULT '',
  machine_id TEXT NOT NULL DEFAULT '',
  workspace TEXT NOT NULL DEFAULT '',
  goal_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'online',
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  tags_json TEXT NOT NULL DEFAULT '[]',
  owner TEXT NOT NULL DEFAULT '',
  visibility TEXT NOT NULL DEFAULT 'private',
  joined_at TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE fabric_messages (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL DEFAULT '',
  reply_to TEXT NOT NULL DEFAULT '',
  from_endpoint_id TEXT NOT NULL,
  to_endpoint_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  body TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'queued',
  error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  replied_at TEXT
);
INSERT INTO machines (id, name, status, capabilities_json, last_seen, created_at)
VALUES ('machine_legacy', 'legacy machine', 'online', '{"shell":true}', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
INSERT INTO goals (id, objective, success_criteria, constraints, priority, status, machine_id, monitor_id, workspace, summary, created_at, updated_at)
VALUES ('goal_legacy', 'preserve this goal', 'still present', 'none', 40, 'active', 'machine_legacy', 'monitor_legacy', '/tmp/legacy-workspace', 'legacy summary', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
INSERT INTO workers (id, goal_id, machine_id, harness, status, pid, thread_id, attempt, response_file, created_at, updated_at)
VALUES ('worker_legacy', 'goal_legacy', 'machine_legacy', 'codex', 'running', 17, 'native-thread-legacy', 3, '/tmp/legacy-response', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
INSERT INTO approvals (id, goal_id, worker_id, method, request_json, status, decision, created_at)
VALUES ('approval_legacy', 'goal_legacy', 'worker_legacy', 'shell', '{"command":"make test"}', 'approved', 'yes', '2025-01-01T00:00:00Z');
INSERT INTO contacts (id, label, identity_json, status, send_sequence, received_sequences_json, created_at, updated_at)
VALUES ('contact_legacy', 'legacy contact', '{"id":"remote-legacy","algorithm":"pq"}', 'trusted', 9, '[2,4,8]', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
INSERT INTO peer_sessions (contact_id, epoch, root_key, send_chain_key, receive_chain_key, send_count, receive_count, pending_offer, status, created_at, updated_at)
VALUES ('contact_legacy', 7, X'01020304', X'05060708', X'090A0B0C', 11, 13, X'0D0E', 'active', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
INSERT INTO peer_messages (id, contact_id, direction, sender_id, recipient_id, sequence, envelope_json, status, created_at)
VALUES ('peer_message_legacy', 'contact_legacy', 'inbound', 'remote-legacy', 'local', 8, '{"ciphertext":"opaque"}', 'received', '2025-01-01T00:00:00Z');
INSERT INTO fabric_endpoints (id, name, role, harness, native_session_id, machine_id, workspace, goal_id, status, capabilities_json, tags_json, owner, visibility, joined_at, last_seen, created_at, updated_at)
VALUES ('endpoint_legacy', 'legacy endpoint', 'worker', 'codex', 'native-session-legacy', 'machine_legacy', '/tmp/legacy-workspace', 'goal_legacy', 'online', '{"ask":true}', '["legacy"]', 'owner-legacy', 'private', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
INSERT INTO fabric_messages (id, request_id, from_endpoint_id, to_endpoint_id, kind, body, status, created_at)
VALUES ('fabric_message_legacy', 'request_legacy', 'endpoint_legacy', 'endpoint_legacy', 'ask', 'opaque durable body', 'queued', '2025-01-01T00:00:00Z');
`)
	if err != nil {
		t.Fatal(err)
	}
}

func assertLegacyStatePreserved(t *testing.T, store *Store) {
	t.Helper()
	var objective, goalStatus, goalWorkspace string
	if err := store.db.QueryRow(`SELECT objective, status, workspace FROM goals WHERE id = 'goal_legacy'`).Scan(&objective, &goalStatus, &goalWorkspace); err != nil {
		t.Fatal(err)
	}
	if objective != "preserve this goal" || goalStatus != "active" || goalWorkspace != "/tmp/legacy-workspace" {
		t.Fatalf("legacy Goal changed: objective=%q status=%q workspace=%q", objective, goalStatus, goalWorkspace)
	}
	var goalOwner, machineOwner string
	if err := store.db.QueryRow(`SELECT owner_id FROM goals WHERE id='goal_legacy'`).Scan(&goalOwner); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT owner_id FROM machines WHERE id='machine_legacy'`).Scan(&machineOwner); err != nil {
		t.Fatal(err)
	}
	if goalOwner != "" || machineOwner != "" {
		t.Fatalf("migration inferred ownership for legacy rows: goal=%q machine=%q", goalOwner, machineOwner)
	}
	var lifecycleVersion int64
	if err := store.db.QueryRow(`SELECT lifecycle_version FROM goals WHERE id='goal_legacy'`).Scan(&lifecycleVersion); err != nil || lifecycleVersion != 1 {
		t.Fatalf("legacy Goal lifecycle version was not initialized without changing status: version=%d err=%v", lifecycleVersion, err)
	}
	var approvalRequest, approvalStatus, approvalDecision string
	if err := store.db.QueryRow(`SELECT request_json, status, decision FROM approvals WHERE id = 'approval_legacy'`).Scan(&approvalRequest, &approvalStatus, &approvalDecision); err != nil {
		t.Fatal(err)
	}
	if approvalRequest != `{"command":"make test"}` || approvalStatus != "approved" || approvalDecision != "yes" {
		t.Fatalf("legacy approval changed: request=%q status=%q decision=%q", approvalRequest, approvalStatus, approvalDecision)
	}
	var remoteID, identity, received string
	var sendSequence int
	if err := store.db.QueryRow(`SELECT remote_id, identity_json, send_sequence, received_sequences_json FROM contacts WHERE id = 'contact_legacy'`).Scan(&remoteID, &identity, &sendSequence, &received); err != nil {
		t.Fatal(err)
	}
	if remoteID != "remote-legacy" || identity != `{"id":"remote-legacy","algorithm":"pq"}` || sendSequence != 9 || received != "[2,4,8]" {
		t.Fatalf("legacy Contact/replay state changed: remote=%q identity=%q send=%d received=%q", remoteID, identity, sendSequence, received)
	}
	var epoch, sendCount, receiveCount int
	var rootKey, sendChainKey, receiveChainKey, pendingOffer []byte
	if err := store.db.QueryRow(`SELECT epoch, root_key, send_chain_key, receive_chain_key, send_count, receive_count, pending_offer FROM peer_sessions WHERE contact_id = 'contact_legacy'`).Scan(&epoch, &rootKey, &sendChainKey, &receiveChainKey, &sendCount, &receiveCount, &pendingOffer); err != nil {
		t.Fatal(err)
	}
	if epoch != 7 || sendCount != 11 || receiveCount != 13 || !bytes.Equal(rootKey, []byte{1, 2, 3, 4}) || !bytes.Equal(sendChainKey, []byte{5, 6, 7, 8}) || !bytes.Equal(receiveChainKey, []byte{9, 10, 11, 12}) || !bytes.Equal(pendingOffer, []byte{13, 14}) {
		t.Fatalf("legacy key/rachet state changed: epoch=%d send=%d receive=%d", epoch, sendCount, receiveCount)
	}
	var envelope string
	var sequence int
	if err := store.db.QueryRow(`SELECT envelope_json, sequence FROM peer_messages WHERE id = 'peer_message_legacy'`).Scan(&envelope, &sequence); err != nil {
		t.Fatal(err)
	}
	if envelope != `{"ciphertext":"opaque"}` || sequence != 8 {
		t.Fatalf("legacy peer replay envelope changed: envelope=%q sequence=%d", envelope, sequence)
	}
	var endpointName, nativeSession, owner string
	if err := store.db.QueryRow(`SELECT name, native_session_id, owner FROM fabric_endpoints WHERE id = 'endpoint_legacy'`).Scan(&endpointName, &nativeSession, &owner); err != nil {
		t.Fatal(err)
	}
	if endpointName != "legacy endpoint" || nativeSession != "native-session-legacy" || owner != "owner-legacy" {
		t.Fatalf("legacy Endpoint changed: name=%q native=%q owner=%q", endpointName, nativeSession, owner)
	}
	var messageBody string
	if err := store.db.QueryRow(`SELECT body FROM fabric_messages WHERE id = 'fabric_message_legacy'`).Scan(&messageBody); err != nil {
		t.Fatal(err)
	}
	if messageBody != "opaque durable body" {
		t.Fatalf("legacy message changed: %q", messageBody)
	}
	endpoint, err := store.GetEndpointV2("endpoint_legacy")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.ID != "endpoint_legacy" || endpoint.NativeSessionID != "native-session-legacy" || endpoint.MigrationState != EndpointMigrationPendingGroup || endpoint.PrincipalID != "" || endpoint.GroupID != "" {
		t.Fatalf("legacy Endpoint was not left pending explicit migration: %#v", endpoint)
	}
}

func assertV2Ledger(t *testing.T, store *Store, expected map[int]string) {
	t.Helper()
	rows, err := store.db.Query(`SELECT version, state FROM schema_migrations_v2 ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := make(map[int]string)
	for rows.Next() {
		var version int
		var state string
		if err := rows.Scan(&version, &state); err != nil {
			t.Fatal(err)
		}
		seen[version] = state
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(expected) {
		t.Fatalf("unexpected migration ledger rows: %#v want %#v", seen, expected)
	}
	for version, state := range expected {
		if seen[version] != state {
			t.Fatalf("migration version %d state=%q want %q", version, seen[version], state)
		}
	}
}

func TestDedicatedThreadPolicyMigrationV52RollsBackAndResumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic dedicated Thread policy interruption")
	failed, err := openStoreWithMigrationHook(path, func(migrationID, phase string) error {
		if migrationID == "v2.fabric.dedicated_thread_context_policy" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatalf("expected v52 interruption, got store=%v err=%v", failed, err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	columns, err := existingColumns(check, "networks_v2", []string{"context_policy"})
	if err != nil || len(columns) != 0 {
		_ = check.Close()
		t.Fatalf("interrupted v52 left the Network policy column: columns=%v err=%v", columns, err)
	}
	for _, index := range []string{"session_bindings_native_history_v52_idx",
		"endpoint_network_memberships_endpoint_history_v52_idx",
		"network_access_sessions_endpoint_history_v52_idx"} {
		var count int
		if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?`, index).Scan(&count); err != nil {
			_ = check.Close()
			t.Fatal(err)
		}
		if count != 0 {
			_ = check.Close()
			t.Fatalf("interrupted v52 left partial index %s", index)
		}
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(52)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v52 retry did not complete exactly once: entry=%+v err=%v", entry, err)
	}
	columns, err = existingColumns(reopened.db, "networks_v2", []string{"context_policy"})
	if err != nil || len(columns) != 1 {
		t.Fatalf("v52 retry omitted Network context policy: columns=%v err=%v", columns, err)
	}
	assertV2Ledger(t, reopened, map[int]string{
		1: v2MigrationApplied, 2: v2MigrationApplied, 3: v2MigrationApplied,
		4: v2MigrationApplied, 5: v2MigrationApplied, 6: v2MigrationApplied,
		7: v2MigrationApplied, 8: v2MigrationApplied, 9: v2MigrationApplied,
		10: v2MigrationApplied, 11: v2MigrationApplied, 12: v2MigrationApplied,
		13: v2MigrationApplied, 14: v2MigrationApplied, 15: v2MigrationApplied,
		16: v2MigrationApplied, 17: v2MigrationApplied, 18: v2MigrationApplied,
		19: v2MigrationApplied, 20: v2MigrationApplied, 21: v2MigrationApplied,
		22: v2MigrationApplied, 23: v2MigrationApplied, 24: v2MigrationApplied,
		25: v2MigrationApplied, 26: v2MigrationApplied, 27: v2MigrationApplied,
		28: v2MigrationApplied, 29: v2MigrationApplied, 30: v2MigrationApplied,
		31: v2MigrationApplied, 32: v2MigrationApplied, 33: v2MigrationApplied,
		34: v2MigrationApplied, 35: v2MigrationApplied, 36: v2MigrationApplied,
		37: v2MigrationApplied, 38: v2MigrationApplied, 39: v2MigrationApplied,
		40: v2MigrationApplied, 41: v2MigrationApplied, 42: v2MigrationApplied,
		43: v2MigrationApplied, 44: v2MigrationApplied, 45: v2MigrationApplied,
		46: v2MigrationApplied, 47: v2MigrationApplied, 48: v2MigrationApplied,
		49: v2MigrationApplied, 50: v2MigrationApplied, 51: v2MigrationApplied,
		52: v2MigrationApplied, 53: v2MigrationApplied, 54: v2MigrationApplied,
		55: v2MigrationApplied,
		56: v2MigrationApplied,
		57: v2MigrationApplied,
		58: v2MigrationApplied,
		59: v2MigrationApplied,
		60: v2MigrationApplied, 61: v2MigrationApplied, 62: v2MigrationApplied, 63: v2MigrationApplied, 64: v2MigrationApplied, 65: v2MigrationApplied, 66: v2MigrationApplied, 67: v2MigrationApplied, 68: v2MigrationApplied,
	})
}

// Reopen verifies a single immutable database snapshot, including corruption
// outside migration-owned objects. Every case gets its own synthetic database;
// only the closed, checkpointed empty schema image is shared as test input.
func TestV2MigrationsAppliedReopenFailClosed(t *testing.T) {
	seedPath := filepath.Join(t.TempDir(), "cicada.sqlite3")
	seed, err := New(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		sql  string
		want string
	}{
		{"missing-object", `DROP INDEX ` + relayAskExpiryOrderIndex, "migration object " + relayAskExpiryOrderIndex + " is missing"},
		{"wrong-index-definition", `DROP INDEX ` + relayAskExpiryOrderIndex + `; CREATE INDEX ` + relayAskExpiryOrderIndex + ` ON relay_v2_requests(request_id)`, "verify applied v2 migration " + relayAskExpiryOrderMigrationID},
		{"ledger-checksum", `UPDATE schema_migrations_v2 SET checksum='synthetic-invalid-checksum' WHERE version=59`, "ledger definition mismatch"},
		{"ledger-id", `UPDATE schema_migrations_v2 SET migration_id='synthetic-invalid-id' WHERE version=59`, "ledger definition mismatch"},
		{"ledger-description", `UPDATE schema_migrations_v2 SET description='synthetic-invalid-description' WHERE version=59`, "ledger definition mismatch"},
		{"ledger-too-new", fmt.Sprintf(`UPDATE schema_migrations_v2 SET version=%d WHERE version=59`, CurrentV2SchemaVersion+1), "newer than this binary supports"},
		{"foreign-key-violation", `PRAGMA foreign_keys=OFF; CREATE TABLE startup_fk_parent(id INTEGER PRIMARY KEY); CREATE TABLE startup_fk_child(parent_id INTEGER REFERENCES startup_fk_parent(id)); INSERT INTO startup_fk_child VALUES(7)`, "sqlite foreign_key_check found"},
		{"integrity-violation", `CREATE TABLE startup_integrity_probe(n INTEGER CHECK(n>0)); PRAGMA ignore_check_constraints=ON; INSERT INTO startup_integrity_probe VALUES(0); PRAGMA ignore_check_constraints=OFF`, "sqlite integrity_check returned"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cicada.sqlite3")
			if err := os.WriteFile(path, image, 0o600); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			if _, err := db.Exec(test.sql); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before := appliedStartupLedger(t, path)
			reopened, err := New(path)
			if err == nil {
				reopened.Close()
				t.Fatal("unsafe applied-schema reopen was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wrong failure boundary: got %v want %q", err, test.want)
			}
			if after := appliedStartupLedger(t, path); !reflect.DeepEqual(before, after) {
				t.Fatal("failed applied-schema verification changed the migration ledger")
			}
			// A rejected startup must not retain its BEGIN IMMEDIATE lock.
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			if _, err := db.Exec("BEGIN IMMEDIATE; ROLLBACK"); err != nil {
				t.Fatalf("rejected startup retained its transaction: %v", err)
			}
		})
	}
	t.Run("damaged-file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cicada.sqlite3")
		damaged := append([]byte(nil), image...)
		damaged[0] = 'X' // Actual invalid SQLite header, not an injected error.
		if err := os.WriteFile(path, damaged, 0o600); err != nil {
			t.Fatal(err)
		}
		reopened, err := New(path)
		if err == nil {
			reopened.Close()
			t.Fatal("damaged SQLite file was accepted")
		}
		var coded interface{ Code() int }
		if !errors.As(err, &coded) || coded.Code() != 26 { // SQLITE_NOTADB
			t.Fatalf("damaged file did not report SQLite corruption: %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(damaged, after) {
			t.Fatal("failed startup rewrote the damaged database")
		}
	})
	t.Run("repeat-stable-ledger", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cicada.sqlite3")
		if err := os.WriteFile(path, image, 0o600); err != nil {
			t.Fatal(err)
		}
		before := appliedStartupLedger(t, path)
		if len(before) != CurrentV2SchemaVersion {
			t.Fatalf("seed ledger contains %d entries", len(before))
		}
		for _, entry := range before {
			if entry.State != v2MigrationApplied || entry.Attempts != 1 {
				t.Fatal("seed ledger is not exactly once applied")
			}
		}
		for i := 0; i < 2; i++ {
			reopened, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, appliedStartupLedger(t, path)) {
				t.Fatal("successful repeated startup changed the applied ledger")
			}
		}
	})
}

func appliedStartupLedger(t *testing.T, path string) []v2MigrationLedgerEntry {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	var ledger []v2MigrationLedgerEntry
	for version := 1; version <= CurrentV2SchemaVersion+1; version++ {
		entry, err := s.readV2Migration(version)
		if err != nil {
			t.Fatal(err)
		}
		if entry != nil {
			ledger = append(ledger, *entry)
		}
	}
	return ledger
}
