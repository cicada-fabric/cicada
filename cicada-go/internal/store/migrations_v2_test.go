package store

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
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
	})
	entry, err := reopened.readV2Migration(3)
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil || entry.Attempts != 2 || entry.LastError != "" {
		t.Fatalf("failed migration did not resume cleanly: %#v", entry)
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
