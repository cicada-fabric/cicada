package main

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
	_ "modernc.org/sqlite"
)

func TestMigrationInventoryCommandIsLocalReadOnlyJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite3")
	seedMigrationInventoryCLIFixture(t, path)
	var output strings.Builder
	if err := migrationInventoryCommandOutput([]string{"inventory", "--db", path, "--format", "json"}, &output); err != nil {
		t.Fatal(err)
	}
	var inventory store.LegacyMigrationInventory
	if err := json.Unmarshal([]byte(output.String()), &inventory); err != nil {
		t.Fatalf("decode inventory output: %v\n%s", err, output.String())
	}
	if !inventory.ReadOnly || inventory.Counts.Endpoints != 1 || inventory.Mapping.Pending != 1 {
		t.Fatalf("unexpected CLI inventory: %#v", inventory)
	}
	if strings.Contains(output.String(), "CLI SECRET MESSAGE") || strings.Contains(output.String(), "credential-plaintext") {
		t.Fatalf("CLI inventory exposed sensitive source values: %s", output.String())
	}
}

func TestMigrationInventoryCommandRejectsApplyModeAndNetworkFlags(t *testing.T) {
	t.Setenv("CICADA_STATE_DB", "")
	if err := migrationInventoryCommandOutput([]string{"inventory"}, &strings.Builder{}); err != store.ErrMigrationInventoryDatabaseRequired {
		t.Fatalf("missing --db error = %v, want %v", err, store.ErrMigrationInventoryDatabaseRequired)
	}
	if err := migrationInventoryCommandOutput([]string{"inventory", "--dry-run=false", "--db", "/does/not/exist"}, &strings.Builder{}); err != store.ErrMigrationInventoryApplyUnsupported {
		t.Fatalf("--dry-run=false error = %v, want %v", err, store.ErrMigrationInventoryApplyUnsupported)
	}
	if err := migrationInventoryCommandOutput([]string{"inventory", "apply", "--db", "/does/not/exist"}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("apply positional args error = %v", err)
	}
}

func TestMigrationInventoryCommandRejectsNonJSONFormat(t *testing.T) {
	if err := migrationInventoryCommandOutput([]string{"inventory", "--format", "text", "--db", "/does/not/exist"}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "only --format json") {
		t.Fatalf("non-JSON format error = %v", err)
	}
}

func seedMigrationInventoryCLIFixture(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE fabric_endpoints (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  harness TEXT NOT NULL,
  native_session_id TEXT NOT NULL,
  machine_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  goal_id TEXT NOT NULL,
  status TEXT NOT NULL,
  owner TEXT NOT NULL,
  visibility TEXT NOT NULL
);
INSERT INTO fabric_endpoints VALUES ('ep_cli', 'cli endpoint', 'thread', 'codex', 'native-cli', 'node-cli', '/workspace/cli', '', 'online', 'owner-cli', 'private');
CREATE TABLE fabric_messages (id TEXT PRIMARY KEY, request_id TEXT NOT NULL, body TEXT NOT NULL);
INSERT INTO fabric_messages VALUES ('msg-cli', 'request-cli', 'CLI SECRET MESSAGE');
CREATE TABLE peer_sessions (contact_id TEXT PRIMARY KEY, root_key BLOB NOT NULL);
INSERT INTO peer_sessions VALUES ('contact-cli', X'63726564656E7469616C2D706C61696E74657874');
`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}
