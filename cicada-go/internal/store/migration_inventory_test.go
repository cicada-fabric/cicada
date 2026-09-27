package store

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestInventoryLegacyMigrationIsReadOnlyAndPreservesIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite3")
	seedLegacyInventoryFixture(t, path)
	beforeBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeSchema := readInventoryFixtureSchema(t, path)

	inventory, err := InventoryLegacyMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	afterBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterBytes) != string(beforeBytes) {
		t.Fatal("read-only migration inventory changed source database bytes")
	}
	if got := readInventoryFixtureSchema(t, path); got != beforeSchema {
		t.Fatalf("read-only migration inventory changed source schema:\nbefore=%s\nafter=%s", beforeSchema, got)
	}
	if !inventory.ReadOnly || inventory.Version != 1 || inventory.SchemaFingerprint == "" {
		t.Fatalf("unexpected inventory metadata: %#v", inventory)
	}
	if inventory.Counts.Endpoints != 2 || inventory.Counts.NativeSessions != 2 || inventory.Counts.Goals != 1 || inventory.Counts.Workers != 1 || inventory.Counts.Approvals != 1 {
		t.Fatalf("unexpected durable object counts: %#v", inventory.Counts)
	}
	if inventory.Counts.Contacts != 1 || inventory.Counts.PeerSessions != 1 || inventory.Counts.PeerMessages != 1 || inventory.Counts.FabricMessages != 2 || inventory.Counts.FabricRequests != 1 {
		t.Fatalf("unexpected communication counts: %#v", inventory.Counts)
	}
	if inventory.Counts.Groups != 0 || inventory.Counts.Principals != 0 || inventory.Counts.Memberships != 0 || inventory.Counts.Bindings != 0 {
		t.Fatalf("inventory invented v2 identity rows: %#v", inventory.Counts)
	}
	if inventory.Mapping.Total != 2 || inventory.Mapping.Pending != 1 || inventory.Mapping.Ready != 1 {
		t.Fatalf("unexpected pending/ready summary: %#v", inventory.Mapping)
	}
	if len(inventory.Endpoints) != 2 || len(inventory.NativeBindings) != 2 {
		t.Fatalf("endpoint/native binding projection lengths = %d/%d", len(inventory.Endpoints), len(inventory.NativeBindings))
	}
	pending, ready := inventory.Endpoints[0], inventory.Endpoints[1]
	if pending.EndpointID != "ep_pending" || pending.MappingState != LegacyMappingPending || pending.NativeSessionID != "native-pending" || pending.Role != "monitor" || pending.Owner != "legacy-owner" {
		t.Fatalf("pending endpoint identity/native/role data was not preserved: %#v", pending)
	}
	if pending.OwnerDecision != LegacyOwnerDecisionNeedsExplicitPrincipal || pending.GroupDecision != LegacyGroupDecisionMissing || !containsString(pending.PendingReasons, LegacyMappingReasonOwnerNeedsExplicitID) || !containsString(pending.PendingReasons, LegacyMappingReasonMissingGroupDecision) {
		t.Fatalf("pending endpoint did not expose explicit owner/group decisions: %#v", pending)
	}
	if ready.EndpointID != "ep_ready" || ready.MappingState != LegacyMappingReady || ready.PrincipalID != "principal-explicit" || ready.GroupID != "group-explicit" || ready.BindingID != "binding-explicit" || ready.NativeSessionID != "native-ready" {
		t.Fatalf("ready endpoint mapping/native data was not preserved: %#v", ready)
	}
	if ready.OwnerDecision != LegacyOwnerDecisionExplicitPrincipal || ready.GroupDecision != LegacyGroupDecisionExplicit || len(ready.PendingReasons) != 0 {
		t.Fatalf("ready endpoint has unexpected pending decisions: %#v", ready)
	}

	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	for _, forbidden := range []string{"TOP SECRET MESSAGE BODY", "opaque-envelope-secret", "private-key-secret", "credential-plaintext"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("inventory output exposed forbidden source value %q: %s", forbidden, output)
		}
	}
	if strings.Contains(output, "global") && strings.Contains(output, "group") {
		t.Fatalf("inventory output suggested an automatic global Group: %s", output)
	}
}

func TestInventoryLegacyMigrationDoesNotCreateMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sqlite3")
	if _, err := InventoryLegacyMigration(path); err == nil {
		t.Fatal("missing source database unexpectedly produced an inventory")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("read-only inventory created missing source database: %v", err)
	}
}

func TestInventoryLegacyMigrationLimitKeepsCountsButMarksProjection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite3")
	seedLegacyInventoryFixture(t, path)
	inventory, err := InventoryLegacyMigrationWithOptions(path, LegacyMigrationInventoryOptions{EndpointLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Endpoints) != 1 || len(inventory.NativeBindings) != 1 {
		t.Fatalf("limited endpoint projection length = %d/%d", len(inventory.Endpoints), len(inventory.NativeBindings))
	}
	if inventory.Mapping.Total != 2 || inventory.Mapping.Ready != 1 || inventory.Mapping.Pending != 1 {
		t.Fatalf("limited mapping summary was not kept complete: %#v", inventory.Mapping)
	}
}

func seedLegacyInventoryFixture(t *testing.T, path string) {
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
  visibility TEXT NOT NULL,
  principal_id TEXT NOT NULL DEFAULT '',
  group_id TEXT NOT NULL DEFAULT '',
  binding_id TEXT NOT NULL DEFAULT '',
  migration_state TEXT NOT NULL DEFAULT 'MIGRATION_PENDING_GROUP'
);
INSERT INTO fabric_endpoints
  (id, name, role, harness, native_session_id, machine_id, workspace, goal_id, status, owner, visibility)
VALUES ('ep_pending', 'old monitor', 'monitor', 'codex', 'native-pending', 'node-a', '/workspace/a', 'goal-a', 'online', 'legacy-owner', 'private');
INSERT INTO fabric_endpoints
  (id, name, role, harness, native_session_id, machine_id, workspace, goal_id, status, owner, visibility, principal_id, group_id, binding_id, migration_state)
VALUES ('ep_ready', 'ready worker', 'worker', 'codex', 'native-ready', 'node-b', '/workspace/b', 'goal-a', 'idle', 'legacy-owner', 'fabric', 'principal-explicit', 'group-explicit', 'binding-explicit', 'READY');
CREATE TABLE goals (id TEXT PRIMARY KEY, objective TEXT NOT NULL);
INSERT INTO goals VALUES ('goal-a', 'private objective');
CREATE TABLE workers (id TEXT PRIMARY KEY, goal_id TEXT NOT NULL, prompt TEXT NOT NULL);
INSERT INTO workers VALUES ('worker-a', 'goal-a', 'private worker prompt');
CREATE TABLE approvals (id TEXT PRIMARY KEY, request TEXT NOT NULL);
INSERT INTO approvals VALUES ('approval-a', 'private approval');
CREATE TABLE contacts (id TEXT PRIMARY KEY, identity_json TEXT NOT NULL);
INSERT INTO contacts VALUES ('contact-a', 'private identity');
CREATE TABLE peer_sessions (contact_id TEXT PRIMARY KEY, root_key BLOB NOT NULL);
INSERT INTO peer_sessions VALUES ('contact-a', X'707269766174652D6B6579');
CREATE TABLE peer_messages (id TEXT PRIMARY KEY, envelope_json TEXT NOT NULL, body TEXT NOT NULL);
INSERT INTO peer_messages VALUES ('peer-message-a', 'opaque-envelope-secret', 'TOP SECRET MESSAGE BODY');
CREATE TABLE fabric_messages (id TEXT PRIMARY KEY, request_id TEXT NOT NULL, body TEXT NOT NULL);
INSERT INTO fabric_messages VALUES ('fabric-message-a', 'request-a', 'TOP SECRET MESSAGE BODY');
INSERT INTO fabric_messages VALUES ('fabric-reply-a', 'request-a', 'TOP SECRET MESSAGE BODY');
`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func readInventoryFixtureSchema(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT type, name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var builder strings.Builder
	for rows.Next() {
		var kind, name, definition string
		if err := rows.Scan(&kind, &name, &definition); err != nil {
			t.Fatal(err)
		}
		builder.WriteString(kind)
		builder.WriteByte(0)
		builder.WriteString(name)
		builder.WriteByte(0)
		builder.WriteString(definition)
		builder.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return builder.String()
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
