package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMCPOutboxNetworkScopeSeparatesGroupsAndNetworksAfterLegacyUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.sqlite3")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE mcp_outbox_operations (
operation_id TEXT PRIMARY KEY,kind TEXT NOT NULL,status TEXT NOT NULL,api_origin TEXT NOT NULL,
scope TEXT NOT NULL,harness TEXT NOT NULL,native_session_id TEXT NOT NULL,node_id TEXT NOT NULL,
workspace TEXT NOT NULL DEFAULT '',endpoint_id TEXT NOT NULL,group_id TEXT NOT NULL,
idempotency_key TEXT NOT NULL,input_json TEXT NOT NULL,input_digest TEXT NOT NULL,
attempt_count INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',result_json TEXT NOT NULL DEFAULT '',
created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX mcp_outbox_scope_key_idx ON mcp_outbox_operations
(api_origin,native_session_id,endpoint_id,group_id,idempotency_key)`)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ id, status string }{{"op_pending", mcpOutboxStatusPending}, {"op_unknown", mcpOutboxStatusUnknown}, {"op_sent", mcpOutboxStatusSent}} {
		_, err = legacy.Exec(`INSERT INTO mcp_outbox_operations
(operation_id,kind,status,api_origin,scope,harness,native_session_id,node_id,workspace,endpoint_id,group_id,
idempotency_key,input_json,input_digest,attempt_count,last_error,result_json,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, item.id, "send", item.status, "http://synthetic-hub", "synthetic-native-scope",
			"codex", "synthetic-thread", "synthetic-node", "/synthetic", "ep_synthetic", "group_synthetic", item.id,
			`{"target":"ep_peer","body":"legacy"}`, "synthetic-digest", 1, "", "", "2026-09-28T00:00:00Z", "2026-09-28T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	box := newMCPOutbox(path)
	defer box.close()
	base := mcpOutboxScope{APIOrigin: "http://synthetic-hub", Scope: "synthetic-native-scope", Harness: "codex",
		NativeSessionID: "synthetic-thread", NodeID: "synthetic-node", Workspace: "/synthetic", EndpointID: "ep_synthetic"}
	group := base
	group.GroupID = "group_synthetic"
	for _, item := range []struct{ id, status string }{{"op_pending", mcpOutboxStatusPending}, {"op_unknown", mcpOutboxStatusUnknown}, {"op_sent", mcpOutboxStatusSent}} {
		got, err := box.load(group, item.id)
		if err != nil || got.Status != item.status || got.NetworkID != "" {
			t.Fatalf("legacy %s lost on upgrade: %#v %v", item.id, got, err)
		}
	}
	first, _, err := box.prepare(group, "send", "same-retry-key", mcpOutboxInput{Target: "ep_peer", Body: "group"})
	if err != nil {
		t.Fatal(err)
	}
	networkA := base
	networkA.NetworkID = "net_a"
	second, _, err := box.prepare(networkA, "network_send", "same-retry-key", mcpOutboxInput{NetworkID: "net_a", Target: "ep_peer", Body: "A"})
	if err != nil {
		t.Fatal(err)
	}
	networkB := base
	networkB.NetworkID = "net_b"
	third, _, err := box.prepare(networkB, "network_send", "same-retry-key", mcpOutboxInput{NetworkID: "net_b", Target: "ep_peer", Body: "B"})
	if err != nil {
		t.Fatal(err)
	}
	if first.OperationID == second.OperationID || first.OperationID == third.OperationID || second.OperationID == third.OperationID {
		t.Fatal("Group and Network operations collided across independently authorized scopes")
	}
	if _, err := box.load(networkA, third.OperationID); err != errMCPOutboxContext {
		t.Fatalf("cross-Network operation lookup: %v", err)
	}
	if err := box.close(); err != nil {
		t.Fatal(err)
	}
	reopened := newMCPOutbox(path)
	defer reopened.close()
	for _, item := range []struct{ id, status string }{{"op_pending", mcpOutboxStatusPending}, {"op_unknown", mcpOutboxStatusUnknown}, {"op_sent", mcpOutboxStatusSent}} {
		got, err := reopened.load(group, item.id)
		if err != nil || got.Status != item.status {
			t.Fatalf("legacy %s lost on reopen: %#v %v", item.id, got, err)
		}
	}
}
