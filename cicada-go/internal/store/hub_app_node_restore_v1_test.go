package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestN3StoreMigrationRollbackAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic N3 migration interruption")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v1.hub.app_node_authority" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatal("migration fault did not stop startup", err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var tables int
	err = check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'hub_app_node_%'`).Scan(&tables)
	check.Close()
	if err != nil || tables != 0 {
		t.Fatal("failed migration retained partial N3 objects", err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(63)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatal("N3 migration did not resume exactly once", err)
	}
}

func syntheticN3Checkpoint() *HubRestoreCheckpoint {
	c := syntheticHubCheckpoint()
	c.rows["hub_app_node_heads_v1"] = map[string]map[string]any{"head": {"owner_id": "synthetic-owner", "device_id": "synthetic-device", "head_version": int64(3), "latest_grant_id": "synthetic-latest", "provenance_id": "synthetic-provenance"}}
	c.rows["hub_app_node_operations_v1"] = map[string]map[string]any{"op": {"operation": "nodes.confirm", "request_digest": "synthetic-exact", "response_packet": "synthetic-exact-ciphertext", "state": "COMPLETED"}}
	c.rows["hub_app_node_provenance_v1"] = map[string]map[string]any{"proof": {"grant_id": "synthetic-initial", "head_version": int64(1), "binding_json": "synthetic-exact-binding", "client_request_id": "synthetic-client-request"}}
	c.rows["hub_app_node_grants_v1"] = map[string]map[string]any{"grant": {"grant_id": "synthetic-latest", "account_id": "synthetic-account", "owner_id": "synthetic-owner", "device_id": "synthetic-device", "claims_json": "synthetic-exact-claims", "owner_proof": "synthetic-exact-proof", "state": "ACTIVE", "remaining": int64(0), "provenance_id": "synthetic-provenance", "created_at": "synthetic-fixed"}}
	c.rows["hub_app_node_reads_v1"] = map[string]map[string]any{"read": {"operation_id": "synthetic-read", "response_packet": "synthetic-old-observation"}}
	c.rows["hub_app_node_rates_v1"] = map[string]map[string]any{"bucket": {"requests": int64(128), "window_start": "synthetic-window"}}
	return c
}
func TestN3StoreRestoreCoveragePreservesAuthorityButAllowsReadCacheEviction(t *testing.T) {
	base, current := syntheticN3Checkpoint(), syntheticN3Checkpoint()
	delete(current.rows["hub_app_node_reads_v1"], "read")
	delete(current.rows["hub_app_node_rates_v1"], "bucket")
	if err := CompareHubRestoreCoverage(base, current); err != nil {
		t.Fatal("ephemeral polling cache became permanent authority history", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*HubRestoreCheckpoint)
	}{
		{"head-floor", func(c *HubRestoreCheckpoint) { c.rows["hub_app_node_heads_v1"]["head"]["head_version"] = int64(2) }},
		{"provenance", func(c *HubRestoreCheckpoint) { c.rows["hub_app_node_heads_v1"]["head"]["provenance_id"] = "" }},
		{"receipt", func(c *HubRestoreCheckpoint) { delete(c.rows["hub_app_node_operations_v1"], "op") }},
		{"exact-effect", func(c *HubRestoreCheckpoint) {
			c.rows["hub_app_node_provenance_v1"]["proof"]["binding_json"] = "synthetic-other-binding"
		}},
		{"claims", func(c *HubRestoreCheckpoint) {
			c.rows["hub_app_node_grants_v1"]["grant"]["claims_json"] = "synthetic-extended-lease"
		}},
		{"budget", func(c *HubRestoreCheckpoint) { c.rows["hub_app_node_grants_v1"]["grant"]["remaining"] = int64(1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := syntheticN3Checkpoint()
			tc.change(next)
			if !errors.Is(CompareHubRestoreCoverage(base, next), ErrHubRestoreCoverage) {
				t.Fatal("N3 authority floor/history rolled back")
			}
		})
	}
}
