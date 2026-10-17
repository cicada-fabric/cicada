package store

import (
	"errors"
	"sort"
	"testing"
)

func TestHubNativePairRestoreCannotRollBackProofsSlotsOrBudget(t *testing.T) {
	makeCheckpoint := func() *HubRestoreCheckpoint {
		cp := syntheticHubCheckpoint()
		rows := map[string]map[string]any{
			"hub_native_pairs_v1":                {"pair_id": "synthetic-pair", "scope_json": "synthetic-exact-scope", "bootstrap_json": "synthetic-exact-bootstrap", "bootstrap_owner_proof": []byte("synthetic-signed-proof-not-a-real-signature"), "control_revision": int64(4), "state": "REVOKED", "peer_expires_at": "2026-10-17T15:00:00Z"},
			"hub_native_pair_slots_v1":           {"pair_id": "synthetic-pair", "slot": "A", "generation": int64(2), "state": "REJECTED", "attempt_id": "synthetic-original-attempt", "native_session_id": "synthetic-original-sid", "binding_id": "synthetic-original-binding"},
			"hub_native_pair_plans_v1":           {"plan_id": "synthetic-plan", "pair_id": "synthetic-pair", "plan_json": "synthetic-exact-plan", "state": "INVALIDATED"},
			"hub_native_pair_consents_v1":        {"owner_proof": "synthetic-exact-owner-consent", "group_key_proof": "synthetic-exact-group-proof"},
			"hub_native_pair_operations_v1":      {"operation_id": "synthetic-original-operation", "state": "REJECTED_FENCED", "response_packet": []byte("synthetic-original-sealed-fence")},
			"hub_native_pair_messages_v1":        {"message_id": "synthetic-original-message", "ciphertext_bytes": int64(8192), "ciphertext_digest": "synthetic-exact-ciphertext-digest"},
			"hub_native_pair_node_operations_v1": {"sequence": int64(8), "operation_id": "synthetic-original-node-op", "response_packet": []byte("synthetic-original-node-receipt")},
		}
		for table, row := range rows {
			cp.Tables = append(cp.Tables, table)
			cp.rows[table] = map[string]map[string]any{"synthetic-row": row}
		}
		sort.Strings(cp.Tables)
		return cp
	}
	for _, edit := range []struct {
		name   string
		change func(*HubRestoreCheckpoint)
	}{
		{"pair_deadline", func(c *HubRestoreCheckpoint) {
			c.rows["hub_native_pairs_v1"]["synthetic-row"]["peer_expires_at"] = "2026-10-17T16:00:00Z"
		}},
		{"terminal_pair", func(c *HubRestoreCheckpoint) { c.rows["hub_native_pairs_v1"]["synthetic-row"]["state"] = "ACTIVE" }},
		{"control_revision", func(c *HubRestoreCheckpoint) {
			c.rows["hub_native_pairs_v1"]["synthetic-row"]["control_revision"] = int64(1)
		}},
		{"slot_sid", func(c *HubRestoreCheckpoint) {
			c.rows["hub_native_pair_slots_v1"]["synthetic-row"]["native_session_id"] = "synthetic-replacement-sid"
		}},
		{"rejected_slot", func(c *HubRestoreCheckpoint) {
			c.rows["hub_native_pair_slots_v1"]["synthetic-row"]["state"] = "RESERVED"
		}},
		{"old_plan", func(c *HubRestoreCheckpoint) {
			c.rows["hub_native_pair_plans_v1"]["synthetic-row"]["state"] = "PREPARED"
		}},
		{"owner_consent", func(c *HubRestoreCheckpoint) {
			c.rows["hub_native_pair_consents_v1"]["synthetic-row"]["owner_proof"] = "synthetic-substitute-proof"
		}},
		{"app_receipt", func(c *HubRestoreCheckpoint) { delete(c.rows["hub_native_pair_operations_v1"], "synthetic-row") }},
		{"message_budget", func(c *HubRestoreCheckpoint) { delete(c.rows["hub_native_pair_messages_v1"], "synthetic-row") }},
		{"node_receipt", func(c *HubRestoreCheckpoint) { delete(c.rows["hub_native_pair_node_operations_v1"], "synthetic-row") }},
	} {
		t.Run(edit.name, func(t *testing.T) {
			base, current := makeCheckpoint(), makeCheckpoint()
			if CompareHubRestoreCoverage(base, current) != nil {
				t.Fatal("unchanged synthetic checkpoint rejected")
			}
			edit.change(current)
			if !errors.Is(CompareHubRestoreCoverage(base, current), ErrHubRestoreCoverage) {
				t.Fatal("restore rolled native-pair authority/history/budget backward")
			}
		})
	}
}
