package store

import (
	"errors"
	"testing"
)

func syntheticHubCheckpoint() *HubRestoreCheckpoint {
	return &HubRestoreCheckpoint{HubID: "synthetic-independent-Hub", SchemaVersion: hubRestoreReviewedSchemaVersion, SchemaFingerprint: "synthetic-exact-schema", IdentityFingerprints: map[string]string{"identity": "synthetic"}, Tables: []string{"contacts", "node_tls_epoch_floors_v1", "node_tls_issuer_serial_floors_v1", "node_control_rpc_sequences_v1", "client_device_request_recovery_v2", "shared_tasks_v2", "resource_v2_authority", "node_control_rpc_inbox_v1"}, rows: map[string]map[string]map[string]any{
		"contacts":                          {"peer": {"send_sequence": int64(12), "received_sequences_json": "[7,9]"}},
		"node_tls_epoch_floors_v1":          {"hub/node": {"floor": int64(8)}},
		"node_tls_issuer_serial_floors_v1":  {"issuer": {"floor": "0000000000000000000000000000002a"}},
		"node_control_rpc_sequences_v1":     {"binding/key": {"last_sequence": int64(41)}},
		"client_device_request_recovery_v2": {"request": {"reserved_response_sequence": int64(17)}},
		"shared_tasks_v2":                   {"task": {"owner_epoch": int64(11)}},
		"resource_v2_authority":             {"resource": {"fencing_epoch": int64(19)}},
		"node_control_rpc_inbox_v1":         {"unknown": {"state": "UNCERTAIN", "operation_id": "synthetic-exact-op", "request_digest": "synthetic-exact-digest", "sequence": int64(41)}},
	}}
}

func TestHubRestoreSchema68OnlyAllowsEmptyNodePairState(t *testing.T) {
	if CurrentV2SchemaVersion != 68 || hubRestoreReviewedSchemaVersion != 67 {
		t.Fatal("change this explicit unsupported boundary only after a separate restore review")
	}
	db, root, _, _ := nativeTLSStoreFixture(t)
	cp, err := InspectHubRestoreCheckpointReadOnly(root)
	if err != nil || cp.SchemaVersion != 68 || CompareHubRestoreCoverage(cp, cp) != nil {
		t.Fatal("schema 68 without NPT state lost old restore behavior", err)
	}
	for _, table := range hubRestoreNPTTables {
		t.Run(table, func(t *testing.T) {
			rows := cp.rows[table]
			cp.rows[table] = map[string]map[string]any{"synthetic-unreviewed-state": {"id": int64(1)}}
			if !errors.Is(CompareHubRestoreCoverage(cp, cp), ErrHubRestoreCoverage) {
				t.Fatal("unreviewed NPT state gained restore coverage")
			}
			cp.rows[table] = rows
		})
	}
	cp.rows["node_control_key_requests_v1"]["synthetic-marker"] = map[string]any{"require_pair_trust_ack": int64(1)}
	if !errors.Is(CompareHubRestoreCoverage(cp, cp), ErrHubRestoreCoverage) {
		t.Fatal("independent RequireACK marker was ignored")
	}
	delete(cp.rows["node_control_key_requests_v1"], "synthetic-marker")
	if _, err := db.db.Exec(`INSERT INTO hub_node_pair_trust_rates_v1 VALUES('SYNTHETIC-attempt','SYNTHETIC-key','2026-10-24T00:00:00Z',1,'2026-10-24T00:02:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectHubRestoreCheckpointReadOnly(root); !errors.Is(err, ErrHubRestoreCoverage) {
		t.Fatal("real nonempty NPT database passed read-only restore admission", err)
	}
}

func TestHubRestoreOwnerBootstrapHistoryAndAccountCannotRollBack(t *testing.T) {
	for _, change := range []func(*HubRestoreCheckpoint){
		func(cp *HubRestoreCheckpoint) { delete(cp.rows["owner_root_history_v1"], "synthetic-owner") },
		func(cp *HubRestoreCheckpoint) { cp.rows["hub_owner_setup_v1"]["setup"]["owner_id"] = "synthetic-guest" },
		func(cp *HubRestoreCheckpoint) { cp.rows["hub_owner_setup_v1"]["setup"]["state"] = "LEGACY_COMPAT" },
		func(cp *HubRestoreCheckpoint) {
			cp.rows["owner_bootstrap_authority_v1"]["authority"]["state"] = "PENDING"
		},
		func(cp *HubRestoreCheckpoint) {
			cp.rows["owner_bootstrap_authority_v1"]["authority"]["proof_digest"] = "synthetic-replacement-proof"
		},
	} {
		makeCheckpoint := func() *HubRestoreCheckpoint {
			cp := syntheticHubCheckpoint()
			cp.Tables = append(cp.Tables, "hub_owner_setup_v1", "owner_root_history_v1", "owner_bootstrap_authority_v1")
			cp.rows["hub_owner_setup_v1"] = map[string]map[string]any{"setup": {"account_id": "synthetic-account", "owner_id": "synthetic-owner", "hub_id": cp.HubID, "state": "HUB_READY", "version": int64(1)}}
			cp.rows["owner_root_history_v1"] = map[string]map[string]any{"synthetic-owner": {"owner_id": "synthetic-owner", "established_at": "2026-10-13T00:00:00Z"}}
			cp.rows["owner_bootstrap_authority_v1"] = map[string]map[string]any{"authority": {"account_id": "synthetic-account", "owner_id": "synthetic-owner", "state": "CONSUMED", "pairing_json": "synthetic-exact-public-pair", "nonce_digest": "synthetic-nonce-digest", "proof_digest": "synthetic-original-proof", "receipt_packet": "synthetic-original-encrypted-receipt"}}
			return cp
		}
		base, current := makeCheckpoint(), makeCheckpoint()
		if e := CompareHubRestoreCoverage(base, current); e != nil {
			t.Fatal(e)
		}
		change(current)
		if e := CompareHubRestoreCoverage(base, current); !errors.Is(e, ErrHubRestoreCoverage) {
			t.Fatal("Owner bootstrap restoration moved trust backwards")
		}
	}
}

func TestHubRestoreCoveragePreservesAccountNonceReplayCoordinates(t *testing.T) {
	makeCheckpoint := func() *HubRestoreCheckpoint {
		cp := syntheticHubCheckpoint()
		cp.Tables = append(cp.Tables, "hub_account_attempts_v1", "hub_account_requests_v1")
		cp.rows["hub_account_attempts_v1"] = map[string]map[string]any{"attempt": {
			"account_id": "synthetic-account", "owner_id": "synthetic-owner", "device_id": "synthetic-device",
			"prepare_nonce_digest": "synthetic-prepare-nonce", "complete_nonce_digest": "synthetic-complete-nonce", "state": "CONSUMED",
		}}
		cp.rows["hub_account_requests_v1"] = map[string]map[string]any{"request": {
			"session_id": "synthetic-session", "operation_id": "synthetic-operation", "operation": "owner.account.session.inspect",
			"request_digest": "synthetic-request", "nonce_digest": "synthetic-session-nonce",
		}}
		return cp
	}
	for _, change := range []struct{ table, field, value string }{
		{"hub_account_attempts_v1", "prepare_nonce_digest", "synthetic-replaced-prepare-nonce"},
		{"hub_account_attempts_v1", "complete_nonce_digest", "synthetic-replaced-complete-nonce"},
		{"hub_account_requests_v1", "nonce_digest", "synthetic-replaced-session-nonce"},
	} {
		base, current := makeCheckpoint(), makeCheckpoint()
		current.rows[change.table][map[string]string{"hub_account_attempts_v1": "attempt", "hub_account_requests_v1": "request"}[change.table]][change.field] = change.value
		if err := CompareHubRestoreCoverage(base, current); !errors.Is(err, ErrHubRestoreCoverage) {
			t.Fatalf("restore replaced %s.%s nonce history: %v", change.table, change.field, err)
		}
	}
}

func TestHubRestoreCoverageRejectsCrossSchemaVersions(t *testing.T) {
	for _, versions := range [][2]int{
		{hubRestoreReviewedSchemaVersion - 1, hubRestoreReviewedSchemaVersion},
		{hubRestoreReviewedSchemaVersion, hubRestoreReviewedSchemaVersion - 1},
	} {
		base, current := syntheticHubCheckpoint(), syntheticHubCheckpoint()
		base.SchemaVersion, current.SchemaVersion = versions[0], versions[1]
		if err := CompareHubRestoreCoverage(base, current); !errors.Is(err, ErrHubRestoreCoverage) {
			t.Fatalf("cross-schema restore coverage passed for versions %v: %v", versions, err)
		}
	}
	base, current := syntheticHubCheckpoint(), syntheticHubCheckpoint()
	current.SchemaFingerprint = "synthetic-different-schema"
	if err := CompareHubRestoreCoverage(base, current); !errors.Is(err, ErrHubRestoreCoverage) {
		t.Fatalf("restore coverage accepted different schema fingerprints: %v", err)
	}
}

func TestHubForwardCoverageRejectsEveryBurnedFloorAndUnknownLoss(t *testing.T) {
	for _, fault := range []struct {
		name, table, key, column string
		value                    any
		remove                   bool
	}{
		{"contact send", "contacts", "peer", "send_sequence", int64(11), false},
		{"contact replay", "contacts", "peer", "received_sequences_json", "[9]", false},
		{"TLS epoch", "node_tls_epoch_floors_v1", "hub/node", "floor", int64(7), false},
		{"TLS issuer serial", "node_tls_issuer_serial_floors_v1", "issuer", "floor", "00000000000000000000000000000029", false},
		{"NodeControl burned sequence", "node_control_rpc_sequences_v1", "binding/key", "last_sequence", int64(40), false},
		{"response reservation", "client_device_request_recovery_v2", "request", "reserved_response_sequence", int64(16), false},
		{"Task ownership epoch", "shared_tasks_v2", "task", "owner_epoch", int64(10), false},
		{"resource fencing", "resource_v2_authority", "resource", "fencing_epoch", int64(18), false},
		{"UNKNOWN removal", "node_control_rpc_inbox_v1", "unknown", "", nil, true},
		{"UNKNOWN execution claim", "node_control_rpc_inbox_v1", "unknown", "state", "COMPLETE", false},
	} {
		t.Run(fault.name, func(t *testing.T) {
			base, current := syntheticHubCheckpoint(), syntheticHubCheckpoint()
			if fault.remove {
				delete(current.rows[fault.table], fault.key)
			} else {
				current.rows[fault.table][fault.key][fault.column] = fault.value
			}
			if e := CompareHubRestoreCoverage(base, current); !errors.Is(e, ErrHubRestoreCoverage) {
				t.Fatalf("rollback passed: %v", e)
			}
		})
	}
	if e := CompareHubRestoreCoverage(syntheticHubCheckpoint(), syntheticHubCheckpoint()); e != nil {
		t.Fatal(e)
	}
}
func TestHubForwardQuiescenceRefusesWorkersLeasesAndRedispatch(t *testing.T) {
	f := newHubForwardFixture(t)
	cp, e := InspectHubRestoreCheckpointReadOnly(f.source)
	if e != nil {
		t.Fatal(e)
	}
	if e = RequireHubRestoreExecutionQuiescent(cp); e != nil {
		t.Fatal(e)
	}
	for _, fault := range []struct{ table, field, value string }{{"workers", "status", "recovering"}, {"client_control_intents_v2", "state", "QUEUED"}, {"relay_v2_inbox", "state", "INJECTED"}, {"resource_v2_leases", "state", "UNCERTAIN"}, {"resource_v2_leases", "state", "RELEASED"}, {"shared_tasks_v2", "status", "RUNNING"}, {"external_actions", "status", "queued"}} {
		t.Run(fault.table, func(t *testing.T) {
			cp, e := InspectHubRestoreCheckpointReadOnly(f.source)
			if e != nil {
				t.Fatal(e)
			}
			cp.rows[fault.table]["synthetic-unsafe"] = map[string]any{fault.field: fault.value}
			if fault.table == "resource_v2_leases" && fault.value == "RELEASED" {
				cp.rows["resource_v2_authority"]["synthetic-resource"] = map[string]any{"state": "AVAILABLE", "current_lease_id": "", "fencing_epoch": int64(19)}
			}
			if e = RequireHubRestoreExecutionQuiescent(cp); !errors.Is(e, ErrHubRestoreExecutionPending) {
				t.Fatalf("unsafe dispatcher passed: %v", e)
			}
		})
	}
}

func TestHubForwardCoveragePreservesSQLiteStorageClass(t *testing.T) {
	for _, change := range []struct {
		name          string
		before, after any
	}{{"BLOB versus text", hubRestoreSQLiteBlob{Hex: "61"}, "blob:61"}, {"INTEGER versus REAL", int64(1), hubRestoreSQLiteReal{Bits: 0x3ff0000000000000}}} {
		t.Run(change.name, func(t *testing.T) {
			base, current := syntheticHubCheckpoint(), syntheticHubCheckpoint()
			base.rows["node_control_rpc_inbox_v1"]["unknown"]["synthetic_tombstone_column"] = change.before
			current.rows["node_control_rpc_inbox_v1"]["unknown"]["synthetic_tombstone_column"] = change.after
			if e := CompareHubRestoreCoverage(base, current); !errors.Is(e, ErrHubRestoreCoverage) {
				t.Fatalf("changed SQLite storage class passed: %v", e)
			}
		})
	}
}
