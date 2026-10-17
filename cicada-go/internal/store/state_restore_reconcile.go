package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Restore only permits schema versions whose table inventory, forward-floor,
// and UNKNOWN-row semantics have been reviewed explicitly. A new migration
// must update this pin only after those restore rules are reviewed.
const hubRestoreReviewedSchemaVersion = 64

type hubRestoreSQLiteBlob struct {
	Hex string `json:"sqlite_blob"`
}
type hubRestoreSQLiteReal struct {
	Bits uint64 `json:"sqlite_real_bits"`
}

type HubRestoreCheckpoint struct {
	HubID                string            `json:"hub_id"`
	SchemaVersion        int               `json:"schema_version"`
	SchemaFingerprint    string            `json:"schema_fingerprint"`
	IdentityFingerprints map[string]string `json:"identity_fingerprints"`
	CoverageSHA256       string            `json:"coverage_digest"`
	UnknownSHA256        string            `json:"unknown_tombstone_digest"`
	Tables               []string          `json:"tables"`
	rows                 map[string]map[string]map[string]any
}
type HubRestoreReconciliationReport struct {
	Authority        *HubRestoreAuthority `json:"authority"`
	Verified         bool                 `json:"verified"`
	ForwardInstalled bool                 `json:"forward_installed"`
	CoverageSHA256   string               `json:"coverage_digest"`
	UnknownSHA256    string               `json:"unknown_tombstone_digest"`
	ParkedStateDir   string               `json:"parked_state_dir,omitempty"`
}

// Full rows never leave this process or appear in a report. Every table is
// included; unsupported tables fail closed against the current schema table
// whitelist. Schema v61 also covers account claims, verifiers, devices, pending public
// association, authentication epochs, challenges, sessions and replay receipts.
// Schema v60 includes immutable account coordinates, finite bootstrap authority
// and permanent root history; forward coverage retains all three tables.
func InspectHubRestoreCheckpointReadOnly(stateDir string) (*HubRestoreCheckpoint, error) {
	root, e := canonicalRestoreTarget(stateDir)
	if e != nil {
		return nil, e
	}
	fps, e := hubRestoreIdentityFingerprints(root)
	if e != nil {
		return nil, e
	}
	db, e := openSQLiteReadOnly(filepath.Join(root, stateDatabaseName))
	if e != nil {
		return nil, e
	}
	defer db.Close()
	tx, e := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	cp := &HubRestoreCheckpoint{IdentityFingerprints: fps, SchemaVersion: hubRestoreReviewedSchemaVersion, rows: map[string]map[string]map[string]any{}}
	var n, max, bad int
	if e = tx.QueryRow(`SELECT count(*),coalesce(max(version),0),sum(CASE WHEN state!='applied' THEN 1 ELSE 0 END) FROM schema_migrations_v2`).Scan(&n, &max, &bad); e != nil || n != hubRestoreReviewedSchemaVersion || max != hubRestoreReviewedSchemaVersion || bad != 0 {
		return nil, ErrHubRestoreCoverage
	}
	if e = tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&cp.HubID); e != nil || cp.HubID == "" {
		return nil, fmt.Errorf("%w: stable SOURCE Hub ID cannot be read (%v)", ErrHubRestoreAuthorityUnproven, e)
	}
	rs, e := tx.Query(`SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if e != nil {
		return nil, e
	}
	for rs.Next() {
		var name, statement string
		if e = rs.Scan(&name, &statement); e != nil {
			rs.Close()
			return nil, e
		}
		if !hubRestoreSupportedTable(name) {
			rs.Close()
			return nil, fmt.Errorf("%w: unsupported table %s", ErrHubRestoreCoverage, name)
		}
		cp.Tables = append(cp.Tables, name)
	}
	e = rs.Err()
	rs.Close()
	if e != nil {
		return nil, e
	}
	// Use the existing exact schema digest (includes indexes and column layout).
	meta, _, e := inspectSQLiteSnapshot(nil, filepath.Join(root, stateDatabaseName))
	if e != nil {
		return nil, e
	}
	cp.SchemaFingerprint = meta.SchemaFingerprint
	budget := 0
	var unknown []string
	for _, table := range cp.Tables {
		columns, e := tx.Query(`PRAGMA table_info("` + table + `")`)
		if e != nil {
			return nil, e
		}
		pkOrder := map[int]string{}
		for columns.Next() {
			var cid, notnull, pk int
			var name, typ string
			var def any
			if e = columns.Scan(&cid, &name, &typ, &notnull, &def, &pk); e != nil {
				columns.Close()
				return nil, e
			}
			if pk > 0 {
				pkOrder[pk] = name
			}
		}
		e = columns.Err()
		columns.Close()
		if e != nil {
			return nil, e
		}
		var orders []int
		for p := range pkOrder {
			orders = append(orders, p)
		}
		sort.Ints(orders)
		rows, e := tx.Query(`SELECT * FROM "` + table + `"`)
		if e != nil {
			return nil, e
		}
		names, e := rows.Columns()
		if e != nil {
			rows.Close()
			return nil, e
		}
		cp.rows[table] = map[string]map[string]any{}
		for rows.Next() {
			values := make([]any, len(names))
			dest := make([]any, len(names))
			for i := range values {
				dest[i] = &values[i]
			}
			if e = rows.Scan(dest...); e != nil {
				rows.Close()
				return nil, e
			}
			row := map[string]any{}
			for i, name := range names {
				v := values[i]
				if b, ok := v.([]byte); ok {
					v = hubRestoreSQLiteBlob{hex.EncodeToString(b)}
				}
				if real, ok := v.(float64); ok {
					v = hubRestoreSQLiteReal{math.Float64bits(real)}
				}
				row[name] = v
			}
			var key []any
			for _, p := range orders {
				key = append(key, row[pkOrder[p]])
			}
			if len(key) == 0 {
				key = append(key, hubRestoreDigest(row))
			}
			k := hubRestoreDigest(key)
			if _, ok := cp.rows[table][k]; ok {
				rows.Close()
				return nil, ErrHubRestoreCoverage
			}
			cp.rows[table][k] = row
			encoded, _ := json.Marshal(row)
			budget += len(encoded)
			if budget > 64<<20 || len(cp.rows[table]) > 100000 {
				rows.Close()
				return nil, ErrHubRestoreCoverage
			}
			if hubRestoreUnknown(row) {
				unknown = append(unknown, table+":"+k+":"+hubRestoreDigest(row))
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
	}
	for _, name := range []string{"hub_native_pairs_v1", "hub_native_pair_slots_v1", "hub_native_pair_plans_v1", "hub_native_pair_consents_v1", "hub_native_pair_operations_v1", "hub_native_pair_messages_v1", "hub_native_pair_node_operations_v1", "hub_app_node_heads_v1", "hub_app_node_grants_v1", "hub_app_node_operations_v1", "hub_app_node_provenance_v1", "hub_owner_activation_v1", "hub_owner_operations_v1", "hub_app_leases_v1", "hub_account_config_v1", "hub_account_claims_v1", "hub_account_credentials_v1", "hub_account_devices_v1", "hub_account_public_association_v1", "hub_account_attempts_v1", "hub_account_sessions_v1", "hub_account_requests_v1", "hub_owner_setup_v1", "owner_root_history_v1", "owner_bootstrap_authority_v1", "contacts", "peer_sessions", "client_devices_v2", "client_device_requests_v2", "client_device_request_recovery_v2", "node_control_rpc_sequences_v1", "node_control_rpc_inbox_v1", "node_tls_authority_v1", "shared_tasks_v2", "resource_v2_leases", "relay_v2_inbox", "workers"} {
		if _, ok := cp.rows[name]; !ok {
			return nil, fmt.Errorf("%w: missing scope %s", ErrHubRestoreCoverage, name)
		}
	}
	sort.Strings(unknown)
	cp.UnknownSHA256 = hubRestoreDigest(unknown)
	cp.CoverageSHA256 = hubRestoreDigest(cp.rows)
	return cp, nil
}
func hubRestoreUnknown(row map[string]any) bool {
	for _, field := range []string{"state", "status"} {
		s, _ := row[field].(string)
		s = strings.ToUpper(s)
		if strings.Contains(s, "UNCERTAIN") || strings.Contains(s, "UNKNOWN") || s == "QUARANTINED" {
			return true
		}
	}
	if v, ok := row["holder_task_epoch"].(int64); ok && v == 0 {
		return true
	}
	return false
}
func hubRestoreFloor(name string) bool {
	switch name {
	case "control_revision", "head_version", "epoch", "version", "session_epoch", "node_key_epoch", "node_key_version", "hub_key_version", "node_credential_version", "last_sequence", "send_sequence", "send_count", "receive_count", "next_sequence", "last_request_sequence", "next_response_sequence", "reserved_response_sequence", "fencing_epoch", "owner_epoch", "binding_epoch", "sequence", "generation", "tls_epoch", "burned_epoch", "highest_epoch", "holder_task_epoch", "issuer_generation", "node_tls_epoch", "revision", "floor", "reservation_version":
		return true
	}
	return false
}
func CompareHubRestoreCoverage(base, current *HubRestoreCheckpoint) error {
	if base == nil || current == nil || base.SchemaVersion != hubRestoreReviewedSchemaVersion || current.SchemaVersion != hubRestoreReviewedSchemaVersion || base.SchemaVersion != current.SchemaVersion || base.HubID != current.HubID || base.SchemaFingerprint != current.SchemaFingerprint || hubRestoreDigest(base.IdentityFingerprints) != hubRestoreDigest(current.IdentityFingerprints) || hubRestoreDigest(base.Tables) != hubRestoreDigest(current.Tables) {
		return ErrHubRestoreCoverage
	}
	for table, rows := range base.rows {
		// These two bounded tables hold no authority, replay nonce, effect or
		// mutation receipt. Ordinary polling/rate-window expiry may evict them.
		if table == "hub_app_node_reads_v1" || table == "hub_app_node_rates_v1" || table == "hub_native_pair_guard_v1" || table == "hub_native_pair_reads_v1" || table == "hub_native_pair_rates_v1" {
			continue
		}

		for key, old := range rows {
			next, ok := current.rows[table][key]
			if !ok {
				return fmt.Errorf("%w: missing %s history", ErrHubRestoreCoverage, table)
			}
			if hubRestoreUnknown(old) && hubRestoreDigest(old) != hubRestoreDigest(next) {
				return fmt.Errorf("%w: %s UNKNOWN tombstone changed", ErrHubRestoreCoverage, table)
			}
			for name, value := range old {
				if name == "floor" && table == "node_tls_issuer_serial_floors_v1" {
					x, xok := value.(string)
					y, yok := next[name].(string)
					if !xok || !yok || len(x) != 32 || len(y) != 32 || y < x {
						return ErrHubRestoreCoverage
					}
				}
				if hubRestoreFloor(name) {
					floor, ok := value.(int64)
					if ok {
						high, ok := next[name].(int64)
						if !ok || high < floor {
							return fmt.Errorf("%w: %s.%s floor", ErrHubRestoreCoverage, table, name)
						}
					}
				}
				// Immutable cryptographic and operation coordinates. Mutable revocation
				// state/version may advance, but cannot silently replace an identity.
				switch name {
				case "manifest_digest", "pairing_json", "nonce_digest", "prepare_nonce_digest", "complete_nonce_digest", "established_at", "root_key", "response_packet", "recovery_packet", "identity_json", "public_identity_json", "node_public_identity_json", "hub_public_identity_json", "public_key_json", "request_digest", "ciphertext_digest", "operation_id", "operation", "native_session_id", "session_id", "credential_hash":
					if hubRestoreDigest(value) != hubRestoreDigest(next[name]) {
						return fmt.Errorf("%w: %s.%s identity", ErrHubRestoreCoverage, table, name)
					}
				}
			}
			if table == "hub_owner_setup_v1" || table == "owner_bootstrap_authority_v1" || table == "owner_root_history_v1" {
				for _, field := range []string{"account_id", "owner_id", "hub_id"} {
					if hubRestoreDigest(old[field]) != hubRestoreDigest(next[field]) {
						return fmt.Errorf("%w: %s.%s coordinate", ErrHubRestoreCoverage, table, field)
					}
				}
			}
			if table == "owner_bootstrap_authority_v1" && old["state"] != "PENDING" && hubRestoreDigest(old) != hubRestoreDigest(next) {
				return fmt.Errorf("%w: terminal Owner bootstrap changed", ErrHubRestoreCoverage)
			}
			if table == "hub_owner_setup_v1" && old["state"] == "HUB_READY" && next["state"] != "HUB_READY" {
				return fmt.Errorf("%w: Hub setup readiness rolled back", ErrHubRestoreCoverage)
			}

			if table == "hub_native_pair_operations_v1" || table == "hub_native_pair_messages_v1" || table == "hub_native_pair_consents_v1" || table == "hub_native_pair_node_operations_v1" {
				if hubRestoreDigest(old) != hubRestoreDigest(next) {
					return ErrHubRestoreCoverage
				}
			}
			if table == "hub_native_pairs_v1" {
				for _, field := range []string{"pair_id", "hub_id", "account_id", "owner_id", "device_id", "node_id", "network_id", "group_id", "scope_json", "bootstrap_json", "prepare_operation_id", "proof_expires_at", "join_until", "peer_expires_at", "created_at"} {
					if hubRestoreDigest(old[field]) != hubRestoreDigest(next[field]) {
						return ErrHubRestoreCoverage
					}
				}
				if old["bootstrap_owner_proof"] != nil && hubRestoreDigest(old["bootstrap_owner_proof"]) != hubRestoreDigest(next["bootstrap_owner_proof"]) {
					return ErrHubRestoreCoverage
				}
				if (old["state"] == "REVOKED" || old["state"] == "EXPIRED") && hubRestoreDigest(old) != hubRestoreDigest(next) {
					return ErrHubRestoreCoverage
				}
				if old["state"] == "ACTIVE" && next["state"] != "ACTIVE" && next["state"] != "REVOKED" && next["state"] != "EXPIRED" {
					return ErrHubRestoreCoverage
				}
			}
			if table == "hub_native_pair_plans_v1" {
				for _, field := range []string{"plan_id", "pair_id", "plan_json", "created_at"} {
					if hubRestoreDigest(old[field]) != hubRestoreDigest(next[field]) {
						return ErrHubRestoreCoverage
					}
				}
				if old["state"] != "PREPARED" && hubRestoreDigest(old) != hubRestoreDigest(next) {
					return ErrHubRestoreCoverage
				}
			}
			if table == "hub_native_pair_slots_v1" {
				for _, field := range []string{"pair_id", "slot", "generation", "created_at"} {
					if hubRestoreDigest(old[field]) != hubRestoreDigest(next[field]) {
						return ErrHubRestoreCoverage
					}
				}
				if old["attempt_id"] != "" {
					for _, field := range []string{"attempt_id", "native_session_id", "endpoint_id", "principal_id", "network_access_binding_id", "binding_id", "lease_owner"} {
						if hubRestoreDigest(old[field]) != hubRestoreDigest(next[field]) {
							return ErrHubRestoreCoverage
						}
					}
				}
				if (old["state"] == "REJECTED" || old["state"] == "ACTIVE") && old["state"] != next["state"] {
					return ErrHubRestoreCoverage
				}
			}

			if table == "hub_app_node_operations_v1" || table == "hub_app_node_provenance_v1" {
				if hubRestoreDigest(old) != hubRestoreDigest(next) {
					return ErrHubRestoreCoverage
				}
			}
			if table == "hub_app_node_heads_v1" {
				if old["head_version"] == next["head_version"] && old["latest_grant_id"] != next["latest_grant_id"] {
					return ErrHubRestoreCoverage
				}
				if old["provenance_id"] != "" && old["provenance_id"] != next["provenance_id"] {
					return ErrHubRestoreCoverage
				}
			}
			if table == "hub_app_node_grants_v1" {
				for _, field := range []string{"grant_id", "account_id", "owner_id", "device_id", "claims_json", "created_at"} {
					if hubRestoreDigest(old[field]) != hubRestoreDigest(next[field]) {
						return ErrHubRestoreCoverage
					}
				}
				if old["owner_proof"] != nil && hubRestoreDigest(old["owner_proof"]) != hubRestoreDigest(next["owner_proof"]) {
					return ErrHubRestoreCoverage
				}
				if old["provenance_id"] != "" && old["provenance_id"] != next["provenance_id"] {
					return ErrHubRestoreCoverage
				}
				remaining, rok := old["remaining"].(int64)
				later, lok := next["remaining"].(int64)
				if !rok || !lok || later > remaining {
					return ErrHubRestoreCoverage
				}
				if old["state"] != "PREPARED" && old["state"] != "ACTIVE" && hubRestoreDigest(old) != hubRestoreDigest(next) {
					return ErrHubRestoreCoverage
				}
				if old["state"] == "ACTIVE" && next["state"] == "PREPARED" {
					return ErrHubRestoreCoverage
				}
			}
			if table == "hub_owner_operations_v1" && hubRestoreDigest(old) != hubRestoreDigest(next) {
				return ErrHubRestoreCoverage
			}
			if table == "hub_app_leases_v1" {
				for _, field := range []string{"owner_id", "device_id", "account_id", "activation_id", "binding_json", "account_epoch", "device_epoch", "owner_key_id", "expires_at"} {
					if hubRestoreDigest(old[field]) != hubRestoreDigest(next[field]) {
						return ErrHubRestoreCoverage
					}
				}
				if old["state"] == "REVOKED" && next["state"] != "REVOKED" {
					return ErrHubRestoreCoverage
				}
			}
			if table == "hub_owner_activation_v1" {
				for _, field := range []string{"activation_id", "account_id", "owner_id", "material_json", "code_digest", "epoch", "created_at"} {
					if hubRestoreDigest(old[field]) != hubRestoreDigest(next[field]) {
						return ErrHubRestoreCoverage
					}
				}
				if old["state"] != "ISSUED" {
					for _, field := range []string{"binding_json", "pairing_json", "grant_bytes", "challenge_packet", "owner_nonce_digest", "device_nonce_digest", "prepare_nonce_digest"} {
						if hubRestoreDigest(old[field]) != hubRestoreDigest(next[field]) {
							return ErrHubRestoreCoverage
						}
					}
				}
				if (old["state"] == "COMPLETED" || old["state"] == "CANCELLED") && hubRestoreDigest(old) != hubRestoreDigest(next) {
					return ErrHubRestoreCoverage
				}
				if old["state"] == "PREPARED" && next["state"] == "ISSUED" {
					return ErrHubRestoreCoverage
				}
			}

			if strings.HasPrefix(table, "hub_account_") {
				for _, field := range []string{"account_id", "owner_id", "hub_id", "origin", "hub_pin", "code_digest", "claim_id", "attempt_id", "device_id", "prepare_id", "prepare_digest", "challenge_digest", "salt", "verifier", "algorithm", "username", "token_digest", "credential_version", "device_epoch"} {
					if _, exists := old[field]; exists && hubRestoreDigest(old[field]) != hubRestoreDigest(next[field]) {
						return fmt.Errorf("%w: %s.%s account scope", ErrHubRestoreCoverage, table, field)
					}
				}
				if table == "hub_account_claims_v1" && (old["state"] == "CONSUMED" || old["state"] == "CANCELLED") && next["state"] != old["state"] {
					return ErrHubRestoreCoverage
				}
				if table == "hub_account_attempts_v1" && old["state"] != "PENDING" && hubRestoreDigest(old) != hubRestoreDigest(next) {
					return ErrHubRestoreCoverage
				}
				if table == "hub_account_sessions_v1" && old["state"] == "REVOKED" && next["state"] != "REVOKED" {
					return ErrHubRestoreCoverage
				}
				if table == "hub_account_devices_v1" && old["status"] == "REVOKED" && next["status"] != "REVOKED" {
					return ErrHubRestoreCoverage
				}
			}
			if table == "peer_sessions" {
				for _, pair := range [][2]string{{"send_count", "send_chain_key"}, {"receive_count", "receive_chain_key"}} {
					if old[pair[0]] == next[pair[0]] && hubRestoreDigest(old[pair[1]]) != hubRestoreDigest(next[pair[1]]) {
						return ErrHubRestoreCoverage
					}
				}
			}
			if table == "contacts" {
				var before, after []uint64
				bs, _ := old["received_sequences_json"].(string)
				cs, _ := next["received_sequences_json"].(string)
				if json.Unmarshal([]byte(bs), &before) != nil || json.Unmarshal([]byte(cs), &after) != nil {
					return ErrHubRestoreCoverage
				}
				seen := map[uint64]bool{}
				for _, v := range after {
					seen[v] = true
				}
				for _, v := range before {
					if !seen[v] {
						return fmt.Errorf("%w: contact replay history lost", ErrHubRestoreCoverage)
					}
				}
			}
		}
	}
	return nil
}

// No advisory "stopped" flag or lease expiry authorizes an external writer.
// Terminal UNKNOWN ledgers can be exposed read-only only where no dispatcher
// can recover them. Resources and jobs with unknown outcomes remain a hold.
func RequireHubRestoreExecutionQuiescent(cp *HubRestoreCheckpoint) error {
	if cp == nil {
		return ErrHubRestoreCoverage
	}
	if leases, ok := cp.rows["resource_v2_leases"]; !ok {
		return ErrHubRestoreCoverage
	} else if len(leases) != 0 {
		return fmt.Errorf("%w: resource lease history has no independently verified executor-stop proof", ErrHubRestoreExecutionPending)
	}
	allowed := map[string]struct {
		field  string
		states string
	}{
		"workers":                    {"status", "completed,failed,cancelled,stopped"},
		"client_control_intents_v2":  {"state", "DONE,UNCERTAIN"},
		"client_device_requests_v2":  {"status", "COMPLETED,FAILED,UNCERTAIN"},
		"node_control_rpc_inbox_v1":  {"state", "COMPLETE,UNCERTAIN"},
		"relay_v2_inbox":             {"state", "ACKED,FAILED,EXPIRED,CANCELLED,INJECTION_UNCERTAIN"},
		"relay_v2_delivery_attempts": {"state", "ACKED,FAILED,CANCELLED,INJECTION_UNCERTAIN"},
		"relay_v2_requests":          {"state", "CANCELLED,EXPIRED,REPLIED,LATE_RESULT"},
		"relay_v2_outbox":            {"state", "ACKED,FAILED,EXPIRED,CANCELLED,INJECTION_UNCERTAIN"},
		"shared_tasks_v2":            {"status", "COMPLETED,CANCELLED"},
		"resource_v2_leases":         {"state", "RELEASED"},
		"resource_v2_authority":      {"state", "AVAILABLE"},
		"peer_messages":              {"status", "received,sent,delivered,failed"},
		"intents":                    {"status", "resolved,needs_input,failed"},
		"external_actions":           {"status", "completed,failed,cancelled"},
		"thread_deliveries":          {"status", "delivered,failed,cancelled"},
		"fabric_messages":            {"status", "delivered,failed,cancelled,expired"},
		"commands":                   {"status", "completed,failed,cancelled"},
		"node_tls_authority_v1":      {"state", "ACTIVE,CANCELLED,REVOKED,UNCERTAIN"},
		"session_bindings":           {"status", "revoked,closed,expired"},
	}
	for table, rule := range allowed {
		rows, ok := cp.rows[table]
		if !ok {
			return fmt.Errorf("%w: absent dispatcher scope %s", ErrHubRestoreCoverage, table)
		}
		for _, row := range rows {
			value, _ := row[rule.field].(string)
			found := false
			for _, s := range strings.Split(rule.states, ",") {
				if value == s {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("%w: %s has nonterminal execution", ErrHubRestoreExecutionPending, table)
			}
			if table == "workers" && row["pid"] != nil {
				return fmt.Errorf("%w: external worker identity remains", ErrHubRestoreExecutionPending)
			}
		}
	}
	return nil
}
func hubRestorePairedHold(target, manifestDigest string) ([]byte, error) {
	var h struct {
		Version        int    `json:"version"`
		Target         string `json:"target_state_dir"`
		ManifestSHA256 string `json:"backup_manifest_sha256"`
		Status         string `json:"recovery_status"`
		CreatedAt      string `json:"created_at"`
	}
	b, e := hubRestoreReadJSON(filepath.Join(target, stateRestoreMarker), &h)
	if e != nil {
		return nil, e
	}
	if h.Version != 1 || h.Target != target || h.ManifestSHA256 != manifestDigest || h.Status != "pending" {
		return nil, ErrHubRestoreAuthorityUnproven
	}
	i, e := os.Lstat(filepath.Dir(stateRestoreRegistrationPath(target)))
	if e != nil || !stateRestorePrivateDirectory(i) {
		return nil, ErrHubRestoreAuthorityUnproven
	}
	paired, e := hubRestoreReadPrivateFile(stateRestoreRegistrationPath(target))
	if e != nil || string(b) != string(paired) {
		return nil, ErrHubRestoreAuthorityUnproven
	}
	return b, nil
}
func InspectHubRestoreHandover(o HubRestoreOperationOptions) (*HubRestoreReconciliationReport, error) {
	path, e := hubRestoreLocate(o.SourceStateDir)
	if e != nil {
		return nil, e
	}
	a, e := hubRestoreReadAuthority(path)
	if e != nil {
		return nil, e
	}
	if a.State == "ACTIVE_SOURCE" {
		if e = hubRestoreVerifyStartupAuthority(o.SourceStateDir, a, path); e != nil {
			return nil, e
		}
		return &HubRestoreReconciliationReport{Authority: a, Verified: true}, nil
	}
	if a.State == "ACTIVE_TARGET" {
		target, e := canonicalRestoreTarget(o.TargetStateDir)
		if e != nil || a.SourceStorage.CanonicalCoordinate != o.SourceStateDir {
			return nil, ErrHubRestoreAuthorityUnproven
		}
		if e = hubRestoreVerifyStartupAuthority(target, a, path); e != nil {
			return nil, e
		}
		prior := *a
		prior.AuthorityEpoch--
		fr, e := hubRestoreReadForwardReceipt(path, &prior)
		if e != nil {
			return nil, e
		}
		return &HubRestoreReconciliationReport{Authority: a, Verified: true, ForwardInstalled: true, CoverageSHA256: a.CoverageSHA256, UnknownSHA256: a.UnknownSHA256, ParkedStateDir: fr.ParkedStateDir}, nil
	}
	return hubRestoreReconcileReadOnly(o, a, path)
}
func hubRestoreReconcileReadOnly(o HubRestoreOperationOptions, a *HubRestoreAuthority, path string) (*HubRestoreReconciliationReport, error) {
	target, e := canonicalRestoreTarget(o.TargetStateDir)
	if e != nil || a.State != "SEALED" || a.TargetStateDir != target || a.SourceStorage.CanonicalCoordinate != o.SourceStateDir || !hubRestoreIncarnationMatches(a.SourceStorage, o.SourceStateDir) {
		return nil, ErrHubRestoreAuthorityUnproven
	}
	bm, e := VerifyStateBackup(a.BaseBackupDir)
	if e != nil || hubRestoreDigest(bm) != a.BaseManifestSHA256 {
		return nil, ErrHubRestoreCoverage
	}
	cm, e := VerifyStateBackup(a.CapsuleDir)
	if e != nil || hubRestoreDigest(cm) != a.CapsuleManifestSHA256 || hubRestoreDigest(cm.Files) != a.InventorySHA256 {
		return nil, ErrHubRestoreCoverage
	}
	hold, e := hubRestorePairedHold(target, a.BaseManifestSHA256)
	if e != nil {
		return nil, e
	}
	base, e := InspectHubRestoreCheckpointReadOnly(filepath.Join(a.BaseBackupDir, stateBackupPayloadName))
	if e != nil {
		return nil, e
	}
	current, e := InspectHubRestoreCheckpointReadOnly(filepath.Join(a.CapsuleDir, stateBackupPayloadName))
	if e != nil {
		return nil, e
	}
	if e = CompareHubRestoreCoverage(base, current); e != nil {
		return nil, e
	}
	if e = RequireHubRestoreExecutionQuiescent(current); e != nil {
		return nil, e
	}
	if current.CoverageSHA256 != a.CoverageSHA256 || current.UnknownSHA256 != a.UnknownSHA256 {
		return nil, ErrHubRestoreCoverage
	}
	report := &HubRestoreReconciliationReport{Authority: a, Verified: true, CoverageSHA256: a.CoverageSHA256, UnknownSHA256: a.UnknownSHA256}
	fr, e := hubRestoreReadForwardReceipt(path, a)
	if e == nil {
		if e = hubRestoreVerifyForward(target, hold, cm, fr); e != nil {
			return nil, e
		}
		report.ForwardInstalled = true
		report.ParkedStateDir = fr.ParkedStateDir
		return report, nil
	}
	if !os.IsNotExist(e) {
		return nil, e
	}
	if e = hubRestoreVerifyPayload(target, bm, hold); e != nil {
		return nil, e
	}
	return report, nil
}

// Explicit schema table names, reviewed against the selected product schema.
// Schema v60 preserves account, consumed authority and permanent root history.
func hubRestoreSupportedTable(name string) bool {
	switch name {
	case "hub_native_pairs_v1", "hub_native_pair_slots_v1", "hub_native_pair_plans_v1", "hub_native_pair_consents_v1", "hub_native_pair_operations_v1", "hub_native_pair_messages_v1", "hub_native_pair_node_operations_v1", "hub_native_pair_guard_v1", "hub_native_pair_reads_v1", "hub_native_pair_rates_v1", "hub_app_node_heads_v1", "hub_app_node_grants_v1", "hub_app_node_operations_v1", "hub_app_node_provenance_v1", "hub_app_node_reads_v1", "hub_app_node_rates_v1", "hub_owner_activation_v1", "hub_owner_operations_v1", "hub_app_leases_v1", "hub_account_config_v1", "hub_account_claims_v1", "hub_account_credentials_v1", "hub_account_devices_v1", "hub_account_public_association_v1", "hub_account_attempts_v1", "hub_account_sessions_v1", "hub_account_requests_v1", "hub_owner_setup_v1", "owner_root_history_v1", "owner_bootstrap_authority_v1", "approvals", "artifact_v2_grants", "artifact_v2_refs", "artifacts", "attachments", "client_control_intents_v2", "client_device_enrollment_proofs_v2", "client_device_grant_nonces_v2", "client_device_hub_config_v2", "client_device_request_recovery_v2", "client_device_requests_v2", "client_devices_v2", "client_status_change_events_v2", "client_status_state_v2", "client_status_streams_v2", "client_topology_group_create_guard_v2", "client_topology_group_creates_v2", "commands", "communication_link_grants_v2", "communication_link_key_grants_v2", "communication_link_message_review_candidates_v2", "communication_link_message_reviews_v2", "communication_link_review_events_v2", "communication_link_review_policy_grants_v2", "communication_link_review_policy_heads_v2", "communication_links_v2", "contact_discovery_requests", "contacts", "cross_owner_group_admissions_v2", "cross_owner_group_joins_v2", "cross_owner_group_key_proofs_v2", "directory_records", "endpoint_group_memberships", "endpoint_key_candidates_v2", "endpoint_network_memberships_v2", "events", "external_actions", "external_events", "external_thread_invites_v2", "external_thread_invites_v2_v51", "fabric_endpoints", "fabric_events", "fabric_messages", "fabric_node_credentials", "gateway_v2_contracts", "gateway_v2_group_cards", "gateway_v2_mailbox", "gateway_v2_representatives", "gateway_v2_request_events", "gateway_v2_requests", "gateway_v2_results", "goals", "group_broadcast_v2_snapshot_recipients", "group_broadcast_v2_snapshots", "group_endpoint_key_grants_v2", "group_space_audience_v2", "group_space_change_sequences_v2", "group_space_history_grants_v2", "group_space_history_manifests_v2", "group_space_read_state_v2", "group_space_readers_v2", "group_space_records_v2", "group_space_sequences_v2", "group_space_tombstones_v2", "group_space_topics_v2", "groups", "ideas", "intents", "machines", "memberships", "memories", "monitors", "network_access_sessions_v2", "network_broadcast_recipients_v2", "network_broadcasts_v2", "network_collaboration_key_grant_nonces_v2", "network_collaboration_key_grants_v2", "network_direct_key_candidates_v2", "network_direct_key_grant_nonces_v2", "network_direct_key_grants_v2", "network_direct_message_routes_v2", "network_direct_native_bindings_v2", "network_group_mappings_v2", "network_invitations_v2", "network_join_consents_v2", "network_memberships_v2", "network_message_enrollment_v2", "network_mode_v2", "network_task_offers_v2", "network_task_readers_v2", "network_task_results_v2", "networks_v2", "node_control_key_bindings_v1", "node_control_key_requests_v1", "node_control_rpc_inbox_v1", "node_control_rpc_sequences_v1", "node_control_snapshot_rpc_responses_v1", "node_device_binding_requests_v2", "node_owner_bindings_v2", "node_tls_application_keys_v1", "node_tls_authority_v1", "node_tls_epoch_floors_v1", "node_tls_issuer_serial_floors_v1", "node_tls_proof_nonces_v1", "notifications", "owner_approval_keys_v2", "peer_messages", "peer_sessions", "permissions", "principals", "push_subscriptions", "regroup_audit_v2", "regroup_delegations_v2", "regroup_proposals_v2", "relay_v2_admission_config", "relay_v2_admission_guard", "relay_v2_consumer_cursors", "relay_v2_delivery_attempts", "relay_v2_inbox", "relay_v2_message_payloads", "relay_v2_message_security", "relay_v2_outbox", "relay_v2_rebind_events", "relay_v2_receipts", "relay_v2_recipient_sequences", "relay_v2_request_events", "relay_v2_requests", "resource_v2_authority", "resource_v2_leases", "resource_v2_managed_blobs", "schema_migrations_v2", "session_bindings", "shared_task_local_handoff_routes_v54", "shared_task_peer_assignments_v57", "shared_task_peer_refs_v57", "shared_task_sealed_handoffs_v2", "shared_task_v2_dependencies", "shared_task_v2_events", "shared_task_v2_guard", "shared_task_v2_handoffs", "shared_task_v2_results", "shared_task_v2_side_effect_events", "shared_task_v2_side_effects", "shared_tasks_v2", "thread_deliveries", "thread_sessions", "user_monitor_broadcast_v2", "user_monitor_broadcast_v2_notice_cursors", "user_monitor_broadcast_v2_notice_receipts", "user_monitor_broadcast_v2_recipient_outcomes", "workers", "workspaces":
		return true
	}
	return false
}
