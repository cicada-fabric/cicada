package store

// Versioned v2 schema initialization lives here rather than in the individual
// Fabric/Relay/Gateway stores.  The existing schema builders remain the source
// of truth for their tables, while this runner supplies the missing migration
// boundary: each version is applied in one SQLite savepoint, recorded in a
// durable ledger, and retried safely when a process stops before commit.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	// CurrentV2SchemaVersion is the highest versioned migration installed by
	// Store initialization.  It is intentionally independent of the product
	// version so a binary can refuse a ledger with a changed definition.
	CurrentV2SchemaVersion = 30

	v2MigrationRunning = "running"
	v2MigrationApplied = "applied"
	v2MigrationFailed  = "failed"
)

type v2Migration struct {
	Version     int
	ID          string
	Description string
	Objects     []string
	Apply       func(*Store) error
}

type v2MigrationLedgerEntry struct {
	Version          int
	MigrationID      string
	Description      string
	Checksum         string
	State            string
	Attempts         int
	SourceCount      int64
	TargetCount      int64
	VerificationJSON string
	StartedAt        string
	AppliedAt        string
	LastError        string
	CreatedAt        string
	UpdatedAt        string
}

// legacyInventory is captured after the pre-v2 compatibility work in
// Store.initialize.  v2 schema creation must not rewrite any of these rows;
// the digest is an opaque consistency check and never contains row contents.
type legacyInventory struct {
	Count  int64
	Digest string
}

var v2Migrations = []v2Migration{
	{
		Version:     1,
		ID:          "v2.fabric.identity",
		Description: "add principals, groups, memberships, and session bindings",
		Objects: []string{
			"principals", "groups", "memberships", "session_bindings",
		},
		Apply: func(s *Store) error { return s.initializeFabricV2Schema() },
	},
	{
		Version:     2,
		ID:          "v2.node.credentials",
		Description: "add hashed node relay credentials",
		Objects:     []string{"fabric_node_credentials"},
		Apply:       func(s *Store) error { return s.initializeNodeCredentialSchema() },
	},
	{
		Version:     3,
		ID:          "v2.relay.delivery",
		Description: "add relay routing, inbox, attempts, receipts, and cursors",
		Objects: []string{
			"relay_v2_message_security", "relay_v2_requests", "relay_v2_outbox",
			"relay_v2_recipient_sequences", "relay_v2_inbox", "relay_v2_consumer_cursors",
			"relay_v2_delivery_attempts", "relay_v2_receipts", "relay_v2_request_events",
			"relay_v2_rebind_events",
		},
		Apply: func(s *Store) error { return s.initializeRelayV2Schema() },
	},
	{
		Version:     4,
		ID:          "v2.gateway.federation",
		Description: "add group cards, contracts, representatives, requests, and results",
		Objects: []string{
			"gateway_v2_group_cards", "gateway_v2_contracts", "gateway_v2_representatives",
			"gateway_v2_requests", "gateway_v2_request_events", "gateway_v2_mailbox",
			"gateway_v2_results",
		},
		Apply: func(s *Store) error { return s.initializeGatewayV2Schema() },
	},
	{
		Version:     5,
		ID:          "v2.relay.admission",
		Description: "add bounded pending Ask admission and retry policy",
		Objects: []string{
			"relay_v2_admission_guard", "relay_v2_admission_config",
		},
		Apply: func(s *Store) error { return s.initializeRelayV2AdmissionSchema() },
	},
	{
		Version:     6,
		ID:          "v2.artifact.scoped_access",
		Description: "add versioned artifact references and scoped read grants",
		Objects: []string{
			"artifact_v2_refs", "artifact_v2_grants",
		},
		Apply: func(s *Store) error { return s.initializeArtifactV2SchemaLocked() },
	},
	{
		Version:     7,
		ID:          "v2.task.shared_responsibility",
		Description: "add group shared task graph, atomic claim, result and acceptance records",
		Objects: []string{
			"shared_task_v2_guard", "shared_tasks_v2", "shared_task_v2_dependencies",
			"shared_task_v2_results", "shared_task_v2_events",
		},
		Apply: func(s *Store) error { return s.initializeSharedTaskV2Schema() },
	},
	{
		Version:     8,
		ID:          "v2.resource.authority",
		Description: "add cross-group resource authority, leases, quarantine, and fenced managed writes",
		Objects: []string{
			"resource_v2_authority", "resource_v2_leases", "resource_v2_managed_blobs",
		},
		Apply: func(s *Store) error { return s.initializeResourceLeaseV2Schema() },
	},
	{
		Version:     9,
		ID:          "v2.task.handoff",
		Description: "add structured owner handoff with atomic epoch-fenced transfer",
		Objects:     []string{"shared_task_v2_handoffs"},
		Apply:       func(s *Store) error { return s.initializeSharedTaskHandoffSchema() },
	},
	{
		Version:     10,
		ID:          "v2.task.side_effect_ledger",
		Description: "add durable epoch-fenced shared task side-effect intent and reconciliation records",
		Objects:     []string{"shared_task_v2_side_effects", "shared_task_v2_side_effect_events"},
		Apply:       func(s *Store) error { return s.initializeSharedTaskSideEffectSchema() },
	},
	{
		Version:     11,
		ID:          "v2.fabric.endpoint_group_membership",
		Description: "add independent endpoint-to-group membership without replacing native sessions",
		Objects:     []string{"endpoint_group_memberships"},
		Apply:       func(s *Store) error { return s.initializeEndpointGroupMembershipSchema() },
	},
	{
		Version:     12,
		ID:          "v2.group.hierarchy",
		Description: "add versioned parent group placement without inheriting authorization",
		Objects:     []string{"groups"},
		Apply:       func(s *Store) error { return s.initializeGroupHierarchyV2Schema() },
	},
	{
		Version:     13,
		ID:          "v2.collaboration.link_proposals",
		Description: "add scoped non-routable communication link proposals and versioned revocation",
		Objects:     []string{"communication_links_v2"},
		Apply:       func(s *Store) error { return s.initializeCommunicationLinksV2Schema() },
	},
	{
		Version:     14,
		ID:          "v2.fabric.endpoint_key_candidates",
		Description: "add self-attested Endpoint public key candidates without establishing trust",
		Objects:     []string{"endpoint_key_candidates_v2"},
		Apply:       func(s *Store) error { return s.initializeEndpointKeyCandidateSchema() },
	},
	{
		Version:     15,
		ID:          "v2.collaboration.owner_approval_keys",
		Description: "add locally bootstrapped independent owner public keys for link approvals",
		Objects:     []string{"owner_approval_keys_v2"},
		Apply:       func(s *Store) error { return s.initializeOwnerApprovalKeySchema() },
	},
	{
		Version:     16,
		ID:          "v2.collaboration.link_owner_grants",
		Description: "record bilateral post-quantum owner signatures without activating legacy plaintext routes",
		Objects:     []string{"communication_link_grants_v2"},
		Apply:       func(s *Store) error { return s.initializeCommunicationLinkGrantsV2Schema() },
	},
	{
		Version:     17,
		ID:          "v2.relay.sealed_payloads",
		Description: "store sealed relay payload bytes separately from legacy fabric message bodies",
		Objects:     []string{"relay_v2_message_payloads"},
		Apply:       func(s *Store) error { return s.initializeRelaySealedPayloadSchema() },
	},
	{
		Version:     18,
		ID:          "v2.client.device_identity_and_replay",
		Description: "add stable Hub identity, owner-authorized Client devices, and durable request replay state",
		Objects: []string{
			"client_device_hub_config_v2", "client_devices_v2",
			"client_device_grant_nonces_v2", "client_device_requests_v2",
		},
		Apply: func(s *Store) error { return s.initializeClientDevicesV2Schema() },
	},
	{
		Version:     19,
		ID:          "v2.client.control_intents",
		Description: "add durable idempotent asynchronous Client Control intent acceptance and recovery state",
		Objects:     []string{"client_control_intents_v2"},
		Apply:       func(s *Store) error { return s.initializeClientControlIntentsV2Schema() },
	},
	{
		Version:     20,
		ID:          "v2.node.owner_device_code_bindings",
		Description: "add expiring single-use Node device codes and owner-authorized revocable credential bindings",
		Objects: []string{
			"node_device_binding_requests_v2", "node_owner_bindings_v2",
		},
		Apply: func(s *Store) error { return s.initializeNodeDeviceBindingV2Schema() },
	},
	{
		Version:     21,
		ID:          "v2.client.status_change_feed",
		Description: "add owner-scoped snapshot-derived Client status changes and durable cursor state",
		Objects: []string{
			"client_status_state_v2", "client_status_streams_v2", "client_status_change_events_v2",
		},
		Apply: func(s *Store) error { return s.initializeClientStatusEventsV2Schema() },
	},
	{
		Version:     22,
		ID:          "v2.collaboration.key_bound_owner_grants",
		Description: "record owner signatures over both current Endpoint key candidates without enabling routes",
		Objects:     []string{"communication_link_key_grants_v2"},
		Apply:       func(s *Store) error { return s.initializeCommunicationLinkKeyGrantsV2Schema() },
	},
	{
		Version:     23,
		ID:          "v2.node.owner_scoped_worker_jobs",
		Description: "attribute Client-created Goals and accepted intents to their authenticated owner for scoped Node jobs",
		Objects: []string{
			"machines", "goals", "client_control_intents_v2",
		},
		Apply: func(s *Store) error { return s.initializeOwnerScopedNodeJobsV2Schema() },
	},
	{
		Version:     24,
		ID:          "v2.client.goal_lifecycle",
		Description: "version owner-scoped Goal lifecycle transitions for queued Node work",
		Objects:     []string{"goals"},
		Apply:       func(s *Store) error { return s.initializeClientGoalLifecycleSchema() },
	},
	{
		Version:     25,
		ID:          "v2.client.status_approval_intent_deltas",
		Description: "extend owner-bound status delta entity types for approval and intent metadata",
		Objects:     []string{"client_status_state_v2", "client_status_change_events_v2"},
		Apply:       func(s *Store) error { return s.expandClientStatusEventsEntityTypes() },
	},
	{
		Version:     26,
		ID:          "v2.collaboration.external_thread_invites",
		Description: "add one-time owner-scoped external Thread invitation storage without activating routes",
		Objects:     []string{"external_thread_invites_v2"},
		Apply:       func(s *Store) error { return s.initializeExternalThreadInvitesV2Schema() },
	},
	{
		Version:     27,
		ID:          "v2.collaboration.group_endpoint_key_grants",
		Description: "record same-owner Group-scoped consent for current Endpoint public key candidates",
		Objects:     []string{"group_endpoint_key_grants_v2"},
		Apply:       func(s *Store) error { return s.initializeGroupEndpointKeyGrantsV2Schema() },
	},
	{
		Version:     28,
		ID:          "v2.fabric.group_broadcast_snapshots",
		Description: "persist immutable, owner-scoped Group broadcast recipient snapshots",
		Objects: []string{
			"group_broadcast_v2_snapshots", "group_broadcast_v2_snapshot_recipients",
		},
		Apply: func(s *Store) error { return s.initializeGroupBroadcastV2Schema() },
	},
	{
		Version:     29,
		ID:          "v2.client.request_recovery",
		Description: "persist exact Client RPC response reservations and sealed uncertainty notices",
		Objects:     []string{"client_device_request_recovery_v2"},
		Apply:       func(s *Store) error { return s.initializeClientRequestRecoveryV2Schema() },
	},
	{
		Version:     30,
		ID:          "v2.node.worker_approval_bridge",
		Description: "add attempt-fenced remote Node Worker approval request identity",
		Objects:     []string{"approvals"},
		Apply:       func(s *Store) error { return s.initializeRemoteWorkerApprovalsV2Schema() },
	},
}

// legacyInventoryColumns selects stable columns from the pre-v2 authority
// tables.  Columns added by a v2 migration are deliberately absent, and the
// compatibility backfills in Store.initialize have completed before this
// inventory is captured.
var legacyInventoryColumns = map[string][]string{
	"machines": {
		"id", "name", "status", "capabilities_json", "last_seen", "created_at",
	},
	"goals": {
		"id", "parent_goal_id", "objective", "success_criteria", "constraints", "priority",
		"deadline", "budget_json", "resources_json", "current_state", "evidence_json", "outcome",
		"status", "machine_id", "monitor_id", "workspace", "summary", "created_at", "updated_at",
	},
	"workers": {
		"id", "goal_id", "machine_id", "harness", "status", "pid", "thread_id", "attempt",
		"started_at", "ended_at", "last_error", "summary", "prompt", "response_file", "workspace",
		"created_at", "updated_at",
	},
	"events": {
		"id", "goal_id", "worker_id", "type", "payload_json", "created_at",
	},
	"commands": {
		"id", "goal_id", "worker_id", "command", "status", "created_at", "consumed_at",
	},
	"approvals": {
		"id", "goal_id", "worker_id", "method", "request_json", "status", "decision",
		"created_at", "resolved_at",
	},
	"permissions": {
		"id", "subject_type", "subject_id", "action", "resource", "effect", "created_at", "updated_at",
	},
	"ideas": {
		"id", "title", "description", "source", "status", "rationale", "revisit_when", "goal_id",
		"created_at", "updated_at",
	},
	"intents": {
		"id", "text", "requested_kind", "resolved_kind", "status", "target_id", "attachments_json",
		"result_json", "question", "error", "created_at", "updated_at",
	},
	"attachments": {
		"id", "name", "mime_type", "source_url", "path", "size", "created_at",
	},
	"workspaces": {
		"id", "goal_id", "path", "source", "revision", "snapshot_digest", "status", "created_at", "updated_at",
	},
	"memories": {
		"id", "scope", "namespace", "content", "source", "importance", "created_at", "updated_at",
	},
	"artifacts": {
		"id", "goal_id", "worker_id", "workspace_id", "name", "path", "kind", "digest", "evidence", "status", "created_at",
	},
	"contacts": {
		"id", "remote_id", "label", "identity_json", "status", "send_sequence", "received_sequences_json", "created_at", "updated_at",
	},
	"peer_sessions": {
		"contact_id", "epoch", "root_key", "send_chain_key", "receive_chain_key", "send_count", "receive_count", "pending_offer", "status", "created_at", "updated_at",
	},
	"contact_discovery_requests": {
		"id", "remote_id", "label", "identity_json", "announcement_json", "status", "contact_id", "created_at", "updated_at",
	},
	"directory_records": {
		"id", "remote_id", "label", "identity_json", "endpoints_json", "announcement_json", "expires_at", "status", "created_at", "updated_at",
	},
	"peer_messages": {
		"id", "transport_id", "contact_id", "direction", "sender_id", "recipient_id", "sequence", "envelope_json", "aad", "status", "created_at", "delivered_at",
	},
	"notifications": {
		"id", "kind", "priority", "title", "body", "goal_id", "status", "created_at", "read_at",
	},
	"push_subscriptions": {
		"id", "endpoint", "p256dh", "auth", "user_agent", "last_error", "created_at", "updated_at",
	},
	"external_events": {
		"id", "connector", "external_id", "event_type", "payload_json", "signature", "status", "goal_id", "created_at", "updated_at",
	},
	"external_actions": {
		"id", "goal_id", "worker_id", "kind", "method", "url", "domain", "payload_json", "status", "approval_id", "result_json", "error", "created_at", "updated_at", "started_at", "completed_at",
	},
	"thread_sessions": {
		"id", "thread_id", "label", "workspace", "status", "created_at", "updated_at",
	},
	"thread_deliveries": {
		"id", "from_thread_id", "to_thread_id", "message", "status", "error", "created_at", "delivered_at",
	},
	"fabric_endpoints": {
		"id", "name", "role", "harness", "native_session_id", "machine_id", "workspace", "goal_id", "status", "capabilities_json", "tags_json", "owner", "visibility", "joined_at", "last_seen", "created_at", "updated_at",
	},
	"fabric_messages": {
		"id", "request_id", "reply_to", "from_endpoint_id", "to_endpoint_id", "kind", "body", "metadata_json", "status", "error", "created_at", "delivered_at", "replied_at",
	},
	"fabric_events": {
		"id", "endpoint_id", "type", "payload_json", "created_at",
	},
}

func v2MigrationChecksum(m v2Migration) string {
	// Keep a schema definition marker in the checksum input.  If a future
	// change modifies a migration's SQL contract, it must either update this
	// marker or use a new migration ID/version; an applied row then fails closed
	// instead of silently accepting a different definition.
	sum := sha256.Sum256([]byte(fmt.Sprintf("cicada-v2-schema-1\x00%d\x00%s\x00%s", m.Version, m.ID, m.Description)))
	return hex.EncodeToString(sum[:])
}

func (s *Store) initializeV2Migrations() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := configureV2BusyTimeout(s.db); err != nil {
		return err
	}
	if err := beginV2Transaction(s.db); err != nil {
		return fmt.Errorf("lock v2 migration ledger: %w", err)
	}
	baseTransactionOpen := true
	defer func() {
		if baseTransactionOpen {
			_, _ = s.db.Exec("ROLLBACK")
		}
	}()
	if err := ensureV2MigrationLedger(s.db); err != nil {
		return err
	}
	var highest sql.NullInt64
	if err := s.db.QueryRow(`SELECT max(version) FROM schema_migrations_v2`).Scan(&highest); err != nil {
		return fmt.Errorf("read v2 schema version: %w", err)
	}
	if highest.Valid && highest.Int64 > CurrentV2SchemaVersion {
		return fmt.Errorf("database v2 schema version %d is newer than this binary supports (max %d)", highest.Int64, CurrentV2SchemaVersion)
	}
	allApplied := true
	for _, migration := range v2Migrations {
		entry, err := s.readV2Migration(migration.Version)
		if err != nil {
			return err
		}
		if entry == nil {
			allApplied = false
			continue
		}
		if entry.MigrationID != migration.ID || entry.Checksum != v2MigrationChecksum(migration) || entry.Description != migration.Description {
			return fmt.Errorf("v2 migration ledger definition mismatch for version %d (%s)", migration.Version, migration.ID)
		}
		if entry.State != v2MigrationApplied {
			allApplied = false
		}
	}
	if allApplied {
		// Normal startup only checks the ledger, schema objects, and SQLite
		// integrity.  It does not scan legacy message bodies, keys, or other
		// large tables after the one-time upgrade has completed.
		for _, migration := range v2Migrations {
			if err := s.verifyV2Migration(migration, nil); err != nil {
				return fmt.Errorf("verify applied v2 migration %s: %w", migration.ID, err)
			}
		}
		if _, err := s.db.Exec("COMMIT"); err != nil {
			return fmt.Errorf("commit v2 ledger verification: %w", err)
		}
		baseTransactionOpen = false
		return nil
	}
	if _, err := s.db.Exec("COMMIT"); err != nil {
		return fmt.Errorf("commit v2 ledger inspection: %w", err)
	}
	baseTransactionOpen = false

	inventory, err := snapshotLegacyInventory(s.db)
	if err != nil {
		return fmt.Errorf("snapshot legacy state before v2 migrations: %w", err)
	}
	for _, migration := range v2Migrations {
		if err := s.applyV2Migration(migration, inventory); err != nil {
			return err
		}
	}
	return nil
}

func ensureV2MigrationLedger(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS schema_migrations_v2 (
  version INTEGER PRIMARY KEY,
  migration_id TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL,
  checksum TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('running', 'applied', 'failed')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  source_count INTEGER NOT NULL DEFAULT 0,
  target_count INTEGER NOT NULL DEFAULT 0,
  verification_json TEXT NOT NULL DEFAULT '{}',
  started_at TEXT NOT NULL DEFAULT '',
  applied_at TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS schema_migrations_v2_state_idx
  ON schema_migrations_v2(state, version);
`)
	if err != nil {
		return fmt.Errorf("initialize v2 migration ledger: %w", err)
	}
	return nil
}

func configureV2BusyTimeout(db *sql.DB) error {
	if _, err := db.Exec(`PRAGMA busy_timeout = 30000`); err != nil {
		return fmt.Errorf("configure v2 sqlite busy timeout: %w", err)
	}
	return nil
}

func beginV2Transaction(db *sql.DB) error {
	if _, err := db.Exec(`BEGIN IMMEDIATE`); err != nil {
		return err
	}
	return nil
}

func (s *Store) readV2Migration(version int) (*v2MigrationLedgerEntry, error) {
	var entry v2MigrationLedgerEntry
	err := s.db.QueryRow(`SELECT version, migration_id, description, checksum, state,
attempts, source_count, target_count, verification_json, started_at, applied_at,
last_error, created_at, updated_at
FROM schema_migrations_v2 WHERE version = ?`, version).Scan(
		&entry.Version, &entry.MigrationID, &entry.Description, &entry.Checksum, &entry.State,
		&entry.Attempts, &entry.SourceCount, &entry.TargetCount, &entry.VerificationJSON,
		&entry.StartedAt, &entry.AppliedAt, &entry.LastError, &entry.CreatedAt, &entry.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read v2 migration ledger version %d: %w", version, err)
	}
	return &entry, nil
}

func (s *Store) applyV2Migration(migration v2Migration, inventory map[string]legacyInventory) error {
	checksum := v2MigrationChecksum(migration)
	if err := beginV2Transaction(s.db); err != nil {
		return fmt.Errorf("start v2 migration %s: %w", migration.ID, err)
	}
	transactionOpen := true
	defer func() {
		if transactionOpen {
			_, _ = s.db.Exec("ROLLBACK")
		}
	}()
	entry, err := s.readV2Migration(migration.Version)
	if err != nil {
		return s.finishV2MigrationFailure(migration, "", err, &transactionOpen)
	}
	if entry != nil {
		if entry.MigrationID != migration.ID || entry.Checksum != checksum || entry.Description != migration.Description {
			return s.finishV2MigrationFailure(migration, "", fmt.Errorf("v2 migration ledger definition mismatch for version %d (%s)", migration.Version, migration.ID), &transactionOpen)
		}
		if entry.State == v2MigrationApplied {
			if err := s.verifyV2Migration(migration, nil); err != nil {
				return s.finishV2MigrationFailure(migration, "", fmt.Errorf("verify applied v2 migration %s: %w", migration.ID, err), &transactionOpen)
			}
			if _, err := s.db.Exec("COMMIT"); err != nil {
				return fmt.Errorf("commit applied v2 migration %s verification: %w", migration.ID, err)
			}
			transactionOpen = false
			return nil
		}
	}

	savepoint := fmt.Sprintf("cicada_v2_migration_%d", migration.Version)
	if _, err := s.db.Exec("SAVEPOINT " + quoteSQLiteIdentifier(savepoint)); err != nil {
		return s.finishV2MigrationFailure(migration, "", fmt.Errorf("start savepoint: %w", err), &transactionOpen)
	}

	started := now()
	sourceCount, sourceDigest := legacyInventorySummary(inventory)
	verificationJSON := migrationVerificationJSON(migration, sourceCount, sourceDigest)
	if _, err := s.db.Exec(`
INSERT INTO schema_migrations_v2
 (version, migration_id, description, checksum, state, attempts, source_count,
  target_count, verification_json, started_at, applied_at, last_error, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 1, ?, 0, ?, ?, '', '', ?, ?)
ON CONFLICT(version) DO UPDATE SET
 migration_id = excluded.migration_id,
 description = excluded.description,
 checksum = excluded.checksum,
 state = excluded.state,
 attempts = schema_migrations_v2.attempts + 1,
 source_count = excluded.source_count,
 target_count = 0,
 verification_json = excluded.verification_json,
 started_at = excluded.started_at,
 applied_at = '',
 last_error = '',
 updated_at = excluded.updated_at`,
		migration.Version, migration.ID, migration.Description, checksum, v2MigrationRunning,
		sourceCount, verificationJSON, started, started, started); err != nil {
		return s.finishV2MigrationFailure(migration, savepoint, fmt.Errorf("record start: %w", err), &transactionOpen)
	}

	if err := s.callMigrationHook(migration.ID, "before_apply"); err != nil {
		return s.finishV2MigrationFailure(migration, savepoint, err, &transactionOpen)
	}
	if err := migration.Apply(s); err != nil {
		return s.finishV2MigrationFailure(migration, savepoint, fmt.Errorf("apply: %w", err), &transactionOpen)
	}
	if err := s.verifyV2Migration(migration, inventory); err != nil {
		return s.finishV2MigrationFailure(migration, savepoint, fmt.Errorf("verify: %w", err), &transactionOpen)
	}
	if err := s.callMigrationHook(migration.ID, "after_apply"); err != nil {
		return s.finishV2MigrationFailure(migration, savepoint, err, &transactionOpen)
	}

	updated := now()
	if _, err := s.db.Exec(`UPDATE schema_migrations_v2
SET state = ?, target_count = ?, verification_json = ?, applied_at = ?, last_error = '', updated_at = ?
WHERE version = ?`, v2MigrationApplied, sourceCount, verificationJSON, updated, updated, migration.Version); err != nil {
		return s.finishV2MigrationFailure(migration, savepoint, fmt.Errorf("record applied: %w", err), &transactionOpen)
	}
	if err := s.callMigrationHook(migration.ID, "before_commit"); err != nil {
		return s.finishV2MigrationFailure(migration, savepoint, err, &transactionOpen)
	}
	if _, err := s.db.Exec("RELEASE SAVEPOINT " + quoteSQLiteIdentifier(savepoint)); err != nil {
		return s.finishV2MigrationFailure(migration, "", fmt.Errorf("release savepoint: %w", err), &transactionOpen)
	}
	if _, err := s.db.Exec("COMMIT"); err != nil {
		return s.finishV2MigrationFailure(migration, "", fmt.Errorf("commit: %w", err), &transactionOpen)
	}
	transactionOpen = false
	return nil
}

func (s *Store) callMigrationHook(migrationID, phase string) error {
	if s.migrationHook == nil {
		return nil
	}
	if err := s.migrationHook(migrationID, phase); err != nil {
		return fmt.Errorf("injected v2 migration failure at %s/%s: %w", migrationID, phase, err)
	}
	return nil
}

func (s *Store) finishV2MigrationFailure(migration v2Migration, savepoint string, cause error, transactionOpen *bool) error {
	rollbackErr := error(nil)
	if savepoint != "" {
		if _, err := s.db.Exec("ROLLBACK TO SAVEPOINT " + quoteSQLiteIdentifier(savepoint)); err != nil {
			rollbackErr = fmt.Errorf("rollback savepoint: %w", err)
		}
		if _, err := s.db.Exec("RELEASE SAVEPOINT " + quoteSQLiteIdentifier(savepoint)); err != nil && rollbackErr == nil {
			rollbackErr = fmt.Errorf("release savepoint: %w", err)
		}
	}
	if _, err := s.db.Exec("ROLLBACK"); err != nil && rollbackErr == nil {
		rollbackErr = fmt.Errorf("rollback transaction: %w", err)
	}
	if transactionOpen != nil {
		*transactionOpen = false
	}
	if rollbackErr != nil {
		cause = fmt.Errorf("%w; %v", cause, rollbackErr)
	}
	if err := s.recordV2MigrationFailure(migration, cause); err != nil {
		return fmt.Errorf("%w; record migration failure: %v", cause, err)
	}
	return fmt.Errorf("v2 migration %s failed: %w", migration.ID, cause)
}

func (s *Store) recordV2MigrationFailure(migration v2Migration, cause error) error {
	if err := beginV2Transaction(s.db); err != nil {
		return err
	}
	transactionOpen := true
	defer func() {
		if transactionOpen {
			_, _ = s.db.Exec("ROLLBACK")
		}
	}()
	timestamp := now()
	_, err := s.db.Exec(`
INSERT INTO schema_migrations_v2
 (version, migration_id, description, checksum, state, attempts, last_error, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
ON CONFLICT(version) DO UPDATE SET
 state = excluded.state,
 attempts = schema_migrations_v2.attempts + 1,
 last_error = excluded.last_error,
 started_at = schema_migrations_v2.started_at,
 applied_at = '',
 updated_at = excluded.updated_at`,
		migration.Version, migration.ID, migration.Description, v2MigrationChecksum(migration),
		v2MigrationFailed, cause.Error(), timestamp, timestamp)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec("COMMIT"); err != nil {
		return err
	}
	transactionOpen = false
	return err
}

func (s *Store) verifyV2Migration(migration v2Migration, inventory map[string]legacyInventory) error {
	for _, object := range migration.Objects {
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, object).Scan(&count); err != nil {
			return fmt.Errorf("inspect object %s: %w", object, err)
		}
		if count != 1 {
			return fmt.Errorf("migration object %s is missing", object)
		}
	}
	if migration.ID == "v2.group.hierarchy" {
		columns, err := existingColumns(s.db, "groups", []string{"parent_group_id"})
		if err != nil {
			return err
		}
		if len(columns) != 1 {
			return errors.New("group hierarchy parent column is missing")
		}
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'groups_parent_idx'`).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return errors.New("group hierarchy index is missing")
		}
	}
	if migration.ID == "v2.node.owner_scoped_worker_jobs" {
		for table, column := range map[string]string{
			"machines":                  "owner_id",
			"goals":                     "owner_id",
			"client_control_intents_v2": "owner_id",
		} {
			columns, err := existingColumns(s.db, table, []string{column})
			if err != nil {
				return err
			}
			if len(columns) != 1 {
				return fmt.Errorf("owner-scoped Node jobs migration is missing %s.%s", table, column)
			}
		}
		for _, index := range []string{"goals_owner_status_idx", "client_control_intents_v2_owner_state_idx"} {
			var count int
			if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?`, index).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("owner-scoped Node jobs migration is missing index %s", index)
			}
		}
	}
	if migration.ID == "v2.client.goal_lifecycle" {
		columns, err := existingColumns(s.db, "goals", []string{"lifecycle_version"})
		if err != nil {
			return err
		}
		if len(columns) != 1 {
			return errors.New("Client Goal lifecycle version column is missing")
		}
	}
	if migration.ID == "v2.client.status_approval_intent_deltas" {
		for _, table := range []string{"client_status_state_v2", "client_status_change_events_v2"} {
			var schema string
			if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&schema); err != nil {
				return err
			}
			if !strings.Contains(schema, "'approval'") || !strings.Contains(schema, "'intent'") {
				return fmt.Errorf("Client status table %s is missing approval or intent entity support", table)
			}
		}
	}
	if migration.ID == "v2.node.worker_approval_bridge" {
		columns, err := existingColumns(s.db, "approvals", []string{
			"source_node_id", "worker_attempt", "request_id", "request_hash",
		})
		if err != nil {
			return err
		}
		if len(columns) != 4 {
			return errors.New("remote Node approval migration is missing required attempt fields")
		}
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='approvals_remote_request_idem_idx'`).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return errors.New("remote Node approval migration is missing idempotency index")
		}
	}
	if migration.ID == "v2.collaboration.external_thread_invites" {
		columns, err := existingColumns(s.db, "external_thread_invites_v2", []string{
			"invite_id", "token_digest", "source_endpoint_id", "source_group_id",
			"source_owner_id", "source_principal_id", "source_node_id", "source_membership_revision",
			"source_join_revision", "source_group_version", "hub_id", "direction", "actions_json",
			"data_scopes_json", "expires_at", "state", "target_owner_id", "target_endpoint_id",
			"target_group_id", "communication_link_id", "created_at", "accepted_at",
		})
		if err != nil {
			return err
		}
		if len(columns) != 22 {
			return errors.New("external Thread invite table is missing required columns")
		}
		for _, indexName := range []string{"external_thread_invites_v2_digest_idx", "external_thread_invites_v2_link_idx"} {
			var indexCount int
			if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?`, indexName).Scan(&indexCount); err != nil {
				return err
			}
			if indexCount != 1 {
				return fmt.Errorf("external Thread invite index %s is missing", indexName)
			}
		}
	}
	if err := verifySQLiteIntegrity(s.db); err != nil {
		return err
	}
	if inventory != nil {
		current, err := snapshotLegacyInventory(s.db)
		if err != nil {
			return err
		}
		if err := compareLegacyInventory(inventory, current); err != nil {
			return err
		}
	}
	return nil
}

func verifySQLiteIntegrity(db *sql.DB) error {
	var result string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil {
		return fmt.Errorf("run sqlite integrity_check: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(result)) != "ok" {
		return fmt.Errorf("sqlite integrity_check returned %q", result)
	}
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("run sqlite foreign_key_check: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var table, rowID, parent, foreignKey any
		if err := rows.Scan(&table, &rowID, &parent, &foreignKey); err != nil {
			return fmt.Errorf("read sqlite foreign_key_check: %w", err)
		}
		return fmt.Errorf("sqlite foreign_key_check found table=%v row=%v parent=%v fk=%v", table, rowID, parent, foreignKey)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read sqlite foreign_key_check: %w", err)
	}
	return nil
}

func snapshotLegacyInventory(db *sql.DB) (map[string]legacyInventory, error) {
	inventory := make(map[string]legacyInventory, len(legacyInventoryColumns))
	tables := make([]string, 0, len(legacyInventoryColumns))
	for table := range legacyInventoryColumns {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, table := range tables {
		columns, err := existingColumns(db, table, legacyInventoryColumns[table])
		if err != nil {
			return nil, err
		}
		if len(columns) == 0 {
			inventory[table] = legacyInventory{}
			continue
		}
		quotedColumns := make([]string, len(columns))
		for i, column := range columns {
			quotedColumns[i] = quoteSQLiteIdentifier(column)
		}
		query := fmt.Sprintf("SELECT %s FROM %s ORDER BY rowid", strings.Join(quotedColumns, ", "), quoteSQLiteIdentifier(table))
		rows, err := db.Query(query)
		if err != nil {
			return nil, fmt.Errorf("snapshot legacy table %s: %w", table, err)
		}
		var encodedRows []string
		for rows.Next() {
			values := make([]any, len(columns))
			destinations := make([]any, len(values))
			for i := range values {
				destinations[i] = &values[i]
			}
			if err := rows.Scan(destinations...); err != nil {
				rows.Close()
				return nil, fmt.Errorf("read legacy table %s: %w", table, err)
			}
			parts := make([]string, len(values))
			for i, value := range values {
				parts[i] = stableSQLiteValue(value)
			}
			encodedRows = append(encodedRows, strings.Join(parts, "\x1f"))
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("read legacy table %s: %w", table, err)
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("close legacy table %s: %w", table, err)
		}
		sort.Strings(encodedRows)
		digest := sha256.Sum256([]byte(strings.Join(encodedRows, "\n")))
		inventory[table] = legacyInventory{Count: int64(len(encodedRows)), Digest: hex.EncodeToString(digest[:])}
	}
	return inventory, nil
}

func existingColumns(db *sql.DB, table string, wanted []string) ([]string, error) {
	rows, err := db.Query("PRAGMA table_info(" + quoteSQLiteIdentifier(table) + ")")
	if err != nil {
		return nil, fmt.Errorf("inspect legacy table %s: %w", table, err)
	}
	defer rows.Close()
	available := make(map[string]struct{})
	for rows.Next() {
		var cid, notNull, pk int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
			return nil, fmt.Errorf("read legacy table %s schema: %w", table, err)
		}
		available[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read legacy table %s schema: %w", table, err)
	}
	columns := make([]string, 0, len(wanted))
	for _, column := range wanted {
		if _, ok := available[column]; ok {
			columns = append(columns, column)
		}
	}
	return columns, nil
}

func stableSQLiteValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case []byte:
		return "blob:" + hex.EncodeToString(typed)
	case string:
		return "text:" + typed
	case int64:
		return fmt.Sprintf("int:%d", typed)
	case float64:
		return fmt.Sprintf("float:%g", typed)
	case bool:
		if typed {
			return "bool:true"
		}
		return "bool:false"
	default:
		return fmt.Sprintf("%T:%v", value, value)
	}
}

func compareLegacyInventory(expected, current map[string]legacyInventory) error {
	if len(expected) != len(current) {
		return fmt.Errorf("legacy inventory table count changed: before=%d after=%d", len(expected), len(current))
	}
	for table, before := range expected {
		after, ok := current[table]
		if !ok {
			return fmt.Errorf("legacy inventory table %s disappeared", table)
		}
		if before.Count != after.Count || before.Digest != after.Digest {
			return fmt.Errorf("legacy inventory changed for %s: before count=%d digest=%s after count=%d digest=%s", table, before.Count, before.Digest, after.Count, after.Digest)
		}
	}
	return nil
}

func legacyInventorySummary(inventory map[string]legacyInventory) (int64, string) {
	tables := make([]string, 0, len(inventory))
	for table := range inventory {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	var total int64
	var builder strings.Builder
	for _, table := range tables {
		item := inventory[table]
		total += item.Count
		fmt.Fprintf(&builder, "%s:%d:%s\n", table, item.Count, item.Digest)
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return total, hex.EncodeToString(sum[:])
}

func migrationVerificationJSON(migration v2Migration, legacyCount int64, legacyDigest string) string {
	payload := map[string]any{
		"legacy_count":  legacyCount,
		"legacy_digest": legacyDigest,
		"objects":       migration.Objects,
		"integrity":     "ok",
		"foreign_keys":  "ok",
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func quoteSQLiteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}
