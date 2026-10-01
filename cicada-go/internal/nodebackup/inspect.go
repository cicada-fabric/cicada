package nodebackup

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/cicada-ai/cicada/internal/nodelock"
)

const recoveryPendingReason = "reconcile Node binding epochs, crypto counters, and uncertain native delivery before startup"

// RecoveryInspectReport contains bounded local metadata only. It never includes
// message bodies, ciphertext, keys, credentials, or user supplied diagnostics.
// Hub authorization, remote crypto watermarks, and native consumption are not
// checked by this offline command.
type RecoveryInspectReport struct {
	NodeID                 string                  `json:"node_id"`
	BackupManifestSHA256   string                  `json:"backup_manifest_sha256"`
	QuarantineStatus       string                  `json:"quarantine_status"`
	AgentMayStart          bool                    `json:"agent_may_start"`
	CheckedFiles           int                     `json:"checked_files"`
	CheckedDirectories     int                     `json:"checked_directories"`
	CheckedDatabases       int                     `json:"checked_databases"`
	CryptoState            CryptoStateInspection   `json:"crypto_state"`
	RelayInbox             NodeInboxInspection     `json:"relay_inbox"`
	LocalInbox             NodeInboxInspection     `json:"local_inbox"`
	LocalMessages          LocalMessagesInspection `json:"local_messages"`
	HubBindingCheck        string                  `json:"hub_binding_check"`
	CryptoCounterWatermark string                  `json:"crypto_counter_watermark"`
	NativeRuntimeCheck     string                  `json:"native_runtime_check"`
	ExternalMCPState       string                  `json:"external_mcp_state"`
	SharedWriterRootCheck  string                  `json:"shared_writer_root_check,omitempty"`
	SharedWriterRootHeld   bool                    `json:"shared_writer_root_held,omitempty"`
}

type CryptoStateInspection struct {
	Present              bool   `json:"present"`
	SchemaVersion        int    `json:"schema_version,omitempty"`
	SequenceStreams      int64  `json:"sequence_streams,omitempty"`
	HighestLocalSequence int64  `json:"highest_local_sequence,omitempty"`
	OutboxRecords        int64  `json:"outbox_records,omitempty"`
	ReplayRecords        int64  `json:"replay_records,omitempty"`
	InboxAvailable       bool   `json:"inbox_available"`
	InboxRecords         int64  `json:"inbox_records,omitempty"`
	Integrity            string `json:"integrity,omitempty"`
}

type NodeInboxInspection struct {
	Present                     bool             `json:"present"`
	DeliveriesByState           map[string]int64 `json:"deliveries_by_state,omitempty"`
	AttemptsByState             map[string]int64 `json:"attempts_by_state,omitempty"`
	PendingInjectionDeliveries  int64            `json:"pending_injection_deliveries,omitempty"`
	UnresolvedInjectionAttempts int64            `json:"unresolved_injection_attempts,omitempty"`
	Integrity                   string           `json:"integrity,omitempty"`
}

type LocalMessagesInspection struct {
	Present         bool             `json:"present"`
	SchemaVersion   int              `json:"schema_version,omitempty"`
	MessagesByState map[string]int64 `json:"messages_by_state,omitempty"`
	RequestsByState map[string]int64 `json:"requests_by_state,omitempty"`
	Integrity       string           `json:"integrity,omitempty"`
}

// Inspect verifies an offline backup and its restored, quarantined Node tree.
// The exclusive maintenance lock makes the byte and SQLite checks stable. All
// database handles use immutable read-only SQLite connections; this function
// never opens the Agent, creates state, runs migrations, or modifies the
// recovery marker.
func Inspect(backupDir, targetStateDir string) (_ *RecoveryInspectReport, retErr error) {
	manifest, err := Verify(backupDir)
	if err != nil {
		return nil, fmt.Errorf("verify Node recovery backup: %w", err)
	}
	stateRoot, err := canonicalPath(targetStateDir)
	if err != nil {
		return nil, err
	}
	nodeDir := nodeStatePath(stateRoot, manifest.NodeID)
	if err := verifyNodeStateDirectory(stateRoot, nodeDir); err != nil {
		return nil, err
	}
	lock, err := nodelock.AcquireMaintenanceExclusive(stateRoot, manifest.NodeID)
	if err != nil {
		if errors.Is(err, nodelock.ErrBusy) {
			return nil, fmt.Errorf("Node %q is busy: %w", manifest.NodeID, err)
		}
		return nil, fmt.Errorf("acquire exclusive Node recovery-inspection lock: %w", err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release Node recovery-inspection lock: %w", closeErr))
		}
	}()
	verifiedManifest, err := Verify(backupDir)
	if err != nil || digestManifest(*verifiedManifest) != digestManifest(*manifest) {
		return nil, fmt.Errorf("Node recovery backup changed during inspection: %w", ErrBackupInvalid)
	}
	manifest = verifiedManifest
	if err := verifyNodeStateDirectory(stateRoot, nodeDir); err != nil {
		return nil, err
	}
	if err := verifyRecoveryMarker(filepath.Join(nodeDir, recoveryMarker), manifest); err != nil {
		return nil, err
	}
	checkedFiles, checkedDirectories, err := verifyRestoredTree(nodeDir, manifest)
	if err != nil {
		return nil, err
	}
	for _, database := range manifest.Databases {
		info, err := checkSQLite(filepath.Join(nodeDir, filepath.FromSlash(database.Path)))
		if err != nil || info.integrity != "ok" {
			return nil, fmt.Errorf("restored Node database integrity check failed: %w", ErrBackupInvalid)
		}
	}

	report := &RecoveryInspectReport{
		NodeID:                 manifest.NodeID,
		BackupManifestSHA256:   digestManifest(*manifest),
		QuarantineStatus:       "pending",
		AgentMayStart:          false,
		CheckedFiles:           checkedFiles,
		CheckedDirectories:     checkedDirectories,
		CheckedDatabases:       len(manifest.Databases),
		HubBindingCheck:        "not_checked_offline",
		CryptoCounterWatermark: "local_only_not_reconciled",
		NativeRuntimeCheck:     "not_checked",
		ExternalMCPState:       "outside_node_backup",
	}
	if err := validateKnownDatabaseLayout(manifest); err != nil {
		return nil, err
	}
	if hasManifestDatabase(manifest, "node-crypto-state.sqlite") {
		report.CryptoState, err = inspectCryptoState(filepath.Join(nodeDir, "node-crypto-state.sqlite"))
		if err != nil {
			return nil, fmt.Errorf("inspect local Node crypto metadata: %w", err)
		}
	} else {
		report.CryptoState = CryptoStateInspection{Present: false, InboxAvailable: false}
	}
	if hasManifestDatabase(manifest, "inbox.sqlite") {
		report.RelayInbox, err = inspectNodeInbox(filepath.Join(nodeDir, "inbox.sqlite"))
		if err != nil {
			return nil, fmt.Errorf("inspect Node Relay inbox metadata: %w", err)
		}
	} else {
		report.RelayInbox = emptyNodeInboxInspection()
	}
	if hasManifestDatabase(manifest, "local-inbox.sqlite3") {
		report.LocalInbox, err = inspectNodeInbox(filepath.Join(nodeDir, "local-inbox.sqlite3"))
		if err != nil {
			return nil, fmt.Errorf("inspect Node local inbox metadata: %w", err)
		}
	} else {
		report.LocalInbox = emptyNodeInboxInspection()
	}
	if hasManifestDatabase(manifest, "local-messages.sqlite3") {
		report.LocalMessages, err = inspectLocalMessages(filepath.Join(nodeDir, "local-messages.sqlite3"))
		if err != nil {
			return nil, fmt.Errorf("inspect Node local message metadata: %w", err)
		}
	} else {
		report.LocalMessages = LocalMessagesInspection{Present: false}
	}
	return report, nil
}

// InspectWithWriterRoot also takes the shared-root coordination lock and
// reports whether the archived fences match the restored common WriterRoot.
// It never clears either Node or WriterRoot quarantine markers.
func InspectWithWriterRoot(backupDir, targetStateDir, writerRoot string) (*RecoveryInspectReport, error) {
	lock, err := nodelock.AcquireWriterRoot(writerRoot)
	if err != nil {
		return nil, fmt.Errorf("acquire shared WriterRoot inspection lock: %w", err)
	}
	defer lock.Close()
	report, err := Inspect(backupDir, targetStateDir)
	if err != nil {
		return nil, err
	}
	manifest, err := Verify(backupDir)
	if err != nil {
		return nil, err
	}
	active, markerErr := WriterRootRecoveryQuarantineActive(writerRoot)
	if markerErr != nil {
		return nil, markerErr
	}
	if active {
		report.SharedWriterRootHeld = true
		report.SharedWriterRootCheck = "quarantined_pending_manual_reconciliation"
		return report, nil
	}
	if manifest.FormatVersion != CurrentFormatVersion || manifest.SharedWriterRoot == nil {
		report.SharedWriterRootHeld = true
		report.SharedWriterRootCheck = "legacy_archive_missing_shared_fences"
		return report, nil
	}
	if err := sharedRootMatchesManifest(writerRoot, manifest.SharedWriterRoot); err != nil {
		report.SharedWriterRootHeld = true
		report.SharedWriterRootCheck = "shared_fence_mismatch_or_missing"
		return report, nil
	}
	report.SharedWriterRootCheck = "matches_archive_bundle_but_reconciliation_required"
	return report, nil
}

func verifyRecoveryMarker(path string, manifest *Manifest) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != privateFileMode.Perm() {
		return fmt.Errorf("Node recovery marker is missing or invalid: %w", ErrBackupInvalid)
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 16*1024 {
		return fmt.Errorf("Node recovery marker is unreadable or invalid: %w", ErrBackupInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var marker recoveryPendingManifest
	if err := decoder.Decode(&marker); err != nil {
		return fmt.Errorf("Node recovery marker is invalid: %w", ErrBackupInvalid)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("Node recovery marker has trailing data: %w", ErrBackupInvalid)
	}
	if marker.Version != 1 || marker.NodeID != manifest.NodeID || marker.Status != "pending" ||
		marker.BackupManifestSHA256 != digestManifest(*manifest) || marker.Reason != recoveryPendingReason {
		return fmt.Errorf("Node recovery marker does not match the verified backup: %w", ErrBackupInvalid)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, marker.CreatedAt)
	if err != nil {
		return fmt.Errorf("Node recovery marker timestamp is invalid: %w", ErrBackupInvalid)
	}
	expected, err := json.MarshalIndent(recoveryPendingManifest{Version: 1, NodeID: manifest.NodeID,
		Status: "pending", BackupManifestSHA256: digestManifest(*manifest),
		CreatedAt: createdAt.UTC().Format(time.RFC3339Nano), Reason: recoveryPendingReason}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode expected Node recovery marker: %w", ErrBackupInvalid)
	}
	expected = append(expected, '\n')
	if !bytes.Equal(data, expected) {
		return fmt.Errorf("Node recovery marker is not the exact restored marker: %w", ErrBackupInvalid)
	}
	return nil
}

func verifyRestoredTree(nodeDir string, manifest *Manifest) (int, int, error) {
	rootInfo, err := os.Lstat(nodeDir)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm() != privateDirMode.Perm() {
		return 0, 0, fmt.Errorf("restored Node directory is invalid: %w", ErrBackupInvalid)
	}
	actual, err := collectTree(nodeDir, false)
	if err != nil {
		return 0, 0, fmt.Errorf("restored Node inventory is invalid: %w", ErrBackupInvalid)
	}
	actualFiles := make([]diskEntry, 0, len(actual.files))
	for _, entry := range actual.files {
		if entry.path != recoveryMarker {
			actualFiles = append(actualFiles, entry)
		}
	}
	expectedFiles := make([]FileEntry, 0, len(manifest.Files))
	for _, entry := range manifest.Files {
		if entry.Path != recoveryMarker {
			expectedFiles = append(expectedFiles, entry)
		}
	}
	if !sameStrings(actual.dirs, manifest.Directories) || len(actualFiles) != len(expectedFiles) {
		return 0, 0, fmt.Errorf("restored Node inventory differs from backup: %w", ErrBackupInvalid)
	}
	for index, actualFile := range actualFiles {
		expected := expectedFiles[index]
		if actualFile.path != expected.Path || actualFile.info.Size() != expected.Size ||
			actualFile.info.Mode().Perm() != privateFileMode.Perm() {
			return 0, 0, fmt.Errorf("restored Node inventory differs from backup: %w", ErrBackupInvalid)
		}
		digest, size, err := hashFile(filepath.Join(nodeDir, filepath.FromSlash(actualFile.path)))
		if err != nil || size != expected.Size || digest != expected.SHA256 {
			return 0, 0, fmt.Errorf("restored Node content differs from backup: %w", ErrBackupInvalid)
		}
	}
	for _, directory := range actual.dirs {
		info, err := os.Lstat(filepath.Join(nodeDir, filepath.FromSlash(directory)))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != privateDirMode.Perm() {
			return 0, 0, fmt.Errorf("restored Node directory inventory is invalid: %w", ErrBackupInvalid)
		}
	}
	return len(actualFiles), len(actual.dirs), nil
}

func validateKnownDatabaseLayout(manifest *Manifest) error {
	known := map[string]struct{}{
		"node-crypto-state.sqlite": {}, "inbox.sqlite": {},
		"local-inbox.sqlite3": {}, "local-messages.sqlite3": {},
	}
	for _, database := range manifest.Databases {
		base := filepath.Base(filepath.FromSlash(database.Path))
		if _, ok := known[base]; ok && database.Path != base {
			return fmt.Errorf("Node database layout is unsupported: %w", ErrBackupInvalid)
		}
	}
	for _, file := range manifest.Files {
		base := filepath.Base(filepath.FromSlash(file.Path))
		if _, ok := known[base]; ok && file.Path == base && !hasManifestDatabase(manifest, file.Path) {
			return fmt.Errorf("Node database inventory is incomplete: %w", ErrBackupInvalid)
		}
	}
	return nil
}

func hasManifestDatabase(manifest *Manifest, path string) bool {
	for _, database := range manifest.Databases {
		if database.Path == path {
			return true
		}
	}
	return false
}

func inspectCryptoState(path string) (CryptoStateInspection, error) {
	db, err := openSQLite(path, "mode=ro&immutable=1")
	if err != nil {
		return CryptoStateInspection{}, err
	}
	defer db.Close()
	var result CryptoStateInspection
	result.Present = true
	result.Integrity = "ok"
	if err := db.QueryRow(`SELECT version FROM node_crypto_schema WHERE singleton=1`).Scan(&result.SchemaVersion); err != nil || result.SchemaVersion < 1 || result.SchemaVersion > 5 {
		return CryptoStateInspection{}, fmt.Errorf("unsupported Node crypto state schema: %w", ErrBackupInvalid)
	}
	for _, table := range []string{"node_crypto_sequences", "node_crypto_outbox", "node_crypto_replay"} {
		if err := requireSQLiteTable(db, table); err != nil {
			return CryptoStateInspection{}, err
		}
	}
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(last_sequence), 0) FROM node_crypto_sequences`).Scan(
		&result.SequenceStreams, &result.HighestLocalSequence); err != nil {
		return CryptoStateInspection{}, ErrBackupInvalid
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM node_crypto_outbox`).Scan(&result.OutboxRecords); err != nil {
		return CryptoStateInspection{}, ErrBackupInvalid
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM node_crypto_replay`).Scan(&result.ReplayRecords); err != nil {
		return CryptoStateInspection{}, ErrBackupInvalid
	}
	result.InboxAvailable, err = sqliteTableExists(db, "node_crypto_inbox")
	if err != nil {
		return CryptoStateInspection{}, err
	}
	if result.SchemaVersion >= 3 && !result.InboxAvailable {
		return CryptoStateInspection{}, fmt.Errorf("Node crypto inbox table is missing: %w", ErrBackupInvalid)
	}
	if result.InboxAvailable {
		if err := db.QueryRow(`SELECT COUNT(*) FROM node_crypto_inbox`).Scan(&result.InboxRecords); err != nil {
			return CryptoStateInspection{}, ErrBackupInvalid
		}
	}
	return result, nil
}

var nodeInboxDeliveryStates = []string{"NODE_RECEIVED", "INJECTING", "RUNTIME_INJECTED", "CONSUMPTION_UNCONFIRMED", "INJECTION_UNCERTAIN", "FAILED"}
var nodeInboxAttemptStates = []string{"CLAIMED", "INJECTING", "RUNTIME_INJECTED", "CONSUMPTION_UNCONFIRMED", "INJECTION_UNCERTAIN", "FAILED", "ABANDONED"}

func emptyNodeInboxInspection() NodeInboxInspection {
	return NodeInboxInspection{Present: false}
}

func inspectNodeInbox(path string) (NodeInboxInspection, error) {
	db, err := openSQLite(path, "mode=ro&immutable=1")
	if err != nil {
		return NodeInboxInspection{}, err
	}
	defer db.Close()
	for _, table := range []string{"node_inbox_deliveries", "node_inbox_attempts"} {
		if err := requireSQLiteTable(db, table); err != nil {
			return NodeInboxInspection{}, err
		}
	}
	deliveries, err := countStates(db, `SELECT state, COUNT(*) FROM node_inbox_deliveries GROUP BY state`, nodeInboxDeliveryStates)
	if err != nil {
		return NodeInboxInspection{}, err
	}
	attempts, err := countStates(db, `SELECT state, COUNT(*) FROM node_inbox_attempts GROUP BY state`, nodeInboxAttemptStates)
	if err != nil {
		return NodeInboxInspection{}, err
	}
	result := NodeInboxInspection{Present: true, Integrity: "ok", DeliveriesByState: deliveries,
		AttemptsByState: attempts, PendingInjectionDeliveries: deliveries["NODE_RECEIVED"],
		UnresolvedInjectionAttempts: attempts["INJECTING"] + attempts["INJECTION_UNCERTAIN"]}
	return result, nil
}

func inspectLocalMessages(path string) (LocalMessagesInspection, error) {
	db, err := openSQLite(path, "mode=ro&immutable=1")
	if err != nil {
		return LocalMessagesInspection{}, err
	}
	defer db.Close()
	var result LocalMessagesInspection
	result.Present = true
	result.Integrity = "ok"
	if err := db.QueryRow(`SELECT version FROM node_local_schema WHERE singleton=1`).Scan(&result.SchemaVersion); err != nil || result.SchemaVersion < 1 || result.SchemaVersion > 2 {
		return LocalMessagesInspection{}, fmt.Errorf("unsupported Node-local message schema: %w", ErrBackupInvalid)
	}
	if err := requireSQLiteTable(db, "node_local_messages"); err != nil {
		return LocalMessagesInspection{}, err
	}
	if err := requireSQLiteTable(db, "node_local_requests"); err != nil {
		return LocalMessagesInspection{}, err
	}
	messageQuery := `SELECT delivery_state, COUNT(*) FROM node_local_messages GROUP BY delivery_state`
	messageStates := []string{"PENDING", "NODE_INBOX_ACCEPTED", "LATE"}
	if result.SchemaVersion >= 2 {
		messageQuery = `SELECT CASE WHEN terminal_state='REJECTED' THEN 'REJECTED' ELSE delivery_state END, COUNT(*) FROM node_local_messages GROUP BY 1`
		messageStates = append(messageStates, "REJECTED")
	}
	result.MessagesByState, err = countStates(db, messageQuery, messageStates)
	if err != nil {
		return LocalMessagesInspection{}, err
	}
	result.RequestsByState, err = countStates(db, `SELECT state, COUNT(*) FROM node_local_requests GROUP BY state`,
		[]string{"OPEN", "ANSWERED", "CANCELLED", "EXPIRED"})
	if err != nil {
		return LocalMessagesInspection{}, err
	}
	return result, nil
}

func requireSQLiteTable(db *sql.DB, table string) error {
	exists, err := sqliteTableExists(db, table)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("required Node recovery table is missing: %w", ErrBackupInvalid)
	}
	return nil
}

func sqliteTableExists(db *sql.DB, table string) (bool, error) {
	var exists int
	err := db.QueryRow(`SELECT 1 FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func countStates(db *sql.DB, query string, allowed []string) (map[string]int64, error) {
	result := make(map[string]int64, len(allowed))
	for _, state := range allowed {
		result[state] = 0
	}
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("read Node recovery state counts: %w", ErrBackupInvalid)
	}
	defer rows.Close()
	allowedStates := make(map[string]struct{}, len(allowed))
	for _, state := range allowed {
		allowedStates[state] = struct{}{}
	}
	for rows.Next() {
		var state string
		var count int64
		if err := rows.Scan(&state, &count); err != nil || count < 0 {
			return nil, ErrBackupInvalid
		}
		if _, ok := allowedStates[state]; !ok {
			return nil, fmt.Errorf("unknown Node recovery state: %w", ErrBackupInvalid)
		}
		result[state] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read Node recovery state counts: %w", ErrBackupInvalid)
	}
	return result, nil
}
