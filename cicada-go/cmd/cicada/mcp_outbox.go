package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	_ "modernc.org/sqlite"
)

const (
	mcpOutboxStatusPending = "PENDING"
	mcpOutboxStatusUnknown = "UNKNOWN"
	mcpOutboxStatusSent    = "SENT"
	mcpOutboxStatusFailed  = "FAILED"

	mcpOutboxMaxInputBytes  = 256 * 1024
	mcpOutboxMaxResultBytes = 1024 * 1024
	mcpOutboxMaxErrorBytes  = 1024
)

var (
	errMCPOutboxConflict    = errors.New("MCP outbox idempotency key conflicts with the original request")
	errMCPOutboxNotFound    = errors.New("MCP outbox operation was not found")
	errMCPOutboxContext     = errors.New("MCP outbox operation belongs to a different authorized session context")
	errMCPOutboxTerminal    = errors.New("MCP outbox operation is terminal and cannot be retried")
	errMCPOutboxPersistence = errors.New("MCP outbox persistence is unavailable")
)

// mcpOutboxInput is the immutable, credential-free part of a send/ask/reply.
// The idempotency key is stored in its own column so it cannot accidentally
// become part of a user payload or be changed during a retry.
type mcpOutboxInput struct {
	ApprovalID string `json:"approval_id,omitempty"`
	NetworkID  string `json:"network_id,omitempty"`
	Target     string `json:"target,omitempty"`
	LinkID     string `json:"link_id,omitempty"`
	DataScope  string `json:"data_scope,omitempty"`
	Body       string `json:"body,omitempty"`
	Question   string `json:"question,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

type mcpOutboxScope struct {
	APIOrigin       string
	Scope           string
	Harness         string
	NativeSessionID string
	NodeID          string
	Workspace       string
	EndpointID      string
	GroupID         string
	NetworkID       string
}

type mcpOutboxOperation struct {
	OperationID     string
	Kind            string
	Status          string
	APIOrigin       string
	Scope           string
	Harness         string
	NativeSessionID string
	NodeID          string
	Workspace       string
	EndpointID      string
	GroupID         string
	NetworkID       string
	IdempotencyKey  string
	InputJSON       string
	InputDigest     string
	AttemptCount    int
	LastError       string
	ResultJSON      string
	CreatedAt       string
	UpdatedAt       string
}

// mcpOutboxStore is deliberately separate from the server's Fabric SQLite
// store. MCP processes may share this file safely through SQLite locking, but
// operations from different native sessions remain isolated by their scope
// columns and are never addressed by a global body hash.
type mcpOutboxStore struct {
	path string
	mu   sync.Mutex
	db   *sql.DB
}

func newMCPOutbox(path string) *mcpOutboxStore {
	path = strings.TrimSpace(path)
	if path != "" && path != ":memory:" {
		if absolute, err := filepath.Abs(filepath.Clean(path)); err == nil {
			path = absolute
		}
	}
	return &mcpOutboxStore{path: path}
}

// mcpOutboxStatePath follows the existing MCP session-state location while
// allowing deployments and tests to choose an explicit per-user file.
func mcpOutboxStatePath(sessionStatePath string) string {
	for _, name := range []string{"CICADA_MCP_OUTBOX_STATE_FILE", "CICADA_MCP_OUTBOX_FILE"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return filepath.Clean(value)
		}
	}
	for _, name := range []string{"CICADA_MCP_OUTBOX_STATE_DIR", "CICADA_MCP_OUTBOX_DIR"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return filepath.Join(filepath.Clean(value), "outbox.sqlite3")
		}
	}
	if value := strings.TrimSpace(sessionStatePath); value != "" && value != ":memory:" {
		return filepath.Join(filepath.Dir(filepath.Clean(value)), "outbox.sqlite3")
	}
	// A directly constructed test/server without a session-state path must fail
	// closed instead of unexpectedly opening a process-wide home-directory DB.
	return ""
}

func (s *mcpOutboxStore) openLocked() error {
	if s == nil {
		return errMCPOutboxPersistence
	}
	if s.db != nil {
		return nil
	}
	if strings.TrimSpace(s.path) == "" {
		return fmt.Errorf("%w: no local state path configured", errMCPOutboxPersistence)
	}

	if s.path != ":memory:" {
		dir := filepath.Clean(filepath.Dir(s.path))
		if dir == "." {
			if absolute, err := filepath.Abs(dir); err == nil {
				dir = absolute
			}
		}
		if err := ensureMCPPrivateDir(dir); err != nil {
			return fmt.Errorf("%w: create private outbox directory: %v", errMCPOutboxPersistence, err)
		}
		if info, err := os.Lstat(s.path); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("%w: outbox path is not a regular file", errMCPOutboxPersistence)
			}
			if err := os.Chmod(s.path, 0o600); err != nil {
				return fmt.Errorf("%w: protect outbox file: %v", errMCPOutboxPersistence, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: inspect outbox file: %v", errMCPOutboxPersistence, err)
		}
	}

	db, err := sql.Open("sqlite", s.path)
	if err != nil {
		return fmt.Errorf("%w: open outbox: %v", errMCPOutboxPersistence, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	closeDB := func(openErr error) error {
		_ = db.Close()
		return fmt.Errorf("%w: initialize outbox: %v", errMCPOutboxPersistence, openErr)
	}
	pragmas := []string{
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = FULL",
	}
	if s.path != ":memory:" {
		pragmas = append(pragmas, "PRAGMA journal_mode = WAL")
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return closeDB(err)
		}
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS mcp_outbox_operations (
  operation_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  api_origin TEXT NOT NULL,
  scope TEXT NOT NULL,
  harness TEXT NOT NULL,
  native_session_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  workspace TEXT NOT NULL DEFAULT '',
  endpoint_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  network_id TEXT NOT NULL DEFAULT '',
  idempotency_key TEXT NOT NULL,
  input_json TEXT NOT NULL,
  input_digest TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  result_json TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
`); err != nil {
		return closeDB(err)
	}
	// Existing private outboxes predate Network direct. Upgrade them in place;
	// Group rows retain an empty network_id and their prior identity.
	upgrade, err := db.Begin()
	if err != nil {
		return closeDB(err)
	}
	defer upgrade.Rollback()
	var hasNetworkID bool
	columns, err := upgrade.Query("PRAGMA table_info(mcp_outbox_operations)")
	if err != nil {
		return closeDB(err)
	}
	for columns.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue sql.NullString
		if err := columns.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = columns.Close()
			return closeDB(err)
		}
		if name == "network_id" {
			hasNetworkID = true
		}
	}
	if err := columns.Err(); err != nil {
		_ = columns.Close()
		return closeDB(err)
	}
	_ = columns.Close()
	if !hasNetworkID {
		if _, err := upgrade.Exec("ALTER TABLE mcp_outbox_operations ADD COLUMN network_id TEXT NOT NULL DEFAULT ''"); err != nil {
			return closeDB(err)
		}
		if _, err := upgrade.Exec("DROP INDEX IF EXISTS mcp_outbox_scope_key_idx"); err != nil {
			return closeDB(err)
		}
		if _, err := upgrade.Exec("DROP INDEX IF EXISTS mcp_outbox_scope_operation_idx"); err != nil {
			return closeDB(err)
		}
	}
	if _, err := upgrade.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS mcp_outbox_scope_key_idx ON mcp_outbox_operations
(api_origin,native_session_id,endpoint_id,group_id,network_id,idempotency_key);
CREATE INDEX IF NOT EXISTS mcp_outbox_scope_operation_idx ON mcp_outbox_operations
(api_origin,native_session_id,endpoint_id,group_id,network_id,operation_id);`); err != nil {
		return closeDB(err)
	}
	if err := upgrade.Commit(); err != nil {
		return closeDB(err)
	}
	if s.path != ":memory:" {
		_ = os.Chmod(s.path, 0o600)
		for _, suffix := range []string{"-wal", "-shm"} {
			if path := s.path + suffix; func() bool { _, err := os.Stat(path); return err == nil }() {
				_ = os.Chmod(path, 0o600)
			}
		}
	}
	s.db = db
	return nil
}

func (s *mcpOutboxStore) close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *mcpOutboxStore) withDBLocked() (*sql.DB, error) {
	if err := s.openLocked(); err != nil {
		return nil, err
	}
	return s.db, nil
}

func newMCPOutboxID(prefix string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate MCP outbox identity: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(random[:]), nil
}

func normalizeMCPOutboxKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", nil
	}
	if len([]byte(key)) > 256 || strings.IndexFunc(key, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "", errors.New("idempotency_key is invalid or too long")
	}
	return key, nil
}

func canonicalMCPOutboxInput(input mcpOutboxInput) (string, string, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", "", err
	}
	if len(encoded) > mcpOutboxMaxInputBytes {
		return "", "", errors.New("MCP outbox input exceeds the bounded local limit")
	}
	digest := sha256.Sum256(encoded)
	return string(encoded), hex.EncodeToString(digest[:]), nil
}

func mcpOutboxNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (s *mcpOutboxStore) prepare(scope mcpOutboxScope, kind, requestedKey string, input mcpOutboxInput) (mcpOutboxOperation, bool, error) {
	return s.prepareOperation(scope, kind, requestedKey, input, "")
}

// prepareMonitorBroadcast preserves the identity reserved by current Hub
// authority. This is not a general caller-selected operation ID API.
func (s *mcpOutboxStore) prepareMonitorBroadcast(scope mcpOutboxScope, approvalID, operationID string) (mcpOutboxOperation, bool, error) {
	if !validMonitorApprovalID(approvalID) {
		return mcpOutboxOperation{}, false, errMCPOutboxConflict
	}
	if _, _, err := localSealedRPCIDs(operationID); err != nil {
		return mcpOutboxOperation{}, false, errMCPOutboxConflict
	}
	return s.prepareOperation(scope, "monitor_broadcast", "monitor:"+approvalID,
		mcpOutboxInput{ApprovalID: approvalID}, operationID)
}

func (s *mcpOutboxStore) prepareOperation(scope mcpOutboxScope, kind, requestedKey string, input mcpOutboxInput, reservedID string) (mcpOutboxOperation, bool, error) {
	inputJSON, inputDigest, err := canonicalMCPOutboxInput(input)
	if err != nil {
		return mcpOutboxOperation{}, false, err
	}
	key, err := normalizeMCPOutboxKey(requestedKey)
	if err != nil {
		return mcpOutboxOperation{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.withDBLocked()
	if err != nil {
		return mcpOutboxOperation{}, false, err
	}
	tx, err := db.Begin()
	if err != nil {
		return mcpOutboxOperation{}, false, fmt.Errorf("%w: begin operation transaction: %v", errMCPOutboxPersistence, err)
	}
	defer tx.Rollback()
	var existing mcpOutboxOperation
	err = scanMCPOutboxOperation(tx.QueryRow(`
SELECT operation_id, kind, status, api_origin, scope, harness, native_session_id,
       node_id, workspace, endpoint_id, group_id, network_id, idempotency_key, input_json,
       input_digest, attempt_count, last_error, result_json, created_at, updated_at
FROM mcp_outbox_operations
WHERE api_origin = ? AND native_session_id = ? AND endpoint_id = ? AND group_id = ? AND network_id = ? AND idempotency_key = ?`,
		scope.APIOrigin, scope.NativeSessionID, scope.EndpointID, scope.GroupID, scope.NetworkID, key), &existing)
	if err == nil {
		if !mcpOutboxScopeMatches(existing, scope) {
			return mcpOutboxOperation{}, false, errMCPOutboxContext
		}
		if existing.Kind != kind || existing.InputDigest != inputDigest || existing.InputJSON != inputJSON ||
			(reservedID != "" && existing.OperationID != reservedID) {
			return mcpOutboxOperation{}, false, errMCPOutboxConflict
		}
		if err := tx.Commit(); err != nil {
			return mcpOutboxOperation{}, false, fmt.Errorf("%w: read existing operation: %v", errMCPOutboxPersistence, err)
		}
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return mcpOutboxOperation{}, false, fmt.Errorf("%w: inspect operation: %v", errMCPOutboxPersistence, err)
	}
	operationID := reservedID
	if operationID == "" {
		operationID, err = newMCPOutboxID("op")
		if err != nil {
			return mcpOutboxOperation{}, false, err
		}
	}
	if key == "" {
		key = operationID
	}
	now := mcpOutboxNow()
	op := mcpOutboxOperation{
		OperationID: operationID, Kind: kind, Status: mcpOutboxStatusPending,
		APIOrigin: scope.APIOrigin, Scope: scope.Scope, Harness: scope.Harness,
		NativeSessionID: scope.NativeSessionID, NodeID: scope.NodeID, Workspace: scope.Workspace,
		EndpointID: scope.EndpointID, GroupID: scope.GroupID, NetworkID: scope.NetworkID, IdempotencyKey: key,
		InputJSON: inputJSON, InputDigest: inputDigest, CreatedAt: now, UpdatedAt: now,
	}
	_, err = tx.Exec(`
INSERT INTO mcp_outbox_operations (
 operation_id, kind, status, api_origin, scope, harness, native_session_id,
 node_id, workspace, endpoint_id, group_id, network_id, idempotency_key, input_json,
 input_digest, attempt_count, last_error, result_json, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', '', ?, ?)`,
		op.OperationID, op.Kind, op.Status, op.APIOrigin, op.Scope, op.Harness,
		op.NativeSessionID, op.NodeID, op.Workspace, op.EndpointID, op.GroupID, op.NetworkID,
		op.IdempotencyKey, op.InputJSON, op.InputDigest, op.CreatedAt, op.UpdatedAt)
	if err != nil {
		return mcpOutboxOperation{}, false, fmt.Errorf("%w: write operation: %v", errMCPOutboxPersistence, err)
	}
	if err := tx.Commit(); err != nil {
		return mcpOutboxOperation{}, false, fmt.Errorf("%w: commit operation: %v", errMCPOutboxPersistence, err)
	}
	return op, true, nil
}

func scanMCPOutboxOperation(scanner interface{ Scan(...any) error }, op *mcpOutboxOperation) error {
	return scanner.Scan(
		&op.OperationID, &op.Kind, &op.Status, &op.APIOrigin, &op.Scope, &op.Harness,
		&op.NativeSessionID, &op.NodeID, &op.Workspace, &op.EndpointID, &op.GroupID, &op.NetworkID,
		&op.IdempotencyKey, &op.InputJSON, &op.InputDigest, &op.AttemptCount,
		&op.LastError, &op.ResultJSON, &op.CreatedAt, &op.UpdatedAt,
	)
}

func (s *mcpOutboxStore) load(scope mcpOutboxScope, operationID string) (mcpOutboxOperation, error) {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return mcpOutboxOperation{}, errors.New("operation_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.withDBLocked()
	if err != nil {
		return mcpOutboxOperation{}, err
	}
	var op mcpOutboxOperation
	err = scanMCPOutboxOperation(db.QueryRow(`
SELECT operation_id, kind, status, api_origin, scope, harness, native_session_id,
       node_id, workspace, endpoint_id, group_id, network_id, idempotency_key, input_json,
       input_digest, attempt_count, last_error, result_json, created_at, updated_at
FROM mcp_outbox_operations WHERE operation_id = ?`, operationID), &op)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpOutboxOperation{}, errMCPOutboxNotFound
	}
	if err != nil {
		return mcpOutboxOperation{}, fmt.Errorf("%w: load operation: %v", errMCPOutboxPersistence, err)
	}
	if !mcpOutboxScopeMatches(op, scope) {
		return mcpOutboxOperation{}, errMCPOutboxContext
	}
	return op, nil
}

func mcpOutboxScopeMatches(op mcpOutboxOperation, scope mcpOutboxScope) bool {
	return op.APIOrigin == scope.APIOrigin && op.Scope == scope.Scope &&
		op.Harness == scope.Harness && op.NativeSessionID == scope.NativeSessionID &&
		op.NodeID == scope.NodeID && op.Workspace == scope.Workspace &&
		op.EndpointID == scope.EndpointID && op.GroupID == scope.GroupID && op.NetworkID == scope.NetworkID
}

func (s *mcpOutboxStore) markAttempt(scope mcpOutboxScope, operationID string) (mcpOutboxOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.withDBLocked()
	if err != nil {
		return mcpOutboxOperation{}, err
	}
	now := mcpOutboxNow()
	result, err := db.Exec(`UPDATE mcp_outbox_operations
SET status = ?, attempt_count = attempt_count + 1, last_error = '', updated_at = ?
WHERE operation_id = ? AND api_origin = ? AND scope = ? AND harness = ? AND native_session_id = ?
  AND node_id = ? AND workspace = ? AND endpoint_id = ? AND group_id = ? AND network_id = ?
  AND status IN (?, ?)`, mcpOutboxStatusUnknown, now, operationID, scope.APIOrigin,
		scope.Scope, scope.Harness, scope.NativeSessionID, scope.NodeID, scope.Workspace,
		scope.EndpointID, scope.GroupID, scope.NetworkID, mcpOutboxStatusPending, mcpOutboxStatusUnknown)
	if err != nil {
		return mcpOutboxOperation{}, fmt.Errorf("%w: mark operation uncertain: %v", errMCPOutboxPersistence, err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		op, loadErr := s.loadLocked(db, scope, operationID)
		if loadErr != nil {
			return mcpOutboxOperation{}, loadErr
		}
		if op.Status == mcpOutboxStatusSent || op.Status == mcpOutboxStatusFailed {
			return op, errMCPOutboxTerminal
		}
	}
	return s.loadLocked(db, scope, operationID)
}

func (s *mcpOutboxStore) loadLocked(db *sql.DB, scope mcpOutboxScope, operationID string) (mcpOutboxOperation, error) {
	var op mcpOutboxOperation
	err := scanMCPOutboxOperation(db.QueryRow(`
SELECT operation_id, kind, status, api_origin, scope, harness, native_session_id,
       node_id, workspace, endpoint_id, group_id, network_id, idempotency_key, input_json,
       input_digest, attempt_count, last_error, result_json, created_at, updated_at
FROM mcp_outbox_operations WHERE operation_id = ?`, operationID), &op)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpOutboxOperation{}, errMCPOutboxNotFound
	}
	if err != nil {
		return mcpOutboxOperation{}, fmt.Errorf("%w: load operation: %v", errMCPOutboxPersistence, err)
	}
	if !mcpOutboxScopeMatches(op, scope) {
		return mcpOutboxOperation{}, errMCPOutboxContext
	}
	return op, nil
}

func (s *mcpOutboxStore) markResult(scope mcpOutboxScope, operationID, status, lastError, resultJSON string) (mcpOutboxOperation, error) {
	if status != mcpOutboxStatusSent && status != mcpOutboxStatusFailed && status != mcpOutboxStatusUnknown {
		return mcpOutboxOperation{}, errors.New("invalid MCP outbox result status")
	}
	if len(lastError) > mcpOutboxMaxErrorBytes {
		lastError = lastError[:mcpOutboxMaxErrorBytes]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.withDBLocked()
	if err != nil {
		return mcpOutboxOperation{}, err
	}
	_, err = db.Exec(`UPDATE mcp_outbox_operations SET status = ?, last_error = ?, result_json = ?, updated_at = ?
	WHERE operation_id = ? AND api_origin = ? AND scope = ? AND harness = ? AND native_session_id = ?
  AND node_id = ? AND workspace = ? AND endpoint_id = ? AND group_id = ? AND network_id = ?`,
		status, lastError, resultJSON, mcpOutboxNow(), operationID, scope.APIOrigin,
		scope.Scope, scope.Harness, scope.NativeSessionID, scope.NodeID, scope.Workspace,
		scope.EndpointID, scope.GroupID, scope.NetworkID)
	if err != nil {
		return mcpOutboxOperation{}, fmt.Errorf("%w: persist operation result: %v", errMCPOutboxPersistence, err)
	}
	return s.loadLocked(db, scope, operationID)
}

func (s *mcpOutboxStore) markError(scope mcpOutboxScope, operationID, status string, err error) (mcpOutboxOperation, error) {
	message := ""
	if err != nil {
		message = err.Error()
	}
	return s.markResult(scope, operationID, status, message, "")
}

func (m *mcpServer) ensureMCPOutbox() (*mcpOutboxStore, error) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.outbox == nil {
		path := mcpOutboxStatePath(m.sessionStatePath)
		if path == "" {
			return nil, fmt.Errorf("%w: MCP server has no state path", errMCPOutboxPersistence)
		}
		m.outbox = newMCPOutbox(path)
	}
	return m.outbox, nil
}

func (m *mcpServer) currentMCPOutboxScope() (mcpOutboxScope, error) {
	m.sessionMu.RLock()
	token := strings.TrimSpace(m.sessionToken)
	context := m.sessionContext
	contextSet := m.sessionContextSet
	endpointID := strings.TrimSpace(m.endpointID)
	groupID := strings.TrimSpace(m.sessionGroupID)
	storedScope := strings.TrimSpace(m.sessionScope)
	originRaw := m.baseURL
	m.sessionMu.RUnlock()
	if token == "" || !contextSet {
		return mcpOutboxScope{}, errors.New("MCP session is not authorized; call cicada_join first")
	}
	trusted, err := normalizeMCPTrustedContext(harness.SessionContext{
		Harness: context.Harness, NativeSessionID: context.NativeSessionID,
		MachineID: context.NodeID, Workspace: context.Workspace,
	})
	if err != nil {
		return mcpOutboxScope{}, err
	}
	origin, err := normalizeMCPAPIOrigin(originRaw)
	if err != nil {
		return mcpOutboxScope{}, err
	}
	scope, _, err := mcpSessionScope(origin, harness.SessionContext{
		Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID,
		MachineID: trusted.NodeID, Workspace: trusted.Workspace,
	})
	if err != nil {
		return mcpOutboxScope{}, err
	}
	if storedScope != "" && storedScope != scope {
		return mcpOutboxScope{}, errMCPOutboxContext
	}
	if endpointID == "" || groupID == "" {
		return mcpOutboxScope{}, errors.New("MCP session has no authenticated Endpoint and Group")
	}
	return mcpOutboxScope{APIOrigin: origin, Scope: scope, Harness: trusted.Harness,
		NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID, Workspace: trusted.Workspace,
		EndpointID: endpointID, GroupID: groupID}, nil
}

func (m *mcpServer) submitMCPOutbox(kind string, input mcpOutboxInput, key string) (any, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	store, err := m.ensureMCPOutbox()
	if err != nil {
		return nil, err
	}
	op, created, err := store.prepare(scope, kind, key, input)
	if err != nil {
		return nil, err
	}
	if !created {
		return mcpOutboxPublicResult(op), nil
	}
	return m.dispatchMCPOutbox(store, scope, op)
}

func (m *mcpServer) dispatchMCPOutbox(store *mcpOutboxStore, scope mcpOutboxScope, op mcpOutboxOperation) (any, error) {
	current, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	if !mcpOutboxScopeEqual(current, scope) || !mcpOutboxScopeMatches(op, current) {
		return nil, errMCPOutboxContext
	}
	op, err = store.markAttempt(scope, op.OperationID)
	if err != nil {
		if errors.Is(err, errMCPOutboxTerminal) {
			return mcpOutboxPublicResult(op), nil
		}
		return nil, err
	}
	if op.Kind == "broadcast" {
		return m.dispatchBroadcastMCPOutbox(store, scope, op)
	}
	if op.Kind == "monitor_broadcast" {
		return m.dispatchMonitorBroadcastMCPOutbox(store, scope, op)
	}
	if op.Kind == "send" || op.Kind == "ask" || op.Kind == "reply" {
		var input mcpOutboxInput
		if err := json.Unmarshal([]byte(op.InputJSON), &input); err != nil {
			failed, persistErr := store.markError(scope, op.OperationID, mcpOutboxStatusFailed,
				errors.New("MCP peer operation has corrupt immutable input"))
			if persistErr != nil {
				return nil, persistErr
			}
			return mcpOutboxPublicResult(failed), nil
		}
		if input.LinkID != "" {
			if op.Kind == "send" {
				return m.dispatchSealedMCPOutbox(store, scope, op)
			}
			return m.dispatchSealedRPCMCPOutbox(store, scope, op, input)
		}
		return m.dispatchLocalGroupMCPOutbox(store, scope, op, input)
	}
	failed, persistErr := store.markError(scope, op.OperationID, mcpOutboxStatusFailed,
		errors.New("unsupported MCP outbox operation kind"))
	if persistErr != nil {
		return nil, persistErr
	}
	return mcpOutboxPublicResult(failed), nil
}

func mcpOutboxScopeEqual(a, b mcpOutboxScope) bool {
	return a.APIOrigin == b.APIOrigin && a.Scope == b.Scope && a.Harness == b.Harness &&
		a.NativeSessionID == b.NativeSessionID && a.NodeID == b.NodeID && a.Workspace == b.Workspace &&
		a.EndpointID == b.EndpointID && a.GroupID == b.GroupID && a.NetworkID == b.NetworkID
}

func (m *mcpServer) mcpOutboxStatus(operationID string) (any, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	store, err := m.ensureMCPOutbox()
	if err != nil {
		return nil, err
	}
	op, err := store.load(scope, operationID)
	if err != nil {
		return nil, err
	}
	return mcpOutboxPublicResult(op), nil
}

func (m *mcpServer) mcpOutboxRetry(operationID string) (any, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	store, err := m.ensureMCPOutbox()
	if err != nil {
		return nil, err
	}
	op, err := store.load(scope, operationID)
	if err != nil {
		return nil, err
	}
	if op.Status == mcpOutboxStatusSent || op.Status == mcpOutboxStatusFailed {
		return mcpOutboxPublicResult(op), nil
	}
	return m.dispatchMCPOutbox(store, scope, op)
}

func mcpOutboxResultJSON(result any, token string) (string, error) {
	result = sanitizeMCPToolResult(result)
	encoded, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	if token != "" {
		encoded = []byte(strings.ReplaceAll(string(encoded), token, "<redacted>"))
		encoded = []byte(strings.ReplaceAll(string(encoded), fabricpkg.HashSessionCredential(token), "<redacted>"))
	}
	if len(encoded) > mcpOutboxMaxResultBytes {
		return "", errors.New("MCP outbox result exceeds the bounded local limit")
	}
	return string(encoded), nil
}

func mcpOutboxPublicResult(op mcpOutboxOperation) map[string]any {
	result := map[string]any{
		"operation_id":    op.OperationID,
		"operation":       op.Kind,
		"status":          op.Status,
		"idempotency_key": op.IdempotencyKey,
		"attempts":        op.AttemptCount,
		"retryable":       op.Status == mcpOutboxStatusPending || op.Status == mcpOutboxStatusUnknown,
	}
	if op.Kind == "broadcast" || op.Kind == "monitor_broadcast" {
		if broadcastID, err := mcpBroadcastID(op.OperationID); err == nil {
			result["broadcast_id"] = broadcastID
		}
	}
	// A timeout can happen after Hub durable acceptance and before the MCP
	// process records the receipt. Publish only immutable correlation metadata
	// so the original joined session can query status without guessing an ID;
	// the question/answer body remains private in the local outbox.
	if op.Kind == "ask" || op.Kind == "reply" {
		var input mcpOutboxInput
		if json.Unmarshal([]byte(op.InputJSON), &input) == nil && input.LinkID != "" {
			result["link_id"] = input.LinkID
			if op.Kind == "ask" {
				if _, requestID, err := localSealedRPCIDs(op.OperationID); err == nil {
					result["request_id"] = requestID
				}
			} else if input.RequestID != "" {
				result["request_id"] = input.RequestID
			}
		}
	}
	if op.Status == mcpOutboxStatusPending {
		result["next_action"] = "cicada_operation_retry"
	} else if op.Status == mcpOutboxStatusUnknown {
		result["next_action"] = "cicada_operation_retry"
	} else {
		result["next_action"] = "none"
	}
	if strings.TrimSpace(op.LastError) != "" {
		result["error"] = op.LastError
	}
	if strings.TrimSpace(op.ResultJSON) != "" {
		var value any
		if json.Unmarshal([]byte(op.ResultJSON), &value) == nil {
			result["result"] = value
			if object, ok := value.(map[string]any); ok {
				for key, item := range object {
					if _, exists := result[key]; !exists {
						result[key] = item
					}
				}
			}
		}
	}
	return result
}
