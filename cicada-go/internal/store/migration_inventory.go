package store

// This file contains the legacy migration inventory reader.  It intentionally
// does not use Store.New: opening a normal Store runs compatibility and v2 DDL
// and therefore cannot be used to prove that a dry-run left the source alone.
// The inventory reader opens SQLite with mode=ro and selects only identity,
// routing metadata, and aggregate counts.  It never reads message bodies,
// opaque envelopes, payloads, or credential material.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	// LegacyMappingPending means an endpoint still needs an explicit operator
	// decision before it can be associated with a v2 Principal and Group.
	LegacyMappingPending = "pending"
	// LegacyMappingReady means the legacy row carries an explicit v2 marker and
	// both Principal and Group associations.  The inventory never creates or
	// changes such an association.
	LegacyMappingReady = "ready"

	LegacyOwnerDecisionExplicitPrincipal      = "explicit_principal"
	LegacyOwnerDecisionNeedsExplicitPrincipal = "legacy_owner_requires_explicit_principal"
	LegacyOwnerDecisionMissing                = "missing_owner_decision"
	LegacyGroupDecisionExplicit               = "explicit_group"
	LegacyGroupDecisionMissing                = "missing_group_decision"
	LegacyMappingReasonMissingOwnerDecision   = "MISSING_OWNER_DECISION"
	LegacyMappingReasonMissingGroupDecision   = "MISSING_GROUP_DECISION"
	LegacyMappingReasonOwnerNeedsExplicitID   = "OWNER_REQUIRES_EXPLICIT_PRINCIPAL"
	LegacyMappingReasonMigrationStateNotReady = "MIGRATION_STATE_NOT_READY"
)

var (
	// ErrMigrationInventoryDatabaseRequired is returned before opening any
	// path.  Keeping this error public makes CLI and embedding callers agree on
	// the fact that an explicit source is required for a dry-run.
	ErrMigrationInventoryDatabaseRequired = errors.New("migration inventory requires a database path")
	ErrMigrationInventoryApplyUnsupported = errors.New("migration inventory is read-only; mapping apply is not supported")
)

// LegacyMigrationInventory is a deterministic, read-only description of the
// rows that an eventual explicit migration would need to account for.  It is
// deliberately a report, not a migration plan with executable operations.
type LegacyMigrationInventory struct {
	Version           int                           `json:"inventory_version"`
	ReadOnly          bool                          `json:"read_only"`
	SchemaFingerprint string                        `json:"schema_fingerprint"`
	SourceTables      []LegacyMigrationTable        `json:"source_tables"`
	Counts            LegacyMigrationCounts         `json:"counts"`
	Mapping           LegacyMigrationMappingSummary `json:"mapping"`
	Endpoints         []LegacyEndpointMapping       `json:"endpoints"`
	NativeBindings    []LegacyNativeBinding         `json:"native_bindings"`
}

// LegacyMigrationTable contains only a table name and row count.  The schema
// SQL and all row values stay out of the report, including for tables that may
// contain credentials or message content.
type LegacyMigrationTable struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

// LegacyMigrationCounts covers the objects called out by the v2 migration
// procedure.  Counts are safe to collect for sensitive tables because no row
// values are returned.
type LegacyMigrationCounts struct {
	Endpoints       int64 `json:"endpoints"`
	NativeSessions  int64 `json:"native_sessions"`
	Goals           int64 `json:"goals"`
	Workers         int64 `json:"workers"`
	Approvals       int64 `json:"approvals"`
	Contacts        int64 `json:"contacts"`
	PeerSessions    int64 `json:"peer_sessions"`
	PeerMessages    int64 `json:"peer_messages"`
	FabricMessages  int64 `json:"fabric_messages"`
	FabricRequests  int64 `json:"fabric_requests"`
	RelayReceipts   int64 `json:"relay_receipts"`
	GatewayRequests int64 `json:"gateway_requests"`
	GatewayResults  int64 `json:"gateway_results"`
	Groups          int64 `json:"groups"`
	Principals      int64 `json:"principals"`
	Memberships     int64 `json:"memberships"`
	Bindings        int64 `json:"session_bindings"`
}

// LegacyMigrationMappingSummary makes the pending/ready split visible even
// when an operator chooses to consume only aggregate report fields.
type LegacyMigrationMappingSummary struct {
	Total   int64 `json:"total"`
	Pending int64 `json:"pending"`
	Ready   int64 `json:"ready"`
}

// LegacyEndpointMapping preserves stable legacy identity and native binding
// coordinates.  Owner is the legacy owner reference; PrincipalID and GroupID
// are emitted only when the source already contains explicit v2 associations.
// No owner or Group is inferred from names, machines, workspaces, or roles.
type LegacyEndpointMapping struct {
	EndpointID      string   `json:"endpoint_id"`
	Name            string   `json:"name,omitempty"`
	Role            string   `json:"role,omitempty"`
	Harness         string   `json:"harness,omitempty"`
	NativeSessionID string   `json:"native_session_id,omitempty"`
	MachineID       string   `json:"machine_id,omitempty"`
	Workspace       string   `json:"workspace,omitempty"`
	GoalID          string   `json:"goal_id,omitempty"`
	Status          string   `json:"status,omitempty"`
	Owner           string   `json:"legacy_owner,omitempty"`
	Visibility      string   `json:"visibility,omitempty"`
	PrincipalID     string   `json:"principal_id,omitempty"`
	GroupID         string   `json:"group_id,omitempty"`
	BindingID       string   `json:"binding_id,omitempty"`
	MigrationState  string   `json:"migration_state,omitempty"`
	MappingState    string   `json:"mapping_state"`
	OwnerDecision   string   `json:"owner_decision"`
	GroupDecision   string   `json:"group_decision"`
	PendingReasons  []string `json:"pending_reasons,omitempty"`
}

// LegacyNativeBinding records the native coordinates separately so consumers
// can compare binding continuity without parsing the endpoint projection.
type LegacyNativeBinding struct {
	EndpointID      string `json:"endpoint_id"`
	Harness         string `json:"harness,omitempty"`
	NativeSessionID string `json:"native_session_id,omitempty"`
	MachineID       string `json:"machine_id,omitempty"`
	Workspace       string `json:"workspace,omitempty"`
	BindingID       string `json:"binding_id,omitempty"`
}

// LegacyMigrationInventoryOptions controls report volume.  A non-positive
// EndpointLimit includes every endpoint.  The count remains complete when a
// positive limit truncates the endpoint projection.
type LegacyMigrationInventoryOptions struct {
	EndpointLimit int
}

// legacyInventoryQueryer is implemented by both *sql.DB and *sql.Tx.  The
// inventory uses *sql.Tx so every metadata query observes one SQLite snapshot.
type legacyInventoryQueryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// InventoryLegacyMigration opens path in SQLite read-only mode and returns a
// dry-run inventory.  It does not intentionally create or alter a source
// table, column, migration ledger, Group, Principal, Membership, or
// SessionBinding.  SQLite may manage read-only WAL sidecar state as required
// by the driver; callers should treat the database plus its WAL/SHM files as
// the source snapshot when taking a byte-level backup.
func InventoryLegacyMigration(path string) (*LegacyMigrationInventory, error) {
	return InventoryLegacyMigrationWithOptions(path, LegacyMigrationInventoryOptions{})
}

// InventoryLegacyMigrationWithOptions is the implementation used by the CLI
// and tests.  All options affect projection size only; none changes the source.
func InventoryLegacyMigrationWithOptions(path string, options LegacyMigrationInventoryOptions) (*LegacyMigrationInventory, error) {
	db, err := openLegacyDatabaseReadOnly(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin legacy inventory read transaction: %w", err)
	}
	defer tx.Rollback()

	tables, tableSet, err := legacySourceTables(tx)
	if err != nil {
		return nil, err
	}
	fingerprint, err := legacySchemaFingerprint(tx)
	if err != nil {
		return nil, err
	}
	tableInventory := make([]LegacyMigrationTable, 0, len(tables))
	for _, table := range tables {
		rows, err := legacyTableCount(tx, table)
		if err != nil {
			return nil, fmt.Errorf("count legacy table %s: %w", table, err)
		}
		tableInventory = append(tableInventory, LegacyMigrationTable{Name: table, Rows: rows})
	}
	counts, err := legacyMigrationCounts(tx, tableSet)
	if err != nil {
		return nil, err
	}
	endpoints, err := legacyEndpointMappings(tx, tableSet, options.EndpointLimit)
	if err != nil {
		return nil, err
	}
	nativeBindings := make([]LegacyNativeBinding, 0, len(endpoints))
	mapping, err := legacyEndpointMappingSummary(tx, tableSet, counts.Endpoints)
	if err != nil {
		return nil, err
	}
	for _, endpoint := range endpoints {
		nativeBindings = append(nativeBindings, LegacyNativeBinding{
			EndpointID: endpoint.EndpointID, Harness: endpoint.Harness,
			NativeSessionID: endpoint.NativeSessionID, MachineID: endpoint.MachineID,
			Workspace: endpoint.Workspace, BindingID: endpoint.BindingID,
		})
	}
	return &LegacyMigrationInventory{
		Version:           1,
		ReadOnly:          true,
		SchemaFingerprint: fingerprint,
		SourceTables:      tableInventory,
		Counts:            counts,
		Mapping:           mapping,
		Endpoints:         endpoints,
		NativeBindings:    nativeBindings,
	}, nil
}

// openLegacyDatabaseReadOnly is intentionally separate from Store.New.  The
// mode=ro prevents SQLite from creating a missing database and rejects writes
// to an existing source, including compatibility DDL on old schemas.  The
// caller additionally holds one explicit read transaction for the report.
func openLegacyDatabaseReadOnly(path string) (*sql.DB, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrMigrationInventoryDatabaseRequired
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve migration inventory database: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("migration inventory database does not exist: %s", abs)
		}
		return nil, fmt.Errorf("stat migration inventory database: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("migration inventory database is a directory: %s", abs)
	}
	// URL.Path makes spaces, '#', '?' and other legal filesystem characters
	// unambiguous in the SQLite URI while retaining an absolute file path.
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String() + "?mode=ro"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, fmt.Errorf("open legacy database read-only: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping legacy database read-only: %w", err)
	}
	return db, nil
}

func legacySourceTables(db legacyInventoryQueryer) ([]string, map[string]struct{}, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, nil, fmt.Errorf("list legacy schema tables: %w", err)
	}
	defer rows.Close()
	var tables []string
	set := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, nil, fmt.Errorf("read legacy schema table: %w", err)
		}
		if name == "" {
			continue
		}
		tables = append(tables, name)
		set[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("read legacy schema tables: %w", err)
	}
	return tables, set, nil
}

func legacySchemaFingerprint(db legacyInventoryQueryer) (string, error) {
	rows, err := db.Query(`SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master WHERE type IN ('table', 'index', 'trigger', 'view') ORDER BY type, name`)
	if err != nil {
		return "", fmt.Errorf("read legacy schema fingerprint: %w", err)
	}
	defer rows.Close()
	hash := sha256.New()
	for rows.Next() {
		var kind, name, tableName, definition string
		if err := rows.Scan(&kind, &name, &tableName, &definition); err != nil {
			return "", fmt.Errorf("scan legacy schema fingerprint: %w", err)
		}
		_, _ = fmt.Fprintf(hash, "%s\x00%s\x00%s\x00%s\n", kind, name, tableName, definition)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("read legacy schema fingerprint: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func legacyTableCount(db legacyInventoryQueryer, table string) (int64, error) {
	var count int64
	if err := db.QueryRow(`SELECT count(*) FROM ` + quoteLegacyInventoryIdentifier(table)).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func legacyMigrationCounts(db legacyInventoryQueryer, tables map[string]struct{}) (LegacyMigrationCounts, error) {
	var result LegacyMigrationCounts
	var err error
	result.Endpoints, err = legacyCountIfPresent(db, tables, "fabric_endpoints")
	if err != nil {
		return result, fmt.Errorf("count legacy endpoints: %w", err)
	}
	result.NativeSessions, err = legacyDistinctCountIfPresent(db, tables, "fabric_endpoints", "native_session_id")
	if err != nil {
		return result, fmt.Errorf("count legacy native sessions: %w", err)
	}
	result.Goals, err = legacyCountIfPresent(db, tables, "goals")
	if err != nil {
		return result, fmt.Errorf("count legacy goals: %w", err)
	}
	result.Workers, err = legacyCountIfPresent(db, tables, "workers")
	if err != nil {
		return result, fmt.Errorf("count legacy workers: %w", err)
	}
	result.Approvals, err = legacyCountIfPresent(db, tables, "approvals")
	if err != nil {
		return result, fmt.Errorf("count legacy approvals: %w", err)
	}
	result.Contacts, err = legacyCountIfPresent(db, tables, "contacts")
	if err != nil {
		return result, fmt.Errorf("count legacy contacts: %w", err)
	}
	result.PeerSessions, err = legacyCountIfPresent(db, tables, "peer_sessions")
	if err != nil {
		return result, fmt.Errorf("count legacy peer sessions: %w", err)
	}
	result.PeerMessages, err = legacyCountIfPresent(db, tables, "peer_messages")
	if err != nil {
		return result, fmt.Errorf("count legacy peer messages: %w", err)
	}
	result.FabricMessages, err = legacyCountIfPresent(db, tables, "fabric_messages")
	if err != nil {
		return result, fmt.Errorf("count legacy fabric messages: %w", err)
	}
	result.FabricRequests, err = legacyDistinctCountIfPresent(db, tables, "fabric_messages", "request_id")
	if err != nil {
		return result, fmt.Errorf("count legacy fabric requests: %w", err)
	}
	result.RelayReceipts, err = legacyCountIfPresent(db, tables, "relay_v2_receipts")
	if err != nil {
		return result, fmt.Errorf("count relay receipts: %w", err)
	}
	result.GatewayRequests, err = legacyCountIfPresent(db, tables, "gateway_v2_requests")
	if err != nil {
		return result, fmt.Errorf("count gateway requests: %w", err)
	}
	result.GatewayResults, err = legacyCountIfPresent(db, tables, "gateway_v2_results")
	if err != nil {
		return result, fmt.Errorf("count gateway results: %w", err)
	}
	result.Groups, err = legacyCountIfPresent(db, tables, "groups")
	if err != nil {
		return result, fmt.Errorf("count groups: %w", err)
	}
	result.Principals, err = legacyCountIfPresent(db, tables, "principals")
	if err != nil {
		return result, fmt.Errorf("count principals: %w", err)
	}
	result.Memberships, err = legacyCountIfPresent(db, tables, "memberships")
	if err != nil {
		return result, fmt.Errorf("count memberships: %w", err)
	}
	result.Bindings, err = legacyCountIfPresent(db, tables, "session_bindings")
	if err != nil {
		return result, fmt.Errorf("count session bindings: %w", err)
	}
	return result, nil
}

func legacyCountIfPresent(db legacyInventoryQueryer, tables map[string]struct{}, table string) (int64, error) {
	if _, ok := tables[table]; !ok {
		return 0, nil
	}
	return legacyTableCount(db, table)
}

func legacyDistinctCountIfPresent(db legacyInventoryQueryer, tables map[string]struct{}, table, column string) (int64, error) {
	if _, ok := tables[table]; !ok {
		return 0, nil
	}
	columns, err := legacyTableColumns(db, table)
	if err != nil {
		return 0, err
	}
	if _, ok := columns[column]; !ok {
		return 0, nil
	}
	var count int64
	query := `SELECT count(DISTINCT ` + quoteLegacyInventoryIdentifier(column) + `) FROM ` + quoteLegacyInventoryIdentifier(table) + ` WHERE ` + quoteLegacyInventoryIdentifier(column) + ` IS NOT NULL AND ` + quoteLegacyInventoryIdentifier(column) + ` <> ''`
	if err := db.QueryRow(query).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func legacyTableColumns(db legacyInventoryQueryer, table string) (map[string]struct{}, error) {
	rows, err := db.Query(`PRAGMA table_info(` + quoteLegacyInventoryIdentifier(table) + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := make(map[string]struct{})
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return columns, nil
}

func legacyEndpointMappingSummary(db legacyInventoryQueryer, tables map[string]struct{}, total int64) (LegacyMigrationMappingSummary, error) {
	result := LegacyMigrationMappingSummary{Total: total, Pending: total}
	if _, ok := tables["fabric_endpoints"]; !ok || total == 0 {
		return result, nil
	}
	columns, err := legacyTableColumns(db, "fabric_endpoints")
	if err != nil {
		return result, fmt.Errorf("inspect endpoint mapping summary columns: %w", err)
	}
	for _, column := range []string{"principal_id", "group_id", "migration_state"} {
		if _, ok := columns[column]; !ok {
			return result, nil
		}
	}
	var ready int64
	if err := db.QueryRow(`SELECT count(*) FROM "fabric_endpoints" WHERE "migration_state" = ? AND "principal_id" <> '' AND "group_id" <> ''`, EndpointMigrationReady).Scan(&ready); err != nil {
		return result, fmt.Errorf("count ready endpoint mappings: %w", err)
	}
	result.Ready = ready
	result.Pending = total - ready
	return result, nil
}

func quoteLegacyInventoryIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

var legacyEndpointColumns = []string{
	"id", "name", "role", "harness", "native_session_id", "machine_id", "workspace", "goal_id",
	"status", "owner", "visibility", "principal_id", "group_id", "binding_id", "migration_state",
}

func legacyEndpointMappings(db legacyInventoryQueryer, tables map[string]struct{}, limit int) ([]LegacyEndpointMapping, error) {
	if _, ok := tables["fabric_endpoints"]; !ok {
		return []LegacyEndpointMapping{}, nil
	}
	columns, err := legacyTableColumns(db, "fabric_endpoints")
	if err != nil {
		return nil, fmt.Errorf("inspect legacy endpoint columns: %w", err)
	}
	if _, ok := columns["id"]; !ok {
		return nil, errors.New("legacy fabric_endpoints table has no id column")
	}
	selected := make([]string, 0, len(legacyEndpointColumns))
	for _, column := range legacyEndpointColumns {
		if _, ok := columns[column]; ok {
			selected = append(selected, column)
		}
	}
	quoted := make([]string, len(selected))
	for i, column := range selected {
		quoted[i] = quoteLegacyInventoryIdentifier(column)
	}
	query := `SELECT ` + strings.Join(quoted, ", ") + ` FROM "fabric_endpoints" ORDER BY "id"`
	args := []any{}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("read legacy endpoint mapping metadata: %w", err)
	}
	defer rows.Close()
	result := make([]LegacyEndpointMapping, 0)
	for rows.Next() {
		values := make([]sql.NullString, len(selected))
		destinations := make([]any, len(selected))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, fmt.Errorf("scan legacy endpoint mapping metadata: %w", err)
		}
		fields := make(map[string]string, len(selected))
		for i, column := range selected {
			if values[i].Valid {
				fields[column] = values[i].String
			}
		}
		endpoint := buildLegacyEndpointMapping(fields)
		result = append(result, endpoint)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read legacy endpoint mapping metadata: %w", err)
	}
	return result, nil
}

func buildLegacyEndpointMapping(fields map[string]string) LegacyEndpointMapping {
	endpoint := LegacyEndpointMapping{
		EndpointID: fields["id"], Name: fields["name"], Role: fields["role"], Harness: fields["harness"],
		NativeSessionID: fields["native_session_id"], MachineID: fields["machine_id"], Workspace: fields["workspace"],
		GoalID: fields["goal_id"], Status: fields["status"], Owner: fields["owner"], Visibility: fields["visibility"],
		PrincipalID: fields["principal_id"], GroupID: fields["group_id"], BindingID: fields["binding_id"],
		MigrationState: fields["migration_state"],
	}
	if endpoint.MigrationState == EndpointMigrationReady && endpoint.PrincipalID != "" && endpoint.GroupID != "" {
		endpoint.MappingState = LegacyMappingReady
	} else {
		endpoint.MappingState = LegacyMappingPending
	}
	if endpoint.PrincipalID != "" {
		endpoint.OwnerDecision = LegacyOwnerDecisionExplicitPrincipal
	} else if endpoint.Owner != "" {
		endpoint.OwnerDecision = LegacyOwnerDecisionNeedsExplicitPrincipal
	} else {
		endpoint.OwnerDecision = LegacyOwnerDecisionMissing
	}
	if endpoint.GroupID != "" {
		endpoint.GroupDecision = LegacyGroupDecisionExplicit
	} else {
		endpoint.GroupDecision = LegacyGroupDecisionMissing
	}
	if endpoint.MappingState == LegacyMappingPending {
		if endpoint.PrincipalID == "" {
			if endpoint.Owner == "" {
				endpoint.PendingReasons = append(endpoint.PendingReasons, LegacyMappingReasonMissingOwnerDecision)
			} else {
				endpoint.PendingReasons = append(endpoint.PendingReasons, LegacyMappingReasonOwnerNeedsExplicitID)
			}
		}
		if endpoint.GroupID == "" {
			endpoint.PendingReasons = append(endpoint.PendingReasons, LegacyMappingReasonMissingGroupDecision)
		}
		if endpoint.MigrationState != EndpointMigrationReady {
			endpoint.PendingReasons = append(endpoint.PendingReasons, LegacyMappingReasonMigrationStateNotReady)
		}
	}
	return endpoint
}
