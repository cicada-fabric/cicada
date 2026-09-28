package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const (
	networkMigrationMaxTables      = 512
	networkMigrationMaxGroupDetail = 64
)

// NetworkMigrationReport is a read-only inventory from one SQLite snapshot.
// It reports counts and digests over safe identifiers only; message bodies,
// grants, key material, credential hashes, invitation tokens and free-form
// mapping reasons are never selected.
type NetworkMigrationReport struct {
	SchemaVersion        int                              `json:"schema_version"`
	Phase                string                           `json:"phase"`
	GroupCount           int64                            `json:"group_count"`
	GroupDetailsOmitted  int64                            `json:"group_details_omitted"`
	GroupInventoryDigest string                           `json:"group_inventory_digest"`
	Groups               []NetworkMigrationGroupImpact    `json:"groups"`
	Tables               []NetworkMigrationTableInventory `json:"tables"`
	UnmappedCount        int64                            `json:"unmapped_count"`
	PendingCount         int64                            `json:"pending_count"`
	ApprovedCount        int64                            `json:"approved_count"`
	ActiveMemberships    int64                            `json:"active_memberships"`
	CrossOwnerGroups     int64                            `json:"cross_owner_groups"`
	Links                int64                            `json:"links"`
	KeyGrants            int64                            `json:"key_grants"`
	PendingReceipts      int64                            `json:"pending_receipts"`
}

type NetworkMigrationGroupImpact struct {
	GroupID       string                              `json:"group_id"`
	NetworkID     string                              `json:"network_id,omitempty"`
	State         string                              `json:"state"`
	GroupVersion  int64                               `json:"group_version"`
	GroupRevision int64                               `json:"group_revision"`
	Relations     []NetworkMigrationRelationInventory `json:"relations,omitempty"`
}

type NetworkMigrationRelationInventory struct {
	Table  string `json:"table"`
	Column string `json:"column"`
	Rows   int64  `json:"rows"`
}

type NetworkMigrationTableInventory struct {
	Table             string   `json:"table"`
	Rows              int64    `json:"rows"`
	IdentifierColumns []string `json:"identifier_columns,omitempty"`
	IdentifierDigest  string   `json:"identifier_digest,omitempty"`
}

// DryRunNetworkMigration holds the Store lock while it reads one database
// transaction. The transaction, rather than the Go mutex, supplies the
// snapshot boundary across separate Store handles.
func (s *Store) DryRunNetworkMigration() (*NetworkMigrationReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	report, err := buildNetworkMigrationReportSnapshot(tx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return report, nil
}

// InspectNetworkMigrationReadOnly opens an existing current-schema database
// with SQLite read-only mode. It never initializes or migrates the source.
func InspectNetworkMigrationReadOnly(dbPath string) (*NetworkMigrationReport, error) {
	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrNetworkMigration
	}
	uri := (&url.URL{Scheme: "file", Path: absPath, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	report, err := buildNetworkMigrationReportSnapshot(tx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return report, nil
}

func buildNetworkMigrationReportSnapshot(tx *sql.Tx) (*NetworkMigrationReport, error) {
	var state string
	if err := tx.QueryRow(`SELECT state FROM schema_migrations_v2 WHERE version=?`, CurrentV2SchemaVersion).Scan(&state); err != nil || state != v2MigrationApplied {
		return nil, fmt.Errorf("network migration inventory requires applied v%d schema: %w", CurrentV2SchemaVersion, ErrNetworkMigration)
	}
	report := &NetworkMigrationReport{SchemaVersion: CurrentV2SchemaVersion, Groups: []NetworkMigrationGroupImpact{}, Tables: []NetworkMigrationTableInventory{}}
	if err := tx.QueryRow(`SELECT phase FROM network_mode_v2 WHERE id=1`).Scan(&report.Phase); err != nil {
		return nil, err
	}
	if err := networkMigrationReadGroups(tx, report); err != nil {
		return nil, err
	}
	if err := networkMigrationInventoryTables(tx, report); err != nil {
		return nil, err
	}
	if err := networkMigrationGroupRelations(tx, report); err != nil {
		return nil, err
	}
	for _, item := range []struct {
		dest  *int64
		query string
	}{
		{&report.ActiveMemberships, `SELECT COUNT(*) FROM memberships WHERE status='active'`},
		{&report.CrossOwnerGroups, `SELECT COUNT(DISTINCT g.id) FROM groups g JOIN memberships m ON m.group_id=g.id JOIN principals p ON p.id=m.principal_id WHERE m.status='active' AND p.owner_id<>g.owner_principal_id`},
		{&report.Links, `SELECT COUNT(*) FROM communication_links_v2 WHERE state='PROPOSED'`},
		{&report.KeyGrants, `SELECT COUNT(*) FROM group_endpoint_key_grants_v2`},
		{&report.PendingReceipts, `SELECT COUNT(*) FROM relay_v2_inbox WHERE state IN ('READY','CLAIMED','INJECTION_UNCERTAIN')`},
	} {
		if err := tx.QueryRow(item.query).Scan(item.dest); err != nil {
			return nil, err
		}
	}
	return report, nil
}

func networkMigrationReadGroups(tx *sql.Tx, report *NetworkMigrationReport) error {
	rows, err := tx.Query(`SELECT g.id,g.network_id,g.version,g.revision,
COALESCE(m.network_id,''),COALESCE(m.state,'')
FROM groups g LEFT JOIN network_group_mappings_v2 m ON m.group_id=g.id ORDER BY g.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	digest := sha256.New()
	for rows.Next() {
		var g NetworkMigrationGroupImpact
		var assigned, candidate string
		if err := rows.Scan(&g.GroupID, &assigned, &g.GroupVersion, &g.GroupRevision, &candidate, &g.State); err != nil {
			return err
		}
		g.NetworkID = candidate
		if g.State == "" && assigned != "" {
			g.NetworkID = assigned
			g.State = NetworkMapApproved
		}
		writeNetworkMigrationFrame(digest, []byte(g.GroupID))
		writeNetworkMigrationFrame(digest, []byte(g.NetworkID))
		writeNetworkMigrationFrame(digest, []byte(g.State))
		writeNetworkMigrationFrame(digest, []byte(fmt.Sprintf("%d:%d", g.GroupVersion, g.GroupRevision)))
		report.GroupCount++
		switch g.State {
		case NetworkMapPending:
			report.PendingCount++
		case NetworkMapApproved:
			report.ApprovedCount++
		default:
			report.UnmappedCount++
		}
		if len(report.Groups) < networkMigrationMaxGroupDetail {
			report.Groups = append(report.Groups, g)
		} else {
			report.GroupDetailsOmitted++
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	report.GroupInventoryDigest = hex.EncodeToString(digest.Sum(nil))
	return rows.Close()
}

type networkMigrationColumn struct {
	Name       string
	PrimaryKey int
}

func networkMigrationInventoryTables(tx *sql.Tx, report *NetworkMigrationReport) error {
	rows, err := tx.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, name)
		if len(tables) > networkMigrationMaxTables {
			rows.Close()
			return fmt.Errorf("network migration inventory exceeds %d tables: %w", networkMigrationMaxTables, ErrNetworkMigration)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, table := range tables {
		quotedTable := networkMigrationQuoteIdentifier(table)
		var inventory NetworkMigrationTableInventory
		inventory.Table = table
		if err := tx.QueryRow(`SELECT COUNT(*) FROM ` + quotedTable).Scan(&inventory.Rows); err != nil {
			return err
		}
		columns, err := networkMigrationTableColumns(tx, table)
		if err != nil {
			return err
		}
		for _, column := range columns {
			if column.PrimaryKey > 0 && networkMigrationSafeIdentifierColumn(column.Name) {
				inventory.IdentifierColumns = append(inventory.IdentifierColumns, column.Name)
			}
		}
		sort.Slice(inventory.IdentifierColumns, func(i, j int) bool {
			return networkMigrationPrimaryKeyOrder(columns, inventory.IdentifierColumns[i]) < networkMigrationPrimaryKeyOrder(columns, inventory.IdentifierColumns[j])
		})
		if len(inventory.IdentifierColumns) > 0 {
			inventory.IdentifierDigest, err = networkMigrationIdentifierDigest(tx, table, inventory.IdentifierColumns)
			if err != nil {
				return err
			}
		}
		report.Tables = append(report.Tables, inventory)
	}
	return nil
}

func networkMigrationTableColumns(tx *sql.Tx, table string) ([]networkMigrationColumn, error) {
	rows, err := tx.Query(`PRAGMA table_info(` + networkMigrationQuoteIdentifier(table) + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var columns []networkMigrationColumn
	for rows.Next() {
		var sequence, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&sequence, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns = append(columns, networkMigrationColumn{Name: name, PrimaryKey: primaryKey})
	}
	return columns, rows.Err()
}

func networkMigrationPrimaryKeyOrder(columns []networkMigrationColumn, name string) int {
	for _, column := range columns {
		if column.Name == name {
			return column.PrimaryKey
		}
	}
	return 0
}

func networkMigrationSafeIdentifierColumn(name string) bool {
	lower := strings.ToLower(name)
	for _, sensitive := range []string{"key", "secret", "token", "credential", "nonce", "digest", "hash", "proof", "payload", "body", "content", "cipher", "signature", "private"} {
		if strings.Contains(lower, sensitive) {
			return false
		}
	}
	return lower == "id" || strings.HasSuffix(lower, "_id") || slices.Contains([]string{"version", "revision", "epoch", "sequence"}, lower)
}

func networkMigrationIdentifierDigest(tx *sql.Tx, table string, columns []string) (string, error) {
	quoted := make([]string, len(columns))
	for i, column := range columns {
		quoted[i] = networkMigrationQuoteIdentifier(column)
	}
	joined := strings.Join(quoted, ",")
	rows, err := tx.Query(`SELECT ` + joined + ` FROM ` + networkMigrationQuoteIdentifier(table) + ` ORDER BY ` + joined)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	digest := sha256.New()
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return "", err
		}
		for i, value := range values {
			writeNetworkMigrationFrame(digest, []byte(columns[i]))
			switch typed := value.(type) {
			case nil:
				writeNetworkMigrationFrame(digest, []byte("null"))
			case int64:
				writeNetworkMigrationFrame(digest, []byte(fmt.Sprintf("i:%d", typed)))
			case float64:
				writeNetworkMigrationFrame(digest, []byte(fmt.Sprintf("f:%g", typed)))
			case string:
				writeNetworkMigrationFrame(digest, []byte("s:"+typed))
			case []byte:
				writeNetworkMigrationFrame(digest, append([]byte("b:"), typed...))
			default:
				return "", fmt.Errorf("unsupported identifier value in %s.%s: %T", table, columns[i], value)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func networkMigrationGroupRelations(tx *sql.Tx, report *NetworkMigrationReport) error {
	if len(report.Groups) == 0 {
		return nil
	}
	groupIndexes := make(map[string]int, len(report.Groups))
	placeholders := make([]string, len(report.Groups))
	args := make([]any, len(report.Groups))
	for i, group := range report.Groups {
		groupIndexes[group.GroupID] = i
		placeholders[i] = "?"
		args[i] = group.GroupID
	}
	rows, err := tx.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, table := range tables {
		columns, err := networkMigrationTableColumns(tx, table)
		if err != nil {
			return err
		}
		for _, column := range columns {
			lower := strings.ToLower(column.Name)
			if lower != "group_id" && !strings.HasSuffix(lower, "_group_id") {
				continue
			}
			query := `SELECT ` + networkMigrationQuoteIdentifier(column.Name) + `,COUNT(*) FROM ` + networkMigrationQuoteIdentifier(table) +
				` WHERE ` + networkMigrationQuoteIdentifier(column.Name) + ` IN (` + strings.Join(placeholders, ",") + `) GROUP BY ` + networkMigrationQuoteIdentifier(column.Name)
			relationRows, err := tx.Query(query, args...)
			if err != nil {
				return err
			}
			for relationRows.Next() {
				var groupID string
				var count int64
				if err := relationRows.Scan(&groupID, &count); err != nil {
					relationRows.Close()
					return err
				}
				if count > 0 {
					index := groupIndexes[groupID]
					report.Groups[index].Relations = append(report.Groups[index].Relations,
						NetworkMigrationRelationInventory{Table: table, Column: column.Name, Rows: count})
				}
			}
			if err := relationRows.Err(); err != nil {
				relationRows.Close()
				return err
			}
			if err := relationRows.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}

func networkMigrationQuoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func writeNetworkMigrationFrame(destination interface{ Write([]byte) (int, error) }, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = destination.Write(size[:])
	_, _ = destination.Write(value)
}
