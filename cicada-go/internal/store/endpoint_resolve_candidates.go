package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"time"
	"unicode"

	"modernc.org/sqlite"
)

const (
	endpointResolveCandidatePageSize  = 128
	endpointResolveCandidateScanLimit = 100_000
)

// ErrEndpointResolveCandidateLimit means the bounded name-scoped lookup could
// not prove a unique or ambiguous result. Callers must not pick a partial hit.
var ErrEndpointResolveCandidateLimit = errors.New("endpoint resolution candidate limit exceeded")

func init() {
	// SQLite's built-in NOCASE/lower functions are ASCII-only. Resolution names
	// are Unicode, so candidate filtering must be at least as broad as the Go
	// predicates used by the resolvers. The Go resolver remains the authority.
	sqlite.MustRegisterDeterministicScalarFunction("cicada_endpoint_resolve_name_candidate", 2,
		func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
			name, nameOK := args[0].(string)
			query, queryOK := args[1].(string)
			if !nameOK || !queryOK {
				return int64(0), nil
			}
			if strings.EqualFold(name, query) || strings.ToLower(name) == strings.ToLower(query) {
				return int64(1), nil
			}
			return int64(0), nil
		})
	sqlite.MustRegisterDeterministicScalarFunction("cicada_endpoint_resolve_machine_candidate", 2,
		func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
			machineID, machineOK := args[0].(string)
			query, queryOK := args[1].(string)
			if !machineOK || !queryOK {
				return int64(0), nil
			}
			if strings.EqualFold(machineID, query) || strings.ToLower(machineID) == strings.ToLower(query) ||
				strings.EqualFold(endpointResolveNormalizedMachine(machineID), query) {
				return int64(1), nil
			}
			return int64(0), nil
		})
}

const endpointResolveV2Columns = `e.id, e.name, e.role, e.harness, e.native_session_id, e.machine_id,
e.workspace, e.goal_id, e.status, e.capabilities_json, e.tags_json, e.owner, e.visibility,
e.joined_at, e.last_seen, e.created_at, e.updated_at, e.principal_id, e.group_id, e.binding_id, e.migration_state`

// ForEachEndpointV2ResolveCandidatePage holds one read transaction while it
// pages through a name-scoped candidate set. Eligibility is filtered before
// paging, and each callback receives only one fixed-size page and its decoded
// active bindings. Returning done stops the scan without materializing the
// full match set.
func (s *Store) ForEachEndpointV2ResolveCandidatePage(groupID, nodeID string, names []string,
	machineQuery, exactQuery string,
	visit func([]Endpoint, map[string]*SessionBinding, map[string]string) (done bool, err error)) error {
	groupID = strings.TrimSpace(groupID)
	nodeID = strings.TrimSpace(nodeID)
	names, err := endpointResolveCandidateNames(names)
	if err != nil {
		return err
	}
	if groupID == "" {
		return ErrEndpointNotFound
	}
	query := `SELECT ` + endpointResolveV2Columns + ` FROM fabric_endpoints e
JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=? AND eg.status='active'
JOIN memberships m ON m.principal_id=e.principal_id AND m.group_id=eg.group_id
JOIN principals p ON p.id=e.principal_id
JOIN groups g ON g.id=eg.group_id
WHERE m.status='active' AND p.status='active' AND g.state='ACTIVE'
  AND cicada_network_expiry_allows(m.expires_at, ?)=1
  AND e.migration_state=? AND e.status<>'left'
  AND EXISTS (SELECT 1 FROM session_bindings sb WHERE sb.endpoint_id=e.id
    AND sb.status IN ('active','leased','online','ready','acquired'))
  AND ` + endpointResolveNamePredicate("e.name", len(names))
	args := []any{groupID, now(), EndpointMigrationReady}
	for _, name := range names {
		args = append(args, name)
	}
	if machineQuery != "" {
		// Keep literal historical names containing '@' in the candidate
		// superset, while narrowing normal qualified spellings by machine.
		query += ` AND (cicada_endpoint_resolve_name_candidate(e.name, ?)=1
    OR cicada_endpoint_resolve_machine_candidate(e.machine_id, ?)=1)`
		args = append(args, exactQuery, machineQuery)
	}
	if nodeID != "" {
		query += ` AND e.machine_id=?`
		args = append(args, nodeID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forEachEndpointResolveCandidatePage(query, args, true, false, groupID, scanEndpointV2, visit)
}

// ForEachLegacyEndpointResolveCandidatePage pages only rows that can be
// visible to the legacy resolver. Private visibility, left state, and the
// candidate name are filtered before each page; the caller preserves its
// original exact/qualified/global Go matching and context narrowing.
func (s *Store) ForEachLegacyEndpointResolveCandidatePage(requesterOwner string, names []string,
	visit func([]Endpoint, map[string]*SessionBinding, map[string]string) (done bool, err error)) error {
	requesterOwner = strings.TrimSpace(requesterOwner)
	names, err := endpointResolveCandidateNames(names)
	if err != nil {
		return err
	}
	query := `SELECT ` + endpointColumns + ` FROM fabric_endpoints e
WHERE (e.migration_state IS NULL OR e.migration_state<>?) AND e.status<>'left'
  AND (?='' OR e.visibility<>'private' OR e.owner=?)
  AND ` + endpointResolveNamePredicate("e.name", len(names))
	args := []any{EndpointMigrationReady, requesterOwner, requesterOwner}
	for _, name := range names {
		args = append(args, name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forEachEndpointResolveCandidatePage(query, args, false, true, "", scanEndpoint, visit)
}

type endpointResolveQueryer interface {
	Query(string, ...any) (*sql.Rows, error)
}

func (s *Store) forEachEndpointResolveCandidatePage(query string, args []any, withBindings, withMachineNames bool, sourceGroup string,
	scan func(interface{ Scan(...any) error }) (*Endpoint, error),
	visit func([]Endpoint, map[string]*SessionBinding, map[string]string) (bool, error)) error {
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cursor string
	scanned := 0
	for {
		pageQuery := query
		pageArgs := append([]any(nil), args...)
		if cursor != "" {
			pageQuery += ` AND e.id COLLATE BINARY > ? COLLATE BINARY`
			pageArgs = append(pageArgs, cursor)
		}
		pageQuery += ` ORDER BY e.id COLLATE BINARY LIMIT ?`
		pageArgs = append(pageArgs, endpointResolveCandidatePageSize+1)
		rows, err := tx.Query(pageQuery, pageArgs...)
		if err != nil {
			return err
		}
		page := make([]Endpoint, 0, endpointResolveCandidatePageSize)
		hasMore := false
		for rows.Next() {
			endpoint, scanErr := scan(rows)
			if scanErr != nil {
				rows.Close()
				return scanErr
			}
			if len(page) == endpointResolveCandidatePageSize {
				hasMore = true
				break
			}
			page = append(page, *endpoint)
		}
		rowsErr := rows.Err()
		closeErr := rows.Close()
		if rowsErr != nil {
			return rowsErr
		}
		if closeErr != nil {
			return closeErr
		}
		rawCount := len(page)
		rawLast := ""
		if rawCount > 0 {
			rawLast = page[rawCount-1].ID
		}
		if sourceGroup != "" {
			page, err = endpointGroupsFilterDirectoryTx(tx, sourceGroup, page, time.Now().UTC())
			if err != nil {
				return err
			}
		}
		bindings := map[string]*SessionBinding{}
		if withBindings && len(page) > 0 {
			ids := make([]string, len(page))
			for i := range page {
				ids[i] = page[i].ID
			}
			bindings, err = listDirectoryActiveSessionBindings(tx, ids)
			if err != nil {
				return err
			}
		}
		machineNames := map[string]string{}
		if withMachineNames && len(page) > 0 {
			ids := make([]string, len(page))
			for i := range page {
				ids[i] = page[i].MachineID
			}
			machineNames, err = listMachineNames(tx, ids)
			if err != nil {
				return err
			}
		}
		done, err := visit(page, bindings, machineNames)
		if err != nil {
			return err
		}
		if done || !hasMore {
			return tx.Commit()
		}
		scanned += rawCount
		if scanned >= endpointResolveCandidateScanLimit {
			return ErrEndpointResolveCandidateLimit
		}
		cursor = rawLast
	}
}

func listMachineNames(queryer endpointResolveQueryer, machineIDs []string) (map[string]string, error) {
	result := make(map[string]string)
	seen := make(map[string]struct{}, len(machineIDs))
	args := make([]any, 0, len(machineIDs))
	for _, id := range machineIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		args = append(args, id)
	}
	if len(args) == 0 {
		return result, nil
	}
	query := `SELECT id,name FROM machines WHERE id IN (` + strings.TrimSuffix(strings.Repeat(`?,`, len(args)), `,`) + `)`
	rows, err := queryer.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		result[id] = name
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// listDirectoryActiveSessionBindings is the transaction-aware implementation
// shared with the public batch lookup. The resolver calls it inside the same
// read snapshot as its candidate pages.
func listDirectoryActiveSessionBindings(queryer endpointResolveQueryer, endpointIDs []string) (map[string]*SessionBinding, error) {
	bindings := make(map[string]*SessionBinding)
	if len(endpointIDs) == 0 {
		return bindings, nil
	}
	args := make([]any, len(endpointIDs))
	for i, id := range endpointIDs {
		args[i] = strings.TrimSpace(id)
	}
	query := `WITH requested(endpoint_id) AS (VALUES ` + strings.TrimSuffix(strings.Repeat(`(?),`, len(args)), `,`) + `)
SELECT ` + sessionBindingColumns + ` FROM session_bindings WHERE id IN (
  SELECT (SELECT id FROM session_bindings
    WHERE endpoint_id = requested.endpoint_id
      AND status IN ('active', 'leased', 'online', 'ready', 'acquired')
    ORDER BY epoch DESC LIMIT 1)
  FROM requested
)`
	rows, err := queryer.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		binding, err := scanSessionBinding(rows)
		if err != nil {
			continue
		}
		bindings[binding.EndpointID] = binding
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bindings, nil
}

func endpointResolveCandidateNames(names []string) ([]string, error) {
	if len(names) == 0 || len(names) > 8 {
		return nil, errors.New("endpoint resolution requires between one and eight candidate names")
	}
	result := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	if len(result) == 0 {
		return nil, errors.New("endpoint resolution candidate names are empty")
	}
	return result, nil
}

func endpointResolveNamePredicate(column string, count int) string {
	parts := make([]string, count)
	for i := range parts {
		parts[i] = "cicada_endpoint_resolve_name_candidate(" + column + ", ?)=1"
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// Keep this candidate-only spelling in sync with fabric.normalizeName. The
// final resolver still compares its original NetworkCard address in Go.
func endpointResolveNormalizedMachine(value string) string {
	value = strings.TrimSpace(value)
	var result strings.Builder
	lastDash := false
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' || character == '.' {
			result.WriteRune(character)
			lastDash = false
			continue
		}
		if !lastDash {
			result.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(strings.ToLower(result.String()), "-.")
}
