package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"

	"github.com/cicada-ai/cicada/internal/apppaths"
)

const mcpOutboxConnectionFormat = "cicada.mcp-outbox-connection.v1"

func mcpOutboxSQLiteURI(path, query string) string {
	return (&url.URL{Scheme: "file", Path: path, RawQuery: query}).String()
}

func (s *mcpOutboxStore) connectionFence(db *sql.DB) error {
	var exists int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='mcp_outbox_connection_pin'").Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		if s.connectionPin != nil {
			return ErrLocalNodeConfigRequired
		}
		return nil
	}
	if s.connectionPin == nil {
		return ErrLocalNodeConfigRequired
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM mcp_outbox_connection_pin").Scan(&count); err != nil || count != 1 {
		return ErrLocalNodeDiscoveryInvalid
	}
	var format string
	var data []byte
	if err := db.QueryRow("SELECT format,CASE WHEN length(pin)<=65536 THEN pin ELSE NULL END FROM mcp_outbox_connection_pin WHERE slot=1").Scan(&format, &data); err != nil || format != mcpOutboxConnectionFormat {
		return ErrLocalNodeDiscoveryInvalid
	}
	var pin LocalNodeConnectionPin
	if decodeLocalNodeJSON(data, &pin) != nil || validateLocalNodePin(pin) != nil {
		return ErrLocalNodeDiscoveryInvalid
	}
	if pin != *s.connectionPin {
		return ErrLocalNodeBindingChanged
	}
	return nil
}

func (s *mcpOutboxStore) connectionDirectory() error {
	dir := filepath.Dir(s.path)
	if s.connectionPin == nil {
		return ensureMCPPrivateDir(dir)
	}
	if _, err := apppaths.ResolveUserRoot(dir); err != nil {
		return ErrLocalNodeDiscoveryInvalid
	}
	return os.MkdirAll(dir, 0700) // Never chmod an existing installation root.
}

// The pin is committed to the main DB before enabling WAL, and never updated.
// immutable=1 lets us reject an old/unfenced DB without creating SHM, replaying
// a journal, changing permissions, or altering its original uncertain rows.
func (s *mcpOutboxStore) prepareConnectionDB() (os.FileInfo, error) {
	if s.path == ":memory:" {
		if s.connectionPin != nil {
			return nil, ErrLocalNodeConfigRequired
		}
		return nil, nil
	}
	info, err := os.Lstat(s.path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrLocalNodeDiscoveryInvalid
		}
		if s.connectionPin != nil && !localNodePrivate(info, false) {
			return nil, ErrLocalNodeDiscoveryInvalid
		}
		db, err := sql.Open("sqlite", mcpOutboxSQLiteURI(s.path, "mode=ro&immutable=1"))
		if err != nil {
			return nil, err
		}
		err = s.connectionFence(db)
		closeErr := db.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return nil, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if s.connectionPin == nil {
		return nil, nil
	}
	if validateLocalNodePin(*s.connectionPin) != nil || s.connectionPin.MCPOutboxStateFile != s.path {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(s.path + suffix); !errors.Is(err, os.ErrNotExist) {
			return nil, ErrLocalNodeConfigRequired
		}
	}
	if err := s.connectionDirectory(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, ErrLocalNodeConfigRequired
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	return info, nil
}

func (s *mcpOutboxStore) initializeConnectionDB(db *sql.DB, created os.FileInfo) error {
	current, err := os.Lstat(s.path)
	if err != nil || !os.SameFile(created, current) || !localNodePrivate(current, false) {
		return ErrLocalNodeDiscoveryInvalid
	}
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, statement := range []string{"PRAGMA busy_timeout = 5000", "PRAGMA synchronous = FULL", "BEGIN IMMEDIATE"} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	defer conn.ExecContext(ctx, "ROLLBACK")
	var tables int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
		return err
	}
	if tables != 0 {
		return ErrLocalNodeConfigRequired
	}
	if _, err := conn.ExecContext(ctx, "CREATE TABLE mcp_outbox_connection_pin (slot INTEGER PRIMARY KEY CHECK(slot=1), format TEXT NOT NULL, pin TEXT NOT NULL)"); err != nil {
		return err
	}
	data, err := json.Marshal(s.connectionPin)
	if err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "INSERT INTO mcp_outbox_connection_pin(slot,format,pin) VALUES(1,?,?)", mcpOutboxConnectionFormat, string(data)); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	current, err = os.Lstat(s.path)
	if err != nil || !os.SameFile(created, current) {
		return ErrLocalNodeDiscoveryInvalid
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
