package nodekeys

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// OpenExistingCryptoState opens the live, already initialized private database,
// including its current WAL. It never creates a directory/database, changes
// permissions, migrates a schema or initializes identity/authorization state.
// Unlike the offline immutable reader, it may be used by a running Node.
func OpenExistingCryptoState(ctx context.Context, stateDir string) (*CryptoState, error) {
	if ctx == nil {
		return nil, errors.New("existing Node crypto state requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := cleanStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	if err := inspectExistingStateDirectory(root); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode().Perm() != cryptoStateMode {
		return nil, errors.New("existing Node crypto state directory must be private 0700")
	}
	path := filepath.Join(root, cryptoStateDBName)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect existing Node crypto database: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != cryptoDBMode {
		return nil, errors.New("existing Node crypto database must be a regular 0600 file")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		side, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !side.Mode().IsRegular() || side.Mode().Perm() != cryptoDBMode {
			return nil, errors.New("existing Node crypto sidecar must be a regular 0600 file")
		}
	}
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=rw"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	state := &CryptoState{db: db, existingOnly: true}
	conn, err := db.Conn(ctx)
	if err == nil {
		err = state.configureConnection(ctx, conn)
		if err == nil {
			var version int
			err = conn.QueryRowContext(ctx, `SELECT version FROM node_crypto_schema WHERE singleton=1`).Scan(&version)
			if err == nil && version != cryptoSchemaVersion {
				err = errors.New("existing Node crypto schema is unsupported; no migration performed")
			}
		}
		_ = conn.Close()
	}
	after, statErr := os.Lstat(path)
	if err == nil && (statErr != nil || !after.Mode().IsRegular() || after.Mode().Perm() != cryptoDBMode || !os.SameFile(before, after)) {
		err = errors.New("existing Node crypto database changed while opening")
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return state, nil
}

// Existing-only handles are read guards. Keep SQLite's lock wait within this
// call's budget without changing the normal writer/outbox configuration.
func (s *CryptoState) configureConnection(ctx context.Context, conn *sql.Conn) error {
	if !s.existingOnly {
		return configureCryptoConnection(ctx, conn)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := 100 // Even a context without a deadline cannot wait 30 seconds.
	if deadline, ok := ctx.Deadline(); ok {
		remaining := int(time.Until(deadline).Milliseconds())
		if remaining < timeout {
			timeout = max(0, remaining)
		}
	}
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA busy_timeout=%d`, timeout)); err != nil {
		return err
	}
	_, err := conn.ExecContext(ctx, `PRAGMA query_only=ON`)
	return err
}
