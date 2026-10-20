package nodekeys

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenExistingCryptoStateNeverCreatesRepairsOrMigrates(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	if _, err := OpenExistingCryptoState(context.Background(), root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing directory did not fail", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created missing state")
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, cryptoStateDBName)
	if _, err := OpenExistingCryptoState(context.Background(), root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing database did not fail", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created missing database")
	}
	state, err := OpenCryptoState(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		path string
		mode os.FileMode
	}{{root, 0755}, {path, 0644}} {
		if err := os.Chmod(bad.path, bad.mode); err != nil {
			t.Fatal(err)
		}
		if s, err := OpenExistingCryptoState(context.Background(), root); err == nil {
			s.Close()
			t.Fatal("accepted unprivate existing state")
		}
		info, _ := os.Lstat(bad.path)
		if info.Mode().Perm() != bad.mode {
			t.Fatal("silently repaired permissions")
		}
		good := os.FileMode(0600)
		if bad.path == root {
			good = 0700
		}
		if err := os.Chmod(bad.path, good); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE node_crypto_schema SET version=5`); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenExistingCryptoState(context.Background(), root); err == nil {
		s.Close()
		t.Fatal("migrated older schema")
	}
	var version int
	if err := db.QueryRow(`SELECT version FROM node_crypto_schema`).Scan(&version); err != nil || version != 5 {
		t.Fatal("changed schema", err)
	}
}

func TestOpenExistingCryptoStateSeesLiveWALAndCannotWrite(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	writer, err := OpenCryptoState(root)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.ReserveOutboundSequence(context.Background(), "synthetic-endpoint", "synthetic-key"); err != nil {
		t.Fatal(err)
	}
	wal, err := os.Stat(filepath.Join(root, cryptoStateDBName) + "-wal")
	if err != nil || wal.Size() == 0 {
		t.Fatal("fixture has no active WAL", err)
	}
	reader, err := OpenExistingCryptoState(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var sequence uint64
	if err := reader.db.QueryRow(`SELECT last_sequence FROM node_crypto_sequences WHERE endpoint_id='synthetic-endpoint'`).Scan(&sequence); err != nil || sequence != 1 {
		t.Fatal("live WAL value unavailable", err)
	}
	if _, err := reader.db.Exec(`DELETE FROM node_crypto_sequences`); err == nil {
		t.Fatal("existing guard permitted writes")
	}
	if _, err := writer.ReserveOutboundSequence(context.Background(), "synthetic-endpoint", "synthetic-key"); err != nil {
		t.Fatal(err)
	}
	if err := reader.db.QueryRow(`SELECT last_sequence FROM node_crypto_sequences WHERE endpoint_id='synthetic-endpoint'`).Scan(&sequence); err != nil || sequence != 2 {
		t.Fatal("reader became immutable snapshot", err)
	}
}

func TestOpenExistingCryptoStateContextAndBusyBudget(t *testing.T) {
	root := t.TempDir()
	state, err := OpenCryptoState(root)
	if err != nil {
		t.Fatal(err)
	}
	state.Close()
	db, err := sql.Open("sqlite", filepath.Join(root, cryptoStateDBName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=DELETE`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ROLLBACK`)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if reader, err := OpenExistingCryptoState(ctx, root); err == nil {
		reader.Close()
		t.Fatal("exclusive lock ignored")
	}
	if time.Since(start) > time.Second {
		t.Fatal("existing reader inherited 30-second busy timeout")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := OpenExistingCryptoState(canceled, root); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored canceled context", err)
	}
}
