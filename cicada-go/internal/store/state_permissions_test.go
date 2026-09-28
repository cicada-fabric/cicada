package store

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNewProtectsSQLiteStateDespitePermissiveUmask(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	dbPath := filepath.Join(stateDir, "cicada.sqlite3")
	oldUmask := syscall.Umask(0o022)
	defer syscall.Umask(oldUmask)
	db, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, path := range []string{stateDir, dbPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s is readable outside the owner: mode=%v", path, info.Mode())
		}
	}
}

func TestNewTightensExistingSQLiteWithoutLosingState(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(stateDir, "cicada.sqlite3")
	first, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.db.Exec("CREATE TABLE permission_fixture (value TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.db.Exec("INSERT INTO permission_fixture(value) VALUES ('retained')"); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0o644); err != nil {
		t.Fatal(err)
	}
	walPath := dbPath + "-wal"
	if err := os.WriteFile(walPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var retained string
	if err := second.db.QueryRow("SELECT value FROM permission_fixture").Scan(&retained); err != nil || retained != "retained" {
		t.Fatalf("existing SQLite data changed: value=%q err=%v", retained, err)
	}
	for _, path := range []string{stateDir, dbPath, walPath} {
		info, err := os.Stat(path)
		if os.IsNotExist(err) && path == walPath {
			continue // SQLite may remove a checkpointed WAL.
		}
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s remains readable outside the owner: mode=%v", path, info.Mode())
		}
	}
}

func TestNewRejectsSQLiteSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside.sqlite3")
	if err := os.WriteFile(outside, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(stateDir, "cicada.sqlite3")); err != nil {
		t.Fatal(err)
	}
	if db, err := New(filepath.Join(stateDir, "cicada.sqlite3")); err == nil {
		_ = db.Close()
		t.Fatal("SQLite symlink was followed")
	}
}
