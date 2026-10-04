package control

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
	"github.com/gofrs/flock"
)

func TestHubRestoreHoldMaintenanceBusyAndConstructorCleanup(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	lease := flock.New(state, flock.SetFlag(os.O_RDONLY))
	ok, err := lease.TryLock()
	if err != nil || !ok {
		t.Fatalf("fixture lock: %v", err)
	}
	defer lease.Close()
	workspace := filepath.Join(root, "workspace")
	c, err := New(Config{StateDir: state, WorkspaceRoot: workspace})
	if c != nil || !errors.Is(err, store.ErrStateMaintenanceBusy) {
		t.Fatalf("busy Control: %v", err)
	}
	for _, path := range []string{workspace, filepath.Join(state, "cicada.sqlite3"), filepath.Join(state, "e2ee")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("busy Control wrote before ownership")
		}
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workspace, []byte("synthetic workspace obstacle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := New(Config{StateDir: state, WorkspaceRoot: workspace}); c != nil || err == nil {
		t.Fatal("invalid workspace accepted")
	}
	ok, err = lease.TryLock()
	if err != nil || !ok {
		t.Fatalf("constructor error stranded lock: %v", err)
	}
}

func TestHubRestoreHoldMaintenanceShutdownTimeoutAndRetry(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	c, err := New(Config{StateDir: state, WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	c.wg.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown did not wait for writer: %v", err)
	}
	lease := flock.New(state, flock.SetFlag(os.O_RDONLY))
	ok, err := lease.TryLock()
	if err != nil || ok {
		t.Fatalf("timeout released writer ownership: %v", err)
	}
	c.wg.Done()
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	ok, err = lease.TryLock()
	if err != nil || !ok {
		t.Fatalf("safe shutdown retry stranded writer ownership: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHubRestoreHoldControlStartupBeforeAnyWrites(t *testing.T) {
	root := t.TempDir()
	source, archive, target := filepath.Join(root, "source"), filepath.Join(root, "archive"), filepath.Join(root, "target")
	db, err := store.New(filepath.Join(source, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BackupStateDir(source, archive); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreStateDir(archive, target); err != nil {
		t.Fatal(err)
	}
	before := hubRestoreControlFiles(t, target)
	workspace := filepath.Join(root, "must-not-create-workspace")
	c, err := New(Config{StateDir: target, WorkspaceRoot: workspace})
	if c != nil || !errors.Is(err, store.ErrStateRestoreQuarantined) {
		t.Fatalf("held Control constructor: %v", err)
	}
	if _, err := os.Lstat(workspace); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("held startup created workspace")
	}
	if _, err := os.Lstat(filepath.Join(target, "e2ee")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("held startup created a trust identity")
	}
	after := hubRestoreControlFiles(t, target)
	if len(before) != len(after) {
		t.Fatal("held startup created files")
	}
	for path, digest := range before {
		if after[path] != digest {
			t.Fatal("held startup changed restored bytes")
		}
	}
	ordinary := filepath.Join(root, "ordinary")
	c, err = New(Config{StateDir: ordinary, WorkspaceRoot: filepath.Join(root, "ordinary-workspace")})
	if err != nil {
		t.Fatalf("ordinary constructor regression: %v", err)
	}
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ordinary, "e2ee", "identity.json")); err != nil {
		t.Fatal("ordinary identity unavailable")
	}
}

func hubRestoreControlFiles(t *testing.T, root string) map[string][32]byte {
	t.Helper()
	files := map[string][32]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[path] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
