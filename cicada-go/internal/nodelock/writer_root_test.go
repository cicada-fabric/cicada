package nodelock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriterRootSharedAgentsCoexistAndOfflineLockIsImmediate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "writer-root")
	first, err := AcquireWriterRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := AcquireWriterRoot(root)
	if err != nil {
		t.Fatalf("second Hub Agent could not share WriterRoot: %v", err)
	}
	defer second.Close()
	if _, err := AcquireWriterRootExclusive(root); !errors.Is(err, ErrBusy) {
		t.Fatalf("exclusive backup lock error=%v, want ErrBusy", err)
	}
}

func TestWriterRootExclusiveBlocksSharedAndReleases(t *testing.T) {
	root := filepath.Join(t.TempDir(), "writer-root")
	exclusive, err := AcquireWriterRootExclusive(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireWriterRoot(root); err == nil {
		t.Fatal("Agent acquired shared WriterRoot lock during offline maintenance")
	}
	if err := exclusive.Close(); err != nil {
		t.Fatal(err)
	}
	shared, err := AcquireWriterRoot(root)
	if err != nil {
		t.Fatalf("Agent could not acquire WriterRoot lock after maintenance: %v", err)
	}
	_ = shared.Close()
}

func TestWriterRootRejectsUnsafeRootAndLockPath(t *testing.T) {
	t.Run("symlink root", func(t *testing.T) {
		base := t.TempDir()
		target := filepath.Join(base, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(base, "alias")
		if err := os.Symlink(target, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := AcquireWriterRoot(alias); err == nil {
			t.Fatal("accepted symlink WriterRoot")
		}
	})
	t.Run("symlink lock", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "writer-root")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "external-lock")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, writerRootMaintenanceName)); err != nil {
			t.Fatal(err)
		}
		if _, err := AcquireWriterRoot(root); err == nil {
			t.Fatal("accepted symlink WriterRoot lock path")
		}
	})
}

func TestExistingWriterRootInspectionNeverCreatesOrRepairs(t *testing.T) {
	for _, kind := range []string{"missing root", "missing file", "public root", "public file", "symlink root", "symlink ancestor", "symlink file", "directory file"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "writer-root")
			lock, err := AcquireWriterRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			_ = lock.Close()
			path := filepath.Join(root, writerRootMaintenanceName)
			if err := os.WriteFile(path, []byte("synthetic-writer-lock"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing root":
				err = os.RemoveAll(root)
			case "missing file":
				err = os.Remove(path)
			case "public root":
				err = os.Chmod(root, 0o755)
			case "public file":
				err = os.Chmod(path, 0o644)
			case "symlink root":
				err = os.Rename(root, filepath.Join(base, "original"))
				if err == nil {
					err = os.Symlink(filepath.Join(base, "original"), root)
				}
			case "symlink ancestor":
				err = os.Symlink(root, filepath.Join(base, "alias"))
				root = filepath.Join(base, "alias", "child")
			case "symlink file", "directory file":
				err = os.Rename(path, filepath.Join(base, "original"))
				if err == nil {
					if kind == "symlink file" {
						err = os.Symlink(filepath.Join(base, "original"), path)
					} else {
						err = os.Mkdir(path, 0o700)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before := snapshotInspectionLocks(t, base)
			if lock, err := AcquireWriterRootExclusiveExisting(root); err == nil {
				_ = lock.Close()
				t.Fatal("accepted missing/unsafe WriterRoot lock")
			}
			assertInspectionLocksUnchanged(t, base, before)
		})
	}
}

func TestExistingWriterRootInspectionExcludesPeersWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "writer-root")
	peer, err := AcquireWriterRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotInspectionLocks(t, root)
	requirePromptLockError(t, func() (*Lock, error) { return AcquireWriterRootExclusiveExisting(root) }, ErrBusy)
	_ = peer.Close()
	inspect, err := AcquireWriterRootExclusiveExisting(root)
	if err != nil {
		t.Fatal(err)
	}
	requirePromptLockError(t, func() (*Lock, error) { return AcquireWriterRoot(root) }, ErrBusy)
	_ = inspect.Close()
	peer, err = AcquireWriterRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	assertInspectionLocksUnchanged(t, root, before)
}
