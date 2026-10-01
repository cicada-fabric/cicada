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
