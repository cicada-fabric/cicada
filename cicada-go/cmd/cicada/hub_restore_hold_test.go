package main

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
	"github.com/gofrs/flock"
)

func TestHubRestoreHoldFabricMaintenanceBusyAndErrorCleanup(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	lease := flock.New(state, flock.SetFlag(os.O_RDONLY))
	ok, err := lease.TryLock()
	if err != nil || !ok {
		t.Fatalf("fixture lock: %v", err)
	}
	defer lease.Close()
	if err := serveFabricOnly("127.0.0.1", 65536, control.Config{StateDir: state}); !errors.Is(err, store.ErrStateMaintenanceBusy) {
		t.Fatalf("busy Fabric reached identity/listener: %v", err)
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatal("busy Fabric wrote StateDir")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := serveFabricOnly("127.0.0.1", 65536, control.Config{StateDir: state}); err == nil || !strings.Contains(err.Error(), "existing trusted identity") {
		t.Fatalf("ordinary missing identity: %v", err)
	}
	ok, err = lease.TryLock()
	if err != nil || !ok {
		t.Fatalf("Fabric identity failure stranded lock: %v", err)
	}
}

func TestHubRestoreHoldFabricStartupBeforeStoreIdentityAndListener(t *testing.T) {
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
	// The deliberately invalid port is never reached: the real constructor must
	// reject quarantine even though the archive has no existing identity.
	for _, lostMarker := range []bool{false, true} {
		if lostMarker {
			if err := os.Remove(filepath.Join(target, ".hub-restore-pending.json")); err != nil {
				t.Fatal(err)
			}
		}
		before := hubRestoreFabricFiles(t, target)
		err := serveFabricOnlyWithTransport("127.0.0.1", 65536, control.Config{StateDir: target}, nil)
		if !errors.Is(err, store.ErrStateRestoreQuarantined) {
			t.Fatalf("held Fabric constructor: %v", err)
		}
		after := hubRestoreFabricFiles(t, target)
		if len(before) != len(after) {
			t.Fatal("held startup created keys or SQLite sidecars")
		}
		for path, digest := range before {
			if after[path] != digest {
				t.Fatal("held startup changed restored bytes")
			}
		}
	}
	ordinary := filepath.Join(root, "ordinary")
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	data, err := identity.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ordinary, "e2ee"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ordinary, "e2ee", "identity.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	// An ordinary production Fabric server now requires independent Hub
	// setup; a crypto identity alone cannot create its human Owner.
	ordinaryStore, err := store.New(filepath.Join(ordinary, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ordinaryStore.InitializeHubOwnerLocal("Synthetic ordinary owner", "https://synthetic.invalid", false); err != nil {
		t.Fatal(err)
	}
	if err = ordinaryStore.Close(); err != nil {
		t.Fatal(err)
	}
	err = serveFabricOnly("127.0.0.1", 65536, control.Config{StateDir: ordinary})
	if err == nil || errors.Is(err, store.ErrStateRestoreQuarantined) || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("ordinary constructor did not reach bounded listener validation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ordinary, "cicada.sqlite3")); err != nil {
		t.Fatal("ordinary Fabric Store was not constructed")
	}
}

func hubRestoreFabricFiles(t *testing.T, root string) map[string][32]byte {
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
