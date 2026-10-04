package nodelock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgentWriterAndOfflineMaintenanceLocking(t *testing.T) {
	stateDir := t.TempDir()
	const nodeID = "node/a"

	agent, err := AcquireAgent(stateDir, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	nodeDir := filepath.Join(stateDir, "nodes", "node-node%2Fa")
	if _, err := os.Stat(nodeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("acquiring locks created the Node subtree: stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "nodes", ".locks", "node-node%2Fa.maintenance.lock")); err != nil {
		t.Fatalf("maintenance lock is not outside the Node subtree: %v", err)
	}

	if _, err := AcquireAgent(stateDir, nodeID); !errors.Is(err, ErrAgentRunning) {
		t.Fatalf("duplicate Agent error=%v, want ErrAgentRunning", err)
	}

	writer, err := AcquireMaintenance(stateDir, nodeID)
	if err != nil {
		t.Fatalf("direct writer could not share the live Agent maintenance lock: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireMaintenanceExclusive(stateDir, nodeID); !errors.Is(err, ErrBusy) {
		t.Fatalf("offline maintenance while Agent is live error=%v, want ErrBusy", err)
	}

	if err := agent.Close(); err != nil {
		t.Fatal(err)
	}
	exclusive, err := AcquireMaintenanceExclusive(stateDir, nodeID)
	if err != nil {
		t.Fatalf("offline maintenance could not acquire released Node: %v", err)
	}
	defer exclusive.Close()
	if _, err := AcquireMaintenanceExclusive(stateDir, nodeID); !errors.Is(err, ErrBusy) {
		t.Fatalf("second offline maintainer error=%v, want ErrBusy", err)
	}
}

func TestLocksCanonicalizeStateDirectoryAliases(t *testing.T) {
	root := t.TempDir()
	alias := filepath.Join(t.TempDir(), "state-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Skipf("symlink setup is unavailable: %v", err)
	}

	agent, err := AcquireAgent(root, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	if _, err := AcquireAgent(alias, "node-a"); !errors.Is(err, ErrAgentRunning) {
		t.Fatalf("Agent acquired through a state-directory alias: %v", err)
	}
}

func TestLockInputsMustHaveCanonicalNodeID(t *testing.T) {
	if _, err := AcquireMaintenance(t.TempDir(), " node-a "); err == nil {
		t.Fatal("lock accepted a noncanonical Node ID")
	}
	if _, err := AcquireMaintenance(" ", "node-a"); err == nil {
		t.Fatal("lock accepted an empty state directory")
	}
}

func TestAgentSingletonLockRejectsAnotherProcess(t *testing.T) {
	if os.Getenv("CICADA_NODELOCK_CHILD") == "1" {
		stateDir := os.Getenv("CICADA_NODELOCK_STATE_DIR")
		nodeID := os.Getenv("CICADA_NODELOCK_NODE_ID")
		if _, err := AcquireAgent(stateDir, nodeID); !errors.Is(err, ErrAgentRunning) {
			t.Fatalf("child Agent error=%v, want ErrAgentRunning", err)
		}
		return
	}

	stateDir := t.TempDir()
	const nodeID = "node-subprocess"
	held, err := AcquireAgent(stateDir, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	command := exec.Command(os.Args[0], "-test.run=^TestAgentSingletonLockRejectsAnotherProcess$")
	command.Env = append(os.Environ(),
		"CICADA_NODELOCK_CHILD=1",
		"CICADA_NODELOCK_STATE_DIR="+stateDir,
		"CICADA_NODELOCK_NODE_ID="+nodeID,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("child Agent did not reject the held singleton lock: %v: %s", err, strings.TrimSpace(string(output)))
	}
}

// Capture entries, bytes, complete modes and inode identities, including dirs
// and symlinks. This catches creation, permission repair and inode replacement.
type inspectionLockSnapshot struct {
	info os.FileInfo
	data string
}

func snapshotInspectionLocks(t *testing.T, root string) map[string]inspectionLockSnapshot {
	t.Helper()
	result := map[string]inspectionLockSnapshot{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		var data []byte
		if info.Mode().IsRegular() {
			data, err = os.ReadFile(path)
		} else if info.Mode()&os.ModeSymlink != 0 {
			var target string
			target, err = os.Readlink(path)
			data = []byte(target)
		}
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[rel] = inspectionLockSnapshot{info: info, data: string(data)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertInspectionLocksUnchanged(t *testing.T, root string, before map[string]inspectionLockSnapshot) {
	t.Helper()
	after := snapshotInspectionLocks(t, root)
	if len(before) != len(after) {
		t.Fatalf("inspection changed entries: %d -> %d", len(before), len(after))
	}
	for path, b := range before {
		a, ok := after[path]
		if !ok || b.data != a.data || b.info.Mode() != a.info.Mode() || !os.SameFile(b.info, a.info) || !b.info.ModTime().Equal(a.info.ModTime()) {
			t.Fatalf("inspection changed %s", path)
		}
	}
}

func requirePromptLockError(t *testing.T, acquire func() (*Lock, error), want error) {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		lock, err := acquire()
		if lock != nil {
			_ = lock.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, want) {
			t.Fatalf("lock error=%v, want %v", err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inspection lock waited instead of returning busy")
	}
}

func TestExistingNodeInspectionLocksNeverCreateOrRepair(t *testing.T) {
	for _, kind := range []string{"missing nodes", "missing locks", "missing file", "public nodes", "public locks", "public file", "symlink file", "directory file", "symlink locks"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			lock, err := AcquireMaintenanceExclusive(root, "synthetic-inspect")
			if err != nil {
				t.Fatal(err)
			}
			_ = lock.Close()
			nodes := filepath.Join(root, "nodes")
			locks := filepath.Join(nodes, ".locks")
			path := filepath.Join(locks, "node-synthetic-inspect.maintenance.lock")
			if err := os.WriteFile(path, []byte("synthetic-lock-sentinel"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing nodes":
				err = os.RemoveAll(nodes)
			case "missing locks":
				err = os.RemoveAll(locks)
			case "missing file":
				err = os.Remove(path)
			case "public nodes":
				err = os.Chmod(nodes, 0o755)
			case "public locks":
				err = os.Chmod(locks, 0o755)
			case "public file":
				err = os.Chmod(path, 0o644)
			case "symlink file", "directory file":
				err = os.Rename(path, filepath.Join(root, "original"))
				if err == nil {
					if kind == "symlink file" {
						err = os.Symlink(filepath.Join(root, "original"), path)
					} else {
						err = os.Mkdir(path, 0o700)
					}
				}
			case "symlink locks":
				err = os.Rename(locks, filepath.Join(root, "original-locks"))
				if err == nil {
					err = os.Symlink(filepath.Join(root, "original-locks"), locks)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before := snapshotInspectionLocks(t, root)
			if lock, err := AcquireMaintenanceExclusiveExisting(root, "synthetic-inspect"); err == nil {
				_ = lock.Close()
				t.Fatal("accepted missing/unsafe lock state")
			}
			assertInspectionLocksUnchanged(t, root, before)
		})
	}
}

func TestExistingNodeInspectionLocksContendThroughAliasesAndRelease(t *testing.T) {
	root := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	agent, err := AcquireAgent(root, "synthetic-inspect")
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotInspectionLocks(t, root)
	requirePromptLockError(t, func() (*Lock, error) { return AcquireMaintenanceExclusiveExisting(alias, "synthetic-inspect") }, ErrBusy)
	assertInspectionLocksUnchanged(t, root, before)
	_ = agent.Close()
	exclusive, err := AcquireMaintenanceExclusiveExisting(alias, "synthetic-inspect")
	if err != nil {
		t.Fatal(err)
	}
	requirePromptLockError(t, func() (*Lock, error) { return AcquireMaintenanceExclusiveExisting(root, "synthetic-inspect") }, ErrBusy)
	_ = exclusive.Close()
	writer, err := AcquireMaintenance(root, "synthetic-inspect")
	if err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	assertInspectionLocksUnchanged(t, root, before)
}

func TestExistingInspectionRejectsInodeSwapBeforeAndAfterOpen(t *testing.T) {
	for _, stage := range []string{"before open", "after open"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "maintenance.lock")
			if err := os.WriteFile(path, []byte("synthetic-original"), 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := existingPrivateLockInfo(path)
			if err != nil {
				t.Fatal(err)
			}
			var held *Lock
			if stage == "after open" {
				held, err = acquireExistingExclusiveLock(path, before)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
			}
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("synthetic-replacement"), 0o600); err != nil {
				t.Fatal(err)
			}
			snapshot := snapshotInspectionLocks(t, root)
			if stage == "before open" {
				if lock, err := acquireExistingExclusiveLock(path, before); err == nil {
					_ = lock.Close()
					t.Fatal("accepted swapped inode")
				}
				// The failure releases the replacement inode, too.
				current, err := existingPrivateLockInfo(path)
				if err != nil {
					t.Fatal(err)
				}
				lock, err := acquireExistingExclusiveLock(path, current)
				if err != nil {
					t.Fatal(err)
				}
				_ = lock.Close()
			} else if err := verifyExistingLockedFile(path, before, held.file); err == nil {
				t.Fatal("pathname comparison failed to detect held-fd mismatch")
			}
			assertInspectionLocksUnchanged(t, root, snapshot)
		})
	}
}
