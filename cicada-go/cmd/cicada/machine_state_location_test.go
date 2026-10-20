package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMachineDefaultStateRefusesOriginalNodeMarkersWithoutReadingOrChangingThem(t *testing.T) {
	for _, marker := range []string{"identity.json", "relay.token", "node-control-state.json", "inbox.sqlite-wal"} {
		t.Run(marker, func(t *testing.T) {
			parent := t.TempDir()
			primary, legacy := filepath.Join(parent, "selected", "state"), filepath.Join(parent, "old-state")
			directory := machineNodeStateDir(legacy, "synthetic-path-node")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(directory, marker)
			original := []byte("SYNTHETIC_ORIGINAL_NODE_STATE_DO_NOT_INITIALIZE")
			if err := os.WriteFile(file, original, 0000); err != nil {
				t.Fatal(err)
			}
			if _, err := chooseMachineDefaultState(primary, legacy); err == nil {
				t.Fatal("original state was hidden by selected empty root")
			}
			if _, err := os.Lstat(filepath.Dir(primary)); !os.IsNotExist(err) {
				t.Fatal("default selection created replacement state")
			}
			if err := os.Chmod(file, 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(file); err != nil || !bytes.Equal(got, original) {
				t.Fatal("original Node marker changed", err)
			}
		})
	}
}

func TestMachineDefaultStateAllowsUnrelatedEmptyLegacyDirectory(t *testing.T) {
	parent := t.TempDir()
	primary, legacy := filepath.Join(parent, "selected", "state"), filepath.Join(parent, "old-state")
	if err := os.MkdirAll(filepath.Join(legacy, "nodes", "node-empty"), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := chooseMachineDefaultState(primary, legacy); err != nil || got != primary {
		t.Fatalf("empty directory blocked new installation: %q %v", got, err)
	}
	if _, err := os.Lstat(filepath.Dir(primary)); !os.IsNotExist(err) {
		t.Fatal("path selection created state")
	}
}

func TestMachineDefaultStateRefusesOriginalSharedSQLiteSideFiles(t *testing.T) {
	for _, base := range []string{"node-native-context-history.sqlite3", "node-provider-admission.sqlite3"} {
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			t.Run(base+suffix, func(t *testing.T) {
				parent := t.TempDir()
				primary, legacy := filepath.Join(parent, "selected", "state"), filepath.Join(parent, "old-state")
				if err := os.MkdirAll(legacy, 0700); err != nil {
					t.Fatal(err)
				}
				original := []byte("SYNTHETIC_ORIGINAL_NODE_SQLITE_SIDE_FILE")
				file := filepath.Join(legacy, base+suffix)
				if err := os.WriteFile(file, original, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := chooseMachineDefaultState(primary, legacy); err == nil {
					t.Fatal("original shared SQLite side file was ignored")
				}
				if got, err := os.ReadFile(file); err != nil || !bytes.Equal(got, original) {
					t.Fatal("original side file changed", err)
				}
				for _, path := range []string{filepath.Dir(primary), filepath.Join(legacy, base)} {
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Fatal("selector created replacement state or main database")
					}
				}
			})
		}
	}
}

func TestInvalidMachineDefaultCannotPrepareCurrentDirectoryState(t *testing.T) {
	working := t.TempDir()
	t.Chdir(working)
	for _, key := range []string{"CICADA_NODE_STATE_DIR", "CICADA_STATE_DIR"} {
		t.Setenv(key, "")
	}
	t.Setenv("CICADA_USER_ROOT", "relative-invalid-root")
	if state := machineAgentStateDir(); state != "" {
		t.Fatalf("invalid root has usable default: %q", state)
	}
	if err := runMachineAgent([]string{"--id", "synthetic-invalid-root", "--control-url", "https://example.invalid", "--once"}); err == nil || !strings.Contains(err.Error(), "state directory is required") {
		t.Fatalf("agent did not stop at state guard: %v", err)
	}
	if err := machineOwnerKeyTrustCommand("trust-owner-key", []string{"--id", "synthetic-invalid-root", "--owner-id", "synthetic-owner"}, &bytes.Buffer{}); err == nil {
		t.Fatal("owner trust accepted an empty state directory")
	}
	if path := machineAgentJoinSocketPath(machineAgentStateDir(), "synthetic-invalid-root"); path != "" {
		t.Fatalf("invalid default reached socket path creation: %q", path)
	}
	if _, err := requestMachineAgentNetworkRenew("", localNetworkRenewRequest{}); err == nil {
		t.Fatal("Network renew accepted an empty socket path")
	}
	entries, err := os.ReadDir(working)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid default wrote into current directory", err)
	}
}
