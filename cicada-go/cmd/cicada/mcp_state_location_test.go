package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMCPStateLocationRetainsOriginalPendingOutboxAndRefusesAmbiguity(t *testing.T) {
	parent := t.TempDir()
	primary := filepath.Join(parent, "selected", "mcp", "sessions.json")
	legacy := filepath.Join(parent, "old", "mcp", "sessions.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0700); err != nil {
		t.Fatal(err)
	}
	packet := []byte("SYNTHETIC_UNCERTAIN_OUTBOX_BYTES")
	file := filepath.Join(filepath.Dir(legacy), "outbox.sqlite3")
	if err := os.WriteFile(file, packet, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := chooseMCPSessionPath(primary, []string{primary, legacy, legacy})
	if err != nil || got != legacy {
		t.Fatalf("old state=%q err=%v", got, err)
	}
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(packet) {
		t.Fatal("outbox changed")
	}
	if _, err := os.Lstat(filepath.Dir(primary)); !os.IsNotExist(err) {
		t.Fatal("new MCP state was created")
	}
	if err := os.MkdirAll(filepath.Dir(primary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(primary, []byte("SYNTHETIC_NEW_SCOPE_STATE"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := chooseMCPSessionPath(primary, []string{primary, legacy}); err == nil {
		t.Fatal("multiple sources were selected silently")
	}
}

func TestMCPStateLocationRejectsOrphanSQLiteSideFilesWithoutCreatingDatabase(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		t.Run(suffix, func(t *testing.T) {
			parent := t.TempDir()
			primary := filepath.Join(parent, "selected", "mcp", "sessions.json")
			legacy := filepath.Join(parent, "old", "mcp", "sessions.json")
			if err := os.MkdirAll(filepath.Dir(legacy), 0700); err != nil {
				t.Fatal(err)
			}
			sideFile := filepath.Join(filepath.Dir(legacy), "outbox.sqlite3"+suffix)
			packet := []byte("SYNTHETIC_RETAINED_SQLITE_SIDE_FILE")
			if err := os.WriteFile(sideFile, packet, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := chooseMCPSessionPath(primary, []string{primary, legacy}); err == nil {
				t.Fatal("orphan side file allowed opening a replacement main database")
			}
			if got, err := os.ReadFile(sideFile); err != nil || string(got) != string(packet) {
				t.Fatal("retained side file changed", err)
			}
			if _, err := os.Lstat(filepath.Dir(primary)); !os.IsNotExist(err) {
				t.Fatal("side file caused replacement storage creation")
			}
			mainFile := filepath.Join(filepath.Dir(legacy), "outbox.sqlite3")
			if _, err := os.Lstat(mainFile); !os.IsNotExist(err) {
				t.Fatal("orphan side file caused original main database creation")
			}
			if err := os.WriteFile(mainFile, []byte("SYNTHETIC_EXISTING_MAIN_DATABASE"), 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := chooseMCPSessionPath(primary, []string{primary, legacy}); err != nil || got != legacy {
				t.Fatalf("existing main database and side file source lost: %q %v", got, err)
			}
			if err := os.MkdirAll(filepath.Dir(primary), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(primary, []byte("SYNTHETIC_OTHER_SCOPE"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := chooseMCPSessionPath(primary, []string{primary, legacy}); err == nil {
				t.Fatal("orphan side file ignored during ambiguity check")
			}
		})
	}
}

func TestMCPAndNodeExplicitPathsTakePrecedenceOverNewUserRoot(t *testing.T) {
	parent := t.TempDir()
	for _, key := range []string{"CICADA_MCP_SESSION_STATE_FILE", "CICADA_MCP_STATE_FILE", "CICADA_SESSION_STATE_DIR", "CICADA_MCP_STATE_DIR", "CICADA_STATE_DIR", "CICADA_NODE_STATE_DIR"} {
		t.Setenv(key, "")
	}
	t.Setenv("CICADA_USER_ROOT", "relative-invalid-root")
	explicit := filepath.Join(parent, "original", "sessions.json")
	t.Setenv("CICADA_MCP_SESSION_STATE_FILE", explicit)
	if got, err := mcpSessionStatePath(); err != nil || got != explicit {
		t.Fatalf("explicit MCP path lost: %q %v", got, err)
	}
	original := filepath.Join(parent, "node", "state")
	t.Setenv("CICADA_NODE_STATE_DIR", original)
	if got := machineAgentStateDir(); got != original || endpointKeyNodeStateBase() != original {
		t.Fatal("explicit Node root changed")
	}
	t.Setenv("CICADA_NODE_STATE_DIR", "")
	t.Setenv("CICADA_STATE_DIR", original)
	if got := machineAgentStateDir(); got != original {
		t.Fatal("legacy explicit state root changed")
	}
}

func TestNodeDefaultUsesSelectedUserRootWithoutCreatingFiles(t *testing.T) {
	parent := t.TempDir()
	selected := filepath.Join(parent, "chosen")
	t.Setenv("CICADA_NODE_STATE_DIR", "")
	t.Setenv("CICADA_STATE_DIR", "")
	t.Setenv("CICADA_USER_ROOT", selected)
	expected := filepath.Join(selected, "state")
	if got := machineAgentStateDir(); got != expected || endpointKeyNodeStateBase() != expected {
		t.Fatalf("Node state %q expected %q", got, expected)
	}
	if _, err := os.Lstat(selected); !os.IsNotExist(err) {
		t.Fatal("resolving paths initialized Node identity")
	}
}
