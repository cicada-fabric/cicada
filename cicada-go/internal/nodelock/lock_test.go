package nodelock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
