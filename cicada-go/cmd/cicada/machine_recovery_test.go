package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/nodebackup"
)

func TestMachineRecoveryInspectCommand(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	nodeDir := filepath.Join(source, "nodes", "node-cli-recovery")
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "identity.json"), []byte("synthetic fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, "backup")
	if _, err := nodebackup.Backup(source, "cli-recovery", backup); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "restored")
	if _, err := nodebackup.Restore(backup, stateDir); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	args := []string{"recovery", "inspect", "--backup", backup, "--state-dir", stateDir}
	if err := machineRecoveryCommandOutput(args, &output); err != nil {
		t.Fatalf("run recovery inspect CLI: %v", err)
	}
	var report struct {
		NodeID        string `json:"node_id"`
		AgentMayStart bool   `json:"agent_may_start"`
		HubCheck      string `json:"hub_binding_check"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("decode recovery inspection output %q: %v", output.String(), err)
	}
	if report.NodeID != "cli-recovery" || report.AgentMayStart || report.HubCheck != "not_checked_offline" {
		t.Fatalf("unexpected recovery CLI result: %+v", report)
	}
}
