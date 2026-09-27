package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMachineNodeBackupCLI(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	nodeDir := machineNodeStateDir(stateDir, "node-cli-backup")
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "identity.json"), []byte("synthetic Node identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(root, "backup")
	var output bytes.Buffer
	if err := machineBackupCommandOutput([]string{"backup", "--id", "node-cli-backup",
		"--state-dir", stateDir, "--output", backupDir}, &output); err != nil {
		t.Fatalf("CLI backup: %v", err)
	}
	if err := machineBackupCommandOutput([]string{"verify", "--backup", backupDir}, &output); err != nil {
		t.Fatalf("CLI verify: %v", err)
	}
	restoreState := filepath.Join(root, "restore-state")
	if err := machineBackupCommandOutput([]string{"restore", "--backup", backupDir,
		"--state-dir", restoreState}, &output); err != nil {
		t.Fatalf("CLI restore: %v", err)
	}
	var last map[string]any
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil {
		t.Fatal(err)
	}
	if quarantined, ok := last["quarantined"].(bool); !ok || !quarantined {
		t.Fatalf("CLI restore result does not report quarantine: %#v", last)
	}
}
