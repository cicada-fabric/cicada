package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

func TestMachineNodeBackupCLI(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	nodeDir := machineNodeStateDir(stateDir, "node-cli-backup")
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "identity.json"), []byte("synthetic Node identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(stateDir, "node-provider-admission.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	_ = provider.Close()
	native, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(stateDir, "node-native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	_ = native.Close()
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
	if err := machineRecoveryCommandOutput([]string{"recovery", "inspect", "--backup", backupDir,
		"--state-dir", restoreState}, &output); err != nil {
		t.Fatalf("CLI shared-fence recovery inspect: %v", err)
	}
	var last map[string]any
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil {
		t.Fatal(err)
	}
	if held, ok := last["shared_writer_root_held"].(bool); !ok || !held {
		t.Fatalf("CLI recovery inspect does not report shared-root quarantine: %#v", last)
	}
	secondHubState := filepath.Join(root, "second-hub-state")
	if err := os.Mkdir(secondHubState, 0o700); err != nil {
		t.Fatal(err)
	}
	pinned := &machineHubContext{Origin: "http://127.0.0.1:9", NodeID: "node-cli-backup",
		StateDir: secondHubState, WriterRoot: restoreState, WriterScope: "synthetic-account"}
	if err := runMachineAgentWithContext(context.Background(), []string{"--id", "node-cli-backup",
		"--state-dir", secondHubState, "--control-url", pinned.Origin, "--once"}, pinned); err == nil {
		t.Fatal("second Hub Agent started with a quarantined shared WriterRoot")
	}
	if _, err := os.Lstat(filepath.Join(machineNodeStateDir(secondHubState, "node-cli-backup"), "identity.json")); !os.IsNotExist(err) {
		t.Fatalf("quarantined Agent created a Node identity: %v", err)
	}
}
