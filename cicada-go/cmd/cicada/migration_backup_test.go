package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestMigrationBackupCommandOutputBackupVerifyRestore(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	persistence, err := store.New(filepath.Join(source, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, "backup")
	var output bytes.Buffer
	if err := migrationBackupCommandOutput([]string{"backup", "--state-dir", source, "--output", backup}, &output); err != nil {
		t.Fatal(err)
	}
	var manifest store.StateBackupManifest
	if err := json.Unmarshal(output.Bytes(), &manifest); err != nil {
		t.Fatalf("decode backup command output: %v", err)
	}
	if !manifest.Complete {
		t.Fatalf("backup command returned incomplete manifest: %#v", manifest)
	}
	output.Reset()
	if err := migrationBackupCommandOutput([]string{"verify", "--backup", backup}, &output); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	target := filepath.Join(root, "target")
	if err := migrationBackupCommandOutput([]string{"restore", "--backup", backup, "--state-dir", target}, &output); err != nil {
		t.Fatal(err)
	}
	var report store.StateRestoreReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("decode restore command output: %v", err)
	}
	if !report.Verified || report.TargetStateDir != target {
		t.Fatalf("unexpected restore command report: %#v", report)
	}
}

func TestMigrationBackupCommandRequiresExplicitPaths(t *testing.T) {
	if err := migrationBackupCommandOutput([]string{"backup"}, &bytes.Buffer{}); err == nil {
		t.Fatal("backup command accepted missing paths")
	}
	if err := migrationBackupCommandOutput([]string{"verify"}, &bytes.Buffer{}); err == nil {
		t.Fatal("verify command accepted missing backup path")
	}
	if err := migrationBackupCommandOutput([]string{"restore", "--backup", "/tmp/missing"}, &bytes.Buffer{}); err == nil {
		t.Fatal("restore command accepted missing target path")
	}
	if err := migrationBackupCommandOutput([]string{"unknown"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown migration backup command was accepted")
	}
}
