package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationRecoveryRequiresExplicitCoordinatesAndNoOverride(t *testing.T) {
	for _, args := range [][]string{
		{}, {"unknown"}, {"prepare"}, {"status"}, {"reconcile"}, {"activate"}, {"register"},
		{"prepare", "--source", "synthetic-source", "--state-dir", "synthetic-T", "--backup", "synthetic-B"},
		{"register", "--source", "synthetic-source", "--trust-file", "synthetic-pin"},
		{"status", "--source", "synthetic-source", "--state-dir", "synthetic-T", "extra"},
		{"status", "--source", "synthetic-source", "--state-dir", "synthetic-T", "--backup", "synthetic-B"},
	} {
		var output bytes.Buffer
		if err := migrationRestoreActivationCommandOutput(args, &output); err == nil || output.Len() != 0 {
			t.Fatalf("incomplete or unknown invocation admitted: %v", args)
		}
	}
	for _, command := range []string{"register", "prepare", "status", "reconcile", "activate"} {
		for _, override := range []string{"force", "reset", "rotate", "clear"} {
			var output bytes.Buffer
			err := migrationRestoreActivationCommandOutput([]string{command, "--source", "synthetic-source", "--" + override}, &output)
			if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") || output.Len() != 0 {
				t.Fatalf("override %s %s admitted: %v", command, override, err)
			}
		}
	}
}
func TestMigrationRecoveryStatusCannotCreateAuthorityOrOpenStore(t *testing.T) {
	root := t.TempDir()
	source, target := filepath.Join(root, "synthetic-source"), filepath.Join(root, "synthetic-T")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	before := hubForwardTreeDigest(t, root)
	var output bytes.Buffer
	err := migrationRestoreActivationCommandOutput([]string{"status", "--source", source, "--state-dir", target}, &output)
	if err == nil || output.Len() != 0 {
		t.Fatal("missing independent authority was reported as authorization")
	}
	if after := hubForwardTreeDigest(t, root); after != before {
		t.Fatal("read-only status created authority, target, lock, or database")
	}
}
func TestMigrationRecoveryNilOutputRefusesBeforeMutation(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "synthetic-source")
	if err := migrationRestoreActivationCommandOutput([]string{"prepare", "--source", source, "--backup", filepath.Join(root, "B"), "--capsule", filepath.Join(root, "C"), "--state-dir", filepath.Join(root, "T")}, nil); err == nil {
		t.Fatal("nil output admitted mutation")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("nil output created filesystem state")
	}
}
