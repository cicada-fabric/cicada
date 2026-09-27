package nodekeys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadExistingRequiresPresentIdentityWithoutCreatingState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing-state")
	if _, err := LoadExisting(root, "monitor_synthetic"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing state should fail closed: %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadExisting created state: %v", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExisting(root, "monitor_synthetic"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing key directory should fail closed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, keyDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadExisting created key directory: %v", err)
	}
}

func TestLoadExistingReadsOnlyMatchingProtectedIdentity(t *testing.T) {
	root := t.TempDir()
	created, err := LoadOrCreate(root, "monitor_synthetic")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadExisting(root, "monitor_synthetic")
	if err != nil || loaded.Public().ID != created.Public().ID {
		t.Fatalf("existing identity changed: %v", err)
	}
	if _, err := LoadExisting(root, "monitor_other"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing other identity should fail closed: %v", err)
	}
	path := identityPath(filepath.Join(root, keyDirectoryName), "monitor_synthetic")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExisting(root, "monitor_synthetic"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatalf("read-only load modified identity: %v", err)
	}
}

func TestLoadExistingRejectsCorruptOrInsecureIdentity(t *testing.T) {
	root := t.TempDir()
	if _, err := LoadOrCreate(root, "monitor_synthetic"); err != nil {
		t.Fatal(err)
	}
	path := identityPath(filepath.Join(root, keyDirectoryName), "monitor_synthetic")
	if err := os.WriteFile(path, []byte("corrupt synthetic key record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExisting(root, "monitor_synthetic"); err == nil {
		t.Fatal("corrupt identity loaded")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExisting(root, "monitor_synthetic"); err == nil {
		t.Fatal("insecure identity mode loaded")
	}
}
