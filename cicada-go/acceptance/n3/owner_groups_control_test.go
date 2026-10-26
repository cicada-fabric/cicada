package n3_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Synthetic private IPC contract only; no product acceptance facts.
func TestN3OwnerGroupsControlPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1.command.json")
	original := []byte(`{"scope":"SYNTHETIC_NOT_PRODUCT","sequence":1}`)
	if publishOwnerGroupsControl(path, original) != nil {
		t.Fatal("synthetic original command was not published")
	}
	info := must(os.Stat(path))
	if info.Mode().Perm() != 0600 {
		t.Fatal("synthetic private command has unexpected permissions")
	}
	if !errors.Is(publishOwnerGroupsControl(path, []byte(`{"synthetic":"replacement"}`)), os.ErrExist) ||
		!bytes.Equal(must(os.ReadFile(path)), original) {
		t.Fatal("duplicate sequence replaced its original command")
	}
	if _, err := os.Stat(path + ".next"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("synthetic private publication left its temporary checkpoint")
	}
}
