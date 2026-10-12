package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestOfflineTLSOperatorMaintainsExclusiveStoreOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.sqlite3")
	live, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewForOfflineMaintenance(path); !errors.Is(err, ErrStateMaintenanceBusy) {
		t.Fatal("operator accepted live writable Store", err)
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	operator, err := NewForOfflineMaintenance(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); !errors.Is(err, ErrStateMaintenanceBusy) {
		t.Fatal("startup passed retained operator ownership", err)
	}
	if _, err := AcquireStateStartup(filepath.Dir(path)); !errors.Is(err, ErrStateMaintenanceBusy) {
		t.Fatal("startup lease passed operator", err)
	}
	if err := operator.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}
