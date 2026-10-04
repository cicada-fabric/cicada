package store

import (
	"path/filepath"
	"testing"
)

func assertStoreBusyTimeout(t *testing.T, s *Store, want int) {
	t.Helper()
	var actual int
	if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != want {
		t.Fatalf("SQLite connection busy_timeout=%d, want %d", actual, want)
	}
}

func TestStoreBusyTimeoutRemainsAuthoritativeAcrossMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	for _, stage := range []string{"fresh", "reopen"} {
		t.Run(stage, func(t *testing.T) {
			s, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			// New must retain the same authoritative wait policy whether v3 ran its
			// Relay schema hook or the ledger verified an already-applied migration.
			assertStoreBusyTimeout(t, s, 30000)
			if err := s.InitializeRelayV2Schema(); err != nil {
				t.Fatal(err)
			}
			assertStoreBusyTimeout(t, s, 30000)
		})
	}
}

func TestRelaySchemaPreservesExistingConnectionBusyTimeout(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// The exported schema hook must not replace a policy supplied by a caller
	// around an already-open database, either with the old 5s or Store's 30s.
	const callerTimeout = 17321
	if _, err := s.db.Exec(`PRAGMA busy_timeout = 17321`); err != nil {
		t.Fatal(err)
	}
	if err := s.InitializeRelayV2Schema(); err != nil {
		t.Fatal(err)
	}
	assertStoreBusyTimeout(t, s, callerTimeout)
}
