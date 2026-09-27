package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestOwnerApprovalKeyLocalBootstrapIsIndependentAndRevocationTerminal(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "owner-keys.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.RegisterOwnerApprovalKeyLocal("owner_a", identity.Public())
	if err != nil || key.State != OwnerApprovalKeyActive || key.Version != 1 {
		t.Fatalf("register owner key: key=%#v err=%v", key, err)
	}
	again, err := s.RegisterOwnerApprovalKeyLocal("owner_a", identity.Public())
	if err != nil || again.KeyID != key.KeyID || again.Version != key.Version {
		t.Fatalf("idempotent local bootstrap: key=%#v err=%v", again, err)
	}
	if _, err := s.GetOwnerApprovalKey("owner_b", key.KeyID); !errors.Is(err, ErrOwnerApprovalKeyNotFound) {
		t.Fatalf("foreign owner obtained key = %v", err)
	}
	if _, err := s.RegisterOwnerApprovalKeyLocal("", identity.Public()); err == nil {
		t.Fatal("missing owner was accepted")
	}
	if _, err := s.RegisterOwnerApprovalKeyLocal("owner_a", e2ee.PublicIdentity{ID: key.KeyID}); err == nil {
		t.Fatal("incomplete public key was accepted")
	}
	revoked, err := s.RevokeOwnerApprovalKeyLocal("owner_a", key.KeyID, 1)
	if err != nil || revoked.State != OwnerApprovalKeyRevoked || revoked.Version != 2 {
		t.Fatalf("revoke owner key: key=%#v err=%v", revoked, err)
	}
	if _, err := s.RegisterOwnerApprovalKeyLocal("owner_a", identity.Public()); !errors.Is(err, ErrOwnerApprovalKeyConflict) {
		t.Fatalf("revoked key silently reactivated = %v", err)
	}
	if _, err := s.RevokeOwnerApprovalKeyLocal("owner_a", key.KeyID, 1); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale revocation accepted = %v", err)
	}
}

func TestOwnerApprovalKeyMigrationIsAtomicAndLegacyPreserving(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("interrupt owner approval key migration")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.collaboration.owner_approval_keys" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatalf("migration interruption = %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master
WHERE type = 'table' AND name = 'owner_approval_keys_v2'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("interrupted owner key migration left a partial table")
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(15)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("resumed migration ledger = %#v err=%v", entry, err)
	}
}
