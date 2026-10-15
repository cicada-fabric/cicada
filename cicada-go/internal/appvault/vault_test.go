package appvault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/appkeys"
)

func TestVaultEncryptsKeysPersistsStateAndChecksFullScope(t *testing.T) {
	dir := privateTestDir(t)
	path := filepath.Join(dir, "app.vault")
	scope := testScope()
	identity, err := appkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	public := identity.Public()

	vault, err := Create(path, scope, testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Put(PurposeOwnerSigner, identity); err != nil {
		t.Fatal(err)
	}
	if err := vault.Put(PurposeOwnerSigner, identity); err != nil {
		t.Fatalf("same identity Put should be idempotent: %v", err)
	}
	pending := []byte("synthetic encrypted pending request marker")
	version, err := vault.CompareAndSwapState("owner.claim", 0, pending)
	if err != nil || version != 1 {
		t.Fatalf("initial state CAS version=%d err=%v", version, err)
	}
	if _, err := vault.CompareAndSwapState("owner.claim", 0, []byte("stale")); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("stale CAS error=%v", err)
	}
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, pending) || bytes.Contains(sealed, []byte("kem_private")) || bytes.Contains(sealed, []byte("private_identity")) {
		t.Fatal("vault file contains plaintext pending state or private-key field names")
	}
	if err := vault.Close(); err != nil {
		t.Fatal(err)
	}

	opened, err := Open(path, scope, testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	loaded, gotVersion, found, err := opened.LoadState("owner.claim")
	if err != nil || !found || gotVersion != 1 || !bytes.Equal(loaded, pending) {
		t.Fatalf("reloaded state version=%d found=%v err=%v", gotVersion, found, err)
	}
	clear(loaded)
	first, err := opened.Get(PurposeOwnerSigner, public.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := opened.Get(PurposeOwnerSigner, public.ID)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	if second.Public().ID != public.ID {
		t.Fatal("closing a detached identity handle affected another handle")
	}
	second.Close()
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	wrongHub := scope
	wrongHub.HubFingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := Open(path, wrongHub, testProtector(t)); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("wrong complete Hub pin error=%v", err)
	}
}

func TestVaultRejectsConcurrentWriter(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "app.vault")
	created, err := Create(path, testScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	if _, err := Open(path, testScope(), testProtector(t)); !errors.Is(err, ErrVaultBusy) {
		t.Fatalf("second writer error=%v", err)
	}
}

func TestVaultFencesPostCommitFailureUntilReopen(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "app.vault")
	scope := testScope()
	created, err := Create(path, scope, testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := created.CompareAndSwapState("pending", 0, []byte("before")); err != nil {
		t.Fatal(err)
	}
	oldSync := syncVaultParentDirectory
	syncVaultParentDirectory = func(string) error { return errors.New("synthetic parent sync failure") }
	version, err := created.CompareAndSwapState("pending", 1, []byte("after"))
	syncVaultParentDirectory = oldSync
	if version != 1 || !errors.Is(err, ErrCommitUncertain) {
		t.Fatalf("postcommit CAS version=%d error=%v", version, err)
	}
	if _, _, _, err := created.LoadState("pending"); !errors.Is(err, ErrCommitUncertain) {
		t.Fatalf("poisoned vault remained readable: %v", err)
	}
	if _, err := created.CompareAndSwapState("other", 0, []byte("must-not-write")); !errors.Is(err, ErrCommitUncertain) {
		t.Fatalf("poisoned vault remained writable: %v", err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, scope, testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	payload, gotVersion, found, err := reopened.LoadState("pending")
	if err != nil || !found || gotVersion != 2 || string(payload) != "after" {
		t.Fatalf("reopened state version=%d found=%v payload=%q err=%v", gotVersion, found, payload, err)
	}
	clear(payload)
	if _, _, found, err := reopened.LoadState("other"); err != nil || found {
		t.Fatalf("poisoned write appeared on disk: found=%v err=%v", found, err)
	}
}

func TestVaultDoesNotRepairExistingBroadDirectoryPermissions(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(parent); err == nil {
		t.Fatal("broad existing directory should be rejected")
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("rejection changed existing directory mode to %04o", got)
	}
}

func testScope() Scope {
	return Scope{
		HubID:          "hub_synthetic_01",
		HubFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Origin:         "https://hub.example.test",
		AccountID:      "account_synthetic_01",
		OwnerID:        "owner_synthetic_01",
	}
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private-app")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testProtector(t *testing.T) *PasswordProtector {
	t.Helper()
	protector, err := NewPasswordProtector([]byte("synthetic test-only password"))
	if err != nil {
		t.Fatal(err)
	}
	return protector
}
