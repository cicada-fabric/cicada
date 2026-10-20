//go:build linux

package appvault

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func preRegistrationTestScope() PreRegistrationScope {
	return PreRegistrationScope{Origin: "https://hub-a.synthetic.invalid", HubID: "hub_synthetic_a",
		HubFingerprint: strings.Repeat("a", 64), InstallationID: strings.Repeat("1", 32)}
}

func preRegistrationTestStore(t *testing.T) (string, *PreRegistrationStore) {
	t.Helper()
	root := privateTestDir(t)
	s, err := CreatePreRegistration(root, preRegistrationTestScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return root, s
}

func preRegistrationIdentityID(t *testing.T, s *PreRegistrationStore) string {
	t.Helper()
	identity, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	return identity.Public().ID
}

func TestPreRegistrationRoundTripPreservesIdentityAndOriginalBytes(t *testing.T) {
	root, s := preRegistrationTestStore(t)
	id := preRegistrationIdentityID(t, s)
	// Opaque local snapshot stands in for the future admission key, high-entropy
	// S and byte-exact original request. Never a usable deployment credential.
	original := []byte("SYNTHETIC_PRE_REGISTRATION_ONLY\x00ADMISSION_PRIVATE\x00S_NOT_A_REAL_SECRET\xffORIGINAL_REQUEST\x00")
	if version, err := s.CompareAndSwapState(0, original); err != nil || version != 1 {
		t.Fatal("initial durable snapshot failed", version, err)
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, original) || bytes.Contains(data, []byte("S_NOT_A_REAL_SECRET")) || bytes.Contains(data, s.private) || bytes.Contains(data, []byte("kem_private")) {
		t.Fatal("private identity or recovery snapshot leaked into file plaintext")
	}
	for _, rendered := range []string{fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s)} {
		if rendered != "AppPreRegistration<protected>" {
			t.Fatal("diagnostic formatting exposes protected store internals")
		}
	}
	loaded, revision, err := s.LoadState()
	if err != nil || revision != 1 || !bytes.Equal(loaded, original) {
		t.Fatal("loaded snapshot differs from the original bytes")
	}
	loaded[0] ^= 1
	clear(loaded)
	if version, err := s.CompareAndSwapState(0, original); version != 1 || !errors.Is(err, ErrStateConflict) {
		t.Fatal("stale retry must conflict even with identical bytes")
	}
	if version, err := s.CompareAndSwapState(1, original); version != 1 || err != nil {
		t.Fatal("current revision exact retry was not idempotent", err)
	}
	unchanged, err := os.ReadFile(s.path)
	if err != nil || !bytes.Equal(unchanged, data) {
		t.Fatal("idempotent retry rewrote the encrypted file")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPreRegistration(root, preRegistrationTestScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, revision, err = reopened.LoadState()
	defer clear(loaded)
	if err != nil || revision != 1 || !bytes.Equal(loaded, original) || preRegistrationIdentityID(t, reopened) != id {
		t.Fatal("restart did not preserve original snapshot and App identity")
	}
	if _, err := CreatePreRegistration(root, preRegistrationTestScope(), testProtector(t)); !errors.Is(err, ErrVaultBusy) {
		t.Fatal("creation bypassed an existing store lock")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := CreatePreRegistration(root, preRegistrationTestScope(), testProtector(t)); !errors.Is(err, ErrVaultExists) {
		t.Fatal("creation replaced an existing immutable App identity")
	}
}

func TestPreRegistrationScopeIsolation(t *testing.T) {
	root, s := preRegistrationTestStore(t)
	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	scope := preRegistrationTestScope()
	for _, field := range []string{"origin", "hub", "fingerprint", "installation"} {
		t.Run(field, func(t *testing.T) {
			other := scope
			var before, after string
			switch field {
			case "origin":
				before, after = other.Origin, "https://hub-b.synthetic.invalid"
				other.Origin = after
			case "hub":
				before, after = other.HubID, "hub_synthetic_b"
				other.HubID = after
			case "fingerprint":
				before, after = other.HubFingerprint, strings.Repeat("b", 64)
				other.HubFingerprint = after
			case "installation":
				before, after = other.InstallationID, strings.Repeat("2", 32)
				other.InstallationID = after
			}
			path, err := PreRegistrationPath(root, other)
			if err != nil || path == s.path {
				t.Fatal("different scope did not get a distinct namespace path")
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenPreRegistration(root, other, testProtector(t)); !errors.Is(err, ErrScopeMismatch) {
				t.Fatal("copied cross-scope file was accepted", err)
			}
			// Merely rewriting the public header cannot rebind the wrapped data
			// key or the authenticated payload to another Hub/installation.
			forged := bytes.Replace(data, []byte(before), []byte(after), 1)
			if bytes.Equal(forged, data) || len(forged) != len(data) {
				t.Fatal("synthetic header edit did not preserve framing")
			}
			if err := os.WriteFile(path, forged, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenPreRegistration(root, other, testProtector(t)); !errors.Is(err, ErrInvalidVault) {
				t.Fatal("rewritten scope bypassed key wrapping or envelope authentication")
			}
		})
	}
}

func TestPreRegistrationRejectsCorruptFilesWithoutReplacement(t *testing.T) {
	root, s := preRegistrationTestStore(t)
	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	for _, corruption := range []string{"truncated", "trailing", "ciphertext", "version", "length", "legacy-format"} {
		t.Run(corruption, func(t *testing.T) {
			bad := bytes.Clone(data)
			switch corruption {
			case "truncated":
				bad = bad[:len(preRegistrationMagic)+1]
			case "trailing":
				bad = append(bad, 0)
			case "ciphertext":
				bad[len(bad)-1] ^= 1
			case "version":
				binary.BigEndian.PutUint16(bad[len(preRegistrationMagic):], 2)
			case "length":
				binary.BigEndian.PutUint16(bad[len(preRegistrationMagic)+2:], 65535)
			case "legacy-format":
				copy(bad, vaultMagic)
			}
			if err := os.WriteFile(s.path, bad, 0600); err != nil {
				t.Fatal(err)
			}
			if opened, err := OpenPreRegistration(root, preRegistrationTestScope(), testProtector(t)); err == nil {
				_ = opened.Close()
				t.Fatal("corrupt protected state was accepted")
			}
			if _, err := CreatePreRegistration(root, preRegistrationTestScope(), testProtector(t)); !errors.Is(err, ErrVaultExists) {
				t.Fatal("corruption caused implicit replacement of an existing identity")
			}
			after, err := os.ReadFile(s.path)
			if err != nil || !bytes.Equal(after, bad) {
				t.Fatal("failed open/create changed the original file")
			}
		})
	}
}

func TestPreRegistrationRejectsInvalidScopeBeforeCreatingFiles(t *testing.T) {
	for _, invalid := range []string{"origin", "hub", "pin", "installation-64", "installation-nonhex", "relative-root"} {
		t.Run(invalid, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "not-created")
			scope := preRegistrationTestScope()
			switch invalid {
			case "origin":
				scope.Origin = "http://hub-a.synthetic.invalid"
			case "hub":
				scope.HubID = ""
			case "pin":
				scope.HubFingerprint = strings.Repeat("A", 64)
			case "installation-64":
				scope.InstallationID = strings.Repeat("1", 64)
			case "installation-nonhex":
				scope.InstallationID = strings.Repeat("x", 32)
			case "relative-root":
				root = "synthetic-relative-pre-registration"
			}
			if _, err := CreatePreRegistration(root, scope, testProtector(t)); !errors.Is(err, ErrInvalidVault) {
				t.Fatal("invalid input accepted")
			}
			if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid input created a destination")
			}
		})
	}
	first, err := NewInstallationID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewInstallationID()
	if err != nil || len(first) != 32 || len(second) != 32 || !isLowerHex(first) || !isLowerHex(second) || first == second {
		t.Fatal("installation identifiers must be distinct 16-byte lowercase-hex values")
	}
}

func TestPreRegistrationCASBoundsAndTombstone(t *testing.T) {
	root, s := preRegistrationTestStore(t)
	id := preRegistrationIdentityID(t, s)
	state := bytes.Repeat([]byte{0x9b}, maxStateBytes)
	if version, err := s.CompareAndSwapState(0, nil); version != 0 || err != nil {
		t.Fatal("empty initial state was not idempotent")
	}
	if version, err := s.CompareAndSwapState(0, state); version != 1 || err != nil {
		t.Fatal("maximum bounded snapshot was rejected", err)
	}
	if _, err := s.CompareAndSwapState(1, append(bytes.Clone(state), 0)); !errors.Is(err, ErrInvalidVault) {
		t.Fatal("oversized snapshot was accepted")
	}
	loaded, revision, err := s.LoadState()
	if err != nil || revision != 1 || !bytes.Equal(loaded, state) {
		t.Fatal("invalid snapshot changed the original state")
	}
	clear(loaded)
	if version, err := s.CompareAndSwapState(1, nil); version != 2 || err != nil {
		t.Fatal("versioned tombstone failed", err)
	}
	_ = s.Close()
	reopened, err := OpenPreRegistration(root, preRegistrationTestScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, revision, err = reopened.LoadState()
	if err != nil || revision != 2 || len(loaded) != 0 || preRegistrationIdentityID(t, reopened) != id {
		t.Fatal("tombstone reset revision or lost the retained identity")
	}
	if err := reopened.persist(^uint64(0), nil, false); err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
	overflow, err := OpenPreRegistration(root, preRegistrationTestScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	defer overflow.Close()
	if version, err := overflow.CompareAndSwapState(^uint64(0), []byte("SYNTHETIC_OVERFLOW")); version != ^uint64(0) || !errors.Is(err, ErrStateConflict) {
		t.Fatal("revision overflow was not fenced")
	}
}

func TestPreRegistrationPostCommitFailureRequiresReopen(t *testing.T) {
	root, s := preRegistrationTestStore(t)
	id := preRegistrationIdentityID(t, s)
	if _, err := s.CompareAndSwapState(0, []byte("SYNTHETIC_ORIGINAL")); err != nil {
		t.Fatal(err)
	}
	oldSync := syncVaultParentDirectory
	t.Cleanup(func() { syncVaultParentDirectory = oldSync })
	syncVaultParentDirectory = func(string) error { return errors.New("synthetic post-publication sync failure") }
	version, err := s.CompareAndSwapState(1, []byte("SYNTHETIC_NEW_ORIGINAL_PACKET"))
	syncVaultParentDirectory = oldSync
	if version != 1 || !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("post-publication failure did not report an uncertain commit")
	}
	if _, _, err := s.LoadState(); !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("uncertain store remained readable")
	}
	if _, err := s.Identity(); !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("uncertain store still exposed its identity")
	}
	if _, err := s.CompareAndSwapState(1, nil); !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("uncertain store remained writable")
	}
	_ = s.Close()
	reopened, err := OpenPreRegistration(root, preRegistrationTestScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, revision, err := reopened.LoadState()
	defer clear(loaded)
	if err != nil || revision != 2 || string(loaded) != "SYNTHETIC_NEW_ORIGINAL_PACKET" || preRegistrationIdentityID(t, reopened) != id {
		t.Fatal("reopen failed to recover the actual committed bytes and identity")
	}
}

func TestPreRegistrationRejectsReplacementWhileOpen(t *testing.T) {
	for _, replacement := range []string{"same-inode", "new-inode", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			_, s := preRegistrationTestStore(t)
			if _, err := s.CompareAndSwapState(0, []byte("SYNTHETIC_RETAINED_ORIGINAL")); err != nil {
				t.Fatal(err)
			}
			other := filepath.Join(filepath.Dir(s.path), "synthetic-other.pending")
			if err := os.WriteFile(other, []byte("SYNTHETIC_FOREIGN_FILE_MUST_SURVIVE"), 0600); err != nil {
				t.Fatal(err)
			}
			switch replacement {
			case "same-inode":
				if err := os.WriteFile(s.path, []byte("SYNTHETIC_FOREIGN_FILE_MUST_SURVIVE"), 0600); err != nil {
					t.Fatal(err)
				}
			case "new-inode", "symlink":
				if err := os.Rename(s.path, s.path+".retained"); err != nil {
					t.Fatal(err)
				}
				if replacement == "new-inode" {
					if err := os.Rename(other, s.path); err != nil {
						t.Fatal(err)
					}
					other = s.path
				} else if err := os.Symlink(other, s.path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.CompareAndSwapState(1, nil); !errors.Is(err, ErrInvalidVault) {
				t.Fatal("changed file was overwritten by a protected-state write")
			}
			loaded, revision, err := s.LoadState()
			defer clear(loaded)
			if err != nil || revision != 1 || string(loaded) != "SYNTHETIC_RETAINED_ORIGINAL" {
				t.Fatal("failed pre-publication write changed in-memory original")
			}
			data, err := os.ReadFile(other)
			if err != nil || string(data) != "SYNTHETIC_FOREIGN_FILE_MUST_SURVIVE" {
				t.Fatal("rejected write changed the substituted file")
			}
		})
	}
}

func TestPreRegistrationProcessLockAndRecovery(t *testing.T) {
	const modeName = "CICADA_SYNTHETIC_PRE_REGISTRATION_CHILD_MODE"
	const rootName = "CICADA_SYNTHETIC_PRE_REGISTRATION_CHILD_ROOT"
	const original = "SYNTHETIC_PROCESS_EXIT_ORIGINAL_PACKET\x00"
	if mode := os.Getenv(modeName); mode != "" {
		s, err := OpenPreRegistration(os.Getenv(rootName), preRegistrationTestScope(), testProtector(t))
		if mode == "busy" {
			if !errors.Is(err, ErrVaultBusy) {
				t.Fatal("second process acquired an already held private-store lock")
			}
			return
		}
		if mode != "write-exit" || err != nil {
			t.Fatal("invalid synthetic child operation or failed reopen")
		}
		if version, err := s.CompareAndSwapState(0, []byte(original)); version != 1 || err != nil {
			t.Fatal("child failed to durably publish the original packet")
		}
		os.Exit(0) // Deliberately bypass Close; OS process exit must release the lock.
	}
	root, s := preRegistrationTestStore(t)
	id := preRegistrationIdentityID(t, s)
	runChild := func(mode string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPreRegistrationProcessLockAndRecovery$", "-test.count=1")
		cmd.Env = append(os.Environ(), modeName+"="+mode, rootName+"="+root)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("synthetic child process failed: %v\n%s", err, output)
		}
	}
	runChild("busy")
	_ = s.Close()
	runChild("write-exit")
	reopened, err := OpenPreRegistration(root, preRegistrationTestScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, revision, err := reopened.LoadState()
	defer clear(loaded)
	if err != nil || revision != 1 || string(loaded) != original || preRegistrationIdentityID(t, reopened) != id {
		t.Fatal("process death recovery changed the original packet or key")
	}
}

func TestPreRegistrationDoesNotBecomeAnAccountProfile(t *testing.T) {
	root, s := preRegistrationTestStore(t)
	if candidates, err := DiscoverCandidates(root); err != nil || len(candidates) != 0 {
		t.Fatal("pre-registration became an account/Owner vault candidate")
	}
	if candidates, err := DiscoverCandidates(filepath.Dir(s.path)); err != nil || len(candidates) != 0 {
		t.Fatal("pending namespace was mistaken for logged-in profiles")
	}
	legacyPath := filepath.Join(root, "legacy.vault")
	legacy, err := Create(legacyPath, testScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = legacy.Close()
	if candidates, err := DiscoverCandidates(root); err != nil || len(candidates) != 1 || candidates[0].Scope != testScope() {
		t.Fatal("pre-registration altered legacy account-vault discovery")
	}
	_ = s.Close()
	missing := preRegistrationTestScope()
	missing.InstallationID = strings.Repeat("3", 32)
	if _, err := OpenPreRegistration(root, missing, testProtector(t)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing store was not reported without generating a replacement key")
	}
	path, err := PreRegistrationPath(root, missing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("opening a missing store created an identity file")
	}
}
