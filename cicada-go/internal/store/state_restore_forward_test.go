package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHubForwardExchangeRetainsBAndOriginalHoldsUntilActivation(t *testing.T) {
	f := newHubForwardFixture(t)
	f.sealRestore(t)
	hold, e := os.ReadFile(filepath.Join(f.target, stateRestoreMarker))
	if e != nil {
		t.Fatal(e)
	}
	old, e := hubRestoreIncarnation(f.target, "synthetic-old")
	if e != nil {
		t.Fatal(e)
	}
	r, e := ReconcileHubRestoreHandover(context.Background(), f.options)
	if e != nil {
		t.Fatal(e)
	}
	if !r.ForwardInstalled || r.ParkedStateDir == "" {
		t.Fatal("forward was not published")
	}
	parked, e := hubRestoreIncarnation(r.ParkedStateDir, "synthetic-old")
	if e != nil || old.Device != parked.Device || old.Inode != parked.Inode {
		t.Fatal("original B inode was not retained")
	}
	bm, e := VerifyStateBackup(f.base)
	if e != nil {
		t.Fatal(e)
	}
	if e = hubRestoreVerifyPayload(r.ParkedStateDir, bm, hold); e != nil {
		t.Fatal(e)
	}
	cm, e := VerifyStateBackup(f.capsule)
	if e != nil {
		t.Fatal(e)
	}
	if e = hubRestoreVerifyPayload(f.target, cm, hold); e != nil {
		t.Fatal(e)
	}
	for _, dir := range []string{f.source, f.target, r.ParkedStateDir} {
		if e = RequireStateRestoreStartupAllowed(dir); !errors.Is(e, ErrStateRestoreQuarantined) {
			t.Fatalf("forward granted early permit for %s: %v", dir, e)
		}
	}
	after, e := os.ReadFile(filepath.Join(f.target, stateRestoreMarker))
	if e != nil || string(after) != string(hold) {
		t.Fatal("original B marker replaced")
	}
	if _, e = ActivateHubRestoreHandover(context.Background(), f.options); e != nil {
		t.Fatal(e)
	}
	if e = RequireStateRestoreStartupAllowed(f.target); e != nil {
		t.Fatal(e)
	}
	if e = RequireStateRestoreStartupAllowed(f.source); !errors.Is(e, ErrStateRestoreQuarantined) {
		t.Fatal("retired SOURCE gained permission")
	}
}
func TestHubForwardActivationAfterRenameSyncFailureRemainsHeld(t *testing.T) {
	f := newHubForwardFixture(t)
	f.sealRestore(t)
	if _, e := ReconcileHubRestoreHandover(context.Background(), f.options); e != nil {
		t.Fatal(e)
	}
	injected := errors.New("synthetic actual-after-rename directory-sync failure")
	seen := false
	_, e := activateHubRestoreHandover(context.Background(), f.options, func(phase string) error {
		if phase != "authority_renamed_before_directory_sync" {
			t.Fatalf("wrong fault boundary %s", phase)
		}
		path, e := hubRestoreLocate(f.source)
		if e != nil {
			t.Fatal(e)
		}
		a, e := hubRestoreReadAuthority(path)
		if e != nil || a.State != "ACTIVE_TARGET" {
			t.Fatal("fault did not occur after actual authority rename")
		}
		seen = true
		return injected
	})
	if !seen || !errors.Is(e, injected) {
		t.Fatalf("fault not exercised: %v", e)
	}
	if e = RequireStateRestoreStartupAllowed(f.target); !errors.Is(e, ErrStateRestoreQuarantined) {
		t.Fatalf("sync failure exposed permit: %v", e)
	}
	a, e := ReadExistingHubRestoreAuthority(f.source)
	if e != nil || a.State != "SEALED" {
		t.Fatalf("failure did not preserve sealed authority: %v", e)
	}
}
func TestHubForwardCannotActivateBeforeFullExchange(t *testing.T) {
	f := newHubForwardFixture(t)
	f.sealRestore(t)
	if _, e := ActivateHubRestoreHandover(context.Background(), f.options); !errors.Is(e, ErrStateRestoreQuarantined) {
		t.Fatalf("old B activated: %v", e)
	}
}

func TestHubForwardSuccessiveHandoverPreservesOriginalHoldsAndExactPriorRecord(t *testing.T) {
	f := newHubForwardFixture(t)
	f.sealRestore(t)
	if _, e := ReconcileHubRestoreHandover(context.Background(), f.options); e != nil {
		t.Fatal(e)
	}
	if _, e := ActivateHubRestoreHandover(context.Background(), f.options); e != nil {
		t.Fatal(e)
	}
	source := f.target
	base := filepath.Join(filepath.Dir(source), "B2")
	capsule := filepath.Join(filepath.Dir(source), "C2")
	target := filepath.Join(filepath.Dir(source), "target2")
	hold, e := os.ReadFile(filepath.Join(source, stateRestoreMarker))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = BackupStateDir(source, base); e != nil {
		t.Fatal(e)
	}
	db, e := New(filepath.Join(source, stateDatabaseName))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.AllocateContactSequence("synthetic-forward-peer"); e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	path, e := hubRestoreLocate(source)
	if e != nil {
		t.Fatal(e)
	}
	prior, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	a, e := PrepareHubRestoreHandover(context.Background(), HubRestorePrepareOptions{source, base, capsule, target})
	if e != nil {
		t.Fatal(e)
	}
	if a.PriorRecordSHA256 != hubRestoreHash(prior) {
		t.Fatal("retirement chain did not bind exact stored prior authority")
	}
	after, e := os.ReadFile(filepath.Join(source, stateRestoreMarker))
	if e != nil || string(after) != string(hold) {
		t.Fatal("existing active hold was rewritten")
	}
	if _, e = RestoreStateDir(base, target); e != nil {
		t.Fatal(e)
	}
	options := HubRestoreOperationOptions{source, target}
	if _, e = ReconcileHubRestoreHandover(context.Background(), options); e != nil {
		t.Fatal(e)
	}
	if _, e = ActivateHubRestoreHandover(context.Background(), options); e != nil {
		t.Fatal(e)
	}
	if e = RequireStateRestoreStartupAllowed(source); !errors.Is(e, ErrStateRestoreQuarantined) {
		t.Fatalf("old active source restarted: %v", e)
	}
	if e = RequireStateRestoreStartupAllowed(target); e != nil {
		t.Fatal(e)
	}
}

func TestHubForwardFailedFenceRetainsLocksAcrossGC(t *testing.T) {
	f := newHubForwardFixture(t)
	f.sealRestore(t)
	if _, e := ReconcileHubRestoreHandover(context.Background(), f.options); e != nil {
		t.Fatal(e)
	}
	path, e := hubRestoreLocate(f.source)
	if e != nil {
		t.Fatal(e)
	}
	authorityDir := filepath.Dir(path)
	savedDir := authorityDir + ".synthetic-io-blocked"
	blockedWithFile := false
	// Close only this synthetic fixture's retained leases after assertions, never
	// a different authority's fail-closed lifetime locks.
	t.Cleanup(func() {
		hubRestoreRetainedLeases.Lock()
		defer hubRestoreRetainedLeases.Unlock()
		kept := hubRestoreRetainedLeases.pairs[:0]
		for _, pair := range hubRestoreRetainedLeases.pairs {
			info, err := pair.target.lock.Stat()
			targetInfo, statErr := os.Stat(f.target)
			if err == nil && statErr == nil && os.SameFile(info, targetInfo) {
				pair.target.Close()
				pair.authority.Close()
			} else {
				kept = append(kept, pair)
			}
		}
		hubRestoreRetainedLeases.pairs = kept
	})
	t.Cleanup(func() {
		if blockedWithFile {
			_ = os.Remove(authorityDir)
			_ = os.Rename(savedDir, authorityDir)
		}
		_ = os.Chmod(authorityDir, 0700)
	})
	injected := errors.New("synthetic post-rename failure with unavailable fencing writes")
	_, e = activateHubRestoreHandover(context.Background(), f.options, func(phase string) error {
		if phase != "authority_renamed_before_directory_sync" {
			t.Fatal(phase)
		}
		if e := os.Chmod(authorityDir, 0500); e != nil {
			t.Fatal(e)
		}
		// Root bypasses chmod write restrictions. Preserve the same real after-
		// rename I/O-failure boundary using an actual non-directory path there.
		if os.Geteuid() == 0 {
			if e := os.Rename(authorityDir, savedDir); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(authorityDir, []byte("synthetic unavailable authority directory"), 0600); e != nil {
				t.Fatal(e)
			}
			blockedWithFile = true
		}
		return injected
	})
	if !errors.Is(e, injected) {
		t.Fatalf("post-rename I/O failure not retained: %v", e)
	}
	if blockedWithFile {
		if e = os.Remove(authorityDir); e != nil {
			t.Fatal(e)
		}
		if e = os.Rename(savedDir, authorityDir); e != nil {
			t.Fatal(e)
		}
		blockedWithFile = false
	}
	if e = os.Chmod(authorityDir, 0700); e != nil {
		t.Fatal(e)
	}
	// The original ACTIVE_TARGET record remains visible after the failed latch
	// and rollback. Therefore a guard-only assertion would miss GC unlocks.
	a, e := hubRestoreReadAuthority(path)
	if e != nil || a.State != "ACTIVE_TARGET" {
		t.Fatalf("fault did not prevent actual fencing/rollback: %v", e)
	}
	runtime.GC()
	runtime.Gosched()
	runtime.GC()
	lease, e := AcquireStateStartup(f.target)
	if lease != nil {
		lease.Close()
	}
	if !errors.Is(e, ErrStateMaintenanceBusy) {
		t.Fatalf("GC released fail-closed target lock: %v", e)
	}
	shared, e := acquireStateMaintenance(authorityDir, false, false)
	if shared != nil {
		shared.Close()
	}
	if !errors.Is(e, ErrStateMaintenanceBusy) {
		t.Fatalf("GC released fail-closed authority lock: %v", e)
	}
}
