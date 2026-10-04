package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHubForwardRestartAllowsLegitimateProgressButRejectsCopiedPermit(t *testing.T) {
	f := newHubForwardFixture(t)
	f.sealRestore(t)
	if _, e := ReconcileHubRestoreHandover(context.Background(), f.options); e != nil {
		t.Fatal(e)
	}
	r, e := ActivateHubRestoreHandover(context.Background(), f.options)
	if e != nil {
		t.Fatal(e)
	}
	db, e := New(filepath.Join(f.target, stateDatabaseName))
	if e != nil {
		t.Fatal(e)
	}
	sequence, e := db.AllocateContactSequence("synthetic-forward-peer")
	if e != nil || sequence != 3 {
		t.Fatalf("current floor lost: %d %v", sequence, e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	lease, e := AcquireStateStartup(f.target)
	if e != nil {
		t.Fatalf("legitimate SQLite progress invalidated restart: %v", e)
	}
	lease.Close()
	a, e := ReadExistingHubRestoreAuthority(f.source)
	if e != nil || a.AuthorityEpoch != r.Authority.AuthorityEpoch {
		t.Fatal("restart consumed epoch again")
	}
	copied := filepath.Join(filepath.Dir(f.target), "copied-activated-payload")
	hubForwardCopyTree(t, f.target, copied)
	if e = RequireStateRestoreStartupAllowed(copied); !errors.Is(e, ErrStateRestoreQuarantined) {
		t.Fatalf("copied permit allowed: %v", e)
	}
}
func TestHubForwardStartupRejectsLostPairedHoldAndCorruptAuthority(t *testing.T) {
	for _, fault := range []string{"internal hold absent", "external hold absent", "authority corrupted"} {
		t.Run(fault, func(t *testing.T) {
			f := newHubForwardFixture(t)
			f.sealRestore(t)
			if _, e := ReconcileHubRestoreHandover(context.Background(), f.options); e != nil {
				t.Fatal(e)
			}
			if _, e := ActivateHubRestoreHandover(context.Background(), f.options); e != nil {
				t.Fatal(e)
			}
			switch fault {
			case "internal hold absent":
				if e := os.Remove(filepath.Join(f.target, stateRestoreMarker)); e != nil {
					t.Fatal(e)
				}
			case "external hold absent":
				if e := os.Remove(stateRestoreRegistrationPath(f.target)); e != nil {
					t.Fatal(e)
				}
			case "authority corrupted":
				path, e := hubRestoreLocate(f.source)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(path, []byte("{broken\n"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e := RequireStateRestoreStartupAllowed(f.target); !errors.Is(e, ErrStateRestoreQuarantined) {
				t.Fatalf("lost lineage permitted restart: %v", e)
			}
		})
	}
}
