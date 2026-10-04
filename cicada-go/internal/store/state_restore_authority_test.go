package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type hubForwardFixture struct {
	source, base, capsule, target, pin string
	options                            HubRestoreOperationOptions
}

func newHubForwardFixture(t *testing.T) hubForwardFixture {
	t.Helper()
	return newHubForwardFixtureAt(t, t.TempDir())
}

func newHubForwardFixtureAt(t *testing.T, parent string) hubForwardFixture {
	t.Helper()
	// This is a private synthetic deployment/pin root, independent of the
	// testing framework's default directory permissions.
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	f := hubForwardFixture{source: filepath.Join(parent, "original-source"), base: filepath.Join(parent, "B"), capsule: filepath.Join(parent, "C"), target: filepath.Join(parent, "restored-target"), pin: filepath.Join(parent, "independent-deployment.json")}
	f.options = HubRestoreOperationOptions{f.source, f.target}
	if e := os.Mkdir(f.source, 0700); e != nil {
		t.Fatal(e)
	}
	db, e := New(filepath.Join(f.source, stateDatabaseName))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.GetClientHubID(); e != nil {
		t.Fatal(e)
	}
	remote, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.CreateContact(Contact{ID: "synthetic-forward-peer", Identity: remote.Public()}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.AllocateContactSequence("synthetic-forward-peer"); e != nil {
		t.Fatal(e)
	}
	if e = db.AcceptContactSequence("synthetic-forward-peer", 17); e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(f.source, "e2ee"), 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"identity.json", "client-control-identity.json", "node-control-identity.json"} {
		id, e := e2ee.NewIdentity()
		if e != nil {
			t.Fatal(e)
		}
		b, e := id.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(f.source, "e2ee", name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	cp, e := InspectHubRestoreCheckpointReadOnly(f.source)
	if e != nil {
		t.Fatalf("inspect established original SOURCE checkpoint: %v", e)
	}
	nonce, e := hubRestoreNonce()
	if e != nil {
		t.Fatal(e)
	}
	inc, e := hubRestoreIncarnation(f.source, nonce)
	if e != nil {
		t.Fatal(e)
	}
	pin := HubRestoreTrustPin{1, cp.HubID, inc, cp.IdentityFingerprints, cp.SchemaFingerprint, hubRestoreHash([]byte("synthetic prior external deployment trust; never production"))}
	if e = writePrivateJSON(f.pin, pin); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(f.pin)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = RegisterEstablishedHubSource(context.Background(), HubRestoreRegistrationOptions{f.source, f.pin, hubRestoreHash(b)}); e != nil {
		t.Fatalf("register independent SOURCE: %v", e)
	}
	if _, e = BackupStateDir(f.source, f.base); e != nil {
		t.Fatalf("registered SOURCE backup: %v", e)
	}
	db, e = New(filepath.Join(f.source, stateDatabaseName))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.AllocateContactSequence("synthetic-forward-peer"); e != nil {
		t.Fatal(e)
	}
	if e = db.AcceptContactSequence("synthetic-forward-peer", 29); e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	return f
}
func (f hubForwardFixture) sealRestore(t *testing.T) {
	t.Helper()
	if _, e := PrepareHubRestoreHandover(context.Background(), HubRestorePrepareOptions{f.source, f.base, f.capsule, f.target}); e != nil {
		t.Fatal(e)
	}
	if _, e := RestoreStateDir(f.base, f.target); e != nil {
		t.Fatal(e)
	}
}
func TestHubForwardRegistrationRejectsCopiedIncarnation(t *testing.T) {
	f := newHubForwardFixture(t)
	var pin HubRestoreTrustPin
	b, e := os.ReadFile(f.pin)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &pin); e != nil {
		t.Fatal(e)
	}
	copyDir := filepath.Join(filepath.Dir(f.source), "unregistered-old-copy")
	hubForwardCopyTree(t, filepath.Join(f.base, stateBackupPayloadName), copyDir)
	_, e = RegisterEstablishedHubSource(context.Background(), HubRestoreRegistrationOptions{copyDir, f.pin, hubRestoreHash(b)})
	if !errors.Is(e, ErrHubRestoreAuthorityUnproven) {
		t.Fatalf("copy registered: %v", e)
	}
	if _, e = os.Lstat(filepath.Join(copyDir, hubRestoreSourceMarker)); !os.IsNotExist(e) {
		t.Fatalf("denied copy was modified: %v", e)
	}
}
func TestHubForwardRetiredSourceCannotLoseAnchorAndStartOrdinary(t *testing.T) {
	f := newHubForwardFixture(t)
	f.sealRestore(t)
	path, e := hubRestoreLocate(f.source)
	if e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(filepath.Join(f.source, hubRestoreSourceMarker))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = RequireStateRestoreStartupAllowed(f.source); !errors.Is(e, ErrStateRestoreQuarantined) {
		t.Fatalf("missing authority allowed SOURCE: %v", e)
	}
	after, e := os.ReadFile(filepath.Join(f.source, hubRestoreSourceMarker))
	if e != nil || string(after) != string(original) {
		t.Fatal("startup changed sentinel")
	}
}
func TestHubForwardBackupDoesNotExportAuthorityAndGenericCollectorRejectsSentinel(t *testing.T) {
	f := newHubForwardFixture(t)
	manifest, e := VerifyStateBackup(f.base)
	if e != nil {
		t.Fatal(e)
	}
	for _, file := range manifest.Files {
		if reservedStateRestorePath(file.Path) {
			t.Fatalf("authority exported: %s", file.Path)
		}
	}
	if _, e = collectStateFiles(f.source); e == nil {
		t.Fatal("generic collector silently accepted reserved sentinel")
	}
}
func hubForwardCopyTree(t *testing.T, source, target string) {
	t.Helper()
	if e := os.Mkdir(target, 0700); e != nil {
		t.Fatal(e)
	}
	e := filepath.WalkDir(source, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(source, path)
		if e != nil {
			return e
		}
		if rel == "." {
			return nil
		}
		dst := filepath.Join(target, rel)
		if d.IsDir() {
			return os.Mkdir(dst, 0700)
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		return os.WriteFile(dst, b, 0600)
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestHubForwardPrepareRejectsSymlinkCapsuleBeforeFence(t *testing.T) {
	f := newHubForwardFixture(t)
	alias := filepath.Join(filepath.Dir(f.source), "source-alias")
	if err := os.Symlink(f.source, alias); err != nil {
		t.Fatal(err)
	}
	beforeSource := statePathSafetySnapshot(t, f.source)
	beforeBase := statePathSafetySnapshot(t, f.base)
	authority, err := hubRestoreLocate(f.source)
	if err != nil {
		t.Fatal(err)
	}
	beforeAuthority := statePathSafetySnapshot(t, filepath.Dir(authority))
	_, err = PrepareHubRestoreHandover(context.Background(), HubRestorePrepareOptions{f.source, f.base, filepath.Join(alias, "nested-C"), f.target})
	if !errors.Is(err, ErrStateBackupPathUnsafe) {
		t.Errorf("symlink capsule was not rejected before fencing: %v", err)
	}
	if !reflect.DeepEqual(beforeSource, statePathSafetySnapshot(t, f.source)) {
		t.Error("unsafe capsule changed source database or payload inventory/bytes/mode")
	}
	if !reflect.DeepEqual(beforeBase, statePathSafetySnapshot(t, f.base)) {
		t.Error("unsafe capsule changed base backup payload")
	}
	if !reflect.DeepEqual(beforeAuthority, statePathSafetySnapshot(t, filepath.Dir(authority))) {
		t.Error("unsafe capsule changed authority state")
	}
	if err := RequireStateRestoreStartupAllowed(f.source); err != nil {
		t.Errorf("unsafe capsule fenced original source: %v", err)
	}
}

func TestHubForwardPrepareRejectsParentAliasesBeforeFence(t *testing.T) {
	for _, kind := range []string{"source-parent", "target-parent", "base-parent", "capsule-parent"} {
		t.Run(kind, func(t *testing.T) {
			f := newHubForwardFixture(t)
			root := filepath.Dir(f.source)
			alias := filepath.Join(root, "parent-alias")
			if err := os.Symlink(root, alias); err != nil {
				t.Fatal(err)
			}
			o := HubRestorePrepareOptions{f.source, f.base, f.capsule, f.target}
			switch kind {
			case "source-parent":
				o.SourceStateDir = filepath.Join(alias, filepath.Base(f.source))
			case "target-parent":
				o.TargetStateDir = filepath.Join(alias, filepath.Base(f.target))
			case "base-parent":
				o.BaseBackupDir = filepath.Join(alias, filepath.Base(f.base))
			case "capsule-parent":
				o.CapsuleDir = filepath.Join(alias, filepath.Base(f.capsule))
			}
			before := statePathSafetySnapshot(t, root)
			if _, err := PrepareHubRestoreHandover(context.Background(), o); !errors.Is(err, ErrStateBackupPathUnsafe) {
				t.Fatalf("%s not rejected before fence: %v", kind, err)
			}
			if !reflect.DeepEqual(before, statePathSafetySnapshot(t, root)) {
				t.Fatal("parent alias changed source, backup or authority bytes/mode")
			}
			if err := RequireStateRestoreStartupAllowed(f.source); err != nil {
				t.Fatalf("parent alias fenced original source: %v", err)
			}
		})
	}
}

func TestHubForwardPrepareRejectsPhysicalBindCapsuleBeforeFence(t *testing.T) {
	a, b := statePathSafetyBindRoots(t)
	f := newHubForwardFixtureAt(t, a)
	before := statePathSafetySnapshot(t, a)
	_, err := PrepareHubRestoreHandover(context.Background(), HubRestorePrepareOptions{f.source, f.base, filepath.Join(b, filepath.Base(f.source), "nested-C"), f.target})
	if !errors.Is(err, ErrStateBackupPathUnsafe) {
		t.Fatalf("bind alias capsule accepted: %v", err)
	}
	if !reflect.DeepEqual(before, statePathSafetySnapshot(t, a)) {
		t.Fatal("physical capsule changed source, backup or authority bytes/mode")
	}
	if err := RequireStateRestoreStartupAllowed(f.source); err != nil {
		t.Fatalf("bind alias capsule fenced original source: %v", err)
	}
}
