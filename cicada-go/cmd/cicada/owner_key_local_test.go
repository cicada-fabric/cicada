package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"

	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestOwnerKeyLocalBootstrapRequiresExactOutOfBandKeyID(t *testing.T) {
	directory := t.TempDir()
	dbPath := filepath.Join(directory, "cicada.sqlite3")
	persistence, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publicData, err := json.Marshal(identity.Public())
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(directory, "owner-public.json")
	if err := os.WriteFile(publicPath, publicData, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	register := []string{"register", "--db", dbPath, "--owner-id", "owner_a",
		"--public", publicPath, "--expect-key-id", identity.Public().ID}
	wrong := append([]string(nil), register...)
	wrong[len(wrong)-1] = "pq1-wrong"
	if err := ownerKeyLocalCommand(wrong, &output); err == nil {
		t.Fatal("unverified key ID was accepted")
	}
	if output.Len() != 0 {
		t.Fatal("failed registration emitted a trusted result")
	}
	if err := ownerKeyLocalCommand(register, &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		OwnerID string `json:"owner_id"`
		KeyID   string `json:"key_id"`
		State   string `json:"state"`
		Version int64  `json:"version"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.OwnerID != "owner_a" || result.KeyID != identity.Public().ID ||
		result.State != store.OwnerApprovalKeyActive || result.Version != 1 {
		t.Fatalf("unexpected registered key metadata: %#v", result)
	}
	registered, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registered.GetPrincipal("owner_a")
	if err != nil || principal == nil || principal.Kind != store.PrincipalKindHuman || principal.OwnerID != "owner_a" ||
		principal.Status != store.PrincipalStatusActive {
		t.Fatalf("trusted guest owner Principal was not registered: %#v err=%v", principal, err)
	}
	if err := registered.Close(); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := ownerKeyLocalCommand([]string{"revoke", "--db", dbPath,
		"--owner-id", "owner_a", "--key-id", result.KeyID,
		"--expected-version", "1"}, &output); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.State != store.OwnerApprovalKeyRevoked || result.Version != 2 {
		t.Fatalf("unexpected revoked key metadata: %#v", result)
	}
	if err := ownerKeyLocalCommand(register, &output); !errors.Is(err, store.ErrOwnerApprovalKeyConflict) {
		t.Fatalf("revoked key was reactivated: %v", err)
	}
}

func TestOwnerKeyGenerationKeepsPrivateIdentityOffHubAndNeverOverwrites(t *testing.T) {
	root := t.TempDir()
	privateDir := filepath.Join(root, "client-private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(privateDir, "owner.json")
	publicPath := filepath.Join(root, "owner-public.json")
	var output bytes.Buffer
	if err := ownerKeyLocalCommand([]string{"generate", "--private", privatePath,
		"--public", publicPath}, &output); err != nil {
		t.Fatal(err)
	}
	privateInfo, err := os.Stat(privatePath)
	if err != nil || privateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key file mode: info=%v err=%v", privateInfo, err)
	}
	privateBytes, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.UnmarshalIdentity(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	var public e2ee.PublicIdentity
	if err := json.Unmarshal(publicBytes, &public); err != nil || public.ID != identity.Public().ID {
		t.Fatalf("generated public identity mismatch: err=%v", err)
	}
	if bytes.Contains(output.Bytes(), privateBytes) {
		t.Fatal("key generation printed private identity")
	}
	if err := ownerKeyLocalCommand([]string{"generate", "--private", privatePath,
		"--public", publicPath}, &output); err == nil {
		t.Fatal("key generation overwrote an existing private identity")
	}
	storedPrivate, err := os.ReadFile(privatePath)
	if err != nil || !bytes.Equal(storedPrivate, privateBytes) {
		t.Fatalf("existing private identity changed: err=%v", err)
	}
	otherPrivate := filepath.Join(privateDir, "other-owner.json")
	if err := ownerKeyLocalCommand([]string{"generate", "--private", otherPrivate,
		"--public", publicPath}, &output); err == nil {
		t.Fatal("key generation overwrote an existing public identity")
	}
	if _, err := os.Lstat(otherPrivate); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed public preflight created an orphan private identity: %v", err)
	}
}

// Synthetic identities and pin are only a disposable test fixture. Exercise
// actual prepare/forward/activate, not a forged retirement marker.
func localOperatorRestoreFixture(t *testing.T, retired bool) (root, db, public, keyID, hubID string) {
	t.Helper()
	root = t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source")
	persistence, err := store.New(filepath.Join(source, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { persistence.Close() })
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.EnsureLocalOwnerPrincipal("owner_seed"); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterOwnerApprovalKeyLocal("owner_seed", identity.Public()); err != nil {
		t.Fatal(err)
	}
	hubID, err = persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	public = filepath.Join(root, "synthetic-owner-public.json")
	data, err := json.Marshal(identity.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(public, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "e2ee"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.json", "client-control-identity.json", "node-control-identity.json"} {
		key, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		data, err := key.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, "e2ee", name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	base := filepath.Join(root, "B")
	if _, err := store.BackupStateDir(source, base); err != nil {
		t.Fatal(err)
	}
	hubForwardWriteEstablishedPin(t, root, source)
	pin := filepath.Join(root, "synthetic-established-pin.json")
	pinBytes, err := os.ReadFile(pin)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(pinBytes)
	if _, err := store.RegisterEstablishedHubSource(context.Background(), store.HubRestoreRegistrationOptions{
		SourceStateDir: source, IndependentTrustFile: pin, IndependentTrustSHA256: hex.EncodeToString(digest[:]),
	}); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if _, err := store.PrepareHubRestoreHandover(context.Background(), store.HubRestorePrepareOptions{
		SourceStateDir: source, BaseBackupDir: base, CapsuleDir: filepath.Join(root, "C"), TargetStateDir: target,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreStateDir(base, target); err != nil {
		t.Fatal(err)
	}
	state := target
	if retired {
		options := store.HubRestoreOperationOptions{SourceStateDir: source, TargetStateDir: target}
		if _, err := store.ReconcileHubRestoreHandover(context.Background(), options); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ActivateHubRestoreHandover(context.Background(), options); err != nil {
			t.Fatal(err)
		}
		state = source
	}
	if err := store.RequireStateRestoreStartupAllowed(state); !errors.Is(err, store.ErrStateRestoreQuarantined) {
		t.Fatalf("fixture did not deny startup: %v", err)
	}
	return root, filepath.Join(state, "cicada.sqlite3"), public, identity.Public().ID, hubID
}

func localOperatorMustRejectWithoutWrites(t *testing.T, root string, command func(*bytes.Buffer) error) {
	t.Helper()
	before := hubRestoreFabricFiles(t, root)
	var output bytes.Buffer
	if err := command(&output); !errors.Is(err, store.ErrStateRestoreQuarantined) {
		t.Errorf("local operator bypassed restore startup authority: %v", err)
	}
	if output.Len() != 0 {
		t.Error("rejected local operator emitted a success result")
	}
	if after := hubRestoreFabricFiles(t, root); !reflect.DeepEqual(before, after) {
		t.Error("rejected local operator changed database, authority, or fixture file bytes")
	}
}

func TestOwnerKeyLocalRestoreStartupGuard(t *testing.T) {
	for _, retired := range []bool{false, true} {
		name := "held_target"
		if retired {
			name = "retired_source"
		}
		t.Run(name, func(t *testing.T) {
			root, db, public, keyID, _ := localOperatorRestoreFixture(t, retired)
			localOperatorMustRejectWithoutWrites(t, root, func(output *bytes.Buffer) error {
				return ownerKeyLocalCommand([]string{"register", "--db", db, "--owner-id", "owner_new", "--public", public, "--expect-key-id", keyID}, output)
			})
			localOperatorMustRejectWithoutWrites(t, root, func(output *bytes.Buffer) error {
				return ownerKeyLocalCommand([]string{"revoke", "--db", db, "--owner-id", "owner_seed", "--key-id", keyID, "--expected-version", "1"}, output)
			})
		})
	}
}

func localOperatorRawDBAlias(t *testing.T, db string) (raw, ordinary string) {
	t.Helper()
	child := filepath.Join(filepath.Dir(db), "synthetic-alias-child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	ordinary = t.TempDir()
	if err := os.Chmod(ordinary, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(child, filepath.Join(ordinary, "alias")); err != nil {
		t.Fatal(err)
	}
	// Joining with filepath.Join would erase the physical counterexample.
	raw = ordinary + string(os.PathSeparator) + "alias" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + filepath.Base(db)
	actual, err := os.Lstat(raw)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.Lstat(db)
	if err != nil || !os.SameFile(actual, expected) {
		t.Fatalf("raw alias did not resolve to held database: %v", err)
	}
	return raw, ordinary
}

func localOperatorMustRejectRawDBAlias(t *testing.T, root, ordinary string, command func(*bytes.Buffer) error) {
	t.Helper()
	before := hubRestoreFabricFiles(t, root)
	var output bytes.Buffer
	if err := command(&output); !errors.Is(err, store.ErrStateBackupPathUnsafe) && !errors.Is(err, store.ErrStateRestoreQuarantined) {
		t.Errorf("raw database alias reached local operation instead of path/startup rejection: %v", err)
	}
	if output.Len() != 0 {
		t.Error("unsafe raw database path emitted success")
	}
	if after := hubRestoreFabricFiles(t, root); !reflect.DeepEqual(before, after) {
		t.Error("raw database alias changed held fixture bytes")
	}
	entries, err := os.ReadDir(ordinary)
	if err != nil || len(entries) != 1 || entries[0].Name() != "alias" {
		t.Errorf("raw database alias initialized SQLite under the wrong guard directory: %v", err)
	}
}

func TestOwnerKeyLocalRawDatabaseCoordinate(t *testing.T) {
	root, db, public, keyID, _ := localOperatorRestoreFixture(t, false)
	raw, ordinary := localOperatorRawDBAlias(t, db)
	localOperatorMustRejectRawDBAlias(t, root, ordinary, func(output *bytes.Buffer) error {
		return ownerKeyLocalCommand([]string{"register", "--db", raw, "--owner-id", "owner_alias", "--public", public, "--expect-key-id", keyID}, output)
	})
}

func TestLocalOperatorRawCoordinateFresh(t *testing.T) {
	root := t.TempDir()
	db := filepath.Join(root, "cicada.sqlite3")
	persistence, err := store.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.EnsureLocalOwnerPrincipal("owner_seed"); err != nil {
		t.Fatal(err)
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "ordinary-child"), 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	public, err := json.Marshal(identity.Public())
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(root, "synthetic-owner-public.json")
	if err := os.WriteFile(publicPath, public, 0600); err != nil {
		t.Fatal(err)
	}
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(working, root)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{root + "/./cicada.sqlite3", root + "/ordinary-child/../cicada.sqlite3", "./" + relative + "/ordinary-child/../cicada.sqlite3"}
	for i, raw := range paths {
		t.Run([]string{"ordinary_dot", "ordinary_dotdot", "relative_dotdot"}[i], func(t *testing.T) {
			owner := []string{"owner_dot", "owner_dotdot", "owner_relative"}[i]
			if err := ownerKeyLocalCommand([]string{"register", "--db", raw, "--owner-id", owner, "--public", publicPath, "--expect-key-id", identity.Public().ID}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			if err := networkOperatorCommand("create", []string{"--db", raw, "--hub", hubID, "--network", []string{"net_dot", "net_dotdot", "net_relative"}[i], "--name", "synthetic ordinary coordinate", "--owner", "owner_seed"}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
