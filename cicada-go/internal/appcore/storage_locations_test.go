package appcore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func syntheticProfileStorage(t *testing.T, primary, legacy string) *profileStorage {
	t.Helper()
	storage, err := newProfileStorage(primary, []string{legacy}, func(root string) VaultOpener {
		return fixtureVaultOpener(root, "synthetic vault passphrase")
	})
	if err != nil {
		t.Fatal(err)
	}
	return storage
}

func TestProfileStorageEmptyCustomRootRecoversOriginalOwnerAndExactPending(t *testing.T) {
	f := newActivationActorFixture(t)
	f.lost = wire.OperationActivationPrepare
	parent := t.TempDir()
	legacy, primary := filepath.Join(parent, "legacy"), filepath.Join(parent, "chosen", "app", "vaults")
	first := f.controller(t, legacy)
	ctx := context.Background()
	code, _ := wire.EncodeActivationCode(f.material)
	for _, action := range []Action{{Kind: ActionConnect, ActivationCode: code}, {Kind: ActionGenerateOwner}} {
		if err := first.Dispatch(ctx, action); err != nil {
			t.Fatal(err)
		}
	}
	if err := first.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err == nil {
		t.Fatal("lost synthetic response reported as complete")
	}
	native := first.(*nativeController)
	original := bytes.Clone(native.state.Pending.Request)
	defer clear(original)
	owner, device := native.owner.Public().ID, native.device.Public().ID
	scope := cardScope(native.connection)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	path, _ := scopeVaultPath(legacy, scope)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)

	storage := syntheticProfileStorage(t, primary, legacy)
	scopes, err := storage.discover(ctx)
	if err != nil || len(scopes) != 1 || scopes[0] != scope {
		t.Fatalf("scopes=%d err=%v", len(scopes), err)
	}
	if len(f.posts) != 1 {
		t.Fatal("local discovery sent a request")
	}
	if _, err := os.Lstat(filepath.Dir(primary)); !os.IsNotExist(err) {
		t.Fatal("empty custom root was initialized during discovery")
	}
	if root, ok := storage.location(scope); !ok || root != legacy {
		t.Fatal("authenticated legacy source was not retained")
	}
	reopened, err := storage.open(ctx, scope, true)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := readProfile(reopened, scope)
	closeErr := reopened.Close()
	if err != nil || closeErr != nil || state.OwnerKeyID != owner || state.DeviceKeyID != device ||
		state.Pending == nil || !bytes.Equal(state.Pending.Request, original) {
		t.Fatal("new root choice changed original keys or uncertain packet")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("discovery/reopen rewrote the original sealed vault")
	}
	clear(after)

	second := f.controller(t, primary)
	defer second.Close()
	resumed := second.(*nativeController)
	resumed.cfg.OpenVault, resumed.cfg.DiscoverVaults = storage.open, storage.discover
	resumed.cfg.UserRoot, resumed.cfg.VaultLocation = filepath.Join(parent, "chosen"), storage.location
	resumed.profileRecoveryRequired = true
	resumed.publish()
	if err := second.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	if err := second.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: second.Snapshot().Profiles[0].ID}); err != nil {
		t.Fatal(err)
	}
	if resumed.owner.Public().ID != owner || resumed.device.Public().ID != device ||
		len(f.posts) < 2 || !bytes.Equal(f.posts[1], original) {
		t.Fatal("controller resume replaced the original profile or sent an uncertain replacement")
	}
}

func TestProfileStorageDuplicateOrCorruptSourceKeepsTrustedLocation(t *testing.T) {
	parent := t.TempDir()
	primary, legacy := filepath.Join(parent, "new"), filepath.Join(parent, "legacy")
	card, _, requests, _ := savedProfileFixture(t, legacy)
	scope := cardScope(card)
	storage := syntheticProfileStorage(t, primary, legacy)
	if _, err := storage.discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	originalPath, _ := scopeVaultPath(legacy, scope)
	data, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	if err := os.Mkdir(primary, 0700); err != nil {
		t.Fatal(err)
	}
	duplicate, _ := scopeVaultPath(primary, scope)
	if err := os.WriteFile(duplicate, data, 0600); err != nil {
		t.Fatal(err)
	}
	if scopes, err := storage.discover(context.Background()); err == nil || scopes != nil {
		t.Fatal("duplicate same-scope source was selected")
	}
	if root, ok := storage.location(scope); !ok || root != legacy {
		t.Fatal("failed discovery replaced a trusted source")
	}
	if err := os.Remove(duplicate); err != nil {
		t.Fatal(err)
	}
	corrupted := bytes.Clone(data)
	corrupted[len(corrupted)-1] ^= 1
	if err := os.WriteFile(originalPath, corrupted, 0600); err != nil {
		t.Fatal(err)
	}
	clear(corrupted)
	if _, err := storage.discover(context.Background()); err == nil {
		t.Fatal("corrupt old source treated as empty")
	}
	if _, err := storage.open(context.Background(), scope, true); err == nil {
		t.Fatal("corrupt original replaced by a new root")
	}
	if root, ok := storage.location(scope); !ok || root != legacy || requests.Load() != 0 {
		t.Fatal("corruption changed source or contacted Hub")
	}
	if _, err := os.Lstat(duplicate); !os.IsNotExist(err) {
		t.Fatal("replacement vault was created")
	}
}

func TestProfileStorageBusyOrMissingSourceNeverBecomesFirstSetup(t *testing.T) {
	parent := t.TempDir()
	primary, legacy := filepath.Join(parent, "new"), filepath.Join(parent, "legacy")
	card, _, requests, _ := savedProfileFixture(t, legacy)
	scope := cardScope(card)
	storage := syntheticProfileStorage(t, primary, legacy)
	if _, err := storage.discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	busy, err := fixtureVaultOpener(legacy, "synthetic vault passphrase")(context.Background(), scope, false)
	if err != nil {
		t.Fatal(err)
	}
	if scopes, err := storage.discover(context.Background()); err == nil || scopes != nil {
		t.Fatal("busy source bypassed")
	}
	other := scope
	other.OwnerID = "owner_synthetic_other"
	if _, err := storage.open(context.Background(), other, true); err == nil {
		t.Fatal("busy old source allowed another first setup")
	}
	if err := busy.Close(); err != nil {
		t.Fatal(err)
	}
	path, _ := scopeVaultPath(legacy, scope)
	if err := os.Rename(path, path+".held"); err != nil {
		t.Fatal(err)
	}
	if scopes, err := storage.discover(context.Background()); err == nil || scopes != nil {
		t.Fatal("missing known identity was forgotten")
	}
	if _, err := storage.open(context.Background(), other, true); err == nil {
		t.Fatal("missing identity caused a new root")
	}
	if root, ok := storage.location(scope); !ok || root != legacy || requests.Load() != 0 {
		t.Fatal("original source was replaced or network was used")
	}
	if _, err := os.Lstat(primary); !os.IsNotExist(err) {
		t.Fatal("new storage was created")
	}
}

func TestProfileStorageRejectsCaseAndTrailingFilenameAliases(t *testing.T) {
	for _, suffix := range []string{"upper", "dot", "space"} {
		t.Run(suffix, func(t *testing.T) {
			if runtime.GOOS == "windows" && suffix != "upper" {
				t.Skip("Win32 normalizes trailing-dot/space rename; physical Windows alias handling is a separate gate")
			}
			parent := t.TempDir()
			primary, legacy := filepath.Join(parent, "new"), filepath.Join(parent, "legacy")
			card, _, requests, _ := savedProfileFixture(t, legacy)
			scope := cardScope(card)
			path, _ := scopeVaultPath(legacy, scope)
			name := filepath.Base(path)
			switch suffix {
			case "upper":
				name = strings.ToUpper(name)
			case "dot":
				name += "."
			case "space":
				name += " "
			}
			if err := os.Rename(path, filepath.Join(legacy, name)); err != nil {
				t.Fatal(err)
			}
			storage := syntheticProfileStorage(t, primary, legacy)
			if scopes, err := storage.discover(context.Background()); err == nil || scopes != nil {
				t.Fatal("aliased identity treated as absent")
			}
			if _, err := storage.open(context.Background(), scope, true); err == nil {
				t.Fatal("alias bypassed the discovery fence")
			}
			if _, ok := storage.location(scope); ok || requests.Load() != 0 {
				t.Fatal("unverified source was published")
			}
			if _, err := os.Lstat(primary); !os.IsNotExist(err) {
				t.Fatal("new profile was created")
			}
		})
	}
}

func TestProfileStorageNewLocationRequiresExplicitCreationAndDeduplicatesSameRoot(t *testing.T) {
	parent := t.TempDir()
	legacy, primary := filepath.Join(parent, "legacy"), filepath.Join(parent, "new", "app", "vaults")
	card, _, requests, _ := savedProfileFixture(t, legacy)
	storage, err := newProfileStorage(primary, []string{legacy, legacy}, func(root string) VaultOpener { return fixtureVaultOpener(root, "synthetic vault passphrase") })
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := storage.discover(context.Background())
	if err != nil || len(scopes) != 1 {
		t.Fatalf("same source duplicated: %d %v", len(scopes), err)
	}
	fresh := cardScope(card)
	fresh.OwnerID = "owner_synthetic_explicit_new"
	fresh.AccountID = "account_synthetic_explicit_new"
	if _, err := storage.open(context.Background(), fresh, false); err == nil {
		t.Fatal("unregistered location opened without explicit creation")
	}
	if _, err := os.Lstat(primary); !os.IsNotExist(err) {
		t.Fatal("discovery created a new profile")
	}
	vault, err := storage.open(context.Background(), fresh, true)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := vault.List()
	if err != nil || len(entries) != 0 {
		t.Fatal("path choice created an Owner/device identity")
	}
	if err := vault.Close(); err != nil {
		t.Fatal(err)
	}
	if root, ok := storage.location(fresh); !ok || root != primary || requests.Load() != 0 {
		t.Fatal("explicit new location was not local and scoped")
	}
}
