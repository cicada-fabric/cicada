package appcore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

func fixtureVaultOpener(root, password string) VaultOpener {
	return func(_ context.Context, scope appvault.Scope, create bool) (*appvault.Vault, error) {
		path, err := scopeVaultPath(root, scope)
		if err != nil {
			return nil, err
		}
		protector, err := appvault.NewPasswordProtector([]byte(password))
		if err != nil {
			return nil, err
		}
		_, err = os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && create {
			return appvault.Create(path, scope, protector)
		}
		return appvault.Open(path, scope, protector)
	}
}

func savedProfileFixture(t *testing.T, root string) (HubConnectionCard, string, *atomic.Int32, *atomic.Bool) {
	t.Helper()
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hub := wire.HubIdentity{Contract: "android-hub-v1", HubID: "hub_synthetic", Public: hubKey.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	pin, err := wire.HubFingerprint(hub)
	if err != nil {
		t.Fatal(err)
	}
	requests, mismatch := new(atomic.Int32), new(atomic.Bool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet {
			t.Error("profile fixture received account traffic")
		}
		switch r.URL.Path {
		case "/healthz":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "cicada-hub"})
		case "/v2/client/identity":
			identity := hub
			if mismatch.Load() {
				identity.HubID = "hub_wrong_synthetic"
			}
			_ = json.NewEncoder(w).Encode(identity)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	now := time.Now().UTC().Add(-48 * time.Hour)
	card := HubConnectionCard{Format: connectionCardFormat, Version: 1, Purpose: connectionCardPurpose,
		Origin: server.URL, AllowLoopbackHTTP: true, HubID: hub.HubID, HubFingerprint: pin,
		AccountID: "account_synthetic", OwnerID: "owner_synthetic", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	opener := fixtureVaultOpener(root, "synthetic vault passphrase")
	vault, err := opener(context.Background(), cardScope(card), true)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	imported := syntheticOwnerImport(t)
	defer clear(imported.KEMPrivatePKCS8)
	defer clear(imported.SigningPrivatePKCS8)
	owner, err := appkeys.ImportOwner(appkeys.ImportOwnerPEM{KEMPrivatePKCS8: imported.KEMPrivatePKCS8,
		SigningPrivatePKCS8: imported.SigningPrivatePKCS8, KEMPublicSPKI: imported.KEMPublicSPKI, SigningPublicSPKI: imported.SigningPublicSPKI})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := vault.Put(appvault.PurposeOwnerSigner, owner); err != nil {
		t.Fatal(err)
	}
	device, err := appkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	if err := vault.Put(appvault.PurposeAppDevice, device); err != nil {
		t.Fatal(err)
	}
	state := newDurableState(card)
	state.OwnerKeyID, state.DeviceKeyID, state.DeviceID = owner.Public().ID, device.Public().ID, "device_synthetic"
	data, err := encodeDurableState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	if _, err := vault.CompareAndSwapState(appStateNamespace, 0, data); err != nil {
		t.Fatal(err)
	}
	return card, owner.Public().ID, requests, mismatch
}

func TestProfileDiscoveryAuthenticatesBeforeNetworkAndResumesExpiredMaterial(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	card, keyID, requests, _ := savedProfileFixture(t, root)
	controller, _ := NewController(Config{OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
	defer controller.Close()
	ctx := context.Background()
	if err := controller.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	profiles := controller.Snapshot().Profiles
	if len(profiles) != 1 || profiles[0].Origin != card.Origin || requests.Load() != 0 {
		t.Fatal("discovery did not remain local and authenticated")
	}
	profiles[0].Origin = "https://untrusted.synthetic.invalid"
	if controller.Snapshot().Profiles[0].Origin != card.Origin {
		t.Fatal("profile snapshots alias internal state")
	}
	if err := controller.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: profiles[0].ID}); err != nil {
		t.Fatal(err)
	}
	native := controller.(*nativeController)
	if requests.Load() != 2 || native.owner == nil || native.owner.Public().ID != keyID || native.activation != nil {
		t.Fatal("resume did not preserve the imported Owner or reverify the Hub")
	}
	if got := controller.Snapshot(); !got.Hub.Verified || got.Management != ManagementUnavailable || got.Account.State != AccountStateLoginRequired {
		t.Fatalf("local profile invented authorization: %+v", got)
	}
}

func TestProfileUnlockAndTamperFailuresNeverContactHub(t *testing.T) {
	for _, mode := range []string{"wrong-unlock", "tamper-after-discovery", "scope-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vaults")
			card, _, requests, _ := savedProfileFixture(t, root)
			password := "synthetic vault passphrase"
			if mode == "wrong-unlock" {
				password = "synthetic wrong passphrase"
			}
			controller, _ := NewController(Config{OpenVault: fixtureVaultOpener(root, password), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
			defer controller.Close()
			ctx := context.Background()
			if mode == "wrong-unlock" {
				if err := controller.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err == nil || len(controller.Snapshot().Profiles) != 0 {
					t.Fatal("wrong protector exposed a profile")
				}
			} else if mode == "scope-mismatch" {
				opener := fixtureVaultOpener(root, password)
				vault, err := opener(ctx, cardScope(card), false)
				if err != nil {
					t.Fatal(err)
				}
				state, version, _ := readProfile(vault, cardScope(card))
				state.Connection.OwnerID = "owner_wrong_synthetic"
				data, _ := encodeDurableState(state)
				_, err = vault.CompareAndSwapState(appStateNamespace, version, data)
				clear(data)
				vault.Close()
				if err != nil {
					t.Fatal(err)
				}
				if err := controller.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err == nil {
					t.Fatal("mismatched encrypted connection was accepted")
				}
			} else {
				if err := controller.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
					t.Fatal(err)
				}
				profile := controller.Snapshot().Profiles[0]
				path, _ := scopeVaultPath(root, cardScope(card))
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				clear(data)
				if err := controller.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: profile.ID}); err == nil {
					t.Fatal("tampered vault unlocked")
				}
			}
			if requests.Load() != 0 {
				t.Fatal("untrusted local configuration caused network traffic")
			}
		})
	}
}

func TestMultipleProfilesStayScopedAndPinMismatchFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	first, _, firstRequests, _ := savedProfileFixture(t, root)
	second, _, secondRequests, mismatch := savedProfileFixture(t, root)
	controller, _ := NewController(Config{OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
	defer controller.Close()
	ctx := context.Background()
	if err := controller.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	profiles := controller.Snapshot().Profiles
	if len(profiles) != 2 {
		t.Fatal("Hub scopes were merged")
	}
	if err := controller.Dispatch(ctx, Action{Kind: ActionResumeProfile}); err == nil {
		t.Fatal("ambiguous profile was guessed")
	}
	var id string
	for _, profile := range profiles {
		if profile.Origin == second.Origin {
			id = profile.ID
		}
	}
	mismatch.Store(true)
	if err := controller.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: id}); err == nil {
		t.Fatal("changed Hub identity accepted")
	}
	if first.Origin == second.Origin || firstRequests.Load() != 0 || secondRequests.Load() != 2 {
		t.Fatal("profile selection crossed origins")
	}
	if got := controller.Snapshot(); got.Hub.Verified || got.Management != ManagementUnavailable || got.Account.State != AccountStateUnknown {
		t.Fatalf("pin failure exposed trusted state: %+v", got)
	}
}
