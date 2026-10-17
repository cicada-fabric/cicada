package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func assertProfileRecoveryBlocked(t *testing.T, c Controller, code string) {
	t.Helper()
	s := c.Snapshot()
	if s.ErrorCode != code || !containsAction(s.AvailableActions, ActionDiscoverProfiles) {
		t.Fatalf("profile recovery lost its public reason or retry: %s", s.ErrorCode)
	}
	for _, kind := range s.AvailableActions {
		if kind != ActionDiscoverProfiles && kind != ActionResumeProfile {
			t.Fatal("profile failure advertised a new setup or business action")
		}
	}
	before, _ := json.Marshal(s)
	for _, kind := range []ActionKind{ActionConnect, ActionGenerateOwner, ActionImportOwner, ActionSetupAccount, ActionLogin, ActionPreviewNode} {
		if err := c.Dispatch(context.Background(), Action{Kind: kind}); !errors.Is(err, ErrInvalidAction) {
			t.Fatalf("profile failure did not reject %s before processing it", kind)
		}
	}
	after, _ := json.Marshal(c.Snapshot())
	if !bytes.Equal(before, after) {
		t.Fatal("rejected setup action changed the blocked profile or error")
	}
}

func TestNativeProfileStartupRequiresCompleteDiscovery(t *testing.T) {
	for _, mode := range []string{"empty", "discovery-failure", "unlock-failure", "over-limit"} {
		t.Run(mode, func(t *testing.T) {
			fixed := mode == "empty"
			scope := appvault.Scope{HubID: "synthetic-profile"}
			c, err := newController(Config{
				DiscoverVaults: func(context.Context) ([]appvault.Scope, error) {
					if fixed {
						return nil, nil
					}
					switch mode {
					case "discovery-failure":
						return nil, errors.New("synthetic private discovery detail")
					case "over-limit":
						return make([]appvault.Scope, 65), nil
					default:
						return []appvault.Scope{scope}, nil
					}
				},
				OpenVault: func(context.Context, appvault.Scope, bool) (*appvault.Vault, error) {
					return nil, appvault.ErrInvalidVault
				},
			}, true)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			assertProfileRecoveryBlocked(t, c, "")
			if mode != "empty" {
				for range 2 {
					if err := c.Dispatch(context.Background(), Action{Kind: ActionDiscoverProfiles}); err == nil {
						t.Fatal("incomplete discovery allowed setup")
					}
					assertProfileRecoveryBlocked(t, c, c.Snapshot().ErrorCode)
				}
			}
			fixed = true
			if err := c.Dispatch(context.Background(), Action{Kind: ActionDiscoverProfiles}); err != nil || !containsAction(c.Snapshot().AvailableActions, ActionConnect) {
				t.Fatal("a complete empty discovery did not enable first setup")
			}
		})
	}
	c, _ := newController(Config{}, true)
	defer c.Close()
	if !containsAction(c.Snapshot().AvailableActions, ActionConnect) {
		t.Fatal("a controller without discovery was incorrectly locked")
	}
}

func TestProfileRecoveryPublishesBlockedControlsDuringSlowStartup(t *testing.T) {
	for _, mode := range []string{"discovery", "resume"} {
		t.Run(mode, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			config := Config{DiscoverVaults: func(ctx context.Context) ([]appvault.Scope, error) {
				close(entered)
				select {
				case <-release:
					return nil, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}}
			if mode == "resume" {
				root := filepath.Join(t.TempDir(), "vaults")
				savedProfileFixture(t, root)
				config = Config{OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true}
			}
			c, _ := newController(config, true)
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			action := Action{Kind: ActionDiscoverProfiles}
			if mode == "resume" {
				if err := c.Dispatch(ctx, action); err != nil {
					t.Fatal(err)
				}
				action = Action{Kind: ActionResumeProfile, ProfileID: c.Snapshot().Profiles[0].ID}
				opener := config.OpenVault
				c.(*nativeController).cfg.OpenVault = func(ctx context.Context, scope appvault.Scope, create bool) (*appvault.Vault, error) {
					close(entered)
					select {
					case <-release:
						return opener(ctx, scope, create)
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			}
			done := make(chan error, 1)
			go func() { done <- c.Dispatch(ctx, action) }()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("startup never reached its blocking callback: %v", err)
			}
			during := c.Snapshot()
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !containsAction(during.AvailableActions, ActionDiscoverProfiles) || containsAction(during.AvailableActions, ActionConnect) || during.Hub.Verified {
				t.Fatal("a slow startup published empty/first-setup controls before recovery completed")
			}
		})
	}
}

func TestProfileRecoveryResetNeverPublishesFirstSetupAcrossFrames(t *testing.T) {
	c, _ := newController(Config{DiscoverVaults: func(context.Context) ([]appvault.Scope, error) { return nil, nil }}, true)
	defer c.Close()
	done := make(chan error, 1)
	go func() {
		native := c.(*nativeController)
		native.actionMu.Lock()
		defer native.actionMu.Unlock()
		for range 1000 {
			if err := native.resetConnection(); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	bad := false
	check := func() {
		s := c.Snapshot()
		bad = bad || !containsAction(s.AvailableActions, ActionDiscoverProfiles) || containsAction(s.AvailableActions, ActionConnect)
	}
	for {
		check()
		select {
		case err := <-done:
			check()
			if err != nil || bad {
				t.Fatal("a reset exposed empty/first-setup controls to a concurrent frame")
			}
			return
		default:
		}
	}
}

func TestProfileResumeFailureRetainsTrustedLocatorsAndRequiresRetry(t *testing.T) {
	for _, mode := range []string{"busy-after-discovery", "hub-unverified", "invalid-app-state", "invalid-session", "failed-rediscovery"} {
		t.Run(mode, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vaults")
			card, ownerKeyID, requests, mismatch := savedProfileFixture(t, root)
			opener := fixtureVaultOpener(root, "synthetic vault passphrase")
			c, _ := NewController(Config{OpenVault: opener, DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
			defer c.Close()
			ctx := context.Background()
			if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
				t.Fatal(err)
			}
			profiles := c.Snapshot().Profiles
			var held *appvault.Vault
			var original []byte
			var namespace string
			var brokenVersion uint64
			switch mode {
			case "busy-after-discovery":
				var err error
				held, err = opener(ctx, cardScope(card), false)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
			case "hub-unverified":
				mismatch.Store(true)
			case "invalid-app-state", "invalid-session":
				namespace = appStateNamespace
				if mode == "invalid-session" {
					namespace = appSessionNamespace
				}
				v, err := opener(ctx, cardScope(card), false)
				if err != nil {
					t.Fatal(err)
				}
				data, version, _, err := v.LoadState(namespace)
				if err != nil {
					t.Fatal(err)
				}
				original = data
				defer clear(original)
				brokenVersion, err = v.CompareAndSwapState(namespace, version, []byte("synthetic invalid local state"))
				if err != nil {
					t.Fatal(err)
				}
				if err := v.Close(); err != nil {
					t.Fatal(err)
				}
			case "failed-rediscovery":
				c.(*nativeController).cfg.DiscoverVaults = func(context.Context) ([]appvault.Scope, error) {
					return nil, errors.New("synthetic discovery failure")
				}
			}
			path, _ := scopeVaultPath(root, cardScope(card))
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before)
			action := Action{Kind: ActionResumeProfile, ProfileID: profiles[0].ID}
			if mode == "failed-rediscovery" {
				action = Action{Kind: ActionDiscoverProfiles}
			}
			if err := c.Dispatch(ctx, action); err == nil {
				t.Fatal("failed profile recovery was reported ready")
			}
			assertProfileRecoveryBlocked(t, c, c.Snapshot().ErrorCode)
			if !reflect.DeepEqual(profiles, c.Snapshot().Profiles) {
				t.Fatal("failed recovery removed previously authenticated profile locators")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed recovery or rejected rekey modified the encrypted vault")
			}
			clear(after)
			if (mode == "busy-after-discovery" || mode == "invalid-app-state" || mode == "failed-rediscovery") && requests.Load() != 0 {
				t.Fatal("local profile failure sent traffic before authentication")
			}
			if held != nil {
				if err := held.Close(); err != nil {
					t.Fatal(err)
				}
			}
			mismatch.Store(false)
			if namespace != "" {
				v, err := opener(ctx, cardScope(card), false)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := v.CompareAndSwapState(namespace, brokenVersion, original); err != nil {
					t.Fatal(err)
				}
				if err := v.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: profiles[0].ID}); err != nil {
				t.Fatal(err)
			}
			if c.(*nativeController).owner.Public().ID != ownerKeyID || !containsAction(c.Snapshot().AvailableActions, ActionConnect) {
				t.Fatal("successful trusted retry did not restore the original identity")
			}
		})
	}
}

func TestProfileBusySecondProcessRetainsOriginalPendingPacket(t *testing.T) {
	const childFlag = "CICADA_APP_PROFILE_BUSY_CHILD"
	const childRoot = "CICADA_APP_PROFILE_BUSY_ROOT"
	if os.Getenv(childFlag) == "synthetic-child" {
		root := os.Getenv(childRoot)
		c, _ := NewController(Config{OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root)})
		defer c.Close()
		if err := c.Dispatch(context.Background(), Action{Kind: ActionDiscoverProfiles}); err == nil {
			t.Fatal("second process unlocked the active profile")
		}
		assertProfileRecoveryBlocked(t, c, "APP_PROFILE_IN_USE")
		return
	}
	f := newActivationActorFixture(t)
	f.lost = wire.OperationActivationPrepare
	root := filepath.Join(t.TempDir(), "vaults")
	first := f.controller(t, root)
	defer first.Close()
	ctx := context.Background()
	code, _ := wire.EncodeActivationCode(f.material)
	for _, action := range []Action{{Kind: ActionConnect, ActivationCode: code}, {Kind: ActionGenerateOwner}} {
		if err := first.Dispatch(ctx, action); err != nil {
			t.Fatal(err)
		}
	}
	if err := first.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err == nil {
		t.Fatal("synthetic lost response was reported complete")
	}
	native := first.(*nativeController)
	original := bytes.Clone(native.state.Pending.Request)
	defer clear(original)
	ownerID, deviceID := native.owner.Public().ID, native.device.Public().ID
	path, _ := scopeVaultPath(root, cardScope(native.connection))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestProfileBusySecondProcessRetainsOriginalPendingPacket$", "-test.v")
	cmd.Env = append(os.Environ(), childFlag+"=synthetic-child", childRoot+"="+root)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("second process did not fail closed: %v\n%s", err, output)
	}
	t.Log("second OS process rejected the busy profile and new setup actions")
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || !bytes.Equal(original, native.state.Pending.Request) || len(f.posts) != 1 {
		t.Fatal("second process changed the first instance's vault, pending packet or network state")
	}
	clear(after)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := f.controller(t, root)
	defer second.Close()
	if err := second.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	if err := second.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: second.Snapshot().Profiles[0].ID}); err != nil {
		t.Fatal(err)
	}
	resumed := second.(*nativeController)
	if len(f.posts) < 2 || !bytes.Equal(original, f.posts[1]) || resumed.owner.Public().ID != ownerID || resumed.device.Public().ID != deviceID {
		t.Fatal("retry changed Owner/device keys or resealed the original pending request")
	}
}

func TestHeadlessBusyProfileCanRetryOriginalConnectionCard(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	card, ownerKeyID, _, _ := savedProfileFixture(t, root)
	opener := fixtureVaultOpener(root, "synthetic vault passphrase")
	held, err := opener(context.Background(), cardScope(card), false)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	card.IssuedAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	card.ExpiresAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	text, err := card.Encode()
	if err != nil {
		t.Fatal(err)
	}
	c, _ := NewController(Config{OpenVault: opener, AllowLoopbackHTTP: true})
	defer c.Close()
	action := Action{Kind: ActionConnect, ConnectionCard: text}
	if err := c.Dispatch(context.Background(), action); err == nil || c.Snapshot().ErrorCode != "APP_PROFILE_IN_USE" || !containsAction(c.Snapshot().AvailableActions, ActionConnect) {
		t.Fatal("headless busy profile lost the original connection-card retry")
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(context.Background(), action); err != nil {
		t.Fatal(err)
	}
	if c.(*nativeController).owner.Public().ID != ownerKeyID {
		t.Fatal("headless retry replaced the original Owner")
	}
}

func TestProfileIdentityLoadPersistsOnlyChangedKeyIDs(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "recorded-key-ids"
		if legacy {
			name = "legacy-missing-key-ids"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vaults")
			card, ownerKeyID, _, _ := savedProfileFixture(t, root)
			v, err := fixtureVaultOpener(root, "synthetic vault passphrase")(context.Background(), cardScope(card), false)
			if err != nil {
				t.Fatal(err)
			}
			state, version, err := readProfile(v, cardScope(card))
			if err != nil {
				t.Fatal(err)
			}
			deviceKeyID := state.DeviceKeyID
			c := &nativeController{vault: v, state: state, stateVer: version}
			defer func() {
				c.clearRuntimeSecrets()
				_ = v.Close()
			}()
			if legacy {
				c.state.OwnerKeyID, c.state.DeviceKeyID = "", ""
				if err := c.persistState(); err != nil {
					t.Fatal(err)
				}
			}
			version = c.stateVer
			path, _ := scopeVaultPath(root, cardScope(card))
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before)
			if err := c.loadIdentities(false); err != nil {
				t.Fatal(err)
			}
			data, afterVersion, _, err := v.LoadState(appStateNamespace)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(data)
			stored, err := decodeDurableState(data)
			if err != nil || stored.OwnerKeyID != ownerKeyID || stored.DeviceKeyID != deviceKeyID {
				t.Fatal("identity loading lost the original Owner or App identity")
			}
			if legacy {
				if afterVersion != version+1 {
					t.Fatal("legacy key-ID completion was not durably committed")
				}
			} else {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) || afterVersion != version {
					t.Fatal("reading already recorded identities rewrote the vault")
				}
				clear(after)
			}
		})
	}
}

func TestNewProfileDeviceAndOriginalRequestPersistBeforePost(t *testing.T) {
	f := newActivationActorFixture(t)
	c := f.controller(t, filepath.Join(t.TempDir(), "vaults"))
	defer c.Close()
	ctx := context.Background()
	code, _ := wire.EncodeActivationCode(f.material)
	for _, action := range []Action{{Kind: ActionConnect, ActivationCode: code}, {Kind: ActionGenerateOwner}} {
		if err := c.Dispatch(ctx, action); err != nil {
			t.Fatal(err)
		}
	}
	native := c.(*nativeController)
	checked := 0
	originalBarrier := f.beforePost
	f.beforePost = func(operation string, packet []byte) {
		originalBarrier(operation, packet)
		data, _, found, err := native.vault.LoadState(appStateNamespace)
		if err != nil || !found {
			t.Fatal("new identity was not durable before POST")
		}
		defer clear(data)
		stored, err := decodeDurableState(data)
		if err != nil || stored.DeviceKeyID != native.device.Public().ID || stored.OwnerKeyID != native.owner.Public().ID {
			t.Fatal("POST preceded durable new App/Owner identity IDs")
		}
		checked++
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("identity persistence barrier was never exercised by a real PQ request")
	}
}
