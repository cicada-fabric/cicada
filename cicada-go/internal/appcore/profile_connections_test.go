package appcore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type profileHTTPProbe struct {
	mu             sync.Mutex
	offline        string
	posts          []string
	packets        [][]byte
	block, entered chan struct{}
}

func (p *profileHTTPProbe) Do(r *http.Request) (*http.Response, error) {
	origin := r.URL.Scheme + "://" + r.URL.Host
	if p.entered != nil {
		close(p.entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	p.mu.Lock()
	if origin == p.offline {
		p.mu.Unlock()
		return nil, errors.New("synthetic offline Hub")
	}
	if r.Method == http.MethodPost {
		raw, _ := io.ReadAll(r.Body)
		p.posts = append(p.posts, origin)
		p.packets = append(p.packets, raw)
		p.mu.Unlock()
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("synthetic unknown result")), Request: r}, nil
	}
	p.mu.Unlock()
	return http.DefaultClient.Do(r)
}
func hubProfile(t *testing.T, c Controller, origin string) ProfileSnapshot {
	t.Helper()
	for _, p := range c.Snapshot().Profiles {
		if p.Origin == origin {
			return p
		}
	}
	t.Fatal("synthetic saved Hub missing")
	return ProfileSnapshot{}
}

func TestHubConnectionsKeepUnknownOriginalAndRestoreIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	a, ownerA, _, _ := savedProfileFixture(t, root)
	b, ownerB, _, _ := savedProfileFixture(t, root, 0x61, 0x62)
	probe := new(profileHTTPProbe)
	open := fixtureVaultOpener(root, "synthetic vault passphrase")
	controller, _ := NewController(Config{HTTP: probe, OpenVault: open, DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
	defer controller.Close()
	c := controller.(*nativeController)
	ctx := context.Background()
	if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	pa, pb := hubProfile(t, c, a.Origin), hubProfile(t, c, b.Origin)
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: pa.ID}); err != nil {
		t.Fatal(err)
	}
	deviceID := c.device.Public().ID
	if ownerA == ownerB {
		t.Fatal("fixture owners are not independent")
	}
	c.state.DeviceID = wire.AccountDeviceIDPrefix + strings.Repeat("a", 32)
	d, err := c.device.E2EE()
	if err != nil {
		t.Fatal(err)
	}
	q, err := wire.NewLoginPrepare(c.hub, a.Origin, a.AccountID, a.OwnerID, c.state.DeviceID, "synthetic-user", d.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := wire.SealClientRequest(d, c.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	c.state.Pending = &pendingOperation{Operation: wire.OperationLoginPrepare, Request: bytes.Clone(packet), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := c.persistState(); err != nil {
		t.Fatal(err)
	}
	retained := []byte("SYNTHETIC independent original/receipt bytes")
	version, err := c.vault.CompareAndSwapState("synthetic.retained.v1", 0, retained)
	if err != nil {
		t.Fatal(err)
	}
	probe.offline = a.Origin
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: pb.ID}); err != nil {
		t.Fatal(err)
	}
	if c.device.Public().ID == deviceID {
		t.Fatal("fixture device keys are not independent")
	}
	if c.owner.Public().ID != ownerB || c.state.Pending != nil || len(probe.posts) != 0 || c.Snapshot().Node.Binding != nil || c.Snapshot().Management != ManagementUnavailable {
		t.Fatal("switch leaked prior identity, request or authority")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionRemoveProfile, ProfileID: pa.ID, ProfileReviewID: pa.ReviewID, ConfirmProfileRemoval: true}); err != nil {
		t.Fatal(err)
	}
	pa = hubProfile(t, c, a.Origin)
	if !pa.Removed || c.owner.Public().ID != ownerB || len(probe.posts) != 0 {
		t.Fatal("local removal touched the other Hub")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionRestoreProfile, ProfileID: pa.ID, ProfileReviewID: pa.ReviewID}); err == nil {
		t.Fatal("offline restore reported success")
	}
	if !hubProfile(t, c, a.Origin).Removed || c.Snapshot().Hub.Verified || c.owner != nil || c.Snapshot().Account.AccountID != "" {
		t.Fatal("offline restore leaked old tenant or changed marker")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionAddHub}); err != nil || !containsAction(c.Snapshot().AvailableActions, ActionConnect) {
		t.Fatal("old offline Hub blocked explicit Add")
	}
	probe.offline = ""
	if err := c.Dispatch(ctx, Action{Kind: ActionRestoreProfile, ProfileID: pa.ID, ProfileReviewID: pa.ReviewID}); err == nil {
		t.Fatal("unknown original response was declared successful")
	}
	if c.owner.Public().ID != ownerA || c.device.Public().ID != deviceID || c.state.Pending == nil || !bytes.Equal(c.state.Pending.Request, packet) || len(probe.posts) != 1 || probe.posts[0] != a.Origin || !bytes.Equal(probe.packets[0], packet) {
		t.Fatal("restore rekeyed or retried a different original/Hub")
	}
	if hubProfile(t, c, a.Origin).Removed {
		t.Fatal("verified original profile was not restored")
	}
	raw, gotVersion, _, err := c.vault.LoadState("synthetic.retained.v1")
	if err != nil || gotVersion != version || !bytes.Equal(raw, retained) {
		t.Fatal("connection marker changed retained state or CAS")
	}
	clear(raw)
	before := len(probe.posts)
	if err := c.Dispatch(ctx, Action{Kind: ActionDisconnectHub}); err != nil {
		t.Fatal(err)
	}
	if c.vault != nil || c.owner != nil || c.device != nil || c.Snapshot().Hub.Verified || c.Snapshot().Account.AccountID != "" || len(probe.posts) != before {
		t.Fatal("disconnect retained runtime identity or sent network revocation")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	if len(c.Snapshot().Profiles) != 2 || len(probe.posts) != before {
		t.Fatal("local discovery retried the unknown packet")
	}
}

func TestHubConnectionRemovalRequiresExactConsentAndDurableMarker(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	card, owner, _, _ := savedProfileFixture(t, root)
	open := fixtureVaultOpener(root, "synthetic vault passphrase")
	c0, _ := NewController(Config{OpenVault: open, DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
	defer c0.Close()
	c := c0.(*nativeController)
	ctx := context.Background()
	if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	p := hubProfile(t, c, card.Origin)
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: p.ID}); err != nil {
		t.Fatal(err)
	}
	for _, a := range []Action{{Kind: ActionRemoveProfile, ProfileID: p.ID, ProfileReviewID: p.ReviewID}, {Kind: ActionRemoveProfile, ProfileID: p.ID, ProfileReviewID: "stale", ConfirmProfileRemoval: true}} {
		if err := c.Dispatch(ctx, a); !errors.Is(err, ErrInvalidAction) {
			t.Fatal("imprecise removal accepted")
		}
	}
	path, _ := scopeVaultPath(root, cardScope(card))
	held := path + ".held"
	c.cfg.OpenVault = func(ctx context.Context, s appvault.Scope, create bool) (*appvault.Vault, error) {
		v, err := open(ctx, s, create)
		if err == nil {
			if err = os.Rename(path, held); err != nil {
				v.Close()
				return nil, err
			}
		}
		return v, err
	}
	err := c.Dispatch(ctx, Action{Kind: ActionRemoveProfile, ProfileID: p.ID, ProfileReviewID: p.ReviewID, ConfirmProfileRemoval: true})
	if err == nil || hubProfile(t, c, card.Origin).Removed || c.Snapshot().ErrorCode != "APP_PROFILE_UPDATE_FAILED" || c.Snapshot().Hub.Verified {
		t.Fatal("failed marker write reported removal/current authority")
	}
	if err := os.Rename(held, path); err != nil {
		t.Fatal(err)
	}
	c.cfg.OpenVault = open
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: p.ID}); err != nil || c.owner.Public().ID != owner {
		t.Fatal("failed remove damaged original identity")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionRemoveProfile, ProfileID: p.ID, ProfileReviewID: p.ReviewID, ConfirmProfileRemoval: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil || !hubProfile(t, c, card.Origin).Removed {
		t.Fatal("removal did not survive encrypted reopen")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: p.ID}); err == nil {
		t.Fatal("removed profile silently resumed without Restore")
	}
	p = hubProfile(t, c, card.Origin)
	if err := c.Dispatch(ctx, Action{Kind: ActionRestoreProfile, ProfileID: p.ID, ProfileReviewID: p.ReviewID}); err != nil || c.owner.Public().ID != owner || hubProfile(t, c, card.Origin).Removed {
		t.Fatal("explicit restore did not retain identity")
	}
}

func TestHubConnectionRestoreCancelsOnControllerClose(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	card, _, _, _ := savedProfileFixture(t, root)
	c0, _ := NewController(Config{OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
	c := c0.(*nativeController)
	ctx := context.Background()
	if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	p := hubProfile(t, c, card.Origin)
	if err := c.Dispatch(ctx, Action{Kind: ActionRemoveProfile, ProfileID: p.ID, ProfileReviewID: p.ReviewID, ConfirmProfileRemoval: true}); err != nil {
		t.Fatal(err)
	}
	p = hubProfile(t, c, card.Origin)
	probe := &profileHTTPProbe{entered: make(chan struct{})}
	c.cfg.HTTP = probe
	done := make(chan error, 1)
	go func() {
		done <- c.Dispatch(ctx, Action{Kind: ActionRestoreProfile, ProfileID: p.ID, ProfileReviewID: p.ReviewID})
	}()
	select {
	case <-probe.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("restore never verified Hub")
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled restore succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("restore outlived controller")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("controller close remained blocked")
	}
}

func TestHubConnectionCapacityCountsRetainedProfilesBeforeCreation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	called := false
	s, err := newProfileStorage(root, nil, func(string) VaultOpener {
		return func(context.Context, appvault.Scope, bool) (*appvault.Vault, error) {
			called = true
			return nil, appvault.ErrInvalidVault
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	s.discovered = true
	for i := 0; i < 64; i++ {
		s.locations[appvault.Scope{HubID: fmt.Sprintf("SYNTHETIC-%d", i)}] = root
	}
	if _, err := s.open(context.Background(), appvault.Scope{HubID: "SYNTHETIC-65"}, true); err == nil || called {
		t.Fatal("65th connection tried to create a vault")
	}
}

func TestHubConnectionAddFreshBootstrapAfterOldOfflineUnknown(t *testing.T) {
	old := newAppTLSFixture(t)
	oldServer := old.serve(t, old.leaf)
	root := filepath.Join(t.TempDir(), "vaults")
	c, legacy := old.controller(t, root)
	ctx := context.Background()
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, HubAddress: oldServer.Listener.Addr().String(), BootstrapCode: old.bootstrap(t, old.descriptor)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	oldOwner, oldDevice, oldScope := c.owner.Public().ID, c.device.Public().ID, c.vault.Scope()
	old.mu.Lock()
	old.actor.lost = wire.OperationActivationPrepare
	old.mu.Unlock()
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, Username: "synthetic-user", Password: n2SyntheticPassword, ConfirmLimitedAuthorization: true}); err == nil || c.state.Pending == nil {
		t.Fatal("old fixture did not retain uncertain activation")
	}
	original := bytes.Clone(c.state.Pending.Request)
	defer clear(original)
	oldServer.Close()
	if err := c.Dispatch(ctx, Action{Kind: ActionAddHub}); err != nil {
		t.Fatal(err)
	}
	if c.owner != nil || c.device != nil || c.state.Pending != nil || c.Snapshot().Hub.Verified {
		t.Fatal("Add retained previous tenant runtime")
	}
	fresh := newAppTLSFixture(t)
	server := fresh.serve(t, fresh.leaf)
	c.cfg.Now = time.Now
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, HubAddress: server.Listener.Addr().String(), BootstrapCode: fresh.bootstrap(t, fresh.descriptor)}); err != nil {
		t.Fatal(err)
	}
	newScope, newDevice := c.vault.Scope(), c.device.Public().ID
	if newScope == oldScope || newDevice == oldDevice || c.owner != nil || c.state.OwnerKeyID != "" || c.session != nil || c.state.Pending != nil || c.Snapshot().Management != ManagementUnavailable || len(c.Snapshot().Profiles) != 2 || legacy.calls != 0 {
		t.Fatal("fresh TLS/bootstrap connection inherited old keys/session/request or authority")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	open := fixtureVaultOpener(root, "synthetic vault passphrase")
	reopened, _ := NewController(Config{OpenVault: open, DiscoverVaults: NewProfileDiscovery(root)})
	defer reopened.Close()
	if err := reopened.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	var id string
	for _, p := range reopened.Snapshot().Profiles {
		if p.Fingerprint == newScope.HubFingerprint {
			id = p.ID
		}
	}
	if id == "" {
		t.Fatal("new scope not discoverable")
	}
	if err := reopened.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: id}); err != nil {
		t.Fatal(err)
	}
	newCore := reopened.(*nativeController)
	if newCore.device.Public().ID != newDevice || newCore.owner != nil || newCore.state.Pending != nil {
		t.Fatal("new profile reopen changed identity/isolation")
	}
	v, err := open(ctx, oldScope, false)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	state, _, err := readProfile(v, oldScope)
	if err != nil || state.OwnerKeyID != oldOwner || state.DeviceKeyID != oldDevice || state.Pending == nil || !bytes.Equal(state.Pending.Request, original) {
		t.Fatal("fresh Add modified original offline recovery scope")
	}
	fresh.mu.Lock()
	freshPosts := len(fresh.actor.posts)
	fresh.mu.Unlock()
	if freshPosts != 0 {
		t.Fatal("new Hub received a prior-scope or automatic secret POST")
	}
}
