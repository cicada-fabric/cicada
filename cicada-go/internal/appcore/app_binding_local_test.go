package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestAppBindingRuntimeIsClearedAcrossHubSwitches(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	a, ownerA, _, _ := savedProfileFixture(t, root)
	b, ownerB, _, _ := savedProfileFixture(t, root, 0x51, 0x52)
	probe := new(profileHTTPProbe)
	controller, _ := NewController(Config{HTTP: probe, OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
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
	deviceA := c.device.Public().ID
	candidate, err := appkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// This is a component-only cleanup test, not a simulated Hub receipt.
	// Real authenticated unlink/cold-reopen is qualified by independent QA.
	c.appBinding = appBindingRuntime{generation: 1, unbound: true, candidateKey: candidate,
		rebind: &appBindingRecord{Rebind: &wire.AppRebindPrepare{}, PreparePacket: []byte("SYNTHETIC_RUNTIME_ORIGINAL")}}
	if !c.appBindingHoldsBusiness() {
		t.Fatal("fixture does not hold its local scope")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: pb.ID}); err != nil {
		t.Fatal(err)
	}
	if c.appBindingHoldsBusiness() || c.appBinding.unbind != nil || c.appBinding.rebind != nil || c.appBinding.candidateKey != nil ||
		candidate.Public().ID != "" || c.owner.Public().ID != ownerB || c.Snapshot().AppBinding.Pending {
		t.Fatal("Hub A binding runtime survived switch to B")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: pa.ID}); err != nil {
		t.Fatal(err)
	}
	if c.device.Public().ID != deviceA || c.owner.Public().ID != ownerA || c.appBindingHoldsBusiness() || len(probe.posts) != 0 {
		t.Fatal("return to A changed keys or replayed foreign binding runtime")
	}
}

func TestAppBindingUncertainOtherOriginalRejectsBeforeHousekeepingOrHTTP(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	card, _, requests, _ := savedProfileFixture(t, root)
	controller, _ := NewController(Config{OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
	defer controller.Close()
	c := controller.(*nativeController)
	ctx := context.Background()
	if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: hubProfile(t, c, card.Origin).ID}); err != nil {
		t.Fatal(err)
	}
	c.state.DeviceID = wire.AccountDeviceIDPrefix + strings.Repeat("a", 32)
	c.state.OwnerKeyIDAtHub = c.owner.Public().ID
	c.state.OwnerFingerprint, _ = e2ee.OwnerDevicePublicKeyFingerprint(c.owner.Public())
	c.state.AccountDeviceEnrolled, c.state.RootState = true, RootStateActive
	now := time.Now().UTC()
	// Synthetic local context exercises the pre-network pending guard. It is
	// never accepted by the metadata-only Hub fixture as account authority.
	c.session = &wire.SessionContext{Origin: card.Origin, HubID: card.HubID, AccountID: card.AccountID, OwnerID: card.OwnerID,
		DeviceID: c.state.DeviceID, DeviceKeyID: c.device.Public().ID, SessionToken: bytes.Repeat([]byte{0x51}, 32),
		AccountEpoch: 1, DeviceEpoch: 1, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	c.sessionInspected = true
	review := c.appBindingReview()
	cryptoKey, _ := c.device.E2EE()
	prepare, err := wire.NewLoginPrepare(c.hub, card.Origin, card.AccountID, card.OwnerID, c.state.DeviceID, "synthetic-user", c.device.Public(), now)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := wire.SealClientRequest(cryptoKey, c.hub, prepare)
	if err != nil {
		t.Fatal(err)
	}
	c.state.Pending = &pendingOperation{Operation: wire.OperationLoginPrepare, Request: packet, CreatedAt: now.Format(time.RFC3339Nano)}
	if err := c.persistState(); err != nil {
		t.Fatal(err)
	}
	path, _ := scopeVaultPath(root, cardScope(card))
	before, _ := os.ReadFile(path)
	version, count := c.stateVer, requests.Load()
	if err := c.Dispatch(ctx, Action{Kind: ActionUnbindApp, AppBinding: AppBindingAction{ReviewID: review, Confirm: true}}); !errors.Is(err, ErrInvalidAction) {
		t.Fatal("prior uncertain original did not refuse unbind at local boundary", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || c.stateVer != version || requests.Load() != count || !bytes.Equal(c.state.Pending.Request, packet) || c.appBinding.unbind != nil {
		t.Fatal("refused unlink changed original/CAS/disk or contacted Hub")
	}
}

func TestAppBindingDurableFencePreventsLegacyAssociationWithoutReceipt(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	card, _, _, _ := savedProfileFixture(t, root)
	state := newDurableState(card)
	state.DeviceID, state.OwnerKeyIDAtHub = "SYNTHETIC_OLD_DEVICE", "SYNTHETIC_OWNER"
	state.AppDeviceUnbound = true
	raw, err := encodeDurableState(state)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeDurableState(raw)
	if err != nil || decoded.AccountDeviceEnrolled {
		t.Fatal("legacy N1 association resurrected the explicitly fenced device", err)
	}
	controller, _ := NewController(Config{OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
	defer controller.Close()
	c := controller.(*nativeController)
	if err := c.Dispatch(context.Background(), Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(context.Background(), Action{Kind: ActionResumeProfile, ProfileID: hubProfile(t, c, card.Origin).ID}); err != nil {
		t.Fatal(err)
	}
	c.state.AppDeviceUnbound = true
	if err := c.loadAppBinding(); !errors.Is(err, appvault.ErrScopeMismatch) {
		t.Fatal("local unbound flag was trusted without authenticated original receipt", err)
	}
}

func TestAppBindingWholeLifecycleCapacityIsReadOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	card, _, _, _ := savedProfileFixture(t, root)
	controller, _ := NewController(Config{OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
	defer controller.Close()
	c := controller.(*nativeController)
	if err := c.Dispatch(context.Background(), Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(context.Background(), Action{Kind: ActionResumeProfile, ProfileID: hubProfile(t, c, card.Origin).ID}); err != nil {
		t.Fatal(err)
	}
	path, _ := scopeVaultPath(root, cardScope(card))
	before, _ := os.ReadFile(path)
	if err := c.checkAppBindingCapacity(); err != nil {
		t.Fatal("small retained profile cannot reserve complete lifecycle", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("capacity projection mutated the vault")
	}
	if _, err := c.vault.CompareAndSwapState("synthetic.history", 0, make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.vault.CompareAndSwapState("synthetic.history.2", 0, make([]byte, 256<<10)); err != nil {
		t.Fatal(err)
	}
	if err := c.checkAppBindingCapacity(); !errors.Is(err, appvault.ErrInvalidVault) {
		t.Fatal("whole lifecycle failed to reserve retained history plus both receipts", err)
	}
}

func TestAppBindingRefusalRetainsSessionButRequiresFreshAuthority(t *testing.T) {
	controller, _ := NewController(Config{})
	defer controller.Close()
	c := controller.(*nativeController)
	session := &wire.SessionContext{SessionToken: []byte("SYNTHETIC_SESSION_TOKEN")}
	c.session, c.sessionInspected = session, true
	c.authorizationChecked, c.nodeChecked, c.nodeContextChecked = true, true, true
	c.noteAppBindingRefusal(&appBindingRecord{Unbind: &wire.AppUnbindPrepare{}})
	if c.session != session || !bytes.Equal(c.session.SessionToken, []byte("SYNTHETIC_SESSION_TOKEN")) {
		t.Fatal("no-effect refusal discarded an existing session original")
	}
	if c.sessionInspected || !c.sessionNeedsCheck || c.authorizationChecked || c.nodeChecked || c.nodeContextChecked || !c.appBinding.unbindRejected {
		t.Fatal("authenticated refusal reused a historical management/account view")
	}
}

func TestAppBindingInitialReservationStillFitsAfterTerminalAndLocalMarker(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vaults")
	card, _, _, _ := savedProfileFixture(t, root)
	controller, _ := NewController(Config{OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
	defer controller.Close()
	c := controller.(*nativeController)
	if err := c.Dispatch(context.Background(), Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(context.Background(), Action{Kind: ActionResumeProfile, ProfileID: hubProfile(t, c, card.Origin).ID}); err != nil {
		t.Fatal(err)
	}
	var version uint64
	// Tight admission can fit a full single padding record. A second retained
	// slot makes the search reach total lifecycle capacity before that ceiling.
	if _, err := c.vault.CompareAndSwapState("synthetic.capacity-fixed", 0, make([]byte, 256<<10)); err != nil {
		t.Fatal(err)
	}
	writePadding := func(n int) {
		t.Helper()
		var err error
		version, err = c.vault.CompareAndSwapState("synthetic.capacity", version, make([]byte, n))
		if err != nil {
			t.Fatal(err)
		}
	}
	low, high := 0, 1<<20
	for low < high {
		mid := (low + high + 1) / 2
		writePadding(mid)
		if c.checkAppBindingCapacity() == nil {
			low = mid
		} else {
			high = mid - 1
		}
	}
	writePadding(low)
	if low == 0 || low == 1<<20 || c.checkAppBindingCapacity() != nil {
		t.Fatal("fixture did not reach the whole-lifecycle admission boundary")
	}
	// This is a local capacity projection, not a fabricated Hub result. The
	// authenticated carrier/receipt boundary is exercised by independent QA.
	c.state.AppDeviceUnbound, c.state.AccountDeviceEnrolled = true, false
	c.state.AccountState = AccountStateLoginRequired
	if err := c.persistState(); err != nil {
		t.Fatal(err)
	}
	presence, _ := json.Marshal(profilePresence{Format: profilePresenceNamespace, Removed: true})
	if _, err := c.vault.CompareAndSwapState(profilePresenceNamespace, 0, presence); err != nil {
		t.Fatal(err)
	}
	if err := c.checkAppBindingCapacity(); err != nil {
		t.Fatal("admitted initial lifecycle was stranded by terminal state or local Remove", err)
	}
}

func appBindingCapacityController(t *testing.T) (*nativeController, string, HubConnectionCard) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "vaults")
	card, _, _, _ := savedProfileFixture(t, root)
	controller, err := NewController(Config{OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	c := controller.(*nativeController)
	if err := c.Dispatch(context.Background(), Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(context.Background(), Action{Kind: ActionResumeProfile, ProfileID: hubProfile(t, c, card.Origin).ID}); err != nil {
		t.Fatal(err)
	}
	c.state.DeviceID = wire.AccountDeviceIDPrefix + strings.Repeat("a", 2*wire.RequestIDBytes)
	if err := c.persistState(); err != nil {
		t.Fatal(err)
	}
	return c, root, card
}

func TestAppBindingClosedRecordProjectionAndLargerOriginalRetention(t *testing.T) {
	c, _, _ := appBindingCapacityController(t)
	now := time.Date(9998, 1, 1, 0, 0, 0, 999999999, time.UTC)
	fingerprint, _ := e2ee.OwnerDevicePublicKeyFingerprint(c.device.Public())
	const epochUpper = (uint64(1) << 63) - 2
	session := wire.SessionContext{Origin: c.connection.Origin, HubID: c.connection.HubID, AccountID: c.connection.AccountID,
		OwnerID: c.connection.OwnerID, DeviceID: c.state.DeviceID, DeviceKeyID: c.device.Public().ID, DeviceKeyFingerprint: fingerprint,
		SessionToken: bytes.Repeat([]byte{0xff}, wire.MaxSessionTokenBytes), AccountEpoch: epochUpper, DeviceEpoch: epochUpper,
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	for _, rebind := range []bool{false, true} {
		upper, err := c.appBindingRecordUpperBound(rebind)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(upper)
		var record appBindingRecord
		if err := decodeStateJSON(upper, &record); err != nil {
			t.Fatal(err)
		}
		if len(record.PreparePacket) != wire.MaxAppBindingOriginalBytes || len(record.ChallengePacket) != appBindingChallengeLimit ||
			len(record.CompletePacket) != maxDurablePacketSize || len(record.ResultPacket) != appBindingResultLimit || len(upper) >= appBindingRecordLimit {
			t.Fatal("closed projection did not retain every complete packet/receipt ceiling")
		}
		if rebind {
			q, err := wire.NewAppRebindPrepare(c.hub, c.connection.Origin, c.connection.AccountID, c.connection.OwnerID,
				c.state.DeviceID, strings.Repeat("f", 64), wire.AccountDeviceIDPrefix+strings.Repeat("b", 2*wire.RequestIDBytes), c.owner.Public(), now)
			if err != nil {
				t.Fatal(err)
			}
			record.Rebind = &q
		} else {
			q, err := wire.NewAppUnbindPrepare(session, c.owner.Public(), now)
			if err != nil {
				t.Fatal(err)
			}
			record.Unbind = &q
		}
		actual, err := json.Marshal(record)
		if err != nil || len(actual) > len(upper) {
			t.Fatal("legal constructor maximum escaped projection", err)
		}
		clear(actual)
	}
	upper, _ := c.appBindingRecordUpperBound(false)
	defer clear(upper)
	retained := bytes.Repeat([]byte{0x53}, len(upper)+17)
	defer clear(retained)
	if _, err := c.vault.CompareAndSwapState(appUnbindNamespace, 0, retained); err != nil {
		t.Fatal(err)
	}
	projected, err := c.appBindingRecordUpperBound(false)
	defer clear(projected)
	if err != nil || !bytes.Equal(projected, retained) {
		t.Fatal("larger existing original was truncated by upper projection", err)
	}
}

func TestAppBindingMeasuredHistoryFitsEveryMaximumStoragePhase(t *testing.T) {
	c, root, card := appBindingCapacityController(t)
	// Root's failed real TLS Node/Group case had these 12 retained slot sizes,
	// totaling 1,175,776 bytes. Use opaque synthetic payloads of that footprint
	// PLUS the real local account state; this storage test claims no Hub proof.
	sizes := []int{0, 0, 0, 0, 929, 41740, 48236, 54575, 71140, 90727, 429849, 438580}
	for i, size := range sizes {
		if _, err := c.vault.CompareAndSwapState(fmt.Sprintf("synthetic.measured.%02d", i), 0, bytes.Repeat([]byte{0x53}, size)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.checkAppBindingCapacity(); err != nil {
		t.Fatal("normal measured Node/Group footprint cannot start unlink", err)
	}
	ownerBefore, err := c.owner.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ownerBefore)
	oldKey := c.device.Public().ID
	unbound, err := c.appBindingRecordUpperBound(false)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(unbound)
	unboundVersion, err := c.vault.CompareAndSwapState(appUnbindNamespace, 0, unbound)
	if err != nil {
		t.Fatal(err)
	}
	c.state.AppDeviceUnbound, c.state.AccountDeviceEnrolled = true, false
	c.state.AccountState = AccountStateLoginRequired
	if err := c.persistState(); err != nil {
		t.Fatal(err)
	}
	presence, _ := json.Marshal(profilePresence{Format: profilePresenceNamespace, Removed: true})
	if _, err := c.vault.CompareAndSwapState(profilePresenceNamespace, 0, presence); err != nil {
		t.Fatal(err)
	}
	if err := c.checkAppBindingCapacity(); err != nil {
		t.Fatal("admitted maximum unbind/marker state stranded rebind", err)
	}
	candidate, err := c.vault.PrepareAppDevice(oldKey, appvault.NewStateGuard(appUnbindNamespace, unboundVersion, unbound))
	if err != nil {
		t.Fatal(err)
	}
	rebound, err := c.appBindingRecordUpperBound(true)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rebound)
	completionVersion, err := c.vault.CompareAndSwapState(appRebindNamespace, 0, rebound)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.checkAppBindingCapacity(); err != nil {
		t.Fatal("maximum stored rebind completion cannot promote", err)
	}
	versions, err := c.vault.StateVersions()
	if err != nil {
		t.Fatal(err)
	}
	type savedState struct {
		raw     []byte
		version uint64
	}
	saved := make(map[string]savedState)
	defer func() {
		for _, state := range saved {
			clear(state.raw)
		}
	}()
	for name := range versions {
		raw, version, _, err := c.vault.LoadState(name)
		if err != nil {
			t.Fatal(err)
		}
		saved[name] = savedState{raw, version}
	}
	if _, ok := versions[appSessionNamespace]; !ok {
		versions[appSessionNamespace] = 0
	}
	fresh := c.freshAppBindingState(wire.AccountDeviceIDPrefix+strings.Repeat("b", 2*wire.RequestIDBytes), candidate.KeyID)
	fresh.ObservedDeviceEpoch = 1
	freshRaw, err := encodeDurableState(fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(freshRaw)
	if _, err := c.vault.PromoteAppDevice(appvault.AppDevicePromotion{CurrentKeyID: oldKey, Candidate: candidate,
		Completion: appvault.NewStateGuard(appRebindNamespace, completionVersion, rebound), ExpectedVersions: versions,
		SessionNamespace: appSessionNamespace, Updates: map[string][]byte{appStateNamespace: freshRaw, appSessionNamespace: nil, profilePresenceNamespace: presence}}); err != nil {
		t.Fatal("full maximum storage lifecycle could not atomically promote", err)
	}
	if err := c.vault.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := fixtureVaultOpener(root, "synthetic vault passphrase")(context.Background(), cardScope(card), false)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	status, err := opened.AppDeviceStatus()
	if err != nil || status.Generation != 2 || status.CurrentKeyID != candidate.KeyID || status.Candidate != nil || len(status.Retired) != 1 {
		t.Fatal("cold storage promotion lost identity generation", err)
	}
	for name, original := range saved {
		raw, version, found, err := opened.LoadRetiredAppDeviceState(1, name)
		if err != nil || !found || version != original.version || !bytes.Equal(raw, original.raw) {
			t.Fatal("retirement lost original bytes/version", name, err)
		}
		clear(raw)
	}
	owner, err := opened.Get(appvault.PurposeOwnerSigner, c.owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	ownerAfter, err := owner.MarshalBinary()
	defer clear(ownerAfter)
	if err != nil || !bytes.Equal(ownerBefore, ownerAfter) {
		t.Fatal("maximum lifecycle changed retained Owner", err)
	}
	if session, _, _, err := opened.LoadState(appSessionNamespace); err != nil || len(session) != 0 {
		t.Fatal("cold promotion inherited a session", err)
	}
}
