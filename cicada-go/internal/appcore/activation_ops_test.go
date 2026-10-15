package appcore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

// This is a crypto/actor fixture, not a replacement production Hub. Backend
// authority, transactions and races have separate real-handler acceptance.
type activationActorFixture struct {
	t                    *testing.T
	now                  time.Time
	hubKey               *e2ee.Identity
	hub                  wire.HubIdentity
	material             wire.ActivationMaterial
	challenge            wire.ActivationChallenge
	nonceDigest          string
	packets              map[string][]byte
	requests             map[string][]byte
	posts                [][]byte
	lost                 string
	denyComplete         bool
	absent               bool
	refused              bool
	completed            bool
	dropStatusUnaccepted bool
	revoked              bool
	beforePost           func(string, []byte)
}

func newActivationActorFixture(t *testing.T) *activationActorFixture {
	t.Helper()
	h, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := &activationActorFixture{t: t, now: time.Now().UTC(), hubKey: h, packets: make(map[string][]byte), requests: make(map[string][]byte)}
	f.hub = wire.HubIdentity{Contract: "android-hub-v1", HubID: "hub_synthetic", Public: h.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	pin, err := wire.HubFingerprint(f.hub)
	if err != nil {
		t.Fatal(err)
	}
	f.material = wire.ActivationMaterial{Format: wire.ActivationFormat, Version: 1, Purpose: wire.PurposeInitialActivation,
		Origin: "https://hub.synthetic.invalid", HubID: f.hub.HubID, HubFingerprint: pin, AccountID: "account_synthetic", OwnerID: "owner_synthetic",
		ActivationID: strings.Repeat("a", 32), SetupEpoch: 1, AccountEpoch: 1, Code: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32)),
		IssuedAt: f.now.Format(time.RFC3339Nano), ExpiresAt: f.now.Add(time.Hour).Format(time.RFC3339Nano)}
	return f
}

func (f *activationActorFixture) Do(req *http.Request) (*http.Response, error) {
	reply := func(raw []byte, status int) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header), Request: req}, nil
	}
	if req.Method == http.MethodGet {
		var raw []byte
		if req.URL.Path == "/healthz" {
			raw = []byte(`{"status":"ok","service":"synthetic-hub"}`)
		} else {
			raw, _ = json.Marshal(f.hub)
		}
		return reply(raw, 200)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	f.posts = append(f.posts, bytes.Clone(raw))
	p, err := wire.DecodePacket(raw)
	if err != nil {
		f.t.Fatal("invalid synthetic actor request")
	}
	route := p.Packet.Route
	if req.URL.Path != wire.ActivationHTTPPath(route.Operation) {
		f.t.Fatal("wrong activation route")
	}
	if f.beforePost != nil {
		f.beforePost(route.Operation, raw)
	}
	digest := wire.ActivationPacketDigest(raw)
	if saved := f.packets[digest]; saved != nil {
		return reply(saved, 200)
	}
	binding := clientwire.Binding{HubID: f.hub.HubID, OwnerID: route.OwnerID, DeviceID: route.DeviceID, SessionEpoch: route.SessionEpoch, HubKeyVersion: 1, DeviceKeyVersion: 1}
	var value any
	switch route.Operation {
	case wire.OperationActivationPrepare:
		var prepare wire.ActivationPrepare
		if err := wire.OpenRequestAt(f.hubKey, nil, binding, route, raw, &prepare, f.now); err != nil {
			f.t.Fatal("prepare envelope rejected")
		}
		b := wire.ActivationBinding{Format: wire.ActivationFormat, Purpose: prepare.Material.Purpose, Origin: f.material.Origin, HubID: f.hub.HubID,
			HubFingerprint: f.material.HubFingerprint, AccountID: f.material.AccountID, OwnerID: f.material.OwnerID, ActivationID: f.material.ActivationID,
			SetupEpoch: 1, AccountEpoch: 1, DeviceEpoch: 1, OwnerPublic: prepare.OwnerPublic, DeviceID: prepare.DeviceID, DevicePublic: p.SenderPublicIdentity,
			PrepareRequestID: prepare.RequestID, PreparePacketDigest: digest, GrantDigest: wire.ActivationGrantDigest(prepare.OwnerDeviceGrant),
			AllowedOperations: wire.ActivationAllowedOperations(), LeaseExpiresAt: f.now.Add(wire.MaxAppLeaseLifetime).Format(time.RFC3339Nano)}
		pair := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: b.Origin, Hub: f.hub, Manifest: ownerbootstrap.Manifest{
			Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: b.AccountID, OwnerID: b.OwnerID, HubID: b.HubID, AuthorityID: b.ActivationID,
			OperationID: b.Digest(), CandidatePublic: b.OwnerPublic, CandidateFingerprint: ownerbootstrap.Fingerprint(b.OwnerPublic), ExpiresAt: f.now.Add(10 * time.Minute).Format(time.RFC3339Nano)}}
		pair, f.nonceDigest, err = ownerbootstrap.CreateChallenge(f.hubKey, pair, f.now)
		if err != nil {
			f.t.Fatal(err)
		}
		nonce, err := wire.NewNonce()
		if err != nil {
			f.t.Fatal(err)
		}
		f.challenge = wire.ActivationChallenge{Format: wire.ActivationChallengeFormat, Binding: b, ClientNonce: prepare.ClientNonce, ServerNonce: nonce,
			Proof: pair, IssuedAt: f.now.Format(time.RFC3339Nano), ExpiresAt: pair.Manifest.ExpiresAt}
		value = f.challenge
	case wire.OperationActivationComplete:
		var complete wire.ActivationComplete
		if err := wire.OpenRequestAt(f.hubKey, &p.SenderPublicIdentity, binding, route, raw, &complete, f.now); err != nil {
			f.t.Fatal("complete envelope rejected")
		}
		if f.denyComplete {
			return reply([]byte("synthetic intermediary rejection"), 403)
		}
		digest, err := ownerbootstrap.VerifyProof(f.hubKey, f.challenge.Proof, complete.OwnerProof, f.now)
		if err != nil || digest != f.nonceDigest {
			f.t.Fatal("native actor did not prove both existing Owner private keys")
		}
		f.completed = true
		value = wire.ActivationResult{Format: wire.ActivationResultFormat, Operation: route.Operation, RequestID: route.OperationID,
			RequestPacketDigest: wire.ActivationPacketDigest(raw), Origin: f.material.Origin, HubID: f.hub.HubID, AccountID: f.material.AccountID,
			OwnerID: f.material.OwnerID, ActivationID: f.material.ActivationID, DeviceID: route.DeviceID, AccountEpoch: 1, DeviceEpoch: 1,
			State: wire.ActivationCompleted, RootState: wire.RootActiveState, LeaseState: wire.ActivationLeaseActive,
			LeaseExpiresAt: f.challenge.Binding.LeaseExpiresAt, AllowedOperations: wire.ActivationAllowedOperations(), LoginRequired: true, ObservedAt: f.now.Format(time.RFC3339Nano)}
	case wire.OperationActivationStatus:
		var status wire.ActivationStatusRequest
		if err := wire.OpenRequestAt(f.hubKey, &p.SenderPublicIdentity, binding, route, raw, &status, f.now); err != nil {
			return reply([]byte("synthetic expired recovery query"), 403)
		}
		if f.dropStatusUnaccepted {
			f.dropStatusUnaccepted = false
			return nil, errors.New("synthetic status failed before acceptance")
		}
		result := wire.ActivationResult{Format: wire.ActivationResultFormat, Operation: route.Operation, RequestID: route.OperationID, RequestPacketDigest: digest,
			Origin: f.material.Origin, HubID: f.hub.HubID, AccountID: f.material.AccountID, OwnerID: f.material.OwnerID, ActivationID: f.material.ActivationID,
			DeviceID: route.DeviceID, AccountEpoch: 1, DeviceEpoch: 1, State: wire.ActivationCompleted, RootState: wire.RootActiveState,
			LeaseState: wire.ActivationLeaseActive, LeaseExpiresAt: f.challenge.Binding.LeaseExpiresAt, AllowedOperations: wire.ActivationAllowedOperations(),
			LoginRequired: true, TargetOperation: status.TargetOperation, TargetRequestID: status.TargetRequestID, TargetPacketDigest: status.TargetPacketDigest,
			TargetState: wire.ActivationCompleted, ReceiptPacket: f.packets[status.TargetPacketDigest], ObservedAt: f.now.Format(time.RFC3339Nano)}
		if !f.completed {
			result.State = wire.ActivationPrepared
			result.RootState = wire.RootPendingState
			result.LeaseState = wire.ActivationLeaseUnavailable
			result.AllowedOperations = nil
		}
		if f.revoked {
			result.RootState = wire.RootUnavailableState
			result.LeaseState = wire.ActivationLeaseRevoked
			result.AllowedOperations = nil
		}
		if f.absent || f.refused {
			result.State = wire.ActivationPrepared
			result.RootState = wire.RootPendingState
			result.LeaseState = wire.ActivationLeaseUnavailable
			result.AllowedOperations = nil
			result.ReceiptPacket = nil
			result.TargetState = wire.ActivationAbsent
			if f.refused {
				result.TargetState = wire.ActivationRejected
			}
		}
		value = result
	default:
		f.t.Fatal("unexpected actor fixture operation")
	}
	response, err := wire.SealResponse(f.hubKey, p.SenderPublicIdentity, route, value)
	if err != nil {
		encoded, _ := json.Marshal(value)
		receiptSize := 0
		if result, ok := value.(wire.ActivationResult); ok {
			receiptSize = len(result.ReceiptPacket)
		}
		f.t.Fatalf("synthetic %s response could not be sealed (body=%d receipt=%d)", route.Operation, len(encoded), receiptSize)
	}
	f.packets[digest], f.requests[digest] = bytes.Clone(response), bytes.Clone(raw)
	if f.lost == route.Operation {
		f.lost = ""
		return nil, errors.New("synthetic lost response")
	}
	return reply(response, 200)
}

func (f *activationActorFixture) controller(t *testing.T, root string) Controller {
	t.Helper()
	c, err := NewController(Config{HTTP: f, Now: func() time.Time { return f.now }, OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root)})
	if err != nil {
		t.Fatal(err)
	}
	f.beforePost = func(operation string, packet []byte) {
		raw, _, found, err := c.(*nativeController).vault.LoadState(appStateNamespace)
		if err != nil || !found {
			t.Fatal("network preceded durable App state")
		}
		defer clear(raw)
		state, err := decodeDurableState(raw)
		if err != nil {
			t.Fatal("durable actor state invalid")
		}
		pending := state.Pending
		if operation == wire.OperationActivationStatus {
			pending = state.Recovery
		}
		if pending == nil || !bytes.Equal(pending.Request, packet) {
			t.Fatal("network preceded exact packet persistence")
		}
	}
	return c
}

func TestNativeActivationRequiresFiniteConsentAndProvesKeysInProcess(t *testing.T) {
	f := newActivationActorFixture(t)
	root := filepath.Join(t.TempDir(), "vaults")
	c := f.controller(t, root)
	defer c.Close()
	code, err := wire.EncodeActivationCode(f.material)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err == nil || len(f.posts) != 0 {
		t.Fatal("activation bypassed human scope confirmation")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err != nil {
		t.Fatal(err)
	}
	s := c.Snapshot()
	if s.Account.RootState != RootStateActive || s.Authorization.State != "LOGIN_REQUIRED" || s.Authorization.Confirmed || s.Management != ManagementUnavailable {
		t.Fatalf("proof without login became management authority: %+v", s)
	}
	if !reflect.DeepEqual(s.Authorization.AllowedOperations, wire.ActivationAllowedOperations()) {
		t.Fatal("App scope differs from finite allowlist")
	}
	f.now = f.now.Add(16 * time.Minute)
	if s := c.Snapshot(); s.Authorization.State != "EXPIRED" || s.Authorization.Confirmed {
		t.Fatal("local lease deadline failed closed")
	}
}

func TestNativeActivationResponseLossRestoresSameOwnerAndExactPrepare(t *testing.T) {
	f := newActivationActorFixture(t)
	f.lost = wire.OperationActivationPrepare
	root := filepath.Join(t.TempDir(), "vaults")
	c := f.controller(t, root)
	ctx := context.Background()
	code, _ := wire.EncodeActivationCode(f.material)
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	owner := c.(*nativeController).owner.Public().ID
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err == nil {
		t.Fatal("lost prepare response was reported complete")
	}
	first := bytes.Clone(f.posts[0])
	defer clear(first)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c = f.controller(t, root)
	defer c.Close()
	if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: c.Snapshot().Profiles[0].ID}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, f.posts[1]) || c.(*nativeController).owner.Public().ID != owner {
		t.Fatal("restart changed Owner identity or exact prepare")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeActivationAbsentCannotSettleButAuthenticatedFenceCan(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "fenced"}[refused], func(t *testing.T) {
			f := newActivationActorFixture(t)
			f.denyComplete, f.absent, f.refused = true, !refused, refused
			c := f.controller(t, filepath.Join(t.TempDir(), "vaults"))
			defer c.Close()
			ctx := context.Background()
			code, _ := wire.EncodeActivationCode(f.material)
			if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
				t.Fatal(err)
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
				t.Fatal(err)
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err == nil {
				t.Fatal("unsigned rejection settled activation")
			}
			original := bytes.Clone(c.(*nativeController).state.Pending.Request)
			defer clear(original)
			if err := c.Dispatch(ctx, Action{Kind: ActionRecover}); err != nil {
				t.Fatal(err)
			}
			pending := c.(*nativeController).state.Pending
			if refused {
				if pending != nil {
					t.Fatal("authenticated exact refusal did not settle original")
				}
			} else if pending == nil || !bytes.Equal(original, pending.Request) || len(pending.Response) != 0 {
				t.Fatal("ABSENT discarded uncertain original")
			}
			if s := c.Snapshot(); s.Authorization.Confirmed || s.Management != ManagementUnavailable {
				t.Fatal("recovery created authority")
			}
		})
	}
}

func activatedActor(t *testing.T) (*activationActorFixture, Controller) {
	t.Helper()
	f := newActivationActorFixture(t)
	c := f.controller(t, filepath.Join(t.TempDir(), "vaults"))
	t.Cleanup(func() { c.Close() })
	ctx := context.Background()
	code, _ := wire.EncodeActivationCode(f.material)
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err != nil {
		t.Fatal(err)
	}
	return f, c
}

func TestSnapshotSessionDeadlineDecaysWithoutNetworkAndKeepsPendingFence(t *testing.T) {
	f, c := activatedActor(t)
	n := c.(*nativeController)
	n.session = &wire.SessionContext{AccountEpoch: 1, DeviceEpoch: 1, ExpiresAt: f.now.Add(5 * time.Second).Format(time.RFC3339Nano)}
	n.sessionInspected, n.sessionNeedsCheck = true, false
	n.state.Enrollment.Result.LoginRequired = false
	n.publish()
	if !c.Snapshot().Authorization.Confirmed {
		t.Fatal("synthetic current session did not expose the finite deadline test state")
	}
	posts := len(f.posts)
	f.now = f.now.Add(6 * time.Second)
	s := c.Snapshot()
	if s.Authorization.Confirmed || s.Account.State != AccountStateLoginRequired || s.Phase == PhaseOwnerReady || containsAction(s.AvailableActions, ActionRefresh) {
		t.Fatal("expired session remained ready")
	}
	if len(f.posts) != posts {
		t.Fatal("deadline decay sent a network request")
	}
	n.state.Pending = &pendingOperation{Operation: wire.OperationSessionInspect, Request: []byte("synthetic pending marker")}
	n.publish()
	if containsAction(c.Snapshot().AvailableActions, ActionLogin) {
		t.Fatal("session expiry bypassed an uncertain packet")
	}
}

func TestActivationCurrentRevocationWinsOverNestedHistoricalReceipt(t *testing.T) {
	f, c := activatedActor(t)
	f.revoked = true
	if err := c.Dispatch(context.Background(), Action{Kind: ActionActivationStatus}); err != nil {
		t.Fatal(err)
	}
	s := c.Snapshot()
	if s.Account.RootState != RootStateUnavailable || s.Authorization.State != "REVOKED" || s.Authorization.Confirmed || containsAction(s.AvailableActions, ActionActivateApp) {
		t.Fatal("historical completion resurrected revoked Root or App access")
	}
	// Replaying the previously committed completion is historical too.
	if err := c.(*nativeController).loadCurrentPendingResponse(); err != nil {
		t.Fatal(err)
	}
	if c.Snapshot().Account.RootState != RootStateUnavailable {
		t.Fatal("saved completion overwrote known revocation")
	}
}

func TestExpiredRecoveryQueryKeepsBusinessPacketAndRenewsOnlyObservation(t *testing.T) {
	f := newActivationActorFixture(t)
	f.dropStatusUnaccepted = true
	c := f.controller(t, filepath.Join(t.TempDir(), "vaults"))
	defer c.Close()
	ctx := context.Background()
	code, _ := wire.EncodeActivationCode(f.material)
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err == nil {
		t.Fatal("lost status was reported current")
	}
	n := c.(*nativeController)
	original := bytes.Clone(n.state.Pending.Request)
	query := bytes.Clone(n.state.Recovery.Request)
	defer clear(original)
	defer clear(query)
	f.now = f.now.Add(2 * time.Minute)
	if err := c.Dispatch(ctx, Action{Kind: ActionRecover}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, n.state.Pending.Request) || len(n.state.RecoveryHistory) != 1 || n.state.Recovery != nil {
		t.Fatal("recovery query expiry replaced business packet or grew unbounded state")
	}
	if len(f.posts) != 5 || !bytes.Equal(query, f.posts[3]) || bytes.Equal(query, f.posts[4]) {
		t.Fatal("expired recovery query was not replayed before a new observation")
	}
}

func TestCachedStatusRetryAlwaysRequiresAnIndependentFreshObservation(t *testing.T) {
	f, c := activatedActor(t)
	f.lost = wire.OperationActivationStatus
	if err := c.Dispatch(context.Background(), Action{Kind: ActionActivationStatus}); err == nil {
		t.Fatal("lost status was reported current")
	}
	query := bytes.Clone(c.(*nativeController).state.Recovery.Request)
	defer clear(query)
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRecover}); err != nil {
		t.Fatal(err)
	}
	if len(f.posts) != 6 || !bytes.Equal(query, f.posts[4]) || bytes.Equal(query, f.posts[5]) {
		t.Fatal("a cached same-instant observation was treated as fresh authorization")
	}
}
