package appcore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

type accountHTTPRecorder struct {
	base HTTPDoer

	mu          sync.Mutex
	paths       []string
	packets     [][]byte
	spoofFirst  bool
	spoofedOnce bool
}

func (r *accountHTTPRecorder) Do(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost {
		return r.base.Do(request)
	}
	packet, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(packet))
	r.mu.Lock()
	r.paths = append(r.paths, request.URL.Path)
	r.packets = append(r.packets, bytes.Clone(packet))
	shouldSpoof := r.spoofFirst && !r.spoofedOnce
	if shouldSpoof {
		r.spoofedOnce = true
	}
	r.mu.Unlock()
	defer clear(packet)

	response, err := r.base.Do(request)
	if err != nil || !shouldSpoof || response.StatusCode != http.StatusOK {
		return response, err
	}
	response.Body.Close()
	return &http.Response{Status: "403 Forbidden", StatusCode: http.StatusForbidden,
		Header: make(http.Header), Body: io.NopCloser(strings.NewReader("synthetic intermediary rejection")), Request: request}, nil
}

func (r *accountHTTPRecorder) snapshot() ([]string, [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	paths := append([]string(nil), r.paths...)
	packets := make([][]byte, len(r.packets))
	for i := range r.packets {
		packets[i] = bytes.Clone(r.packets[i])
	}
	return paths, packets
}

func (r *accountHTTPRecorder) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, packet := range r.packets {
		clear(packet)
	}
	r.packets = nil
	r.paths = nil
}

func TestControllerRealHTTPAccountFlowAndExactUncertainRecovery(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "hub", "cicada.sqlite3")
	stateDir := filepath.Join(t.TempDir(), "hub-state")
	db, err := store.New(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "http://" + listener.Addr().String()
	setup, err := db.InitializeHubOwnerLocal("Synthetic native App fixture", origin, true)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ids, err := hubidentity.LoadOrCreate(stateDir, "")
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	owner, err := hubowner.NewService(db, ids)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	auth, err := hubauth.NewService(db, ids)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	fixture := httptestServer(t, listener, server.NewHubHandlerWithAccount(owner, auth))
	card, err := auth.IssueClaimLocal(false)
	if err != nil {
		t.Fatal(err)
	}
	if card.Origin != fixture.URL || card.Origin != setup.Origin {
		t.Fatal("synthetic account card origin does not match the real HTTP fixture")
	}
	activation, err := NewActivationCode(*card)
	if err != nil {
		t.Fatal("could not create synthetic App activation code")
	}
	activationText := activation.Encode()
	if activationText == "" || strings.Contains(activationText, "://") {
		t.Fatal("activation code was not a compact local code")
	}

	recorder := &accountHTTPRecorder{base: NewHTTPClient(), spoofFirst: true}
	vaultRoot := filepath.Join(t.TempDir(), "vaults")
	openVault := func(_ context.Context, scope appvault.Scope, create bool) (*appvault.Vault, error) {
		path, pathErr := scopeVaultPath(vaultRoot, scope)
		if pathErr != nil {
			return nil, pathErr
		}
		protector, protectorErr := appvault.NewPasswordProtector([]byte("synthetic vault passphrase"))
		if protectorErr != nil {
			return nil, protectorErr
		}
		_, statErr := os.Lstat(path)
		if errors.Is(statErr, os.ErrNotExist) {
			if !create {
				protector.Close()
				return nil, appvault.ErrStateNotFound
			}
			return appvault.Create(path, scope, protector)
		}
		if statErr != nil {
			protector.Close()
			return nil, statErr
		}
		return appvault.Open(path, scope, protector)
	}
	newController := func() Controller {
		controller, controllerErr := NewController(Config{HTTP: recorder, OpenVault: openVault, AllowLoopbackHTTP: true})
		if controllerErr != nil {
			t.Fatal(controllerErr)
		}
		return controller
	}
	controller := newController()
	defer controller.Close()
	ctx := context.Background()
	if err := controller.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: activationText}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got := controller.Snapshot(); !got.Hub.Verified || got.Management != ManagementUnavailable || got.Canvas.State != CanvasNoAuthorization {
		t.Fatalf("verified connection overstated authority: %+v", got)
	}

	// A failed durable commit poisons the actor. It must not put a packet on
	// the network from memory-only state, and only a fresh reconnect can resume.
	native := controller.(*nativeController)
	if err := native.vault.Close(); err != nil {
		t.Fatal(err)
	}
	if err := controller.Dispatch(ctx, Action{Kind: ActionClaimPrepare}); err == nil {
		t.Fatal("claim prepare succeeded after the vault was closed")
	}
	paths, packets := recorder.snapshot()
	if len(paths) != 0 || len(packets) != 0 {
		t.Fatal("failed exact-request commit sent a packet from memory-only state")
	}
	if got := controller.Snapshot(); got.Phase != PhaseError || !reflect.DeepEqual(got.AvailableActions, []ActionKind{ActionConnect}) || got.Account.State != AccountStateUnknown {
		t.Fatalf("storage fault did not fail closed: %+v", got)
	}
	if err := controller.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: activationText}); err != nil {
		t.Fatalf("reconnect after storage failure: %v", err)
	}
	if err := controller.Dispatch(ctx, Action{Kind: ActionClaimPrepare}); err == nil || controller.Snapshot().ErrorCode != "ACCOUNT_RESPONSE_UNKNOWN" {
		t.Fatalf("expected advisory response uncertainty after intermediary 403: err=%v state=%+v", err, controller.Snapshot())
	}
	if got := controller.Snapshot(); !containsAction(got.AvailableActions, ActionRetry) || containsAction(got.AvailableActions, ActionClaimComplete) {
		t.Fatalf("unauthenticated HTTP status settled a claim request: %+v", got)
	}
	paths, packets = recorder.snapshot()
	if len(paths) != 1 || len(packets) != 1 {
		t.Fatal("unexpected packet count after ambiguous response")
	}
	firstClaimPrepare := bytes.Clone(packets[0])
	for _, packet := range packets {
		clear(packet)
	}

	// Simulate process restart with the exact pending packet encrypted in the
	// vault. A matching activation code only selects this existing scope; the
	// server's consumed one-use code is never sent again.
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	controller = newController()
	defer controller.Close()
	if err := controller.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: activationText}); err != nil {
		t.Fatalf("reopen encrypted pending state: %v", err)
	}
	if got := controller.Snapshot(); !containsAction(got.AvailableActions, ActionRetry) {
		t.Fatalf("pending exact recovery was not restored: %+v", got)
	}
	if err := controller.Dispatch(ctx, Action{Kind: ActionRetry}); err != nil {
		t.Fatalf("exact claim prepare recovery: %v", err)
	}
	paths, packets = recorder.snapshot()
	if len(paths) != 2 || paths[0] != paths[1] || !bytes.Equal(firstClaimPrepare, packets[1]) {
		t.Fatal("restart recovery did not retry the original encrypted request bytes")
	}
	clear(firstClaimPrepare)
	for _, packet := range packets {
		clear(packet)
	}
	if err := controller.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatalf("generate local Owner signer: %v", err)
	}
	password := "Purple sky windows Garden 42!"
	if err := controller.Dispatch(ctx, Action{Kind: ActionClaimComplete, Username: "native-owner", Password: password}); err != nil {
		t.Fatalf("complete initial account claim: %v", err)
	}
	if got := controller.Snapshot(); got.Account.RootState != RootStatePending || !got.Account.LocalOwnerKeyPresent || got.Phase == PhaseOwnerReady || got.Management != ManagementUnavailable {
		t.Fatalf("pending Owner key was misrepresented as Root or Manager authority: %+v", got)
	}
	if err := controller.Dispatch(ctx, Action{Kind: ActionLoginPrepare, Username: "native-owner"}); err != nil {
		t.Fatalf("login prepare: %v", err)
	}
	if err := controller.Dispatch(ctx, Action{Kind: ActionLoginComplete, Password: password}); err != nil {
		t.Fatalf("login complete: %v", err)
	}
	if got := controller.Snapshot(); got.Phase != PhaseSessionCheck || got.Management != ManagementUnavailable {
		t.Fatalf("login receipt granted offline or management authority: %+v", got)
	}
	if err := controller.Dispatch(ctx, Action{Kind: ActionSessionInspect}); err != nil {
		t.Fatalf("session inspect: %v", err)
	}
	if got := controller.Snapshot(); got.Phase != PhaseAccountSession || got.Account.State != AccountStateOwnerProof || got.Account.RootState != RootStatePending || got.Management != ManagementUnavailable {
		t.Fatalf("session inspection overstated Owner/management authority: %+v", got)
	}
	if err := controller.Dispatch(ctx, Action{Kind: ActionLogout}); err != nil {
		t.Fatalf("session logout: %v", err)
	}
	if got := controller.Snapshot(); got.Account.State != AccountStateLoginRequired || got.Management != ManagementUnavailable {
		t.Fatalf("logout did not return to login-required state: %+v", got)
	}

	paths, packets = recorder.snapshot()
	defer func() {
		for _, packet := range packets {
			clear(packet)
		}
		recorder.clear()
	}()
	expected := []string{
		"/v2/owner/account/claim/prepare", "/v2/owner/account/claim/prepare",
		"/v2/owner/account/claim/complete", "/v2/owner/account/login/prepare",
		"/v2/owner/account/login/complete", "/v2/owner/account/session/inspect",
		"/v2/owner/account/session/logout",
	}
	if !reflect.DeepEqual(paths, expected) {
		t.Fatalf("real HTTP account API operations = %v, want %v", paths, expected)
	}
}

func containsAction(actions []ActionKind, action ActionKind) bool {
	for _, candidate := range actions {
		if candidate == action {
			return true
		}
	}
	return false
}

// httptestServer starts the real Hub handler on a pre-bound listener so the
// synthetic deployment origin in SQLite and the claim card match exactly.
func httptestServer(t *testing.T, listener net.Listener, handler http.Handler) *httptest.Server {
	t.Helper()
	instance := httptest.NewUnstartedServer(handler)
	instance.Listener = listener
	instance.Start()
	t.Cleanup(instance.Close)
	return instance
}
