package appcore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

const n2SyntheticPassword = "Synthetic App meadow 72!"

type n2AppHTTP struct {
	mu         sync.Mutex
	base       HTTPDoer
	dropPath   string
	packets    map[string][][]byte
	beforePost func(string, []byte)
}

func (r *n2AppHTTP) Do(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost {
		return r.base.Do(req)
	}
	packet, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	defer clear(packet)
	req.Body = io.NopCloser(bytes.NewReader(packet))
	r.mu.Lock()
	r.packets[req.URL.Path] = append(r.packets[req.URL.Path], bytes.Clone(packet))
	observer := r.beforePost
	r.mu.Unlock()
	if observer != nil {
		observer(req.URL.Path, packet)
	}
	response, err := r.base.Do(req)
	if err != nil {
		return response, err
	}
	r.mu.Lock()
	drop := r.dropPath == req.URL.Path && response.StatusCode == 200
	if drop {
		r.dropPath = ""
	}
	r.mu.Unlock()
	if drop {
		response.Body.Close()
		return nil, errors.New("synthetic response lost after Hub commit")
	}
	return response, nil
}

func (r *n2AppHTTP) records(path string) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	var packets [][]byte
	for _, p := range r.packets[path] {
		packets = append(packets, bytes.Clone(p))
	}
	return packets
}

type n2AppHub struct {
	dbPath, stateDir, origin string
	db                       *store.Store
	auth                     *hubauth.Service
	setup                    *store.HubOwnerSetup
	http                     *httptest.Server
	transport                *n2AppHTTP
}

func newN2AppHub(t *testing.T) *n2AppHub {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	f := &n2AppHub{dbPath: filepath.Join(root, "hub", "synthetic.sqlite3"), stateDir: filepath.Join(root, "identity"),
		origin: "http://" + listener.Addr().String(), transport: &n2AppHTTP{base: NewHTTPClient(), packets: make(map[string][][]byte)}}
	f.db, err = store.New(f.dbPath)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	f.setup, err = f.db.InitializeHubOwnerLocal("Synthetic native N2 Owner", f.origin, true)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	f.start(t, listener)
	t.Cleanup(func() { f.http.Close(); f.db.Close() })
	return f
}

func (f *n2AppHub) start(t *testing.T, listener net.Listener) {
	t.Helper()
	ids, err := hubidentity.LoadOrCreate(f.stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := hubowner.NewService(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	f.auth, err = hubauth.NewService(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	// Production routes, account/Owner services, SQLite and PQC; no Control.
	f.http = httptestServer(t, listener, server.NewHubHandlerWithAccount(owner, f.auth))
}

func (f *n2AppHub) restart(t *testing.T, mutate func(*sql.DB)) {
	t.Helper()
	f.http.Close()
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		db, err := sql.Open("sqlite", f.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		mutate(db)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	f.db, err = store.New(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	address := f.origin[len("http://"):]
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, listener)
}

func (f *n2AppHub) controller(t *testing.T, root string) Controller {
	t.Helper()
	c, err := NewController(Config{HTTP: f.transport, OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	f.transport.mu.Lock()
	f.transport.beforePost = func(path string, packet []byte) {
		raw, _, found, err := c.(*nativeController).vault.LoadState(appStateNamespace)
		if err != nil || !found {
			t.Fatal("HTTP preceded durable App state")
		}
		defer clear(raw)
		state, err := decodeDurableState(raw)
		if err != nil {
			t.Fatal("stored App state is invalid")
		}
		pending := state.Pending
		if path == wire.ActivationHTTPPath(wire.OperationActivationStatus) || path == wire.ActivationHTTPPath(wire.OperationAccountReconcile) {
			pending = state.Recovery
		}
		if pending == nil || !bytes.Equal(pending.Request, packet) {
			t.Fatal("HTTP preceded exact packet commit")
		}
	}
	f.transport.mu.Unlock()
	return c
}

func resumeN2App(t *testing.T, c Controller) {
	t.Helper()
	ctx := context.Background()
	if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	profiles := c.Snapshot().Profiles
	if len(profiles) != 1 {
		t.Fatal("trusted profile missing on reopen")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: profiles[0].ID}); err != nil {
		t.Fatal(err)
	}
}

func TestN2AppRealHTTPInitialRecoveryAndFiniteLogin(t *testing.T) {
	for _, operation := range []string{wire.OperationActivationPrepare, wire.OperationActivationComplete} {
		t.Run(operation, func(t *testing.T) {
			f := newN2AppHub(t)
			material, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
			if err != nil {
				t.Fatal(err)
			}
			code, err := wire.EncodeActivationCode(*material)
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(t.TempDir(), "vaults")
			c := f.controller(t, root)
			defer func() { c.Close() }()
			ctx := context.Background()
			if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
				t.Fatal(err)
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
				t.Fatal(err)
			}
			ownerID := c.(*nativeController).owner.Public().ID
			f.transport.mu.Lock()
			f.transport.dropPath = wire.ActivationHTTPPath(operation)
			f.transport.mu.Unlock()
			action := Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "native-n2-synthetic", Password: n2SyntheticPassword}
			if err := c.Dispatch(ctx, action); err == nil {
				t.Fatal("lost activation response was reported complete")
			}
			if s := c.Snapshot(); s.Authorization.Confirmed || s.Management != ManagementUnavailable || !containsAction(s.AvailableActions, ActionRecover) {
				t.Fatal("lost response granted authority or removed recovery")
			}
			original := f.transport.records(wire.ActivationHTTPPath(operation))[0]
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			f.restart(t, nil)
			c = f.controller(t, root)
			resumeN2App(t, c)
			packets := f.transport.records(wire.ActivationHTTPPath(operation))
			if len(packets) < 2 || !bytes.Equal(original, packets[1]) {
				t.Fatal("App/Hub restart resealed uncertain activation")
			}
			if c.(*nativeController).owner.Public().ID != ownerID {
				t.Fatal("restart changed Owner key ID")
			}
			if operation == wire.OperationActivationPrepare {
				if err := c.Dispatch(ctx, action); err != nil {
					t.Fatal(err)
				}
			}
			if s := c.Snapshot(); s.Account.RootState != RootStateActive || s.Authorization.Confirmed || s.Authorization.State != "LOGIN_REQUIRED" {
				t.Fatalf("activation without login = %s/%s", s.Account.RootState, s.Authorization.State)
			}
			deadline := c.Snapshot().Authorization.ExpiresAt
			if err := c.Dispatch(ctx, Action{Kind: ActionLogin, Username: action.Username, Password: n2SyntheticPassword}); err != nil {
				t.Fatal(err)
			}
			s := c.Snapshot()
			if !s.Authorization.Confirmed || s.Authorization.State != "ACTIVE" || s.Management != ManagementUnavailable || !reflect.DeepEqual(s.Authorization.AllowedOperations, wire.ActivationAllowedOperations()) {
				t.Fatal("ordinary login did not establish only finite App access")
			}
			if err := f.db.CheckAppLease(s.Account.OwnerID, s.Account.DeviceID, "nodes.list"); err != nil {
				t.Fatal(err)
			}
			if err := f.db.CheckAppLease(s.Account.OwnerID, s.Account.DeviceID, "intent.submit"); err == nil {
				t.Fatal("finite App lease allowed a write")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			c = f.controller(t, root)
			resumeN2App(t, c)
			if s := c.Snapshot(); !s.Authorization.Confirmed || s.Authorization.ExpiresAt != deadline {
				t.Fatal("trusted reopen renewed lease or skipped fresh account/status checks")
			}
			if _, err := f.db.RevokeOwnerApprovalKeyLocal(material.OwnerID, ownerID, 1); err != nil {
				t.Fatal(err)
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionRefresh}); err != nil {
				t.Fatal(err)
			}
			if s := c.Snapshot(); s.Authorization.Confirmed || s.Authorization.State != "REVOKED" || s.Account.RootState != RootStateUnavailable || containsAction(s.AvailableActions, ActionActivateApp) {
				t.Fatal("cached completion reopened revoked Root/App authority")
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionLogout}); err != nil {
				t.Fatal(err)
			}
			if !containsAction(c.Snapshot().AvailableActions, ActionLogin) {
				t.Fatal("Root revocation incorrectly blocked ordinary registered-account login")
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionLogin, Username: action.Username, Password: n2SyntheticPassword}); err != nil {
				t.Fatal(err)
			}
			if s := c.Snapshot(); s.Account.State != AccountStateSessionActive || s.Account.RootState != RootStateUnavailable || s.Authorization.State != "REVOKED" || s.Authorization.Confirmed {
				t.Fatal("diagnostic account re-login revived Root or finite permissions")
			}
		})
	}
}

func TestN2AppRealHTTPLegacyImportedOwnerAndCredentialStayExact(t *testing.T) {
	f := newN2AppHub(t)
	ctx := context.Background()
	claim, err := f.auth.IssueClaimLocal(false)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := NewActivationCode(*claim)
	if err != nil {
		t.Fatal(err)
	}
	old := f.controller(t, filepath.Join(t.TempDir(), "old-app"))
	if err := old.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: legacy.Encode()}); err != nil {
		t.Fatal(err)
	}
	imported := syntheticOwnerImport(t)
	defer clear(imported.KEMPrivatePKCS8)
	defer clear(imported.SigningPrivatePKCS8)
	if err := old.Dispatch(ctx, Action{Kind: ActionImportOwner, OwnerImport: &imported}); err != nil {
		t.Fatal(err)
	}
	if err := old.Dispatch(ctx, Action{Kind: ActionSetupAccount, Username: "native-existing", Password: n2SyntheticPassword}); err != nil {
		t.Fatal(err)
	}
	n := old.(*nativeController)
	owner := n.owner.Public()
	oldDeviceID := n.state.DeviceID
	oldDevicePublic := n.device.Public()
	before, err := f.db.HubAccountCredential(f.setup.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	material, err := f.auth.IssueActivationLocal(wire.PurposeLegacyContinuation, owner.ID, ownerbootstrap.Fingerprint(owner), false)
	if err != nil {
		t.Fatal(err)
	}
	code, err := wire.EncodeActivationCode(*material)
	if err != nil {
		t.Fatal(err)
	}
	c := f.controller(t, filepath.Join(t.TempDir(), "new-app"))
	defer c.Close()
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
		t.Fatal(err)
	}
	if containsAction(c.Snapshot().AvailableActions, ActionGenerateOwner) || c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}) == nil {
		t.Fatal("legacy continuation offered replacement Owner keys")
	}
	wrong := syntheticOwnerImportWithSeeds(t, 0x37, 0x59)
	defer clear(wrong.KEMPrivatePKCS8)
	defer clear(wrong.SigningPrivatePKCS8)
	if err := c.Dispatch(ctx, Action{Kind: ActionImportOwner, OwnerImport: &wrong}); err == nil {
		t.Fatal("unrelated Owner imported into fixed legacy scope")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionImportOwner, OwnerImport: &imported}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionLogin, Username: "native-existing", Password: n2SyntheticPassword}); err != nil {
		t.Fatal(err)
	}
	s := c.Snapshot()
	if !s.Authorization.Confirmed || s.Account.AccountID != f.setup.AccountID || s.Account.OwnerID != f.setup.OwnerID || c.(*nativeController).owner.Public().ID != owner.ID {
		t.Fatal("legacy import changed stable identity or failed finite access")
	}
	after, err := f.db.HubAccountCredential(f.setup.AccountID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("legacy activation changed account credential")
	}
	device, err := f.db.HubAccountDevice(f.setup.AccountID, oldDeviceID)
	if err != nil || !reflect.DeepEqual(device.Public, oldDevicePublic) {
		t.Fatal("legacy activation replaced an existing App identity")
	}
}

func TestN2AppRealHTTPWrongPasswordAndExpiredSessionReconcile(t *testing.T) {
	f := newN2AppHub(t)
	ctx := context.Background()
	material, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := wire.EncodeActivationCode(*material)
	c := f.controller(t, filepath.Join(t.TempDir(), "vaults"))
	defer c.Close()
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "native-reconcile", Password: n2SyntheticPassword}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionLogin, Username: "native-reconcile", Password: "Synthetic incorrect password!"}); err == nil {
		t.Fatal("wrong password logged in")
	}
	if s := c.Snapshot(); !containsAction(s.AvailableActions, ActionRecover) || containsAction(s.AvailableActions, ActionLogin) {
		t.Fatal("unsigned password rejection discarded pending request")
	}
	original := bytes.Clone(c.(*nativeController).state.Pending.Request)
	if err := c.Dispatch(ctx, Action{Kind: ActionRecover}); err != nil {
		t.Fatal(err)
	}
	packets := f.transport.records(accountRoutes[wire.OperationLoginComplete])
	if len(packets) != 2 || !bytes.Equal(original, packets[1]) {
		t.Fatal("password recovery replaced original before authenticated fence")
	}
	if c.(*nativeController).state.Pending != nil || !containsAction(c.Snapshot().AvailableActions, ActionLogin) {
		t.Fatal("authenticated refusal did not restore login")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionLogin, Username: "native-reconcile", Password: n2SyntheticPassword}); err != nil {
		t.Fatal(err)
	}
	deadline := c.Snapshot().Authorization.ExpiresAt
	f.restart(t, func(db *sql.DB) {
		if _, err := db.Exec(`UPDATE hub_account_sessions_v1 SET expires_at=? WHERE state='ACTIVE'`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	})
	if err := c.Dispatch(ctx, Action{Kind: ActionRefresh}); err == nil {
		t.Fatal("expired server session stayed authenticated")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionRecover}); err != nil {
		t.Fatal(err)
	}
	if c.Snapshot().Authorization.Confirmed || !containsAction(c.Snapshot().AvailableActions, ActionLogin) {
		t.Fatal("expired session did not return to ordinary login")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionLogin, Username: "native-reconcile", Password: n2SyntheticPassword}); err != nil {
		t.Fatal(err)
	}
	if s := c.Snapshot(); !s.Authorization.Confirmed || s.Authorization.ExpiresAt != deadline {
		t.Fatal("re-login failed or renewed finite lease")
	}
}

func TestN2AppReconcileSettlesOldLoginReceiptWithoutRevivingAdvancedEpoch(t *testing.T) {
	for _, fence := range []string{"account", "device"} {
		t.Run(fence, func(t *testing.T) {
			f := newN2AppHub(t)
			ctx := context.Background()
			m, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
			if err != nil {
				t.Fatal(err)
			}
			code, _ := wire.EncodeActivationCode(*m)
			root := filepath.Join(t.TempDir(), "vaults")
			c := f.controller(t, root)
			defer func() { c.Close() }()
			if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
				t.Fatal(err)
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
				t.Fatal(err)
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "native-epoch", Password: n2SyntheticPassword}); err != nil {
				t.Fatal(err)
			}
			f.transport.mu.Lock()
			f.transport.dropPath = accountRoutes[wire.OperationLoginComplete]
			f.transport.mu.Unlock()
			if err := c.Dispatch(ctx, Action{Kind: ActionLogin, Username: "native-epoch", Password: n2SyntheticPassword}); err == nil {
				t.Fatal("lost login receipt was treated as accepted locally")
			}
			// Disposable SQL fault models the authoritative epoch fence. This is
			// not a claim to have run the complete restore-handover procedure.
			f.restart(t, func(db *sql.DB) {
				statement := `UPDATE hub_account_config_v1 SET epoch=epoch+1 WHERE id=1`
				if fence == "device" {
					statement = `UPDATE hub_account_devices_v1 SET epoch=epoch+1`
				}
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE state='ACTIVE'`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`UPDATE hub_app_leases_v1 SET state='REVOKED' WHERE state='ACTIVE'`); err != nil {
					t.Fatal(err)
				}
			})
			if err := c.Dispatch(ctx, Action{Kind: ActionRecover}); err != nil {
				t.Fatal(err)
			}
			n := c.(*nativeController)
			if n.session != nil || c.Snapshot().Authorization.Confirmed || c.Snapshot().Authorization.State != "REVOKED" {
				t.Fatal("old accepted receipt revived authority after an epoch fence")
			}
			if len(f.transport.records(accountRoutes[wire.OperationSessionInspect])) != 0 {
				t.Fatal("old receipt entered an inspect/reconcile loop")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			c = f.controller(t, root)
			resumeN2App(t, c)
			if c.(*nativeController).session != nil || c.Snapshot().Authorization.Confirmed || len(f.transport.records(accountRoutes[wire.OperationSessionInspect])) != 0 {
				t.Fatal("reopen revived a fenced cached session")
			}
			if !containsAction(c.Snapshot().AvailableActions, ActionLogin) {
				t.Fatal("revoked runtime lease hid ordinary account re-login")
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionLogin, Username: "native-epoch", Password: n2SyntheticPassword}); err != nil {
				t.Fatal(err)
			}
			n = c.(*nativeController)
			if n.session == nil || n.session.AccountEpoch != n.state.ObservedAccountEpoch || n.session.DeviceEpoch != n.state.ObservedDeviceEpoch || c.Snapshot().Authorization.State != "REVOKED" || c.Snapshot().Authorization.Confirmed {
				t.Fatal("new-epoch account login renewed a revoked runtime lease or used old epochs")
			}
		})
	}
}

func TestN2AppOperatorReplacementAfterAuthenticatedRefusalPreservesKeys(t *testing.T) {
	f := newN2AppHub(t)
	ctx := context.Background()
	m, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := wire.EncodeActivationCode(*m)
	c := f.controller(t, filepath.Join(t.TempDir(), "vaults"))
	defer c.Close()
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	n := c.(*nativeController)
	owner, device := n.owner.Public(), n.device.Public()
	// A bounded clock-fault request is authenticated but durably refused by
	// the real Hub. There is no uncertain packet to discard afterward.
	n.cfg.Now = func() time.Time { return time.Now().UTC().Add(2 * time.Minute) }
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "native-replacement", Password: n2SyntheticPassword}); err == nil {
		t.Fatal("future-dated activation was accepted")
	}
	if n.state.Pending == nil || len(n.state.Pending.Response) == 0 || n.state.Enrollment.Result == nil || n.state.Enrollment.Result.State != wire.ActivationRejected {
		t.Fatal("clock-fault request did not receive an authenticated terminal refusal")
	}
	n.cfg.Now = func() time.Time { return time.Now().UTC() }
	replacement, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	newCode, _ := wire.EncodeActivationCode(*replacement)
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: newCode}); err != nil {
		t.Fatalf("explicit operator replacement could not reopen settled local setup: %v", err)
	}
	if !reflect.DeepEqual(n.owner.Public(), owner) || !reflect.DeepEqual(n.device.Public(), device) {
		t.Fatal("operator replacement changed local identities")
	}
	if n.state.PreviousActivationReceipt == nil || len(n.state.PreviousActivationReceipt.Response) == 0 {
		t.Fatal("replacement lost the authenticated old disposition receipt")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "native-replacement", Password: n2SyntheticPassword}); err != nil {
		t.Fatal(err)
	}
}

func TestN2AppReplacementWaitsForAuthenticatedCancellationOfPreparedTuple(t *testing.T) {
	f := newN2AppHub(t)
	ctx := context.Background()
	m, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := wire.EncodeActivationCode(*m)
	c := f.controller(t, filepath.Join(t.TempDir(), "vaults"))
	defer c.Close()
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	f.transport.mu.Lock()
	f.transport.dropPath = wire.ActivationHTTPPath(wire.OperationActivationPrepare)
	f.transport.mu.Unlock()
	a := Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "native-cancel", Password: n2SyntheticPassword}
	if err := c.Dispatch(ctx, a); err == nil {
		t.Fatal("lost prepare response was not uncertain")
	}
	n := c.(*nativeController)
	owner, device, id := n.owner.Public(), n.device.Public(), n.state.DeviceID
	packet := bytes.Clone(n.state.Pending.Request)
	defer clear(packet)
	replacement, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	newCode, _ := wire.EncodeActivationCode(*replacement)
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: newCode}); err == nil {
		t.Fatal("new material discarded an uncertain original")
	}
	if n.state.Pending == nil || !bytes.Equal(n.state.Pending.Request, packet) || n.state.Enrollment.Material.ActivationID != m.ActivationID || c.Snapshot().Setup.ReplacementAllowed {
		t.Fatal("uncertain activation was replaced before authenticated settlement")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionRecover}); err != nil {
		t.Fatal(err)
	}
	if !c.Snapshot().Setup.ReplacementAllowed || containsAction(c.Snapshot().AvailableActions, ActionLogin) || containsAction(c.Snapshot().AvailableActions, ActionActivateApp) {
		t.Fatal("cancelled prepared candidate was treated as enrolled or its old authority reopened")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: newCode}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(owner, n.owner.Public()) || !reflect.DeepEqual(device, n.device.Public()) || n.state.DeviceID != id {
		t.Fatal("operator replacement changed the reserved full tuple")
	}
	if err := c.Dispatch(ctx, a); err != nil {
		t.Fatal(err)
	}
}

func TestN2AppNeverStartedReplacementAndEpochRollback(t *testing.T) {
	f := newN2AppHub(t)
	ctx := context.Background()
	old, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	oldCode, _ := wire.EncodeActivationCode(*old)
	c := f.controller(t, filepath.Join(t.TempDir(), "vaults"))
	defer c.Close()
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: oldCode}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	n := c.(*nativeController)
	owner, device := n.owner.Public(), n.device.Public()
	if containsAction(c.Snapshot().AvailableActions, ActionLogin) || containsAction(c.Snapshot().AvailableActions, ActionLoginPrepare) {
		t.Fatal("unregistered keys advertised account login")
	}
	f.restart(t, func(db *sql.DB) {
		if _, err := db.Exec(`UPDATE hub_account_config_v1 SET epoch=epoch+1 WHERE id=1`); err != nil {
			t.Fatal(err)
		}
	})
	replacement, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	newCode, _ := wire.EncodeActivationCode(*replacement)
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: newCode}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(owner, n.owner.Public()) || !reflect.DeepEqual(device, n.device.Public()) || n.state.Enrollment.Material.AccountEpoch != replacement.AccountEpoch {
		t.Fatal("never-started replacement changed keys or epoch")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: oldCode}); err == nil {
		t.Fatal("activation account epoch rolled back")
	}
	if n.state.Enrollment.Material.ActivationID != replacement.ActivationID || !reflect.DeepEqual(owner, n.owner.Public()) {
		t.Fatal("rejected rollback replaced local enrollment")
	}
}

func TestN2AppScopeChangesAndEstablishedRootCannotReplaceMaterial(t *testing.T) {
	f := newN2AppHub(t)
	ctx := context.Background()
	m, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := wire.EncodeActivationCode(*m)
	c := f.controller(t, filepath.Join(t.TempDir(), "vaults"))
	defer c.Close()
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	n := c.(*nativeController)
	owner, device := n.owner.Public(), n.device.Public()
	for _, field := range []string{"hub", "pin", "origin", "account", "owner", "purpose", "setup-epoch"} {
		candidate := *m
		candidate.ActivationID, _ = wire.NewRequestID()
		switch field {
		case "hub":
			candidate.HubID += "_other"
		case "pin":
			candidate.HubFingerprint = "other"
		case "origin":
			candidate.Origin = "https://other.synthetic.invalid"
		case "account":
			candidate.AccountID += "_other"
		case "owner":
			candidate.OwnerID += "_other"
		case "purpose":
			candidate.Purpose = wire.PurposeLegacyContinuation
		case "setup-epoch":
			candidate.SetupEpoch = 0
		}
		if err := n.installActivationMaterial(candidate); err == nil {
			t.Fatalf("%s changed an existing enrollment scope", field)
		}
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "native-no-renew", Password: n2SyntheticPassword}); err != nil {
		t.Fatal(err)
	}
	deadline := c.Snapshot().Authorization.ExpiresAt
	for _, revoked := range []bool{false, true} {
		if revoked {
			if _, err := f.db.RevokeOwnerApprovalKeyLocal(m.OwnerID, owner.ID, 1); err != nil {
				t.Fatal(err)
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionActivationStatus}); err != nil {
				t.Fatal(err)
			}
		}
		candidate := *m
		candidate.ActivationID, _ = wire.NewRequestID()
		encoded, _ := wire.EncodeActivationCode(candidate)
		if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: encoded}); err == nil {
			t.Fatal("established or revoked Root accepted replacement activation material")
		}
		if !reflect.DeepEqual(owner, n.owner.Public()) || !reflect.DeepEqual(device, n.device.Public()) || n.state.Enrollment.Material.ActivationID != m.ActivationID || n.state.Enrollment.Result.LeaseExpiresAt != deadline {
			t.Fatal("Root replacement rejection changed keys, identity or lease expiry")
		}
	}
}
