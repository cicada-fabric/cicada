package n3_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const syntheticPassword = "Synthetic N3 meadow password 42!"

// This backend exercises the real encrypted vault in the Linux fixture. It
// cannot establish Windows DPAPI, ACL or GUI behavior.
func syntheticVaultOpener(root string) appcore.VaultOpener {
	return syntheticVaultOpenerWithHook(root, nil)
}

func syntheticVaultOpenerWithHook(root string, hook func(*appvault.PasswordProtector, string) appvault.Protector) appcore.VaultOpener {
	return func(_ context.Context, scope appvault.Scope, create bool) (*appvault.Vault, error) {
		raw, err := json.Marshal(scope)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(root, hash(raw)+".vault")
		clear(raw)
		base, err := appvault.NewPasswordProtector([]byte("Synthetic N3 acceptance vault passphrase"))
		if err != nil {
			return nil, err
		}
		var protector appvault.Protector = base
		if hook != nil {
			protector = hook(base, path)
		}
		_, err = os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && create {
			return appvault.Create(path, scope, protector)
		}
		if err != nil {
			base.Close()
			return nil, err
		}
		return appvault.Open(path, scope, protector)
	}
}

// The production actor must be stopped before its vault is opened here. The
// real vault lock also rejects accidental concurrent access. Private keys stay
// exclusively in this synthetic fixture, never in acceptance evidence.
func ownedAppVault(t *testing.T, f *hubFixture) *appvault.Vault {
	t.Helper()
	m := f.cfg.Material
	scope := appvault.Scope{HubID: m.HubID, HubFingerprint: m.HubFingerprint, Origin: m.Origin,
		AccountID: m.AccountID, OwnerID: m.OwnerID}
	return must(syntheticVaultOpener(filepath.Join(f.dir, "synthetic-app", "vaults"))(context.Background(), scope, false))
}

func ownedAppIdentity(t *testing.T, f *hubFixture, purpose appvault.Purpose) *e2ee.Identity {
	t.Helper()
	vault := ownedAppVault(t, f)
	defer vault.Close()
	for _, entry := range must(vault.List()) {
		if entry.Purpose == purpose {
			identity := must(vault.Get(purpose, entry.KeyID))
			t.Cleanup(identity.Close)
			return must(identity.E2EE())
		}
	}
	t.Fatal("synthetic App vault lacks its original scoped key")
	return nil
}

func ownedAppPublicKeys(t *testing.T, f *hubFixture) map[appvault.Purpose]e2ee.PublicIdentity {
	t.Helper()
	keys := make(map[appvault.Purpose]e2ee.PublicIdentity)
	for _, purpose := range []appvault.Purpose{appvault.PurposeOwnerSigner, appvault.PurposeAppDevice} {
		keys[purpose] = ownedAppIdentity(t, f, purpose).Public()
	}
	return keys
}

// Adversarial wire cases reuse a real authenticated account session from the
// production App. Its only durable representation remains the encrypted vault
// receipt; the token is authenticated in memory and never exported to evidence.
func ownedAccountSession(t *testing.T, f *hubFixture) wire.SessionReceipt {
	t.Helper()
	device := ownedAppIdentity(t, f, appvault.PurposeAppDevice)
	vault := ownedAppVault(t, f)
	raw, _, found, err := vault.LoadState("appcore.session.v1")
	if vault.Close() != nil || err != nil || !found {
		t.Fatal("synthetic App lacks its encrypted account session receipt")
	}
	defer clear(raw)
	var saved struct {
		Request  []byte `json:"request"`
		Response []byte `json:"response"`
	}
	if json.Unmarshal(raw, &saved) != nil {
		t.Fatal("synthetic App account session record is invalid")
	}
	defer clear(saved.Request)
	defer clear(saved.Response)
	var session wire.SessionReceipt
	if wire.OpenClientResponse(device, f.cfg.Hub, saved.Request, saved.Response, &session) != nil ||
		session.Origin != f.cfg.Origin || session.AccountID != f.cfg.Material.AccountID ||
		session.OwnerID != f.cfg.Material.OwnerID || session.DeviceKeyID != device.Public().ID {
		t.Fatal("synthetic App saved session failed full cryptographic scope authentication")
	}
	t.Cleanup(func() { clear(session.SessionToken) })
	return session
}

type appProxyDoer struct {
	target string
	base   *http.Client
}

func (p appProxyDoer) Do(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	target, err := url.Parse(p.target)
	if err != nil {
		return nil, err
	}
	clone.URL.Scheme, clone.URL.Host = target.Scheme, target.Host
	response, err := p.base.Do(clone)
	if response != nil {
		response.Request = request
	}
	return response, err
}

type appActorInput struct {
	Proxy    string                   `json:"proxy"`
	Step     string                   `json:"step"`
	Mailbox  string                   `json:"mailbox"`
	Material *wire.ActivationMaterial `json:"synthetic_n2_material,omitempty"`
}

type appActorCheckpoint struct {
	Actor       string           `json:"actor"`
	BeforeLogin appcore.Snapshot `json:"before_login"`
	Current     appcore.Snapshot `json:"current"`
}

// Commands and responses remain in the private fixture. Only the production
// Controller's display-safe Snapshot and a boolean action outcome are returned.
type appActorCommand struct {
	Action             *appcore.Action `json:"action,omitempty"`
	ClockOffsetSeconds int64           `json:"logical_clock_offset_seconds"`
}

type appActorReply struct {
	ActionFailed bool             `json:"action_failed"`
	ActionError  string           `json:"action_error,omitempty"`
	Current      appcore.Snapshot `json:"current"`
	ClockMode    string           `json:"clock_mode"`
}

type appProcess struct {
	*process
	mailbox string
}

func commandApp(t *testing.T, f *hubFixture, p *appProcess, sequence int, command appActorCommand) appActorReply {
	t.Helper()
	base := queueAppCommand(t, f, p, sequence, command)
	awaitMarker(t, p.process, base+"-reply.json")
	var reply appActorReply
	readJSON(t, base+"-reply.json", &reply)
	return reply
}

func queueAppCommand(t *testing.T, f *hubFixture, p *appProcess, sequence int, command appActorCommand) string {
	t.Helper()
	// Match ordinary human command cadence instead of exhausting production's
	// auth4/sec burst12 bucket. Raw concurrent adversaries remain unpaced.
	time.Sleep(time.Second)
	base := filepath.Join(f.dir, "app-command-"+p.mailbox+"-"+strconv.Itoa(sequence))
	writeJSON(t, base+".json", command)
	return base
}

func startAppProcess(t *testing.T, f *hubFixture, step, marker string) *appProcess {
	t.Helper()
	input := appActorInput{Proxy: f.proxy.server.URL, Step: step, Mailbox: must(wire.NewRequestID())}
	if step == "bootstrap" {
		input.Material = &f.cfg.Material
	}
	// A resumed child receives no installer/activation material. Its only
	// connection locator is the authenticated, already-encrypted local profile.
	writeJSON(t, filepath.Join(f.dir, "synthetic-app-input.json"), input)
	cmd := exec.Command(must(os.Executable()), "-test.run=^TestN3AppProcess$", "-test.timeout=10m")
	cmd.Env = append(os.Environ(), "CICADA_N3_APP_CHILD=1", "CICADA_N3_FIXTURE="+f.dir, "CICADA_N3_MARKER="+marker)
	return &appProcess{process: startProcess(t, cmd), mailbox: input.Mailbox}
}

// The actor invokes the production App Controller and its persistence and
// cryptographic code in an actual separate process. It is not the native GUI.
func TestN3AppProcess(t *testing.T) {
	if os.Getenv("CICADA_N3_APP_CHILD") == "" {
		return
	}
	dir := os.Getenv("CICADA_N3_FIXTURE")
	var input appActorInput
	readJSON(t, filepath.Join(dir, "synthetic-app-input.json"), &input)
	loopback(t, input.Proxy)
	root := filepath.Join(dir, "synthetic-app", "vaults")
	var clockOffset atomic.Int64
	barrier := &vaultCommitBarrier{t: t, dir: filepath.Join(dir, "app-vault-gate-"+input.Mailbox)}
	c := must(appcore.NewController(appcore.Config{HTTP: appProxyDoer{input.Proxy, appcore.NewHTTPClient()},
		OpenVault: syntheticVaultOpenerWithHook(root, barrier.wrap), DiscoverVaults: appcore.NewProfileDiscovery(root), AllowLoopbackHTTP: true,
		Now: func() time.Time { return time.Now().UTC().Add(time.Duration(clockOffset.Load()) * time.Second) }}))
	defer c.Close()
	ctx := context.Background()
	dispatch := func(action appcore.Action) {
		if c.Dispatch(ctx, action) != nil {
			t.Fatalf("production App action failed: kind=%s code=%s", action.Kind, c.Snapshot().ErrorCode)
		}
	}
	checkpoint := appActorCheckpoint{Actor: "PRODUCTION_APP_CORE_PROCESS_NOT_NATIVE_GUI"}
	switch input.Step {
	case "bootstrap":
		if input.Material == nil {
			t.Fatal("synthetic bootstrap material missing")
		}
		dispatch(appcore.Action{Kind: appcore.ActionConnect, ActivationCode: must(wire.EncodeActivationCode(*input.Material))})
		dispatch(appcore.Action{Kind: appcore.ActionGenerateOwner})
		dispatch(appcore.Action{Kind: appcore.ActionActivateApp, ConfirmLimitedAuthorization: true,
			Username: "synthetic-user", Password: syntheticPassword})
		checkpoint.BeforeLogin = c.Snapshot()
		if checkpoint.BeforeLogin.Account.RootState != appcore.RootStateActive || checkpoint.BeforeLogin.Authorization.Confirmed {
			t.Fatal("N2 Root proof and account login were conflated")
		}
		dispatch(appcore.Action{Kind: appcore.ActionLogin, Username: "synthetic-user", Password: syntheticPassword})
	case "resume", "resume-node":
		if input.Material != nil {
			t.Fatal("profile resume received installer material")
		}
		dispatch(appcore.Action{Kind: appcore.ActionDiscoverProfiles})
		profiles := c.Snapshot().Profiles
		if len(profiles) != 1 {
			t.Fatal("fixture did not discover exactly one authenticated profile")
		}
		dispatch(appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: profiles[0].ID})
	default:
		t.Fatal("unknown App actor step")
	}
	checkpoint.Current = c.Snapshot()
	s := checkpoint.Current
	if !s.Hub.Verified || !s.Account.LocalOwnerKeyPresent || s.Management != appcore.ManagementUnavailable || s.Canvas.State != appcore.CanvasNoAuthorization {
		t.Fatal("actual App overstated general management or lost its original local identity")
	}
	if input.Step != "resume-node" && (s.Account.RootState != appcore.RootStateActive ||
		!s.Authorization.Confirmed || s.Authorization.State != "ACTIVE" ||
		!reflect.DeepEqual(s.Authorization.AllowedOperations, wire.ActivationAllowedOperations())) {
		t.Fatal("actual App did not retain the expected limited N2 authority")
	}
	writeJSON(t, os.Getenv("CICADA_N3_MARKER"), checkpoint)
	for sequence := 1; ; sequence++ {
		base := filepath.Join(dir, "app-command-"+input.Mailbox+"-"+strconv.Itoa(sequence))
		for {
			if _, err := os.Stat(base + ".json"); err == nil {
				break
			} else if !os.IsNotExist(err) {
				t.Fatal("private App command unavailable")
			}
			time.Sleep(10 * time.Millisecond)
		}
		var command appActorCommand
		readJSON(t, base+".json", &command)
		// Logical-clock evidence is explicitly labeled; it never establishes a
		// real 15-minute wall-clock wait or a production Hub clock transition.
		clockOffset.Store(command.ClockOffsetSeconds)
		reply := appActorReply{ClockMode: "WALL_CLOCK"}
		if command.ClockOffsetSeconds != 0 {
			reply.ClockMode = "APP_LOGICAL_CLOCK_ONLY"
		}
		if command.Action != nil {
			err := c.Dispatch(ctx, *command.Action)
			reply.ActionFailed = err != nil
			switch {
			case errors.Is(err, appcore.ErrInvalidAction):
				reply.ActionError = "INVALID_ACTION"
			case errors.Is(err, appcore.ErrControllerBusy):
				reply.ActionError = "BUSY"
			case err != nil:
				reply.ActionError = "OTHER"
			}
		}
		reply.Current = c.Snapshot()
		writeJSON(t, base+"-reply.json", reply)
	}
}

func TestN3HarnessActualAppBootstrapAndResume(t *testing.T) {
	f := newHubFixture(t)
	firstMarker := filepath.Join(f.dir, "app-bootstrap.json")
	first := startAppProcess(t, f, "bootstrap", firstMarker)
	awaitMarker(t, first.process, firstMarker)
	firstPID, firstHubPID := first.cmd.Process.Pid, f.hub.cmd.Process.Pid
	first.kill(t)
	f.hub.kill(t)
	originalKeys := ownedAppPublicKeys(t, f)
	var original appActorCheckpoint
	readJSON(t, firstMarker, &original)
	db := f.db(t)
	setup, _, err := db.HubAccountSetup()
	activation := must(db.HubActivation(f.cfg.Material.ActivationID))
	if err != nil || !setup.RootEverEstablished || activation == nil || activation.State != wire.ActivationCompleted {
		t.Fatal("actual App did not establish the expected durable N2 Root")
	}
	db.Close()
	f.start(t)
	secondMarker := filepath.Join(f.dir, "app-resume.json")
	second := startAppProcess(t, f, "resume", secondMarker)
	awaitMarker(t, second.process, secondMarker)
	var resumed appActorCheckpoint
	readJSON(t, secondMarker, &resumed)
	query := commandApp(t, f, second, 1, appActorCommand{})
	second.kill(t)
	if !reflect.DeepEqual(originalKeys, ownedAppPublicKeys(t, f)) {
		t.Fatal("process recovery changed either complete App/Owner public identity")
	}
	if query.ActionFailed || query.ClockMode != "WALL_CLOCK" || !reflect.DeepEqual(query.Current, resumed.Current) {
		t.Fatal("separate App actor did not return its current production snapshot")
	}
	a, b := original.Current, resumed.Current
	if firstPID == second.cmd.Process.Pid || firstHubPID == f.hub.cmd.Process.Pid ||
		a.Hub.Fingerprint != b.Hub.Fingerprint || a.Account.AccountID != b.Account.AccountID ||
		a.Account.OwnerID != b.Account.OwnerID || a.Account.DeviceID != b.Account.DeviceID ||
		a.Account.OwnerFingerprint != b.Account.OwnerFingerprint || a.Authorization.ExpiresAt != b.Authorization.ExpiresAt {
		t.Fatal("actual process restart changed identity, scope or the original finite lease")
	}
	t.Logf("HARNESS_ONLY actualAppCoreProcess=true actualHubProcess=true encryptedVault=true noInstallerOnResume=true N3_NOT_RUN=true hub_fingerprint=%s owner_fingerprint=%s", b.Hub.Fingerprint, b.Account.OwnerFingerprint)
}
