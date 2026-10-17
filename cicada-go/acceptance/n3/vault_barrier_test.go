package n3_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// The real vault calls Protector.ID before its next atomic write. Pausing
// here exposes the previous fully committed encrypted image while the actual
// Controller is still inside CompareAndSwapState. Crypto and the returned ID
// are unchanged. This is test-only Linux persistence infrastructure, not DPAPI.
type vaultCommitBarrier struct {
	t   *testing.T
	dir string
	seq atomic.Uint64
}

type gatedPasswordProtector struct {
	*appvault.PasswordProtector
	barrier *vaultCommitBarrier
	path    string
}

type vaultGateCheckpoint struct {
	PreviousImageSHA256 string `json:"previous_encrypted_image_sha256"`
}

func (b *vaultCommitBarrier) wrap(base *appvault.PasswordProtector, path string) appvault.Protector {
	return &gatedPasswordProtector{PasswordProtector: base, barrier: b, path: path}
}

func (p *gatedPasswordProtector) ID() string {
	id := p.PasswordProtector.ID()
	b := p.barrier
	if _, err := os.Stat(filepath.Join(b.dir, "armed")); os.IsNotExist(err) {
		return id
	} else if err != nil {
		panic("private vault barrier arm unavailable")
	}
	base := filepath.Join(b.dir, strconv.FormatUint(b.seq.Add(1), 10))
	raw := readPrivate(b.t, p.path)
	writeJSON(b.t, base+".json", vaultGateCheckpoint{PreviousImageSHA256: hash(raw)})
	clear(raw)
	for {
		if _, err := os.Stat(base + ".release"); err == nil {
			return id
		} else if !os.IsNotExist(err) {
			panic("private vault barrier release unavailable")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func armVaultBarrier(t *testing.T, f *hubFixture, p *appProcess) string {
	t.Helper()
	dir := filepath.Join(f.dir, "app-vault-gate-"+p.mailbox)
	if os.MkdirAll(dir, 0700) != nil {
		t.Fatal("private vault barrier directory unavailable")
	}
	atomicPrivate(t, filepath.Join(dir, "armed"), []byte("SYNTHETIC COMMIT BARRIER"))
	return dir
}

// Read a coherent copy of the previous atomic vault image at the paused real
// commit boundary. The live vault lock is respected; only its immutable byte
// image is copied to a different private path and authenticated independently.
func vaultImageAtGate(t *testing.T, f *hubFixture, p *appProcess, gate int) (*appvault.Vault, func()) {
	t.Helper()
	dir := filepath.Join(f.dir, "app-vault-gate-"+p.mailbox)
	base := filepath.Join(dir, strconv.Itoa(gate))
	awaitMarker(t, p.process, base+".json")
	var checkpoint vaultGateCheckpoint
	readJSON(t, base+".json", &checkpoint)
	m := f.cfg.Material
	scope := appvault.Scope{HubID: m.HubID, HubFingerprint: m.HubFingerprint, Origin: m.Origin,
		AccountID: m.AccountID, OwnerID: m.OwnerID}
	scopeRaw := must(json.Marshal(scope))
	path := filepath.Join(f.dir, "synthetic-app", "vaults", hash(scopeRaw)+".vault")
	clear(scopeRaw)
	raw := readPrivate(t, path)
	if hash(raw) != checkpoint.PreviousImageSHA256 {
		t.Fatal("paused vault image changed before the next atomic write")
	}
	snapshot := filepath.Join(dir, "snapshot-"+strconv.Itoa(gate)+".vault")
	atomicPrivate(t, snapshot, raw)
	clear(raw)
	vault := must(appvault.Open(snapshot, scope, must(appvault.NewPasswordProtector([]byte("Synthetic N3 acceptance vault passphrase")))))
	return vault, func() { atomicPrivate(t, base+".release", []byte("RELEASE")) }
}

func vaultStateAtGate(t *testing.T, f *hubFixture, p *appProcess, gate int, namespace string) ([]byte, func()) {
	t.Helper()
	vault, release := vaultImageAtGate(t, f, p, gate)
	state, _, found, err := vault.LoadState(namespace)
	if vault.Close() != nil || err != nil || !found {
		t.Fatal("paused committed vault image did not authenticate its expected state")
	}
	return state, release
}

func TestN3HarnessActualAppVaultCommitBarrier(t *testing.T) {
	f := newHubFixture(t)
	marker := filepath.Join(f.dir, "vault-app-ready.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	armVaultBarrier(t, f, app)
	action := appcore.Action{Kind: appcore.ActionSessionInspect}
	command := queueAppCommand(t, f, app, 1, appActorCommand{Action: &action})
	var responseDigest string
	for gate := 1; gate <= 12; gate++ {
		raw, release := vaultStateAtGate(t, f, app, gate, "appcore.state.v1")
		var state struct {
			Pending *struct {
				Operation string `json:"operation"`
				Response  []byte `json:"response"`
			} `json:"pending"`
		}
		err := json.Unmarshal(raw, &state)
		clear(raw)
		if err != nil {
			t.Fatal("paused App state is invalid")
		}
		if state.Pending != nil && state.Pending.Operation == wire.OperationSessionInspect && len(state.Pending.Response) > 0 {
			responseDigest = hash(state.Pending.Response)
			clear(state.Pending.Response)
			app.kill(t)
			break
		}
		release()
	}
	if responseDigest == "" {
		t.Fatal("local response-durable/unapplied boundary was not observed")
	}
	if _, err := os.Stat(command + "-reply.json"); !os.IsNotExist(err) {
		t.Fatal("App action returned before the controlled local commit crash")
	}
	f.hub.kill(t)
	f.start(t)
	resumeMarker := filepath.Join(f.dir, "vault-app-resumed.json")
	resumed := startAppProcess(t, f, "resume", resumeMarker)
	awaitMarker(t, resumed.process, resumeMarker)
	resumed.kill(t)
	t.Logf("HARNESS_ONLY actualAppCoreProcess=true local_response_durable_before_apply=true actualSIGKILL=true N3_NOT_RUN=true response_sha256=%s", responseDigest)
}
