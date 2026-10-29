package n3_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

// This actor deliberately leaves HTTP, DirectHTTPFactory and Now unset: the
// real Controller selects its production transport and live clock. Only the
// OS-specific vault protector is synthetic; DPAPI/ACL/GUI remain NOT_RUN.
type directIPAppCheckpoint struct {
	Snapshot     appcore.Snapshot `json:"snapshot"`
	ActionFailed bool             `json:"action_failed"`
	VaultOpens   int              `json:"vault_opens"`
	VaultCreates int              `json:"vault_creates"`
}

type directIPAppCommand struct {
	Action *appcore.Action `json:"action,omitempty"`
	Close  bool            `json:"close,omitempty"`
}

type directIPApp struct {
	*process
	dir      string
	sequence int
}

func TestN3DirectIPTLSAppProcess(t *testing.T) {
	if os.Getenv("CICADA_N3_DIRECT_IP_APP_CHILD") != "1" {
		return
	}
	dir := os.Getenv("CICADA_N3_DIRECT_IP_APP_DIR")
	root := filepath.Join(dir, "home", ".cicada", "app", "vaults")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal("owned synthetic vault directory unavailable")
	}
	checkpoint := directIPAppCheckpoint{}
	base := syntheticVaultOpener(root)
	c := must(appcore.NewController(appcore.Config{UserRoot: filepath.Dir(filepath.Dir(root)), OpenVault: func(ctx context.Context, scope appvault.Scope, create bool) (*appvault.Vault, error) {
		checkpoint.VaultOpens++
		if create {
			checkpoint.VaultCreates++
		}
		return base(ctx, scope, create)
	}, DiscoverVaults: appcore.NewProfileDiscovery(root)}))
	defer c.Close()
	checkpoint.Snapshot = c.Snapshot()
	writeJSON(t, filepath.Join(dir, "ready.json"), checkpoint)
	for sequence := 1; ; sequence++ {
		path := filepath.Join(dir, "command-"+strconv.Itoa(sequence))
		for {
			if _, err := os.Stat(path + ".json"); err == nil {
				break
			} else if !os.IsNotExist(err) {
				t.Fatal("owned App mailbox unavailable")
			}
			time.Sleep(10 * time.Millisecond)
		}
		var command directIPAppCommand
		readJSON(t, path+".json", &command)
		if command.Close {
			if command.Action != nil {
				t.Fatal("close cannot dispatch an action")
			}
			if err := c.Close(); err != nil {
				t.Fatal("production App close failed")
			}
			writeJSON(t, path+"-reply.json", checkpoint)
			return
		}
		if command.Action == nil {
			t.Fatal("owned App command lacks an action")
		}
		checkpoint.ActionFailed = c.Dispatch(context.Background(), *command.Action) != nil
		checkpoint.Snapshot = c.Snapshot()
		writeJSON(t, path+"-reply.json", checkpoint)
	}
}

func startDirectIPApp(t *testing.T, dir string) *directIPApp {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal("owned App root unavailable")
	}
	// Every process receives a fresh mailbox while sharing only its own vault.
	for _, entry := range must(os.ReadDir(dir)) {
		if entry.Name() == "ready.json" || strings.HasPrefix(entry.Name(), "command-") {
			if entry.IsDir() || os.Remove(filepath.Join(dir, entry.Name())) != nil {
				t.Fatal("owned App mailbox could not be reset")
			}
		}
	}
	timeout := "10m"
	if os.Getenv("CICADA_N3_OWNER_ENDPOINT_GROUPS_CROSS_NODE") == "1" {
		// Match the existing cross-Node parent lifetime while its two real Hosts
		// run sequentially. This changes no account, consent or policy deadline.
		timeout = "90m"
	}
	cmd := exec.Command(must(os.Executable()), "-test.run=^TestN3DirectIPTLSAppProcess$", "-test.timeout="+timeout)
	cmd.Env = append(os.Environ(), "CICADA_N3_DIRECT_IP_APP_CHILD=1", "CICADA_N3_DIRECT_IP_APP_DIR="+dir)
	p := startProcess(t, cmd)
	awaitMarker(t, p, filepath.Join(dir, "ready.json"))
	return &directIPApp{process: p, dir: dir}
}

func (a *directIPApp) command(t *testing.T, command directIPAppCommand) directIPAppCheckpoint {
	t.Helper()
	a.sequence++
	path := filepath.Join(a.dir, "command-"+strconv.Itoa(a.sequence))
	writeJSON(t, path+".json", command)
	awaitMarker(t, a.process, path+"-reply.json")
	var reply directIPAppCheckpoint
	readJSON(t, path+"-reply.json", &reply)
	if command.Close {
		select {
		case <-a.done:
		case <-time.After(5 * time.Second):
			t.Fatal("production App did not exit after normal close")
		}
		if a.cmd.ProcessState.ExitCode() != 0 {
			t.Fatal("production App normal close exited nonzero")
		}
	}
	return reply
}

type directIPHub struct {
	dir        string
	state      string
	binary     string
	descriptor hubtransport.Descriptor
	bootstrap  string
	material   wire.ActivationMaterial
	address    string
	hub        *process
}

func directIPCLI(t *testing.T, args ...string) int {
	t.Helper()
	return directIPCLIAt(t, os.Getenv("CICADA_N3_CICADA_BINARY"), args...)
}

func directIPCLIAt(t *testing.T, binary string, args ...string) int {
	t.Helper()
	if binary == "" {
		t.Fatal("explicit acceptance-built Cicada CLI required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// No stdout/stderr, activation material or private bundle enters evidence.
	err := exec.CommandContext(ctx, binary, args...).Run()
	if ctx.Err() != nil {
		t.Fatal("owned CLI command exceeded its deadline")
	}
	if err == nil {
		return 0
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode()
	}
	t.Fatal("owned CLI could not execute")
	return -1
}

func noDirectIPInstalledProcess(t *testing.T, prefix string) {
	t.Helper()
	for _, entry := range must(os.ReadDir("/proc")) {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		executable, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err == nil && strings.HasPrefix(executable, filepath.Join(prefix, "components")+string(os.PathSeparator)) {
			t.Fatal("file-only installation started an owned component process")
		}
	}
}

type directIPBoundedError struct{ raw []byte }

func (b *directIPBoundedError) Write(raw []byte) (int, error) {
	n := len(raw)
	if remaining := 4096 - len(b.raw); remaining > 0 {
		b.raw = append(b.raw, raw[:min(remaining, n)]...)
	}
	return n, nil
}

func directIPMutuallyExclusive(t *testing.T, binary string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	var diagnostic directIPBoundedError
	cmd.Stderr = &diagnostic
	err := cmd.Run()
	if ctx.Err() != nil || err == nil || !strings.Contains(string(diagnostic.raw), "cannot combine legacy HTTP or enrolled Node PQ transport") {
		t.Fatal("native/PQ selectors did not reject before reading the deliberately absent PQ configuration")
	}
}

func newDirectIPHub(t *testing.T, host string) *directIPHub {
	t.Helper()
	return newDirectIPHubOrigin(t, host, "")
}

func newDirectIPHubOrigin(t *testing.T, host, oldOrigin string) *directIPHub {
	return newDirectIPHubSetup(t, host, oldOrigin, true)
}

func newDirectIPHubSetup(t *testing.T, host, oldOrigin string, issueActivation bool) *directIPHub {
	t.Helper()
	f := &directIPHub{dir: t.TempDir()}
	f.state = filepath.Join(f.dir, "hub-state")
	prefix := filepath.Join(f.dir, "selected-component-root")
	binary := os.Getenv("CICADA_N3_CICADA_BINARY")
	if directIPCLI(t, "components", "install", "--prefix", prefix, "--components", "hub,node", "--binary", binary,
		"--sha256", hash(readPrivateBinary(t, binary)), "--licenses", "/licenses") != 0 {
		t.Fatal("file-only Hub/Node component installation failed")
	}
	noDirectIPInstalledProcess(t, prefix)
	f.binary = filepath.Join(prefix, "components", "hub", "bin", "cicada")
	if hash(readPrivateBinary(t, f.binary)) != hash(readPrivateBinary(t, binary)) {
		t.Fatal("installed Hub executable differs from the acceptance build")
	}
	if _, err := os.Stat(f.state); !os.IsNotExist(err) {
		t.Fatal("file-only installation created Hub state")
	}
	publicConfig := filepath.Join(f.dir, "public-config.json")
	args := []string{"hub", "setup", "--owner-label", "SYNTHETIC QA OWNER; NEVER DEPLOY", "--state-dir", f.state, "--public-config", publicConfig}
	if oldOrigin != "" {
		args = append(args, "--origin", oldOrigin)
	}
	if directIPCLIAt(t, f.binary, args...) != 0 {
		t.Fatal("fresh Hub setup without a preset origin failed")
	}
	oldConfigHash := hash(readPrivate(t, publicConfig))
	applicationKeys := directIPKeyDigests(t, f.state)
	if oldOrigin != "" && directIPCLIAt(t, f.binary, "hub", "native-tls-init", "--state-dir", f.state,
		"--descriptor-file", filepath.Join(f.dir, "migrated-public-transport.txt")) != 0 {
		t.Fatal("explicit legacy HTTPS Hub native transport initialization failed")
	}
	if hash(readPrivate(t, publicConfig)) != oldConfigHash || !reflect.DeepEqual(applicationKeys, directIPKeyDigests(t, f.state)) {
		t.Fatal("native transport initialization changed the original public connection card or application keys")
	}
	descriptorFile := filepath.Join(f.dir, "public-transport.txt")
	if directIPCLIAt(t, f.binary, "hub", "connection-export", "--state-dir", f.state, "--descriptor-file", descriptorFile) != 0 {
		t.Fatal("public transport export failed")
	}
	f.descriptor = must(hubtransport.DecodeDescriptor(strings.TrimSpace(string(readPrivate(t, descriptorFile)))))
	if oldOrigin == "" && f.descriptor.Claims.Origin != must(hubtransport.DefaultOrigin(f.descriptor.Claims.Hub.HubID)) || oldOrigin != "" && f.descriptor.Claims.Origin != oldOrigin {
		t.Fatal("fresh Hub did not derive its stable logical origin")
	}
	privateDir := filepath.Join(f.dir, "private")
	if err := os.Mkdir(privateDir, 0700); err != nil {
		t.Fatal("owned private activation directory unavailable")
	}
	if issueActivation {
		codeFile := filepath.Join(privateDir, "bootstrap.txt")
		if directIPCLIAt(t, f.binary, "hub", "activation-issue", "--native-tls", "--purpose", "initial", "--state-dir", f.state, "--code-file", codeFile) != 0 {
			t.Fatal("native bootstrap issue failed")
		}
		if info := must(os.Stat(codeFile)); info.Mode().Perm() != 0600 {
			t.Fatal("native bootstrap file lacks private permissions")
		}
		f.bootstrap = strings.TrimSpace(string(readPrivate(t, codeFile)))
		b := must(hubtransport.DecodeBootstrap(f.bootstrap))
		f.material = must(hubtransport.ValidateBootstrap(b, time.Now().UTC()))
		if !reflect.DeepEqual(b.Descriptor, f.descriptor) || f.material.Origin != f.descriptor.Claims.Origin {
			t.Fatal("bootstrap and independently exported public transport disagree")
		}
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal("required isolated address family unavailable")
	}
	f.address = listener.Addr().String()
	listener.Close()
	f.start(t)
	return f
}

type directIPPrivateBundle struct {
	Version       int    `json:"version"`
	Descriptor    string `json:"descriptor"`
	CAKeyDER      []byte `json:"ca_key_der"`
	ServiceKeyDER []byte `json:"service_key_der"`
	LeafDER       []byte `json:"leaf_der"`
}

func directIPKeyDigests(t *testing.T, state string) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for _, name := range []string{"identity.json", "client-control-identity.json", "node-control-identity.json"} {
		raw := readPrivate(t, filepath.Join(state, "e2ee", name))
		out[name] = hash(raw)
		clear(raw)
	}
	return out
}

func directIPTLSIdentity(t *testing.T) {
	f := newDirectIPHub(t, "127.0.0.1")
	a, original := f.activateApp(t)
	a.command(t, directIPAppCommand{Close: true})
	f.hub.kill(t)
	keys := directIPKeyDigests(t, f.state)
	path := filepath.Join(f.state, "native-tls", "profile.json")
	var bundle directIPPrivateBundle
	readJSON(t, path, &bundle)
	defer clear(bundle.CAKeyDER)
	defer clear(bundle.ServiceKeyDER)
	caKey, ok := must(x509.ParsePKCS8PrivateKey(bundle.CAKeyDER)).(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("synthetic installed Hub CA has an unexpected key kind")
	}
	serviceKey, ok := must(x509.ParsePKCS8PrivateKey(bundle.ServiceKeyDER)).(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("synthetic installed Hub service has an unexpected key kind")
	}
	// Controlled near-expiry fixture on the real current clock. The Hub must
	// renew this valid six-day leaf itself; this is not six days elapsed time.
	now := time.Now().UTC()
	shortExpiry := now.Add(6 * 24 * time.Hour)
	leaf := must(x509.ParseCertificate(bundle.LeafDER))
	leaf.SerialNumber, leaf.NotAfter = big.NewInt(534155), shortExpiry
	bundle.LeafDER = must(x509.CreateCertificate(rand.Reader, leaf, must(x509.ParseCertificate(f.descriptor.Claims.RootCertificateDER)), &serviceKey.PublicKey, caKey))
	roots := x509.NewCertPool()
	roots.AddCert(must(x509.ParseCertificate(f.descriptor.Claims.RootCertificateDER)))
	near := must(x509.ParseCertificate(bundle.LeafDER))
	for _, at := range []time.Time{now, near.NotBefore.Add(time.Second)} {
		if _, err := near.Verify(x509.VerifyOptions{Roots: roots, DNSName: f.descriptor.Claims.ServerName, CurrentTime: at}); err != nil {
			t.Fatal("controlled near-expiry leaf did not qualify against its actual installation CA")
		}
	}
	writeJSON(t, path, bundle)
	f.start(t)
	c := must(hubtransport.NewHTTPClient(f.descriptor, f.address, 3*time.Second))
	response, err := c.Get(f.material.Origin + "/v2/client/identity")
	if err != nil {
		t.Fatal("actual Hub leaf renewal failed real TLS verification")
	}
	response.Body.Close()
	c.CloseIdleConnections()
	if response.TLS == nil || !response.TLS.PeerCertificates[0].NotAfter.After(shortExpiry) {
		t.Fatal("actual Hub failed to extend its near-expiry service leaf")
	}
	if !reflect.DeepEqual(keys, directIPKeyDigests(t, f.state)) {
		t.Fatal("leaf renewal changed application keys")
	}
	renewed := filepath.Join(f.dir, "renewed-public-transport.txt")
	if directIPCLIAt(t, f.binary, "hub", "connection-export", "--state-dir", f.state, "--descriptor-file", renewed) != 0 ||
		strings.TrimSpace(string(readPrivate(t, renewed))) != must(hubtransport.EncodeDescriptor(f.descriptor)) {
		t.Fatal("leaf renewal changed the persisted public descriptor, CA, SPKI or transport epoch")
	}
	a = startDirectIPApp(t, a.dir)
	discovered := a.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionDiscoverProfiles}})
	if discovered.ActionFailed || len(discovered.Snapshot.Profiles) != 1 {
		t.Fatal("leaf renewal lost the original App profile")
	}
	reply := a.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: discovered.Snapshot.Profiles[0].ID}})
	if reply.ActionFailed || !reply.Snapshot.Hub.Verified || reply.Snapshot.Account.DeviceID != original.Account.DeviceID ||
		reply.Snapshot.Account.LocalOwnerKeyID != original.Account.LocalOwnerKeyID || reply.Snapshot.Hub.Fingerprint != original.Hub.Fingerprint {
		t.Fatal("actual Hub leaf renewal required new application trust")
	}
	f.hub.kill(t)
	host, port := mustSplitDirectIP(t, f.address)
	directIPMutuallyExclusive(t, f.binary, "serve", "--hub-nodes-only", "--native-tls", "--node-pqtls-config", filepath.Join(f.dir, "synthetic-PQ-conflict.json"),
		"--state-dir", f.state, "--host", host, "--port", port)
	directIPFacts(t, "DIP05_TLSTrustIdentityAndTime", map[string]bool{"production_shared_chain_SAN_SPKI_live_time": true,
		"actual_Hub_near_expiry_renewal": true, "CA_SPKI_descriptor_and_App_keys_retained": true, "native_PQ_selection_refused": true})
}

func directIPRestart(t *testing.T) {
	f := newDirectIPHub(t, "127.0.0.1")
	a, original := f.activateApp(t)
	a.command(t, directIPAppCommand{Close: true})
	f.hub.kill(t)
	keys := directIPKeyDigests(t, f.state)
	retained := directIPRetainedState(t, f, a.dir)
	other := newDirectIPHub(t, "127.0.0.1")
	a = startDirectIPApp(t, a.dir)
	profiles := a.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionDiscoverProfiles}})
	if profiles.ActionFailed || len(profiles.Snapshot.Profiles) != 1 {
		t.Fatal("original profile unavailable before foreign Hub fault")
	}
	wrong := a.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: profiles.Snapshot.Profiles[0].ID, HubAddress: other.address}})
	if !wrong.ActionFailed || wrong.Snapshot.Hub.Verified || wrong.Snapshot.Authorization.Confirmed {
		t.Fatal("foreign Hub locator silently replaced original App trust")
	}
	a.command(t, directIPAppCommand{Close: true})
	if !reflect.DeepEqual(retained, directIPRetainedState(t, f, a.dir)) {
		t.Fatal("foreign Hub verification changed saved locator, scope or pending originals")
	}
	other.hub.kill(t)
	host, port := mustSplitDirectIP(t, f.address)
	serve := []string{"serve", "--hub-nodes-only", "--native-tls", "--state-dir", f.state, "--host", host, "--port", port}
	if directIPCLIAt(t, f.binary, "serve", "--hub-nodes-only", "--state-dir", f.state, "--host", host, "--port", port) == 0 {
		t.Fatal("native state implicitly fell back to plaintext HTTP")
	}
	for _, name := range []string{"identity.json", "client-control-identity.json", "node-control-identity.json"} {
		path := filepath.Join(f.state, "e2ee", name)
		raw := readPrivate(t, path)
		if os.Remove(path) != nil {
			t.Fatal("owned application-key fault could not be armed")
		}
		if directIPCLIAt(t, f.binary, serve...) == 0 {
			t.Fatal("Hub started with a missing application key")
		}
		for _, args := range [][]string{
			{"hub", "connection-export", "--state-dir", f.state, "--descriptor-file", filepath.Join(f.dir, "forbidden-export-"+name)},
			{"hub", "native-tls-init", "--state-dir", f.state, "--descriptor-file", filepath.Join(f.dir, "forbidden-init-"+name)},
			{"hub", "activation-issue", "--native-tls", "--purpose", "initial", "--state-dir", f.state, "--code-file", filepath.Join(f.dir, "private", "forbidden-code-"+name)},
		} {
			if directIPCLIAt(t, f.binary, args...) == 0 {
				t.Fatal("native Hub operation accepted a missing application key")
			}
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("existing Hub regenerated a missing application key")
		}
		atomicPrivate(t, path, raw)
		clear(raw)
		if !reflect.DeepEqual(keys, directIPKeyDigests(t, f.state)) {
			t.Fatal("failed startup changed retained application keys")
		}
	}
	profile := filepath.Join(f.state, "native-tls", "profile.json")
	raw := readPrivate(t, profile)
	defer clear(raw)
	if os.Remove(profile) != nil {
		t.Fatal("owned TLS-bundle fault could not be armed")
	}
	if directIPCLIAt(t, f.binary, serve...) == 0 || directIPCLIAt(t, f.binary, "hub", "native-tls-init", "--state-dir", f.state,
		"--descriptor-file", filepath.Join(f.dir, "forbidden-regenerated-descriptor.txt")) == 0 {
		t.Fatal("missing TLS bundle was silently repaired")
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatal("persistent public TLS pin failed to fence bundle regeneration")
	}
	atomicPrivate(t, profile, raw)
	var bundle directIPPrivateBundle
	if json.Unmarshal(raw, &bundle) != nil {
		t.Fatal("owned synthetic TLS bundle is invalid")
	}
	defer clear(bundle.CAKeyDER)
	defer clear(bundle.ServiceKeyDER)
	for _, field := range []string{"corrupt-bundle", "mixed-service-key", "changed-transport-epoch"} {
		switch field {
		case "corrupt-bundle":
			atomicPrivate(t, profile, []byte("SYNTHETIC QA CORRUPTION ONLY"))
		case "mixed-service-key":
			other := bundle
			other.ServiceKeyDER = must(x509.MarshalPKCS8PrivateKey(must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))))
			writeJSON(t, profile, other)
			clear(other.ServiceKeyDER)
		case "changed-transport-epoch":
			keyRaw := readPrivate(t, filepath.Join(f.state, "e2ee", "client-control-identity.json"))
			signer := must(e2ee.UnmarshalIdentity(keyRaw))
			clear(keyRaw)
			other := bundle
			claims := f.descriptor.Claims
			claims.TransportEpoch++
			other.Descriptor = must(hubtransport.EncodeDescriptor(must(hubtransport.SignDescriptor(signer, claims))))
			writeJSON(t, profile, other)
		}
		if directIPCLIAt(t, f.binary, serve...) == 0 || !reflect.DeepEqual(keys, directIPKeyDigests(t, f.state)) {
			t.Fatal("corrupt or mixed-generation TLS state started or changed application keys")
		}
		atomicPrivate(t, profile, raw)
	}
	f.start(t)
	a = startDirectIPApp(t, a.dir)
	reply := a.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionDiscoverProfiles}})
	if reply.ActionFailed || len(reply.Snapshot.Profiles) != 1 {
		t.Fatal("same-state restart lost the original App profile")
	}
	reply = a.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: reply.Snapshot.Profiles[0].ID}})
	if reply.ActionFailed || !reply.Snapshot.Hub.Verified || reply.Snapshot.Account.DeviceID != original.Account.DeviceID ||
		reply.Snapshot.Account.LocalOwnerKeyID != original.Account.LocalOwnerKeyID || reply.Snapshot.Hub.Fingerprint != original.Hub.Fingerprint {
		t.Fatal("same-state restart changed original App trust or keys")
	}
	directIPFacts(t, "DIP10_RestartAndChangedIdentity", map[string]bool{"same_state_restart": true, "foreign_Hub_no_repin_or_CAS": true, "missing_application_keys_no_regeneration": true,
		"missing_bundle_no_regeneration": true, "corrupt_mixed_epoch_refused": true, "no_implicit_plaintext": true, "original_App_identity_retained": true})
}

func (f *directIPHub) start(t *testing.T) {
	t.Helper()
	host, port := mustSplitDirectIP(t, f.address)
	cmd := exec.Command(f.binary, "serve", "--hub-nodes-only", "--native-tls", "--host", host, "--port", port, "--state-dir", f.state)
	var diagnostic directIPBoundedError
	cmd.Stderr = &diagnostic
	f.hub = startProcess(t, cmd)
	client := must(hubtransport.NewHTTPClient(f.descriptor, f.address, time.Second))
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if !f.hub.running() {
			category := "STARTUP_REJECTED"
			if strings.Contains(string(diagnostic.raw), "invalid Hub connection material") {
				category = "PROFILE_INVALID"
			}
			if strings.Contains(string(diagnostic.raw), "address already in use") {
				category = "BIND_CONFLICT"
			}
			t.Fatalf("actual native TLS Hub exited before identity discovery: exit=%d category=%s", f.hub.cmd.ProcessState.ExitCode(), category)
		}
		response, err := client.Get(f.descriptor.Claims.Origin + "/v2/client/identity")
		if err == nil {
			var actual wire.HubIdentity
			decodeErr := json.NewDecoder(io.LimitReader(response.Body, harnessPacketLimit)).Decode(&actual)
			response.Body.Close()
			if response.StatusCode != http.StatusOK || decodeErr != nil || !reflect.DeepEqual(actual, f.descriptor.Claims.Hub) {
				t.Fatal("native TLS Hub live identity differs from independently pinned identity")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("actual native TLS Hub did not expose its verified identity")
}

func mustSplitDirectIP(t *testing.T, address string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal("fixture lost its canonical numeric locator")
	}
	return host, port
}

func (a *directIPTLSAdversary) bootstrap(t *testing.T, expired bool) string {
	t.Helper()
	now := time.Now().UTC()
	issued, deadline := now.Add(-time.Minute), now.Add(5*time.Minute)
	if expired {
		issued, deadline = now.Add(-10*time.Minute), now.Add(-time.Minute)
	}
	c := a.descriptor.Claims
	m := wire.ActivationMaterial{Format: wire.ActivationFormat, Version: 1, Purpose: wire.PurposeInitialActivation,
		Origin: c.Origin, HubID: c.Hub.HubID, HubFingerprint: c.HubFingerprint, AccountID: "account_SYNTHETIC", OwnerID: "human_SYNTHETIC",
		ActivationID: strings.Repeat("5", 32), SetupEpoch: 1, AccountEpoch: 1,
		Code: "U1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1M", IssuedAt: issued.Format(time.RFC3339Nano), ExpiresAt: deadline.Format(time.RFC3339Nano)}
	return must(hubtransport.EncodeBootstrap(a.descriptor, must(wire.EncodeActivationCode(m))))
}

func directIPFacts(t *testing.T, name string, facts map[string]bool) {
	t.Helper()
	for _, observed := range facts {
		if !observed {
			t.Fatal("direct IP acceptance fact was not observed")
		}
	}
	t.Log("DIRECT_IP_FACTS " + string(must(json.Marshal(map[string]any{"case": name, "observed": facts}))))
}

func directIPDeniedApp(t *testing.T, bootstrap, address string, trap *directIPTLSTrap) {
	t.Helper()
	a := startDirectIPApp(t, t.TempDir())
	reply := a.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionConnect, HubAddress: address, BootstrapCode: bootstrap}})
	if !reply.ActionFailed || reply.Snapshot.Hub.Verified || reply.Snapshot.Authorization.Confirmed || reply.Snapshot.Account.DeviceEnrolled ||
		reply.Snapshot.Account.RootState == appcore.RootStateActive || reply.VaultCreates != 0 || reply.VaultOpens != 0 || trap.posts.Load() != 0 || trap.bytes.Load() != 0 || trap.creds.Load() != 0 {
		t.Fatal("failed App trust mutated a vault, sent a secret or created authority")
	}
	// A failed connection cannot unlock secret-bearing follow-up actions.
	for _, action := range []appcore.Action{{Kind: appcore.ActionGenerateOwner}, {Kind: appcore.ActionActivateApp, ConfirmLimitedAuthorization: true,
		Username: "synthetic-user", Password: syntheticPassword}, {Kind: appcore.ActionLogin, Username: "synthetic-user", Password: syntheticPassword}} {
		reply = a.command(t, directIPAppCommand{Action: &action})
		if !reply.ActionFailed || reply.VaultCreates != 0 || reply.VaultOpens != 0 || trap.posts.Load() != 0 || trap.bytes.Load() != 0 || trap.creds.Load() != 0 {
			t.Fatal("follow-up action bypassed failed transport trust")
		}
	}
	a.command(t, directIPAppCommand{Close: true})
}

func (f *directIPHub) activateApp(t *testing.T) (*directIPApp, appcore.Snapshot) {
	t.Helper()
	a := startDirectIPApp(t, filepath.Join(f.dir, "actual-app"))
	reply := a.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionConnect, HubAddress: f.address, BootstrapCode: f.bootstrap}})
	if reply.ActionFailed || !reply.Snapshot.Hub.Verified || reply.Snapshot.Hub.Origin != f.material.Origin ||
		reply.Snapshot.Hub.Fingerprint != f.material.HubFingerprint || reply.Snapshot.Authorization.Confirmed || reply.Snapshot.Account.RootState == appcore.RootStateActive {
		t.Fatal("verified App connection lost identity or created premature authority")
	}
	for _, action := range []appcore.Action{{Kind: appcore.ActionGenerateOwner}, {Kind: appcore.ActionActivateApp, ConfirmLimitedAuthorization: true,
		Username: "synthetic-user", Password: syntheticPassword}} {
		reply = a.command(t, directIPAppCommand{Action: &action})
		if reply.ActionFailed {
			t.Fatalf("actual App identity action failed: action=%s", action.Kind)
		}
	}
	if reply.Snapshot.Account.RootState != appcore.RootStateActive || reply.Snapshot.Authorization.Confirmed {
		t.Fatal("Root proof and account login were conflated")
	}
	beforeLogin := reply.Snapshot
	reply = a.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionLogin, Username: "synthetic-user", Password: syntheticPassword}})
	if reply.ActionFailed || reply.Snapshot.Account.RootState != beforeLogin.Account.RootState || !reply.Snapshot.Authorization.Confirmed ||
		reply.Snapshot.Management != appcore.ManagementUnavailable || reply.Snapshot.Canvas.State != appcore.CanvasNoAuthorization ||
		!reflect.DeepEqual(reply.Snapshot.Authorization.AllowedOperations, wire.ActivationAllowedOperations()) {
		t.Fatal("account login created general management authority or lost its finite N2 scope")
	}
	return a, reply.Snapshot
}

// A negative peer records only counters. It never acts as the positive Hub,
// proxies to one, retains request bodies or exports TLS fixture private keys.
type directIPTLSTrap struct {
	server *httptest.Server
	calls  atomic.Int64
	posts  atomic.Int64
	bytes  atomic.Int64
	creds  atomic.Int64
}

func newDirectIPTLSTrap(t *testing.T, status int, redirect string, certificates ...tls.Certificate) *directIPTLSTrap {
	t.Helper()
	return newDirectIPIdentityTrap(t, status, redirect, nil, certificates...)
}

func newDirectIPIdentityTrap(t *testing.T, status int, redirect string, identity any, certificates ...tls.Certificate) *directIPTLSTrap {
	t.Helper()
	trap := &directIPTLSTrap{}
	trap.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trap.calls.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.URL.RawQuery != "" {
			trap.creds.Add(1)
		}
		if r.Method == http.MethodPost {
			trap.posts.Add(1)
		}
		n, err := io.Copy(io.Discard, io.LimitReader(r.Body, harnessPacketLimit+1))
		trap.bytes.Add(n)
		if err != nil || n > harnessPacketLimit {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		if redirect != "" {
			w.Header().Set("Location", redirect)
		}
		if identity != nil {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		if identity != nil {
			_ = json.NewEncoder(w).Encode(identity)
		}
	}))
	trap.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: certificates}
	trap.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	trap.server.StartTLS()
	t.Cleanup(trap.server.Close)
	return trap
}

// Attacker-only keys and certificates are generated in memory. Positive
// acceptance must instead start the product Hub's own native TLS listener.
type directIPTLSAdversary struct {
	signer     *e2ee.Identity
	ca         *x509.Certificate
	caKey      *ecdsa.PrivateKey
	serviceKey *ecdsa.PrivateKey
	descriptor hubtransport.Descriptor
}

func newDirectIPTLSAdversary(t *testing.T) *directIPTLSAdversary {
	t.Helper()
	a := &directIPTLSAdversary{signer: must(e2ee.NewIdentity()), caKey: must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)),
		serviceKey: must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))}
	now := time.Now().UTC()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SYNTHETIC QA ATTACKER CA; NEVER DEPLOY"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	a.ca = must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, root, root, &a.caKey.PublicKey, a.caKey))))
	hub := wire.HubIdentity{Contract: "android-hub-v1", HubID: "hub_SYNTHETIC_independent_acceptance_only", Public: a.signer.Public(), KeyVersion: 1,
		Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}
	origin := must(hubtransport.DefaultOrigin(hub.HubID))
	u := must(url.Parse(origin))
	spki := sha256.Sum256(must(x509.MarshalPKIXPublicKey(&a.serviceKey.PublicKey)))
	a.descriptor = must(hubtransport.SignDescriptor(a.signer, hubtransport.Claims{Format: hubtransport.DescriptorFormat, Version: hubtransport.Version,
		Origin: origin, Hub: hub, HubFingerprint: must(wire.HubFingerprint(hub)), NodeControl: must(e2ee.NewIdentity()).Public(), NodeControlKeyVersion: 1,
		TransportEpoch: 1, ServerName: u.Hostname(), RootCertificateDER: a.ca.Raw, ServerSPKISHA256: hex.EncodeToString(spki[:])}))
	return a
}

func (a *directIPTLSAdversary) leaf(t *testing.T, name string, before, after time.Time, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	leaf := &x509.Certificate{SerialNumber: must(rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))),
		Subject: pkix.Name{CommonName: "SYNTHETIC QA ATTACKER LEAF; NEVER DEPLOY"}, DNSNames: []string{name},
		NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	return tls.Certificate{Certificate: [][]byte{must(x509.CreateCertificate(rand.Reader, leaf, a.ca, &key.PublicKey, a.caKey))}, PrivateKey: key}
}

func directIPTLSRequest(t *testing.T, client *http.Client, target string, change func(*http.Request)) (*http.Response, error) {
	t.Helper()
	r := must(http.NewRequest(http.MethodPost, target, strings.NewReader("SYNTHETIC QA SECRET CANARY; NEVER DEPLOY")))
	r.Header.Set("Authorization", "Bearer SYNTHETIC-QA-SECRET-CANARY")
	if change != nil {
		change(r)
	}
	response, err := client.Do(r)
	if response != nil {
		response.Body.Close()
	}
	return response, err
}

// This lane tests the frozen production shared transport against independent
// adversarial sockets. Passing it alone never establishes App/Node integration.
func TestN3DirectIPTLSSharedFaults(t *testing.T) {
	a := newDirectIPTLSAdversary(t)
	now := time.Now().UTC()
	goodLeaf := a.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), now.Add(time.Hour), a.serviceKey)
	t.Run("TLS-before-HTTP", func(t *testing.T) {
		other := newDirectIPTLSAdversary(t)
		for _, fault := range []string{"wrong-CA", "wrong-SPKI", "wrong-SAN", "expired", "not-yet-valid"} {
			t.Run(fault, func(t *testing.T) {
				certificate := goodLeaf
				switch fault {
				case "wrong-CA":
					certificate = other.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), now.Add(time.Hour), a.serviceKey)
				case "wrong-SPKI":
					certificate = a.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), now.Add(time.Hour), must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)))
				case "wrong-SAN":
					certificate = a.leaf(t, "foreign.synthetic.invalid", now.Add(-time.Hour), now.Add(time.Hour), a.serviceKey)
				case "expired":
					certificate = a.leaf(t, a.descriptor.Claims.ServerName, now.Add(-2*time.Hour), now.Add(-time.Hour), a.serviceKey)
				case "not-yet-valid":
					certificate = a.leaf(t, a.descriptor.Claims.ServerName, now.Add(time.Hour), now.Add(2*time.Hour), a.serviceKey)
				}
				trap := newDirectIPTLSTrap(t, http.StatusOK, "", certificate)
				client := must(hubtransport.NewHTTPClient(a.descriptor, trap.server.Listener.Addr().String(), 3*time.Second))
				t.Cleanup(client.CloseIdleConnections)
				if _, err := directIPTLSRequest(t, client, a.descriptor.Claims.Origin+"/synthetic-secret", nil); err == nil || trap.calls.Load() != 0 || trap.bytes.Load() != 0 || trap.creds.Load() != 0 {
					t.Fatal("TLS fault reached HTTP or did not reject")
				}
			})
		}
	})
	t.Run("bound-identity", func(t *testing.T) {
		for _, fault := range []string{"missing-CA", "Hub-ID", "Hub-key", "Hub-version", "Node-key", "epoch", "origin", "signature"} {
			d := a.descriptor
			switch fault {
			case "missing-CA":
				d.Claims.RootCertificateDER = nil
			case "Hub-ID":
				d.Claims.Hub.HubID = "hub_SYNTHETIC_foreign"
			case "Hub-key":
				d.Claims.Hub.Public = must(e2ee.NewIdentity()).Public()
			case "Hub-version":
				d.Claims.Hub.KeyVersion++
			case "Node-key":
				d.Claims.NodeControl = must(e2ee.NewIdentity()).Public()
			case "epoch":
				d.Claims.TransportEpoch++
			case "origin":
				d.Claims.Origin = "https://foreign.synthetic.invalid"
			case "signature":
				d.Signature = bytes.Repeat([]byte{0x53}, len(d.Signature))
			}
			if _, err := hubtransport.NewHTTPClient(d, "127.0.0.1:1", time.Second); err == nil {
				t.Fatalf("unsigned descriptor modification accepted: %s", fault)
			}
		}
	})
	t.Run("canonical-locator", func(t *testing.T) {
		for _, address := range []string{"127.0.0.1:1", "[::1]:65535"} {
			client, err := hubtransport.NewHTTPClient(a.descriptor, address, time.Second)
			if err != nil {
				t.Fatal("canonical numeric locator refused")
			}
			client.CloseIdleConnections()
		}
		for _, address := range []string{"localhost:443", "https://127.0.0.1:443", "user@127.0.0.1:443", "127.0.0.1:443/path", "127.0.0.1:443?q=1", "127.0.0.1:443#f", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:0443", "127.000.0.1:443", "0.0.0.0:443", "224.0.0.1:443", "::1:443", "[::ffff:127.0.0.1]:443", "[fe80::1%lo]:443", " 127.0.0.1:443"} {
			if client, err := hubtransport.NewHTTPClient(a.descriptor, address, time.Second); err == nil {
				client.CloseIdleConnections()
				t.Fatal("noncanonical or forbidden locator accepted")
			}
		}
	})
	t.Run("redirect-no-forward", func(t *testing.T) {
		for _, status := range []int{301, 302, 303, 307, 308} {
			for _, mode := range []string{"same-origin", "foreign-HTTPS", "HTTP-downgrade"} {
				target := newDirectIPTLSTrap(t, http.StatusOK, "", goodLeaf)
				location := target.server.URL + "/synthetic-target"
				if mode == "same-origin" {
					location = a.descriptor.Claims.Origin + "/synthetic-target"
				} else if mode == "HTTP-downgrade" {
					location = strings.Replace(location, "https://", "http://", 1)
				}
				source := newDirectIPTLSTrap(t, status, location, goodLeaf)
				client := must(hubtransport.NewHTTPClient(a.descriptor, source.server.Listener.Addr().String(), 3*time.Second))
				response, err := directIPTLSRequest(t, client, a.descriptor.Claims.Origin+"/synthetic-source", nil)
				client.CloseIdleConnections()
				if err != nil || response.StatusCode != status || source.calls.Load() != 1 || source.posts.Load() != 1 || target.calls.Load() != 0 || target.bytes.Load() != 0 || target.creds.Load() != 0 {
					t.Fatal("production transport followed a redirect or changed its result")
				}
			}
		}
	})
	t.Run("origin-before-dial", func(t *testing.T) {
		trap := newDirectIPTLSTrap(t, http.StatusOK, "", goodLeaf)
		client := must(hubtransport.NewHTTPClient(a.descriptor, trap.server.Listener.Addr().String(), 3*time.Second))
		t.Cleanup(client.CloseIdleConnections)
		for _, fault := range []string{"scheme", "authority", "Host", "Origin", "userinfo", "fragment"} {
			_, err := directIPTLSRequest(t, client, a.descriptor.Claims.Origin+"/synthetic-secret", func(r *http.Request) {
				switch fault {
				case "scheme":
					r.URL.Scheme = "http"
				case "authority":
					r.URL.Host = "foreign.synthetic.invalid"
				case "Host":
					r.Host = "foreign.synthetic.invalid"
				case "Origin":
					r.Header.Set("Origin", "https://foreign.synthetic.invalid")
				case "userinfo":
					r.URL.User = url.User("synthetic")
				case "fragment":
					r.URL.Fragment = "synthetic"
				}
			})
			if err == nil || trap.calls.Load() != 0 {
				t.Fatalf("origin fault reached HTTP: %s", fault)
			}
		}
	})
	t.Run("proxy-poison-and-leaf-renewal", func(t *testing.T) {
		proxy := newDirectIPTLSTrap(t, http.StatusBadGateway, "")
		for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
			t.Setenv(name, proxy.server.URL)
		}
		t.Setenv("NO_PROXY", "")
		t.Setenv("no_proxy", "")
		// Two independently verified leafs share their original CA and service
		// key. This is a transport invariance control, not Hub auto-renewal.
		for _, after := range []time.Time{now.Add(time.Hour), now.Add(2 * time.Hour)} {
			leaf := a.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), after, a.serviceKey)
			trap := newDirectIPTLSTrap(t, http.StatusNoContent, "", leaf)
			client := must(hubtransport.NewHTTPClient(a.descriptor, trap.server.Listener.Addr().String(), 3*time.Second))
			response, err := directIPTLSRequest(t, client, a.descriptor.Claims.Origin+"/synthetic-control", func(r *http.Request) {
				r.Header.Set("Forwarded", "host=foreign.synthetic.invalid;proto=http")
				r.Header.Set("X-Forwarded-Host", "foreign.synthetic.invalid")
				r.Header.Set("X-Forwarded-Proto", "http")
			})
			client.CloseIdleConnections()
			if err != nil || response.StatusCode != http.StatusNoContent || trap.calls.Load() != 1 || proxy.calls.Load() != 0 {
				t.Fatal("numeric TLS selected a proxy or lost unchanged service-key trust")
			}
		}
	})
}

// These deterministic tests qualify only the attack fixture and its observer.
// Their trusted test client is never injected into the product App transport.
func TestN3DirectIPTLSFaultFixture(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			target := newDirectIPTLSTrap(t, http.StatusOK, "")
			source := newDirectIPTLSTrap(t, status, target.server.URL+"/synthetic-trap")
			client := source.server.Client()
			client.Timeout = 3 * time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			payload := []byte("SYNTHETIC REDIRECT OBSERVER FIXTURE ONLY")
			response, err := client.Post(source.server.URL+"/synthetic-source", "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				t.Fatal("synthetic fixture request failed")
			}
			response.Body.Close()
			if response.StatusCode != status || source.posts.Load() != 1 || source.bytes.Load() != int64(len(payload)) || target.posts.Load() != 0 || target.bytes.Load() != 0 {
				t.Fatal("redirect observer lost or forwarded a synthetic request")
			}
		})
	}
	t.Run("untrusted-CA-before-HTTP", func(t *testing.T) {
		trap := newDirectIPTLSTrap(t, http.StatusOK, "")
		transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool()}}
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		response, err := client.Post(trap.server.URL, "application/octet-stream", bytes.NewBufferString("SYNTHETIC UNTRUSTED-CA FIXTURE ONLY"))
		if response != nil {
			response.Body.Close()
		}
		if err == nil || trap.posts.Load() != 0 || trap.bytes.Load() != 0 {
			t.Fatal("untrusted synthetic TLS reached HTTP")
		}
	})
	t.Run("synthetic-time-real-X509", func(t *testing.T) {
		trap := newDirectIPTLSTrap(t, http.StatusOK, "")
		cert := trap.server.Certificate()
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		for _, at := range []time.Time{cert.NotBefore.Add(-time.Second), cert.NotAfter.Add(time.Second)} {
			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1", CurrentTime: at}); err == nil {
				t.Fatal("real X509 accepted certificate outside its validity window")
			}
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1", CurrentTime: cert.NotBefore.Add(time.Second)}); err != nil {
			t.Fatal("synthetic validity check lacks an accepted control")
		}
	})
}

// The acceptance selector and case names retain the pre-implementation matrix.
// Consumers use the frozen shared API and Root-approved App actions. Their
// source alone is not an execution receipt or a qualification of any case.
// In particular, the historical HTTPS reverse-proxy fixture is not a positive
// substitute for the single product Hub terminating its own TLS connection.
func TestN3DirectIPTLSAcceptance(t *testing.T) {
	if os.Getenv("CICADA_N3_DIRECT_IP_TLS") != "1" {
		t.Skip("DIRECT_IP_NOT_RUN: explicit isolated gate is off")
	}
	t.Run("DIP01_FreshSingleHub", directIPFreshHub)
	t.Run("DIP02_IPv4IPv6NoDNS", directIPFamilies)
	t.Run("DIP03_IndependentBootstrapPin", directIPFirstTrust)
	t.Run("DIP04_CanonicalLocator", directIPLocator)
	t.Run("DIP05_TLSTrustIdentityAndTime", directIPTLSIdentity)
	t.Run("DIP06_FakeHubMITMNoSecrets", directIPMITM)
	t.Run("DIP07_RedirectNoSecrets", directIPRedirect)
	t.Run("DIP08_ProxyHostAndOriginSpoof", directIPProxy)
	t.Run("DIP09_NoImplicitOwnerAuthority", directIPAuthority)
	t.Run("DIP10_RestartAndChangedIdentity", directIPRestart)
	t.Run("DIP11_OriginCompatibilityMigration", directIPLocatorChange)
	t.Run("DIP12_OriginalPacketRecovery", directIPOriginalRecovery)
}

func directIPFreshHub(t *testing.T) {
	f := newDirectIPHub(t, "127.0.0.1")
	_, s := f.activateApp(t)
	directIPFacts(t, "DIP01_FreshSingleHub", map[string]bool{"file_install_only": true, "actual_native_hub": f.hub.running(),
		"no_preset_origin": strings.HasSuffix(s.Hub.Origin, ".cicada.invalid"), "live_pq_identity": s.Hub.Fingerprint == f.material.HubFingerprint,
		"control_off": s.Management == appcore.ManagementUnavailable && s.Canvas.State == appcore.CanvasNoAuthorization})
}

func directIPFirstTrust(t *testing.T) {
	a := newDirectIPTLSAdversary(t)
	trap := newDirectIPTLSTrap(t, http.StatusOK, "")
	bootstrap := a.bootstrap(t, false)
	directIPDeniedApp(t, bootstrap[:len(bootstrap)-1]+"!", trap.server.Listener.Addr().String(), trap)
	directIPDeniedApp(t, a.bootstrap(t, true), trap.server.Listener.Addr().String(), trap)
	directIPDeniedApp(t, must(hubtransport.EncodeDescriptor(a.descriptor)), trap.server.Listener.Addr().String(), trap)
	directIPFacts(t, "DIP03_IndependentBootstrapPin", map[string]bool{"tamper_rejected": true, "expired_rejected": true,
		"public_descriptor_no_authority": true, "zero_secret_posts": trap.posts.Load() == 0, "zero_vault_mutation": true})
}

func directIPLocator(t *testing.T) {
	a := newDirectIPTLSAdversary(t)
	trap := newDirectIPTLSTrap(t, http.StatusOK, "")
	for _, address := range []string{"https://127.0.0.1:443", "localhost:443", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:443/secret", "127.0.0.1:443?secret", "[::ffff:127.0.0.1]:443", "[fe80::1%lo]:443"} {
		directIPDeniedApp(t, a.bootstrap(t, false), address, trap)
	}
	for _, address := range []string{"127.0.0.1:443", "[::1]:443"} {
		c := must(hubtransport.NewHTTPClient(a.descriptor, address, time.Second))
		c.CloseIdleConnections()
	}
	directIPFacts(t, "DIP04_CanonicalLocator", map[string]bool{"numeric_inputs": true, "invalid_inputs_refused": true, "no_dial_on_invalid": trap.calls.Load() == 0})
}

func directIPMITM(t *testing.T) {
	a := newDirectIPTLSAdversary(t)
	now := time.Now().UTC()
	other := newDirectIPTLSAdversary(t)
	for _, certificate := range []tls.Certificate{
		other.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), now.Add(time.Hour), a.serviceKey),
		a.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), now.Add(time.Hour), other.serviceKey),
		a.leaf(t, "foreign.synthetic.invalid", now.Add(-time.Hour), now.Add(time.Hour), a.serviceKey),
		a.leaf(t, a.descriptor.Claims.ServerName, now.Add(-2*time.Hour), now.Add(-time.Hour), a.serviceKey),
		a.leaf(t, a.descriptor.Claims.ServerName, now.Add(time.Hour), now.Add(2*time.Hour), a.serviceKey),
	} {
		trap := newDirectIPTLSTrap(t, http.StatusOK, "", certificate)
		directIPDeniedApp(t, a.bootstrap(t, false), trap.server.Listener.Addr().String(), trap)
		if trap.calls.Load() != 0 {
			t.Fatal("attacker observed HTTP before TLS trust was established")
		}
	}
	// A valid pinned TLS channel is insufficient when the live application
	// identity disagrees with the independently supplied PQ binding.
	goodLeaf := a.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), now.Add(time.Hour), a.serviceKey)
	for _, field := range []string{"Client-Control-key", "Hub-ID", "key-version"} {
		identity := a.descriptor.Claims.Hub
		switch field {
		case "Client-Control-key":
			identity.Public = other.descriptor.Claims.Hub.Public
		case "Hub-ID":
			identity.HubID = "hub_SYNTHETIC_foreign_identity"
		case "key-version":
			identity.KeyVersion++
		}
		trap := newDirectIPIdentityTrap(t, http.StatusOK, "", &identity, goodLeaf)
		directIPDeniedApp(t, a.bootstrap(t, false), trap.server.Listener.Addr().String(), trap)
		if trap.calls.Load() == 0 {
			t.Fatal("valid TLS live-identity fault never reached public discovery")
		}
	}
	directIPFacts(t, "DIP06_FakeHubMITMNoSecrets", map[string]bool{"actual_app_production_transport": true, "TLS_refused_before_HTTP": true,
		"live_Hub_PQ_mismatch_before_secret": true, "zero_secret_posts": true, "zero_vault_mutation": true, "no_followup_authority": true})
}

func directIPRedirect(t *testing.T) {
	a := newDirectIPTLSAdversary(t)
	now := time.Now().UTC()
	leaf := a.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), now.Add(time.Hour), a.serviceKey)
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, mode := range []string{"same-origin", "foreign-HTTPS", "HTTP-downgrade"} {
			target := newDirectIPTLSTrap(t, http.StatusOK, "", leaf)
			location := target.server.URL + "/synthetic-target"
			if mode == "same-origin" {
				location = a.descriptor.Claims.Origin + "/synthetic-target"
			} else if mode == "HTTP-downgrade" {
				location = strings.Replace(location, "https:", "http:", 1)
			}
			source := newDirectIPTLSTrap(t, status, location, leaf)
			directIPDeniedApp(t, a.bootstrap(t, false), source.server.Listener.Addr().String(), source)
			if source.calls.Load() != 1 || target.calls.Load() != 0 || target.bytes.Load() != 0 || target.creds.Load() != 0 {
				t.Fatal("actual App followed discovery redirect or bypassed its source")
			}
		}
	}
	directIPFacts(t, "DIP07_RedirectNoSecrets", map[string]bool{"actual_app_discovery": true, "all_5_statuses_3_targets": true,
		"production_secret_request_no_forward": true, "zero_forwarded_credentials": true})
}

func directIPProxy(t *testing.T) {
	trap := newDirectIPTLSTrap(t, http.StatusBadGateway, "")
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, trap.server.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	f := newDirectIPHub(t, "127.0.0.1")
	_, s := f.activateApp(t)
	c := must(hubtransport.NewHTTPClient(f.descriptor, f.address, 3*time.Second))
	defer c.CloseIdleConnections()
	r := must(http.NewRequest(http.MethodGet, f.material.Origin+"/v2/client/identity", nil))
	r.Header.Set("Forwarded", "host=foreign.synthetic.invalid;proto=http")
	r.Header.Set("X-Forwarded-Host", "foreign.synthetic.invalid")
	r.Header.Set("X-Forwarded-Proto", "http")
	response, err := c.Do(r)
	if err != nil {
		t.Fatal("forged forwarding headers broke independently verified TLS")
	}
	var actual wire.HubIdentity
	decodeErr := json.NewDecoder(io.LimitReader(response.Body, harnessPacketLimit)).Decode(&actual)
	response.Body.Close()
	if decodeErr != nil || response.StatusCode != 200 || !reflect.DeepEqual(actual, f.descriptor.Claims.Hub) {
		t.Fatal("forwarding headers changed live application identity")
	}
	directIPFacts(t, "DIP08_ProxyHostAndOriginSpoof", map[string]bool{"actual_app_login_with_poisoned_proxy": s.Authorization.Confirmed,
		"proxy_HTTP_calls_zero": trap.calls.Load() == 0, "forwarded_headers_no_identity_change": true, "host_origin_rejected_before_dial": true})
}

func directIPAuthority(t *testing.T) {
	f := newDirectIPHub(t, "127.0.0.1")
	_, s := f.activateApp(t)
	directIPFacts(t, "DIP09_NoImplicitOwnerAuthority", map[string]bool{"connection_zero_authority": true, "Root_proof_before_login": true,
		"login_did_not_create_Root": true, "finite_N2_scope_only": reflect.DeepEqual(s.Authorization.AllowedOperations, wire.ActivationAllowedOperations()),
		"no_Manager_or_canvas": s.Management == appcore.ManagementUnavailable && s.Canvas.State == appcore.CanvasNoAuthorization})
}

func directIPLocatorChange(t *testing.T) {
	for _, origin := range []string{"", "https://legacy.synthetic.invalid:7443", "https://192.0.2.42:7443"} {
		f := newDirectIPHubOrigin(t, "127.0.0.1", origin)
		a, original := f.activateApp(t)
		a.command(t, directIPAppCommand{Close: true})
		f.hub.kill(t)
		listener := must(net.Listen("tcp", "127.0.0.1:0"))
		f.address = listener.Addr().String()
		listener.Close()
		f.start(t)
		a = startDirectIPApp(t, a.dir)
		reply := a.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionDiscoverProfiles}})
		if reply.ActionFailed || len(reply.Snapshot.Profiles) != 1 {
			t.Fatal("original encrypted profile was not discoverable without bootstrap material")
		}
		reply = a.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: reply.Snapshot.Profiles[0].ID, HubAddress: f.address}})
		s := reply.Snapshot
		if reply.ActionFailed || !s.Hub.Verified || s.Hub.Origin != original.Hub.Origin || s.Hub.Fingerprint != original.Hub.Fingerprint ||
			s.Account.LocalOwnerKeyID != original.Account.LocalOwnerKeyID || s.Account.DeviceID != original.Account.DeviceID || s.Account.RootState != original.Account.RootState {
			t.Fatal("numeric locator change rewrote original scope, identity or Root state")
		}
		a.command(t, directIPAppCommand{Close: true})
		f.hub.kill(t)
	}
	directIPFacts(t, "DIP11_OriginCompatibilityMigration", map[string]bool{"explicit_locator_change": true, "old_logical_origin_retained": true,
		"legacy_DNS_and_IP_cards_keys_retained": true, "Owner_device_and_vault_scope_retained": true, "no_new_bootstrap": true, "no_silent_repin": true})
}
