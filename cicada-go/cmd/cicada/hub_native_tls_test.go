package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/ownersigner"
	"github.com/cicada-ai/cicada/internal/store"
)

func readTreeHashesForNativeTLS(t *testing.T, root string) map[string][32]byte {
	t.Helper()
	files := map[string][32]byte{}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		defer clear(raw)
		files[path] = sha256.Sum256(raw)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return files
}

func setupNativeHub(t *testing.T) (string, hubtransport.Descriptor, string) {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "SYNTHETIC-native-Hub")
	if err := hubSetupCommand([]string{"--owner-label", "SYNTHETIC native owner", "--state-dir", state, "--public-config", filepath.Join(root, "owner-public.json")}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "hub-transport.txt")
	if err := hubNativeTLSCommand([]string{"--state-dir", state, "--descriptor-file", path}, &bytes.Buffer{}, false); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := hubtransport.DecodeDescriptor(strings.TrimSuffix(string(text), "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return state, d, strings.TrimSuffix(string(text), "\n")
}

func TestHubNativeTLSCLISetupExportAndActivationPreserveScope(t *testing.T) {
	state, d, text := setupNativeHub(t)
	config := hubControlConfig(state, "")
	db, err := store.New(filepath.Join(state, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	setup, err := db.GetHubOwnerSetup()
	if err != nil {
		t.Fatal(err)
	}
	want, err := hubtransport.DefaultOrigin(setup.HubID)
	if err != nil || setup.Origin != want || d.Claims.Origin != want {
		t.Fatal("setup required or invented external locator")
	}
	before := readTreeHashesForNativeTLS(t, filepath.Join(state, "e2ee"))
	if err := hubSetupCommand([]string{"--owner-label", setup.Name, "--state-dir", state, "--public-config", filepath.Join(filepath.Dir(state), "owner-public.json")}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if pinned, err := db.HubNativeTLSDescriptor(); err != nil || pinned != text {
		t.Fatal("repeat setup changed signed transport")
	}
	for path, digest := range before {
		if after := readTreeHashesForNativeTLS(t, filepath.Join(state, "e2ee"))[path]; after != digest {
			t.Fatal("repeat setup changed application key")
		}
	}
	path := filepath.Join(state, "SYNTHETIC-activation-private.txt")
	var output bytes.Buffer
	if err := hubActivationIssueCommand([]string{"--state-dir", state, "--native-tls", "--purpose", "initial", "--code-file", path}, &output); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	b, err := hubtransport.DecodeBootstrap(strings.TrimSuffix(string(raw), "\n"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := hubtransport.ValidateBootstrap(b, time.Now())
	if err != nil || m.AccountID != setup.AccountID || m.OwnerID != setup.OwnerID || b.Descriptor.Claims.HubFingerprint != d.Claims.HubFingerprint {
		t.Fatal("activation wrapper changed scope")
	}
	if bytes.Contains(output.Bytes(), []byte(m.Code)) || bytes.Contains(output.Bytes(), []byte(b.ActivationCode)) {
		t.Fatal("CLI exposed activation secret")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe activation mode")
	}
	after, err := db.GetHubOwnerSetup()
	if err != nil || after.RootEverEstablished {
		t.Fatal("TLS installation granted Root")
	}
	if err = checkHubNativeTLSMode(config, true, false); err != nil {
		t.Fatal(err)
	}
}

func TestHubNativeTLSMissingFlagsKeysAndConflictingModesFailClosed(t *testing.T) {
	state, _, _ := setupNativeHub(t)
	config := hubControlConfig(state, "")
	if err := serve([]string{"--hub-nodes-only", "--state-dir", state, "--port", "0"}); err == nil {
		t.Fatal("native state started implicit plaintext")
	}
	if err := checkHubNativeTLSMode(config, false, true); err != nil {
		t.Fatal("explicit operator legacy mode rejected")
	}
	if err := serve([]string{"--hub-nodes-only", "--native-tls", "--node-pqtls-config", "SYNTHETIC-not-read", "--state-dir", state}); err == nil {
		t.Fatal("mixed transports accepted")
	}
	for _, name := range []string{"identity.json", "client-control-identity.json", "node-control-identity.json"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(state, "e2ee", name)
			if err := os.Rename(path, path+".retained"); err != nil {
				t.Fatal(err)
			}
			defer os.Rename(path+".retained", path)
			if err := serve([]string{"--hub-nodes-only", "--native-tls", "--state-dir", state, "--port", "0"}); err == nil {
				t.Fatal("missing application key accepted")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("serve regenerated missing application key")
			}
		})
	}
	if err := os.RemoveAll(filepath.Join(state, "native-tls")); err != nil {
		t.Fatal(err)
	}
	if err := checkHubNativeTLSMode(config, false, false); err == nil {
		t.Fatal("deleted profile silently enabled plaintext")
	}
	if err := hubNativeTLSCommand([]string{"--state-dir", state, "--descriptor-file", filepath.Join(filepath.Dir(state), "must-not-create.txt")}, &bytes.Buffer{}, true); err == nil {
		t.Fatal("deleted bundle regenerated under permanent pin")
	}
}

func TestHubNativeTLSExistingOriginAndInterruptedPinKeepActivationBytes(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "SYNTHETIC-legacy-Hub")
	origin := "https://legacy.synthetic.invalid:9443"
	if err := hubSetupCommand([]string{"--owner-label", "SYNTHETIC legacy owner", "--origin", origin, "--state-dir", state, "--public-config", filepath.Join(root, "old-owner.json")}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	codeFile := filepath.Join(state, "SYNTHETIC-old-activation.txt")
	if err := hubActivationIssueCommand([]string{"--state-dir", state, "--purpose", "initial", "--code-file", codeFile}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(codeFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	keys := readTreeHashesForNativeTLS(t, filepath.Join(state, "e2ee"))
	config := hubControlConfig(state, "")
	db, err := store.New(filepath.Join(state, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := db.GetHubOwnerSetup()
	if err != nil {
		t.Fatal(err)
	}
	ids, err := existingHubNodeIdentities(config)
	if err != nil {
		t.Fatal(err)
	}
	p, err := hubtransport.InitializeProfile(state, ids.ClientControl, nativeHubIdentity(before, ids), ids.NodeControl.Public(), origin, "")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := checkHubNativeTLSMode(config, false, false); err == nil {
		t.Fatal("interrupted TLS init opened implicit plaintext")
	}
	if err := checkHubNativeTLSMode(config, true, false); err == nil {
		t.Fatal("uncommitted pin served native TLS")
	}
	file := filepath.Join(root, "resumed-transport.txt")
	if err := hubNativeTLSCommand([]string{"--state-dir", state, "--descriptor-file", file}, &bytes.Buffer{}, true); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(file)
	if err != nil || strings.TrimSuffix(string(text), "\n") != p.DescriptorText() {
		t.Fatal("resume re-signed original public descriptor")
	}
	db, err = store.New(filepath.Join(state, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	after, err := db.GetHubOwnerSetup()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("native init changed original Owner/account/epoch/origin")
	}
	retained, err := os.ReadFile(codeFile)
	if err != nil || !bytes.Equal(original, retained) {
		t.Fatal("native init rewrote pending activation")
	}
	clear(retained)
	if !reflect.DeepEqual(keys, readTreeHashesForNativeTLS(t, filepath.Join(state, "e2ee"))) {
		t.Fatal("native init regenerated an application identity")
	}
}

func TestHubNativeTLSRejectsHTTPWithoutChangingLegacySetup(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "SYNTHETIC-loopback-Hub")
	base := []string{"--owner-label", "SYNTHETIC loopback owner", "--origin", "http://127.0.0.1:8787", "--allow-loopback-http", "--state-dir", state, "--public-config", filepath.Join(root, "owner.json")}
	if err := hubSetupCommand(append(append([]string{}, base...), "--native-tls"), &bytes.Buffer{}); err == nil {
		t.Fatal("native setup accepted HTTP")
	}
	if _, err := os.Lstat(state); !os.IsNotExist(err) {
		t.Fatal("rejected setup created StateDir")
	}
	if err := hubSetupCommand(base, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := hubNativeTLSCommand([]string{"--state-dir", state, "--descriptor-file", filepath.Join(root, "must-not-export.txt")}, &bytes.Buffer{}, true); err == nil {
		t.Fatal("existing HTTP scope accepted native init")
	}
	if present, err := hubtransport.ProfilePresent(state); err != nil || present {
		t.Fatal("rejected init left native marker")
	}
	if err := checkHubNativeTLSMode(hubControlConfig(state, ""), false, false); err != nil {
		t.Fatal("rejected native init broke legacy start")
	}
}

func TestHubNativeTLSHistoricalIssuersNeverRegenerateMissingKeys(t *testing.T) {
	for _, mode := range []string{"committed-pin", "profile-before-pin", "pin-with-lost-bundle"} {
		t.Run(mode, func(t *testing.T) {
			var state string
			if mode == "profile-before-pin" {
				root := t.TempDir()
				state = filepath.Join(root, "SYNTHETIC-residual-Hub")
				if err := hubSetupCommand([]string{"--owner-label", "SYNTHETIC residual owner", "--origin", "https://residual.synthetic.invalid", "--state-dir", state, "--public-config", filepath.Join(root, "owner.json")}, &bytes.Buffer{}); err != nil {
					t.Fatal(err)
				}
				config := hubControlConfig(state, "")
				db, err := store.New(filepath.Join(state, "cicada.sqlite3"))
				if err != nil {
					t.Fatal(err)
				}
				setup, err := db.GetHubOwnerSetup()
				if err != nil {
					t.Fatal(err)
				}
				ids, err := existingHubNodeIdentities(config)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = hubtransport.InitializeProfile(state, ids.ClientControl, nativeHubIdentity(setup, ids), ids.NodeControl.Public(), setup.Origin, ""); err != nil {
					t.Fatal(err)
				}
				db.Close()
			} else {
				state, _, _ = setupNativeHub(t)
			}
			config := hubControlConfig(state, "")
			db, err := store.New(filepath.Join(state, "cicada.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			setup, err := db.GetHubOwnerSetup()
			if err != nil {
				t.Fatal(err)
			}
			ids, err := existingHubNodeIdentities(config)
			if err != nil {
				t.Fatal(err)
			}
			db.Close()
			if mode == "pin-with-lost-bundle" {
				if err := os.RemoveAll(filepath.Join(state, "native-tls")); err != nil {
					t.Fatal(err)
				}
			}
			owner, err := e2ee.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			candidate := ownersigner.PublicManifest{Format: "cicada.owner-signer-public.v1", AccountID: setup.AccountID, OwnerID: setup.OwnerID, OwnerPublic: owner.Public(), Fingerprint: ownerbootstrap.Fingerprint(owner.Public()), Origin: setup.Origin,
				Hub: clientoperator.HubIdentity{Contract: "android-hub-v1", HubID: setup.HubID, Public: ids.ClientControl.Public(), KeyVersion: 1, Suite: clientoperator.Suite}}
			raw, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			candidateFile := filepath.Join(state, "SYNTHETIC-public-candidate.json")
			if err = os.WriteFile(candidateFile, raw, 0644); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"identity.json", "client-control-identity.json", "node-control-identity.json"} {
				t.Run(name, func(t *testing.T) {
					path := filepath.Join(state, "e2ee", name)
					if err := os.Rename(path, path+".retained"); err != nil {
						t.Fatal(err)
					}
					defer os.Rename(path+".retained", path)
					claim := filepath.Join(state, "must-not-issue-claim.json")
					if err := hubAccountClaimIssueCommand([]string{"--state-dir", state, "--claim-file", claim}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
						t.Fatal("account issuer accepted missing key")
					}
					pair := filepath.Join(state, "must-not-issue-pair.json")
					if err := hubOwnerBootstrapIssueCommand([]string{"--state-dir", state, "--candidate-manifest", candidateFile, "--candidate-fingerprint", candidate.Fingerprint, "--pair-file", pair}, strings.NewReader("approve\n"), &bytes.Buffer{}); err == nil {
						t.Fatal("Owner issuer accepted missing key")
					}
					for _, abs := range []string{path, claim, pair} {
						if _, err := os.Lstat(abs); !os.IsNotExist(err) {
							t.Fatal("issuer created missing identity or authority output")
						}
					}
				})
			}
		})
	}
}

func TestHubNativeTLSProcessHelper(t *testing.T) {
	if os.Getenv("CICADA_SYNTHETIC_NATIVE_TLS_CHILD") != "1" {
		return
	}
	var args []string
	if json.Unmarshal([]byte(os.Getenv("CICADA_SYNTHETIC_NATIVE_TLS_ARGS")), &args) != nil {
		t.Fatal("invalid synthetic child arguments")
	}
	if err := serve(args); err != nil {
		t.Fatal(err)
	}
}

func TestHubNativeTLSActualServeProcessHasNoProxyOrDNS(t *testing.T) {
	state, d, _ := setupNativeHub(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_, port, err := net.SplitHostPort(address)
	listener.Close()
	if err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal([]string{"--hub-nodes-only", "--native-tls", "--state-dir", state, "--host", "127.0.0.1", "--port", port})
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestHubNativeTLSProcessHelper$")
	cmd.Env = append(os.Environ(), "CICADA_SYNTHETIC_NATIVE_TLS_CHILD=1", "CICADA_SYNTHETIC_NATIVE_TLS_ARGS="+string(args))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	client, err := hubtransport.NewHTTPClient(d, address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	var response *http.Response
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err = client.Get(d.Claims.Origin + "/v2/client/identity")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("native CLI listener failed to become ready")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("native identity route unavailable")
	}
	plain := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	defer plain.CloseIdleConnections()
	r, err := plain.Get("http://" + address + "/healthz")
	if err == nil {
		defer r.Body.Close()
		if r.StatusCode == http.StatusOK {
			t.Fatal("native listener served plaintext health")
		}
	}
}
