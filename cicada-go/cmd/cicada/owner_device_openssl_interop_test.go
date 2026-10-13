//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/server"
	"golang.org/x/sys/unix"
)

const syntheticOpenSSLPassword = "SYNTHETIC-EPHEMERAL-TEST-ONLY-no-deployment\n"

type syntheticOpenSSLOwner struct {
	dir, executable, signingPrivate, publicFile string
	public                                      e2ee.PublicIdentity
}

// This helper is reached only by the private PTY subprocess below. The product
// receives an actual terminal, and OpenSSL alone reads the typed passphrase.
func TestOwnerDeviceOpenSSLPTYHelper(t *testing.T) {
	encoded := os.Getenv("CICADA_SYNTHETIC_OWNER_PTY_ARGS")
	if encoded == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(encoded), &args); err != nil {
		t.Fatal(err)
	}
	if err := ownerDeviceGrantSignOpenSSLCommand(args, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func signSyntheticOwnerThroughPTY(t *testing.T, args []string) error {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0600)
	if err != nil {
		return err
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		return err
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		return err
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0600)
	if err != nil {
		return err
	}
	defer slave.Close()
	encoded, err := json.Marshal(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOwnerDeviceOpenSSLPTYHelper$", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), "CICADA_SYNTHETIC_OWNER_PTY_ARGS="+string(encoded))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = slave.Close()
	promptSeen := make(chan bool, 1)
	go func() {
		buffer := make([]byte, 4096)
		seen := ""
		typed := false
		for {
			n, err := master.Read(buffer)
			seen += string(buffer[:n])
			if !typed && strings.Contains(seen, "Enter pass phrase") {
				_, _ = master.Write([]byte(syntheticOpenSSLPassword))
				typed = true
			}
			if err != nil {
				break
			}
		}
		promptSeen <- typed
	}()
	err = cmd.Wait()
	_ = master.Close()
	if !<-promptSeen && err == nil {
		return fmt.Errorf("actual OpenSSL encrypted-key terminal prompt was not observed")
	}
	return err
}

func newSyntheticOpenSSLOwner(t *testing.T) syntheticOpenSSLOwner {
	t.Helper()
	executable := os.Getenv("CICADA_TEST_OWNER_OPENSSL")
	if executable == "" {
		t.Skip("set CICADA_TEST_OWNER_OPENSSL to independently verified OpenSSL 3.5.9")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command(executable, args...)
		cmd.Stdin = strings.NewReader(syntheticOpenSSLPassword)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("synthetic OpenSSL %s failed: %v", args[0], err)
		}
		return out
	}
	if !strings.Contains(string(run("version")), "OpenSSL 3.5.9 ") {
		t.Fatal("interop requires actual OpenSSL3.5.9")
	}
	for _, algorithm := range []string{"ML-KEM-768", "ML-DSA-65"} {
		private := filepath.Join(dir, algorithm+".pem")
		run("genpkey", "-algorithm", algorithm, "-aes-256-cbc", "-pass", "stdin", "-out", private)
		if err := os.Chmod(private, 0600); err != nil {
			t.Fatal(err)
		}
		run("pkey", "-in", private, "-passin", "stdin", "-pubout", "-out", filepath.Join(dir, algorithm+"-public.pem"))
	}
	f := syntheticOpenSSLOwner{dir: dir, executable: executable, signingPrivate: filepath.Join(dir, "ML-DSA-65.pem"), publicFile: filepath.Join(dir, "synthetic-owner-public.json")}
	if err := ownerKeyFromOpenSSLCommand([]string{"--kem-public", filepath.Join(dir, "ML-KEM-768-public.pem"), "--signing-public", filepath.Join(dir, "ML-DSA-65-public.pem"), "--output", f.publicFile}, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.publicFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &f.public); err != nil {
		t.Fatal(err)
	}
	if err := e2ee.ValidatePublicIdentity(f.public); err != nil {
		t.Fatal(err)
	}
	return f
}

func syntheticOpenSSLGrantArgs(t *testing.T, f syntheticOpenSSLOwner, ownerID, hubID, deviceID string, device e2ee.PublicIdentity, output string) []string {
	t.Helper()
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(device)
	if err != nil {
		t.Fatal(err)
	}
	manifest := ownerDeviceEnrollmentManifest{Format: ownerDeviceEnrollmentFormat, OwnerID: ownerID, OwnerKeyID: f.public.ID, HubID: hubID, DeviceID: deviceID, DeviceKeyFingerprint: fingerprint, Purpose: e2ee.OwnerDevicePurposeControl, DevicePublicIdentity: device}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestFile := output + ".manifest.json"
	if err := os.WriteFile(manifestFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	return []string{"--owner-public", f.publicFile, "--signing-private", f.signingPrivate, "--openssl", f.executable, "--manifest", manifestFile, "--output", output, "--expect-owner-id", ownerID, "--expect-owner-key-id", f.public.ID, "--expect-hub-id", hubID, "--expect-device-id", deviceID, "--expect-device-key-id", device.ID, "--expect-device-fingerprint", fingerprint, "--expires-at", time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)}
}

// The same external proof runs against either current production Core or an
// explicitly supplied owned, disposable real-TCP Docker Hub. No crypto bypass.
func TestOwnerDeviceOpenSSLActualCoreEnrollment(t *testing.T) {
	f := newSyntheticOpenSSLOwner(t)
	baseURL, dbPath := os.Getenv("CICADA_TEST_EXTERNAL_OWNER_HUB_URL"), os.Getenv("CICADA_TEST_EXTERNAL_OWNER_HUB_DB")
	var manager *control.Control
	if baseURL == "" {
		root := t.TempDir()
		var err error
		manager, err = control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "SYNTHETIC-EPHEMERAL-no-deployment"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := manager.Shutdown(ctx); err != nil {
				t.Error(err)
			}
		})
		hub := httptest.NewServer(server.NewHandler(manager))
		t.Cleanup(hub.Close)
		baseURL, dbPath = hub.URL, filepath.Join(root, "state", "cicada.sqlite3")
	} else if dbPath == "" || os.Getenv("CICADA_TEST_EXTERNAL_OWNER_DISPOSABLE") != "SYNTHETIC_OWNED_FIXTURE" {
		t.Fatal("external Hub requires explicit disposable fixture marker and owned DB")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	call := func(method, path string, body []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, baseURL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token := os.Getenv("CICADA_TEST_EXTERNAL_OWNER_HUB_TOKEN"); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 300*1024))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	ownerID := ""
	if manager != nil {
		ownerID = manager.Identity().ID
	} else {
		status, data := call(http.MethodGet, "/v1/identity", nil)
		var principal e2ee.PublicIdentity
		if status != 200 || json.Unmarshal(data, &principal) != nil || principal.ID == "" {
			t.Fatal("fresh Hub initial public principal unavailable")
		}
		ownerID = principal.ID
	}
	var identity struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	status, identityData := call(http.MethodGet, "/v2/client/identity", nil)
	if status != 200 || json.Unmarshal(identityData, &identity) != nil || identity.HubID == "" {
		t.Fatal("Hub public Client identity unavailable")
	}
	if err := ownerKeyLocalCommand([]string{"register", "--db", dbPath, "--owner-id", ownerID, "--public", f.publicFile, "--expect-key-id", f.public.ID}, io.Discard); err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	const deviceID = "synthetic-external-openssl-phone"
	grantFile := filepath.Join(f.dir, "synthetic-owner-grant.json")
	args := syntheticOpenSSLGrantArgs(t, f, ownerID, identity.HubID, deviceID, device.Public(), grantFile)
	if err := signSyntheticOwnerThroughPTY(t, args); err != nil {
		t.Fatal(err)
	}
	proof, err := os.ReadFile(grantFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2ee.VerifyOwnerDeviceGrant(proof, f.public, device.Public(), ownerID, f.public.ID, deviceID, identity.HubID, e2ee.OwnerDevicePurposeControl, time.Now()); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(grantFile); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("grant output must be private 0600")
	}
	enrollment := func(owner string, public e2ee.PublicIdentity, grant []byte) []byte {
		data, err := json.Marshal(map[string]any{"owner_id": owner, "owner_key_id": f.public.ID, "device_id": deviceID, "device_public_identity": public, "owner_device_grant": grant})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, refusal := range []struct {
		name, owner string
		public      e2ee.PublicIdentity
		proof       []byte
	}{
		{"WrongOwnerBinding", "synthetic-wrong-owner", device.Public(), proof},
		{"WrongDeviceKey", ownerID, f.public, proof},
	} {
		t.Run(refusal.name, func(t *testing.T) {
			status, _ := call(http.MethodPost, "/v2/client/devices/enroll", enrollment(refusal.owner, refusal.public, refusal.proof))
			if status != http.StatusForbidden {
				t.Fatalf("Guard refusal status=%d", status)
			}
		})
	}
	t.Run("ChangedGrantPayload", func(t *testing.T) {
		var grant e2ee.OwnerDeviceGrant
		if err := json.Unmarshal(proof, &grant); err != nil {
			t.Fatal(err)
		}
		grant.ExpiresAt = time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339Nano)
		changed, err := json.Marshal(grant)
		if err != nil {
			t.Fatal(err)
		}
		status, _ := call(http.MethodPost, "/v2/client/devices/enroll", enrollment(ownerID, device.Public(), changed))
		if status != http.StatusForbidden {
			t.Fatalf("changed grant status=%d", status)
		}
	})
	body := enrollment(ownerID, device.Public(), proof)
	status, enrolled := call(http.MethodPost, "/v2/client/devices/enroll", body)
	if status != http.StatusCreated {
		t.Fatalf("external OpenSSL enrollment status=%d", status)
	}
	status, retry := call(http.MethodPost, "/v2/client/devices/enroll", body)
	if status != http.StatusCreated || !bytes.Equal(enrolled, retry) {
		t.Fatal("exact 201 enrollment recovery differs from accepted binding")
	}
	var coordinates struct {
		SessionEpoch     uint64 `json:"session_epoch"`
		DeviceKeyVersion uint64 `json:"device_key_version"`
	}
	if err := json.Unmarshal(enrolled, &coordinates); err != nil || coordinates.SessionEpoch == 0 || coordinates.DeviceKeyVersion == 0 {
		t.Fatal("enrollment binding omitted")
	}
	binding := clientwire.Binding{HubID: identity.HubID, OwnerID: ownerID, DeviceID: deviceID, SessionEpoch: coordinates.SessionEpoch, HubKeyVersion: 1, DeviceKeyVersion: coordinates.DeviceKeyVersion}
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest, HubID: binding.HubID, OwnerID: ownerID, DeviceID: deviceID, SessionEpoch: binding.SessionEpoch, Sequence: 1, OperationID: "synthetic-openssl-snapshot-1", Operation: "status.snapshot", SenderKeyID: device.Public().ID, SenderKeyVersion: binding.DeviceKeyVersion, ReceiverKeyID: identity.ControlPublicIdentity.ID, ReceiverKeyVersion: 1}
	packet, err := clientwire.SealRequest(device, identity.ControlPublicIdentity, binding, route, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	status, sealed := call(http.MethodPost, "/v2/client/rpc", packet)
	if status != 200 {
		t.Fatalf("encrypted current Guard RPC status=%d", status)
	}
	opened, err := clientwire.OpenResponse(device, identity.ControlPublicIdentity, binding, sealed)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			OwnerID string `json:"owner_principal_id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(opened.Plaintext, &result); err != nil || !result.OK || result.Result.OwnerID != ownerID {
		t.Fatal("encrypted snapshot did not return current authorized owner")
	}
	status, recovered := call(http.MethodPost, "/v2/client/rpc/recover", packet)
	if status != 200 || !bytes.Equal(sealed, recovered) {
		t.Fatal("original encrypted request recovery changed response")
	}
	t.Log("actual external OpenSSL encrypted PKCS8 signing -> unchanged production Owner registration, enrollment Guard, exact201 recovery and encrypted RPC passed; native Windows and Android remain NOT_RUN")
}
