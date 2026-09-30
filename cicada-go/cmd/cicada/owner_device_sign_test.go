package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestOwnerDeviceGrantSignUsesExactPublicEnrollmentAndPrivateOutput(t *testing.T) {
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(device.Public())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	privatePath := filepath.Join(root, "owner-private.bin")
	privateBytes, err := owner.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privatePath, privateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "device.json")
	manifest := ownerDeviceEnrollmentManifest{
		Format: ownerDeviceEnrollmentFormat, HubID: "hub-pinned-synthetic", OwnerID: "owner-synthetic",
		OwnerKeyID: owner.Public().ID, DeviceID: "browser-synthetic", DeviceKeyFingerprint: fingerprint,
		Purpose: e2ee.OwnerDevicePurposeControl, DevicePublicIdentity: device.Public(),
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	grantPath := filepath.Join(root, "owner-device-grant.json")
	args := ownerDeviceSignTestArgs(privatePath, manifestPath, grantPath, owner.Public().ID,
		device.Public().ID, fingerprint, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	var summary bytes.Buffer
	if err := ownerDeviceGrantSignCommand(args, &summary); err != nil {
		t.Fatalf("sign exact grant: %v", err)
	}
	info, err := os.Stat(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("grant mode=%o, want 0600", info.Mode().Perm())
	}
	grantBytes, err := os.ReadFile(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(grantBytes, privateBytes) || bytes.Contains(summary.Bytes(), privateBytes) {
		t.Fatal("private Owner identity appeared in grant output")
	}
	var grant e2ee.OwnerDeviceGrant
	if err := json.Unmarshal(grantBytes, &grant); err != nil {
		t.Fatal(err)
	}
	if _, err := e2ee.VerifyOwnerDeviceGrant(grantBytes, owner.Public(), device.Public(),
		"owner-synthetic", owner.Public().ID, "browser-synthetic", "hub-pinned-synthetic",
		e2ee.OwnerDevicePurposeControl, time.Now().UTC()); err != nil {
		t.Fatalf("verify emitted exact grant: %v", err)
	}
	if grant.DeviceKeyFingerprint != fingerprint || grant.DeviceKeyID != device.Public().ID {
		t.Fatal("grant does not bind the reviewed browser public identity")
	}
	var grantSummary struct {
		OwnerPublicIdentity e2ee.PublicIdentity `json:"owner_public_identity"`
	}
	if err := json.Unmarshal(summary.Bytes(), &grantSummary); err != nil {
		t.Fatal("signer summary must provide only the public Owner identity for local grant verification")
	}
	if grantSummary.OwnerPublicIdentity.ID != owner.Public().ID {
		t.Fatal("signer summary Owner public identity differs from the existing private signer")
	}
	before := append([]byte(nil), grantBytes...)
	if err := ownerDeviceGrantSignCommand(args, &summary); err == nil {
		t.Fatal("existing grant output was overwritten")
	}
	after, err := os.ReadFile(grantPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed retry changed the existing grant file")
	}
}

func TestOwnerDeviceGrantSignRejectsScopeFingerprintExpiryAndLooseKey(t *testing.T) {
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(device.Public())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	privatePath := filepath.Join(root, "owner-private.bin")
	privateBytes, _ := owner.MarshalBinary()
	if err := os.WriteFile(privatePath, privateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "device.json")
	manifest := ownerDeviceEnrollmentManifest{Format: ownerDeviceEnrollmentFormat,
		HubID: "hub-pinned-synthetic", OwnerID: "owner-synthetic", OwnerKeyID: owner.Public().ID,
		DeviceID: "browser-synthetic", DeviceKeyFingerprint: fingerprint,
		Purpose: e2ee.OwnerDevicePurposeControl, DevicePublicIdentity: device.Public()}
	writeManifest := func() {
		t.Helper()
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeManifest()
	validExpiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	base := ownerDeviceSignTestArgs(privatePath, manifestPath, filepath.Join(root, "grant.json"),
		owner.Public().ID, device.Public().ID, fingerprint, validExpiry)
	for name, mutate := range map[string]func([]string){
		"wrong expected hub":       func(args []string) { replaceArg(args, "--expect-hub-id", "other-hub") },
		"wrong public fingerprint": func(args []string) { replaceArg(args, "--expect-device-fingerprint", strings.Repeat("0", 64)) },
		"expiry beyond 24 hours": func(args []string) {
			replaceArg(args, "--expires-at", time.Now().UTC().Add(25*time.Hour).Format(time.RFC3339Nano))
		},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string(nil), base...)
			mutate(args)
			var summary bytes.Buffer
			if err := ownerDeviceGrantSignCommand(args, &summary); err == nil {
				t.Fatal("out-of-scope Owner grant was accepted")
			}
		})
	}
	manifest.HubID = "different-hub"
	writeManifest()
	var summary bytes.Buffer
	if err := ownerDeviceGrantSignCommand(base, &summary); err == nil {
		t.Fatal("manifest Hub mismatch was accepted")
	}
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ownerDeviceGrantSignCommand(base, &summary); err == nil {
		t.Fatal("Owner private key with loose permissions was accepted")
	}
}

func ownerDeviceSignTestArgs(privatePath, manifestPath, outputPath, ownerKeyID, deviceKeyID, fingerprint, expires string) []string {
	return []string{"--private", privatePath, "--manifest", manifestPath, "--output", outputPath,
		"--expect-owner-id", "owner-synthetic", "--expect-owner-key-id", ownerKeyID,
		"--expect-hub-id", "hub-pinned-synthetic", "--expect-device-id", "browser-synthetic",
		"--expect-device-key-id", deviceKeyID, "--expect-device-fingerprint", fingerprint,
		"--expires-at", expires}
}

func replaceArg(args []string, key, value string) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key {
			args[i+1] = value
			return
		}
	}
}
