package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const ownerDeviceEnrollmentPrepareUsage = "usage: cicada owner device-enrollment-prepare --device-public JSON --owner-public JSON --owner-id ID --hub-id PINNED_ID --device-id ID --output NEW_MANIFEST"
const ownerDeviceGrantSignOpenSSLUsage = "usage: cicada owner device-grant-sign-openssl --owner-public JSON --signing-private ENCRYPTED_PEM --openssl ABSOLUTE_EXE --manifest FILE --output NEW_GRANT --expect-owner-id ID --expect-owner-key-id ID --expect-hub-id ID --expect-device-id ID --expect-device-key-id ID --expect-device-fingerprint SHA256 --expires-at UTC_RFC3339"

// The Android Client can copy a bare device PublicIdentity. Preparation wraps
// that public JSON with metadata obtained independently by the user and displays
// the full fingerprint. It neither signs nor enrolls anything.
func ownerDeviceEnrollmentPrepareCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("owner device-enrollment-prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	devicePath := flags.String("device-public", "", "bare public JSON copied from the device")
	ownerPath := flags.String("owner-public", "", "existing Owner public identity JSON")
	ownerID := flags.String("owner-id", "", "independently reviewed Owner ID")
	hubID := flags.String("hub-id", "", "Hub ID pinned out of band")
	deviceID := flags.String("device-id", "", "device ID displayed by the Client")
	outputPath := flags.String("output", "", "new public enrollment manifest")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 || output == nil ||
		*devicePath == "" || *ownerPath == "" || *ownerID == "" || *hubID == "" || *deviceID == "" || *outputPath == "" {
		return errors.New(ownerDeviceEnrollmentPrepareUsage)
	}
	owner, err := readOfflineOwnerIdentity(*ownerPath)
	if err != nil {
		return err
	}
	device, err := readOfflineOwnerIdentity(*devicePath)
	if err != nil {
		return err
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(device)
	if err != nil {
		return err
	}
	manifest := ownerDeviceEnrollmentManifest{
		Format: ownerDeviceEnrollmentFormat, HubID: *hubID, OwnerID: *ownerID,
		OwnerKeyID: owner.ID, DeviceID: *deviceID, DeviceKeyFingerprint: fingerprint,
		Purpose: e2ee.OwnerDevicePurposeControl, DevicePublicIdentity: device,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if len(data) > 64*1024 {
		return errors.New("device enrollment manifest is too large")
	}
	if err := writeOfflineOwnerFile(*outputPath, data, 0o644); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(manifest)
}

func ownerDeviceGrantSignOpenSSLCommand(args []string, output io.Writer) error {
	return ownerDeviceGrantSignOpenSSL(args, output, signOfflineOwnerWithOpenSSL)
}

func ownerDeviceGrantSignOpenSSL(args []string, output io.Writer,
	sign func(executable, privatePath string, message []byte) ([]byte, error)) error {
	flags := flag.NewFlagSet("owner device-grant-sign-openssl", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	ownerPath := flags.String("owner-public", "", "existing Owner public identity JSON")
	privatePath := flags.String("signing-private", "", "user-held encrypted ML-DSA-65 PKCS#8 PEM, opened only by OpenSSL")
	executable := flags.String("openssl", "", "absolute path to user-installed OpenSSL 3.5 or newer")
	manifestPath := flags.String("manifest", "", "public device enrollment manifest")
	outputPath := flags.String("output", "", "new Owner-signed grant file")
	expectOwner := flags.String("expect-owner-id", "", "independently reviewed Owner ID")
	expectOwnerKey := flags.String("expect-owner-key-id", "", "independently reviewed Owner public key ID")
	expectHub := flags.String("expect-hub-id", "", "Hub ID pinned out of band")
	expectDevice := flags.String("expect-device-id", "", "device ID displayed by the Client")
	expectDeviceKey := flags.String("expect-device-key-id", "", "independently reviewed device public key ID")
	expectFingerprint := flags.String("expect-device-fingerprint", "", "full independently reviewed SHA-256 device fingerprint")
	expiresRaw := flags.String("expires-at", "", "explicit canonical UTC expiry within 24 hours")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 || output == nil || sign == nil ||
		*ownerPath == "" || *privatePath == "" || !filepath.IsAbs(*executable) || *manifestPath == "" || *outputPath == "" ||
		*expectOwner == "" || *expectOwnerKey == "" || *expectHub == "" || *expectDevice == "" ||
		*expectDeviceKey == "" || *expectFingerprint == "" || *expiresRaw == "" {
		return errors.New(ownerDeviceGrantSignOpenSSLUsage)
	}
	// Refuse existing output before invoking a signer or prompting for a password.
	if _, err := os.Lstat(*outputPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("grant output must be a new file")
	}
	owner, err := readOfflineOwnerIdentity(*ownerPath)
	if err != nil {
		return err
	}
	if owner.ID != strings.TrimSpace(*expectOwnerKey) {
		return errors.New("Owner public key differs from the independently reviewed key ID")
	}
	data, err := readOfflineOwnerPublicFile(*manifestPath, 64*1024)
	if err != nil {
		return err
	}
	var manifest ownerDeviceEnrollmentManifest
	if err := decodeStrictBridgeJSON(data, &manifest); err != nil {
		return errors.New("device enrollment manifest is invalid")
	}
	ownerID, hubID, deviceID := strings.TrimSpace(*expectOwner), strings.TrimSpace(*expectHub), strings.TrimSpace(*expectDevice)
	if manifest.Format != ownerDeviceEnrollmentFormat || manifest.Purpose != e2ee.OwnerDevicePurposeControl ||
		manifest.OwnerID != ownerID || manifest.OwnerKeyID != owner.ID || manifest.HubID != hubID ||
		manifest.DeviceID != deviceID || manifest.DevicePublicIdentity.ID != strings.TrimSpace(*expectDeviceKey) {
		return errors.New("device enrollment manifest differs from the reviewed Owner, Hub, purpose, or device identity")
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(manifest.DevicePublicIdentity)
	if err != nil || fingerprint != manifest.DeviceKeyFingerprint || fingerprint != strings.TrimSpace(*expectFingerprint) {
		return errors.New("device public identity fingerprint differs from the reviewed fingerprint")
	}
	expires, err := time.Parse(time.RFC3339Nano, *expiresRaw)
	if err != nil || expires.UTC().Format(time.RFC3339Nano) != *expiresRaw {
		return errors.New("grant expiry must be canonical UTC RFC3339Nano")
	}
	issued := time.Now().UTC()
	if !expires.After(issued) || expires.After(issued.Add(24*time.Hour)) {
		return errors.New("grant expiry must be in the future and within 24 hours")
	}
	// Public metadata only. The explicit expected flags are the prior review;
	// this display does not turn untrusted Hub discovery into authorization.
	review := struct {
		OwnerID           string `json:"owner_id"`
		OwnerKeyID        string `json:"owner_key_id"`
		HubID             string `json:"hub_id"`
		DeviceID          string `json:"device_id"`
		DeviceKeyID       string `json:"device_key_id"`
		DeviceFingerprint string `json:"device_key_fingerprint"`
		Purpose           string `json:"purpose"`
		ExpiresAt         string `json:"expires_at"`
	}{ownerID, owner.ID, hubID, deviceID, manifest.DevicePublicIdentity.ID, fingerprint,
		e2ee.OwnerDevicePurposeControl, *expiresRaw}
	proof, err := e2ee.SignOwnerDeviceGrantWithSigner(owner, ownerID, deviceID, manifest.DevicePublicIdentity,
		hubID, e2ee.OwnerDevicePurposeControl, issued, expires, func(message []byte) ([]byte, error) {
			if err := json.NewEncoder(os.Stderr).Encode(review); err != nil {
				return nil, err
			}
			return sign(*executable, *privatePath, message)
		})
	if err != nil {
		return fmt.Errorf("sign exact Client device grant: %w", err)
	}
	// An interactive prompt can take time; do not publish an already expired proof.
	if _, err := e2ee.VerifyOwnerDeviceGrant(proof, owner, manifest.DevicePublicIdentity,
		ownerID, owner.ID, deviceID, hubID, e2ee.OwnerDevicePurposeControl, time.Now().UTC()); err != nil {
		return errors.New("signed device grant failed current enrollment verification")
	}
	if err := writeOfflineOwnerFile(*outputPath, proof, 0o600); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		OwnerPublicIdentity e2ee.PublicIdentity `json:"owner_public_identity"`
		GrantFile           string              `json:"grant_file"`
	}{owner, *outputPath})
}

func signOfflineOwnerWithOpenSSL(executable, privatePath string, message []byte) ([]byte, error) {
	if !filepath.IsAbs(executable) || len(message) == 0 || len(message) > 16*1024 {
		return nil, errors.New("OpenSSL requires an absolute executable and bounded signing claims")
	}
	privateAbs, err := filepath.Abs(privatePath)
	if err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp("", "cicada-owner-sign-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(directory) // Remove only this process's own empty directory.
	claimsPath, signaturePath := filepath.Join(directory, "claims"), filepath.Join(directory, "signature")
	defer os.Remove(claimsPath)
	defer os.Remove(signaturePath)
	if err := writeOfflineOwnerFile(claimsPath, message, 0o600); err != nil {
		return nil, err
	}
	if err := writeOfflineOwnerFile(signaturePath, nil, 0o600); err != nil {
		return nil, err
	}
	// No shell and no passphrase argument, environment variable, logger, pipe or
	// private-key reader. OpenSSL owns password entry through the child terminal.
	// Unix file modes protect these temporary public claims/signature files;
	// on Windows they inherit the user's temporary-directory ACL. No ACL claim
	// or Unix 0600 validation is made for the user's external private PEM.
	command := exec.Command(executable, "pkeyutl", "-sign", "-rawin", "-inkey", privateAbs,
		"-in", claimsPath, "-out", signaturePath)
	command.Stdin, command.Stderr, command.Stdout = os.Stdin, os.Stderr, io.Discard
	if err := command.Run(); err != nil {
		return nil, errors.New("OpenSSL signing failed; no grant was written")
	}
	signature, err := readOfflineOwnerPublicFile(signaturePath, int64(mldsa65.SignatureSize))
	if err != nil || len(signature) != mldsa65.SignatureSize {
		return nil, errors.New("OpenSSL did not produce an ML-DSA-65 signature")
	}
	return signature, nil
}
