package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const ownerDeviceGrantSignUsage = "usage: cicada owner device-grant-sign --private FILE --manifest FILE --output FILE --expect-owner-id ID --expect-owner-key-id KEY_ID --expect-hub-id HUB_ID --expect-device-id DEVICE_ID --expect-device-key-id KEY_ID --expect-device-fingerprint SHA256 --expires-at UTC_RFC3339"

const ownerDeviceEnrollmentFormat = "cicada.owner-device-enrollment.v1"

type ownerDeviceEnrollmentManifest struct {
	Format               string              `json:"format"`
	HubID                string              `json:"hub_id"`
	OwnerID              string              `json:"owner_id"`
	OwnerKeyID           string              `json:"owner_key_id"`
	DeviceID             string              `json:"device_id"`
	DeviceKeyFingerprint string              `json:"device_key_fingerprint"`
	Purpose              string              `json:"purpose"`
	DevicePublicIdentity e2ee.PublicIdentity `json:"device_public_identity"`
}

// ownerDeviceGrantSignCommand signs one browser-generated public device key
// for one independently pinned Hub. It never enrolls the key or sends the
// private Owner identity outside this offline process.
func ownerDeviceGrantSignCommand(args []string, output io.Writer) error {
	if output == nil {
		return errors.New(ownerDeviceGrantSignUsage)
	}
	flags := flag.NewFlagSet("owner device-grant-sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privatePath := flags.String("private", "", "existing 0600 Owner identity file")
	manifestPath := flags.String("manifest", "", "browser-generated public device enrollment manifest")
	outputPath := flags.String("output", "", "new 0600 Owner-signed device grant file")
	expectOwner := flags.String("expect-owner-id", "", "independently reviewed Owner ID")
	expectOwnerKey := flags.String("expect-owner-key-id", "", "independently reviewed Owner public key ID")
	expectHub := flags.String("expect-hub-id", "", "Hub ID pinned out of band")
	expectDevice := flags.String("expect-device-id", "", "device ID shown by the browser")
	expectDeviceKey := flags.String("expect-device-key-id", "", "device public key ID shown by the browser")
	expectFingerprint := flags.String("expect-device-fingerprint", "", "full SHA-256 public identity fingerprint shown by the browser")
	expiresRaw := flags.String("expires-at", "", "explicit UTC RFC3339 expiry, no more than 24 hours away")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 ||
		*privatePath == "" || *manifestPath == "" || *outputPath == "" ||
		*expectOwner == "" || *expectOwnerKey == "" || *expectHub == "" ||
		*expectDevice == "" || *expectDeviceKey == "" || *expectFingerprint == "" || *expiresRaw == "" {
		return errors.New(ownerDeviceGrantSignUsage)
	}
	private, err := readOwnerNetworkKeyFile(*privatePath, 32768, true)
	if err != nil {
		return err
	}
	owner, err := e2ee.UnmarshalIdentity(private)
	if err != nil {
		return errors.New("Owner private identity is invalid")
	}
	if owner.Public().ID != strings.TrimSpace(*expectOwnerKey) {
		return errors.New("Owner private identity differs from the independently verified Owner key ID")
	}
	manifestBytes, err := readOwnerNetworkKeyFile(*manifestPath, 64*1024, false)
	if err != nil {
		return err
	}
	var manifest ownerDeviceEnrollmentManifest
	if err := decodeStrictBridgeJSON(manifestBytes, &manifest); err != nil {
		return errors.New("device enrollment manifest is invalid")
	}
	ownerID := strings.TrimSpace(*expectOwner)
	hubID := strings.TrimSpace(*expectHub)
	deviceID := strings.TrimSpace(*expectDevice)
	if manifest.Format != ownerDeviceEnrollmentFormat || manifest.Purpose != e2ee.OwnerDevicePurposeControl ||
		manifest.OwnerID != ownerID || manifest.OwnerKeyID != owner.Public().ID ||
		manifest.HubID != hubID || manifest.DeviceID != deviceID ||
		manifest.DevicePublicIdentity.ID != strings.TrimSpace(*expectDeviceKey) {
		return errors.New("device enrollment manifest differs from the reviewed Owner, Hub, purpose, or device identity")
	}
	if err := e2ee.ValidatePublicIdentity(manifest.DevicePublicIdentity); err != nil {
		return errors.New("device public identity is invalid")
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(manifest.DevicePublicIdentity)
	if err != nil || fingerprint != manifest.DeviceKeyFingerprint || fingerprint != strings.TrimSpace(*expectFingerprint) {
		return errors.New("device public identity fingerprint differs from the reviewed fingerprint")
	}
	expires, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(*expiresRaw))
	if err != nil || expires.UTC().Format(time.RFC3339Nano) != strings.TrimSpace(*expiresRaw) {
		return errors.New("grant expiry must be canonical UTC RFC3339Nano")
	}
	issued := time.Now().UTC()
	if !expires.After(issued) || expires.After(issued.Add(24*time.Hour)) {
		return errors.New("grant expiry must be in the future and within 24 hours")
	}
	proof, err := owner.SignOwnerDeviceGrant(ownerID, deviceID, manifest.DevicePublicIdentity,
		hubID, e2ee.OwnerDevicePurposeControl, issued, expires)
	if err != nil {
		return fmt.Errorf("sign exact Client device grant: %w", err)
	}
	file, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create Owner grant without overwrite: %w", err)
	}
	// Keep the grant byte-for-byte canonical: the Hub verifies the exact signed
	// proof bytes, so a trailing newline would change the signed representation.
	if _, err = file.Write(proof); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(*outputPath)
		return errors.New("could not persist Owner-signed device grant")
	}
	return json.NewEncoder(output).Encode(struct {
		Format               string              `json:"format"`
		OwnerID              string              `json:"owner_id"`
		OwnerKeyID           string              `json:"owner_key_id"`
		OwnerPublicIdentity  e2ee.PublicIdentity `json:"owner_public_identity"`
		HubID                string              `json:"hub_id"`
		DeviceID             string              `json:"device_id"`
		DeviceKeyID          string              `json:"device_key_id"`
		DeviceKeyFingerprint string              `json:"device_key_fingerprint"`
		Purpose              string              `json:"purpose"`
		IssuedAt             string              `json:"issued_at"`
		ExpiresAt            string              `json:"expires_at"`
		GrantFile            string              `json:"grant_file"`
	}{ownerDeviceEnrollmentFormat, ownerID, owner.Public().ID, owner.Public(), hubID, deviceID,
		manifest.DevicePublicIdentity.ID, fingerprint, e2ee.OwnerDevicePurposeControl,
		issued.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano), *outputPath})
}
