package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

const ownerNetworkCollaborationSignUsage = "usage: cicada owner network-collaboration-key-sign --private FILE --manifest FILE --output FILE --expect-owner-id ID --expect-owner-key-id KEY_ID --expect-hub-id ID --expect-network-id ID --expect-endpoint-id ID --expect-native-session-digest SHA256 --purpose TASK|BROADCAST --expires-at UTC_RFC3339Nano"

// ownerNetworkCollaborationKeySignCommand signs an independently reviewed
// purpose-specific manifest offline. It never submits the proof or enrolls
// the Endpoint, and it refuses an output path that already exists.
func ownerNetworkCollaborationKeySignCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("owner network-collaboration-key-sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privatePath := flags.String("private", "", "existing 0600 Owner identity file")
	manifestPath := flags.String("manifest", "", "encrypted-RPC Network collaboration manifest saved by the Client")
	outputPath := flags.String("output", "", "new 0600 Owner proof wrapper for explicit Client submission")
	expectOwner := flags.String("expect-owner-id", "", "independently verified Owner ID")
	expectOwnerKey := flags.String("expect-owner-key-id", "", "independently verified Owner key ID")
	expectHub := flags.String("expect-hub-id", "", "Hub ID pinned out of band")
	expectNetwork := flags.String("expect-network-id", "", "reviewed Network ID")
	expectEndpoint := flags.String("expect-endpoint-id", "", "reviewed Endpoint ID")
	expectNativeDigest := flags.String("expect-native-session-digest", "", "independently reviewed native Thread digest")
	purpose := flags.String("purpose", "", "exact consent purpose: TASK or BROADCAST")
	expiresRaw := flags.String("expires-at", "", "canonical UTC RFC3339Nano proof expiry within 24 hours")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || output == nil ||
		*privatePath == "" || *manifestPath == "" || *outputPath == "" || *expectOwner == "" ||
		*expectOwnerKey == "" || *expectHub == "" || *expectNetwork == "" || *expectEndpoint == "" ||
		*expectNativeDigest == "" || *expiresRaw == "" ||
		(*purpose != e2ee.NetworkCollaborationPurposeTask && *purpose != e2ee.NetworkCollaborationPurposeBroadcast) {
		return errors.New(ownerNetworkCollaborationSignUsage)
	}
	ownerID, ownerKeyID := strings.TrimSpace(*expectOwner), strings.TrimSpace(*expectOwnerKey)
	hubID, networkID, endpointID := strings.TrimSpace(*expectHub), strings.TrimSpace(*expectNetwork), strings.TrimSpace(*expectEndpoint)
	nativeDigest := strings.TrimSpace(*expectNativeDigest)
	private, err := readOwnerNetworkKeyFile(*privatePath, 32768, true)
	if err != nil {
		return err
	}
	identity, err := e2ee.UnmarshalIdentity(private)
	if err != nil || identity.Public().ID != ownerKeyID {
		return errors.New("Owner private identity differs from the independently reviewed key ID")
	}
	data, err := readOwnerNetworkKeyFile(*manifestPath, 64*1024, false)
	if err != nil {
		return err
	}
	var manifest store.NetworkCollaborationKeyManifest
	if err := decodeStrictBridgeJSON(data, &manifest); err != nil {
		return errors.New("Network collaboration manifest JSON is invalid")
	}
	if manifest.Purpose != *purpose {
		return errors.New("manifest purpose differs from the separately reviewed consent purpose")
	}
	if err := verifyOwnerNetworkKeyManifest(manifest.Key, ownerKeyID, ownerID, hubID,
		networkID, endpointID, nativeDigest); err != nil {
		return fmt.Errorf("verify full Network key manifest: %w", err)
	}
	claims, err := manifest.Key.CanonicalClaims()
	if err != nil || manifest.Digest != e2ee.NetworkCollaborationManifestDigest(manifest.Purpose, claims) {
		return errors.New("purpose-separated collaboration manifest digest is invalid")
	}
	expiresText := strings.TrimSpace(*expiresRaw)
	expires, err := time.Parse(time.RFC3339Nano, expiresText)
	if err != nil || expires.UTC().Format(time.RFC3339Nano) != expiresText {
		return errors.New("proof expiry must be canonical UTC RFC3339Nano")
	}
	issued := time.Now().UTC()
	if !expires.After(issued) || expires.After(issued.Add(24*time.Hour)) {
		return errors.New("proof expiry must be in the future and within 24 hours")
	}
	proof, err := identity.SignOwnerNetworkCollaborationKeyGrant(manifest.Purpose, hubID,
		networkID, endpointID, ownerID, manifest.Digest, issued, expires)
	if err != nil {
		return fmt.Errorf("sign purpose-specific Owner proof: %w", err)
	}
	encoded, err := json.Marshal(struct {
		SignedProof string `json:"signed_proof"`
	}{base64.StdEncoding.EncodeToString(proof)})
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create Owner proof without overwrite: %w", err)
	}
	if _, err = file.Write(append(encoded, '\n')); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(*outputPath)
		return errors.New("could not persist Owner purpose proof")
	}
	return json.NewEncoder(output).Encode(struct {
		Purpose        string `json:"purpose"`
		HubID          string `json:"hub_id"`
		NetworkID      string `json:"network_id"`
		EndpointID     string `json:"endpoint_id"`
		OwnerID        string `json:"owner_id"`
		OwnerKeyID     string `json:"owner_key_id"`
		ManifestDigest string `json:"manifest_digest"`
		IssuedAt       string `json:"issued_at"`
		ExpiresAt      string `json:"expires_at"`
		ProofFile      string `json:"proof_file"`
	}{manifest.Purpose, hubID, networkID, endpointID, ownerID, ownerKeyID,
		manifest.Digest, issued.Format(time.RFC3339Nano), expiresText, *outputPath})
}
