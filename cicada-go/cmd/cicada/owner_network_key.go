package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

const ownerNetworkKeyUsage = "usage: cicada owner network-key-sign --private FILE --manifest FILE --output FILE --expect-owner-id ID --expect-hub-id ID --expect-network-id ID --expect-endpoint-id ID --expect-native-session-digest SHA256 --expires-at RFC3339"

// ownerNetworkKeySignCommand signs only a fully verified, reviewed public
// manifest. A Hub supplied digest by itself is never sufficient authority.
func ownerNetworkKeySignCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("owner network-key-sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privatePath := flags.String("private", "", "existing private Owner identity")
	manifestPath := flags.String("manifest", "", "reviewed Network key manifest")
	outputPath := flags.String("output", "", "new private proof file")
	expectOwner := flags.String("expect-owner-id", "", "reviewed Owner ID")
	expectHub := flags.String("expect-hub-id", "", "pinned Hub ID")
	expectNetwork := flags.String("expect-network-id", "", "reviewed Network ID")
	expectEndpoint := flags.String("expect-endpoint-id", "", "reviewed Endpoint ID")
	expectNativeDigest := flags.String("expect-native-session-digest", "", "independently checked native Thread digest")
	expiresRaw := flags.String("expires-at", "", "UTC proof expiry")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || output == nil ||
		*privatePath == "" || *manifestPath == "" || *outputPath == "" ||
		*expectOwner == "" || *expectHub == "" || *expectNetwork == "" ||
		*expectEndpoint == "" || *expectNativeDigest == "" || *expiresRaw == "" {
		return errors.New(ownerNetworkKeyUsage)
	}
	private, err := readOwnerNetworkKeyFile(*privatePath, 32768, true)
	if err != nil {
		return err
	}
	identity, err := e2ee.UnmarshalIdentity(private)
	if err != nil {
		return errors.New("Owner private key is invalid")
	}
	data, err := readOwnerNetworkKeyFile(*manifestPath, 65536, false)
	if err != nil {
		return err
	}
	var manifest store.NetworkDirectKeyManifest
	if err := decodeStrictBridgeJSON(data, &manifest); err != nil {
		return errors.New("Network key manifest JSON is invalid")
	}
	if err := verifyOwnerNetworkKeyManifest(manifest, identity.Public().ID,
		strings.TrimSpace(*expectOwner), strings.TrimSpace(*expectHub),
		strings.TrimSpace(*expectNetwork), strings.TrimSpace(*expectEndpoint),
		strings.TrimSpace(*expectNativeDigest)); err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339Nano, *expiresRaw)
	if err != nil {
		return errors.New("proof expiry must be RFC3339")
	}
	issued := time.Now().UTC()
	if !expires.After(issued) || expires.After(issued.Add(24*time.Hour)) {
		return errors.New("proof expiry must be within 24 hours")
	}
	proof, err := identity.SignOwnerNetworkDirectKeyGrant(manifest.HubID, manifest.NetworkID,
		manifest.EndpointID, manifest.OwnerID, manifest.Digest, issued, expires)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(struct {
		SignedProof string `json:"signed_proof"`
	}{base64.StdEncoding.EncodeToString(proof)})
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create proof file without overwrite: %w", err)
	}
	if _, err = file.Write(append(encoded, '\n')); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(*outputPath)
		return errors.New("could not persist Owner proof")
	}
	return json.NewEncoder(output).Encode(struct {
		HubID          string `json:"hub_id"`
		NetworkID      string `json:"network_id"`
		EndpointID     string `json:"endpoint_id"`
		OwnerID        string `json:"owner_id"`
		OwnerKeyID     string `json:"owner_key_id"`
		ManifestDigest string `json:"manifest_digest"`
		IssuedAt       string `json:"issued_at"`
		ExpiresAt      string `json:"expires_at"`
		ProofFile      string `json:"proof_file"`
	}{manifest.HubID, manifest.NetworkID, manifest.EndpointID, manifest.OwnerID,
		identity.Public().ID, manifest.Digest, issued.Format(time.RFC3339Nano),
		expires.UTC().Format(time.RFC3339Nano), *outputPath})
}

func readOwnerNetworkKeyFile(path string, max int64, secret bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > max ||
		(secret && info.Mode().Perm() != 0o600) {
		return nil, errors.New("Owner key or manifest must be a bounded regular file with private key mode 0600")
	}
	return os.ReadFile(path)
}

func verifyOwnerNetworkKeyManifest(manifest store.NetworkDirectKeyManifest, ownerKeyID,
	ownerID, hubID, networkID, endpointID, nativeDigest string) error {
	if manifest.Version != 1 || manifest.HubID != hubID || manifest.NetworkID != networkID ||
		manifest.EndpointID != endpointID || manifest.OwnerID != ownerID ||
		manifest.Candidate.OwnerID != ownerID || manifest.Candidate.NetworkID != networkID ||
		manifest.Candidate.EndpointID != endpointID || manifest.Candidate.PrincipalID != manifest.PrincipalID ||
		manifest.Candidate.NodeID != manifest.NodeID || manifest.Candidate.BindingID != manifest.BindingID ||
		manifest.Candidate.BindingEpoch != manifest.BindingEpoch || manifest.Candidate.Version <= 0 ||
		manifest.BindingEpoch == 0 || manifest.MembershipRevision <= 0 ||
		manifest.EndpointEnrollmentRevision <= 0 || ownerKeyID == "" ||
		manifest.NativeSessionID == "" || manifest.NativeSessionDigest != nativeDigest ||
		e2ee.NetworkDirectNativeSessionDigest(manifest.NativeSessionID) != nativeDigest {
		return errors.New("Network key manifest scope or native Thread digest differs from reviewed values")
	}
	public, err := e2ee.VerifyNetworkDirectKeyAttestation(manifest.Candidate.Attestation,
		e2ee.NetworkDirectKeyAttestation{HubID: hubID, NetworkID: networkID,
			EndpointID: endpointID, PrincipalID: manifest.PrincipalID,
			NodeID: manifest.NodeID, BindingID: manifest.BindingID,
			BindingEpoch: manifest.BindingEpoch})
	if err != nil || !reflect.DeepEqual(public, manifest.Candidate.Public) {
		return errors.New("Network key candidate self-attestation is invalid")
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(public)
	if err != nil || fingerprint != manifest.Candidate.Fingerprint {
		return errors.New("Network key candidate fingerprint is invalid")
	}
	digest, err := manifest.CanonicalDigest()
	if err != nil || digest != manifest.Digest {
		return errors.New("Network key manifest canonical digest is invalid")
	}
	return nil
}
