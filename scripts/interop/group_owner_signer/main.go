// Command group_owner_signer is a development-only, external owner signer.
// It is intentionally kept outside the Android APK and uses CICADA's pinned
// e2ee implementation rather than a second ML-DSA implementation.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	groupKeyGrantOperation = "group-endpoint-key-grant:v1"
	groupBindingDomain     = "cicada/group/endpoint-key-binding/v1\x00"
	groupManifestDomain    = "cicada/group/endpoint-key-grant-manifest/v1\x00"
	peerFingerprintDomain  = "cicada/nodekeys/peer-key-fingerprint/v1\x00"
	maxPrivateIdentity     = 16 * 1024
	maxPublicIdentity      = 32 * 1024
	maxManifest            = 64 * 1024
)

type groupManifest struct {
	Version                 int                 `json:"version"`
	Operation               string              `json:"operation"`
	HubID                   string              `json:"hub_id"`
	OwnerID                 string              `json:"owner_id"`
	PrincipalID             string              `json:"principal_id"`
	GroupID                 string              `json:"group_id"`
	GroupRevision           int64               `json:"group_revision"`
	EndpointID              string              `json:"endpoint_id"`
	NodeID                  string              `json:"node_id"`
	BindingID               string              `json:"binding_id"`
	BindingEpoch            uint64              `json:"binding_epoch"`
	MembershipRevision      int64               `json:"membership_revision"`
	EndpointJoinRevision    int64               `json:"endpoint_join_revision"`
	CandidateVersion        int64               `json:"candidate_version"`
	CandidateKeyID          string              `json:"candidate_key_id"`
	CandidateFingerprint    string              `json:"candidate_fingerprint"`
	CandidateProofDigest    string              `json:"candidate_proof_digest"`
	CandidateBindingDigest  string              `json:"candidate_binding_digest"`
	CandidatePublicIdentity e2ee.PublicIdentity `json:"candidate_public_identity"`
	CandidateAttestation    []byte              `json:"candidate_attestation"`
	OwnerKeyID              string              `json:"owner_key_id"`
	IssuedAt                string              `json:"issued_at"`
	ExpiresAt               string              `json:"expires_at"`
	Digest                  string              `json:"digest"`
}

// These claims structs intentionally mirror the ordered v1.2.1 Store DTOs.
// encoding/json's struct field order is part of the domain-separated digest.
type groupManifestClaims struct {
	Version                 int                 `json:"version"`
	Operation               string              `json:"operation"`
	HubID                   string              `json:"hub_id"`
	OwnerID                 string              `json:"owner_id"`
	PrincipalID             string              `json:"principal_id"`
	GroupID                 string              `json:"group_id"`
	GroupRevision           int64               `json:"group_revision"`
	EndpointID              string              `json:"endpoint_id"`
	NodeID                  string              `json:"node_id"`
	BindingID               string              `json:"binding_id"`
	BindingEpoch            uint64              `json:"binding_epoch"`
	MembershipRevision      int64               `json:"membership_revision"`
	EndpointJoinRevision    int64               `json:"endpoint_join_revision"`
	CandidateVersion        int64               `json:"candidate_version"`
	CandidateKeyID          string              `json:"candidate_key_id"`
	CandidateFingerprint    string              `json:"candidate_fingerprint"`
	CandidateProofDigest    string              `json:"candidate_proof_digest"`
	CandidateBindingDigest  string              `json:"candidate_binding_digest"`
	CandidatePublicIdentity e2ee.PublicIdentity `json:"candidate_public_identity"`
	OwnerKeyID              string              `json:"owner_key_id"`
	IssuedAt                string              `json:"issued_at"`
	ExpiresAt               string              `json:"expires_at"`
}

type groupBindingClaims struct {
	Operation            string              `json:"operation"`
	OwnerID              string              `json:"owner_id"`
	PrincipalID          string              `json:"principal_id"`
	GroupID              string              `json:"group_id"`
	EndpointID           string              `json:"endpoint_id"`
	NodeID               string              `json:"node_id"`
	BindingID            string              `json:"binding_id"`
	BindingEpoch         uint64              `json:"binding_epoch"`
	MembershipRevision   int64               `json:"membership_revision"`
	EndpointJoinRevision int64               `json:"endpoint_join_revision"`
	CandidateVersion     int64               `json:"candidate_version"`
	CandidateKeyID       string              `json:"candidate_key_id"`
	Fingerprint          string              `json:"candidate_fingerprint"`
	ProofDigest          string              `json:"candidate_proof_digest"`
	PublicIdentity       e2ee.PublicIdentity `json:"candidate_public_identity"`
}

type endpointAttestation struct {
	Version      int                 `json:"version"`
	EndpointID   string              `json:"endpoint_id"`
	PrincipalID  string              `json:"principal_id"`
	NodeID       string              `json:"node_id"`
	BindingID    string              `json:"binding_id"`
	BindingEpoch uint64              `json:"binding_epoch"`
	Public       e2ee.PublicIdentity `json:"public_identity"`
	Signature    []byte              `json:"signature"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New(usage())
	}
	switch args[0] {
	case "device-grant":
		return runDeviceGrant(args[1:])
	case "group-grant":
		return runGroupGrant(args[1:])
	case "link-key-grant":
		return runLinkConsentGrant(args[1:], "KEY")
	case "link-review-policy":
		return runLinkConsentGrant(args[1:], "REVIEW_POLICY")
	case "help", "--help", "-h":
		fmt.Println(usage())
		return nil
	default:
		return errors.New(usage())
	}
}

func usage() string {
	return "usage:\n" +
		"  group_owner_signer device-grant --private FILE --device-public FILE --owner ID --device ID --hub ID --expect-device-key ID --out FILE [--expires-in 1h]\n" +
		"  group_owner_signer group-grant --private FILE --manifest FILE --expect-owner ID --expect-hub ID --expect-group ID --expect-endpoint ID --expect-node ID --expect-principal ID --expect-digest SHA256 --out FILE\n" +
		"  group_owner_signer link-key-grant --private FILE --request FILE --expect-owner ID --expect-owner-key ID --expect-owner-fingerprint HEX --expect-link ID --expect-version N --expect-contract-digest SHA256 --expect-manifest-digest SHA256 --expect-side SOURCE|TARGET --expect-max-expiry RFC3339NANO --expect-expires-at RFC3339NANO --out FILE\n" +
		"  group_owner_signer link-review-policy --private FILE --request FILE --expect-owner ID --expect-owner-key ID --expect-owner-fingerprint HEX --expect-link ID --expect-version N --expect-contract-digest SHA256 --expect-policy-digest SHA256 --expect-policy-head N --expect-policy-version N --expect-side SOURCE|TARGET --expect-max-expiry RFC3339NANO --expect-expires-at RFC3339NANO --out FILE"
}

func runDeviceGrant(args []string) error {
	fs := flag.NewFlagSet("device-grant", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	privatePath := fs.String("private", "", "owner private identity file")
	devicePublicPath := fs.String("device-public", "", "Android device public identity JSON")
	ownerID := fs.String("owner", "", "expected owner ID")
	deviceID := fs.String("device", "", "Android device ID")
	hubID := fs.String("hub", "", "independently pinned Hub ID")
	expectedDeviceKeyID := fs.String("expect-device-key", "", "device key ID shown by Android")
	outPath := fs.String("out", "", "new proof output file")
	expiresIn := fs.Duration("expires-in", time.Hour, "grant lifetime (1m to 24h)")
	if err := fs.Parse(args); err != nil || len(fs.Args()) != 0 {
		return errors.New("invalid device-grant arguments")
	}
	if *privatePath == "" || *devicePublicPath == "" || *ownerID == "" ||
		*deviceID == "" || *hubID == "" || *expectedDeviceKeyID == "" ||
		*outPath == "" || *expiresIn < time.Minute || *expiresIn > 24*time.Hour {
		return errors.New("device-grant requires the owner, Hub, device identity, output path, and a 1m to 24h lifetime")
	}
	if !canonicalToken(*ownerID) || !canonicalToken(*deviceID) || !canonicalToken(*hubID) ||
		!canonicalToken(*expectedDeviceKeyID) {
		return errors.New("device-grant scope contains an invalid identifier")
	}

	devicePublic, err := readPublicIdentity(*devicePublicPath)
	if err != nil {
		return err
	}
	if devicePublic.ID != *expectedDeviceKeyID {
		return errors.New("Android device key ID differs from the expected key ID")
	}
	owner, err := readOwnerIdentity(*privatePath)
	if err != nil {
		return err
	}
	defer runtimeKeepIdentityAlive(owner)
	ownerKeyID := owner.Public().ID
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(devicePublic)
	if err != nil {
		return errors.New("Android device public identity is invalid")
	}
	now := time.Now().UTC().Truncate(time.Second)
	issuedAt := now.Add(-time.Minute)
	expiresAt := now.Add(*expiresIn)

	fmt.Fprintf(os.Stderr, "Owner: %s\nOwner key: %s\nDevice: %s\nDevice key: %s\nDevice fingerprint: %s\nHub: %s\nPurpose: %s\nExpires: %s\n",
		*ownerID, ownerKeyID, *deviceID, devicePublic.ID, fingerprint, *hubID,
		e2ee.OwnerDevicePurposeControl, expiresAt.Format(time.RFC3339Nano))
	if err := requireTypedConfirmation("SIGN DEVICE " + *deviceID + " " + devicePublic.ID); err != nil {
		return err
	}
	proof, err := owner.SignOwnerDeviceGrant(*ownerID, *deviceID, devicePublic,
		*hubID, e2ee.OwnerDevicePurposeControl, issuedAt, expiresAt)
	if err != nil {
		return errors.New("could not sign the owner device grant")
	}
	defer zero(proof)
	if err := writeNewPrivate(*outPath, proof); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Owner Device Grant saved (0600): %s\n", *outPath)
	return nil
}

func runGroupGrant(args []string) error {
	fs := flag.NewFlagSet("group-grant", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	privatePath := fs.String("private", "", "owner private identity file")
	manifestPath := fs.String("manifest", "", "exact GroupEndpointKeyGrantManifest result JSON")
	expectedOwner := fs.String("expect-owner", "", "owner ID shown by Android")
	expectedHub := fs.String("expect-hub", "", "pinned Hub ID shown by Android")
	expectedGroup := fs.String("expect-group", "", "Group ID shown by Android")
	expectedEndpoint := fs.String("expect-endpoint", "", "Endpoint ID shown by Android")
	expectedNode := fs.String("expect-node", "", "Node ID shown by Android")
	expectedPrincipal := fs.String("expect-principal", "", "Principal ID shown by Android")
	expectedDigest := fs.String("expect-digest", "", "manifest digest shown by Android")
	outPath := fs.String("out", "", "new proof output file")
	if err := fs.Parse(args); err != nil || len(fs.Args()) != 0 {
		return errors.New("invalid group-grant arguments")
	}
	if *privatePath == "" || *manifestPath == "" || *expectedOwner == "" ||
		*expectedHub == "" || *expectedGroup == "" || *expectedEndpoint == "" ||
		*expectedNode == "" || *expectedPrincipal == "" || *expectedDigest == "" || *outPath == "" {
		return errors.New("group-grant requires the complete reviewed manifest scope, digest, private key, and output path")
	}
	for _, token := range []string{*expectedOwner, *expectedHub, *expectedGroup,
		*expectedEndpoint, *expectedNode, *expectedPrincipal} {
		if !canonicalToken(token) {
			return errors.New("expected Group grant scope contains an invalid identifier")
		}
	}
	if !canonicalSHA256(*expectedDigest) {
		return errors.New("expected manifest digest must be lowercase SHA-256 hex")
	}

	manifest, err := readAndVerifyManifest(*manifestPath, *expectedOwner, *expectedHub,
		*expectedGroup, *expectedEndpoint, *expectedNode, *expectedPrincipal, *expectedDigest)
	if err != nil {
		return err
	}
	owner, err := readOwnerIdentity(*privatePath)
	if err != nil {
		return err
	}
	defer runtimeKeepIdentityAlive(owner)
	if manifest.OwnerKeyID != owner.Public().ID {
		return errors.New("manifest owner key differs from the selected private identity")
	}

	fmt.Fprintf(os.Stderr, "Hub: %s\nOwner: %s / key %s\nGroup: %s (revision %d)\nEndpoint: %s / principal %s\nNode: %s\nBinding: %s / epoch %d\nMembership revision: %d\nEndpoint join revision: %d\nCandidate version: %d\nCandidate key: %s\nCandidate fingerprint: %s\nManifest digest: %s\nExpires: %s\n",
		manifest.HubID, manifest.OwnerID, manifest.OwnerKeyID,
		manifest.GroupID, manifest.GroupRevision, manifest.EndpointID, manifest.PrincipalID,
		manifest.NodeID, manifest.BindingID, manifest.BindingEpoch,
		manifest.MembershipRevision, manifest.EndpointJoinRevision, manifest.CandidateVersion,
		manifest.CandidateKeyID, manifest.CandidateFingerprint, manifest.Digest, manifest.ExpiresAt)
	if err := requireTypedConfirmation("SIGN GROUP " + manifest.Digest); err != nil {
		return err
	}
	issuedAt, _ := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	expiresAt, _ := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if issuedAt.After(time.Now().UTC()) || !expiresAt.After(time.Now().UTC()) {
		return errors.New("Group manifest expired while awaiting confirmation")
	}
	proof, err := owner.SignOwnerLinkKeyGrant(manifest.OwnerID, groupKeyGrantOperation,
		manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
	if err != nil {
		return errors.New("could not sign the owner Group Endpoint key grant")
	}
	defer zero(proof)
	if err := writeNewPrivate(*outPath, proof); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Owner Group Endpoint key grant saved (0600): %s\n", *outPath)
	return nil
}

func readAndVerifyManifest(path, expectedOwner, expectedHub, expectedGroup,
	expectedEndpoint, expectedNode, expectedPrincipal, expectedDigest string) (groupManifest, error) {
	var manifest groupManifest
	raw, err := readBoundedRegular(path, maxManifest, false)
	if err != nil {
		return manifest, errors.New("could not read the Group manifest file")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, errors.New("Group manifest is not the exact v1.2.1 manifest JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return manifest, errors.New("Group manifest has trailing JSON")
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return manifest, errors.New("Group manifest JSON is not canonical or contains duplicate fields")
	}
	if manifest.Version != 1 || manifest.Operation != groupKeyGrantOperation ||
		manifest.OwnerID != expectedOwner || manifest.HubID != expectedHub ||
		manifest.GroupID != expectedGroup || manifest.EndpointID != expectedEndpoint ||
		manifest.NodeID != expectedNode || manifest.PrincipalID != expectedPrincipal ||
		manifest.Digest != expectedDigest {
		return manifest, errors.New("Group manifest does not match the reviewed Hub, owner, Group, Endpoint, Node, principal, and digest")
	}
	for _, token := range []string{manifest.HubID, manifest.OwnerID, manifest.PrincipalID,
		manifest.GroupID, manifest.EndpointID, manifest.NodeID, manifest.BindingID,
		manifest.CandidateKeyID, manifest.OwnerKeyID} {
		if !canonicalToken(token) {
			return manifest, errors.New("Group manifest contains an invalid identifier")
		}
	}
	if manifest.GroupRevision <= 0 || manifest.BindingEpoch == 0 ||
		manifest.MembershipRevision <= 0 || manifest.EndpointJoinRevision <= 0 ||
		manifest.CandidateVersion <= 0 {
		return manifest, errors.New("Group manifest has a missing or invalid revision")
	}
	if !canonicalSHA256(manifest.Digest) || !canonicalSHA256(manifest.CandidateBindingDigest) ||
		!canonicalSHA256(manifest.CandidateProofDigest) ||
		!strings.HasPrefix(manifest.CandidateFingerprint, "sha256:") ||
		!canonicalSHA256(strings.TrimPrefix(manifest.CandidateFingerprint, "sha256:")) {
		return manifest, errors.New("Group manifest contains an invalid digest or fingerprint")
	}
	issuedAt, err := parseCanonicalUTC(manifest.IssuedAt)
	if err != nil {
		return manifest, errors.New("Group manifest issue time is invalid")
	}
	expiresAt, err := parseCanonicalUTC(manifest.ExpiresAt)
	if err != nil || !expiresAt.After(time.Now().UTC()) || !expiresAt.After(issuedAt) || issuedAt.After(time.Now().UTC()) {
		return manifest, errors.New("Group manifest is expired or outside its validity period")
	}
	if err := verifyCandidateEvidence(manifest); err != nil {
		return manifest, err
	}
	if err := verifyBindingDigest(manifest); err != nil {
		return manifest, err
	}
	if err := verifyManifestDigest(manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func verifyCandidateEvidence(manifest groupManifest) error {
	proofDigest := sha256.Sum256(manifest.CandidateAttestation)
	if hex.EncodeToString(proofDigest[:]) != manifest.CandidateProofDigest {
		return errors.New("Endpoint attestation digest does not match the manifest")
	}
	var proof endpointAttestation
	decoder := json.NewDecoder(bytes.NewReader(manifest.CandidateAttestation))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return errors.New("Endpoint attestation JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Endpoint attestation has trailing JSON")
	}
	canonical, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(canonical, manifest.CandidateAttestation) {
		return errors.New("Endpoint attestation JSON is not canonical")
	}
	if !publicIdentityEqual(proof.Public, manifest.CandidatePublicIdentity) {
		return errors.New("Endpoint attestation public key differs from the manifest")
	}
	verified, err := e2ee.VerifyEndpointKeyAttestation(manifest.CandidateAttestation,
		manifest.EndpointID, manifest.PrincipalID, manifest.NodeID,
		manifest.BindingID, manifest.BindingEpoch)
	if err != nil || !publicIdentityEqual(verified, manifest.CandidatePublicIdentity) {
		return errors.New("Endpoint attestation signature or binding is invalid")
	}
	if err := e2ee.ValidatePublicIdentity(manifest.CandidatePublicIdentity); err != nil ||
		manifest.CandidateKeyID != manifest.CandidatePublicIdentity.ID {
		return errors.New("candidate public key ID is invalid")
	}
	fingerprintInput := append([]byte(peerFingerprintDomain),
		manifest.CandidatePublicIdentity.KEMPublic...)
	fingerprintInput = append(fingerprintInput, manifest.CandidatePublicIdentity.SigningPublic...)
	fingerprint := sha256.Sum256(fingerprintInput)
	if "sha256:"+hex.EncodeToString(fingerprint[:]) != manifest.CandidateFingerprint {
		return errors.New("candidate public key fingerprint is invalid")
	}
	return nil
}

func verifyBindingDigest(manifest groupManifest) error {
	claims := groupBindingClaims{
		Operation: groupKeyGrantOperation, OwnerID: manifest.OwnerID,
		PrincipalID: manifest.PrincipalID, GroupID: manifest.GroupID,
		EndpointID: manifest.EndpointID, NodeID: manifest.NodeID,
		BindingID: manifest.BindingID, BindingEpoch: manifest.BindingEpoch,
		MembershipRevision:   manifest.MembershipRevision,
		EndpointJoinRevision: manifest.EndpointJoinRevision,
		CandidateVersion:     manifest.CandidateVersion,
		CandidateKeyID:       manifest.CandidateKeyID,
		Fingerprint:          manifest.CandidateFingerprint,
		ProofDigest:          manifest.CandidateProofDigest,
		PublicIdentity:       manifest.CandidatePublicIdentity,
	}
	actual, err := digestClaims(groupBindingDomain, claims)
	if err != nil || actual != manifest.CandidateBindingDigest {
		return errors.New("candidate binding digest is invalid")
	}
	return nil
}

func verifyManifestDigest(manifest groupManifest) error {
	claims := groupManifestClaims{
		Version: manifest.Version, Operation: manifest.Operation, HubID: manifest.HubID,
		OwnerID: manifest.OwnerID, PrincipalID: manifest.PrincipalID,
		GroupID: manifest.GroupID, GroupRevision: manifest.GroupRevision,
		EndpointID: manifest.EndpointID, NodeID: manifest.NodeID,
		BindingID: manifest.BindingID, BindingEpoch: manifest.BindingEpoch,
		MembershipRevision:      manifest.MembershipRevision,
		EndpointJoinRevision:    manifest.EndpointJoinRevision,
		CandidateVersion:        manifest.CandidateVersion,
		CandidateKeyID:          manifest.CandidateKeyID,
		CandidateFingerprint:    manifest.CandidateFingerprint,
		CandidateProofDigest:    manifest.CandidateProofDigest,
		CandidateBindingDigest:  manifest.CandidateBindingDigest,
		CandidatePublicIdentity: manifest.CandidatePublicIdentity,
		OwnerKeyID:              manifest.OwnerKeyID, IssuedAt: manifest.IssuedAt,
		ExpiresAt: manifest.ExpiresAt,
	}
	actual, err := digestClaims(groupManifestDomain, claims)
	if err != nil || actual != manifest.Digest {
		return errors.New("Group manifest digest is invalid")
	}
	return nil
}

func digestClaims(domain string, claims any) (string, error) {
	encoded, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := append([]byte(domain), encoded...)
	digest := sha256.Sum256(input)
	return hex.EncodeToString(digest[:]), nil
}

func parseCanonicalUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("timestamp is not canonical UTC RFC3339Nano")
	}
	return parsed, nil
}

func canonicalToken(value string) bool {
	if value == "" || len([]byte(value)) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

func canonicalSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func readOwnerIdentity(path string) (*e2ee.Identity, error) {
	data, err := readBoundedRegular(path, maxPrivateIdentity, true)
	if err != nil {
		return nil, errors.New("owner private identity must be a regular private file with mode 0600 or stricter")
	}
	defer zero(data)
	identity, err := e2ee.UnmarshalIdentity(data)
	if err != nil || identity == nil || identity.Public().ID == "" {
		return nil, errors.New("owner private identity file is invalid")
	}
	return identity, nil
}

func readPublicIdentity(path string) (e2ee.PublicIdentity, error) {
	var identity e2ee.PublicIdentity
	data, err := readBoundedRegular(path, maxPublicIdentity, false)
	if err != nil {
		return identity, errors.New("could not read Android device public identity")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&identity); err != nil {
		return identity, errors.New("Android device public identity JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return identity, errors.New("Android device public identity has trailing JSON")
	}
	canonical, err := json.Marshal(identity)
	if err != nil || !bytes.Equal(bytes.TrimSpace(data), canonical) || e2ee.ValidatePublicIdentity(identity) != nil {
		return identity, errors.New("Android device public identity is not canonical or valid")
	}
	return identity, nil
}

func readBoundedRegular(path string, maxBytes int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxBytes {
		return nil, errors.New("not a bounded regular file")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private file permissions are too broad")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || len(data) == 0 || int64(len(data)) > maxBytes {
		zero(data)
		return nil, errors.New("file is empty or exceeds its size limit")
	}
	return data, nil
}

func requireTypedConfirmation(expected string) error {
	fmt.Fprintf(os.Stderr, "Type exactly %q to authorize signing: ", expected)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.New("could not read signing confirmation")
	}
	if strings.TrimSpace(line) != expected {
		return errors.New("signing confirmation did not match")
	}
	return nil
}

func writeNewPrivate(path string, contents []byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("output path is required")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("output directory must already exist and must not be a symlink")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("output file already exists or cannot be created")
	}
	keep := false
	defer func() {
		file.Close()
		if !keep {
			os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return errors.New("could not restrict output file permissions")
	}
	written, err := file.Write(contents)
	if err != nil || written != len(contents) {
		return errors.New("could not write complete proof")
	}
	if err := file.Sync(); err != nil {
		return errors.New("could not persist proof file")
	}
	if err := file.Close(); err != nil {
		return errors.New("could not close proof file")
	}
	keep = true
	return nil
}

func publicIdentityEqual(a, b e2ee.PublicIdentity) bool {
	return a.ID == b.ID && bytes.Equal(a.KEMPublic, b.KEMPublic) &&
		bytes.Equal(a.SigningPublic, b.SigningPublic)
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

// Keep an explicit lifetime boundary for the private identity until command
// completion. The underlying pinned e2ee.Identity exposes no zeroization API.
func runtimeKeepIdentityAlive(identity *e2ee.Identity) { _ = identity.Public().ID }
