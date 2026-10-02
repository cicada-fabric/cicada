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
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	maxLinkSigningRequest           = 24 * 1024
	linkSigningRequestSchema        = "cicada.client.link-consent-signing-request.v1"
	maxNativeRevision        uint64 = 1<<63 - 1
)

// linkSigningRequest is a public, flat request envelope produced by Android.
// It intentionally carries no private key, proof, or peer Owner authority.
// The key-grant manifest_digest maps to Core's key_binding_digest claim.
type linkSigningRequest struct {
	Schema                string `json:"schema"`
	Kind                  string `json:"kind"`
	OwnerID               string `json:"owner_id"`
	OwnerKeyID            string `json:"owner_key_id"`
	OwnerKeyFingerprint   string `json:"owner_key_fingerprint"`
	LinkID                string `json:"link_id"`
	LinkVersion           uint64 `json:"link_version"`
	ContractDigest        string `json:"contract_digest"`
	Side                  string `json:"side"`
	MaxExpiry             string `json:"max_expiry"`
	ExpiresAt             string `json:"expires_at"`
	ManifestDigest        string `json:"manifest_digest,omitempty"`
	PolicyDigest          string `json:"policy_digest,omitempty"`
	ExpectedPolicyVersion uint64 `json:"expected_policy_version,omitempty"`
	PolicyVersion         uint64 `json:"policy_version,omitempty"`
}

type linkSigningExpected struct {
	Kind                string
	OwnerID             string
	OwnerKeyID          string
	OwnerKeyFingerprint string
	LinkID              string
	LinkVersion         uint64
	ContractDigest      string
	Digest              string
	Side                string
	MaxExpiry           string
	ExpiresAt           string
	ExpectedPolicyHead  uint64
	PolicyVersion       uint64
}

func runLinkConsentGrant(args []string, kind string) error {
	fs := flag.NewFlagSet("link-"+strings.ToLower(strings.ReplaceAll(kind, "_", "-")), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	privatePath := fs.String("private", "", "Owner private identity file on the trusted Owner host")
	requestPath := fs.String("request", "", "Android prepare.signingRequestJson envelope")
	expectedOwner := fs.String("expect-owner", "", "independently reviewed Owner ID")
	expectedOwnerKey := fs.String("expect-owner-key", "", "independently reviewed Owner key ID")
	expectedOwnerFingerprint := fs.String("expect-owner-fingerprint", "", "independently reviewed Owner fingerprint (lowercase SHA-256 hex)")
	expectedLink := fs.String("expect-link", "", "independently reviewed Link ID")
	expectedVersion := fs.Uint64("expect-version", 0, "independently reviewed current Link version")
	expectedContractDigest := fs.String("expect-contract-digest", "", "independently reviewed Link contract digest")
	expectedManifestDigest := fs.String("expect-manifest-digest", "", "independently reviewed key manifest digest")
	expectedPolicyDigest := fs.String("expect-policy-digest", "", "independently reviewed review-policy digest")
	expectedSide := fs.String("expect-side", "", "independently reviewed Link side (SOURCE or TARGET)")
	expectedMaxExpiry := fs.String("expect-max-expiry", "", "independently reviewed maximum proof expiry")
	expectedExpiresAt := fs.String("expect-expires-at", "", "exact proof expiry to sign, no later than the maximum")
	expectedPolicyHead := fs.Uint64("expect-policy-head", 0, "review-policy preview CAS head")
	expectedPolicyVersion := fs.Uint64("expect-policy-version", 0, "review-policy candidate version")
	outPath := fs.String("out", "", "new mode-0600 proof file on the trusted Owner host")
	if err := fs.Parse(args); err != nil || len(fs.Args()) != 0 {
		return errors.New("invalid Link consent signer arguments")
	}
	if *privatePath == "" || *requestPath == "" || *expectedOwner == "" ||
		*expectedOwnerKey == "" || *expectedOwnerFingerprint == "" || *expectedLink == "" ||
		*expectedVersion == 0 || *expectedContractDigest == "" ||
		*expectedSide == "" || *expectedMaxExpiry == "" || *expectedExpiresAt == "" || *outPath == "" {
		return errors.New("Link consent signing requires the complete independently reviewed Owner, Link, digest, side, expiry, private-file and output scope")
	}
	if kind == "KEY" {
		if *expectedManifestDigest == "" || *expectedPolicyDigest != "" || *expectedPolicyHead != 0 || *expectedPolicyVersion != 0 {
			return errors.New("key-grant signing does not accept policy-version flags")
		}
	} else if kind == "REVIEW_POLICY" {
		if *expectedPolicyDigest == "" || *expectedManifestDigest != "" ||
			!flagWasSet(fs, "expect-policy-head") || *expectedPolicyVersion == 0 || *expectedPolicyHead >= maxNativeRevision ||
			*expectedPolicyVersion != *expectedPolicyHead+1 {
			return errors.New("review-policy signing requires candidate policy version equal to head plus one within signed-64-bit bounds")
		}
	} else {
		return errors.New("unsupported Link consent signing kind")
	}
	expectedDigest := *expectedManifestDigest
	if kind == "REVIEW_POLICY" {
		expectedDigest = *expectedPolicyDigest
	}

	raw, err := readBoundedRegular(*requestPath, maxLinkSigningRequest, false)
	if err != nil {
		return errors.New("could not read a bounded regular Android signing-request file")
	}
	defer zero(raw)
	request, err := parseLinkSigningRequest(raw)
	if err != nil {
		return err
	}
	expected := linkSigningExpected{
		Kind: kind, OwnerID: *expectedOwner, OwnerKeyID: *expectedOwnerKey,
		OwnerKeyFingerprint: *expectedOwnerFingerprint, LinkID: *expectedLink,
		LinkVersion: *expectedVersion, ContractDigest: *expectedContractDigest,
		Digest: expectedDigest, Side: *expectedSide, MaxExpiry: *expectedMaxExpiry,
		ExpiresAt: *expectedExpiresAt, ExpectedPolicyHead: *expectedPolicyHead,
		PolicyVersion: *expectedPolicyVersion,
	}
	now := time.Now().UTC()
	if err := validateLinkSigningRequest(request, expected, now); err != nil {
		return err
	}

	// Open the host-only secret only after the Android envelope and every
	// independently entered expected claim have passed validation.
	owner, err := readOwnerIdentity(*privatePath)
	if err != nil {
		return err
	}
	defer runtimeKeepIdentityAlive(owner)
	public := owner.Public()
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(public)
	if err != nil || public.ID != request.OwnerKeyID || fingerprint != request.OwnerKeyFingerprint {
		return errors.New("selected Owner private identity does not match the independently pinned Owner key ID and fingerprint")
	}

	challenge := linkSigningChallenge(request)
	printLinkSigningReview(request, fingerprint)
	if err := requireExactTypedConfirmation(challenge); err != nil {
		return err
	}

	issuedAt := time.Now().UTC()
	maxExpiry, _ := parseCanonicalUTC(request.MaxExpiry)
	expiresAt, _ := parseCanonicalUTC(request.ExpiresAt)
	if !issuedAt.Before(expiresAt) || !issuedAt.Before(maxExpiry) {
		return errors.New("Link consent expiry elapsed while awaiting confirmation")
	}
	var proof []byte
	switch request.Kind {
	case "KEY":
		proof, err = owner.SignOwnerLinkKeyGrant(
			request.OwnerID, request.LinkID, request.ContractDigest, request.ManifestDigest,
			request.LinkVersion, e2ee.OwnerLinkGrantSide(request.Side), issuedAt, expiresAt,
		)
		if err == nil {
			_, err = e2ee.VerifyOwnerLinkKeyGrant(proof, public, request.OwnerID, request.LinkID,
				request.ContractDigest, request.ManifestDigest, request.LinkVersion,
				e2ee.OwnerLinkGrantSide(request.Side), issuedAt)
		}
	case "REVIEW_POLICY":
		proof, err = owner.SignOwnerLinkReviewPolicy(
			request.OwnerID, request.LinkID, request.ContractDigest, request.PolicyDigest,
			request.LinkVersion, request.PolicyVersion, e2ee.OwnerLinkGrantSide(request.Side),
			issuedAt, expiresAt,
		)
		if err == nil {
			_, err = e2ee.VerifyOwnerLinkReviewPolicy(proof, public, request.OwnerID, request.LinkID,
				request.ContractDigest, request.PolicyDigest, request.LinkVersion,
				request.PolicyVersion, e2ee.OwnerLinkGrantSide(request.Side), issuedAt)
		}
	}
	if err != nil {
		zero(proof)
		return errors.New("Core could not create and verify the exact Owner Link consent proof")
	}
	defer zero(proof)
	if err := writeNewPrivate(*outPath, proof); err != nil {
		return err
	}
	if err := verifyNewPrivateOutput(*outPath); err != nil {
		return err
	}
	proofDigest := sha256.Sum256(proof)
	fmt.Fprintf(os.Stdout, "status=created kind=%s proof_sha256=%s mode=0600 output=%s\n",
		request.Kind, hex.EncodeToString(proofDigest[:]), *outPath)
	return nil
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(current *flag.Flag) {
		if current.Name == name {
			set = true
		}
	})
	return set
}

func parseLinkSigningRequest(raw []byte) (linkSigningRequest, error) {
	var request linkSigningRequest
	if len(raw) == 0 || len(raw) > maxLinkSigningRequest || !utf8.Valid(raw) {
		return request, errors.New("Android Link signing request is empty, oversized, or invalid UTF-8")
	}
	keys, err := parseUniqueJSONObjectKeys(raw)
	if err != nil {
		return request, errors.New("Android Link signing request is invalid JSON or contains duplicate fields")
	}
	var kind struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &kind); err != nil {
		return request, errors.New("Android Link signing request has no valid kind")
	}
	want := []string{"schema", "kind", "owner_id", "owner_key_id", "owner_key_fingerprint", "link_id", "link_version", "contract_digest", "side", "max_expiry", "expires_at"}
	switch kind.Kind {
	case "KEY":
		want = append(want, "manifest_digest")
	case "REVIEW_POLICY":
		want = append(want, "policy_digest", "expected_policy_version", "policy_version")
	default:
		return request, errors.New("Android Link signing request kind is unsupported")
	}
	if len(keys) != len(want) {
		return request, errors.New("Android Link signing request has missing or unexpected fields for its kind")
	}
	for _, key := range want {
		if _, exists := keys[key]; !exists {
			return request, errors.New("Android Link signing request has missing or unexpected fields for its kind")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, errors.New("Android Link signing request fields have invalid types")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return request, errors.New("Android Link signing request has trailing JSON")
	}
	return request, nil
}

func parseUniqueJSONObjectKeys(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("expected a JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errors.New("duplicate object field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') {
		return nil, errors.New("unterminated JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON value")
	}
	return fields, nil
}

func validateLinkSigningRequest(request linkSigningRequest, expected linkSigningExpected, now time.Time) error {
	if now.IsZero() || request.Schema != linkSigningRequestSchema || request.Kind != expected.Kind ||
		(request.Kind != "KEY" && request.Kind != "REVIEW_POLICY") {
		return errors.New("Android Link signing request schema or kind is not supported")
	}
	for _, token := range []string{request.OwnerID, request.OwnerKeyID, request.LinkID} {
		if !canonicalToken(token) {
			return errors.New("Android Link signing request has an invalid Owner or Link identifier")
		}
	}
	if request.OwnerID != expected.OwnerID || request.OwnerKeyID != expected.OwnerKeyID ||
		request.OwnerKeyFingerprint != expected.OwnerKeyFingerprint || request.LinkID != expected.LinkID ||
		request.LinkVersion != expected.LinkVersion || request.ContractDigest != expected.ContractDigest ||
		request.Side != expected.Side || request.MaxExpiry != expected.MaxExpiry || request.ExpiresAt != expected.ExpiresAt {
		return errors.New("Android Link signing request differs from the independently reviewed Owner, Link, version, side, digest, or expiry")
	}
	if request.LinkVersion == 0 || request.LinkVersion > maxNativeRevision ||
		!canonicalSHA256(request.ContractDigest) || !canonicalSHA256(request.OwnerKeyFingerprint) ||
		!canonicalSHA256(expected.ContractDigest) || !canonicalSHA256(expected.OwnerKeyFingerprint) ||
		(request.Side != "SOURCE" && request.Side != "TARGET") {
		return errors.New("Android Link signing request has an invalid version, digest, fingerprint, or side")
	}
	maxExpiry, err := parseCanonicalUTC(request.MaxExpiry)
	if err != nil {
		return errors.New("Android Link maximum proof expiry is not canonical UTC RFC3339Nano")
	}
	expiresAt, err := parseCanonicalUTC(request.ExpiresAt)
	if err != nil || !expiresAt.After(now) || !maxExpiry.After(now) || expiresAt.After(maxExpiry) {
		return errors.New("Android Link proof expiry is invalid, elapsed, or exceeds the preview maximum")
	}
	if expected.Kind == "KEY" {
		if !canonicalSHA256(request.ManifestDigest) || request.ManifestDigest != expected.Digest ||
			request.PolicyDigest != "" || request.ExpectedPolicyVersion != 0 || request.PolicyVersion != 0 {
			return errors.New("Android key-grant request does not match the independently reviewed manifest digest")
		}
	} else {
		if !canonicalSHA256(request.PolicyDigest) || request.PolicyDigest != expected.Digest ||
			request.ManifestDigest != "" || request.ExpectedPolicyVersion != expected.ExpectedPolicyHead ||
			request.PolicyVersion != expected.PolicyVersion || request.PolicyVersion == 0 ||
			request.ExpectedPolicyVersion >= maxNativeRevision ||
			request.ExpectedPolicyVersion+1 != request.PolicyVersion || request.PolicyVersion > maxNativeRevision {
			return errors.New("Android review-policy request differs from the independently reviewed digest or head-plus-one version")
		}
	}
	if expected.OwnerID == "" || expected.OwnerKeyID == "" || expected.LinkID == "" ||
		expected.LinkVersion == 0 || expected.LinkVersion > maxNativeRevision ||
		!canonicalToken(expected.OwnerID) || !canonicalToken(expected.OwnerKeyID) || !canonicalToken(expected.LinkID) ||
		!canonicalSHA256(expected.Digest) || expected.Side != "SOURCE" && expected.Side != "TARGET" {
		return errors.New("independent Link signer expectations are invalid")
	}
	return nil
}

func linkSigningChallenge(request linkSigningRequest) string {
	if request.Kind == "KEY" {
		return strings.Join([]string{"SIGN", "LINK", "KEY",
			"owner=" + request.OwnerID, "owner-key=" + request.OwnerKeyID,
			"owner-fingerprint=" + request.OwnerKeyFingerprint, "link=" + request.LinkID,
			"link-version=" + fmt.Sprint(request.LinkVersion), "side=" + request.Side,
			"contract=" + request.ContractDigest, "manifest=" + request.ManifestDigest,
			"expires=" + request.ExpiresAt, "max-expiry=" + request.MaxExpiry}, " ")
	}
	return strings.Join([]string{"SIGN", "LINK", "REVIEW_POLICY",
		"owner=" + request.OwnerID, "owner-key=" + request.OwnerKeyID,
		"owner-fingerprint=" + request.OwnerKeyFingerprint, "link=" + request.LinkID,
		"link-version=" + fmt.Sprint(request.LinkVersion), "side=" + request.Side,
		"contract=" + request.ContractDigest, "policy=" + request.PolicyDigest,
		"policy-head=" + fmt.Sprint(request.ExpectedPolicyVersion),
		"policy-version=" + fmt.Sprint(request.PolicyVersion),
		"expires=" + request.ExpiresAt, "max-expiry=" + request.MaxExpiry}, " ")
}

func printLinkSigningReview(request linkSigningRequest, fingerprint string) {
	fmt.Fprintf(os.Stderr, "Owner Link consent review\nKind: %s\nOwner: %s\nOwner key: %s\nOwner fingerprint: %s\nLink: %s (version %d)\nSide: %s\nContract digest: %s\n",
		request.Kind, request.OwnerID, request.OwnerKeyID, fingerprint,
		request.LinkID, request.LinkVersion, request.Side, request.ContractDigest)
	if request.Kind == "KEY" {
		fmt.Fprintf(os.Stderr, "Key manifest digest: %s\n", request.ManifestDigest)
	} else {
		fmt.Fprintf(os.Stderr, "Policy digest: %s\nPolicy head: %d\nPolicy version: %d\n",
			request.PolicyDigest, request.ExpectedPolicyVersion, request.PolicyVersion)
	}
	fmt.Fprintf(os.Stderr, "Proof expiry: %s (maximum %s)\n", request.ExpiresAt, request.MaxExpiry)
}

func requireExactTypedConfirmation(expected string) error {
	fmt.Fprintf(os.Stderr, "Type exactly %q to authorize signing: ", expected)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.New("could not read signing confirmation")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if !exactConfirmationMatches(line, expected) {
		return errors.New("signing confirmation did not match exactly")
	}
	return nil
}

func exactConfirmationMatches(line, expected string) bool {
	return line == expected
}

func verifyNewPrivateOutput(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return errors.New("proof output is not a regular create-new mode-0600 file")
	}
	return nil
}
