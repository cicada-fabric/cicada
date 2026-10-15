package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLinkRequest(kind string) linkSigningRequest {
	request := linkSigningRequest{
		Schema: linkSigningRequestSchema, Kind: kind,
		OwnerID: "owner-a", OwnerKeyID: "pq1-owner-key",
		OwnerKeyFingerprint: strings.Repeat("a", 64),
		LinkID:              "link-a", LinkVersion: 7,
		ContractDigest: strings.Repeat("b", 64), Side: "SOURCE",
		MaxExpiry: "2026-10-02T14:00:00Z", ExpiresAt: "2026-10-02T13:00:00Z",
	}
	if kind == "KEY" {
		request.ManifestDigest = strings.Repeat("c", 64)
	} else {
		request.PolicyDigest = strings.Repeat("d", 64)
		request.ExpectedPolicyVersion = 0
		request.PolicyVersion = 1
	}
	return request
}

func testExpected(request linkSigningRequest) linkSigningExpected {
	expected := linkSigningExpected{
		Kind: request.Kind, OwnerID: request.OwnerID, OwnerKeyID: request.OwnerKeyID,
		OwnerKeyFingerprint: request.OwnerKeyFingerprint, LinkID: request.LinkID,
		LinkVersion: request.LinkVersion, ContractDigest: request.ContractDigest,
		Side: request.Side, MaxExpiry: request.MaxExpiry, ExpiresAt: request.ExpiresAt,
	}
	if request.Kind == "KEY" {
		expected.Digest = request.ManifestDigest
	} else {
		expected.Digest = request.PolicyDigest
		expected.ExpectedPolicyHead = request.ExpectedPolicyVersion
		expected.PolicyVersion = request.PolicyVersion
	}
	return expected
}

func marshalLinkRequest(t *testing.T, request linkSigningRequest) []byte {
	t.Helper()
	fields := map[string]any{
		"schema": request.Schema, "kind": request.Kind,
		"owner_id": request.OwnerID, "owner_key_id": request.OwnerKeyID,
		"owner_key_fingerprint": request.OwnerKeyFingerprint,
		"link_id":               request.LinkID, "link_version": request.LinkVersion,
		"contract_digest": request.ContractDigest, "side": request.Side,
		"max_expiry": request.MaxExpiry, "expires_at": request.ExpiresAt,
	}
	if request.Kind == "KEY" {
		fields["manifest_digest"] = request.ManifestDigest
	} else {
		fields["policy_digest"] = request.PolicyDigest
		fields["expected_policy_version"] = request.ExpectedPolicyVersion
		fields["policy_version"] = request.PolicyVersion
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseAndValidateLinkKeySigningRequest(t *testing.T) {
	request := testLinkRequest("KEY")
	parsed, err := parseLinkSigningRequest(marshalLinkRequest(t, request))
	if err != nil {
		t.Fatalf("valid key request rejected: %v", err)
	}
	if err := validateLinkSigningRequest(parsed, testExpected(request), time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("valid key request failed independent validation: %v", err)
	}
	if parsed.ManifestDigest != request.ManifestDigest || parsed.PolicyDigest != "" {
		t.Fatal("key request digest fields were not kept kind-specific")
	}
}

func TestParseAndValidateLinkReviewPolicySigningRequest(t *testing.T) {
	request := testLinkRequest("REVIEW_POLICY")
	parsed, err := parseLinkSigningRequest(marshalLinkRequest(t, request))
	if err != nil {
		t.Fatalf("valid review-policy request rejected: %v", err)
	}
	if err := validateLinkSigningRequest(parsed, testExpected(request), time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("valid review-policy request failed independent validation: %v", err)
	}
	if parsed.PolicyVersion != parsed.ExpectedPolicyVersion+1 {
		t.Fatal("review-policy request did not bind the next policy head")
	}
}

func TestParseLinkSigningRequestRejectsDuplicateAndExtraFields(t *testing.T) {
	base := marshalLinkRequest(t, testLinkRequest("KEY"))
	duplicate := strings.Replace(string(base), `"link_id":"link-a"`, `"link_id":"link-a","link_id":"link-a"`, 1)
	if _, err := parseLinkSigningRequest([]byte(duplicate)); err == nil {
		t.Fatal("duplicate request field was accepted")
	}
	withUnexpected := strings.TrimSuffix(string(base), "}") + `,"policy_digest":"` + strings.Repeat("d", 64) + `"}`
	if _, err := parseLinkSigningRequest([]byte(withUnexpected)); err == nil {
		t.Fatal("kind-incompatible request field was accepted")
	}
	wrongNumber := strings.Replace(string(base), `"link_version":7`, `"link_version":7.0`, 1)
	if _, err := parseLinkSigningRequest([]byte(wrongNumber)); err == nil {
		t.Fatal("non-integer Link version was accepted")
	}
}

func TestLinkSigningRequestRejectsChangedExpectedAuthority(t *testing.T) {
	request := testLinkRequest("KEY")
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	mutations := map[string]func(*linkSigningExpected){
		"owner key":         func(v *linkSigningExpected) { v.OwnerKeyID = "pq1-other-key" },
		"owner fingerprint": func(v *linkSigningExpected) { v.OwnerKeyFingerprint = strings.Repeat("e", 64) },
		"manifest digest":   func(v *linkSigningExpected) { v.Digest = strings.Repeat("f", 64) },
		"Link version":      func(v *linkSigningExpected) { v.LinkVersion++ },
		"side":              func(v *linkSigningExpected) { v.Side = "TARGET" },
		"contract":          func(v *linkSigningExpected) { v.ContractDigest = strings.Repeat("9", 64) },
		"expiry":            func(v *linkSigningExpected) { v.ExpiresAt = "2026-10-02T12:30:00Z" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			expected := testExpected(request)
			mutate(&expected)
			if err := validateLinkSigningRequest(request, expected, now); err == nil {
				t.Fatalf("changed expected %s was accepted", name)
			}
		})
	}
}

func TestLinkSigningRequestRejectsExpiryAndPolicyVersionBoundary(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	key := testLinkRequest("KEY")
	for name, mutate := range map[string]func(*linkSigningRequest){
		"expired":                func(v *linkSigningRequest) { v.ExpiresAt = "2026-10-02T11:59:59Z" },
		"past maximum":           func(v *linkSigningRequest) { v.ExpiresAt = "2026-10-02T14:00:01Z" },
		"noncanonical timestamp": func(v *linkSigningRequest) { v.ExpiresAt = "2026-10-02T13:00:00+00:00" },
		"unsafe Link version":    func(v *linkSigningRequest) { v.LinkVersion = maxNativeRevision + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := key
			mutate(&changed)
			if err := validateLinkSigningRequest(changed, testExpected(changed), now); err == nil {
				t.Fatal("invalid expiry or version was accepted")
			}
		})
	}
	policy := testLinkRequest("REVIEW_POLICY")
	policy.PolicyVersion = 2
	if err := validateLinkSigningRequest(policy, testExpected(policy), now); err == nil {
		t.Fatal("review-policy candidate not equal to head plus one was accepted")
	}
	policy.ExpectedPolicyVersion = maxNativeRevision
	policy.PolicyVersion = maxNativeRevision
	if err := validateLinkSigningRequest(policy, testExpected(policy), now); err == nil {
		t.Fatal("review-policy version overflow boundary was accepted")
	}
}

func TestLinkSigningChallengeRequiresExactText(t *testing.T) {
	request := testLinkRequest("REVIEW_POLICY")
	challenge := linkSigningChallenge(request)
	if !exactConfirmationMatches(challenge, challenge) {
		t.Fatal("exact challenge did not match")
	}
	for _, altered := range []string{challenge + " ", " " + challenge, strings.Replace(challenge, request.PolicyDigest, strings.Repeat("e", 64), 1)} {
		if exactConfirmationMatches(altered, challenge) {
			t.Fatal("altered human challenge was accepted")
		}
	}
}

func TestCreateNewProofOutputIs0600AndRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := writeNewPrivate(path, []byte("synthetic-proof-bytes")); err != nil {
		t.Fatal(err)
	}
	if err := verifyNewPrivateOutput(path); err != nil {
		t.Fatalf("created output failed permission check: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %04o, want 0600", info.Mode().Perm())
	}
	if err := writeNewPrivate(path, []byte("replacement")); err == nil {
		t.Fatal("existing output was overwritten")
	}
}
