package ownersigner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

func TestOwnerSignerPrepareCustodyExportAndClose(t *testing.T) {
	root := t.TempDir()
	hubIdentity, hub := testHubIdentity(t)
	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	profileDir := filepath.Join(root, "profile")
	profile, err := Prepare(profileDir, "account_test", "owner_test", "https://hub.example", hub, false, ownerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		profileDir: 0700,
		filepath.Join(profileDir, profileFileName): 0600,
		filepath.Join(profileDir, profileLockName): 0600,
	} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("mode for %s = %v, err=%v; want %04o", filepath.Base(path), infoMode(info), err, want)
		}
	}
	publicPath, err := profile.ExportManifest("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profile.ExportManifest(""); err != nil {
		t.Fatalf("exact public export retry: %v", err)
	}
	publicInfo, err := os.Stat(publicPath)
	if err != nil || publicInfo.Mode().Perm() != 0644 {
		t.Fatalf("public manifest mode = %v, err=%v; want 0644", infoMode(publicInfo), err)
	}
	publicBytes, err := os.ReadFile(publicPath)
	if err != nil || bytes.Contains(publicBytes, []byte("owner_private_identity")) {
		t.Fatal("public manifest contains private profile data")
	}
	stateBytes, err := os.ReadFile(filepath.Join(profileDir, profileFileName))
	if err != nil || !bytes.Contains(stateBytes, []byte("owner_private_identity")) {
		t.Fatal("private profile did not retain its Owner identity")
	}
	if got := profile.PublicManifest().Hub.Public.ID; got != hubIdentity.Public().ID {
		t.Fatalf("exported Hub pin = %q, want %q", got, hubIdentity.Public().ID)
	}
	if err := profile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := profile.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := profile.ExportManifest(""); err == nil {
		t.Fatal("closed profile still exported")
	}
	if _, err := profile.Bootstrap(context.Background(), nil, func(BootstrapReview) error { return nil }); err == nil {
		t.Fatal("closed profile still performed bootstrap")
	}
	if got := profile.PublicManifest(); got.Format != "" {
		t.Fatal("closed profile exposed a live public manifest")
	}
}

func TestOwnerSignerRejectsUnsafeOriginProfileAndGrantBeforeReceipt(t *testing.T) {
	_, hub := testHubIdentity(t)
	for _, test := range []struct {
		origin string
		allow  bool
	}{
		{origin: "https://hub.example/path"},
		{origin: "http://hub.example", allow: true},
		{origin: "http://localhost:8787", allow: true},
	} {
		if _, err := Prepare(filepath.Join(t.TempDir(), "profile"), "account_test", "owner_test", test.origin, hub, test.allow, nil); err == nil {
			t.Fatalf("Prepare accepted unsafe origin %q", test.origin)
		}
	}
	loopback, err := Prepare(filepath.Join(t.TempDir(), "profile"), "account_test", "owner_test", "http://127.0.0.1:8787", hub, true, nil)
	if err != nil {
		t.Fatalf("explicit literal-loopback development origin: %v", err)
	}
	_ = loopback.Close()
	profile, err := Prepare(filepath.Join(t.TempDir(), "profile"), "account_test", "owner_test", "https://hub.example", hub, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	manifest := testEnrollmentManifest(t, profile, device)
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	reviewCalled := false
	if _, err := profile.SignDeviceGrant(encoded, time.Now().UTC().Add(time.Hour), func(GrantReview) error {
		reviewCalled = true
		return nil
	}); err == nil {
		t.Fatal("profile signed a device grant before bootstrap receipt")
	}
	if reviewCalled {
		t.Fatal("grant review ran before receipt readiness was checked")
	}
	if _, err := Open(profile.dir); !errors.Is(err, ErrBusy) {
		t.Fatalf("second opener error = %v, want busy profile", err)
	}
}

func TestOwnerSignerBootstrapPersistsExactProofAndRecoversAfterExpiry(t *testing.T) {
	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, hub := testHubIdentity(t)
	profileDir := filepath.Join(t.TempDir(), "profile")
	var mu sync.Mutex
	var pair ownerbootstrap.PairingFile
	var requests [][]byte
	var firstPersisted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/owner/bootstrap/accept" || r.URL.RawQuery != "" {
			t.Errorf("unexpected bootstrap request target %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 256*1024+1))
		if readErr != nil || len(body) == 0 || len(body) > 256*1024 {
			t.Errorf("bootstrap request body invalid: %v", readErr)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		call := len(requests)
		requests = append(requests, append([]byte(nil), body...))
		mu.Unlock()
		if call == 0 {
			data, err := os.ReadFile(filepath.Join(profileDir, profileFileName))
			var state profileState
			if err == nil {
				err = json.Unmarshal(data, &state)
			}
			mu.Lock()
			firstPersisted = err == nil && state.Bootstrap != nil && bytes.Equal(state.Bootstrap.Proof, body)
			mu.Unlock()
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Errorf("test server does not support connection hijacking")
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("hijack first response: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		if call != 1 {
			t.Errorf("unexpected bootstrap retry count %d", call+1)
			w.WriteHeader(http.StatusConflict)
			return
		}
		if _, err := ownerbootstrap.VerifyProof(hubKey, pair, body, time.Time{}); err != nil {
			t.Errorf("exact saved proof did not verify after expiry: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receipt := ownerbootstrap.Receipt{Format: ownerbootstrap.Format, ManifestDigest: pair.Manifest.Digest(),
			AuthorityID: pair.Manifest.AuthorityID, AccountID: pair.Manifest.AccountID, OwnerID: pair.Manifest.OwnerID,
			KeyID: pair.Manifest.CandidatePublic.ID, State: "ACTIVE", Version: 1}
		packet, err := ownerbootstrap.CreateReceipt(hubKey, pair, receipt)
		if err != nil {
			t.Errorf("create receipt: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(packet)
	}))
	defer server.Close()

	profile, err := Prepare(profileDir, "account_retry", "owner_retry", server.URL, clientoperator.HubIdentity{
		Contract: "android-hub-v1", HubID: "hub_retry", Public: hub.Public, KeyVersion: 1, Suite: clientoperator.Suite,
	}, true, ownerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	pair = testPair(t, profile, ownerIdentity, hubKey, time.Now().UTC().Add(2*time.Second))
	pairBytes, err := json.Marshal(pair)
	if err != nil {
		t.Fatal(err)
	}
	reviewCalls := 0
	_, err = profile.Bootstrap(context.Background(), pairBytes, func(review BootstrapReview) error {
		reviewCalls++
		if review.Fingerprint != ownerbootstrap.Fingerprint(ownerIdentity.Public()) || review.AccountID != "account_retry" || review.HubID != "hub_retry" {
			t.Errorf("bootstrap review scope is wrong: %+v", review)
		}
		return nil
	})
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("first request error = %v, want uncertain delivery", err)
	}
	mu.Lock()
	persisted := firstPersisted
	mu.Unlock()
	if !persisted {
		t.Fatal("Hub observed the proof before it was durably saved in the owner profile")
	}
	if err := profile.Close(); err != nil {
		t.Fatal(err)
	}
	expires, _ := time.Parse(time.RFC3339Nano, pair.Manifest.ExpiresAt)
	if wait := time.Until(expires) + 50*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}

	profile, err = Open(profileDir)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	receipt, err := profile.Recover(context.Background(), func(review BootstrapReview) error {
		reviewCalls++
		if review.ExpiresAt != pair.Manifest.ExpiresAt {
			t.Errorf("recovery did not show the original expired challenge")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("recover exact operation after expiry: %v", err)
	}
	if receipt.KeyID != ownerIdentity.Public().ID || receipt.AccountID != "account_retry" || receipt.State != "ACTIVE" {
		t.Fatalf("invalid authenticated receipt: %+v", receipt)
	}
	mu.Lock()
	if len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) {
		mu.Unlock()
		t.Fatal("recovery changed the exact persisted bootstrap proof")
	}
	mu.Unlock()
	if reviewCalls != 2 {
		t.Fatalf("human review calls = %d, want initial plus retry", reviewCalls)
	}

	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	manifest := testEnrollmentManifest(t, profile, device)
	unsafeManifest := manifest
	unsafeManifest.DeviceID = "device-\x1b[31mspoof"
	unsafeBytes, _ := json.Marshal(unsafeManifest)
	unsafeReviewCalled := false
	if _, err := profile.SignDeviceGrant(unsafeBytes, time.Now().UTC().Add(time.Hour), func(GrantReview) error {
		unsafeReviewCalled = true
		return nil
	}); err == nil {
		t.Fatal("profile accepted a terminal-control device ID")
	}
	if unsafeReviewCalled {
		t.Fatal("unsafe device identity reached the human review callback")
	}
	manifestBytes, _ := json.Marshal(manifest)
	grantReviewed := false
	grant, err := profile.SignDeviceGrant(manifestBytes, time.Now().UTC().Add(time.Hour), func(review GrantReview) error {
		grantReviewed = true
		if review.AccountID != "account_retry" || review.HubID != "hub_retry" || review.DeviceFingerprint != manifest.DeviceKeyFingerprint {
			t.Errorf("grant review scope is wrong: %+v", review)
		}
		return nil
	})
	if err != nil || len(grant) == 0 || !grantReviewed {
		t.Fatalf("verified signer could not produce reviewed grant: len=%d review=%t err=%v", len(grant), grantReviewed, err)
	}

	profile.state.Bootstrap.Response[0] ^= 1
	if err := profile.save(); err != nil {
		t.Fatal(err)
	}
	if err := profile.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(profileDir); err == nil {
		t.Fatal("profile accepted a corrupted cached bootstrap receipt")
	}
}

func TestOwnerSignerReplacesExpiredBootstrapWithLaterAuthenticatedPair(t *testing.T) {
	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, hub := testHubIdentity(t)
	profileDir := filepath.Join(t.TempDir(), "profile")
	var profile *Profile
	var newPair ownerbootstrap.PairingFile
	var newPairBytes []byte
	var oldProof []byte
	var requests [][]byte
	var cachedReceipt []byte
	var requestMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 256*1024+1))
		if readErr != nil || len(body) == 0 || len(body) > 256*1024 {
			t.Errorf("replacement request body invalid: %v", readErr)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requestMu.Lock()
		call := len(requests)
		requests = append(requests, append([]byte(nil), body...))
		requestMu.Unlock()
		if bytes.Equal(body, oldProof) {
			t.Error("signer resent the expired original proof instead of the reviewed replacement")
			w.WriteHeader(http.StatusConflict)
			return
		}
		if _, err := ownerbootstrap.VerifyProof(hubKey, newPair, body, time.Now().UTC()); err != nil {
			t.Errorf("replacement proof did not open under the new Hub challenge: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if call == 0 {
			persisted, err := os.ReadFile(filepath.Join(profileDir, profileFileName))
			var saved profileState
			if err == nil {
				err = json.Unmarshal(persisted, &saved)
			}
			if err != nil || saved.Bootstrap == nil || !bytes.Equal(saved.Bootstrap.PairFile, newPairBytes) || !bytes.Equal(saved.Bootstrap.Proof, body) {
				t.Errorf("replacement proof was not durably saved before HTTP: %v", err)
			}
			receipt := ownerbootstrap.Receipt{Format: ownerbootstrap.Format, ManifestDigest: newPair.Manifest.Digest(),
				AuthorityID: newPair.Manifest.AuthorityID, AccountID: newPair.Manifest.AccountID, OwnerID: newPair.Manifest.OwnerID,
				KeyID: newPair.Manifest.CandidatePublic.ID, State: "ACTIVE", Version: 1}
			packet, err := ownerbootstrap.CreateReceipt(hubKey, newPair, receipt)
			if err != nil {
				t.Errorf("create replacement receipt: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			requestMu.Lock()
			cachedReceipt = append([]byte(nil), packet...)
			requestMu.Unlock()
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("test server does not support connection hijacking")
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("drop first replacement response: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		requestMu.Lock()
		packet := append([]byte(nil), cachedReceipt...)
		requestMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(packet)
	}))
	defer server.Close()

	profile, err = Prepare(profileDir, "account_replace", "owner_replace", server.URL, clientoperator.HubIdentity{
		Contract: "android-hub-v1", HubID: "hub_replace", Public: hub.Public, KeyVersion: 1, Suite: clientoperator.Suite,
	}, true, ownerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if profile != nil {
			_ = profile.Close()
		}
	}()
	now := time.Now().UTC()
	oldExpiry := now.Add(-2 * time.Minute)
	oldIssue := oldExpiry.Add(-ownerbootstrap.MaxLifetime)
	oldPair := testPairAt(t, profile, ownerIdentity, hubKey, oldIssue, oldExpiry, "root_old", "operation_old")
	oldPairBytes, err := json.Marshal(oldPair)
	if err != nil {
		t.Fatal(err)
	}
	oldProof, err = ownerbootstrap.CreateProof(ownerIdentity, oldPair, oldIssue)
	if err != nil {
		t.Fatal(err)
	}
	profile.state.Bootstrap = &pendingBootstrap{PairFile: append([]byte(nil), oldPairBytes...), Proof: append([]byte(nil), oldProof...)}
	if err := profile.save(); err != nil {
		t.Fatal(err)
	}

	newIssue := oldExpiry.Add(time.Second)
	newExpiry := newIssue.Add(ownerbootstrap.MaxLifetime)
	newPair = testPairAt(t, profile, ownerIdentity, hubKey, newIssue, newExpiry, "root_new", "operation_new")
	newPairBytes, err = json.Marshal(newPair)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, rejected := range []struct {
		name string
		pair ownerbootstrap.PairingFile
	}{
		{name: "wrong account", pair: func() ownerbootstrap.PairingFile {
			bad := testPairAt(t, profile, ownerIdentity, hubKey, newIssue, newExpiry, "root_bad_account", "operation_bad_account")
			bad.Manifest.AccountID = "account_other"
			bad, _, err = ownerbootstrap.CreateChallenge(hubKey, bad, newIssue)
			if err != nil {
				t.Fatal(err)
			}
			return bad
		}()},
		{name: "wrong candidate", pair: func() ownerbootstrap.PairingFile {
			other, err := e2ee.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			return testPairAt(t, profile, other, hubKey, newIssue, newExpiry, "root_other_key", "operation_other_key")
		}()},
		{name: "issued before old expiry", pair: testPairAt(t, profile, ownerIdentity, hubKey,
			oldExpiry.Add(-time.Second), oldExpiry.Add(-time.Second).Add(ownerbootstrap.MaxLifetime), "root_early", "operation_early")},
	} {
		t.Run(rejected.name, func(t *testing.T) {
			encoded, err := json.Marshal(rejected.pair)
			if err != nil {
				t.Fatal(err)
			}
			reviewCalled := false
			if _, err := profile.Bootstrap(ctx, encoded, func(BootstrapReview) error {
				reviewCalled = true
				return nil
			}); err == nil {
				t.Fatal("unsafe replacement pairing was accepted")
			}
			if reviewCalled {
				t.Fatal("replacement scope reached review before validation")
			}
			if !bytes.Equal(profile.state.Bootstrap.PairFile, oldPairBytes) || !bytes.Equal(profile.state.Bootstrap.Proof, oldProof) {
				t.Fatal("rejected replacement changed the original pending proof")
			}
		})
	}
	reviewRejected := false
	if _, err := profile.Bootstrap(ctx, newPairBytes, func(BootstrapReview) error {
		reviewRejected = true
		return errors.New("synthetic review refusal")
	}); !errors.Is(err, ErrReview) {
		t.Fatalf("review refusal result = %v, want ErrReview", err)
	}
	if !reviewRejected || !bytes.Equal(profile.state.Bootstrap.PairFile, oldPairBytes) || !bytes.Equal(profile.state.Bootstrap.Proof, oldProof) {
		t.Fatal("review refusal replaced or cleared the original pending proof")
	}
	requestMu.Lock()
	noRequestsBeforeApproval := len(requests) == 0
	requestMu.Unlock()
	if !noRequestsBeforeApproval {
		t.Fatal("invalid or declined replacement reached the Hub")
	}

	reviewCalls := 0
	_, err = profile.Bootstrap(ctx, newPairBytes, func(review BootstrapReview) error {
		reviewCalls++
		if review.AuthorityID != "root_new" || review.OperationID != "operation_new" ||
			review.AccountID != "account_replace" || review.Fingerprint != ownerbootstrap.Fingerprint(ownerIdentity.Public()) {
			t.Errorf("replacement review did not include the exact new scope: %+v", review)
		}
		return nil
	})
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("replacement request result = %v, want uncertain dropped response", err)
	}
	if reviewCalls != 1 {
		t.Fatalf("replacement review count = %d, want one", reviewCalls)
	}
	if err := profile.Close(); err != nil {
		t.Fatal(err)
	}
	profile = nil
	profile, err = Open(profileDir)
	if err != nil {
		t.Fatalf("reopen replacement operation after response loss: %v", err)
	}
	receipt, err := profile.Recover(ctx, func(review BootstrapReview) error {
		reviewCalls++
		if review.AuthorityID != "root_new" || review.OperationID != "operation_new" {
			t.Errorf("recovery did not retain the replacement authority: %+v", review)
		}
		return nil
	})
	if err != nil || receipt == nil || receipt.AuthorityID != "root_new" || receipt.KeyID != ownerIdentity.Public().ID {
		t.Fatalf("replacement recovery did not authenticate its receipt: receipt=%+v err=%v", receipt, err)
	}
	if profile.PublicManifest().OwnerPublic.ID != ownerIdentity.Public().ID {
		t.Fatal("replacement generated a new Owner identity instead of retaining the same key")
	}
	requestMu.Lock()
	if len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) || !bytes.Equal(requests[0], profile.state.Bootstrap.Proof) {
		requestMu.Unlock()
		t.Fatal("replacement recovery did not resend the exact durably saved proof")
	}
	requestMu.Unlock()

	postReceiptPair := testPairAt(t, profile, ownerIdentity, hubKey, time.Now().UTC(), time.Now().UTC().Add(ownerbootstrap.MaxLifetime), "root_after_receipt", "operation_after_receipt")
	postReceiptBytes, _ := json.Marshal(postReceiptPair)
	postReceiptReview := false
	if _, err := profile.Bootstrap(ctx, postReceiptBytes, func(BootstrapReview) error {
		postReceiptReview = true
		return nil
	}); !errors.Is(err, ErrPending) {
		t.Fatalf("authenticated receipt allowed a new challenge replacement: %v", err)
	}
	if postReceiptReview {
		t.Fatal("replacement after an authenticated receipt reached review")
	}
}

func TestOwnerSignerRejectsMismatchedAndOverlongPairing(t *testing.T) {
	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, hub := testHubIdentity(t)
	profile, err := Prepare(filepath.Join(t.TempDir(), "profile"), "account_pair", "owner_pair", "https://hub.example", clientoperator.HubIdentity{
		Contract: "android-hub-v1", HubID: "hub_pair", Public: hub.Public, KeyVersion: 1, Suite: clientoperator.Suite,
	}, false, ownerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()

	wrongAccount := testPair(t, profile, ownerIdentity, hubKey, time.Now().UTC().Add(time.Minute))
	wrongAccount.Manifest.AccountID = "account_other"
	wrongAccount, _, err = ownerbootstrap.CreateChallenge(hubKey, wrongAccount, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	wrongBytes, _ := json.Marshal(wrongAccount)
	if _, err := profile.Bootstrap(context.Background(), wrongBytes, func(BootstrapReview) error { return nil }); !errors.Is(err, ErrMismatch) {
		t.Fatalf("mismatched account result = %v", err)
	}

	tooLong := testPair(t, profile, ownerIdentity, hubKey, time.Now().UTC().Add(ownerbootstrap.MaxLifetime+time.Minute))
	tooLongBytes, _ := json.Marshal(tooLong)
	reviewCalled := false
	if _, err := profile.Bootstrap(context.Background(), tooLongBytes, func(BootstrapReview) error {
		reviewCalled = true
		return nil
	}); err == nil {
		t.Fatal("profile accepted an Owner bootstrap challenge longer than ten minutes")
	}
	if reviewCalled {
		t.Fatal("profile prompted before rejecting overlong challenge lifetime")
	}
	if profile.state.Bootstrap != nil {
		t.Fatal("rejected pairing material was persisted")
	}
}

func testHubIdentity(t *testing.T) (*e2ee.Identity, clientoperator.HubIdentity) {
	t.Helper()
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return identity, clientoperator.HubIdentity{Contract: "android-hub-v1", HubID: "hub_test", Public: identity.Public(), KeyVersion: 1, Suite: clientoperator.Suite}
}

func testPair(t *testing.T, profile *Profile, owner, hub *e2ee.Identity, expires time.Time) ownerbootstrap.PairingFile {
	t.Helper()
	return testPairAt(t, profile, owner, hub, time.Now().UTC(), expires, "root_test", "bootstrap_test")
}

func testPairAt(t *testing.T, profile *Profile, owner, hub *e2ee.Identity, issuedAt, expires time.Time, authorityID, operationID string) ownerbootstrap.PairingFile {
	t.Helper()
	public := profile.PublicManifest()
	hubID := public.Hub.HubID
	pair := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: public.Origin,
		AllowLoopbackHTTP: public.AllowLoopbackHTTP,
		Hub: ownerbootstrap.HubIdentity{Contract: public.Hub.Contract, HubID: public.Hub.HubID,
			Public: public.Hub.Public, KeyVersion: public.Hub.KeyVersion, Suite: public.Hub.Suite},
		Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: public.AccountID,
			OwnerID: public.OwnerID, HubID: hubID, AuthorityID: authorityID, OperationID: operationID,
			CandidatePublic: owner.Public(), CandidateFingerprint: ownerbootstrap.Fingerprint(owner.Public()),
			ExpiresAt: expires.UTC().Format(time.RFC3339Nano)},
	}
	created, _, err := ownerbootstrap.CreateChallenge(hub, pair, issuedAt.UTC())
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func testEnrollmentManifest(t *testing.T, profile *Profile, device *e2ee.Identity) clientoperator.EnrollmentManifest {
	t.Helper()
	public := profile.PublicManifest()
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(device.Public())
	if err != nil {
		t.Fatal(err)
	}
	return clientoperator.EnrollmentManifest{Format: "cicada.owner-device-enrollment.v1", HubID: public.Hub.HubID,
		OwnerID: public.OwnerID, OwnerKeyID: public.OwnerPublic.ID, DeviceID: "client_test_device",
		DeviceKeyFingerprint: fingerprint, Purpose: e2ee.OwnerDevicePurposeControl, DevicePublicIdentity: device.Public()}
}

func infoMode(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode().Perm()
}
