package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestClientDockerHubHeadlessOperator exercises the bounded public Client
// operator API against the independently running disposable Hub used by the
// client interop suite. The loopback proxy drops one committed enrollment
// response to model an actual TCP response loss without accessing SDK internals.
func TestClientDockerHubHeadlessOperator(t *testing.T) {
	baseURL := os.Getenv("CICADA_TEST_HUB_URL")
	dbPath := os.Getenv("CICADA_TEST_HUB_DB")
	legacyToken := os.Getenv("CICADA_TEST_HUB_TOKEN")
	if baseURL == "" || dbPath == "" || legacyToken == "" {
		t.Skip("set the isolated Docker Hub fixture variables to run the headless Client operator interop test")
	}
	if err := validateHeadlessDockerFixture(baseURL, dbPath); err != nil {
		t.Fatalf("refusing unsafe Docker Hub fixture: %v", err)
	}

	base, _ := url.Parse(baseURL)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	hubHTTP := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	defer transport.CloseIdleConnections()
	callHub := func(method, path string, body []byte, bearer string, expectedStatus int) []byte {
		t.Helper()
		request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal("could not prepare disposable Hub request")
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := hubHTTP.Do(request)
		if err != nil {
			t.Fatal("disposable Hub request failed")
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 512*1024))
		if err != nil || response.StatusCode != expectedStatus {
			t.Fatalf("disposable Hub %s %s returned unexpected status %d", method, path, response.StatusCode)
		}
		return data
	}
	var residentOwner e2ee.PublicIdentity
	if json.Unmarshal(callHub(http.MethodGet, "/v1/identity", nil, legacyToken, http.StatusOK), &residentOwner) != nil || residentOwner.ID == "" {
		t.Fatal("disposable Hub did not return its public resident identity")
	}
	var hub clientoperator.HubIdentity
	if json.Unmarshal(callHub(http.MethodGet, "/v2/client/identity", nil, "", http.StatusOK), &hub) != nil ||
		hub.HubID == "" || hub.Contract != "android-hub-v1" || hub.KeyVersion != 1 || hub.Suite != clientoperator.Suite {
		t.Fatal("disposable Hub did not return a complete Client identity")
	}

	// The Owner signer stays in this test process; only its synthetic public
	// identity is registered into the marked disposable database.
	const ownerID = "synthetic-docker-headless-owner"
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("could not create synthetic Owner signing key")
	}
	registration, err := store.New(dbPath)
	if err != nil {
		t.Fatal("could not open marked disposable Hub database")
	}
	if err = registration.EnsureLocalOwnerPrincipal(ownerID); err == nil {
		_, err = registration.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public())
	}
	closeErr := registration.Close()
	if err != nil || closeErr != nil {
		t.Fatal("could not register the synthetic Owner public key in the disposable Hub")
	}

	// Alter the Hub key bytes while keeping the advertised short key ID intact.
	// The SDK must compare the complete pin and reject before enrollment.
	tamperedIdentity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/client/identity" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		request, requestErr := http.NewRequestWithContext(r.Context(), http.MethodGet,
			baseURL+"/v2/client/identity", nil)
		if requestErr != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		response, doErr := hubHTTP.Do(request)
		if doErr != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024))
		var advertised clientoperator.HubIdentity
		if readErr != nil || response.StatusCode != http.StatusOK || json.Unmarshal(data, &advertised) != nil ||
			len(advertised.Public.KEMPublic) == 0 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		advertised.Public.KEMPublic[0] ^= 1
		data, _ = json.Marshal(advertised)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer tamperedIdentity.Close()
	wrongDir := filepath.Join(t.TempDir(), "wrong-pin-profile")
	if err = os.Mkdir(wrongDir, 0700); err != nil {
		t.Fatal("could not create private wrong-pin profile directory")
	}
	if err = os.Chmod(wrongDir, 0700); err != nil {
		t.Fatal("could not set private wrong-pin profile directory mode")
	}
	wrongProfile, err := clientoperator.Prepare(wrongDir, tamperedIdentity.URL, ownerID, hub, ownerKey.Public(), true)
	if err != nil {
		t.Fatal("could not prepare wrong-pin profile fixture")
	}
	wrongManifest := wrongProfile.Manifest()
	wrongGrant, err := ownerKey.SignOwnerDeviceGrant(ownerID, wrongManifest.DeviceID,
		wrongManifest.DevicePublicIdentity, hub.HubID, e2ee.OwnerDevicePurposeControl,
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		_ = wrongProfile.Close()
		t.Fatal("could not sign synthetic wrong-pin fixture grant")
	}
	wrongPinErr := wrongProfile.Enroll(context.Background(), wrongGrant)
	_ = wrongProfile.Close()
	if wrongPinErr == nil || !strings.Contains(wrongPinErr.Error(), "full pin") {
		t.Fatal("Client operator accepted a Hub identity that differed from the complete public-key pin")
	}

	// This response-loss shim forwards every request to the real disposable
	// Hub TCP endpoint and drops only the first successful enrollment response.
	var dropped atomic.Bool
	upstreamTransport := http.DefaultTransport.(*http.Transport).Clone()
	upstreamTransport.Proxy = nil
	upstream := &http.Client{Timeout: 10 * time.Second, Transport: upstreamTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused in test proxy") }}
	defer upstreamTransport.CloseIdleConnections()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 512*1024+1))
		if readErr != nil || len(body) > 512*1024 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		target := base.Scheme + "://" + base.Host + r.URL.RequestURI()
		request, requestErr := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
		if requestErr != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		for _, header := range []string{"Content-Type", "Cache-Control", "Accept"} {
			if value := r.Header.Get(header); value != "" {
				request.Header.Set(header, value)
			}
		}
		response, doErr := upstream.Do(request)
		if doErr != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		if r.Method == http.MethodPost && r.URL.Path == "/v2/client/devices/enroll" &&
			response.StatusCode == http.StatusCreated && dropped.CompareAndSwap(false, true) {
			_, _ = io.Copy(io.Discard, response.Body)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		for _, header := range []string{"Content-Type", "Cache-Control"} {
			if value := response.Header.Get(header); value != "" {
				w.Header().Set(header, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	defer proxy.Close()

	profileDir := filepath.Join(t.TempDir(), "headless-profile")
	if err = os.Mkdir(profileDir, 0700); err != nil {
		t.Fatal("could not create private Client profile directory")
	}
	if err = os.Chmod(profileDir, 0700); err != nil {
		t.Fatal("could not set private Client profile directory mode")
	}
	profile, err := clientoperator.Prepare(profileDir, proxy.URL, ownerID, hub, ownerKey.Public(), true)
	if err != nil {
		t.Fatal("could not prepare Client profile with the independently supplied Hub pin")
	}
	defer func() { _ = profile.Close() }()
	manifestPath, err := profile.WriteManifest()
	if err != nil {
		t.Fatal("could not export the public enrollment manifest")
	}
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode().Perm() != 0600 {
		t.Fatal("public enrollment manifest did not use a regular mode 0600 file")
	}
	manifestBefore := profile.Manifest()
	if err = profile.Close(); err != nil {
		t.Fatal("could not close Client profile before reopen")
	}
	profile, err = clientoperator.Open(profileDir)
	if err != nil {
		t.Fatal("could not reopen the saved Client profile")
	}
	if profile.Manifest().DeviceID != manifestBefore.DeviceID {
		t.Fatal("reopening the Client profile changed its device identity")
	}
	if repeatedPath, repeatErr := profile.WriteManifest(); repeatErr != nil || repeatedPath != manifestPath {
		t.Fatal("reopened Client profile could not safely resume its public manifest export")
	}

	expires := time.Now().UTC().Add(6 * time.Second)
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, manifestBefore.DeviceID,
		manifestBefore.DevicePublicIdentity, hub.HubID, e2ee.OwnerDevicePurposeControl,
		time.Now().UTC().Add(-time.Minute), expires)
	if err != nil {
		t.Fatal("could not sign synthetic Owner device grant")
	}
	if err = profile.Enroll(context.Background(), grant); err == nil || !dropped.Load() {
		t.Fatal("enrollment response loss was not observed after Hub commit")
	}
	if err = profile.Close(); err != nil {
		t.Fatal("could not close Client profile after lost enrollment response")
	}
	profile, err = clientoperator.Open(profileDir)
	if err != nil {
		t.Fatal("could not reopen Client profile with its saved enrollment")
	}
	if delay := time.Until(expires) + 20*time.Millisecond; delay > 0 {
		time.Sleep(delay)
	}
	changedGrant, err := ownerKey.SignOwnerDeviceGrant(ownerID, manifestBefore.DeviceID,
		manifestBefore.DevicePublicIdentity, hub.HubID, e2ee.OwnerDevicePurposeControl,
		time.Now().UTC().Add(-time.Second), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal("could not create alternate synthetic Owner grant")
	}
	if err = profile.Enroll(context.Background(), changedGrant); err == nil {
		t.Fatal("saved enrollment accepted a replacement Owner grant")
	}
	if err = profile.Enroll(context.Background(), grant); err != nil {
		t.Fatal("exact saved enrollment could not be retried after grant expiry")
	}

	// Check the SDK method surface for a generic RPC entry point; the encrypted
	// server capabilities and Guard below remain authoritative per operation.
	profileType := reflect.TypeOf(profile)
	boundedMethods := map[string]bool{
		"Capabilities": true, "Close": true, "ConfirmNode": true, "Enroll": true,
		"Manifest": true, "NodeReview": true, "Nodes": true, "PreviewNode": true,
		"Recover": true, "Retry": true, "Status": true, "WriteManifest": true,
	}
	for i := 0; i < profileType.NumMethod(); i++ {
		if method := profileType.Method(i).Name; !boundedMethods[method] {
			t.Fatalf("Client operator unexpectedly exposes method %s", method)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	capabilities, err := profile.Capabilities(ctx)
	if err != nil || capabilities == nil || !capabilities.OK {
		t.Fatal("encrypted external-owner capabilities request failed")
	}
	var scope struct {
		OwnerID       string   `json:"owner_id"`
		Role          string   `json:"role"`
		Recovery      bool     `json:"rpc_recovery"`
		Operations    []string `json:"available_rpc_operations"`
		Contract      string   `json:"contract_revision"`
		CatalogSHA256 string   `json:"catalog_sha256"`
	}
	if json.Unmarshal(capabilities.Result, &scope) != nil || scope.OwnerID != ownerID || scope.Role != "external" ||
		!scope.Recovery || scope.Contract == "" || scope.CatalogSHA256 == "" ||
		!containsHeadlessOperation(scope.Operations, "status.snapshot") ||
		!containsHeadlessOperation(scope.Operations, "nodes.preview") ||
		!containsHeadlessOperation(scope.Operations, "nodes.confirm") ||
		containsHeadlessOperation(scope.Operations, "intent.submit") ||
		containsHeadlessOperation(scope.Operations, "approvals.decide") {
		t.Fatal("encrypted capabilities did not preserve the external-owner operation scope")
	}
	status, err := profile.Status(ctx)
	if err != nil || status == nil || !status.OK {
		t.Fatal("encrypted external-owner status request failed")
	}
	var snapshot control.ClientStatusSnapshot
	if json.Unmarshal(status.Result, &snapshot) != nil || snapshot.OwnerPrincipalID != ownerID ||
		snapshot.ScopeMode != control.ClientStatusSnapshotScopeAttributed || bytes.Contains(status.Result, []byte(residentOwner.ID)) {
		t.Fatal("encrypted status crossed the synthetic external-owner boundary")
	}

	// Stage a clearly synthetic Node, obtain the exact authenticated candidate,
	// then confirm only the tuple the SDK returned for review.
	const nodeID = "synthetic-docker-headless-node"
	nodeToken, nodeDigest, err := fabric.NewNodeCredential()
	if err != nil || nodeToken == "" || nodeDigest == "" {
		t.Fatal("could not create synthetic Node credential fixture")
	}
	var nodeHub control.NodeControlHubIdentity
	if json.Unmarshal(callHub(http.MethodGet, "/v2/node/identity", nil, "", http.StatusOK), &nodeHub) != nil ||
		nodeHub.HubID != hub.HubID || nodeHub.KeyVersion == 0 || nodeHub.Fingerprint == "" {
		t.Fatal("disposable Hub did not return a complete Node-Control identity")
	}
	nodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("could not create synthetic Node application key")
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal("could not create synthetic Node proof nonce")
	}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{
		HubID: nodeHub.HubID, NodeID: nodeID, RequestNonce: nonce, CredentialDigest: nodeDigest,
		NodePublicIdentity: nodeKey.Public(), HubPublicIdentity: nodeHub.PublicIdentity,
		HubKeyVersion: nodeHub.KeyVersion,
	})
	if err != nil {
		t.Fatal("could not create synthetic Node proof transcript")
	}
	proof, err := e2ee.Seal(nodeKey, nodeHub.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal("could not seal synthetic Node proof")
	}
	nodeStart, err := json.Marshal(map[string]any{
		"node_id": nodeID, "node_name": "Synthetic Docker Headless Node", "credential_digest": nodeDigest,
		"request_nonce": nonce, "node_public_identity": nodeKey.Public(),
		"node_fingerprint": nodewire.IdentityFingerprint(nodeKey.Public()), "proof_packet": proof,
		"hub_id": nodeHub.HubID, "hub_public_identity": nodeHub.PublicIdentity,
		"hub_key_version": nodeHub.KeyVersion, "hub_fingerprint": nodeHub.Fingerprint,
	})
	if err != nil {
		t.Fatal("could not encode synthetic Node device-code request")
	}
	var deviceCode struct {
		UserCode string `json:"user_code"`
	}
	if json.Unmarshal(callHub(http.MethodPost, "/v2/nodes/device-code", nodeStart, "", http.StatusCreated), &deviceCode) != nil || deviceCode.UserCode == "" {
		t.Fatal("disposable Hub did not issue a synthetic Node device code")
	}
	preview, err := profile.PreviewNode(ctx, deviceCode.UserCode)
	if err != nil || preview == nil || !preview.OK {
		t.Fatal("encrypted Node preview failed")
	}
	var candidate clientoperator.NodeCandidate
	if json.Unmarshal(preview.Result, &candidate) != nil || candidate.NodeID != nodeID || candidate.Mode != store.NodeControlPairingInitial ||
		candidate.State != "PENDING" || candidate.NodeKeyFingerprint == "" || candidate.HubNodeControlFingerprint == "" {
		t.Fatal("encrypted Node preview omitted the reviewed candidate tuple")
	}
	reviewed, err := profile.NodeReview()
	if err != nil || reviewed != candidate {
		t.Fatal("SDK review tuple differed from the authenticated preview")
	}
	confirmed, err := profile.ConfirmNode(ctx, reviewed)
	if err != nil || confirmed == nil || !confirmed.OK {
		t.Fatal("encrypted Node confirmation failed")
	}
	var binding store.NodeControlKeyBinding
	if json.Unmarshal(confirmed.Result, &binding) != nil || binding.NodeID != nodeID || binding.State != "ACTIVE" ||
		binding.ClientDeviceID != manifestBefore.DeviceID || binding.ApprovedOwnerDeviceID != manifestBefore.DeviceID ||
		binding.ApprovedCandidateDigest != candidate.CandidateDigest {
		t.Fatal("Node confirmation did not bind the reviewed tuple to this Client device")
	}
	nodes, err := profile.Nodes(ctx)
	if err != nil || nodes == nil || !nodes.OK {
		t.Fatal("encrypted Node list request failed")
	}
	var listed []store.NodeDeviceBinding
	if json.Unmarshal(nodes.Result, &listed) != nil || len(listed) != 1 || listed[0].NodeID != nodeID ||
		listed[0].ClientDeviceID != manifestBefore.DeviceID || listed[0].State != "ACTIVE" || !listed[0].Authorized {
		t.Fatal("encrypted Node list did not remain scoped to the synthetic external Owner")
	}
}

func validateHeadlessDockerFixture(baseURL, dbPath string) error {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("Hub URL must be an HTTP origin for the isolated loopback fixture")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return errors.New("Hub URL must use a literal loopback address")
	}
	cleanDBPath := filepath.Clean(dbPath)
	absoluteDBPath, err := filepath.Abs(cleanDBPath)
	if err != nil || cleanDBPath != dbPath || absoluteDBPath != cleanDBPath || filepath.Base(cleanDBPath) != "cicada.sqlite3" {
		return errors.New("disposable Hub database path must be its canonical fixture location")
	}
	dir := filepath.Dir(cleanDBPath)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return errors.New("disposable Hub database directory must not contain symlinks")
	}
	databaseInfo, err := os.Lstat(cleanDBPath)
	if err != nil || !databaseInfo.Mode().IsRegular() || databaseInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("disposable Hub database must be an existing regular file without symlinks")
	}
	resolvedDatabase, err := filepath.EvalSymlinks(cleanDBPath)
	if err != nil || resolvedDatabase != cleanDBPath {
		return errors.New("disposable Hub database file must not contain symlinks")
	}
	markerPath := filepath.Join(dir, ".cicada-disposable-recovery-fixture")
	markerInfo, err := os.Lstat(markerPath)
	if err != nil || !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 || markerInfo.Mode().Perm() != 0600 {
		return errors.New("disposable Hub database marker is missing or unsafe")
	}
	marker, err := os.ReadFile(markerPath)
	if err != nil || string(marker) != "disposable\n" {
		return errors.New("disposable Hub database marker content is invalid")
	}
	return nil
}

func containsHeadlessOperation(operations []string, expected string) bool {
	for _, operation := range operations {
		if operation == expected {
			return true
		}
	}
	return false
}
