package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/ownersigner"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestClientDockerHubOwnerBootstrap starts a second Hub from the exact binary
// built for the interop image. The first-owner case owns a separate marked
// StateDir; it does not reuse the smoke fixture, whose compatibility Root is
// deliberately established by the older smoke test. A local reverse proxy
// drops the first committed response to exercise the signer's persisted proof
// and the Hub's exact cached-receipt recovery across a process restart.
func TestClientDockerHubOwnerBootstrap(t *testing.T) {
	fixtureURL := os.Getenv("CICADA_TEST_HUB_URL")
	fixtureDB := os.Getenv("CICADA_TEST_HUB_DB")
	if fixtureURL == "" || fixtureDB == "" || os.Getenv("CICADA_TEST_HUB_TOKEN") == "" {
		t.Skip("requires the isolated disposable Docker Hub interop fixture")
	}
	if err := validateHeadlessDockerFixture(fixtureURL, fixtureDB); err != nil {
		t.Fatalf("refusing unsafe parent Docker fixture: %v", err)
	}
	const builtHubBinary = "/out/cicada"
	if info, err := os.Stat(builtHubBinary); err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		t.Fatalf("built Hub binary is unavailable for independent owner-bootstrap fixture")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	fixtureRoot, stateDir, workspaceRoot, homeDir := newOwnerBootstrapFixtureDirs(t)
	databasePath := filepath.Join(stateDir, "cicada.sqlite3")
	markerPath := filepath.Join(stateDir, ".cicada-disposable-recovery-fixture")
	if err := writeOwnerBootstrapFixtureMarker(markerPath); err != nil {
		t.Fatalf("could not mark owned Hub fixture: %v", err)
	}

	backendPort := reserveOwnerBootstrapPort(t)
	backendOrigin := "http://127.0.0.1:" + strconv.Itoa(backendPort)
	proxyState := &ownerBootstrapProxyState{}
	proxy := newOwnerBootstrapDropProxy(t, backendOrigin, proxyState)
	t.Cleanup(proxy.Close)

	// Use the new local setup API. The chosen Owner account is created before
	// Control identities are loaded; it is not derived from a crypto key ID.
	setupStore, err := store.New(databasePath)
	if err != nil {
		t.Fatalf("could not initialize disposable Hub Store: %v", err)
	}
	setup, err := setupStore.InitializeHubOwnerLocal("Synthetic bootstrap owner", proxy.URL, true)
	if closeErr := setupStore.Close(); err != nil || closeErr != nil {
		t.Fatalf("could not initialize local Hub account: setup=%v close=%v", err, closeErr)
	}
	if setup == nil || setup.State != store.HubOwnerReady || setup.AccountID == "" || setup.OwnerID == "" || setup.HubID == "" {
		t.Fatal("local Hub setup did not create a stable HUB_READY account mapping")
	}

	config := control.DefaultConfig()
	config.StateDir = stateDir
	config.WorkspaceRoot = workspaceRoot
	config.APIToken = ""
	localControl, err := control.New(config)
	if err != nil {
		t.Fatalf("could not open the newly configured local Hub: %v", err)
	}
	legacyCryptoID := localControl.Identity().ID
	if legacyCryptoID == setup.OwnerID {
		t.Fatal("synthetic stable Owner account reused the Hub's legacy cryptographic identity")
	}
	hubIdentity := clientoperator.HubIdentity{
		Contract: "android-hub-v1", HubID: setup.HubID,
		Public: localControl.ClientControlPublicIdentity(), KeyVersion: 1, Suite: clientoperator.Suite,
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		_ = localControl.Shutdown(context.Background())
		t.Fatal("could not generate synthetic external Owner identity")
	}
	ownerPrivate, err := ownerKey.MarshalBinary()
	if err != nil {
		_ = localControl.Shutdown(context.Background())
		t.Fatal("could not serialize synthetic Owner identity for the custody assertion")
	}
	ownerProfileDir := filepath.Join(fixtureRoot, "owner-signer")
	ownerProfile, err := ownersigner.Prepare(ownerProfileDir, setup.AccountID, setup.OwnerID,
		proxy.URL, hubIdentity, true, ownerKey)
	if err != nil {
		_ = localControl.Shutdown(context.Background())
		t.Fatalf("could not create synthetic local Owner signer profile: %v", err)
	}
	defer ownerProfile.Close()
	if _, err := ownerProfile.ExportManifest(filepath.Join(fixtureRoot, "owner-public.json")); err != nil {
		_ = localControl.Shutdown(context.Background())
		t.Fatalf("could not export public Owner manifest: %v", err)
	}
	pair, err := localControl.IssueOwnerBootstrapLocal(ownerKey.Public(), ownerbootstrap.Fingerprint(ownerKey.Public()))
	if err != nil {
		_ = localControl.Shutdown(context.Background())
		t.Fatalf("local Hub could not issue exact-candidate bootstrap authority: %v", err)
	}
	pairBytes, err := json.Marshal(pair)
	if err != nil {
		_ = localControl.Shutdown(context.Background())
		t.Fatal("could not encode the synthetic private pairing file")
	}
	pairPath := filepath.Join(fixtureRoot, "owner-bootstrap-pair.json")
	if err := writeOwnerBootstrapPrivateFile(pairPath, pairBytes); err != nil {
		_ = localControl.Shutdown(context.Background())
		t.Fatal("could not write mode-0600 synthetic pairing file")
	}
	pairBytes, err = os.ReadFile(pairPath)
	if err != nil {
		_ = localControl.Shutdown(context.Background())
		t.Fatal("could not read mode-0600 synthetic pairing file")
	}
	if err := localControl.Shutdown(context.Background()); err != nil {
		t.Fatalf("could not close local setup Control before starting Hub process: %v", err)
	}

	child := startOwnerBootstrapHub(t, ctx, builtHubBinary, stateDir, workspaceRoot, homeDir, backendPort)
	waitOwnerBootstrapHub(t, ctx, proxy.URL, child)
	issueRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		proxy.URL+"/v2/owner/bootstrap/issue", bytes.NewReader([]byte(`{"format":"cicada.owner-signer-public.v1"}`)))
	if err != nil {
		t.Fatal("could not prepare synthetic public-issuer rejection check")
	}
	issueRequest.Header.Set("Content-Type", "application/json")
	issueResponse, err := (&http.Client{Timeout: 2 * time.Second}).Do(issueRequest)
	if err != nil {
		t.Fatal("could not check that no public bootstrap issuer exists")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(issueResponse.Body, 4096))
	_ = issueResponse.Body.Close()
	if issueResponse.StatusCode != http.StatusNotFound {
		t.Fatal("Hub exposed a public first-Root issuer endpoint")
	}

	review := func(info ownersigner.BootstrapReview) error {
		if info.AccountID != setup.AccountID || info.OwnerID != setup.OwnerID || info.HubID != setup.HubID ||
			info.Origin != proxy.URL || info.Purpose != ownerbootstrap.Purpose ||
			info.Fingerprint != ownerbootstrap.Fingerprint(ownerKey.Public()) || info.AuthorityID == "" ||
			info.OperationID == "" || info.ExpiresAt == "" {
			return errors.New("synthetic Owner review differed from the exact bootstrap tuple")
		}
		return nil
	}
	if _, err := ownerProfile.Bootstrap(ctx, pairBytes, review); err == nil {
		t.Fatal("Owner signer reported success after its accepted HTTP response was dropped")
	}
	firstProof, firstReceipt, dropped := proxyState.firstAccepted()
	if !dropped || len(firstProof) == 0 || len(firstReceipt) == 0 {
		t.Fatal("proxy did not observe and drop the first committed bootstrap response")
	}
	if err := ownerProfile.Close(); err != nil {
		t.Fatalf("could not close Owner profile after uncertain response: %v", err)
	}

	// Restart the independent Hub before resending the same saved proof.
	child.stop(t)
	child = nil
	child = startOwnerBootstrapHub(t, ctx, builtHubBinary, stateDir, workspaceRoot, homeDir, backendPort)
	waitOwnerBootstrapHub(t, ctx, proxy.URL, child)
	ownerProfile, err = ownersigner.Open(ownerProfileDir)
	if err != nil {
		t.Fatalf("could not reopen Owner profile after uncertain bootstrap: %v", err)
	}
	defer ownerProfile.Close()
	receipt, err := ownerProfile.Recover(ctx, review)
	if err != nil || receipt == nil || receipt.State != store.OwnerApprovalKeyActive || receipt.KeyID != ownerKey.Public().ID {
		t.Fatalf("exact Owner bootstrap recovery did not return the active signer receipt: %v", err)
	}
	secondProof, secondReceipt, secondStatus := proxyState.secondAccepted()
	if !bytes.Equal(firstProof, secondProof) || !bytes.Equal(firstReceipt, secondReceipt) || secondStatus != http.StatusOK {
		t.Fatal("response-loss recovery changed the exact proof or cached receipt bytes")
	}

	// The newly bootstrapped Owner signs the existing Client enrollment grant;
	// its encrypted capability snapshot must use the persisted account mapping.
	managerClientDir := filepath.Join(fixtureRoot, "manager-client")
	if err := os.Mkdir(managerClientDir, 0700); err != nil {
		t.Fatal("could not create manager Client profile directory")
	}
	managerClient, err := clientoperator.Prepare(managerClientDir, proxy.URL, setup.OwnerID, hubIdentity, ownerKey.Public(), true)
	if err != nil {
		t.Fatalf("could not prepare synthetic manager Client: %v", err)
	}
	defer managerClient.Close()
	managerManifestPath, err := managerClient.WriteManifest()
	if err != nil {
		t.Fatal("could not write manager Client public enrollment manifest")
	}
	managerManifest, err := os.ReadFile(managerManifestPath)
	if err != nil {
		t.Fatal("could not read manager Client public enrollment manifest")
	}
	managerGrant, err := ownerProfile.SignDeviceGrant(managerManifest, time.Now().UTC().Add(15*time.Minute), func(info ownersigner.GrantReview) error {
		if info.AccountID != setup.AccountID || info.OwnerID != setup.OwnerID || info.OwnerKeyID != ownerKey.Public().ID ||
			info.HubID != setup.HubID || info.DeviceID == "" || info.DeviceFingerprint == "" || info.Purpose != e2ee.OwnerDevicePurposeControl {
			return errors.New("manager grant review differed from the exact Client enrollment tuple")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("could not sign the existing manager Client grant: %v", err)
	}
	if err := managerClient.Enroll(ctx, managerGrant); err != nil {
		t.Fatalf("newly bootstrapped Owner could not enroll an exact Client: %v", err)
	}
	managerCaps, err := managerClient.Capabilities(ctx)
	if err != nil || managerCaps == nil || !managerCaps.OK {
		t.Fatalf("configured Owner did not receive encrypted manager capabilities: %v", err)
	}
	if !ownerBootstrapCapabilitiesHaveRole(t, managerCaps.Result, "manager", "intent.submit", "approvals.decide") {
		t.Fatal("configured stable Owner account did not receive manager-only operations")
	}

	// Continue through the existing Node INITIAL flow on this newly bootstrapped
	// Root and the same independent Hub process. This exercises SDK and Hub
	// protocol behavior with synthetic Node material, not a Node Agent runtime.
	nodeHTTPTransport := http.DefaultTransport.(*http.Transport).Clone()
	nodeHTTPTransport.Proxy = nil
	nodeHTTP := &http.Client{Timeout: 10 * time.Second, Transport: nodeHTTPTransport}
	defer nodeHTTPTransport.CloseIdleConnections()
	nodeCallHub := func(method, path string, body []byte, expectedStatus int) []byte {
		request, err := http.NewRequestWithContext(ctx, method, proxy.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal("could not prepare synthetic Node Hub request")
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := nodeHTTP.Do(request)
		if err != nil {
			t.Fatal("synthetic Node Hub request failed")
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 512*1024))
		if err != nil || response.StatusCode != expectedStatus {
			t.Fatal("synthetic Node Hub request returned an unexpected result")
		}
		return data
	}
	nodeBinding := exerciseSyntheticInitialNode(t, ctx, managerClient, setup.HubID,
		setup.OwnerID, managerClient.Manifest().DeviceID,
		"synthetic-docker-owner-bootstrap-node", nodeCallHub)
	if nodeBinding.OwnerID != setup.OwnerID || nodeBinding.ClientDeviceID != managerClient.Manifest().DeviceID ||
		nodeBinding.ApprovedOwnerDeviceID != managerClient.Manifest().DeviceID {
		t.Fatal("fresh-Root Node binding did not retain its Owner and confirming-Client identities")
	}

	// Model the historical crypto-ID shape as a separate self-owned Human.
	// Its key is an external-owner fixture only; it does not establish the new
	// account's Root. Matching the Hub's Control crypto ID alone must not grant
	// manager capabilities.
	guestKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("could not create synthetic external Owner key")
	}
	guestStore, err := store.New(databasePath)
	if err != nil {
		t.Fatal("could not reopen disposable Hub Store for the external-owner fixture")
	}
	if err := guestStore.EnsureLocalOwnerPrincipal(legacyCryptoID); err != nil {
		_ = guestStore.Close()
		t.Fatalf("could not create historical crypto-ID Owner fixture: %v", err)
	}
	if _, err := guestStore.RegisterOwnerApprovalKeyLocal(legacyCryptoID, guestKey.Public()); err != nil {
		_ = guestStore.Close()
		t.Fatalf("could not register the external-owner fixture key: %v", err)
	}
	if err := guestStore.Close(); err != nil {
		t.Fatal("could not close external-owner fixture Store")
	}
	guestClientDir := filepath.Join(fixtureRoot, "legacy-crypto-owner-client")
	if err := os.Mkdir(guestClientDir, 0700); err != nil {
		t.Fatal("could not create external-owner Client profile directory")
	}
	guestClient, err := clientoperator.Prepare(guestClientDir, proxy.URL, legacyCryptoID, hubIdentity, guestKey.Public(), true)
	if err != nil {
		t.Fatalf("could not prepare legacy crypto-ID Client: %v", err)
	}
	defer guestClient.Close()
	guestManifestPath, err := guestClient.WriteManifest()
	if err != nil {
		t.Fatal("could not write external-owner enrollment manifest")
	}
	guestManifest, err := os.ReadFile(guestManifestPath)
	if err != nil {
		t.Fatal("could not read external-owner enrollment manifest")
	}
	guestGrant, err := guestKey.SignOwnerDeviceGrant(legacyCryptoID, guestClient.Manifest().DeviceID,
		guestClient.Manifest().DevicePublicIdentity, setup.HubID, e2ee.OwnerDevicePurposeControl,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(15*time.Minute))
	if err != nil {
		t.Fatal("could not sign exact external-owner Client grant")
	}
	if len(guestManifest) == 0 || guestClient.Enroll(ctx, guestGrant) != nil {
		t.Fatal("legacy crypto-ID human could not complete external Client enrollment")
	}
	guestCaps, err := guestClient.Capabilities(ctx)
	if err != nil || guestCaps == nil || !guestCaps.OK ||
		!ownerBootstrapCapabilitiesHaveRole(t, guestCaps.Result, "external", "status.snapshot") ||
		ownerBootstrapCapabilitiesContain(t, guestCaps.Result, "intent.submit", "approvals.decide") {
		t.Fatalf("Hub's legacy crypto identity received manager capabilities without account mapping: %v", err)
	}

	// A mode-0600 Owner private identity must never appear in Hub state.
	child.stop(t)
	if len(ownerPrivate) == 0 || ownerBootstrapTreeContains(t, stateDir, ownerPrivate) {
		t.Fatal("Hub StateDir retained the synthetic Owner private identity")
	}

	// Revoking the first Root leaves its permanent history intact. Neither a
	// local issue nor a retry of its consumed proof may reopen first setup.
	rootStore, err := store.New(databasePath)
	if err != nil {
		t.Fatal("could not reopen Hub Store for Root revocation")
	}
	if _, err := rootStore.RevokeOwnerApprovalKeyLocal(setup.OwnerID, ownerKey.Public().ID, 1); err != nil {
		_ = rootStore.Close()
		t.Fatalf("could not revoke the synthetic first Root: %v", err)
	}
	postRevoke, err := rootStore.GetHubOwnerSetup()
	if err != nil || postRevoke == nil || !postRevoke.RootEverEstablished || postRevoke.SignerState != "NEEDS_OWNER_SIGNER" {
		_ = rootStore.Close()
		t.Fatal("Root revocation cleared permanent first-root history")
	}
	if err := rootStore.Close(); err != nil {
		t.Fatal("could not close Hub Store after revocation")
	}
	secondRoot, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("could not create second synthetic candidate")
	}
	postRevokeControl, err := control.New(config)
	if err != nil {
		t.Fatalf("could not reopen locally configured Hub after Root revocation: %v", err)
	}
	_, issueErr := postRevokeControl.IssueOwnerBootstrapLocal(secondRoot.Public(), ownerbootstrap.Fingerprint(secondRoot.Public()))
	closeErr := postRevokeControl.Shutdown(context.Background())
	if issueErr == nil || closeErr != nil {
		t.Fatal("a revoked first Root allowed local re-bootstrap or Hub close failed")
	}

	child = startOwnerBootstrapHub(t, ctx, builtHubBinary, stateDir, workspaceRoot, homeDir, backendPort)
	waitOwnerBootstrapHub(t, ctx, proxy.URL, child)
	response, err := http.Post(proxy.URL+"/v2/owner/bootstrap/accept", "application/json", bytes.NewReader(firstProof))
	if err != nil {
		t.Fatal("could not check consumed proof after Root revocation")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("revoked Root's consumed proof returned a cached active receipt")
	}
	if setupAfterRestart, err := readOwnerBootstrapSetup(databasePath); err != nil || setupAfterRestart == nil || !setupAfterRestart.RootEverEstablished {
		t.Fatal("restart erased permanent Root history")
	}
	child.stop(t)
	child = nil
}

type ownerBootstrapProxyState struct {
	mu        sync.Mutex
	proofs    [][]byte
	responses [][]byte
	statuses  []int
	dropped   bool
}

func (s *ownerBootstrapProxyState) observe(proof []byte, status int, response []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proofs = append(s.proofs, append([]byte(nil), proof...))
	s.responses = append(s.responses, append([]byte(nil), response...))
	s.statuses = append(s.statuses, status)
	if !s.dropped && status == http.StatusOK {
		s.dropped = true
		return true
	}
	return false
}

func (s *ownerBootstrapProxyState) firstAccepted() (proof, response []byte, dropped bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, status := range s.statuses {
		if status == http.StatusOK {
			return append([]byte(nil), s.proofs[i]...), append([]byte(nil), s.responses[i]...), s.dropped
		}
	}
	return nil, nil, s.dropped
}

func (s *ownerBootstrapProxyState) secondAccepted() (proof, response []byte, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := 0
	for i, code := range s.statuses {
		if code == http.StatusOK {
			seen++
			if seen == 2 {
				return append([]byte(nil), s.proofs[i]...), append([]byte(nil), s.responses[i]...), code
			}
		}
	}
	return nil, nil, 0
}

func newOwnerBootstrapDropProxy(t *testing.T, upstream string, state *ownerBootstrapProxyState) *httptest.Server {
	t.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("proxy redirects disabled") }}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, 256*1024+1))
		if err != nil || len(body) > 256*1024 {
			http.Error(response, "fixture request too large", http.StatusRequestEntityTooLarge)
			return
		}
		forward, err := http.NewRequestWithContext(request.Context(), request.Method, upstream+request.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			http.Error(response, "fixture request unavailable", http.StatusBadGateway)
			return
		}
		forward.Header = request.Header.Clone()
		upstreamResponse, err := client.Do(forward)
		if err != nil {
			http.Error(response, "fixture Hub unavailable", http.StatusBadGateway)
			return
		}
		defer upstreamResponse.Body.Close()
		upstreamBody, err := io.ReadAll(io.LimitReader(upstreamResponse.Body, 512*1024))
		if err != nil {
			http.Error(response, "fixture Hub response unavailable", http.StatusBadGateway)
			return
		}
		drop := false
		if request.URL.Path == "/v2/owner/bootstrap/accept" {
			drop = state.observe(body, upstreamResponse.StatusCode, upstreamBody)
		}
		if drop {
			hijacker, ok := response.(http.Hijacker)
			if !ok {
				http.Error(response, "fixture response cannot be dropped", http.StatusBadGateway)
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				return
			}
			_ = connection.Close()
			return
		}
		for key, values := range upstreamResponse.Header {
			for _, value := range values {
				response.Header().Add(key, value)
			}
		}
		response.WriteHeader(upstreamResponse.StatusCode)
		_, _ = response.Write(upstreamBody)
	}))
	t.Cleanup(func() { transport.CloseIdleConnections() })
	return server
}

type ownerBootstrapHubChild struct {
	cmd    *exec.Cmd
	done   chan struct{}
	cancel context.CancelFunc
	mu     sync.Mutex
	err    error
}

func startOwnerBootstrapHub(t *testing.T, parent context.Context, binary, stateDir, workspaceRoot, homeDir string, port int) *ownerBootstrapHubChild {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	cmd := exec.CommandContext(ctx, binary, "serve", "--host", "127.0.0.1", "--port", strconv.Itoa(port))
	cmd.Env = []string{
		"HOME=" + homeDir,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"CICADA_STATE_DIR=" + stateDir,
		"CICADA_WORKSPACE_ROOT=" + workspaceRoot,
		"CICADA_API_TOKEN=",
		"CICADA_INTENT_PLANNER_BIN=",
		"CICADA_COMPLETION_VERIFIER_BIN=",
	}
	cmd.Stderr = io.Discard
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("could not start independent Hub binary: %v", err)
	}
	child := &ownerBootstrapHubChild{cmd: cmd, done: make(chan struct{}), cancel: cancel}
	go func() {
		child.mu.Lock()
		child.err = cmd.Wait()
		child.mu.Unlock()
		close(child.done)
	}()
	// No protocol packets or credentials are passed to child stdin or included
	// in its environment, and child output is discarded rather than buffered.
	t.Cleanup(func() { child.stop(t) })
	return child
}

func (child *ownerBootstrapHubChild) stop(t *testing.T) {
	t.Helper()
	if child == nil || child.cmd == nil {
		return
	}
	select {
	case <-child.done:
		child.cancel()
		return
	default:
	}
	if child.cmd.Process != nil {
		_ = child.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-child.done:
	case <-time.After(5 * time.Second):
		child.cancel()
		select {
		case <-child.done:
		case <-time.After(3 * time.Second):
			if child.cmd.Process != nil {
				_ = child.cmd.Process.Kill()
			}
			select {
			case <-child.done:
			case <-time.After(2 * time.Second):
				t.Fatal("independent Hub process did not stop after termination")
			}
		}
	}
	child.cancel()
}

func waitOwnerBootstrapHub(t *testing.T, ctx context.Context, origin string, child *ownerBootstrapHubChild) {
	t.Helper()
	client := &http.Client{Timeout: 1 * time.Second}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/healthz", nil)
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case <-child.done:
			child.mu.Lock()
			err := child.err
			child.mu.Unlock()
			t.Fatalf("independent Hub exited before readiness: %v", err)
		case <-ctx.Done():
			t.Fatal("independent Hub did not become ready before deadline")
		case <-ticker.C:
		}
	}
}

func newOwnerBootstrapFixtureDirs(t *testing.T) (root, state, workspace, home string) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "cicada-owner-bootstrap-")
	if err != nil {
		t.Fatal("could not create private Owner bootstrap fixture root")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatalf("could not protect Owner bootstrap fixture root: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		t.Fatal("Owner bootstrap fixture root contains a symlink")
	}
	state, workspace, home = filepath.Join(root, "hub-state"), filepath.Join(root, "workspace"), filepath.Join(root, "home")
	for _, dir := range []string{state, workspace, home} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatalf("could not create private Owner bootstrap fixture directory: %v", err)
		}
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("could not remove owned Owner bootstrap fixture directory: %v", err)
		}
	})
	return root, state, workspace, home
}

func writeOwnerBootstrapFixtureMarker(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString("disposable\n")
	closeErr := file.Close()
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	return errors.Join(writeErr, closeErr)
}

func writeOwnerBootstrapPrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	return errors.Join(writeErr, closeErr)
}

func reserveOwnerBootstrapPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("could not reserve a loopback Hub port")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal("could not release a loopback Hub port")
	}
	return port
}

func ownerBootstrapCapabilitiesHaveRole(t *testing.T, encoded []byte, role string, operations ...string) bool {
	t.Helper()
	var capabilities struct {
		Role       string   `json:"role"`
		Operations []string `json:"available_rpc_operations"`
	}
	if json.Unmarshal(encoded, &capabilities) != nil || capabilities.Role != role {
		return false
	}
	for _, required := range operations {
		if !containsHeadlessOperation(capabilities.Operations, required) {
			return false
		}
	}
	return true
}

func ownerBootstrapCapabilitiesContain(t *testing.T, encoded []byte, operations ...string) bool {
	t.Helper()
	var capabilities struct {
		Operations []string `json:"available_rpc_operations"`
	}
	if json.Unmarshal(encoded, &capabilities) != nil {
		return true
	}
	for _, expected := range operations {
		if containsHeadlessOperation(capabilities.Operations, expected) {
			return true
		}
	}
	return false
}

func ownerBootstrapTreeContains(t *testing.T, root string, needle []byte) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("Hub StateDir contains a non-regular fixture entry")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, needle) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("could not inspect owned Hub StateDir: %v", err)
	}
	return found
}

func readOwnerBootstrapSetup(path string) (*store.HubOwnerSetup, error) {
	db, err := store.New(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return db.GetHubOwnerSetup()
}
