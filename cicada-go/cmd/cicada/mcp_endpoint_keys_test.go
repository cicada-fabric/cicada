package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

type mcpEndpointKeyFixture struct {
	mcp             *mcpServer
	remote          *httptest.Server
	service         *fabric.Service
	joined          fabric.JoinResult
	joinInput       fabric.JoinInput
	requestCount    atomic.Int32
	whoamiCount     atomic.Int32
	keyGetCount     atomic.Int32
	keyPostCount    atomic.Int32
	keyAccessProbe  func()
	authorization   []string
	authorizationMu sync.Mutex
}

func TestMCPGroupEndpointKeyPublicationRespectsWriterRootExclusive(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprint(separate), func(t *testing.T) {
			fixture := newMCPEndpointKeyFixture(t)
			state := privateRecoveryTestDir(t)
			writer := state
			if separate {
				writer = privateRecoveryTestDir(t)
			}
			fixture.mcp.hubStateDir, fixture.mcp.writerRoot = state, writer
			exclusive, err := nodelock.AcquireWriterRootExclusive(writer)
			if err != nil {
				t.Fatal(err)
			}
			defer exclusive.Close()
			_, err = fixture.mcp.publishEndpointKeyCandidate(map[string]any{})
			if !errors.Is(err, nodelock.ErrBusy) {
				t.Fatalf("root exclusion bypassed: %v", err)
			}
			if _, err := os.Lstat(machineNodeStateDir(state, fixture.joinInput.NodeID)); !os.IsNotExist(err) {
				t.Fatal("blocked publication created key state")
			}
			if fixture.keyGetCount.Load() != 0 || fixture.keyPostCount.Load() != 0 {
				t.Fatal("blocked publication reached candidate paths")
			}
		})
	}
}

func TestMCPGroupEndpointKeyPublicationRejectsRecoveryBeforeKeyCreation(t *testing.T) {
	for _, hold := range []string{"node", "registration", "common-writer-root"} {
		t.Run(hold, func(t *testing.T) {
			fixture := newMCPEndpointKeyFixture(t)
			state, writer := t.TempDir(), t.TempDir()
			fixture.mcp.hubStateDir = state
			fixture.mcp.writerRoot = writer
			nodeID := fixture.joinInput.NodeID
			path := filepath.Join(machineNodeStateDir(state, nodeID), "recovery-pending.json")
			if hold == "registration" {
				path = filepath.Join(state, "nodes", ".recovery-pending", "node-"+nodeID+".json")
			}
			if hold == "common-writer-root" {
				path = filepath.Join(writer, ".writer-root-recovery-pending.json")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("synthetic malformed hold"), 0400); err != nil {
				t.Fatal(err)
			}
			before, _ := recoveryTreeDigest(state)
			writerBefore, _ := recoveryTreeDigest(writer)
			_, err := fixture.mcp.publishEndpointKeyCandidate(map[string]any{})
			if err == nil || !strings.Contains(err.Error(), "quarantine") {
				t.Fatalf("publication did not fail at quarantine: %v", err)
			}
			after, _ := recoveryTreeDigest(state)
			writerAfter, _ := recoveryTreeDigest(writer)
			if before != after || writerBefore != writerAfter || fixture.keyPostCount.Load() != 0 || fixture.keyGetCount.Load() != 0 || fixture.whoamiCount.Load() != 1 {
				t.Fatal("denial created keys or published candidate")
			}
		})
	}
}

func newMCPEndpointKeyFixture(t *testing.T) *mcpEndpointKeyFixture {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "workspace")
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "native-key-session")
	t.Setenv("CODEX_THREAD_ID", "")
	t.Setenv("CODEX_SESSION_ID", "")
	t.Setenv("CICADA_MACHINE_ID", "node-key-test")
	t.Setenv("CICADA_WORKSPACE", workspace)
	t.Setenv("CICADA_GROUP_ID", "")
	t.Setenv("CICADA_NODE_STATE_DIR", "")
	t.Setenv("CICADA_STATE_DIR", "")

	database, err := store.New(filepath.Join(t.TempDir(), "fabric.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	owner, err := database.CreatePrincipal(store.Principal{ID: "owner-key-test", Kind: store.PrincipalKindHuman,
		OwnerID: "owner-key-test", TrustDomainID: "domain-key-test", Name: "Key Test Owner", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	group, err := database.CreateGroup(store.Group{Name: "Key Test Group", OwnerPrincipalID: owner.ID,
		TrustDomainID: owner.TrustDomainID, State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(database, owner.ID, owner.TrustDomainID)
	if err != nil {
		t.Fatal(err)
	}
	joinInput := fabric.JoinInput{GroupID: group.ID, PrincipalName: "Key Test Endpoint", EndpointName: "Key Test Endpoint",
		Harness: "codex", NativeSessionID: "native-key-session", NodeID: "node-key-test", Workspace: workspace}
	joined, err := service.Join(joinInput)
	if err != nil {
		t.Fatal(err)
	}

	fixture := &mcpEndpointKeyFixture{service: service, joined: *joined, joinInput: joinInput}
	fabricHandler := server.NewFabricHandler(service, "")
	fixture.remote = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fixture.requestCount.Add(1)
		fixture.authorizationMu.Lock()
		fixture.authorization = append(fixture.authorization, request.Header.Get("Authorization"))
		fixture.authorizationMu.Unlock()
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			fixture.whoamiCount.Add(1)
		case "/v2/fabric/endpoint-keys/" + joined.Endpoint.ID:
			fixture.keyGetCount.Add(1)
			if fixture.keyAccessProbe != nil {
				fixture.keyAccessProbe()
			}
		case "/v2/fabric/endpoint-keys":
			if request.Method == http.MethodPost {
				fixture.keyPostCount.Add(1)
				if fixture.keyAccessProbe != nil {
					fixture.keyAccessProbe()
				}
			}
		}
		fabricHandler.ServeHTTP(response, request)
	}))
	t.Cleanup(fixture.remote.Close)
	fixture.mcp = newMCPServer(fixture.remote.URL, joined.Endpoint.ID, "")
	t.Cleanup(func() { close(fixture.mcp.stop) })
	context, err := harness.DetectCurrentSession()
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := normalizeMCPTrustedContext(context)
	if err != nil {
		t.Fatal(err)
	}
	scope, _, err := mcpSessionScope(fixture.remote.URL, context)
	if err != nil {
		t.Fatal(err)
	}
	public := mcpPublicJoinResult{Endpoint: joined.Endpoint, NetworkCard: joined.NetworkCard,
		BindingID: joined.BindingID, BindingEpoch: joined.BindingEpoch, LeaseExpiresAt: joined.LeaseExpiresAt}
	fixture.mcp.setSession(joined.SessionToken, joined.Endpoint.ID, joined.NetworkCard.GroupID, trusted, scope, public)
	return fixture
}

func TestMCPGroupEndpointKeyPublicationHoldsRootThroughCandidateHTTP(t *testing.T) {
	fixture := newMCPEndpointKeyFixture(t)
	root := privateRecoveryTestDir(t)
	fixture.mcp.hubStateDir, fixture.mcp.writerRoot = root, root
	var checks atomic.Int32
	fixture.keyAccessProbe = func() {
		lock, err := nodelock.AcquireWriterRootExclusive(root)
		if lock != nil {
			lock.Close()
		}
		if !errors.Is(err, nodelock.ErrBusy) {
			t.Errorf("candidate HTTP escaped shared root exclusion: %v", err)
		}
		checks.Add(1)
	}
	if _, err := fixture.mcp.publishEndpointKeyCandidate(map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if checks.Load() != 2 {
		t.Fatal("did not check both candidate GET and POST")
	}
}

func TestCicadaMCPAdvertisesEndpointKeyCandidateToolWithOnlyNetworkSelector(t *testing.T) {
	for _, tool := range cicadaMCPTools() {
		if tool["name"] != "cicada_publish_endpoint_key_candidate" {
			continue
		}
		schema, ok := tool["inputSchema"].(map[string]any)
		if !ok {
			t.Fatalf("input schema has type %T", tool["inputSchema"])
		}
		properties, ok := schema["properties"].(map[string]any)
		if !ok || len(properties) != 1 || schema["additionalProperties"] != false || properties["network_id"] == nil {
			t.Fatalf("tool accepts model-supplied identity fields: %#v", schema)
		}
		return
	}
	t.Fatal("endpoint key candidate tool was not advertised")
}

func TestCicadaPublishEndpointKeyCandidateRequiresJoinedSession(t *testing.T) {
	mcp := newMCPServer("http://127.0.0.1:1", "", "")
	t.Cleanup(func() { close(mcp.stop) })
	if _, err := mcp.callTool("cicada_publish_endpoint_key_candidate", nil); err == nil || !strings.Contains(err.Error(), "active Cicada session") {
		t.Fatalf("unjoined publication error = %v", err)
	}
}

func TestCicadaPublishEndpointKeyCandidateRejectsMismatchedNativeContext(t *testing.T) {
	fixture := newMCPEndpointKeyFixture(t)
	t.Setenv("CICADA_NATIVE_SESSION_ID", "different-native-session")
	if _, err := fixture.mcp.callTool("cicada_publish_endpoint_key_candidate", nil); err == nil || !strings.Contains(err.Error(), "different native session context") {
		t.Fatalf("mismatched native context error = %v", err)
	}
	if got := fixture.requestCount.Load(); got != 0 {
		t.Fatalf("mismatched context made %d HTTP requests", got)
	}
}

func TestCicadaPublishEndpointKeyCandidateRejectsModelSuppliedIdentity(t *testing.T) {
	fixture := newMCPEndpointKeyFixture(t)
	if _, err := fixture.mcp.callTool("cicada_publish_endpoint_key_candidate", map[string]any{"endpoint_id": "forged-endpoint"}); err == nil || !strings.Contains(err.Error(), "accepts only network_id") {
		t.Fatalf("model-supplied endpoint error = %v", err)
	}
	if got := fixture.requestCount.Load(); got != 0 {
		t.Fatalf("model-supplied identity made %d HTTP requests", got)
	}
}

func TestCicadaPublishEndpointKeyCandidateRequiresExplicitNodeStateDir(t *testing.T) {
	fixture := newMCPEndpointKeyFixture(t)
	t.Setenv("CICADA_NODE_STATE_DIR", "")
	t.Setenv("CICADA_STATE_DIR", "")
	if _, err := fixture.mcp.callTool("cicada_publish_endpoint_key_candidate", nil); err == nil || !strings.Contains(err.Error(), "requires CICADA_NODE_STATE_DIR or CICADA_STATE_DIR") {
		t.Fatalf("missing state directory error = %v", err)
	}
	if fixture.whoamiCount.Load() != 1 || fixture.keyGetCount.Load() != 0 || fixture.keyPostCount.Load() != 0 {
		t.Fatalf("unexpected requests without a configured Node state directory: whoami=%d key_get=%d key_post=%d",
			fixture.whoamiCount.Load(), fixture.keyGetCount.Load(), fixture.keyPostCount.Load())
	}
}

func TestCicadaPublishEndpointKeyCandidateRegistersAndRepeatsSafely(t *testing.T) {
	fixture := newMCPEndpointKeyFixture(t)
	t.Setenv("CICADA_NODE_STATE_DIR", privateRecoveryTestDir(t))
	first, err := fixture.mcp.callTool("cicada_publish_endpoint_key_candidate", nil)
	if err != nil {
		t.Fatal(err)
	}
	firstResult, ok := first.(mcpEndpointKeyCandidateResult)
	if !ok || firstResult.EndpointID != fixture.joined.Endpoint.ID || firstResult.CandidateStatus != store.EndpointKeyCandidateStateCandidate || firstResult.CandidateVersion != 1 {
		t.Fatalf("first registration result = %#v", first)
	}
	second, err := fixture.mcp.callTool("cicada_publish_endpoint_key_candidate", nil)
	if err != nil {
		t.Fatal(err)
	}
	secondResult, ok := second.(mcpEndpointKeyCandidateResult)
	if !ok || secondResult != firstResult {
		t.Fatalf("idempotent repeat result = %#v, first = %#v", second, firstResult)
	}
	if fixture.keyPostCount.Load() != 2 || fixture.keyGetCount.Load() != 2 || fixture.whoamiCount.Load() != 2 {
		t.Fatalf("registration requests whoami=%d key_get=%d key_post=%d", fixture.whoamiCount.Load(), fixture.keyGetCount.Load(), fixture.keyPostCount.Load())
	}

	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 5 {
		t.Fatalf("result contains fields outside the public summary: %s", encoded)
	}
	for _, forbidden := range []string{"proof", "attestation", "private_identity", "kem_private", "session_token", fixture.joined.SessionToken} {
		if strings.Contains(strings.ToLower(string(encoded)), strings.ToLower(forbidden)) {
			t.Fatalf("result exposed %q: %s", forbidden, encoded)
		}
	}
	for _, key := range []string{"endpoint_id", "key_id", "fingerprint", "candidate_status", "candidate_version"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("result omitted %q: %s", key, encoded)
		}
	}

	actor, err := fixture.service.Authenticate(fixture.joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := fixture.service.EndpointKeyCandidate(actor, fixture.joined.Endpoint.ID)
	if err != nil || candidate.KeyID != firstResult.KeyID || candidate.BindingEpoch != fixture.joined.BindingEpoch {
		t.Fatalf("stored candidate = %#v, err = %v", candidate, err)
	}
	verified, err := e2ee.VerifyEndpointKeyAttestation(candidate.Proof, fixture.joined.Endpoint.ID,
		fixture.joined.NetworkCard.PrincipalID, fixture.joined.NetworkCard.NodeID,
		fixture.joined.BindingID, fixture.joined.BindingEpoch)
	if err != nil || verified.ID != firstResult.KeyID {
		t.Fatalf("stored proof does not bind current session: key=%q err=%v", verified.ID, err)
	}
	fixture.assertSessionAuthorization(t, fixture.joined.SessionToken)
}

func TestCicadaPublishEndpointKeyCandidateWaitsForOfflineMaintenance(t *testing.T) {
	fixture := newMCPEndpointKeyFixture(t)
	stateDir := privateRecoveryTestDir(t)
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	offline, err := nodelock.AcquireMaintenanceExclusive(stateDir, fixture.joined.NetworkCard.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer offline.Close()

	done := make(chan error, 1)
	go func() {
		_, err := fixture.mcp.callTool("cicada_publish_endpoint_key_candidate", nil)
		done <- err
	}()

	deadline := time.After(5 * time.Second)
	for fixture.whoamiCount.Load() == 0 {
		select {
		case err := <-done:
			t.Fatalf("Endpoint key publication completed before reaching its Node write: %v", err)
		case <-deadline:
			t.Fatalf("Endpoint key publication did not reach the Node write: requests=%d whoami=%d key_get=%d",
				fixture.requestCount.Load(), fixture.whoamiCount.Load(), fixture.keyGetCount.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
	select {
	case err := <-done:
		t.Fatalf("Endpoint key publication bypassed exclusive maintenance: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := os.Stat(machineNodeStateDir(stateDir, fixture.joined.NetworkCard.NodeID)); !os.IsNotExist(err) {
		t.Fatalf("blocked Endpoint key writer created the Node subtree: %v", err)
	}
	if err := offline.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Endpoint key publication failed after maintenance ended: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Endpoint key publication did not resume after maintenance ended")
	}
	if _, err := os.Stat(machineNodeStateDir(stateDir, fixture.joined.NetworkCard.NodeID)); err != nil {
		t.Fatalf("Endpoint key writer did not create its Node subtree after unlocking: %v", err)
	}
}

func TestCicadaPublishEndpointKeyCandidateRejoinRefreshesSameNodeKey(t *testing.T) {
	fixture := newMCPEndpointKeyFixture(t)
	t.Setenv("CICADA_NODE_STATE_DIR", privateRecoveryTestDir(t))
	first, err := fixture.mcp.callTool("cicada_publish_endpoint_key_candidate", nil)
	if err != nil {
		t.Fatal(err)
	}
	firstResult := first.(mcpEndpointKeyCandidateResult)

	rejoined, err := fixture.service.Join(fixture.joinInput)
	if err != nil {
		t.Fatal(err)
	}
	if rejoined.Endpoint.ID != fixture.joined.Endpoint.ID || rejoined.BindingEpoch <= fixture.joined.BindingEpoch {
		t.Fatalf("rejoin did not preserve Endpoint and rotate binding: first=%#v rejoined=%#v", fixture.joined, rejoined)
	}
	context, err := harness.DetectCurrentSession()
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := normalizeMCPTrustedContext(context)
	if err != nil {
		t.Fatal(err)
	}
	scope, _, err := mcpSessionScope(fixture.remote.URL, context)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mcp.setSession(rejoined.SessionToken, rejoined.Endpoint.ID, rejoined.NetworkCard.GroupID, trusted, scope,
		mcpPublicJoinResult{Endpoint: rejoined.Endpoint, NetworkCard: rejoined.NetworkCard,
			BindingID: rejoined.BindingID, BindingEpoch: rejoined.BindingEpoch, LeaseExpiresAt: rejoined.LeaseExpiresAt})
	second, err := fixture.mcp.callTool("cicada_publish_endpoint_key_candidate", nil)
	if err != nil {
		t.Fatal(err)
	}
	secondResult := second.(mcpEndpointKeyCandidateResult)
	if secondResult.KeyID != firstResult.KeyID || secondResult.Fingerprint != firstResult.Fingerprint || secondResult.CandidateVersion <= firstResult.CandidateVersion {
		t.Fatalf("rejoin did not refresh the same Node key: first=%#v second=%#v", firstResult, secondResult)
	}
	actor, err := fixture.service.Authenticate(rejoined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := fixture.service.EndpointKeyCandidate(actor, rejoined.Endpoint.ID)
	if err != nil || candidate.BindingID != rejoined.BindingID || candidate.BindingEpoch != rejoined.BindingEpoch {
		t.Fatalf("refreshed candidate = %#v, err = %v", candidate, err)
	}
	fixture.assertSessionAuthorization(t, fixture.joined.SessionToken, rejoined.SessionToken)
}

func TestCicadaPublishEndpointKeyCandidateFailsClosedOnHubKeyMismatch(t *testing.T) {
	fixture := newMCPEndpointKeyFixture(t)
	t.Setenv("CICADA_NODE_STATE_DIR", privateRecoveryTestDir(t))
	otherIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := otherIdentity.SignEndpointKeyAttestation(fixture.joined.Endpoint.ID,
		fixture.joined.NetworkCard.PrincipalID, fixture.joined.NetworkCard.NodeID,
		fixture.joined.BindingID, fixture.joined.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := fixture.service.Authenticate(fixture.joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	preexisting, err := fixture.service.RegisterEndpointKeyCandidate(actor, proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.mcp.callTool("cicada_publish_endpoint_key_candidate", nil); err == nil || !strings.Contains(err.Error(), "different public key candidate") {
		t.Fatalf("mismatched Hub candidate error = %v", err)
	}
	if fixture.keyPostCount.Load() != 0 {
		t.Fatalf("mismatch path attempted %d candidate registrations", fixture.keyPostCount.Load())
	}
	current, err := fixture.service.EndpointKeyCandidate(actor, fixture.joined.Endpoint.ID)
	if err != nil || current.KeyID != preexisting.KeyID {
		t.Fatalf("mismatch path replaced Hub candidate: current=%#v err=%v", current, err)
	}
	fixture.assertSessionAuthorization(t, fixture.joined.SessionToken)
}

func (f *mcpEndpointKeyFixture) assertSessionAuthorization(t *testing.T, sessionTokens ...string) {
	t.Helper()
	f.authorizationMu.Lock()
	defer f.authorizationMu.Unlock()
	if len(f.authorization) == 0 {
		t.Fatal("tool made no authenticated Fabric requests")
	}
	allowed := make(map[string]bool, len(sessionTokens))
	for _, token := range sessionTokens {
		allowed["CicadaSession "+token] = true
	}
	for _, got := range f.authorization {
		if !allowed[got] {
			t.Fatalf("Fabric request authorization = %q, want current session credential", got)
		}
	}
}
