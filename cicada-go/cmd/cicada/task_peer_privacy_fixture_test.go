package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/harness"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

func newTaskPeerPrivacyFixture(t *testing.T) *localGroupFailureFixture {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	f := newLocalGroupFailureFixture(t)
	for _, m := range []*mcpServer{f.sourceMCP, f.targetMCP} {
		membership, err := f.store.GetMembershipByPrincipalGroup(m.sessionPublic.NetworkCard.PrincipalID, f.groupID)
		if err != nil {
			t.Fatal(err)
		}
		grants := append(append([]string(nil), membership.Grants...), "task.read", "task.claim", "task.submit", "task.verify", "artifact.read")
		if _, err = f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles, grants, membership.Authorization, membership.Version); err != nil {
			t.Fatal(err)
		}
	}
	authorizeSameNodeRelayFixture(t, f, f.sourceMCP, f.targetMCP)
	service, err := fabric.NewService(f.store, f.ownerID, f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	f.hub.Config.Handler = serverpkg.NewFabricHandler(service, "")
	return f
}
func selectPrivacySession(t *testing.T, m *mcpServer) {
	t.Helper()
	t.Setenv("CODEX_THREAD_ID", m.sessionContext.NativeSessionID)
	t.Setenv("CODEX_SESSION_ID", "session-"+m.sessionContext.NativeSessionID)
}
func readPrivacyTask(t *testing.T, f *localGroupFailureFixture, id string) *store.SharedTask {
	t.Helper()
	task, err := f.store.GetSharedTask(id)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

// This exercises current authorization, crypto/replay and Inbox.Save only.
// No native queue/model is called and no injection receipt is fabricated.
func deliverPrivacyCandidate(t *testing.T, f *localGroupFailureFixture, receiver *mcpServer, messageID string) []byte {
	t.Helper()
	actor := taskRelayActor(t, f, receiver)
	claims, err := f.store.ClaimSameGroupSealedV1Inbox(fabric.HashSessionCredential(f.nodeToken), store.RelayClaimInput{RecipientEndpointID: actor.EndpointID, ConsumerID: "synthetic_privacy_receiver", BindingID: actor.BindingID, BindingEpoch: actor.BindingEpoch, Limit: 16})
	if err != nil {
		t.Fatal(err)
	}
	var chosen *store.RelaySealedV1DeliveryAttempt
	for i := range claims {
		if claims[i].MessageID == messageID {
			chosen = &claims[i]
			break
		}
	}
	if chosen == nil {
		t.Fatal("registered message has no ordinary Relay candidate")
	}
	authorization, err := f.store.AuthorizeClaimedSameGroupSealedV1Delivery(fabric.HashSessionCredential(f.nodeToken), chosen.MessageID, chosen.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(authorization)
	var current crossNodeGroupDeliveryAuthorization
	if json.Unmarshal(encoded, &current) != nil {
		t.Fatal("invalid current route")
	}
	delivery := fabric.NodeSealedDelivery{RelaySealedV1DeliveryAttempt: *chosen, Harness: "codex", NativeSessionID: receiver.sessionContext.NativeSessionID, NodeID: f.nodeID}
	opened, err := openMachineCrossNodeGroupDelivery(f.bridgeCtx, f.stateDir, f.nodeID, delivery, current)
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := nodeinbox.Open(machineNodeInboxPath(f.stateDir, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	route, err := machineSealedNodeInboxRoute(chosen.Route, messageID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = inbox.Save(context.Background(), nodeinbox.Message{MessageID: messageID, Digest: chosen.Digest, EndpointID: actor.EndpointID, SessionID: receiver.sessionContext.NativeSessionID, BindingEpoch: actor.BindingEpoch, GroupID: f.groupID, Route: route, Payload: opened.Plaintext}); err != nil {
		t.Fatal(err)
	}
	return opened.Plaintext
}
func decodePrivacyRegisteredRef(t *testing.T, result any) store.SharedTaskSealedRef {
	t.Helper()
	public, ok := result.(map[string]any)
	if !ok || public["task_authority"] != "REGISTERED" {
		t.Fatal("ordinary SEND was not formally registered")
	}
	encoded, _ := json.Marshal(public["registered_ref"])
	var ref store.SharedTaskSealedRef
	if json.Unmarshal(encoded, &ref) != nil || ref.MessageID == "" {
		t.Fatal("missing current registered ref")
	}
	return ref
}

func TestTaskPeerPrivacyHTTPMCPSealedReferenceLostReplyRestartAndAccept(t *testing.T) {
	f := newTaskPeerPrivacyFixture(t)
	const objective = "SYNTHETIC_PRIVATE_TASK_OBJECTIVE_SENTINEL"
	const criteria = "SYNTHETIC_PRIVATE_TASK_CRITERIA_SENTINEL"
	const summary = "SYNTHETIC_PRIVATE_TASK_RESULT_SENTINEL"
	task, err := f.store.CreateSharedTaskPeerShell(f.groupID, "synthetic-manager-bearer", store.SharedTaskPeerShellInput{PublisherEndpointID: f.targetMCP.endpointID, ResultRecipientEndpointID: f.targetMCP.endpointID})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(f.store, f.ownerID, f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	handler := serverpkg.NewFabricHandler(service, "")
	var mu sync.Mutex
	lostReply, privateSeen := true, false
	registrations := 0
	f.hub.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		mu.Lock()
		for _, secret := range []string{objective, criteria, summary} {
			privateSeen = privateSeen || bytes.Contains(body, []byte(secret))
		}
		isRegistration := r.Method == http.MethodPost && r.URL.Path == "/v2/fabric/tasks/sealed-reference"
		lose := isRegistration && lostReply
		if isRegistration {
			registrations++
			if lostReply {
				lostReply = false
			}
		}
		mu.Unlock()
		if lose {
			// Candidate receipt arrives before formal registration; neither business
			// CAS nor result authority may have advanced merely through sealed SEND.
			before := readPrivacyTask(t, f, task.ID)
			if before.Revision != task.Revision || before.Status != task.Status {
				t.Error("early candidate advanced Task CAS")
			}
			record := httptest.NewRecorder()
			handler.ServeHTTP(record, r)
			if record.Code != http.StatusAccepted {
				t.Errorf("formal registration failed: %d", record.Code)
			}
			http.Error(w, "synthetic lost durable registration response", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	})
	selectPrivacySession(t, f.targetMCP)
	definitionArgs := map[string]any{"task_id": task.ID, "expected_revision": task.Revision, "owner_epoch": task.OwnerEpoch, "assignment_version": int64(1), "content_version": int64(1), "target_endpoint_id": f.sourceMCP.endpointID, "objective": objective, "acceptance_criteria": criteria, "artifact_refs": []any{}, "idempotency_key": "synthetic-definition-operation"}
	if _, err = f.targetMCP.callTool("cicada_task_define", definitionArgs); err == nil {
		t.Fatal("lost registration reply was not observed")
	}
	before := readPrivacyTask(t, f, task.ID)
	sent, err := f.targetMCP.callTool("cicada_task_define", definitionArgs)
	if err != nil {
		t.Fatal(err)
	}
	def := decodePrivacyRegisteredRef(t, sent)
	if after := readPrivacyTask(t, f, task.ID); !reflect.DeepEqual(before, after) {
		t.Fatal("definition receipt recovery advanced CAS")
	}
	for _, secret := range []string{objective, criteria, summary} {
		encoded, _ := json.Marshal(sent)
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("private body entered public outbox receipt")
		}
	}
	changed := map[string]any{}
	for k, v := range definitionArgs {
		changed[k] = v
	}
	changed["target_endpoint_id"] = f.targetMCP.endpointID
	if _, err = f.targetMCP.callTool("cicada_task_define", changed); err == nil {
		t.Fatal("immutable operation retargeted")
	}
	plaintext := deliverPrivacyCandidate(t, f, f.sourceMCP, def.MessageID)
	if !bytes.Contains(plaintext, []byte(objective)) {
		t.Fatal("exact reader could not open definition")
	}
	wrong, err := nodekeys.LoadExisting(machineNodeStateDir(f.stateDir, f.nodeID), f.targetMCP.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.store.GetRelaySealedV1(def.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	var envelope e2ee.EndpointMessageEnvelope
	if json.Unmarshal(record.Ciphertext, &envelope) != nil {
		t.Fatal("invalid envelope")
	}
	sender, err := nodekeys.LoadExisting(machineNodeStateDir(f.stateDir, f.nodeID), f.targetMCP.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = e2ee.OpenEndpointMessage(wrong, sender.Public(), envelope.Context, record.Ciphertext); err == nil {
		t.Fatal("nonreader decrypted Task definition")
	}
	selectPrivacySession(t, f.sourceMCP)
	body, err := f.sourceMCP.callTool("cicada_task_body", map[string]any{"task_id": task.ID, "message_id": def.MessageID})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(body)
	if !bytes.Contains(encoded, []byte(objective)) {
		t.Fatal("formal typed body unavailable")
	}
	task, err = f.store.ReadySharedTask(task.ID, task.Revision, "synthetic-manager-bearer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.sourceMCP.callTool("cicada_task_claim", map[string]any{"task_id": task.ID, "expected_revision": task.Revision, "idempotency_key": "synthetic-worker-claim", "lease_seconds": 600}); err != nil {
		t.Fatal(err)
	}
	task = readPrivacyTask(t, f, task.ID)
	artifact, err := f.store.CreateArtifact(store.Artifact{ID: "artifact_synthetic_privacy", Name: "synthetic evidence", Path: "synthetic/evidence", Digest: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := f.store.CreateArtifactRefV2(store.ArtifactRefV2Input{ID: "ref_synthetic_privacy", ArtifactID: artifact.ID, GroupID: f.groupID, Digest: strings.Repeat("b", 64), Scopes: []string{store.ArtifactRefV2ScopeMetadata, store.ArtifactRefV2ScopeDigest}})
	if err != nil {
		t.Fatal(err)
	}
	resultArgs := map[string]any{"task_id": task.ID, "expected_revision": task.Revision, "owner_epoch": task.OwnerEpoch, "assignment_version": int64(1), "content_version": int64(1), "summary": summary, "artifact_refs": []store.SharedTaskArtifactRef{{ArtifactRefID: evidence.ID, Version: evidence.Version, Digest: evidence.Digest, Scopes: []string{store.ArtifactRefV2ScopeMetadata, store.ArtifactRefV2ScopeDigest}}}, "idempotency_key": "synthetic-result-operation"}
	result, err := f.sourceMCP.callTool("cicada_task_submit", resultArgs)
	if err != nil {
		t.Fatal(err)
	}
	resultRef := decodePrivacyRegisteredRef(t, result)
	state := readPrivacyTask(t, f, task.ID)
	if state.Status != store.SharedTaskResultSubmitted || state.Revision != task.Revision+1 {
		t.Fatal("formal result did not apply exact business CAS")
	}
	if err = f.restartBridge(); err != nil {
		t.Fatal(err)
	}
	// Restart only the fixture Node bridge process state; the original immutable
	// encrypted outbox and replay state are retained, never reset.
	again, err := f.sourceMCP.callTool("cicada_task_submit", resultArgs)
	if err != nil || decodePrivacyRegisteredRef(t, again).MessageID != resultRef.MessageID {
		t.Fatal("original result retry failed after bridge restart", err)
	}
	if !reflect.DeepEqual(state, readPrivacyTask(t, f, task.ID)) {
		t.Fatal("retry advanced responsibility twice")
	}
	deliverPrivacyCandidate(t, f, f.targetMCP, resultRef.MessageID)
	selectPrivacySession(t, f.targetMCP)
	accepted, err := f.targetMCP.callTool("cicada_task_accept", map[string]any{"task_id": task.ID, "result_id": resultRef.ResultID, "expected_revision": state.Revision})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(accepted)
	if bytes.Contains(encoded, []byte(summary)) || bytes.Contains(encoded, []byte(objective)) || bytes.Contains(encoded, []byte(criteria)) {
		t.Fatal("accept peer response exposed prose")
	}
	if readPrivacyTask(t, f, task.ID).Status != store.SharedTaskCompleted {
		t.Fatal("formal result acceptance did not complete Task")
	}
	mu.Lock()
	seen, count := privateSeen, registrations
	mu.Unlock()
	if seen || count < 4 {
		t.Fatal("Hub saw new Task prose or missing actual registration retries")
	}
}

func newTaskPeerPrivacyManagedBase(t *testing.T) (*localGroupFailureFixture, *control.Control) {
	t.Helper()
	f := &localGroupFailureFixture{
		stateDir: shortLocalJoinStateDir(t),
		groupID:  "group_local_failure",
		ownerID:  "owner_local_failure",
		nodeID:   "node_local_failure",
		nativeA:  "native_local_failure_a",
		nativeB:  "native_local_failure_b",
	}
	var err error
	f.workspace, err = os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	writeCodexSessionRecord(t, codexHome, f.nativeA, f.workspace)
	writeCodexSessionRecord(t, codexHome, f.nativeB, f.workspace)
	hubStateDir := filepath.Join(t.TempDir(), "hub-state")
	manager, err := control.New(control.Config{StateDir: hubStateDir, WorkspaceRoot: filepath.Join(t.TempDir(), "workspace"), APIToken: "synthetic-task-manager-bearer"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Shutdown(context.Background()) })
	f.store, err = store.New(filepath.Join(hubStateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.bridge != nil {
			_ = f.bridge.Close()
		}
		if f.bridgeCancel != nil {
			f.bridgeCancel()
		}
		if f.hub != nil {
			f.hub.Close()
		}
		if f.store != nil {
			_ = f.store.Close()
		}
		if f.nativeHistory != nil {
			_ = f.nativeHistory.Close()
		}
	})
	owner, err := f.store.CreatePrincipal(store.Principal{
		ID: f.ownerID, Kind: store.PrincipalKindHuman, OwnerID: f.ownerID,
		TrustDomainID: f.ownerID, Name: "Local failure-test owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateGroup(store.Group{
		ID: f.groupID, Name: "Local failure-test Group", OwnerPrincipalID: owner.ID,
		TrustDomainID: f.ownerID, State: store.GroupStateActive,
	}); err != nil {
		t.Fatal(err)
	}
	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := f.store.RegisterOwnerApprovalKeyLocal(f.ownerID, ownerIdentity.Public())
	if err != nil {
		t.Fatal(err)
	}
	clientIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "client_" + f.nodeID
	hubID, err := f.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	f.hubID = hubID
	now := time.Now().UTC()
	grant, err := ownerIdentity.SignOwnerDeviceGrant(f.ownerID, deviceID,
		clientIdentity.Public(), hubID, e2ee.OwnerDevicePurposeControl,
		now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: f.ownerID, OwnerKeyID: ownerKey.KeyID, DeviceID: deviceID,
		DevicePublic: clientIdentity.Public(), OwnerDeviceGrant: grant,
	}); err != nil {
		t.Fatal(err)
	}
	f.nodeToken, _, err = fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	codeSum := sha256.Sum256([]byte("local-failure-device-code"))
	codeDigest := hex.EncodeToString(codeSum[:])
	if _, err := f.store.CreatePendingNodeDeviceBinding(f.nodeID, f.nodeID,
		fabric.HashSessionCredential(f.nodeToken), codeDigest, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ConfirmPendingNodeDeviceBinding(f.ownerID, deviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(f.store, f.ownerID, f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	fabricHandler := serverpkg.NewFabricHandler(service, "")
	allowed := map[string]bool{
		"/v2/fabric/node/join":                                      true,
		"/v2/fabric/whoami":                                         true,
		"/v2/fabric/endpoint-keys":                                  true,
		"/v2/fabric/resolve":                                        true,
		"/v2/relay/nodes/" + f.nodeID + "/local/authorize":          true,
		"/v2/relay/nodes/" + f.nodeID + "/local/revalidate":         true,
		"/v2/relay/nodes/" + f.nodeID + "/group/broadcast/snapshot": true,
	}
	f.hub = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/relay/nodes/"+f.nodeID+"/local/revalidate" &&
			f.failNextGuard.CompareAndSwap(true, false) {
			http.Error(response, "temporary Guard outage", http.StatusServiceUnavailable)
			return
		}
		if !allowed[request.URL.Path] && !strings.HasPrefix(request.URL.Path, "/v2/relay/nodes/"+f.nodeID+"/group/sealed/") {
			t.Errorf("failure harness attempted unsupported Hub path %s", request.URL.Path)
			http.NotFound(response, request)
			return
		}
		fabricHandler.ServeHTTP(response, request)
	}))
	f.nativeHistory, err = nodeinbox.OpenNativeContextRegistry(filepath.Join(f.stateDir, "native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	f.bridgeCtx, f.bridgeCancel = context.WithCancel(f.machineContextForNode(f.nodeID, f.nodeToken))
	if err := f.restartBridge(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_NODE_STATE_DIR", f.stateDir)
	t.Setenv("CICADA_WORKSPACE", f.workspace)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CICADA_MACHINE_ID", f.nodeID)
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	f.sourceMCP = f.joinSession(t, f.nativeA)
	f.targetMCP = f.joinSession(t, f.nativeB)
	return f, manager
}

// Only this test binary exposes fixture control. Production server/Node/CLI
// binaries have no fixture routes, bootstrap export or fault injection.
type taskPrivacySessionFixture struct {
	Token   string              `json:"token"`
	Context mcpTrustedContext   `json:"context"`
	Public  mcpPublicJoinResult `json:"public"`
}
type taskPrivacyProcessFixture struct {
	Origin    string                      `json:"origin"`
	HubID     string                      `json:"hub_id"`
	OwnerID   string                      `json:"owner_id"`
	GroupID   string                      `json:"group_id"`
	NodeID    string                      `json:"node_id"`
	NodeToken string                      `json:"node_token"`
	Tasks     []string                    `json:"tasks"`
	Artifact  store.SharedTaskArtifactRef `json:"artifact"`
	Source    taskPrivacySessionFixture   `json:"source"`
	Target    taskPrivacySessionFixture   `json:"target"`
}

func privacyFixtureHTTP(t *testing.T, handler http.Handler, method, path, authorization string, input any, status int) []byte {
	t.Helper()
	data, _ := json.Marshal(input)
	request := httptest.NewRequest(method, path, bytes.NewReader(data))
	request.Header.Set("Authorization", authorization)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != status {
		t.Fatalf("synthetic management/fixture route %s returned %d", path, response.Code)
	}
	return response.Body.Bytes()
}
func copyPrivacyFixtureTree(t *testing.T, source, target string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("fixture copy refuses links")
		}
		if info.IsDir() {
			return os.MkdirAll(destination, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return nil
		} // closed initial Unix socket is not copied
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, data, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestTaskPeerPrivacyIsolatedHubFixture(t *testing.T) {
	if os.Getenv("CICADA_TASK_PRIVACY_FIXTURE_ROLE") != "hub" {
		t.Skip("isolated Docker fixture only")
	}
	nodeRoot := os.Getenv("CICADA_TASK_PRIVACY_NODE_ROOT")
	publicRoot := os.Getenv("CICADA_TASK_PRIVACY_PUBLIC_ROOT")
	if nodeRoot == "" || publicRoot == "" {
		t.Fatal("fixture private/public mounts missing")
	}
	f, manager := newTaskPeerPrivacyManagedBase(t)
	for _, m := range []*mcpServer{f.sourceMCP, f.targetMCP} {
		member, err := f.store.GetMembershipByPrincipalGroup(m.sessionPublic.NetworkCard.PrincipalID, f.groupID)
		if err != nil {
			t.Fatal(err)
		}
		grants := append(append([]string(nil), member.Grants...), "task.read", "task.claim", "task.submit", "task.verify", "artifact.read")
		if _, err = f.store.UpdateMembershipAuthorization(member.ID, member.Roles, grants, member.Authorization, member.Version); err != nil {
			t.Fatal(err)
		}
	}
	authorizeSameNodeRelayFixture(t, f, f.sourceMCP, f.targetMCP)
	service, err := fabric.NewService(f.store, f.ownerID, f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	peer := serverpkg.NewFabricHandler(service, "")
	management := serverpkg.NewHandler(manager)
	combined := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/groups/") {
			management.ServeHTTP(w, r)
		} else {
			peer.ServeHTTP(w, r)
		}
	})
	cfg := taskPrivacyProcessFixture{Origin: "http://task-privacy-hub.localhost:8787", HubID: f.hubID, OwnerID: f.ownerID, GroupID: f.groupID, NodeID: f.nodeID, NodeToken: f.nodeToken}
	shellInput := store.SharedTaskPeerShellInput{PublisherEndpointID: f.targetMCP.endpointID, ResultRecipientEndpointID: f.targetMCP.endpointID}
	for i := 0; i < 2; i++ {
		path := "/v1/groups/" + f.groupID + "/tasks/peer-shell"
		// A valid native peer credential cannot select the management entrance.
		privacyFixtureHTTP(t, combined, http.MethodPost, path, "CicadaSession "+f.sourceMCP.sessionToken, shellInput, http.StatusUnauthorized)
		data := privacyFixtureHTTP(t, combined, http.MethodPost, path, "Bearer synthetic-task-manager-bearer", shellInput, http.StatusCreated)
		var task store.SharedTask
		if json.Unmarshal(data, &task) != nil || task.Objective != "" || task.AcceptanceCriteria != "" {
			t.Fatal("management shell is not metadata only")
		}
		data = privacyFixtureHTTP(t, combined, http.MethodPost, "/v1/groups/"+f.groupID+"/tasks/"+task.ID+"/ready", "Bearer synthetic-task-manager-bearer", map[string]any{"expected_revision": task.Revision}, http.StatusOK)
		if json.Unmarshal(data, &task) != nil || task.Status != store.SharedTaskReady {
			t.Fatal("metadata shell not READY")
		}
		cfg.Tasks = append(cfg.Tasks, task.ID)
	}
	artifact, err := f.store.CreateArtifact(store.Artifact{ID: "artifact_privacy_process", Name: "synthetic evidence", Path: "synthetic/evidence", Digest: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.store.CreateArtifactRefV2(store.ArtifactRefV2Input{ID: "ref_privacy_process", ArtifactID: artifact.ID, GroupID: f.groupID, Digest: strings.Repeat("b", 64), Scopes: []string{store.ArtifactRefV2ScopeMetadata, store.ArtifactRefV2ScopeDigest}})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Artifact = store.SharedTaskArtifactRef{ArtifactRefID: ref.ID, Version: ref.Version, Digest: ref.Digest, Scopes: []string{store.ArtifactRefV2ScopeMetadata, store.ArtifactRefV2ScopeDigest}}
	cfg.Source = taskPrivacySessionFixture{f.sourceMCP.sessionToken, f.sourceMCP.sessionContext, f.sourceMCP.sessionPublic}
	cfg.Target = taskPrivacySessionFixture{f.targetMCP.sessionToken, f.targetMCP.sessionContext, f.targetMCP.sessionPublic}
	if err = f.bridge.Close(); err != nil {
		t.Fatal(err)
	}
	f.bridge = nil
	if err = f.nativeHistory.Close(); err != nil {
		t.Fatal(err)
	}
	f.nativeHistory = nil
	copyPrivacyFixtureTree(t, f.stateDir, filepath.Join(nodeRoot, "state"))
	copyPrivacyFixtureTree(t, os.Getenv("CODEX_HOME"), filepath.Join(nodeRoot, "codex"))
	encoded, _ := json.Marshal(cfg)
	if err = os.WriteFile(filepath.Join(nodeRoot, "config.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	var stopOnce sync.Once
	var lost atomic.Bool
	lost.Store(true)
	var privateSeen atomic.Bool
	state := func(id string) any {
		task, err := f.store.GetSharedTask(id)
		if err != nil {
			return map[string]any{"error": "unknown synthetic Task"}
		}
		return store.ProjectSharedTaskPeer(task)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/__fixture/") {
			if r.Header.Get("Authorization") != "CicadaFixture "+cfg.NodeToken {
				http.Error(w, "fixture authorization required", 403)
				return
			}
			switch r.URL.Path {
			case "/__fixture/state":
				json.NewEncoder(w).Encode(map[string]any{"tasks": []any{state(cfg.Tasks[0]), state(cfg.Tasks[1])}, "private_prose_absent": !privateSeen.Load()})
			case "/__fixture/revoke":
				if _, err := f.store.RevokeMembershipForPrincipalGroup(f.targetMCP.sessionPublic.NetworkCard.PrincipalID, f.groupID, "synthetic privacy negative fixture"); err != nil {
					http.Error(w, "synthetic revocation failed", 500)
					return
				}
				json.NewEncoder(w).Encode(map[string]bool{"revoked": true})
			case "/__fixture/stop":
				json.NewEncoder(w).Encode(map[string]bool{"stopped": true})
				stopOnce.Do(func() { close(stopped) })
			default:
				http.NotFound(w, r)
			}
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20+1))
		if err != nil || len(body) > 2<<20 {
			http.Error(w, "fixture bound", 400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		for _, secret := range []string{"SYNTHETIC_PRIVATE_TASK_OBJECTIVE_SENTINEL", "SYNTHETIC_PRIVATE_TASK_CRITERIA_SENTINEL", "SYNTHETIC_PRIVATE_TASK_RESULT_SENTINEL"} {
			if bytes.Contains(body, []byte(secret)) {
				privateSeen.Store(true)
			}
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v2/fabric/tasks/sealed-reference" && lost.CompareAndSwap(true, false) {
			record := httptest.NewRecorder()
			combined.ServeHTTP(record, r)
			if record.Code != http.StatusAccepted {
				t.Error("fixture initial registration failed")
			}
			http.Error(w, "synthetic lost durable registration response", 503)
			return
		}
		combined.ServeHTTP(w, r)
	})
	listener, err := net.Listen("tcp", "0.0.0.0:8787")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	go server.Serve(listener)
	ready, _ := json.Marshal(map[string]any{"ready": true, "management_peer_credentials_denied": true, "metadata_shell_via_manager_http": true, "port": 8787})
	if err = os.WriteFile(filepath.Join(publicRoot, "hub-ready.json"), ready, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(8 * time.Minute):
		t.Fatal("bounded fixture timed out")
	}
	report, _ := json.Marshal(map[string]any{"private_prose_absent_in_http": !privateSeen.Load(), "manager_http_shell": true, "peer_management_denied": true, "native_runtime": "NOT_RUN"})
	if err = os.WriteFile(filepath.Join(publicRoot, "hub-report.json"), report, 0600); err != nil {
		t.Fatal(err)
	}
	if privateSeen.Load() {
		t.Fatal("Hub received new peer Task prose")
	}
}

type taskPrivacySavedPhase struct {
	ResultArgs map[string]any            `json:"result_args"`
	Result     store.SharedTaskSealedRef `json:"result"`
}

func privacyCLI(t *testing.T, cfg taskPrivacyProcessFixture, session taskPrivacySessionFixture, name string, args map[string]any) (any, error) {
	t.Helper()
	root := os.Getenv("CICADA_TASK_PRIVACY_NODE_ROOT")
	binary := os.Getenv("CICADA_TASK_PRIVACY_CLI")
	if binary == "" {
		return nil, errors.New("production CLI fixture binary missing")
	}
	nativeContext := harness.SessionContext{Harness: session.Context.Harness, NativeSessionID: session.Context.NativeSessionID, MachineID: session.Context.NodeID, Workspace: session.Context.Workspace}
	scope, _, err := mcpSessionScope(cfg.Origin, nativeContext)
	if err != nil {
		return nil, err
	}
	statePath := filepath.Join(root, "mcp", "sessions.json")
	cached := mcpCachedSession{Scope: scope, APIOrigin: cfg.Origin, Harness: nativeContext.Harness, NativeSessionID: nativeContext.NativeSessionID, NodeID: nativeContext.MachineID, Workspace: nativeContext.Workspace, GroupID: cfg.GroupID, EndpointID: session.Public.Endpoint.ID, OwnerID: cfg.OwnerID, BindingID: session.Public.BindingID, BindingEpoch: session.Public.BindingEpoch, LeaseExpiresAt: session.Public.LeaseExpiresAt, SessionToken: session.Token}
	if err = newMCPSessionStateStore(statePath).save(cached); err != nil {
		return nil, err
	}
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
	request, _ := json.Marshal(mcpRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})
	commandContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, binary, "mcp", "--api-url", cfg.Origin)
	command.Env = append(os.Environ(), "CICADA_MCP_SESSION_STATE_FILE="+statePath, "CODEX_THREAD_ID="+nativeContext.NativeSessionID, "CODEX_SESSION_ID=session-"+nativeContext.NativeSessionID)
	command.Stdin = bytes.NewReader(append(request, '\n'))
	var output, diagnostic bytes.Buffer
	command.Stdout = &output
	command.Stderr = &diagnostic
	if err = command.Run(); err != nil {
		return nil, errors.New("production MCP CLI fixture command failed")
	}
	var response mcpResponse
	if json.Unmarshal(output.Bytes(), &response) != nil || response.Error != nil {
		return nil, errors.New("invalid production MCP stdio response")
	}
	result, ok := response.Result.(map[string]any)
	if !ok {
		return nil, errors.New("incomplete production MCP result")
	}
	if result["isError"] == true {
		encoded, _ := json.Marshal(result["content"])
		return nil, errors.New(string(encoded))
	}
	return result["structuredContent"], nil
}
func privacyNodeFixtureControl(t *testing.T, cfg taskPrivacyProcessFixture, path string) map[string]any {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, cfg.Origin+"/__fixture/"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "CicadaFixture "+cfg.NodeToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("synthetic fixture control failed")
	}
	var result map[string]any
	if json.NewDecoder(response.Body).Decode(&result) != nil {
		t.Fatal("invalid bounded fixture state")
	}
	return result
}
func privacyNodeReceive(t *testing.T, cfg taskPrivacyProcessFixture, ctx context.Context, stateDir, messageID string) {
	t.Helper()
	var page struct {
		Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
	}
	path := cfg.Origin + "/v2/relay/nodes/" + cfg.NodeID + "/group/sealed/claim"
	if err := machineAPIJSON(ctx, path, http.MethodPost, fabric.NodeClaimInput{ConsumerID: "synthetic_privacy_fixture", Limit: 16}, &page); err != nil {
		t.Fatal(err)
	}
	var delivery *fabric.NodeSealedDelivery
	for i := range page.Deliveries {
		if page.Deliveries[i].MessageID == messageID {
			delivery = &page.Deliveries[i]
			break
		}
	}
	if delivery == nil {
		t.Fatal("normal sealed candidate has no authenticated Node claim")
	}
	auth, err := fetchCrossNodeGroupDeliveryAuthorization(ctx, cfg.Origin, cfg.NodeID, messageID, delivery.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openMachineCrossNodeGroupDelivery(ctx, stateDir, cfg.NodeID, *delivery, *auth)
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := nodeinbox.Open(machineNodeInboxPath(stateDir, cfg.NodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	route, err := machineSealedNodeInboxRoute(delivery.Route, messageID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = inbox.Save(ctx, nodeinbox.Message{MessageID: messageID, Digest: delivery.Digest, EndpointID: auth.EndpointID, SessionID: auth.NativeSessionID, BindingEpoch: auth.BindingEpoch, GroupID: cfg.GroupID, Route: route, Payload: opened.Plaintext}); err != nil {
		t.Fatal(err)
	}
}
func TestTaskPeerPrivacyIsolatedNodeFixture(t *testing.T) {
	if os.Getenv("CICADA_TASK_PRIVACY_FIXTURE_ROLE") != "node" {
		t.Skip("isolated Docker fixture only")
	}
	root := os.Getenv("CICADA_TASK_PRIVACY_NODE_ROOT")
	publicRoot := os.Getenv("CICADA_TASK_PRIVACY_PUBLIC_ROOT")
	data, err := os.ReadFile(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg taskPrivacyProcessFixture
	if json.Unmarshal(data, &cfg) != nil || len(cfg.Tasks) != 2 {
		t.Fatal("invalid private synthetic bootstrap")
	}
	stateDir := filepath.Join(root, "state")
	t.Setenv("CODEX_HOME", filepath.Join(root, "codex"))
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	t.Setenv("CICADA_WORKSPACE", cfg.Source.Context.Workspace)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_MACHINE_ID", cfg.NodeID)
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	history, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(stateDir, "native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	ctx := withMachineHubContext(context.Background(), machineHubContext{HubID: cfg.HubID, Origin: cfg.Origin, NodeID: cfg.NodeID, StateDir: stateDir, Token: cfg.NodeToken, WriterRoot: stateDir, WriterScope: machineNativeWriterScope(), RequireNativeContext: true, NativeContexts: history})
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, cfg.Origin, cfg.NodeID, cfg.NodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	cases := []map[string]any{}
	pass := func(name string) { cases = append(cases, map[string]any{"case": name, "status": "PASS"}) }
	taskView := func(session taskPrivacySessionFixture, id string) store.SharedTaskPeerView {
		t.Helper()
		value, err := privacyCLI(t, cfg, session, "cicada_task_get", map[string]any{"task_id": id})
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(value)
		var view store.SharedTaskPeerView
		if json.Unmarshal(encoded, &view) != nil || view.ID != id {
			t.Fatal("invalid metadata peer DTO")
		}
		for _, secret := range []string{"SYNTHETIC_PRIVATE_TASK_OBJECTIVE_SENTINEL", "SYNTHETIC_PRIVATE_TASK_CRITERIA_SENTINEL", "SYNTHETIC_PRIVATE_TASK_RESULT_SENTINEL"} {
			if bytes.Contains(encoded, []byte(secret)) {
				t.Fatal("peer DTO exposed new private Task body")
			}
		}
		return view
	}
	const objective = "SYNTHETIC_PRIVATE_TASK_OBJECTIVE_SENTINEL"
	const criteria = "SYNTHETIC_PRIVATE_TASK_CRITERIA_SENTINEL"
	const summary = "SYNTHETIC_PRIVATE_TASK_RESULT_SENTINEL"
	phasePath := filepath.Join(root, "saved-phase.json")
	if savedData, readErr := os.ReadFile(phasePath); readErr == nil {
		var saved taskPrivacySavedPhase
		if json.Unmarshal(savedData, &saved) != nil {
			t.Fatal("invalid original operation")
		}
		before := privacyNodeFixtureControl(t, cfg, "state")
		cryptoBefore := privacyFixtureFiles(t, machineNodeStateDir(stateDir, cfg.NodeID))
		retried, err := privacyCLI(t, cfg, cfg.Source, "cicada_task_submit", saved.ResultArgs)
		if err != nil {
			t.Fatal(err)
		}
		ref := decodePrivacyRegisteredRef(t, retried)
		if !reflect.DeepEqual(ref, saved.Result) || !reflect.DeepEqual(before, privacyNodeFixtureControl(t, cfg, "state")) {
			t.Fatal("process restart retry retargeted or advanced Task state")
		}
		if !reflect.DeepEqual(cryptoBefore, privacyFixtureFiles(t, machineNodeStateDir(stateDir, cfg.NodeID))) {
			t.Fatal("restart retry changed keys, crypto counters/replay or raw modes")
		}
		pass("actual_node_process_restart_original_immutable_ref_and_crypto")
		view := taskView(cfg.Target, cfg.Tasks[0])
		accepted, err := privacyCLI(t, cfg, cfg.Target, "cicada_task_accept", map[string]any{"task_id": view.ID, "result_id": saved.Result.ResultID, "expected_revision": view.Revision})
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(accepted)
		if bytes.Contains(encoded, []byte(summary)) {
			t.Fatal("accepted result exposed plaintext")
		}
		if taskView(cfg.Target, view.ID).Status != store.SharedTaskCompleted {
			t.Fatal("current registered result did not complete")
		}
		pass("current_exact_recipient_actual_stdio_acceptance")
		// A second independent Task stays PENDING through current revocation.
		second := taskView(cfg.Target, cfg.Tasks[1])
		if len(second.ResultRefs) != 1 {
			t.Fatal("second Task lacks one current registered result")
		}
		privacyNodeFixtureControl(t, cfg, "revoke")
		before = privacyNodeFixtureControl(t, cfg, "state")
		if _, err = privacyCLI(t, cfg, cfg.Target, "cicada_task_accept", map[string]any{"task_id": second.ID, "result_id": second.ResultRefs[0].ResultID, "expected_revision": second.Revision}); err == nil {
			t.Fatal("revoked recipient accepted Task")
		}
		if !reflect.DeepEqual(before, privacyNodeFixtureControl(t, cfg, "state")) {
			t.Fatal("revoked acceptance changed Task CAS")
		}
		pass("current_recipient_revocation_denied_without_task_cas")
		report, _ := json.Marshal(map[string]any{"phase": "restart", "cases": cases, "status": "PASS", "transport": "production CLI MCP stdio over authenticated production Hub HTTP", "native_runtime": "NOT_RUN", "node_delivery_receipts": "NONE"})
		if err = os.WriteFile(filepath.Join(publicRoot, "node-restart-report.json"), report, 0600); err != nil {
			t.Fatal(err)
		}
		privacyNodeFixtureControl(t, cfg, "stop")
		return
	}
	for index, id := range cfg.Tasks {
		initial := taskView(cfg.Target, id)
		before := privacyNodeFixtureControl(t, cfg, "state")
		if _, err = privacyCLI(t, cfg, cfg.Source, "cicada_task_submit", map[string]any{"task_id": id, "expected_revision": initial.Revision, "owner_epoch": initial.OwnerEpoch, "summary": summary, "purpose": "TASK_RESULT_V1"}); err == nil {
			t.Fatal("legacy/fake-purpose plaintext submit succeeded")
		}
		if !reflect.DeepEqual(before, privacyNodeFixtureControl(t, cfg, "state")) {
			t.Fatal("plaintext denial changed Task")
		}
		pass("plaintext_fake_purpose_prewrite_denied")
		args := map[string]any{"task_id": id, "expected_revision": initial.Revision, "owner_epoch": initial.OwnerEpoch, "assignment_version": int64(1), "content_version": int64(1), "target_endpoint_id": cfg.Source.Public.Endpoint.ID, "objective": objective, "acceptance_criteria": criteria, "artifact_refs": []any{}, "idempotency_key": "synthetic-definition-" + strconv.Itoa(index)}
		value, err := privacyCLI(t, cfg, cfg.Target, "cicada_task_define", args)
		if index == 0 {
			if err == nil {
				t.Fatal("lost durable registration response not observed")
			}
			if !reflect.DeepEqual(before, privacyNodeFixtureControl(t, cfg, "state")) {
				t.Fatal("definition registration advanced Task business CAS")
			}
			value, err = privacyCLI(t, cfg, cfg.Target, "cicada_task_define", args)
			pass("lost_registration_response_immutable_recovery_without_business_cas")
		}
		if err != nil {
			t.Fatal(err)
		}
		definition := decodePrivacyRegisteredRef(t, value)
		privacyNodeReceive(t, cfg, ctx, stateDir, definition.MessageID)
		body, err := privacyCLI(t, cfg, cfg.Source, "cicada_task_body", map[string]any{"task_id": id, "message_id": definition.MessageID})
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(body)
		if !bytes.Contains(encoded, []byte(objective)) {
			t.Fatal("exact receiver did not open typed private definition")
		}
		pass("actual_sealed_send_receiver_crypto_typed_ref_match")
		if _, err = privacyCLI(t, cfg, cfg.Target, "cicada_task_body", map[string]any{"task_id": id, "message_id": definition.MessageID}); err == nil {
			t.Fatal("wrong reader obtained body")
		}
		pass("wrong_reader_no_registered_body")
		mutated := map[string]any{}
		for key, value := range args {
			mutated[key] = value
		}
		mutated["content_version"] = int64(2)
		before = privacyNodeFixtureControl(t, cfg, "state")
		if _, err = privacyCLI(t, cfg, cfg.Target, "cicada_task_define", mutated); err == nil || !reflect.DeepEqual(before, privacyNodeFixtureControl(t, cfg, "state")) {
			t.Fatal("immutable retry changed content version")
		}
		pass("immutable_content_version_transplant_denied")
		_, err = privacyCLI(t, cfg, cfg.Source, "cicada_task_claim", map[string]any{"task_id": id, "expected_revision": initial.Revision, "idempotency_key": "synthetic-worker-" + strconv.Itoa(index), "lease_seconds": 600})
		if err != nil {
			t.Fatal(err)
		}
		claimed := taskView(cfg.Source, id)
		resultArgs := map[string]any{"task_id": id, "expected_revision": claimed.Revision, "owner_epoch": claimed.OwnerEpoch, "assignment_version": int64(1), "content_version": int64(1), "summary": summary, "artifact_refs": []store.SharedTaskArtifactRef{cfg.Artifact}, "idempotency_key": "synthetic-result-" + strconv.Itoa(index)}
		result, err := privacyCLI(t, cfg, cfg.Source, "cicada_task_submit", resultArgs)
		if err != nil {
			t.Fatal(err)
		}
		resultRef := decodePrivacyRegisteredRef(t, result)
		privacyNodeReceive(t, cfg, ctx, stateDir, resultRef.MessageID)
		current := taskView(cfg.Target, id)
		if current.Status != store.SharedTaskResultSubmitted || current.Revision != claimed.Revision+1 {
			t.Fatal("formal result did not apply exact CAS")
		}
		pass("formal_registered_result_distinct_from_send_receipt")
		if index == 0 {
			saved := taskPrivacySavedPhase{ResultArgs: resultArgs, Result: resultRef}
			data, _ := json.Marshal(saved)
			if err = os.WriteFile(phasePath, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	publicState := privacyNodeFixtureControl(t, cfg, "state")
	if publicState["private_prose_absent"] != true {
		t.Fatal("Hub HTTP received private Task prose")
	}
	pass("hub_http_new_task_prose_absent")
	report, _ := json.Marshal(map[string]any{"phase": "initial", "cases": cases, "status": "PASS", "transport": "production CLI MCP stdio over authenticated production Hub HTTP", "native_runtime": "NOT_RUN", "node_delivery_receipts": "NONE"})
	if err = os.WriteFile(filepath.Join(publicRoot, "node-initial-report.json"), report, 0600); err != nil {
		t.Fatal(err)
	}
}
