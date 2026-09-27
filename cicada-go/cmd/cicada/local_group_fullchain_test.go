package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelocal"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestMCPSealedSameNodeGroupAskReplyFullChain exercises real Store/Fabric
// authorization, both MCP outboxes, the owner-only Node bridge, the sealed
// Node ledger/inbox, and exact native queue arguments. Control is not
// constructed; Codex is a recording queue fake, so this verifies the handoff
// protocol and isolation rather than real model consumption or two processes.
func TestMCPSealedSameNodeGroupAskReplyFullChain(t *testing.T) {
	const (
		ownerID  = "owner_local_fullchain"
		groupID  = "group_local_fullchain"
		nodeID   = "node_local_fullchain"
		nativeA  = "native_local_fullchain_a"
		nativeB  = "native_local_fullchain_b"
		question = "private same-Node question must stay local"
		answer   = "private same-Node answer must stay local"
	)
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	writeCodexSessionRecord(t, codexHome, nativeA, workspace)
	writeCodexSessionRecord(t, codexHome, nativeB, workspace)

	state, err := store.New(filepath.Join(t.TempDir(), "hub.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	owner, err := state.CreatePrincipal(store.Principal{
		ID: ownerID, Kind: store.PrincipalKindHuman, OwnerID: ownerID,
		TrustDomainID: ownerID, Name: "Local full-chain owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.CreateGroup(store.Group{
		ID: groupID, Name: "Local full-chain Group", OwnerPrincipalID: owner.ID,
		TrustDomainID: ownerID, State: store.GroupStateActive,
	}); err != nil {
		t.Fatal(err)
	}
	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := state.RegisterOwnerApprovalKeyLocal(ownerID, ownerIdentity.Public())
	if err != nil {
		t.Fatal(err)
	}
	clientIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "client_" + nodeID
	hubID, err := state.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	deviceGrant, err := ownerIdentity.SignOwnerDeviceGrant(ownerID, deviceID,
		clientIdentity.Public(), hubID, e2ee.OwnerDevicePurposeControl,
		now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: ownerKey.KeyID, DeviceID: deviceID,
		DevicePublic: clientIdentity.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		t.Fatal(err)
	}
	nodeToken, _, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	codeSum := sha256.Sum256([]byte("local-fullchain-device-code"))
	codeDigest := hex.EncodeToString(codeSum[:])
	if _, err := state.CreatePendingNodeDeviceBinding(nodeID, nodeID,
		fabric.HashSessionCredential(nodeToken), codeDigest, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := state.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(state, ownerID, ownerID)
	if err != nil {
		t.Fatal(err)
	}

	// NewFabricHandler intentionally constructs only the Fabric data plane;
	// no Control planner, scheduler, or reporting service exists in this test.
	fabricHandler := serverpkg.NewFabricHandler(service, "")
	stateDir := shortLocalJoinStateDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var pathsMu sync.Mutex
	var hubPaths []string
	var unexpectedPaths []string
	hubSawPlaintext := false
	allowedPaths := map[string]bool{
		"/v2/fabric/node/join":                            true,
		"/v2/fabric/whoami":                               true,
		"/v2/fabric/endpoint-keys":                        true,
		"/v2/fabric/resolve":                              true,
		"/v2/relay/nodes/" + nodeID + "/local/authorize":  true,
		"/v2/relay/nodes/" + nodeID + "/local/revalidate": true,
		// An intentionally nonexistent request is probed once to distinguish
		// it from a valid cross-Node request; valid same-Node RPC stays local.
		"/v2/relay/nodes/" + nodeID + "/group/sealed/requests/rq_nonexistent_local_fullchain": true,
	}
	hub := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read Hub request: %v", readErr)
			http.Error(response, "invalid request", http.StatusBadRequest)
			return
		}
		_ = request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
		pathsMu.Lock()
		hubPaths = append(hubPaths, request.URL.Path)
		if !allowedPaths[request.URL.Path] {
			unexpectedPaths = append(unexpectedPaths, request.Method+" "+request.URL.Path)
		}
		if bytes.Contains(body, []byte(question)) || bytes.Contains(body, []byte(answer)) {
			hubSawPlaintext = true
		}
		pathsMu.Unlock()
		if !allowedPaths[request.URL.Path] {
			http.NotFound(response, request)
			return
		}
		fabricHandler.ServeHTTP(response, request)
	}))
	defer hub.Close()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, hub.URL, nodeID, nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	t.Setenv("CICADA_WORKSPACE", workspace)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CICADA_MACHINE_ID", nodeID)
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	newJoinedMCP := func(nativeID string) *mcpServer {
		t.Helper()
		t.Setenv("CODEX_THREAD_ID", nativeID)
		t.Setenv("CODEX_SESSION_ID", "session-"+nativeID)
		mcp := newMCPServer(hub.URL, "", filepath.Join(t.TempDir(), "mcp", "sessions.json"))
		if _, err := mcp.callTool("cicada_join", map[string]any{"group_id": groupID}); err != nil {
			t.Fatalf("explicit local Node Join for %s: %v", nativeID, err)
		}
		t.Cleanup(func() {
			if mcp.outbox != nil {
				_ = mcp.outbox.close()
			}
			close(mcp.stop)
		})
		mcp.sessionMu.RLock()
		joinedToken := mcp.sessionToken
		joinedEndpoint := mcp.sessionPublic.Endpoint
		joinedCard := mcp.sessionPublic.NetworkCard
		mcp.sessionMu.RUnlock()
		if joinedToken == "" || joinedEndpoint.ID == "" || joinedEndpoint.GroupID != groupID ||
			joinedEndpoint.Owner != ownerID || joinedCard.NodeID != nodeID || joinedCard.GroupID != groupID ||
			joinedCard.Capabilities["local_peer_delivery"] != "sealed_v1" {
			t.Fatalf("native session did not join the same Node-local Group: endpoint=%#v card=%#v", joinedEndpoint, joinedCard)
		}
		return mcp
	}

	sourceMCP := newJoinedMCP(nativeA)
	targetMCP := newJoinedMCP(nativeB)
	if sourceMCP.endpointID == targetMCP.endpointID || sourceMCP.sessionToken == targetMCP.sessionToken {
		t.Fatalf("distinct native Codex sessions did not receive separate Fabric bindings: source=%q target=%q",
			sourceMCP.endpointID, targetMCP.endpointID)
	}
	assertCurrentCandidate := func(mcp *mcpServer, nativeID string) *store.EndpointKeyCandidate {
		t.Helper()
		mcp.sessionMu.RLock()
		endpoint := mcp.sessionPublic.Endpoint
		card := mcp.sessionPublic.NetworkCard
		mcp.sessionMu.RUnlock()
		binding, err := state.GetActiveSessionBinding(endpoint.ID)
		if err != nil || binding.NativeSessionID != nativeID || binding.NodeID != nodeID || binding.ID != endpoint.BindingID {
			t.Fatalf("current SessionBinding does not preserve %s: binding=%#v error=%v", nativeID, binding, err)
		}
		identity, err := nodekeys.LoadOrCreate(machineNodeStateDir(stateDir, nodeID), endpoint.ID)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := state.GetEndpointKeyCandidate(endpoint.ID)
		if err != nil || candidate.State != store.EndpointKeyCandidateStateCandidate ||
			candidate.EndpointID != endpoint.ID || candidate.PrincipalID != card.PrincipalID ||
			candidate.OwnerID != ownerID || candidate.NodeID != nodeID || candidate.BindingID != binding.ID ||
			candidate.BindingEpoch != binding.Epoch || candidate.KeyID != identity.Public().ID ||
			!sameMCPKeyPublic(candidate.Public, identity.Public()) {
			t.Fatalf("Node-local candidate does not match the active native Endpoint key: candidate=%#v error=%v", candidate, err)
		}
		verified, err := e2ee.VerifyEndpointKeyAttestation(candidate.Proof, endpoint.ID,
			card.PrincipalID, nodeID, binding.ID, binding.Epoch)
		if err != nil || !sameMCPKeyPublic(verified, identity.Public()) {
			t.Fatalf("Node-joined key candidate proof does not match local identity: err=%v", err)
		}
		return candidate
	}
	sourceKey := assertCurrentCandidate(sourceMCP, nativeA)
	targetKey := assertCurrentCandidate(targetMCP, nativeB)

	// MCPA ASK goes through the durable per-native-session outbox and the
	// trusted Node Unix bridge. Its body is never sent to an HTTP Hub route.
	t.Setenv("CODEX_THREAD_ID", nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeA)
	asked, err := sourceMCP.callTool("cicada_ask", map[string]any{
		"target": targetMCP.endpointID, "question": question,
	})
	if err != nil {
		t.Fatal(err)
	}
	askResult, ok := asked.(map[string]any)
	if !ok {
		t.Fatalf("local ASK returned an unexpected result type: %T", asked)
	}
	requestID, _ := askResult["request_id"].(string)
	askMessageID, _ := askResult["message_id"].(string)
	if askResult["status"] != mcpOutboxStatusSent || requestID == "" || askMessageID == "" ||
		askResult["delivery"] != "LOCAL_PERSISTED" || askResult["target_endpoint_id"] != targetMCP.endpointID {
		t.Fatalf("same-Node ASK was not durably accepted with a request ID: %#v", askResult)
	}
	ledger, err := nodelocal.Open(machineLocalGroupLedgerPath(stateDir, nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	askRecord, err := ledger.GetRequest(context.Background(), requestID)
	if err != nil || askRecord.State != nodelocal.RequestOpen || askRecord.MessageID != askMessageID ||
		askRecord.SourceEndpointID != sourceMCP.endpointID || askRecord.TargetEndpointID != targetMCP.endpointID ||
		askRecord.Route.SourceSessionID != nativeA || askRecord.Route.TargetSessionID != nativeB ||
		askRecord.Route.SourceGroupID != groupID || askRecord.Route.TargetGroupID != groupID ||
		askRecord.Route.SourceNodeID != nodeID || askRecord.Route.TargetNodeID != nodeID ||
		askRecord.Route.SourceKeyID != sourceKey.KeyID || askRecord.Route.TargetKeyID != targetKey.KeyID {
		t.Fatalf("durable local ASK route lost its exact same-Node native identities: request=%#v error=%v", askRecord, err)
	}
	askMessage, err := ledger.GetMessage(context.Background(), askMessageID)
	if err != nil || askMessage.Kind != nodelocal.KindAsk || bytes.Contains(askMessage.Ciphertext, []byte(question)) {
		t.Fatalf("local ASK ledger did not retain only sealed bytes: message=%#v error=%v", askMessage, err)
	}

	targetArgs, targetCount := installMachineSealedFakeCodex(t, false, nodeToken)
	targetInbox, err := nodeinbox.Open(machineLocalGroupInboxPath(stateDir, nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer targetInbox.Close()
	for attempt := 0; attempt < 2; attempt++ {
		if err := processMachineLocalGroupDeliveries(context.Background(), bridge, targetInbox); err != nil {
			t.Fatalf("drain local REQUEST attempt %d: %v", attempt, err)
		}
	}
	targetPrompt, err := os.ReadFile(targetArgs)
	if err != nil {
		t.Fatal(err)
	}
	targetQueueCount, err := os.ReadFile(targetCount)
	if err != nil || string(targetQueueCount) != "x" ||
		!bytes.Contains(targetPrompt, []byte("queue\n--thread\n"+nativeB+"\n--message\n")) ||
		!bytes.Contains(targetPrompt, []byte(question)) || !bytes.Contains(targetPrompt, []byte(requestID)) ||
		!bytes.Contains(targetPrompt, []byte(sourceMCP.endpointID)) || !bytes.Contains(targetPrompt, []byte(targetMCP.endpointID)) {
		t.Fatalf("ASK did not inject exactly once into B's original native Codex session: count=%q argv=%q err=%v",
			targetQueueCount, targetPrompt, err)
	}
	queuedAsk, err := targetInbox.Get(context.Background(), askMessageID)
	if err != nil || queuedAsk.SessionID != nativeB || queuedAsk.EndpointID != targetMCP.endpointID ||
		queuedAsk.State != nodeinbox.CONSUMPTION_UNCONFIRMED {
		t.Fatalf("B inbox did not retain the exact native ASK delivery: delivery=%#v error=%v", queuedAsk, err)
	}
	t.Setenv("CODEX_THREAD_ID", nativeB)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeB)
	receivedAsk, err := targetMCP.callTool("cicada_receive", map[string]any{"limit": 8})
	if err != nil {
		t.Fatalf("B native Session could not read its scoped Node inbox: %v", err)
	}
	askPage, ok := receivedAsk.(map[string]any)
	if !ok {
		t.Fatalf("B receive returned %T", receivedAsk)
	}
	askMessages, ok := askPage["messages"].([]nodeinbox.VisibleMessage)
	if !ok || len(askMessages) != 1 || askMessages[0].MessageID != askMessageID ||
		askMessages[0].Body != question || askMessages[0].Kind != "REQUEST" ||
		askMessages[0].RequestID != requestID || askMessages[0].ReplyTo != "" ||
		askMessages[0].SenderEndpointID != sourceMCP.endpointID || askPage["next_cursor"] == "" {
		t.Fatalf("B receive did not expose only its injected ASK: %#v", askPage)
	}

	// The responder replies using only the durable request ID. The local Node
	// ledger derives the reverse target from the original ASK route.
	t.Setenv("CODEX_THREAD_ID", nativeB)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeB)
	missingReply, err := targetMCP.callTool("cicada_reply", map[string]any{
		"request_id": "rq_nonexistent_local_fullchain", "body": "no such request",
	})
	if err != nil {
		t.Fatal(err)
	}
	missingResult, ok := missingReply.(map[string]any)
	if !ok || missingResult["status"] != mcpOutboxStatusFailed {
		t.Fatalf("missing local request did not fail closed: %#v", missingReply)
	}
	replied, err := targetMCP.callTool("cicada_reply", map[string]any{
		"request_id": requestID, "body": answer,
	})
	if err != nil {
		t.Fatal(err)
	}
	replyResult, ok := replied.(map[string]any)
	if !ok || replyResult["status"] != mcpOutboxStatusSent || replyResult["request_id"] != requestID ||
		replyResult["delivery"] != "LOCAL_PERSISTED" {
		t.Fatalf("same-Node REPLY was not durably correlated: %#v", replied)
	}
	replyMessageID, _ := replyResult["message_id"].(string)
	if replyMessageID == "" {
		t.Fatalf("same-Node REPLY omitted its message ID: %#v", replyResult)
	}
	replyRecord, err := ledger.GetMessage(context.Background(), replyMessageID)
	if err != nil || replyRecord.Kind != nodelocal.KindReply || replyRecord.RequestID != requestID ||
		replyRecord.ReplyToMessageID != askMessageID || replyRecord.Route.SourceEndpointID != targetMCP.endpointID ||
		replyRecord.Route.TargetEndpointID != sourceMCP.endpointID ||
		replyRecord.Route.SourceSessionID != nativeB || replyRecord.Route.TargetSessionID != nativeA ||
		bytes.Contains(replyRecord.Ciphertext, []byte(answer)) {
		t.Fatalf("REPLY ledger did not reverse the original sealed ASK route: message=%#v error=%v", replyRecord, err)
	}

	sourceArgs, sourceCount := installMachineSealedFakeCodex(t, false, nodeToken)
	sourceInbox, err := nodeinbox.Open(machineLocalGroupInboxPath(stateDir, nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer sourceInbox.Close()
	for attempt := 0; attempt < 2; attempt++ {
		if err := processMachineLocalGroupDeliveries(context.Background(), bridge, sourceInbox); err != nil {
			t.Fatalf("drain local REPLY attempt %d: %v", attempt, err)
		}
	}
	t.Setenv("CODEX_THREAD_ID", nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeA)
	receivedReply, err := sourceMCP.callTool("cicada_receive", map[string]any{"limit": 8})
	if err != nil {
		t.Fatalf("A native Session could not read its scoped Node inbox: %v", err)
	}
	replyPage, ok := receivedReply.(map[string]any)
	if !ok {
		t.Fatalf("A receive returned %T", receivedReply)
	}
	replyMessages, ok := replyPage["messages"].([]nodeinbox.VisibleMessage)
	if !ok || len(replyMessages) != 1 || replyMessages[0].MessageID != replyMessageID ||
		replyMessages[0].Body != answer || replyMessages[0].Kind != "REPLY" ||
		replyMessages[0].RequestID != requestID || replyMessages[0].ReplyTo != askMessageID ||
		replyMessages[0].SenderEndpointID != targetMCP.endpointID {
		t.Fatalf("A receive did not expose only its correlated injected REPLY: %#v", replyPage)
	}
	sourcePrompt, err := os.ReadFile(sourceArgs)
	if err != nil {
		t.Fatal(err)
	}
	sourceQueueCount, err := os.ReadFile(sourceCount)
	if err != nil || string(sourceQueueCount) != "x" ||
		!bytes.Contains(sourcePrompt, []byte("queue\n--thread\n"+nativeA+"\n--message\n")) ||
		!bytes.Contains(sourcePrompt, []byte(answer)) || !bytes.Contains(sourcePrompt, []byte(requestID)) ||
		!bytes.Contains(sourcePrompt, []byte(askMessageID)) || !bytes.Contains(sourcePrompt, []byte(sourceMCP.endpointID)) ||
		!bytes.Contains(sourcePrompt, []byte(targetMCP.endpointID)) {
		t.Fatalf("REPLY did not inject exactly once into A's original native Codex session: count=%q argv=%q err=%v",
			sourceQueueCount, sourcePrompt, err)
	}
	queuedReply, err := sourceInbox.Get(context.Background(), replyMessageID)
	if err != nil || queuedReply.SessionID != nativeA || queuedReply.EndpointID != sourceMCP.endpointID ||
		queuedReply.State != nodeinbox.CONSUMPTION_UNCONFIRMED {
		t.Fatalf("A inbox did not retain the exact native REPLY delivery: delivery=%#v error=%v", queuedReply, err)
	}
	if count, err := os.ReadFile(targetCount); err != nil || string(count) != "x" {
		t.Fatalf("duplicate Node drain reinjected the original ASK: count=%q error=%v", count, err)
	}

	for _, item := range []struct {
		mcp      *mcpServer
		nativeID string
	}{{sourceMCP, nativeA}, {targetMCP, nativeB}} {
		binding, err := state.GetActiveSessionBinding(item.mcp.endpointID)
		if err != nil || binding.NativeSessionID != item.nativeID || binding.NodeID != nodeID || binding.ID != item.mcp.sessionPublic.BindingID {
			t.Fatalf("original native Session binding changed during ASK/REPLY: native=%s binding=%#v error=%v", item.nativeID, binding, err)
		}
	}
	pathsMu.Lock()
	finalPaths := append([]string(nil), hubPaths...)
	finalUnexpected := append([]string(nil), unexpectedPaths...)
	finalPlaintext := hubSawPlaintext
	pathsMu.Unlock()
	if finalPlaintext {
		t.Fatal("Hub observed peer ASK or REPLY plaintext in an HTTP request body")
	}
	if len(finalUnexpected) != 0 {
		t.Fatalf("local full-chain used a Relay message or Control/business route: %v (all paths: %v)", finalUnexpected, finalPaths)
	}
	if len(finalPaths) == 0 || !containsPath(finalPaths, "/v2/relay/nodes/"+nodeID+"/local/authorize") ||
		!containsPath(finalPaths, "/v2/relay/nodes/"+nodeID+"/local/revalidate") ||
		!containsPath(finalPaths, "/v2/fabric/node/join") || !containsPath(finalPaths, "/v2/fabric/endpoint-keys") {
		t.Fatalf("full chain did not exercise Node Join, key candidate publication, and authoritative Guard APIs: %v", finalPaths)
	}
	t.Log("harness limitation: the queue executable records protocol arguments only; no real Codex model consumes the ASK or REPLY")
}

func containsPath(paths []string, expected string) bool {
	for _, path := range paths {
		if path == expected {
			return true
		}
	}
	return false
}

type localGroupFailureFixture struct {
	store         *store.Store
	stateDir      string
	groupID       string
	ownerID       string
	nodeID        string
	nodeToken     string
	nativeA       string
	nativeB       string
	workspace     string
	sourceMCP     *mcpServer
	targetMCP     *mcpServer
	bridge        *machineAgentJoinBridge
	bridgeCtx     context.Context
	bridgeCancel  context.CancelFunc
	hub           *httptest.Server
	failNextGuard atomic.Bool
}

func newLocalGroupFailureFixture(t *testing.T) *localGroupFailureFixture {
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
	f.store, err = store.New(filepath.Join(t.TempDir(), "hub.sqlite3"))
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
		"/v2/fabric/node/join":                              true,
		"/v2/fabric/whoami":                                 true,
		"/v2/fabric/endpoint-keys":                          true,
		"/v2/fabric/resolve":                                true,
		"/v2/relay/nodes/" + f.nodeID + "/local/authorize":  true,
		"/v2/relay/nodes/" + f.nodeID + "/local/revalidate": true,
	}
	f.hub = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/relay/nodes/"+f.nodeID+"/local/revalidate" &&
			f.failNextGuard.CompareAndSwap(true, false) {
			http.Error(response, "temporary Guard outage", http.StatusServiceUnavailable)
			return
		}
		if !allowed[request.URL.Path] {
			t.Errorf("failure harness attempted unsupported Hub path %s", request.URL.Path)
			http.NotFound(response, request)
			return
		}
		fabricHandler.ServeHTTP(response, request)
	}))
	f.bridgeCtx, f.bridgeCancel = context.WithCancel(context.Background())
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
	return f
}

func (f *localGroupFailureFixture) joinSession(t *testing.T, nativeID string) *mcpServer {
	t.Helper()
	t.Setenv("CODEX_THREAD_ID", nativeID)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeID)
	mcp := newMCPServer(f.hub.URL, "", filepath.Join(t.TempDir(), "mcp", "sessions.json"))
	if _, err := mcp.callTool("cicada_join", map[string]any{"group_id": f.groupID}); err != nil {
		t.Fatalf("could not join local native session: %v", err)
	}
	mcp.sessionMu.RLock()
	endpoint := mcp.sessionPublic.Endpoint
	card := mcp.sessionPublic.NetworkCard
	token := mcp.sessionToken
	mcp.sessionMu.RUnlock()
	if token == "" || endpoint.ID == "" || endpoint.Owner != f.ownerID || endpoint.GroupID != f.groupID ||
		card.NodeID != f.nodeID || card.GroupID != f.groupID || card.Capabilities["local_peer_delivery"] != "sealed_v1" {
		t.Fatal("native session did not join the current local Group binding")
	}
	t.Cleanup(func() {
		if mcp.outbox != nil {
			_ = mcp.outbox.close()
		}
		close(mcp.stop)
	})
	return mcp
}

func (f *localGroupFailureFixture) restartBridge() error {
	if f.bridge != nil {
		if err := f.bridge.Close(); err != nil {
			return err
		}
	}
	bridge, err := startMachineAgentJoinBridge(f.bridgeCtx, f.stateDir, f.hub.URL, f.nodeID, f.nodeToken)
	if err != nil {
		return err
	}
	f.bridge = bridge
	return nil
}

func (f *localGroupFailureFixture) ask(t *testing.T) (requestID, messageID string) {
	t.Helper()
	t.Setenv("CODEX_THREAD_ID", f.nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+f.nativeA)
	result, err := f.sourceMCP.callTool("cicada_ask", map[string]any{
		"target": f.targetMCP.endpointID, "question": "private local failure-path question",
	})
	if err != nil {
		t.Fatalf("local ASK failed before durable acceptance: %v", err)
	}
	public, ok := result.(map[string]any)
	if !ok || public["status"] != mcpOutboxStatusSent || public["delivery"] != "LOCAL_PERSISTED" {
		t.Fatal("local ASK did not report durable Node acceptance")
	}
	requestID, _ = public["request_id"].(string)
	messageID, _ = public["message_id"].(string)
	if requestID == "" || messageID == "" {
		t.Fatal("durably accepted local ASK omitted its request or message identity")
	}
	return requestID, messageID
}

func TestMCPSealedSameNodeAskRevokedBeforeDrainIsRejectedWithoutQueue(t *testing.T) {
	f := newLocalGroupFailureFixture(t)
	requestID, messageID := f.ask(t)
	f.targetMCP.sessionMu.RLock()
	principalID := f.targetMCP.sessionPublic.NetworkCard.PrincipalID
	f.targetMCP.sessionMu.RUnlock()
	if _, err := f.store.RevokeMembershipForPrincipalGroup(principalID, f.groupID, "test revocation"); err != nil {
		t.Fatal(err)
	}
	_, queueCount := installMachineSealedFakeCodex(t, false, f.nodeToken)
	inbox, err := nodeinbox.Open(machineLocalGroupInboxPath(f.stateDir, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	if err := processMachineLocalGroupDeliveries(context.Background(), f.bridge, inbox); err != nil {
		t.Fatalf("revoked pending ASK drain returned an unexpected error: %v", err)
	}
	ledger, err := nodelocal.Open(machineLocalGroupLedgerPath(f.stateDir, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	message, err := ledger.GetMessage(context.Background(), messageID)
	if err != nil || message.State != nodelocal.DeliveryRejected {
		t.Fatal("revoked pending ASK was not recorded as terminal REJECTED")
	}
	request, err := ledger.GetRequest(context.Background(), requestID)
	if err != nil || request.State != nodelocal.RequestRejected {
		t.Fatal("revoked pending ASK did not close its durable request")
	}
	pending, err := ledger.PendingAll(context.Background(), 10)
	if err != nil || len(pending) != 0 {
		t.Fatal("terminally rejected ASK remained in the pending ledger")
	}
	if _, err := inbox.Get(context.Background(), messageID); !errors.Is(err, nodeinbox.ErrNotFound) {
		t.Fatal("revoked ASK crossed into the Node inbox")
	}
	if _, err := os.Stat(queueCount); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("revoked ASK invoked the native queue")
	}
}

func TestMCPSealedSameNodeAskGuard503SurvivesRestartAndRecoversOnce(t *testing.T) {
	f := newLocalGroupFailureFixture(t)
	_, messageID := f.ask(t)
	queueArgs, queueCount := installMachineSealedFakeCodex(t, false, f.nodeToken)
	inbox, err := nodeinbox.Open(machineLocalGroupInboxPath(f.stateDir, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if inbox != nil {
			_ = inbox.Close()
		}
	}()
	f.failNextGuard.Store(true)
	if err := processMachineLocalGroupDeliveries(context.Background(), f.bridge, inbox); err == nil {
		t.Fatal("temporary Guard 503 did not leave local drain retryable")
	}
	if _, err := os.Stat(queueCount); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary Guard failure reached the native queue")
	}
	if _, err := inbox.Get(context.Background(), messageID); !errors.Is(err, nodeinbox.ErrNotFound) {
		t.Fatal("temporary Guard failure crossed the durable inbox boundary")
	}
	ledger, err := nodelocal.Open(machineLocalGroupLedgerPath(f.stateDir, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := ledger.PendingAll(context.Background(), 10)
	_ = ledger.Close()
	if err != nil || len(pending) != 1 || pending[0].MessageID != messageID {
		t.Fatal("temporary Guard failure did not preserve the pending sealed ASK")
	}
	if err := inbox.Close(); err != nil {
		t.Fatal(err)
	}
	inbox = nil
	if err := f.restartBridge(); err != nil {
		t.Fatal(err)
	}
	inbox, err = nodeinbox.Open(machineLocalGroupInboxPath(f.stateDir, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := processMachineLocalGroupDeliveries(context.Background(), f.bridge, inbox); err != nil {
			t.Fatalf("recovered local ASK drain failed: %v", err)
		}
	}
	queued, err := os.ReadFile(queueCount)
	if err != nil || string(queued) != "x" {
		t.Fatal("recovered local ASK was not injected exactly once")
	}
	args, err := os.ReadFile(queueArgs)
	if err != nil || !bytes.Contains(args, []byte("queue\n--thread\n"+f.nativeB+"\n--message\n")) {
		t.Fatal("recovered local ASK did not target B's original native session")
	}
	if delivery, err := inbox.Get(context.Background(), messageID); err != nil ||
		delivery.SessionID != f.nativeB || delivery.State != nodeinbox.CONSUMPTION_UNCONFIRMED {
		t.Fatal("recovered local ASK did not finish in the exact native inbox state")
	}
}

func TestMCPSealedSameNodeQueueFailureIsUncertainAndNeverRetried(t *testing.T) {
	f := newLocalGroupFailureFixture(t)
	_, messageID := f.ask(t)
	queueArgs, queueCount := installMachineSealedFakeCodex(t, true, f.nodeToken)
	inbox, err := nodeinbox.Open(machineLocalGroupInboxPath(f.stateDir, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	if err := processMachineLocalGroupDeliveries(context.Background(), f.bridge, inbox); err != nil {
		t.Fatalf("queue failure should be durably classified, not retried as a drain error: %v", err)
	}
	count, err := os.ReadFile(queueCount)
	if err != nil || string(count) != "x" {
		t.Fatal("queue failure harness did not start exactly one native queue attempt")
	}
	if err := inbox.Close(); err != nil {
		t.Fatal(err)
	}
	inbox, err = nodeinbox.Open(machineLocalGroupInboxPath(f.stateDir, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	for attempt := 0; attempt < 2; attempt++ {
		if err := processMachineLocalGroupDeliveries(context.Background(), f.bridge, inbox); err != nil {
			t.Fatalf("uncertain delivery recovery attempted an unsafe reinjection: %v", err)
		}
	}
	count, err = os.ReadFile(queueCount)
	if err != nil || string(count) != "x" {
		t.Fatal("uncertain local delivery was reinjected after queue failure")
	}
	if args, err := os.ReadFile(queueArgs); err != nil ||
		!bytes.Contains(args, []byte("queue\n--thread\n"+f.nativeB+"\n--message\n")) {
		t.Fatal("failed queue attempt was not for B's original native session")
	}
	if delivery, err := inbox.Get(context.Background(), messageID); err != nil ||
		delivery.State != nodeinbox.INJECTION_UNCERTAIN || delivery.SessionID != f.nativeB {
		t.Fatal("post-begin queue failure was not retained as exact-session INJECTION_UNCERTAIN")
	}
}
