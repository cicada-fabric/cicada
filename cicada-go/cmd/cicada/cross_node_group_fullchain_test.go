package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// This exercises two logical Nodes against real Store/Fabric authorization,
// owner-only MCP sockets, Node-local key state, and the fake Codex queue. The
// fake records exact native Thread arguments; it does not run the Codex model.
func TestMCPSealedSameGroupCrossNodeAskReplyFullChain(t *testing.T) {
	const (
		ownerID  = "owner_cross_node_group_fullchain"
		groupID  = "group_cross_node_group_fullchain"
		nodeA    = "node_cross_node_group_a"
		nodeB    = "node_cross_node_group_b"
		nativeA  = "native_cross_node_group_a"
		nativeB  = "native_cross_node_group_b"
		sendBody = "private cross-Node SEND plaintext"
		question = "private cross-Node ASK plaintext"
		answer   = "private cross-Node REPLY plaintext"
	)
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	writeCodexSessionRecord(t, codexHome, nativeA, workspace)
	writeCodexSessionRecord(t, codexHome, nativeB, workspace)

	persistence, err := store.New(filepath.Join(t.TempDir(), "cross-node-group.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = persistence.Close() })
	owner, err := persistence.CreatePrincipal(store.Principal{
		ID: ownerID, Kind: store.PrincipalKindHuman, OwnerID: ownerID,
		TrustDomainID: ownerID, Name: ownerID, Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(store.Group{
		ID: groupID, Name: groupID, OwnerPrincipalID: owner.ID,
		TrustDomainID: owner.TrustDomainID, State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherGroup, err := persistence.CreateGroup(store.Group{
		ID: "group_cross_node_group_other", Name: "other Group",
		OwnerPrincipalID: owner.ID, TrustDomainID: owner.TrustDomainID,
		State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := persistence.RegisterOwnerApprovalKeyLocal(ownerID, ownerIdentity.Public())
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	clientIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "client_cross_node_group_fullchain"
	deviceGrant, err := ownerIdentity.SignOwnerDeviceGrant(ownerID, deviceID,
		clientIdentity.Public(), hubID, e2ee.OwnerDevicePurposeControl,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: ownerKey.KeyID, DeviceID: deviceID,
		DevicePublic: clientIdentity.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		t.Fatal(err)
	}
	bindNode := func(nodeID string) string {
		t.Helper()
		token, digest, err := fabric.NewNodeCredential()
		if err != nil {
			t.Fatal(err)
		}
		code := sha256.Sum256([]byte("cross-node-group-code-" + nodeID))
		codeDigest := hex.EncodeToString(code[:])
		if _, err := persistence.CreatePendingNodeDeviceBinding(nodeID, nodeID, digest,
			codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
			t.Fatal(err)
		}
		return token
	}
	tokenA, tokenB := bindNode(nodeA), bindNode(nodeB)
	service, err := fabric.NewService(persistence, ownerID, owner.TrustDomainID)
	if err != nil {
		t.Fatal(err)
	}
	dataPlane := serverpkg.NewFabricHandler(service, "")

	stateDir := shortLocalJoinStateDir(t)
	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	t.Cleanup(cancelA)
	t.Cleanup(cancelB)
	var mu sync.Mutex
	var hubPaths, unexpectedPaths []string
	var sawPlaintext bool
	var events, receiptSequence []string
	var denyFinalAuthorizationFor string
	authorizationCounts := make(map[string]int)
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024+1))
		if readErr != nil {
			t.Errorf("read Hub request: %v", readErr)
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		if len(body) > 2*1024*1024 {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		_ = r.Body.Close()
		path := r.URL.Path
		allowed := strings.HasPrefix(path, "/v2/fabric/") ||
			(strings.HasPrefix(path, "/v2/relay/nodes/") &&
				(strings.Contains(path, "/group/sealed/") || strings.Contains(path, "/sealed/") ||
					strings.HasSuffix(path, "/claim") || strings.HasSuffix(path, "/receipts")))
			// Plaintext Fabric message routes and every Control route are excluded.
		if path == "/v2/fabric/send" || path == "/v2/fabric/ask" || path == "/v2/fabric/reply" ||
			strings.HasPrefix(path, "/v2/control/") {
			allowed = false
		}
		mu.Lock()
		hubPaths = append(hubPaths, path)
		if !allowed {
			unexpectedPaths = append(unexpectedPaths, r.Method+" "+path)
		}
		if bytes.Contains(body, []byte(sendBody)) || bytes.Contains(body, []byte(question)) || bytes.Contains(body, []byte(answer)) {
			sawPlaintext = true
		}
		if strings.Contains(path, "/group/sealed/requests/") && strings.HasSuffix(path, "/cancel") &&
			!bytes.Equal(bytes.TrimSpace(body), []byte("{}")) {
			t.Errorf("Hub cancellation body = %q, want empty JSON object", body)
		}
		if strings.Contains(path, "/group/sealed/") {
			events = append(events, path)
		}
		if strings.HasSuffix(path, "/authorization") && strings.Contains(path, "/group/sealed/deliveries/") {
			parts := strings.Split(strings.Trim(path, "/"), "/")
			receiptSequence = append(receiptSequence, "authorization:"+parts[len(parts)-2])
		}
		if strings.HasSuffix(path, "/receipts") {
			var receipt fabric.NodeReceiptInput
			if err := json.Unmarshal(body, &receipt); err != nil {
				t.Errorf("decode Node receipt sequence: %v", err)
			} else {
				receiptSequence = append(receiptSequence,
					"receipt:"+receipt.MessageID+":"+receipt.Layer)
			}
		}
		mu.Unlock()
		if !allowed {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(path, "/authorization") && strings.Contains(path, "/group/sealed/deliveries/") {
			parts := strings.Split(strings.Trim(path, "/"), "/")
			messageID := parts[len(parts)-2]
			mu.Lock()
			denyFinal := false
			if messageID == denyFinalAuthorizationFor {
				authorizationCounts[messageID]++
				denyFinal = authorizationCounts[messageID] == 3
			}
			mu.Unlock()
			if denyFinal {
				http.Error(w, "current route revoked before injection", http.StatusNotFound)
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		dataPlane.ServeHTTP(w, r)
	}))
	defer hub.Close()
	bridgeA, err := startMachineAgentJoinBridge(ctxA, stateDir, hub.URL, nodeA, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridgeA.Close() })
	bridgeB, err := startMachineAgentJoinBridge(ctxB, stateDir, hub.URL, nodeB, tokenB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridgeB.Close() })
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	t.Setenv("CICADA_WORKSPACE", workspace)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	t.Setenv("CICADA_NODE_TOKEN", "")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	t.Setenv("CICADA_HUB_ID", hubID)
	closeMCP := func(server *mcpServer) {
		if server == nil {
			return
		}
		if server.outbox != nil {
			_ = server.outbox.close()
			server.outbox = nil
		}
		select {
		case <-server.stop:
		default:
			close(server.stop)
		}
	}
	newJoinedSession := func(nodeID, nativeID string) *mcpServer {
		t.Helper()
		t.Setenv("CICADA_MACHINE_ID", nodeID)
		t.Setenv("CODEX_THREAD_ID", nativeID)
		t.Setenv("CODEX_SESSION_ID", "session-"+nativeID)
		server := newMCPServer(hub.URL, "", filepath.Join(t.TempDir(), "mcp", "session.json"))
		if _, err := server.callTool("cicada_join", map[string]any{"group_id": groupID}); err != nil {
			t.Fatalf("join native session %s: %v", nativeID, err)
		}
		server.sessionMu.RLock()
		endpoint := server.sessionPublic.Endpoint
		card := server.sessionPublic.NetworkCard
		server.sessionMu.RUnlock()
		if endpoint.ID == "" || card.NodeID != nodeID || card.GroupID != groupID ||
			card.Capabilities["local_peer_delivery"] != "sealed_v1" {
			t.Fatalf("joined session lacks the expected Node-local sealed route: endpoint=%#v card=%#v", endpoint, card)
		}
		t.Cleanup(func() { closeMCP(server) })
		return server
	}
	source := newJoinedSession(nodeA, nativeA)
	target := newJoinedSession(nodeB, nativeB)
	trustOwnerOnNode := func(nodeID string) {
		t.Helper()
		crypto, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, nodeID))
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := nodekeys.PeerKeyFingerprint(ownerIdentity.Public())
		if err != nil {
			_ = crypto.Close()
			t.Fatal(err)
		}
		if _, err := crypto.TrustOwnerApprovalKeyLocal(ownerID, ownerKey.KeyID,
			ownerIdentity.Public(), fingerprint); err != nil {
			_ = crypto.Close()
			t.Fatal(err)
		}
		if err := crypto.Close(); err != nil {
			t.Fatal(err)
		}
	}
	trustOwnerOnNode(nodeA)
	trustOwnerOnNode(nodeB)
	grantEndpoint := func(endpointID string) {
		t.Helper()
		manifest, err := persistence.PreviewGroupEndpointKeyGrant(ownerID, group.ID,
			endpointID, ownerKey.KeyID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		issuedAt, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := ownerIdentity.SignOwnerLinkKeyGrant(ownerID,
			store.GroupEndpointKeyGrantOperation, manifest.Digest, manifest.CandidateBindingDigest,
			uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.AcceptGroupEndpointKeyGrant(ownerID, group.ID,
			endpointID, ownerKey.KeyID, proof); err != nil {
			t.Fatal(err)
		}
	}
	grantEndpoint(source.endpointID)
	grantEndpoint(target.endpointID)

	// The trusted Hub identity is local configuration, independent of Store's
	// Hub response. Missing and mismatched values fail before encryption/send.
	t.Setenv("CICADA_HUB_ID", "")
	if _, err := bridgeA.fetchCrossNodeGroupPeerKey(group.ID, source.endpointID, target.endpointID); err == nil {
		t.Fatal("missing local Hub ID accepted current grant evidence")
	}
	t.Setenv("CICADA_HUB_ID", "hub_wrong_cross_node_group")
	if _, err := bridgeA.fetchCrossNodeGroupPeerKey(group.ID, source.endpointID, target.endpointID); err == nil {
		t.Fatal("peer evidence from a different Hub passed the local Hub identity check")
	}
	t.Setenv("CICADA_HUB_ID", hubID)
	peerKey, err := bridgeA.fetchCrossNodeGroupPeerKey(group.ID, source.endpointID, target.endpointID)
	if err != nil || peerKey.Receiver.NativeSessionID != "" {
		t.Fatalf("correct Hub evidence was rejected or leaked receiver native identity: %#v err=%v", peerKey, err)
	}
	if _, err := bridgeA.fetchCrossNodeGroupPeerKey(otherGroup.ID, source.endpointID, target.endpointID); err == nil {
		t.Fatal("cross-Group peer key evidence was accepted")
	}

	// Stop the receiver bridge after enrollment. Hub accepts the opaque envelope
	// durably while the target is offline; restarting the same Node state later
	// preserves the key, inbox, replay window, and native Session route.
	if err := bridgeB.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_MACHINE_ID", nodeA)
	t.Setenv("CODEX_THREAD_ID", nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeA)
	sendResult, err := source.callTool("cicada_send", map[string]any{
		"target": target.endpointID, "body": sendBody, "idempotency_key": "cross-node-send-key",
	})
	if err != nil {
		t.Fatalf("sealed cross-Node SEND: %v", err)
	}
	sendPublic, ok := sendResult.(map[string]any)
	if !ok || sendPublic["status"] != mcpOutboxStatusSent || sendPublic["payload_mode"] != "SEALED_V1" ||
		sendPublic["delivery"] != "RELAY_PERSISTED" || sendPublic["message_id"] == "" {
		t.Fatalf("cross-Node SEND was not accepted with a compact Hub receipt: %#v", sendResult)
	}
	sendMessageID, _ := sendPublic["message_id"].(string)
	storedSend, err := persistence.GetRelaySealedV1(sendMessageID)
	if err != nil || storedSend == nil || storedSend.PayloadMode != store.RelayPayloadModeSealedV1 ||
		bytes.Contains(storedSend.Ciphertext, []byte(sendBody)) {
		t.Fatalf("Hub did not persist only opaque SEND ciphertext: record=%#v err=%v", storedSend, err)
	}
	bridgeB, err = startMachineAgentJoinBridge(ctxB, stateDir, hub.URL, nodeB, tokenB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bridgeB.Close() }()

	processTarget := func() (string, string) {
		t.Helper()
		t.Setenv("CICADA_NODE_TOKEN", tokenB)
		t.Setenv("CICADA_NODE_TOKEN_FILE", "")
		argsPath, countPath := installMachineSealedFakeCodex(t, false, tokenB)
		inbox, err := nodeinbox.Open(machineNodeInboxPath(stateDir, nodeB))
		if err != nil {
			t.Fatal(err)
		}
		defer inbox.Close()
		if err := processMachineFabricDeliveriesV2(context.Background(), hub.URL, nodeB, inbox, stateDir); err != nil {
			t.Fatalf("process receiver Node Group inbox: %v", err)
		}
		return argsPath, countPath
	}
	targetArgs, targetCount := processTarget()
	assertNativeInjection := func(argsPath, countPath, nativeID, plaintext string) {
		t.Helper()
		args, err := os.ReadFile(argsPath)
		if err != nil {
			t.Fatal(err)
		}
		count, err := os.ReadFile(countPath)
		if err != nil || string(count) != "x" ||
			!bytes.Contains(args, []byte("queue\n--thread\n"+nativeID+"\n--message\n")) ||
			!bytes.Contains(args, []byte(plaintext)) {
			t.Fatalf("exact native Thread delivery failed: count=%q args=%q err=%v", count, args, err)
		}
	}
	assertNativeInjection(targetArgs, targetCount, nativeB, sendBody)
	target.sessionMu.RLock()
	targetBindingEpoch := target.sessionPublic.BindingEpoch
	target.sessionMu.RUnlock()
	targetInbox, err := nodeinbox.Open(machineNodeInboxPath(stateDir, nodeB))
	if err != nil {
		t.Fatal(err)
	}
	visibleSend, err := targetInbox.ListInjectedForSession(context.Background(), target.endpointID,
		nativeB, targetBindingEpoch, groupID, 0, 8)
	wrongGroupVisible, wrongGroupErr := targetInbox.ListInjectedForSession(context.Background(), target.endpointID,
		nativeB, targetBindingEpoch, otherGroup.ID, 0, 8)
	_ = targetInbox.Close()
	if err != nil || len(visibleSend) != 1 || visibleSend[0].MessageID != sendMessageID ||
		visibleSend[0].Body != sendBody || visibleSend[0].Kind != "SEND" ||
		visibleSend[0].SenderEndpointID != source.endpointID ||
		wrongGroupErr != nil || len(wrongGroupVisible) != 0 {
		t.Fatalf("cross-Node message was not retained in only its current Group inbox: visible=%#v wrong=%#v err=%v wrongErr=%v",
			visibleSend, wrongGroupVisible, err, wrongGroupErr)
	}
	mu.Lock()
	sequenceAfterSend := append([]string(nil), receiptSequence...)
	mu.Unlock()
	findSequenceEvent := func(sequence []string, event string, start int) int {
		for index := start; index < len(sequence); index++ {
			if sequence[index] == event {
				return index
			}
		}
		return -1
	}
	authBeforeNodeReceived := findSequenceEvent(sequenceAfterSend, "authorization:"+sendMessageID, 0)
	nodeReceived := findSequenceEvent(sequenceAfterSend,
		"receipt:"+sendMessageID+":"+fabric.ReceiptNodeReceived, 0)
	guardRecheck := findSequenceEvent(sequenceAfterSend, "authorization:"+sendMessageID, authBeforeNodeReceived+1)
	finalGuardRecheck := findSequenceEvent(sequenceAfterSend, "authorization:"+sendMessageID, guardRecheck+1)
	if authBeforeNodeReceived < 0 || nodeReceived <= authBeforeNodeReceived ||
		guardRecheck <= nodeReceived || finalGuardRecheck <= guardRecheck {
		t.Fatalf("receiver did not report NODE_RECEIVED before the exact current Guard recheck: %v", sequenceAfterSend)
	}
	if delivery, err := persistence.GetRelaySealedV1(sendMessageID); err != nil || delivery == nil ||
		delivery.Route.ReceiverEndpointID != target.endpointID {
		t.Fatalf("SEND route did not retain the current exact receiver: %#v err=%v", delivery, err)
	}

	// ASK and REPLY use the durable MCP outboxes and compact Hub receipts. The
	// Node derives reverse routing only from the original request record.
	t.Setenv("CICADA_MACHINE_ID", nodeA)
	t.Setenv("CODEX_THREAD_ID", nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeA)
	askResult, err := source.callTool("cicada_ask", map[string]any{
		"target": target.endpointID, "question": question, "idempotency_key": "cross-node-ask-key",
	})
	if err != nil {
		t.Fatalf("sealed cross-Node ASK: %v", err)
	}
	askPublic, ok := askResult.(map[string]any)
	if !ok || askPublic["status"] != mcpOutboxStatusSent || askPublic["payload_mode"] != "SEALED_V1" ||
		askPublic["delivery"] != "RELAY_PERSISTED" {
		t.Fatalf("cross-Node ASK was not durably accepted: %#v", askResult)
	}
	requestID, _ := askPublic["request_id"].(string)
	askMessageID, _ := askPublic["message_id"].(string)
	if requestID == "" || askMessageID == "" {
		t.Fatalf("cross-Node ASK omitted durable request/message IDs: %#v", askResult)
	}
	if ask, err := persistence.GetSameGroupSealedV1RequestStatus(fabric.HashSessionCredential(tokenA), requestID); err != nil || ask == nil ||
		ask.MessageID != askMessageID || ask.SenderEndpointID != source.endpointID ||
		ask.ReceiverEndpointID != target.endpointID || ask.VisibilityPolicyRef != store.SameGroupSealedV1DataScope {
		t.Fatalf("Hub did not retain the exact asynchronous ASK route: %#v err=%v", ask, err)
	}
	// Reopening the MCP outbox proves the accepted request and correlation
	// metadata survive client process restart without exposing its question.
	sourceStatePath := source.sessionStatePath
	closeMCP(source)
	source = newMCPServer(hub.URL, "", sourceStatePath)
	restartedSource := source
	t.Cleanup(func() { closeMCP(restartedSource) })
	t.Setenv("CICADA_MACHINE_ID", nodeA)
	t.Setenv("CODEX_THREAD_ID", nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeA)
	if err := source.restoreSession(harness.SessionContext{
		Harness: "codex", NativeSessionID: nativeA, MachineID: nodeA, Workspace: workspace,
	}); err != nil {
		t.Fatalf("restore source MCP's durable native session after restart: %v", err)
	}
	statusResult, err := source.callTool("cicada_operation_status", map[string]any{
		"operation_id": askPublic["operation_id"],
	})
	if err != nil {
		t.Fatalf("read durable ASK outbox after MCP restart: %v", err)
	}
	statusPublic, ok := statusResult.(map[string]any)
	if !ok || statusPublic["status"] != mcpOutboxStatusSent || statusPublic["request_id"] != requestID {
		t.Fatalf("restarted MCP lost the durable ASK receipt: %#v", statusResult)
	}

	t.Setenv("CICADA_MACHINE_ID", nodeB)
	t.Setenv("CODEX_THREAD_ID", nativeB)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeB)
	askArgs, askCount := processTarget()
	assertNativeInjection(askArgs, askCount, nativeB, question)
	// The MCP boundary caps a model-requested oversized page to the Node's
	// supported bound instead of rejecting an otherwise valid sealed inbox read.
	receivedAsk, err := target.callTool("cicada_receive", map[string]any{"limit": 64})
	if err != nil {
		t.Fatalf("native target could not read its scoped injected Group inbox: %v", err)
	}
	askPage, ok := receivedAsk.(map[string]any)
	askMessages, messagesOK := askPage["messages"].([]nodeinbox.VisibleMessage)
	if !ok || !messagesOK {
		t.Fatalf("cross-Node ASK receive returned an invalid shape: %#v", receivedAsk)
	}
	foundAsk := false
	for _, message := range askMessages {
		if message.MessageID == askMessageID {
			foundAsk = message.Kind == "REQUEST" && message.RequestID == requestID &&
				message.ReplyTo == "" && message.SenderEndpointID == source.endpointID
		}
	}
	if !foundAsk {
		t.Fatalf("cross-Node ASK receive omitted its verified route: %#v", askMessages)
	}
	replyResult, err := target.callTool("cicada_reply", map[string]any{
		"request_id": requestID, "body": answer, "idempotency_key": "cross-node-reply-key",
	})
	if err != nil {
		t.Fatalf("sealed cross-Node REPLY: %v", err)
	}
	replyPublic, ok := replyResult.(map[string]any)
	if !ok || replyPublic["status"] != mcpOutboxStatusSent || replyPublic["payload_mode"] != "SEALED_V1" ||
		replyPublic["delivery"] != "RELAY_PERSISTED" || replyPublic["request_id"] != requestID {
		t.Fatalf("cross-Node REPLY was not durably accepted: %#v", replyResult)
	}
	replyMessageID, _ := replyPublic["message_id"].(string)
	if replyMessageID == "" {
		t.Fatalf("cross-Node REPLY omitted its message ID: %#v", replyResult)
	}
	requestAfterReply, err := persistence.GetSameGroupSealedV1RequestStatus(fabric.HashSessionCredential(tokenA), requestID)
	if err != nil || requestAfterReply == nil || requestAfterReply.ReplyMessageID != replyMessageID ||
		requestAfterReply.ReceiverEndpointID != target.endpointID || requestAfterReply.SenderEndpointID != source.endpointID {
		t.Fatalf("REPLY did not preserve the original reverse route: %#v err=%v", requestAfterReply, err)
	}
	t.Setenv("CICADA_MACHINE_ID", nodeA)
	t.Setenv("CICADA_NODE_TOKEN", tokenA)
	t.Setenv("CODEX_THREAD_ID", nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeA)
	replyArgs, replyCount := func() (string, string) {
		argsPath, countPath := installMachineSealedFakeCodex(t, false, tokenA)
		inbox, err := nodeinbox.Open(machineNodeInboxPath(stateDir, nodeA))
		if err != nil {
			t.Fatal(err)
		}
		defer inbox.Close()
		if err := processMachineFabricDeliveriesV2(context.Background(), hub.URL, nodeA, inbox, stateDir); err != nil {
			t.Fatalf("process source Node REPLY inbox: %v", err)
		}
		return argsPath, countPath
	}()
	assertNativeInjection(replyArgs, replyCount, nativeA, answer)
	receivedReply, err := source.callTool("cicada_receive", map[string]any{"limit": 8})
	if err != nil {
		t.Fatalf("native source could not read its scoped injected Group inbox: %v", err)
	}
	replyPage, ok := receivedReply.(map[string]any)
	replyMessages, messagesOK := replyPage["messages"].([]nodeinbox.VisibleMessage)
	if !ok || !messagesOK {
		t.Fatalf("cross-Node REPLY receive returned an invalid shape: %#v", receivedReply)
	}
	foundReply := false
	for _, message := range replyMessages {
		if message.MessageID == replyMessageID {
			foundReply = message.Kind == "REPLY" && message.RequestID == requestID &&
				message.ReplyTo == askMessageID && message.SenderEndpointID == target.endpointID
		}
	}
	if !foundReply {
		t.Fatalf("cross-Node REPLY receive omitted its verified route: %#v", replyMessages)
	}

	// A Node cancellation has no reason field in the Hub contract. Reject it
	// locally when supplied, and exercise the actual `{}` Hub cancellation.
	t.Setenv("CICADA_MACHINE_ID", nodeA)
	t.Setenv("CODEX_THREAD_ID", nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeA)
	cancelAskResult, err := source.callTool("cicada_ask", map[string]any{
		"target": target.endpointID, "question": "cancel this remote request",
		"idempotency_key": "cross-node-cancel-ask-key",
	})
	if err != nil {
		t.Fatalf("submit cancellation contract ASK: %v", err)
	}
	cancelAsk, ok := cancelAskResult.(map[string]any)
	if !ok || cancelAsk["status"] != mcpOutboxStatusSent {
		t.Fatalf("cancellation contract ASK was not accepted: %#v", cancelAskResult)
	}
	cancelRequestID, _ := cancelAsk["request_id"].(string)
	if cancelRequestID == "" {
		t.Fatalf("cancellation contract ASK has no request ID: %#v", cancelAskResult)
	}
	if _, err := source.callTool("cicada_request_cancel", map[string]any{
		"request_id": cancelRequestID, "reason": "unsupported reason",
	}); err == nil {
		t.Fatal("cross-Node cancel reason was silently dropped")
	}
	cancelResult, err := source.callTool("cicada_request_cancel", map[string]any{
		"request_id": cancelRequestID,
	})
	if err != nil {
		t.Fatalf("cross-Node cancellation with the supported empty body: %v", err)
	}
	cancelPublic, ok := cancelResult.(map[string]any)
	if !ok || cancelPublic["request_id"] != cancelRequestID ||
		(cancelPublic["state"] != store.FabricRequestCancelRequested && cancelPublic["state"] != store.FabricRequestCancelled) {
		t.Fatalf("cross-Node cancellation returned an invalid compact status: %#v", cancelResult)
	}

	// Denying the post-crypto exact-attempt Guard check must stop the final
	// injection even though the message was claimed, decrypted, and saved.
	t.Setenv("CICADA_MACHINE_ID", nodeA)
	t.Setenv("CODEX_THREAD_ID", nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeA)
	deniedResult, err := source.callTool("cicada_send", map[string]any{
		"target": target.endpointID, "body": "must be denied at final Guard", "idempotency_key": "cross-node-final-guard-deny",
	})
	if err != nil {
		t.Fatalf("submit final-Guard test message: %v", err)
	}
	deniedPublic, ok := deniedResult.(map[string]any)
	if !ok || deniedPublic["status"] != mcpOutboxStatusSent {
		t.Fatalf("final-Guard test message was not durably accepted: %#v", deniedResult)
	}
	deniedMessageID, _ := deniedPublic["message_id"].(string)
	mu.Lock()
	denyFinalAuthorizationFor = deniedMessageID
	mu.Unlock()
	t.Setenv("CICADA_MACHINE_ID", nodeB)
	t.Setenv("CICADA_NODE_TOKEN", tokenB)
	deniedArgs, deniedCount := installMachineSealedFakeCodex(t, false, tokenB)
	deniedInbox, err := nodeinbox.Open(machineNodeInboxPath(stateDir, nodeB))
	if err != nil {
		t.Fatal(err)
	}
	if err := processMachineFabricDeliveriesV2(context.Background(), hub.URL, nodeB, deniedInbox, stateDir); err != nil {
		_ = deniedInbox.Close()
		t.Fatalf("process final-Guard-denied delivery: %v", err)
	}
	deniedDelivery, getErr := deniedInbox.Get(context.Background(), deniedMessageID)
	_ = deniedInbox.Close()
	if getErr != nil || deniedDelivery == nil || deniedDelivery.State != nodeinbox.FAILED {
		t.Fatalf("final Guard denial did not fence the local delivery: %#v err=%v", deniedDelivery, getErr)
	}
	if _, err := os.Stat(deniedCount); !os.IsNotExist(err) {
		t.Fatalf("final Guard denial reached fake Codex queue; args=%s countErr=%v", deniedArgs, err)
	}

	// The transport must never downgrade to plaintext or touch Control. Every
	// remote write uses the fixed scope and carries ciphertext only.
	mu.Lock()
	paths := append([]string(nil), hubPaths...)
	unexpected := append([]string(nil), unexpectedPaths...)
	plaintextSeen := sawPlaintext
	routeEvents := append([]string(nil), events...)
	mu.Unlock()
	if plaintextSeen {
		t.Fatal("Hub observed a cross-Node SEND, ASK, or REPLY body in plaintext")
	}
	if len(unexpected) != 0 {
		t.Fatalf("cross-Node path used plaintext Fabric, Control, or unexpected Hub routes: %v", unexpected)
	}
	for _, suffix := range []string{"/group/sealed/peer-key", "/group/sealed/send", "/group/sealed/ask", "/group/sealed/reply", "/group/sealed/claim"} {
		found := false
		for _, path := range routeEvents {
			if strings.HasSuffix(path, suffix) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("full chain did not exercise Node-only Hub route %s; routes=%v all=%v", suffix, routeEvents, paths)
		}
	}
	for _, forbidden := range []string{"/v2/fabric/send", "/v2/fabric/ask", "/v2/fabric/reply", "/v2/control/"} {
		for _, path := range paths {
			if strings.HasPrefix(path, forbidden) {
				t.Fatalf("sealed cross-Node path reached forbidden route %s", path)
			}
		}
	}
	t.Log("harness limitation: two isolated Node state directories and the fake Codex queue verify routing and exact Thread arguments; no real Codex model or physical second Node was run")
}

func TestCrossNodeGroupCancelRejectsUnsupportedReason(t *testing.T) {
	request := crossNodeGroupRequest{
		Version: crossNodeGroupProtocolVersion, Operation: "cross_node_group_cancel",
		Harness: "codex", NativeSessionID: "native", NodeID: "node", Workspace: "/workspace",
		SessionToken: "session", EndpointID: "endpoint", PrincipalID: "principal", OwnerID: "owner",
		GroupID: "group", BindingID: "binding", BindingEpoch: 1,
		RequestID: "request", Reason: "not supported by the Node Group API",
	}
	if err := validateCrossNodeGroupRequest(request, "node"); err == nil {
		t.Fatal("cross-Node cancellation silently accepted a reason the Hub contract cannot retain")
	}
}

func TestCommunicationLinkSealedInboxRetainsGroupForScopedReceive(t *testing.T) {
	fixture := newMachineSealedReceiveFixture(t)
	installMachineSealedFakeCodex(t, false, fixture.targetToken)
	linkHub := fixture.server(t, nil)
	defer linkHub.Close()
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/relay/nodes/"+fixture.targetNodeID+"/group/sealed/claim" {
			if r.Header.Get("Authorization") != "CicadaNode "+fixture.targetToken {
				http.Error(w, "wrong Node", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"deliveries":[]}`))
			return
		}
		linkHub.Config.Handler.ServeHTTP(w, r)
	}))
	defer hub.Close()
	inbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	if err := processMachineFabricDeliveriesV2(context.Background(), hub.URL,
		fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
		t.Fatalf("process Link sealed delivery: %v", err)
	}
	nativeID := "native_" + fixture.targetEndpoint
	visible, err := inbox.ListInjectedForSession(context.Background(), fixture.targetEndpoint,
		nativeID, fixture.manifest.Target.BindingEpoch, fixture.link.TargetGroupID, 0, 8)
	if err != nil || len(visible) != 1 || visible[0].MessageID != fixture.messageID ||
		visible[0].Body != "private message for the original session" {
		t.Fatalf("injected Link message is missing from its exact Group-scoped inbox: %#v err=%v", visible, err)
	}
	otherGroup, err := inbox.ListInjectedForSession(context.Background(), fixture.targetEndpoint,
		nativeID, fixture.manifest.Target.BindingEpoch, "different-group", 0, 8)
	if err != nil || len(otherGroup) != 0 {
		t.Fatalf("Link inbox crossed its verified receiver Group scope: %#v err=%v", otherGroup, err)
	}
}

func TestCommunicationLinkSealedRecoveryRetainsGroupForScopedReceive(t *testing.T) {
	fixture := newMachineSealedReceiveFixture(t)
	t.Setenv("CICADA_NODE_TOKEN", fixture.targetToken)
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	ctx := context.Background()
	deliveries, err := fixture.service.ClaimNodeSealedDeliveries(fixture.targetToken,
		fixture.targetNodeID, fabric.NodeClaimInput{
			ConsumerID: machineRelayConsumerID(fixture.targetNodeID), Limit: 50,
		})
	if err != nil || len(deliveries) != 1 || deliveries[0].MessageID != fixture.messageID {
		t.Fatalf("could not claim seeded Link delivery for recovery: %#v err=%v", deliveries, err)
	}
	delivery := deliveries[0]
	authorization, err := fixture.service.AuthorizeNodeSealedDelivery(fixture.targetToken,
		delivery.MessageID, delivery.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openMachineSealedDelivery(ctx, fixture.stateDir, fixture.targetNodeID,
		delivery, *authorization)
	if err != nil || opened.Duplicate {
		t.Fatalf("seed crash-window Node crypto inbox: duplicate=%t err=%v", opened.Duplicate, err)
	}
	journal, err := openMachineRelayJournal(fixture.stateDir, fixture.targetNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.putSealed(delivery, authorization.DataScope); err != nil {
		t.Fatal(err)
	}
	inbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	linkHub := fixture.server(t, nil)
	defer linkHub.Close()
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/relay/nodes/"+fixture.targetNodeID+"/group/sealed/claim" {
			_, _ = w.Write([]byte(`{"deliveries":[]}`))
			return
		}
		linkHub.Config.Handler.ServeHTTP(w, r)
	}))
	defer hub.Close()
	entry := journal.entry(delivery.MessageID)
	if entry == nil {
		t.Fatal("sealed crash-window journal row was not persisted")
	}
	if err := recoverMachineSealedInboxSave(ctx, hub.URL, fixture.stateDir,
		fixture.targetNodeID, inbox, *entry); err != nil {
		t.Fatalf("recover Link sealed inbox save: %v", err)
	}
	installMachineSealedFakeCodex(t, false, fixture.targetToken)
	if err := processMachineFabricDeliveriesV2(ctx, hub.URL, fixture.targetNodeID,
		inbox, fixture.stateDir); err != nil {
		t.Fatalf("drain recovered Link sealed delivery: %v", err)
	}
	visible, err := inbox.ListInjectedForSession(ctx, fixture.targetEndpoint,
		"native_"+fixture.targetEndpoint, fixture.manifest.Target.BindingEpoch,
		fixture.link.TargetGroupID, 0, 8)
	if err != nil || len(visible) != 1 || visible[0].MessageID != fixture.messageID ||
		visible[0].Body != "private message for the original session" || visible[0].Kind != "SEND" ||
		visible[0].RequestID != "" || visible[0].ReplyTo != "" ||
		visible[0].SenderEndpointID != fixture.sourceEndpoint {
		t.Fatalf("recovered Link message is missing from its exact Group-scoped inbox: %#v err=%v", visible, err)
	}
}
