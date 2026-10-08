package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// Two owner-bound Nodes, two native-session records, the production MCP and
// local bridges, Store/Fabric, ciphertext claim, and exact Codex queue run
// through one Hub API. Codex itself is a recording fake: this proves the
// protocol and Control isolation, not real model consumption or two hosts.
func TestMCPSealedAskReplyAcrossTwoLogicalNodesWithoutControlBusiness(t *testing.T) {
	fixture := newMachineSealedReceiveFixtureWithOwnerGrantTimingDirectionAndJoin(t, false,
		"ask", []string{"ask", "reply"}, []string{"message.ask"}, "", "", false, "forward", true)
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	for _, nativeID := range []string{"native_" + fixture.sourceEndpoint, "native_" + fixture.targetEndpoint} {
		writeCodexSessionRecord(t, codexHome, nativeID, workspace)
	}
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_NODE_STATE_DIR", fixture.stateDir)
	t.Setenv("CICADA_WORKSPACE", workspace)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")

	sourceSession := fixture.sourceJoin.SessionToken
	targetSession := fixture.targetJoin.SessionToken
	const question = "private cross-owner question"
	const answer = "private correlated answer"
	cards := make(map[string]fabric.NetworkCard)
	const managerToken = "PUBLIC_SYNTHETIC_MANAGER_TOKEN"
	production := server.NewFabricHandler(fixture.service, managerToken)
	var sealedWireBodies [][]byte
	var receiptLayers []string
	var observedMu sync.Mutex
	hub := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		if request.Method == http.MethodPost &&
			(strings.HasSuffix(path, "/sealed/ask") || strings.HasSuffix(path, "/sealed/reply") ||
				strings.HasSuffix(path, "/receipts")) {
			wire, err := io.ReadAll(io.LimitReader(request.Body, 512*1024+1))
			if err != nil || len(wire) > 512*1024 {
				t.Error("fixture observation body exceeded its bound")
				http.Error(response, "fixture observation failed", http.StatusBadRequest)
				return
			}
			_ = request.Body.Close()
			request.Body = io.NopCloser(bytes.NewReader(wire))
			observedMu.Lock()
			if strings.HasSuffix(path, "/receipts") {
				var receipt fabric.NodeReceiptInput
				if err := json.Unmarshal(wire, &receipt); err != nil {
					t.Error(err)
				}
				receiptLayers = append(receiptLayers, receipt.Layer)
			} else {
				if bytes.Contains(wire, []byte(question)) || bytes.Contains(wire, []byte(answer)) {
					t.Error("Hub observed peer plaintext in sealed traffic")
				}
				sealedWireBodies = append(sealedWireBodies, wire)
			}
			observedMu.Unlock()
		}
		production.ServeHTTP(response, request)
	}))
	defer hub.Close()
	for _, bearer := range []string{"", "Bearer PUBLIC_SYNTHETIC_WRONG_TOKEN"} {
		request, err := http.NewRequest(http.MethodGet, hub.URL+"/v1/status", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", bearer)
		response, err := hub.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("missing/wrong Manager bearer must be rejected: %d", response.StatusCode)
		}
	}
	managerRequest, err := http.NewRequest(http.MethodGet, hub.URL+"/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	managerRequest.Header.Set("Authorization", "Bearer "+managerToken)
	managerResponse, err := hub.Client().Do(managerRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = managerResponse.Body.Close()
	if managerResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("authenticated Manager status must be unavailable without Control: %d", managerResponse.StatusCode)
	}

	for _, joined := range []*fabric.JoinResult{fixture.sourceJoin, fixture.targetJoin} {
		request, err := http.NewRequest(http.MethodGet, hub.URL+"/v2/fabric/whoami", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "CicadaSession "+joined.SessionToken)
		request.Header.Set("Cicada-Group-Scope", joined.NetworkCard.GroupID)
		response, err := hub.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var card fabric.NetworkCard
		decodeErr := json.NewDecoder(response.Body).Decode(&card)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || decodeErr != nil ||
			card.EndpointID != joined.Endpoint.ID || card.BindingID != joined.BindingID ||
			card.BindingEpoch != joined.BindingEpoch || card.NativeSessionID != joined.Endpoint.NativeSessionID {
			t.Fatalf("production whoami did not authenticate the joined binding: status=%d card=%#v err=%v", response.StatusCode, card, decodeErr)
		}
		cards[joined.SessionToken] = card
	}

	hubID, err := fixture.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_HUB_ID", hubID)
	for _, node := range []struct{ id, token string }{{fixture.sourceNodeID, fixture.sourceToken}, {fixture.targetNodeID, fixture.targetToken}} {
		bridgeCtx := pinnedNativeTestHubContext(context.Background(), hubID, node.id,
			fixture.stateDir, hub.URL, node.token)
		bridge, err := startMachineAgentJoinBridge(bridgeCtx, fixture.stateDir, hub.URL, node.id, node.token)
		if err != nil {
			t.Fatal(err)
		}
		defer bridge.Close()
	}
	setNative := func(nodeID, endpointID string) {
		t.Setenv("CICADA_MACHINE_ID", nodeID)
		t.Setenv("CODEX_THREAD_ID", "native_"+endpointID)
		t.Setenv("CODEX_SESSION_ID", "session-native_"+endpointID)
	}
	newMCP := func(sessionToken string) *mcpServer {
		card := cards[sessionToken]
		origin, err := normalizeMCPAPIOrigin(hub.URL)
		if err != nil {
			t.Fatal(err)
		}
		current := mcpTestContext("codex", card.NativeSessionID, card.NodeID, workspace)
		scope, trusted, err := mcpSessionScope(origin, current)
		if err != nil {
			t.Fatal(err)
		}
		mcp := newMCPServer(hub.URL, card.EndpointID, filepath.Join(t.TempDir(), "mcp", "sessions.json"))
		ownerID := fixture.link.SourceOwnerID
		if sessionToken == targetSession {
			ownerID = fixture.link.TargetOwnerID
		}
		mcp.setSession(sessionToken, card.EndpointID, card.GroupID, trusted, scope, mcpPublicJoinResult{
			Endpoint:    store.Endpoint{ID: card.EndpointID, GroupID: card.GroupID, Owner: ownerID},
			NetworkCard: card, BindingID: card.BindingID, BindingEpoch: card.BindingEpoch,
		})
		t.Cleanup(func() {
			if mcp.outbox != nil {
				_ = mcp.outbox.close()
			}
			close(mcp.stop)
		})
		return mcp
	}
	setNative(fixture.sourceNodeID, fixture.sourceEndpoint)
	sourceMCP := newMCP(sourceSession)
	setNative(fixture.targetNodeID, fixture.targetEndpoint)
	targetMCP := newMCP(targetSession)
	setNative(fixture.sourceNodeID, fixture.sourceEndpoint)
	asked, err := sourceMCP.callTool("cicada_ask", map[string]any{
		"link_id": fixture.link.ID, "data_scope": fixture.dataScope, "question": question,
	})
	if err != nil {
		t.Fatal(err)
	}
	askResult := asked.(map[string]any)
	requestID, _ := askResult["request_id"].(string)
	if askResult["status"] != mcpOutboxStatusSent || requestID == "" {
		t.Fatalf("sealed ASK was not durably accepted: %#v", askResult)
	}
	request, err := fixture.service.NodeSealedLinkRequestStatus(fixture.sourceToken, requestID)
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.store.GetRelaySealedV1(request.MessageID)
	if err != nil || first.PayloadMode != store.RelayPayloadModeSealedV1 ||
		bytes.Contains(first.Ciphertext, []byte(question)) {
		t.Fatalf("Hub retained plaintext ASK: %#v, %v", first, err)
	}

	targetArgs, targetCount := installMachineSealedFakeCodex(t, false, fixture.targetToken)
	targetInbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer targetInbox.Close()
	for i := 0; i < 2; i++ {
		if err := processPinnedTestMachineFabricDeliveries(context.Background(), hub.URL,
			fixture.targetNodeID, targetInbox, fixture.stateDir); err != nil {
			t.Fatal(err)
		}
	}
	targetPrompt, _ := os.ReadFile(targetArgs)
	targetQueueCount, _ := os.ReadFile(targetCount)
	if string(targetQueueCount) != "x" || !bytes.Contains(targetPrompt, []byte("native_"+fixture.targetEndpoint)) ||
		!bytes.Contains(targetPrompt, []byte(question)) || !bytes.Contains(targetPrompt, []byte(requestID)) {
		t.Fatalf("REQUEST did not queue once to exact target session: count=%q argv=%q", targetQueueCount, targetPrompt)
	}

	setNative(fixture.targetNodeID, fixture.targetEndpoint)
	replied, err := targetMCP.callTool("cicada_reply", map[string]any{
		"request_id": requestID, "link_id": fixture.link.ID, "body": answer,
	})
	if err != nil {
		t.Fatal(err)
	}
	replyResult := replied.(map[string]any)
	if replyResult["status"] != mcpOutboxStatusSent || replyResult["request_id"] != requestID {
		t.Fatalf("sealed REPLY was not durably correlated: %#v", replyResult)
	}
	replyMessageID, _ := replyResult["message_id"].(string)
	second, err := fixture.store.GetRelaySealedV1(replyMessageID)
	if err != nil || second.PayloadMode != store.RelayPayloadModeSealedV1 ||
		bytes.Contains(second.Ciphertext, []byte(answer)) {
		t.Fatalf("Hub retained plaintext REPLY: %#v, %v", second, err)
	}

	sourceArgs, sourceCount := installMachineSealedFakeCodex(t, false, fixture.sourceToken)
	sourceInbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.sourceNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer sourceInbox.Close()
	for i := 0; i < 2; i++ {
		if err := processPinnedTestMachineFabricDeliveries(context.Background(), hub.URL,
			fixture.sourceNodeID, sourceInbox, fixture.stateDir); err != nil {
			t.Fatal(err)
		}
	}
	sourcePrompt, _ := os.ReadFile(sourceArgs)
	sourceQueueCount, _ := os.ReadFile(sourceCount)
	if string(sourceQueueCount) != "x" || !bytes.Contains(sourcePrompt, []byte("native_"+fixture.sourceEndpoint)) ||
		!bytes.Contains(sourcePrompt, []byte(answer)) || !bytes.Contains(sourcePrompt, []byte(requestID)) ||
		!bytes.Contains(sourcePrompt, []byte(request.MessageID)) {
		t.Fatalf("REPLY did not queue once to original source session: count=%q argv=%q", sourceQueueCount, sourcePrompt)
	}
	observedMu.Lock()
	wireCount := len(sealedWireBodies)
	layers := append([]string(nil), receiptLayers...)
	observedMu.Unlock()
	if wireCount != 2 || len(layers) < 4 {
		t.Fatalf("missing opaque ASK/REPLY or layered Node receipts: bodies=%d receipts=%v", wireCount, layers)
	}
	setNative(fixture.sourceNodeID, fixture.sourceEndpoint)
	status, err := sourceMCP.callTool("cicada_request_status", map[string]any{
		"request_id": requestID, "link_id": fixture.link.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.(map[string]any)["status"] != string(store.FabricRequestReplied) {
		t.Fatalf("source status did not reflect correlated reply: %#v", status)
	}
}
