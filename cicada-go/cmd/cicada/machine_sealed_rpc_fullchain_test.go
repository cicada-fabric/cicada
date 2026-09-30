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
	"github.com/cicada-ai/cicada/internal/store"
)

// Two owner-bound Nodes, two native-session records, the production MCP and
// local bridges, Store/Fabric, ciphertext claim, and exact Codex queue run
// through one Hub API. Codex itself is a recording fake: this proves the
// protocol and Control isolation, not real model consumption or two hosts.
func TestMCPSealedAskReplyAcrossTwoLogicalNodesWithoutControlBusiness(t *testing.T) {
	fixture := newMachineSealedReceiveFixtureWithActions(t, false, "ask", []string{"ask", "reply"})
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

	const sourceSession = "cicada_session_sealed_source"
	const targetSession = "cicada_session_sealed_target"
	const question = "private cross-owner question"
	const answer = "private correlated answer"
	cards := map[string]fabric.NetworkCard{
		sourceSession: {
			EndpointID: fixture.sourceEndpoint, PrincipalID: fixture.link.SourcePrincipalID,
			GroupID: fixture.link.SourceGroupID, NodeID: fixture.sourceNodeID,
			Harness: "codex", Workspace: workspace, BindingID: fixture.manifest.Source.BindingID,
			BindingEpoch: fixture.manifest.Source.BindingEpoch, NativeSessionID: "native_" + fixture.sourceEndpoint,
		},
		targetSession: {
			EndpointID: fixture.targetEndpoint, PrincipalID: fixture.link.TargetPrincipalID,
			GroupID: fixture.link.TargetGroupID, NodeID: fixture.targetNodeID,
			Harness: "codex", Workspace: workspace, BindingID: fixture.manifest.Target.BindingID,
			BindingEpoch: fixture.manifest.Target.BindingEpoch, NativeSessionID: "native_" + fixture.targetEndpoint,
		},
	}
	tokens := map[string]string{fixture.sourceNodeID: fixture.sourceToken, fixture.targetNodeID: fixture.targetToken}
	var sealedWireBodies [][]byte
	var receiptLayers []string
	var observedMu sync.Mutex
	hub := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		if path == "/v2/fabric/whoami" {
			token := strings.TrimPrefix(request.Header.Get("Authorization"), "CicadaSession ")
			card, ok := cards[token]
			if !ok || request.Header.Get("Cicada-Group-Scope") != card.GroupID {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(response).Encode(card)
			return
		}
		if path == "/v2/fabric/node/networks/direct/claim" {
			credential := request.Header.Get("Authorization")
			if credential != "CicadaNode "+tokens[fixture.sourceNodeID] &&
				credential != "CicadaNode "+tokens[fixture.targetNodeID] {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
			return
		}
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) < 4 || parts[0] != "v2" || parts[1] != "relay" || parts[2] != "nodes" {
			t.Errorf("Control/business route invoked: %s %s", request.Method, path)
			response.WriteHeader(http.StatusNotFound)
			return
		}
		nodeID := parts[3]
		nodeToken := tokens[nodeID]
		if nodeToken == "" || request.Header.Get("Authorization") != "CicadaNode "+nodeToken {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case len(parts) == 6 && parts[4] == "links" && parts[5] == fixture.link.ID:
			t.Errorf("unexpected Link API route %s", path)
			response.WriteHeader(http.StatusNotFound)
		case len(parts) == 7 && parts[4] == "links" && parts[6] == "authorization":
			bundle, err := fixture.service.NodeCommunicationLinkAuthorizationBundle(nodeToken, parts[5])
			if err != nil {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(response).Encode(bundle)
		case len(parts) == 6 && parts[4] == "sealed" && parts[5] == "ask":
			wire, _ := io.ReadAll(io.LimitReader(request.Body, 512*1024))
			if bytes.Contains(wire, []byte(question)) || bytes.Contains(wire, []byte(answer)) {
				t.Error("Hub observed peer plaintext in sealed ASK")
			}
			observedMu.Lock()
			sealedWireBodies = append(sealedWireBodies, wire)
			observedMu.Unlock()
			var input fabric.NodeSealedLinkAskInput
			if json.Unmarshal(wire, &input) != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			accepted, err := fixture.service.AskNodeSealedLinkMessage(nodeToken, input)
			if err != nil {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			response.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(response).Encode(map[string]any{
				"request_id": accepted.RequestID, "message_id": accepted.MessageID,
				"state": accepted.State, "expires_at": accepted.ExpiresAt,
				"reply_mode": "asynchronous", "payload_mode": store.RelayPayloadModeSealedV1,
			})
		case len(parts) == 6 && parts[4] == "sealed" && parts[5] == "reply":
			wire, _ := io.ReadAll(io.LimitReader(request.Body, 512*1024))
			if bytes.Contains(wire, []byte(question)) || bytes.Contains(wire, []byte(answer)) {
				t.Error("Hub observed peer plaintext in sealed REPLY")
			}
			observedMu.Lock()
			sealedWireBodies = append(sealedWireBodies, wire)
			observedMu.Unlock()
			var input fabric.NodeSealedLinkReplyInput
			if json.Unmarshal(wire, &input) != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			accepted, err := fixture.service.ReplyNodeSealedLinkMessage(nodeToken, input)
			if err != nil {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			response.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(response).Encode(map[string]any{
				"request_id": accepted.RequestID, "message_id": input.MessageID,
				"state": accepted.State, "payload_mode": store.RelayPayloadModeSealedV1,
			})
		case len(parts) == 7 && parts[4] == "sealed" && parts[5] == "requests":
			status, err := fixture.service.NodeSealedLinkRequestStatus(nodeToken, parts[6])
			if err != nil {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(response).Encode(status)
		case len(parts) == 6 && parts[4] == "sealed" && parts[5] == "claim":
			var input fabric.NodeClaimInput
			if json.NewDecoder(request.Body).Decode(&input) != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			deliveries, err := fixture.service.ClaimNodeSealedDeliveries(nodeToken, nodeID, input)
			if err != nil {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": deliveries})
		case len(parts) == 7 && parts[4] == "sealed" && parts[6] == "authorization":
			authorization, err := fixture.service.AuthorizeNodeSealedDelivery(nodeToken,
				parts[5], request.URL.Query().Get("attempt_id"))
			if err != nil {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(response).Encode(authorization)
		case len(parts) == 7 && parts[4] == "group" && parts[5] == "sealed" && parts[6] == "claim":
			var input fabric.NodeClaimInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			deliveries, err := fixture.service.ClaimNodeSameGroupSealedV1Deliveries(nodeToken, nodeID, input)
			if err != nil {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": deliveries})
		case len(parts) == 5 && parts[4] == "claim":
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case len(parts) == 5 && parts[4] == "receipts":
			var input fabric.NodeReceiptInput
			if json.NewDecoder(request.Body).Decode(&input) != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			if _, err := fixture.service.RecordNodeReceipt(nodeID, input); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			observedMu.Lock()
			receiptLayers = append(receiptLayers, input.Layer)
			observedMu.Unlock()
			_ = json.NewEncoder(response).Encode(map[string]any{"status": input.Layer})
		default:
			t.Errorf("Control/business route invoked: %s %s", request.Method, path)
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer hub.Close()

	for _, node := range []struct{ id, token string }{{fixture.sourceNodeID, fixture.sourceToken}, {fixture.targetNodeID, fixture.targetToken}} {
		bridge, err := startMachineAgentJoinBridge(context.Background(), fixture.stateDir, hub.URL, node.id, node.token)
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
