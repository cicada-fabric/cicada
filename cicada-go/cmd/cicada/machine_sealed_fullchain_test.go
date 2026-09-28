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

// This exercises the complete production send/receive call path with two
// isolated Node state directories and a real Fabric/Store. The HTTP transport
// and official Codex queue binary are local test doubles; this is not a claim
// of real native model consumption or two physical machines.
func TestMCPSealedSendAcrossTwoLogicalNodesWithoutControlBusiness(t *testing.T) {
	fixture := newMachineSealedReceiveFixtureWithSeed(t, false)
	const sessionToken = "cicada_session_fullchain"
	const body = "private fullchain message"
	workspace := prepareLocalSealedBridgeSession(t, "native_ep_source")
	t.Setenv("CICADA_MACHINE_ID", fixture.sourceNodeID)
	t.Setenv("CICADA_NODE_STATE_DIR", fixture.stateDir)
	card := fabric.NetworkCard{
		EndpointID: fixture.link.SourceEndpointID, PrincipalID: fixture.link.SourcePrincipalID,
		GroupID: fixture.link.SourceGroupID, NodeID: fixture.sourceNodeID,
		Harness: "codex", Workspace: workspace,
		BindingID:       fixture.manifest.Source.BindingID,
		BindingEpoch:    fixture.manifest.Source.BindingEpoch,
		NativeSessionID: "native_ep_source",
	}
	var receipts []string
	var senderHTTPBody []byte
	var observedMu sync.Mutex
	hub := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/v2/fabric/node/networks/direct/claim":
			credential := request.Header.Get("Authorization")
			if credential != "CicadaNode "+fixture.sourceToken && credential != "CicadaNode "+fixture.targetToken {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case path == "/v2/fabric/whoami":
			if request.Header.Get("Authorization") != "CicadaSession "+sessionToken ||
				request.Header.Get("Cicada-Group-Scope") != fixture.link.SourceGroupID {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(response).Encode(card)
		case path == "/v2/relay/nodes/"+fixture.sourceNodeID+"/links/"+fixture.link.ID+"/authorization":
			if request.Header.Get("Authorization") != "CicadaNode "+fixture.sourceToken {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			bundle, err := fixture.service.NodeCommunicationLinkAuthorizationBundle(fixture.sourceToken, fixture.link.ID)
			if err != nil {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(response).Encode(bundle)
		case path == "/v2/relay/nodes/"+fixture.sourceNodeID+"/sealed/send":
			if request.Header.Get("Authorization") != "CicadaNode "+fixture.sourceToken {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			wire, err := io.ReadAll(io.LimitReader(request.Body, 512*1024+1))
			if err != nil || len(wire) > 512*1024 || bytes.Contains(wire, []byte(body)) {
				t.Errorf("Hub received plaintext or invalid sealed send request")
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			observedMu.Lock()
			senderHTTPBody = append([]byte(nil), wire...)
			observedMu.Unlock()
			var input fabric.NodeSealedLinkSendInput
			if err := json.Unmarshal(wire, &input); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			record, err := fixture.service.SendNodeSealedLinkMessage(fixture.sourceToken, input)
			if err != nil {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			response.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(response).Encode(map[string]any{
				"message_id": record.Route.MessageID, "payload_mode": record.PayloadMode,
				"outbox_state": record.OutboxState,
			})
		case path == "/v2/relay/nodes/"+fixture.targetNodeID+"/sealed/claim":
			if request.Header.Get("Authorization") != "CicadaNode "+fixture.targetToken {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			var input fabric.NodeClaimInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			deliveries, err := fixture.service.ClaimNodeSealedDeliveries(fixture.targetToken, fixture.targetNodeID, input)
			if err != nil {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": deliveries})
		case path == "/v2/relay/nodes/"+fixture.targetNodeID+"/group/sealed/claim":
			if request.Header.Get("Authorization") != "CicadaNode "+fixture.targetToken {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			var input fabric.NodeClaimInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			deliveries, err := fixture.service.ClaimNodeSameGroupSealedV1Deliveries(
				fixture.targetToken, fixture.targetNodeID, input)
			if err != nil {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": deliveries})
		case strings.HasPrefix(path, "/v2/relay/nodes/"+fixture.targetNodeID+"/sealed/") &&
			strings.HasSuffix(path, "/authorization"):
			if request.Header.Get("Authorization") != "CicadaNode "+fixture.targetToken {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			parts := strings.Split(strings.Trim(path, "/"), "/")
			authorization, err := fixture.service.AuthorizeNodeSealedDelivery(fixture.targetToken,
				parts[len(parts)-2], request.URL.Query().Get("attempt_id"))
			if err != nil {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(response).Encode(authorization)
		case path == "/v2/relay/nodes/"+fixture.targetNodeID+"/claim":
			if request.Header.Get("Authorization") != "CicadaNode "+fixture.targetToken {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case path == "/v2/relay/nodes/"+fixture.targetNodeID+"/receipts":
			if request.Header.Get("Authorization") != "CicadaNode "+fixture.targetToken {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			var input fabric.NodeReceiptInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			if _, err := fixture.service.RecordNodeReceipt(fixture.targetNodeID, input); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			observedMu.Lock()
			receipts = append(receipts, input.Layer)
			observedMu.Unlock()
			_ = json.NewEncoder(response).Encode(map[string]any{"status": input.Layer})
		default:
			// No Control business module exists in this fixture. Any unexpected
			// management route is an architectural test failure.
			t.Errorf("unexpected Hub route %s %s", request.Method, path)
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer hub.Close()

	bridge, err := startMachineAgentJoinBridge(context.Background(), fixture.stateDir,
		hub.URL, fixture.sourceNodeID, fixture.sourceToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	origin, err := normalizeMCPAPIOrigin(hub.URL)
	if err != nil {
		t.Fatal(err)
	}
	current := mcpTestContext("codex", "native_ep_source", fixture.sourceNodeID, workspace)
	scope, trusted, err := mcpSessionScope(origin, current)
	if err != nil {
		t.Fatal(err)
	}
	mcp := newMCPServer(hub.URL, card.EndpointID, filepath.Join(t.TempDir(), "mcp", "sessions.json"))
	mcp.setSession(sessionToken, card.EndpointID, card.GroupID, trusted, scope, mcpPublicJoinResult{
		Endpoint:    store.Endpoint{ID: card.EndpointID, GroupID: card.GroupID, Owner: fixture.link.SourceOwnerID},
		NetworkCard: card, BindingID: card.BindingID, BindingEpoch: card.BindingEpoch,
	})
	defer func() {
		if mcp.outbox != nil {
			_ = mcp.outbox.close()
		}
		close(mcp.stop)
	}()
	result, err := mcp.callTool("cicada_send", map[string]any{
		"link_id": fixture.link.ID, "data_scope": fixture.dataScope, "body": body,
	})
	if err != nil {
		t.Fatal(err)
	}
	operation := result.(map[string]any)
	observedMu.Lock()
	sentHTTPBody := append([]byte(nil), senderHTTPBody...)
	observedMu.Unlock()
	if operation["status"] != mcpOutboxStatusSent {
		t.Fatalf("sealed MCP send did not reach the durable Hub Relay: %#v", operation)
	}
	messageID, ok := operation["operation_id"].(string)
	if !ok || messageID == "" || len(sentHTTPBody) == 0 {
		t.Fatalf("sealed Hub acceptance missing message or opaque bytes: %#v", operation)
	}
	record, err := fixture.store.GetRelaySealedV1(messageID)
	if err != nil || bytes.Contains(record.Ciphertext, []byte(body)) || record.PayloadMode != store.RelayPayloadModeSealedV1 {
		t.Fatalf("Hub Store did not retain opaque SEALED_V1 bytes: record=%#v error=%v", record, err)
	}
	argumentsPath, countPath := installMachineSealedFakeCodex(t, false, fixture.targetToken)
	inbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	for attempt := 0; attempt < 2; attempt++ {
		if err := processMachineFabricDeliveriesV2(context.Background(), hub.URL,
			fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
			t.Fatalf("process target sealed delivery %d: %v", attempt, err)
		}
	}
	count, err := os.ReadFile(countPath)
	if err != nil || string(count) != "x" {
		t.Fatalf("target native queue count=%q error=%v", count, err)
	}
	argv, err := os.ReadFile(argumentsPath)
	if err != nil || !bytes.Contains(argv, []byte("native_"+fixture.targetEndpoint)) ||
		!bytes.Contains(argv, []byte(body)) {
		t.Fatalf("target did not receive plaintext in its exact native session: argv=%q error=%v", argv, err)
	}
	observedMu.Lock()
	receivedLayers := append([]string(nil), receipts...)
	observedMu.Unlock()
	if strings.Join(receivedLayers, ",") != "NODE_RECEIVED,CODEX_QUEUE_ACCEPTED,CONSUMPTION_UNCONFIRMED" {
		t.Fatalf("unexpected layered target receipts: %v", receivedLayers)
	}
}
