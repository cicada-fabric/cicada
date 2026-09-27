package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

func prepareLocalSealedBridgeSession(t *testing.T, nativeID string) string {
	t.Helper()
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_WORKSPACE", workspace)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_MACHINE_ID", "node-a")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CODEX_THREAD_ID", nativeID)
	t.Setenv("CODEX_SESSION_ID", "session-"+nativeID)
	writeCodexSessionRecord(t, codexHome, nativeID, workspace)
	return workspace
}

func localSealedBridgeTestRequest(workspace string) localSealedSendRequest {
	return localSealedSendRequest{
		Version: localSealedSendProtocolVersion, Operation: "sealed_send", Harness: "codex",
		NativeSessionID: "thread-send", NodeID: "node-a", Workspace: workspace,
		SessionToken: "cicada_session_local-only", EndpointID: "ep-source", PrincipalID: "pr-source",
		OwnerID: "owner-source", GroupID: "group-source", BindingID: "binding-source",
		BindingEpoch: 3, LinkID: "link-explicit", DataScope: "thread.message",
		MessageID: "op_0123456789abcdef0123456789abcdef", IdempotencyKey: "idem-retry-1", Body: "private body",
	}
}

func TestLocalSealedSendRejectsForgedCurrentEndpointIdentity(t *testing.T) {
	workspace := prepareLocalSealedBridgeSession(t, "thread-send")
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	var linkCalls atomic.Int32
	var sendCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			if got := request.Header.Get("Authorization"); got != "CicadaSession cicada_session_local-only" {
				t.Errorf("binding check Authorization=%q, want session credential", got)
			}
			_ = json.NewEncoder(response).Encode(fabricpkg.NetworkCard{
				EndpointID: "ep-source", GroupID: "group-source", PrincipalID: "pr-source",
				NodeID: "node-a", Harness: "codex", Workspace: workspace,
				BindingID: "binding-source", BindingEpoch: 3, NativeSessionID: "thread-send",
			})
		case "/v2/relay/nodes/node-a/links/link-explicit/authorization":
			linkCalls.Add(1)
			http.NotFound(response, request)
		case "/v2/relay/nodes/node-a/sealed/send":
			sendCalls.Add(1)
			http.Error(response, "unexpected send", http.StatusInternalServerError)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	stateDir := shortLocalJoinStateDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-a", nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	request := localSealedBridgeTestRequest(workspace)
	request.EndpointID = "ep-forged"
	_, err = requestMachineAgentSealedSend(machineAgentJoinSocketPath(stateDir, "node-a"), request)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("forged sender Endpoint was accepted: %v", err)
	}
	if linkCalls.Load() != 0 || sendCalls.Load() != 0 {
		t.Fatalf("forged identity reached Link/Send APIs: links=%d sends=%d", linkCalls.Load(), sendCalls.Load())
	}
	writeCodexSessionRecord(t, os.Getenv("CODEX_HOME"), "thread-other", workspace)
	request = localSealedBridgeTestRequest(workspace)
	request.NativeSessionID = "thread-other"
	_, err = requestMachineAgentSealedSend(machineAgentJoinSocketPath(stateDir, "node-a"), request)
	if err == nil || !strings.Contains(err.Error(), "trusted native binding") {
		t.Fatalf("another local Codex thread used this session binding: %v", err)
	}
	if linkCalls.Load() != 0 || sendCalls.Load() != 0 {
		t.Fatalf("wrong native thread reached Link/Send APIs: links=%d sends=%d", linkCalls.Load(), sendCalls.Load())
	}
}

func TestLocalSealedSendRequiresCurrentBilateralLinkAuthorization(t *testing.T) {
	workspace := prepareLocalSealedBridgeSession(t, "thread-send")
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	var linkCalls atomic.Int32
	var sendCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			if got := request.Header.Get("Authorization"); got != "CicadaSession cicada_session_local-only" {
				t.Errorf("binding check Authorization=%q, want session credential", got)
			}
			_ = json.NewEncoder(response).Encode(fabricpkg.NetworkCard{
				EndpointID: "ep-source", GroupID: "group-source", PrincipalID: "pr-source",
				NodeID: "node-a", Harness: "codex", Workspace: workspace,
				BindingID: "binding-source", BindingEpoch: 3, NativeSessionID: "thread-send",
			})
		case "/v2/relay/nodes/node-a/links/link-explicit/authorization":
			linkCalls.Add(1)
			if got := request.Header.Get("Authorization"); got != "CicadaNode "+nodeToken {
				t.Errorf("Link authorization request used %q, want Node credential", got)
			}
			http.NotFound(response, request)
		case "/v2/relay/nodes/node-a/sealed/send":
			sendCalls.Add(1)
			http.Error(response, "unexpected send", http.StatusInternalServerError)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	stateDir := shortLocalJoinStateDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-a", nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	_, err = requestMachineAgentSealedSend(machineAgentJoinSocketPath(stateDir, "node-a"), localSealedBridgeTestRequest(workspace))
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("SEND without current bilateral Link authorization did not fail closed: %v", err)
	}
	if linkCalls.Load() != 1 || sendCalls.Load() != 0 {
		t.Fatalf("unauthorized SEND called wrong endpoints: links=%d sends=%d", linkCalls.Load(), sendCalls.Load())
	}
}

func TestLocalSealedSendBridgeRejectsNodeBearerOnSessionBindingProbe(t *testing.T) {
	workspace := prepareLocalSealedBridgeSession(t, "thread-send")
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	var linkCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/fabric/whoami" {
			if got := request.Header.Get("Authorization"); got != "CicadaSession cicada_session_local-only" && got != "CicadaNode "+nodeToken {
				t.Errorf("unexpected binding credential %q", got)
			}
			if got := request.Header.Get("Authorization"); got == "CicadaNode "+nodeToken {
				t.Error("session binding probe used Node bearer instead of current session credential")
			}
			_ = json.NewEncoder(response).Encode(fabricpkg.NetworkCard{
				EndpointID: "ep-source", GroupID: "group-source", PrincipalID: "pr-source",
				NodeID: "node-a", Harness: "codex", Workspace: workspace,
				BindingID: "binding-source", BindingEpoch: 3, NativeSessionID: "thread-send",
			})
			return
		}
		if strings.Contains(request.URL.Path, "/links/") {
			linkCalls.Add(1)
		}
		http.NotFound(response, request)
	}))
	defer server.Close()

	stateDir := shortLocalJoinStateDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-a", nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	_, _ = requestMachineAgentSealedSend(machineAgentJoinSocketPath(stateDir, "node-a"), localSealedBridgeTestRequest(workspace))
	if linkCalls.Load() != 1 {
		t.Fatalf("request did not pass current-session binding verification: link calls=%d", linkCalls.Load())
	}
	if _, err := os.Stat(filepath.Join(machineNodeStateDir(stateDir, "node-a"), "node-crypto-state.sqlite")); err != nil {
		t.Fatalf("Node crypto state was not opened after valid current-session verification: %v", err)
	}
}

func TestLocalSealedSendPinsSealsAndRetriesExactCiphertext(t *testing.T) {
	workspace := prepareLocalSealedBridgeSession(t, "thread-send")
	stateDir := t.TempDir()
	const nodeID = "node-a"
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	sourceIdentity, err := nodekeys.LoadOrCreate(machineNodeStateDir(stateDir, nodeID), "ep-source")
	if err != nil {
		t.Fatal(err)
	}
	bundle, ownerKeys := localSealedSendTestBundle(t, sourceIdentity)
	cryptoState, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, nodeID))
	if err != nil {
		t.Fatal(err)
	}
	for ownerID, ownerKey := range ownerKeys {
		fingerprint, err := nodekeys.PeerKeyFingerprint(ownerKey.Public())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cryptoState.TrustOwnerApprovalKeyLocal(ownerID, ownerKey.Public().ID,
			ownerKey.Public(), fingerprint); err != nil {
			t.Fatal(err)
		}
	}
	if err := cryptoState.Close(); err != nil {
		t.Fatal(err)
	}

	var sent [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			if got := request.Header.Get("Authorization"); got != "CicadaSession cicada_session_local-only" {
				t.Errorf("whoami authorization=%q, want current Session credential", got)
			}
			if got := request.Header.Get("Cicada-Group-Scope"); got != "group-source" {
				t.Errorf("whoami group scope=%q", got)
			}
			_ = json.NewEncoder(response).Encode(fabricpkg.NetworkCard{
				EndpointID: "ep-source", PrincipalID: "pr-source",
				GroupID: "group-source", NodeID: nodeID, Harness: "codex", Workspace: workspace,
				BindingID: "binding-source", BindingEpoch: 3, NativeSessionID: "thread-send",
			})
		case "/v2/relay/nodes/node-a/links/link-explicit/authorization":
			if got := request.Header.Get("Authorization"); got != "CicadaNode "+nodeToken {
				t.Errorf("authorization lookup credential=%q, want private Node bearer", got)
			}
			_ = json.NewEncoder(response).Encode(bundle)
		case "/v2/relay/nodes/node-a/sealed/send":
			if got := request.Header.Get("Authorization"); got != "CicadaNode "+nodeToken {
				t.Errorf("sealed/send credential=%q, want private Node bearer", got)
			}
			data, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read sealed/send body: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			if bytes.Contains(data, []byte("private body")) {
				t.Error("Hub received plaintext in the sealed/send request")
			}
			var input fabricpkg.NodeSealedLinkSendInput
			if err := json.Unmarshal(data, &input); err != nil {
				t.Errorf("decode sealed/send request: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			if len(input.Ciphertext) == 0 || bytes.Contains(input.Ciphertext, []byte("private body")) {
				t.Error("Hub did not receive opaque ciphertext")
			}
			sent = append(sent, append([]byte(nil), input.Ciphertext...))
			_ = json.NewEncoder(response).Encode(map[string]string{
				"message_id": input.MessageID, "payload_mode": "SEALED_V1", "outbox_state": "RELAY_ACCEPTED",
			})
		default:
			t.Errorf("unexpected local sender Hub request: %s %s", request.Method, request.URL.Path)
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, nodeID, nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	request := localSealedBridgeTestRequest(workspace)
	first, err := requestMachineAgentSealedSend(machineAgentJoinSocketPath(stateDir, nodeID), request)
	if err != nil {
		t.Fatalf("first sealed send: %v", err)
	}
	second, err := requestMachineAgentSealedSend(machineAgentJoinSocketPath(stateDir, nodeID), request)
	if err != nil {
		t.Fatalf("retry sealed send: %v", err)
	}
	if len(sent) != 2 || !bytes.Equal(sent[0], sent[1]) {
		t.Fatalf("retry did not reuse the exact persisted ciphertext: sends=%d", len(sent))
	}
	if first.Sequence == 0 || first.Sequence != second.Sequence || first.CiphertextReused || !second.CiphertextReused {
		t.Fatalf("unexpected durable retry metadata: first=%+v second=%+v", first, second)
	}
}

func localSealedSendTestBundle(t *testing.T, sourceIdentity *e2ee.Identity) (nodekeys.PeerKeyAuthorizationBundle, map[string]*e2ee.Identity) {
	t.Helper()
	const linkID = "link-explicit"
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(time.Hour)
	targetIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sourceOwnerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	targetOwnerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	contract := localLinkContract{
		LinkID:           linkID,
		SourceEndpointID: "ep-source", SourcePrincipalID: "pr-source", SourceGroupID: "group-source",
		SourceOwnerID: "owner-source", SourceNodeID: "node-a",
		TargetEndpointID: "ep-target", TargetPrincipalID: "pr-target", TargetGroupID: "group-target",
		TargetOwnerID: "owner-target", TargetNodeID: "node-b",
		Direction: "forward", Actions: []string{"send"}, DataScopes: []string{"thread.message"},
		TransportHubID: "hub-test", ExpiresAt: expires.Format(time.RFC3339),
		ScopeSnapshot: store.CommunicationLinkScopeSnapshot{
			SourceMembershipRevision: 1, SourceJoinRevision: 1, SourceGroupVersion: 1,
			TargetMembershipRevision: 1, TargetJoinRevision: 1, TargetGroupVersion: 1,
		},
	}
	canonicalContract, err := json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	contractHash := sha256.Sum256(append([]byte("cicada/communication-link/proposal/v1\x00"), canonicalContract...))
	contractDigest := hex.EncodeToString(contractHash[:])
	sourceSide := localSealedSendTestManifestSide(t, "ep-source", "group-source", "pr-source", "owner-source", "node-a", "binding-source", 3, sourceIdentity)
	targetSide := localSealedSendTestManifestSide(t, "ep-target", "group-target", "pr-target", "owner-target", "node-b", "binding-target", 4, targetIdentity)
	manifest := nodekeys.PeerKeyAuthorizationManifest{
		Version: 2, LinkID: linkID, LinkVersion: 1, ContractDigest: contractDigest,
		ContractCanonical: canonicalContract, Source: sourceSide, Target: targetSide,
	}
	type manifestClaims struct {
		Version           int                          `json:"version"`
		LinkID            string                       `json:"link_id"`
		LinkVersion       int64                        `json:"link_version"`
		ContractDigest    string                       `json:"contract_digest"`
		ContractCanonical []byte                       `json:"contract_canonical"`
		Source            nodekeys.PeerKeyManifestSide `json:"source"`
		Target            nodekeys.PeerKeyManifestSide `json:"target"`
	}
	claims, err := json.Marshal(manifestClaims{manifest.Version, manifest.LinkID, manifest.LinkVersion,
		manifest.ContractDigest, manifest.ContractCanonical, manifest.Source, manifest.Target})
	if err != nil {
		t.Fatal(err)
	}
	manifestHash := sha256.Sum256(append([]byte("cicada/communication-link/key-manifest/v2\x00"), claims...))
	manifest.Digest = hex.EncodeToString(manifestHash[:])
	sourceGrant, err := sourceOwnerKey.SignOwnerLinkKeyGrant("owner-source", linkID,
		contractDigest, manifest.Digest, uint64(manifest.LinkVersion), e2ee.OwnerLinkGrantSideSource,
		now.Add(-time.Minute), expires)
	if err != nil {
		t.Fatal(err)
	}
	targetGrant, err := targetOwnerKey.SignOwnerLinkKeyGrant("owner-target", linkID,
		contractDigest, manifest.Digest, uint64(manifest.LinkVersion), e2ee.OwnerLinkGrantSideTarget,
		now.Add(-time.Minute), expires)
	if err != nil {
		t.Fatal(err)
	}
	return nodekeys.PeerKeyAuthorizationBundle{
		Manifest: manifest, LinkState: "PROPOSED",
		SourceGrant: nodekeys.PeerOwnerKeyGrantEvidence{Side: string(e2ee.OwnerLinkGrantSideSource),
			OwnerID: "owner-source", OwnerKeyID: sourceOwnerKey.Public().ID,
			OwnerPublicIdentity: sourceOwnerKey.Public(), OwnerKeyState: "ACTIVE", OwnerKeyVersion: 1,
			CurrentStatus: "ACCEPTED", SignedProof: sourceGrant},
		TargetGrant: nodekeys.PeerOwnerKeyGrantEvidence{Side: string(e2ee.OwnerLinkGrantSideTarget),
			OwnerID: "owner-target", OwnerKeyID: targetOwnerKey.Public().ID,
			OwnerPublicIdentity: targetOwnerKey.Public(), OwnerKeyState: "ACTIVE", OwnerKeyVersion: 1,
			CurrentStatus: "ACCEPTED", SignedProof: targetGrant},
	}, map[string]*e2ee.Identity{"owner-source": sourceOwnerKey, "owner-target": targetOwnerKey}
}

func localSealedSendTestManifestSide(t *testing.T, endpointID, groupID, principalID, ownerID, nodeID,
	bindingID string, epoch uint64, identity *e2ee.Identity) nodekeys.PeerKeyManifestSide {
	t.Helper()
	attestation, err := identity.SignEndpointKeyAttestation(endpointID, principalID, nodeID, bindingID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(identity.Public())
	if err != nil {
		t.Fatal(err)
	}
	proofHash := sha256.Sum256(attestation)
	return nodekeys.PeerKeyManifestSide{
		EndpointID: endpointID, GroupID: groupID, PrincipalID: principalID, OwnerID: ownerID,
		NodeID: nodeID, BindingID: bindingID, BindingEpoch: epoch, CandidateVersion: 1,
		KeyID: identity.Public().ID, KeyFingerprint: fingerprint,
		ProofDigest: hex.EncodeToString(proofHash[:]), PublicIdentity: identity.Public(), Attestation: attestation,
	}
}

func TestMCPSealedSendOfflineRetryKeepsTheSameImmutableRoute(t *testing.T) {
	workspace := prepareLocalSealedBridgeSession(t, "thread-send")
	stateDir := t.TempDir()
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	token := "cicada_session_current"
	card := fabricpkg.NetworkCard{
		EndpointID: "ep-source", GroupID: "group-source", PrincipalID: "pr-source",
		NodeID: "node-a", Harness: "codex", Workspace: workspace,
		BindingID: "binding-source", BindingEpoch: 3, NativeSessionID: "thread-send",
	}
	var hubCalls atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/fabric/whoami" {
			http.NotFound(response, request)
			return
		}
		hubCalls.Add(1)
		if request.Header.Get("Authorization") != "CicadaSession "+token ||
			request.Header.Get("Cicada-Group-Scope") != "group-source" {
			t.Errorf("fresh current-session probe used unexpected headers: %#v", request.Header)
		}
		_ = json.NewEncoder(response).Encode(card)
	}))
	defer hub.Close()

	context := mcpTestContext("codex", "thread-send", "node-a", workspace)
	origin, err := normalizeMCPAPIOrigin(hub.URL)
	if err != nil {
		t.Fatal(err)
	}
	scope, trusted, err := mcpSessionScope(origin, context)
	if err != nil {
		t.Fatal(err)
	}
	public := mcpPublicJoinResult{
		Endpoint:    store.Endpoint{ID: card.EndpointID, GroupID: card.GroupID, Owner: "owner-source"},
		NetworkCard: card, BindingID: card.BindingID, BindingEpoch: card.BindingEpoch,
	}
	mcp := newMCPServer(hub.URL, card.EndpointID, filepath.Join(t.TempDir(), "mcp", "sessions.json"))
	mcp.setSession(token, card.EndpointID, card.GroupID, trusted, scope, public)
	defer func() {
		if mcp.outbox != nil {
			_ = mcp.outbox.close()
		}
		close(mcp.stop)
	}()

	type observed struct {
		request localSealedSendRequest
	}
	var observationsMu sync.Mutex
	var observations []observed
	var bridgeCalls atomic.Int32
	originalDial := netDialLocalBridge
	netDialLocalBridge = func(string) (localBridgeConn, error) {
		client, agent := net.Pipe()
		call := bridgeCalls.Add(1)
		go func() {
			defer agent.Close()
			decoder := json.NewDecoder(agent)
			decoder.DisallowUnknownFields()
			var request localSealedSendRequest
			if err := decoder.Decode(&request); err != nil {
				t.Errorf("decode local sealed-send call %d: %v", call, err)
				return
			}
			observationsMu.Lock()
			observations = append(observations, observed{request: request})
			observationsMu.Unlock()
			encoder := json.NewEncoder(agent)
			if call == 1 {
				_ = encoder.Encode(localJoinResponse{Version: localJoinProtocolVersion,
					Retryable: true, Error: "Hub unavailable after durable local seal"})
				return
			}
			_ = encoder.Encode(localJoinResponse{Version: localJoinProtocolVersion,
				SealedSend: &localSealedSendResult{MessageID: request.MessageID, LinkID: request.LinkID,
					TargetEndpointID: "ep-target", TargetGroupID: "group-target", DataScope: request.DataScope,
					Sequence: 4, CiphertextReused: true, OutboxState: "RELAY_ACCEPTED"}})
		}()
		return client, nil
	}
	t.Cleanup(func() { netDialLocalBridge = originalDial })

	args := map[string]any{"link_id": "link-explicit", "data_scope": "thread.message",
		"body": "same private body", "idempotency_key": "retry-same-link-send"}
	first, err := mcp.callTool("cicada_send", args)
	if err != nil {
		t.Fatal(err)
	}
	firstResult := first.(map[string]any)
	if firstResult["status"] != mcpOutboxStatusUnknown {
		t.Fatalf("offline sealed send status=%#v, want UNKNOWN", firstResult["status"])
	}
	operationID := mcpOutboxOperationID(t, first)
	if strings.Contains(fmt.Sprint(first), token) {
		t.Fatal("sealed-send tool result exposed its session credential")
	}
	retried, err := mcp.callTool("cicada_operation_retry", map[string]any{"operation_id": operationID})
	if err != nil {
		t.Fatal(err)
	}
	if retried.(map[string]any)["status"] != mcpOutboxStatusSent {
		t.Fatalf("sealed-send retry result=%#v, want SENT", retried)
	}
	observationsMu.Lock()
	defer observationsMu.Unlock()
	if len(observations) != 2 || observations[0].request.MessageID != operationID ||
		observations[1].request.MessageID != operationID ||
		observations[0].request.IdempotencyKey != "retry-same-link-send" ||
		observations[1].request.IdempotencyKey != observations[0].request.IdempotencyKey ||
		observations[1].request.LinkID != observations[0].request.LinkID ||
		observations[1].request.DataScope != observations[0].request.DataScope ||
		observations[1].request.Body != observations[0].request.Body ||
		observations[1].request.EndpointID != card.EndpointID ||
		observations[1].request.PrincipalID != card.PrincipalID ||
		observations[1].request.OwnerID != "owner-source" ||
		observations[1].request.BindingID != card.BindingID ||
		observations[1].request.BindingEpoch != card.BindingEpoch {
		t.Fatalf("retry changed its immutable route or trusted local identity: %#v", observations)
	}
	if bridgeCalls.Load() != 2 || hubCalls.Load() != 2 {
		t.Fatalf("bridge calls=%d Hub session checks=%d, want 2 each", bridgeCalls.Load(), hubCalls.Load())
	}
}
