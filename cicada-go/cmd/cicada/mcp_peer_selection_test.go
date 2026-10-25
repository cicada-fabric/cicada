package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

func peerTestStdio(t *testing.T, m *mcpServer) (*json.Encoder, *json.Decoder) {
	t.Helper()
	client, server := net.Pipe()
	client.SetDeadline(time.Now().Add(20 * time.Second))
	m.stdio = newMCPStdioTransport(server, server)
	done := make(chan error, 1)
	go func() { done <- m.stdio.serve(m.handle) }()
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("stdio did not stop")
		}
	})
	e, d := json.NewEncoder(client), json.NewDecoder(client)
	if err := e.Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"capabilities": map[string]any{"elicitation": map[string]any{"form": map[string]any{}}}}}); err != nil {
		t.Fatal(err)
	}
	var ready map[string]any
	if err := d.Decode(&ready); err != nil {
		t.Fatal(err)
	}
	return e, d
}

func peerTestForm(t *testing.T, e *json.Encoder, d *json.Decoder, args map[string]any, match string, beforeAccept func()) map[string]any {
	t.Helper()
	if err := e.Encode(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "cicada_select_peer", "arguments": args}}); err != nil {
		t.Fatal(err)
	}
	var request struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		ID     any    `json:"id"`
		Method string `json:"method"`
		Params struct {
			Message string `json:"message"`
			Schema  struct {
				Properties struct {
					Peer struct {
						OneOf []struct{ Const, Title string } `json:"oneOf"`
					} `json:"peer"`
				} `json:"properties"`
			} `json:"requestedSchema"`
		} `json:"params"`
	}
	if err := d.Decode(&request); err != nil {
		t.Fatal(err)
	}
	if request.Method != "elicitation/create" {
		t.Fatal("expected real form request", request.Method, request.Result.Content)
	}
	var choice string
	for _, option := range request.Params.Schema.Properties.Peer.OneOf {
		if strings.Contains(option.Title, match) {
			if choice != "" {
				t.Fatal("ambiguous test selection")
			}
			choice = option.Const
		}
	}
	if choice == "" {
		t.Fatal("exact expected peer not offered", match, request.Params.Schema.Properties.Peer.OneOf)
	}
	if beforeAccept != nil {
		beforeAccept()
	}
	if err := e.Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{"action": "accept", "content": map[string]any{"peer": choice}}}); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result map[string]any `json:"result"`
	}
	if err := d.Decode(&response); err != nil {
		t.Fatal(err)
	}
	return response.Result
}

func peerMockGroup(t *testing.T) (*mcpServer, *mcpOutboxHTTPFixture, fabric.NetworkCard) {
	t.Helper()
	f := newMCPOutboxHTTPFixture(t)
	f.sourceCapabilities = map[string]any{"local_peer_delivery": "sealed_v1"}
	card := fabric.NetworkCard{EndpointID: "ep_synthetic_peer_b", PrincipalID: "principal-b", GroupID: "group-a", Name: "Same visible name", NodeID: "node-b", Workspace: "/synthetic/peer-folder", BindingID: "synthetic-peer-binding", BindingEpoch: 7, Capabilities: map[string]any{"local_peer_delivery": "sealed_v1"}}
	f.directoryTargets = map[string]fabric.NetworkCard{card.EndpointID: card}
	original := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/fabric/list" {
			if r.URL.Query().Get("node_id") != "" {
				t.Error("selector restricted directory to caller Node")
			}
			json.NewEncoder(w).Encode(map[string]any{"endpoints": []fabric.NetworkCard{card}})
			return
		}
		original.ServeHTTP(w, r)
	})
	m := mcpOutboxTestServer(t, f, filepath.Join(t.TempDir(), "mcp", "sessions.json"), "synthetic-peer-thread-a", "ep_synthetic_a", "group-a")
	return m, f, card
}

func TestMCPPeerSelectionClosedArgumentsAndOldHostHasNoEffects(t *testing.T) {
	m, f, _ := peerMockGroup(t)
	for _, args := range []map[string]any{{"scope": "owner"}, {"scope": "network"}, {"scope": "group", "network_id": "net_other"}, {"scope": "group", "owner_id": "fake"}, {"scope": "group", "query": true}} {
		if err := validateMCPArguments("cicada_select_peer", args); err == nil {
			t.Fatal("invalid selector accepted")
		}
	}
	for _, key := range []string{"target", "link_id", "network_id", "data_scope"} {
		if err := validateMCPArguments("cicada_send", map[string]any{"peer_selection_id": "peerselection_synthetic", "body": "x", key: ""}); err == nil {
			t.Fatal("mixed selector accepted", key)
		}
	}
	before := f.whoamiCalls.Load()
	if _, err := m.callTool("cicada_select_peer", map[string]any{"scope": "group"}); err == nil {
		t.Fatal("unsupported Host selected")
	}
	if f.whoamiCalls.Load() != before {
		t.Fatal("old Host read directory/authority")
	}
}

func TestMCPPeerSelectionCrossNodeFormAndFreshBindingRefusal(t *testing.T) {
	m, f, card := peerMockGroup(t)
	e, d := peerTestStdio(t, m)
	result := peerTestForm(t, e, d, map[string]any{"scope": "group", "query": "peer-folder"}, "peer-folder", nil)
	selected, ok := result["structuredContent"].(map[string]any)
	if !ok || selected["endpoint_id"] != card.EndpointID || selected["binding_id"] != card.BindingID || selected["binding_epoch"] != float64(7) {
		t.Fatal("form did not retain exact peer")
	}
	id := selected["peer_selection_id"].(string)
	f.mu.Lock()
	changed := f.directoryTargets[card.EndpointID]
	changed.BindingEpoch++
	f.directoryTargets[card.EndpointID] = changed
	f.mu.Unlock()
	if _, err := m.callTool("cicada_send", map[string]any{"peer_selection_id": id, "body": "no stale target"}); !errors.Is(err, errMCPPeerStale) {
		t.Fatal("binding replacement accepted", err)
	}
	// Expiry is checked before another directory read or outbox creation.
	m.peerMu.Lock()
	s := m.peerSelections[id]
	s.Expires = time.Now().Add(-time.Second)
	m.peerSelections[id] = s
	m.peerMu.Unlock()
	if _, err := m.callTool("cicada_send", map[string]any{"peer_selection_id": id, "body": "no expired target"}); !errors.Is(err, errMCPPeerStale) {
		t.Fatal("expired selection accepted", err)
	}
}

func TestMCPPeerSelectionChangedDuringFormCannotAccept(t *testing.T) {
	m, f, card := peerMockGroup(t)
	e, d := peerTestStdio(t, m)
	result := peerTestForm(t, e, d, map[string]any{"scope": "group"}, "peer-folder", func() {
		f.mu.Lock()
		changed := f.directoryTargets[card.EndpointID]
		changed.BindingID = "replacement-binding"
		f.directoryTargets[card.EndpointID] = changed
		f.mu.Unlock()
	})
	if result["isError"] != true || len(m.peerSelections) != 0 {
		t.Fatal("accepted stale form selection")
	}
}

func TestMCPPeerSelectionCancelDuringFinalHubCheckCreatesNoReference(t *testing.T) {
	m, f, _ := peerMockGroup(t)
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	original := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/fabric/resolve" {
			close(entered)
			<-release
		}
		original.ServeHTTP(w, r)
	})
	e, d := peerTestStdio(t, m)
	if err := e.Encode(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "cicada_select_peer", "arguments": map[string]any{"scope": "group"}}}); err != nil {
		t.Fatal(err)
	}
	var form map[string]any
	if err := d.Decode(&form); err != nil {
		t.Fatal(err)
	}
	choices := form["params"].(map[string]any)["requestedSchema"].(map[string]any)["properties"].(map[string]any)["peer"].(map[string]any)["oneOf"].([]any)
	choice := choices[0].(map[string]any)["const"]
	if err := e.Encode(map[string]any{"jsonrpc": "2.0", "id": form["id"], "result": map[string]any{"action": "accept", "content": map[string]any{"peer": choice}}}); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := e.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 2}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	cancelled := false
	for time.Now().Before(deadline) {
		m.stdio.mu.Lock()
		cancelled = m.stdio.active != nil && m.stdio.active.ctx.Err() != nil
		m.stdio.mu.Unlock()
		if cancelled {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !cancelled {
		t.Fatal("cancellation did not reach original call")
	}
	close(release)
	// A cancelled request has no response. The queued ping proves the handler
	// finished its final check and the healthy connection remains usable.
	if err := e.Encode(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "ping"}); err != nil {
		t.Fatal(err)
	}
	var ping map[string]any
	if err := d.Decode(&ping); err != nil || ping["id"] != float64(3) {
		t.Fatal("cancelled request emitted a result or blocked the worker", err)
	}
	m.peerMu.Lock()
	count := len(m.peerSelections)
	m.peerMu.Unlock()
	if count != 0 {
		t.Fatal("cancelled call committed a reference")
	}
}

func TestMCPPeerSelectionExactRecoverySurvivesMemoryLossWithoutResend(t *testing.T) {
	m, _, _ := peerMockGroup(t)
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"peer_selection_id": "peerselection_synthetic_retained", "body": "synthetic exact body", "idempotency_key": "synthetic-original-key"}
	input := mcpOutboxInput{PeerSelectionID: args["peer_selection_id"].(string), PeerIntentDigest: peerDigest([]any{"cicada_send", args}), Target: "ep_synthetic_retained", Body: "synthetic exact body"}
	op, _, err := m.outbox.prepare(scope, "send", "synthetic-original-key", input)
	if err != nil {
		t.Fatal(err)
	}
	m.outbox.markError(scope, op.OperationID, mcpOutboxStatusUnknown, errors.New("SYNTHETIC lost response"))
	m.peerSelections = nil
	result, err := m.callTool("cicada_send", args)
	if err != nil || mcpOutboxOperationID(t, result) != op.OperationID {
		t.Fatal("exact operation was replaced", err)
	}
	args["body"] = "changed"
	if _, err := m.callTool("cicada_send", args); !errors.Is(err, errMCPOutboxConflict) {
		t.Fatal("changed intent retried original operation", err)
	}
}

func TestMCPPeerNetworkRecoveryBoundPreservesPendingEvidence(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for i := 0; i < 64; i++ {
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("net_synthetic_%02d.renew-pending.json", i)), []byte("SYNTHETIC retained uncertainty"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if lock, err := boundedSelectedNetworkLock(root, filepath.Join(directory, "net_new.session.json"), "net_new"); err == nil {
		lock.Unlock()
		t.Fatal("unbounded new Network recovery admitted")
	}
	if _, err := os.Stat(filepath.Join(directory, "net_new.session.json.lock")); !os.IsNotExist(err) {
		t.Fatal("overflow created a new per-Network file")
	}
	lock, err := boundedSelectedNetworkLock(root, filepath.Join(directory, "net_synthetic_00.session.json"), "net_synthetic_00")
	if err != nil {
		t.Fatal("existing uncertain Network was made inaccessible", err)
	}
	lock.Unlock()
	for i := 0; i < 64; i++ {
		raw, err := os.ReadFile(filepath.Join(directory, fmt.Sprintf("net_synthetic_%02d.renew-pending.json", i)))
		if err != nil || string(raw) != "SYNTHETIC retained uncertainty" {
			t.Fatal("pending evidence removed", i)
		}
	}
}

func TestMCPPeerSelectionMinimalForeignUsesPrivateNodeExactRouteOnly(t *testing.T) {
	m, f, card := peerMockGroup(t)
	minimal := card
	minimal.Name = card.EndpointID
	minimal.NodeID = ""
	minimal.Workspace = ""
	minimal.BindingID = ""
	minimal.BindingEpoch = 0
	minimal.Capabilities = nil
	f.mu.Lock()
	f.directoryTargets[card.EndpointID] = minimal
	f.mu.Unlock()
	original := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/fabric/list" {
			json.NewEncoder(w).Encode(map[string]any{"endpoints": []fabric.NetworkCard{minimal}})
			return
		}
		original.ServeHTTP(w, r)
	})
	state := t.TempDir()
	t.Setenv("CICADA_NODE_STATE_DIR", state)
	var sent int
	codexConsumerNode(t, state, "node-a", func(connection net.Conn, raw json.RawMessage) {
		var request crossNodeGroupRequest
		if decodeLocalBridgeRequest(raw, &request) != nil || request.TargetEndpointID != card.EndpointID || request.ExpectedTargetBindingID != "" {
			t.Error("minimal selection was guessed or filled with private metadata")
			return
		}
		sent++
		json.NewEncoder(connection).Encode(localJoinResponse{Version: 1, CrossNodeGroup: &crossNodeGroupResult{MessageID: "SYNTHETIC-selected-message", TargetEndpointID: card.EndpointID, State: "RELAY_PERSISTED", Delivery: "RELAY", PayloadMode: "SEALED_V1"}})
	})
	e, d := peerTestStdio(t, m)
	result := peerTestForm(t, e, d, map[string]any{"scope": "group"}, "Contact", nil)
	id := result["structuredContent"].(map[string]any)["peer_selection_id"].(string)
	if _, err := m.callTool("cicada_send", map[string]any{"peer_selection_id": id, "body": "SYNTHETIC selected minimal contact"}); err != nil {
		t.Fatal(err)
	}
	if sent != 1 {
		t.Fatal("exact selected route did not reach private Node boundary")
	}
	if _, err := m.callTool("cicada_send", map[string]any{"target": card.EndpointID, "peer_intent_digest": "forged", "body": "SYNTHETIC forged internal"}); err == nil {
		t.Fatal("model injected internal selection")
	}
	if _, err := m.callTool("cicada_send", map[string]any{"peer_selection_id": "peerselection_forged", "body": "SYNTHETIC forged handle"}); err == nil {
		t.Fatal("unoffered reference used")
	}
	f.mu.Lock()
	f.currentSession.capabilities = nil
	f.mu.Unlock()
	denied, err := m.callTool("cicada_send", map[string]any{"peer_selection_id": id, "body": "SYNTHETIC no source permission"})
	if err == nil && denied.(map[string]any)["status"] != mcpOutboxStatusFailed {
		t.Fatal("selection bypassed source capability Guard")
	}
	if sent != 1 {
		t.Fatal("ungranted request reached Node boundary")
	}
}

// Public Store/Service calls and real Owner signatures create the fixture's
// independent Network registrations. There is no SQL authority injection.
type peerNetworkFixture struct {
	f       *nativePairTCPConsumerFixture
	network string
	joined  [2]*fabric.NetworkJoinResult
	tokens  [2]string
	nodes   [2]string
	service *fabric.Service
}

func newPeerNetworkFixture(t *testing.T) *peerNetworkFixture {
	t.Helper()
	f := newNativePeerTCPConsumerFixture(t, false)
	p, err := f.db.GetPrincipal(f.setup.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	p.TrustDomainID = "SYNTHETIC-peer-network-domain"
	if _, err := f.db.UpsertPrincipal(*p); err != nil {
		t.Fatal(err)
	}
	svc, err := fabric.NewService(f.db, p.ID, p.TrustDomainID)
	if err != nil {
		t.Fatal(err)
	}
	boundToken, _, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	nodeB := "synthetic-peer-network-node-b"
	code := localNodeDigest([]byte("SYNTHETIC-peer-network-device"))
	if _, err := f.db.CreatePendingNodeDeviceBinding(nodeB, nodeB, fabric.HashSessionCredential(boundToken), code, time.Now().UTC().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ConfirmPendingNodeDeviceBinding(f.setup.OwnerID, f.scope.Actor.DeviceID, code); err != nil {
		t.Fatal(err)
	}
	network, err := f.db.CreateNetwork(store.Network{ID: "net_synthetic_peer_picker", HubID: f.hub.HubID, OwnerID: f.setup.OwnerID, Name: "Synthetic independent peer directory"})
	if err != nil {
		t.Fatal(err)
	}
	n := &peerNetworkFixture{f: f, network: network.ID, tokens: [2]string{f.token, boundToken}, nodes: [2]string{f.nodeID, nodeB}, service: svc}
	grants := []string{"directory.discover", "directory.publish", "direct.send", "direct.receive"}
	for i := 0; i < 2; i++ {
		invitation := strings.Repeat(string(rune('a'+i)), 40)
		if err := f.db.IssueNetworkInvitation(network.ID, p.ID, p.ID, invitation, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
			t.Fatal(err)
		}
		proof, err := f.owner.SignOwnerNetworkJoinGrant(p.ID, f.hub.HubID, network.ID, n.nodes[i], f.native[i], store.NetworkInvitationDigest(invitation), f.owner.Public().ID, grants, true, time.Now().UTC().Add(-time.Second), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		n.joined[i], err = svc.JoinNetworkForNodeCredential(n.tokens[i], fabric.NetworkJoinInput{NetworkID: network.ID, InvitationToken: invitation, OwnerJoinProof: string(proof), Harness: "codex", NativeSessionID: f.native[i], EndpointName: []string{"Synthetic network A", "Synthetic network B"}[i]})
		if err != nil {
			t.Fatal("real signed Network Join", i, err)
		}
	}
	if _, _, err := f.bridge.completeNetworkNativeJoin(n.joined[0], "codex", f.native[0]); err != nil {
		t.Fatal("original Node did not record real independent Network enrollment", err)
	}
	return n
}

func peerFixtureNetworkStatePath(t *testing.T, n *peerNetworkFixture, m *mcpServer) string {
	t.Helper()
	native := harness.SessionContext{Harness: "codex", NativeSessionID: n.f.native[0], MachineID: n.f.nodeID, Workspace: n.f.workspace}
	scope, _, err := mcpSessionScope(m.baseURL, native)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(filepath.Dir(m.localNode.Pin.MCPSessionStateFile), "network-session", "scopes", scope, n.network+".session.json")
}

func TestMCPPeerNetworkOnlyMissingTokenRenewsOriginalEnrollment(t *testing.T) {
	n := newPeerNetworkFixture(t)
	m := n.formalMCP(t)
	if m.isJoined() {
		t.Fatal("Network-only recovery fixture borrowed a Group")
	}
	path := peerFixtureNetworkStatePath(t, n, m)
	if err := os.Rename(path, path+".original-retained"); err != nil {
		t.Fatal(err)
	}
	e, d := peerTestStdio(t, m)
	args := peerHookArguments(t, n.f, m, 0, "cicada_select_peer", map[string]any{"scope": "network", "network_id": n.network})
	result := peerTestForm(t, e, d, args, n.joined[1].Endpoint.Name, nil)
	if result["isError"] == true {
		t.Fatal("original Network-only registration could not recover", result)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recovered networkCLIState
	if decodeLocalNodeJSON(raw, &recovered) != nil || recovered.EndpointID != n.joined[0].Endpoint.ID || recovered.SessionToken == n.joined[0].SessionToken {
		t.Fatal("recovery did not retain original Endpoint with renewed access")
	}
	actor, err := n.service.AuthenticateForNetwork(recovered.SessionToken, n.network)
	if err != nil || actor.EndpointID != n.joined[0].Endpoint.ID {
		t.Fatal("recovered token has wrong authority", err)
	}
	if _, err := os.Stat(strings.TrimSuffix(path, ".session.json") + ".renew-pending.json"); !os.IsNotExist(err) {
		t.Fatal("known successful renewal left uncertainty")
	}
	if m.isJoined() {
		t.Fatal("Network recovery implicitly joined a Group")
	}
}

func TestMCPPeerNetworkRenewalLossAndKnownBindingFailureRetainOriginal(t *testing.T) {
	for _, known := range []bool{false, true} {
		name := "unknown-response"
		if known {
			name = "known-token-binding-pending"
		}
		t.Run(name, func(t *testing.T) {
			n := newPeerNetworkFixture(t)
			m := n.formalMCP(t)
			path := peerFixtureNetworkStatePath(t, n, m)
			if err := os.Rename(path, path+".retained"); err != nil {
				t.Fatal(err)
			}
			var renewals atomic.Int32
			n.f.mu.Lock()
			original := n.f.handler
			n.f.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/fabric/node/networks/renew" {
					renewals.Add(1)
					if !known {
						buffer := httptest.NewRecorder()
						original.ServeHTTP(buffer, r)
						if buffer.Code < 200 || buffer.Code >= 300 {
							t.Error("original renewal did not commit", buffer.Code)
						}
						http.Error(w, "SYNTHETIC committed response lost", http.StatusServiceUnavailable)
						return
					}
				}
				if known && strings.HasSuffix(r.URL.Path, "/direct/native-binding") {
					http.Error(w, "SYNTHETIC post-renew binding failure", http.StatusServiceUnavailable)
					return
				}
				original.ServeHTTP(w, r)
			})
			n.f.mu.Unlock()
			e, d := peerTestStdio(t, m)
			for i := 0; i < 2; i++ {
				args := peerHookArguments(t, n.f, m, 0, "cicada_select_peer", map[string]any{"scope": "network", "network_id": n.network})
				if err := e.Encode(map[string]any{"jsonrpc": "2.0", "id": 20 + i, "method": "tools/call", "params": map[string]any{"name": "cicada_select_peer", "arguments": args}}); err != nil {
					t.Fatal(err)
				}
				var reply struct {
					Method string `json:"method"`
					Result struct {
						IsError bool `json:"isError"`
						Content []struct {
							Text string `json:"text"`
						} `json:"content"`
					} `json:"result"`
				}
				if err := d.Decode(&reply); err != nil || reply.Method != "" || !reply.Result.IsError {
					t.Fatal("uncertain renewal displayed a form or succeeded", err)
				}
				if renewals.Load() != 1 {
					t.Fatal("retry silently rotated another access epoch", renewals.Load())
				}
			}
			if len(m.peerSelections) != 0 {
				t.Fatal("failed renewal created a send selection")
			}
			marker := strings.TrimSuffix(path, ".session.json") + ".renew-pending.json"
			if _, err := os.Stat(marker); err != nil {
				t.Fatal("uncertainty evidence missing", err)
			}
			raw, err := os.ReadFile(path)
			if known {
				var retained networkCLIState
				if err != nil || decodeLocalNodeJSON(raw, &retained) != nil || retained.EndpointID != n.joined[0].Endpoint.ID || retained.SessionToken == "" || retained.SessionToken == n.joined[0].SessionToken {
					t.Fatal("known original renewed credential was discarded", err)
				}
				actor, err := n.service.AuthenticateForNetwork(retained.SessionToken, n.network)
				if err != nil || actor.EndpointID != retained.EndpointID {
					t.Fatal("known credential does not authenticate its original Endpoint", err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("unknown response invented a replacement credential")
			}
		})
	}
}

func (n *peerNetworkFixture) authorizeKeys(t *testing.T) [2]*e2ee.Identity {
	t.Helper()
	f := n.f
	var keys [2]*e2ee.Identity
	for i, joined := range n.joined {
		actor, err := n.service.AuthenticateForNetwork(joined.SessionToken, n.network)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := n.service.NetworkDirectNativeBinding(actor)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			keys[i], err = nodekeys.LoadOrCreate(machineNodeStateDir(f.nodeRoot, f.nodeID), joined.Endpoint.ID)
		} else {
			keys[i], err = e2ee.NewIdentity()
		}
		if err != nil {
			t.Fatal(err)
		}
		proof, err := keys[i].SignNetworkDirectKeyAttestation(f.hub.HubID, n.network, joined.Endpoint.ID, joined.Endpoint.PrincipalID, n.nodes[i], binding.ID, binding.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.service.PublishNetworkDirectKeyCandidate(actor, proof); err != nil {
			t.Fatal(err)
		}
		manifest, err := f.db.PreviewNetworkDirectKeyGrant(f.setup.OwnerID, n.network, joined.Endpoint.ID, f.owner.Public().ID)
		if err != nil {
			t.Fatal(err)
		}
		grant, err := f.owner.SignOwnerNetworkDirectKeyGrant(f.hub.HubID, n.network, joined.Endpoint.ID, f.setup.OwnerID, manifest.Digest, time.Now().UTC().Add(-time.Second), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.AcceptNetworkDirectKeyGrant(f.setup.OwnerID, n.network, joined.Endpoint.ID, grant); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func peerHookArguments(t *testing.T, f *nativePairTCPConsumerFixture, m *mcpServer, index int, tool string, args map[string]any) map[string]any {
	t.Helper()
	issue := localDomainConsumerIssue(t, f, index)
	// Independent Network registrations retain the original strict native
	// record profile. The shared helper models desktop domain permissions;
	// restore private fixture modes rather than relaxing the Node verifier.
	if err := os.Chmod(issue.TranscriptPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(issue.TranscriptPath), 0700); err != nil {
		t.Fatal(err)
	}
	input := map[string]any{}
	for k, v := range args {
		input[k] = v
	}
	input[codexMCPContextArgument] = map[string]any{"connection_nonce": m.codexContext.nonce}
	event := codexHookInput{Event: "PreToolUse", SessionID: f.native[index], CWD: f.workspace, TranscriptPath: issue.TranscriptPath, ToolName: "mcp__cicada__" + tool, ToolInput: input, TurnID: "synthetic-peer-turn", ToolUseID: "synthetic-peer-tool"}
	var out bytes.Buffer
	if err := codexPreToolUseWithSelection(event, &out, &LocalNodeSelection{UserRoot: m.localNode.Pin.UserRoot}); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Hook struct {
			Decision string         `json:"permissionDecision"`
			Input    map[string]any `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if json.Unmarshal(out.Bytes(), &reply) != nil || reply.Hook.Decision != "allow" {
		t.Fatal("real Hook proof denied", out.String())
	}
	return reply.Hook.Input
}

func (n *peerNetworkFixture) formalMCP(t *testing.T) *mcpServer {
	t.Helper()
	f := n.f
	root := filepath.Join(f.root, "formal-network-root")
	if err := os.MkdirAll(filepath.Join(root, "mcp"), 0700); err != nil {
		t.Fatal(err)
	}
	config := localNodePublishConfig{root, filepath.Join(root, "mcp", "sessions.json"), filepath.Join(root, "mcp", "outbox.sqlite3")}
	if err := startLocalNodeDiscovery(f.bridge, config); err != nil {
		t.Fatal(err)
	}
	m, err := newLocalNodeMCPServer(LocalNodeSelection{UserRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		close(m.stop)
		m.stopCodexHeartbeat()
		m.selectedNodeHTTPPool().close()
		if m.outbox != nil {
			m.outbox.close()
		}
	})
	native := harness.SessionContext{Harness: "codex", NativeSessionID: f.native[0], MachineID: f.nodeID, Workspace: f.workspace}
	scope, _, err := mcpSessionScope(f.server.URL, native)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "mcp", "network-session")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	private, err := privateNetworkScopeDir(dir, scope, true)
	if err != nil {
		t.Fatal(err)
	}
	state := networkCLIState{Version: 1, APIOrigin: f.server.URL, NetworkID: n.network, EndpointID: n.joined[0].Endpoint.ID, Harness: "codex", NativeSessionID: f.native[0], NodeID: f.nodeID, Workspace: f.workspace, SessionToken: n.joined[0].SessionToken}
	data, _ := json.Marshal(state)
	if err := writeNewPrivateNetworkSession(filepath.Join(private, n.network+".session.json"), data); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMCPPeerSelectionRealHubFormalNetworkAcrossNodesAndRevocation(t *testing.T) {
	n := newPeerNetworkFixture(t)
	m := n.formalMCP(t)
	t.Setenv("CICADA_NETWORK_SESSION_DIR", filepath.Join(t.TempDir(), "poisoned-foreign-session-root"))
	e, d := peerTestStdio(t, m)
	args := peerHookArguments(t, n.f, m, 0, "cicada_select_peer", map[string]any{"scope": "network", "network_id": n.network})
	result := peerTestForm(t, e, d, args, n.joined[1].Endpoint.Name, nil)
	selected, ok := result["structuredContent"].(map[string]any)
	if !ok || selected["endpoint_id"] != n.joined[1].Endpoint.ID {
		t.Fatal("real Network peer not selected", result)
	}
	if n.joined[0].Endpoint.MachineID == n.joined[1].Endpoint.MachineID {
		t.Fatal("fixture is not across Nodes")
	}
	id := selected["peer_selection_id"].(string)
	keys := n.authorizeKeys(t)
	originalSelection := m.peerSelections[id]
	body := "SYNTHETIC exact cross-Node selected message"
	sendArgs := peerHookArguments(t, n.f, m, 0, "cicada_send", map[string]any{"peer_selection_id": id, "body": body, "idempotency_key": "synthetic-selected-original"})
	sent, err := m.callTool("cicada_send", sendArgs)
	if err != nil {
		t.Fatal("formal selected send", err)
	}
	if sent.(map[string]any)["status"] != mcpOutboxStatusSent {
		t.Fatal("formal send not persisted", sent)
	}
	claimed, err := n.f.db.ClaimNetworkDirectSealedInbox(store.NetworkDirectClaimInput{NodeID: n.nodes[1], ConsumerID: "SYNTHETIC-selected-receiver", Limit: 4, CredentialDigest: fabric.HashSessionCredential(n.tokens[1])})
	if err != nil || len(claimed) != 1 {
		t.Fatal("selected peer did not receive exact sealed route", err)
	}
	auth, err := n.f.db.AuthorizeClaimedNetworkDirectDelivery(fabric.HashSessionCredential(n.tokens[1]), claimed[0].MessageID, claimed[0].AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := e2ee.OpenNetworkDirectMessage(keys[1], keys[0].Public(), auth.Context, claimed[0].Ciphertext)
	if err != nil || string(plain) != body {
		t.Fatal("selected Endpoint could not decrypt exact message", err)
	}
	// Original outcome recovery does not require another form or resealing.
	m.peerSelections = nil
	retryArgs := peerHookArguments(t, n.f, m, 0, "cicada_send", map[string]any{"peer_selection_id": id, "body": body, "idempotency_key": "synthetic-selected-original"})
	retried, err := m.callTool("cicada_send", retryArgs)
	if err != nil || mcpOutboxOperationID(t, retried) != mcpOutboxOperationID(t, sent) {
		t.Fatal("selected exact retry changed operation", err)
	}
	// Keep this live choice only to test a new send after current revocation.
	m.peerMu.Lock()
	m.peerSelections = map[string]mcpPeerSelection{}
	m.peerSelections[id] = originalSelection
	m.peerMu.Unlock()
	actor, err := n.service.AuthenticateForNetwork(n.joined[1].SessionToken, n.network)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.f.db.RevokeNetworkMembership(n.network, actor.PrincipalID, actor.MembershipRevision); err != nil {
		t.Fatal(err)
	}
	input := peerHookArguments(t, n.f, m, 0, "cicada_send", map[string]any{"peer_selection_id": id, "body": "SYNTHETIC denied message"})
	if _, err := m.callTool("cicada_send", input); err == nil {
		t.Fatal("revoked target selected/sent")
	}
}
