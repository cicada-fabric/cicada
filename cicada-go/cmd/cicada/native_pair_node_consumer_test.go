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
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

// This is a scripted, cryptographically authenticated Node-RPC actor. It
// exercises the production MCP/IPC/outbox paths with synthetic native records;
// it does not manufacture a real Hub ACTIVE grant or execute a Runtime.
type nativePairConsumerFixture struct {
	t                                                 *testing.T
	mu                                                sync.Mutex
	root, workspace, token, pairID                    string
	client                                            *machineNodeControlClient
	ctx                                               context.Context
	bridge                                            *machineAgentJoinBridge
	server                                            *httptest.Server
	owner, appHub, hubControl                         *e2ee.Identity
	binding                                           nodewire.Binding
	scope                                             e2ee.OwnerNativePairScope
	bootstrap                                         []byte
	joined                                            fabric.JoinResult
	packets                                           map[string][]byte
	replies                                           map[string][]byte
	joinRequests                                      [][]byte
	describes, joinEffects, diagnostics, publications int
	dropJoinReplies, dropPublications                 int
	diagnosticHTTPStatus                              int
	rejectJoins                                       int
	generation                                        uint64
	initialLease                                      string
	available                                         bool
}

func newNativePairConsumerFixture(t *testing.T) *nativePairConsumerFixture {
	t.Helper()
	f := &nativePairConsumerFixture{t: t, root: shortLocalJoinStateDir(t), token: "cicada_node_synthetic_pair", pairID: strings.Repeat("2", 32), packets: map[string][]byte{}, replies: map[string][]byte{}, available: true, generation: 1}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	keys := make([]*e2ee.Identity, 4)
	for i := range keys {
		var err error
		keys[i], err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
	}
	node, device := keys[0], keys[1]
	f.owner, f.hubControl = keys[2], keys[3]
	var err error
	f.appHub, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	const nodeID, hubID = "synthetic-pair-node", "synthetic-pair-hub"
	identityPath, _ := machineNodeControlPaths(f.root, nodeID)
	if err := os.MkdirAll(filepath.Dir(identityPath), 0700); err != nil {
		t.Fatal(err)
	}
	private, err := node.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistNodeSecretFile(identityPath, private, ".synthetic-node-key-"); err != nil {
		t.Fatal(err)
	}
	f.client, err = openMachineNodeControlClient(f.root, f.server.URL, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	f.client.mu.Lock()
	s := &f.client.state
	s.HubID, s.HubKeyID, s.HubPublicIdentity = hubID, f.hubControl.Public().ID, f.hubControl.Public()
	s.HubFingerprint, s.HubKeyVersion = nodewire.IdentityFingerprint(f.hubControl.Public()), 1
	s.NodeKeyID, s.NodeKeyFingerprint, s.NodeKeyVersion = node.Public().ID, nodewire.IdentityFingerprint(node.Public()), 1
	s.BindingID, s.BindingVersion, s.NodeKeyEpoch = "synthetic-owner-binding", 1, 1
	s.ApprovedRequestID, s.ApprovedRequestVersion, s.ApprovedCandidateDigest = "synthetic-approved", 1, strings.Repeat("c", 64)
	if err := f.client.persistLocked(); err != nil {
		t.Fatal(err)
	}
	f.binding = machineNodeControlBindingFromState(f.client)
	f.client.mu.Unlock()
	t.Cleanup(func() { machineNodeControlClients.Delete(f.client.statePath) })
	history, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(f.root, "synthetic-native-context.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = history.Close() })
	f.ctx = withMachineHubContext(context.Background(), machineHubContext{HubID: hubID, Origin: f.server.URL, NodeID: nodeID, StateDir: f.root, Token: f.token, WriterRoot: f.root, WriterScope: "synthetic-account", NativeContexts: history, RequireNativeContext: true})
	now := time.Now().UTC().Add(-time.Second)
	stamp := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339Nano) }
	hub := wire.HubIdentity{Contract: "android-hub-v1", HubID: hubID, Public: f.appHub.Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}
	fp, _ := wire.HubFingerprint(hub)
	a := e2ee.OwnerAppNodeScope{Version: 1, Origin: f.server.URL, HubID: hubID, HubFingerprint: fp, AccountID: "synthetic-account", AccountSessionID: "synthetic-session", AccountSessionExpiresAt: stamp(15 * time.Minute), OwnerID: "synthetic-owner", OwnerPublic: f.owner.Public(), OwnerKeyVersion: 1, DeviceID: wire.AccountDeviceIDPrefix + strings.Repeat("a", 32), DevicePublic: device.Public(), AccountEpoch: 1, DeviceEpoch: 1, ClientSessionEpoch: 1, TransportPolicy: wire.AppNodeTransportLoopbackTest}
	f.scope = e2ee.OwnerNativePairScope{Actor: a, NodeControlBindingVersion: 1, CredentialCommitment: wire.NativePairCredentialCommitment(f.token), Node: e2ee.OwnerAppNodeBinding{OwnerBindingID: s.BindingID, OwnerID: a.OwnerID, HubID: hubID, NodeID: nodeID, NodeName: "Synthetic Node", ClientDeviceID: a.DeviceID, OwnerKeyID: f.owner.Public().ID, CredentialVersion: 1, BindingVersion: s.BindingVersion, NodePublic: node.Public(), NodeKeyFingerprint: s.NodeKeyFingerprint, NodeKeyVersion: 1, NodeKeyEpoch: 1, HubNodeControlPublic: f.hubControl.Public(), HubNodeControlFingerprint: s.HubFingerprint, HubNodeControlKeyVersion: 1, ApprovedRequestID: s.ApprovedRequestID, ApprovedRequestVersion: 1, ApprovedCandidateDigest: s.ApprovedCandidateDigest, ApprovedAt: stamp(-time.Minute), State: "ACTIVE"}}
	f.scope.NodeTupleDigest, _ = wire.NativePairNodeTupleDigest(f.scope)
	claims := e2ee.OwnerNativePairClaims{Version: 1, Purpose: e2ee.OwnerNativePairBootstrapCommit, Scope: f.scope, RequestID: strings.Repeat("1", 32), Nonce: strings.Repeat("d", 64), IssuedAt: stamp(0), ExpiresAt: stamp(5 * time.Minute), Bootstrap: &e2ee.NativePairBootstrapClaims{PairID: f.pairID, NetworkID: "synthetic-pair-network", GroupID: "synthetic-pair-group", GroupLabel: "Synthetic pair", Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy(), PreparedAt: stamp(0), JoinUntil: stamp(10 * time.Minute), PeerExpiresAt: stamp(time.Hour), PrepareRequestID: strings.Repeat("3", 32), PreparePacketDigest: strings.Repeat("4", 64), ServerNonce: strings.Repeat("5", 64)}}
	f.bootstrap, err = e2ee.SignOwnerNativePair(f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.root, nodeID))
	if err != nil {
		t.Fatal(err)
	}
	ownerFP, _ := nodekeys.PeerKeyFingerprint(f.owner.Public())
	if _, err := state.TrustOwnerApprovalKeyLocal(a.OwnerID, f.owner.Public().ID, f.owner.Public(), ownerFP); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	f.bridge, err = startMachineAgentJoinBridge(f.ctx, f.root, f.server.URL, nodeID, f.token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.bridge.Close() })
	return f
}

func (f *nativePairConsumerFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case wire.NativePairCapabilitiesPath:
		raw, _ := json.Marshal(wire.NativePairCapabilities{Format: wire.NativePairFormat, ContractRevision: wire.NativePairContractRevision, Available: f.available, ServeMode: "--hub-nodes-only", TransportPolicy: wire.AppNodeTransportLoopbackTest, HTTPOperations: wire.NativePairHTTPOperations(), NodeOperations: wire.NativePairNodeOperations(), PeerTransport: "SEALED_RELAY", Policy: e2ee.NativePairFixedPeerPolicy()})
		_, _ = w.Write(raw)
	case "/v2/node/control/rpc":
		f.nodeRPC(w, r)
	case "/v2/fabric/whoami":
		card := f.joined.NetworkCard
		card.NativeSessionID = f.joined.Endpoint.NativeSessionID
		_ = json.NewEncoder(w).Encode(card)
	case "/v2/fabric/heartbeat":
		_ = json.NewEncoder(w).Encode(fabric.Actor{PrincipalID: f.joined.Endpoint.PrincipalID, EndpointID: f.joined.Endpoint.ID, GroupID: f.joined.Endpoint.GroupID, BindingID: f.joined.BindingID, BindingEpoch: f.joined.BindingEpoch, LeaseOwner: "synthetic-native-lease", LeaseExpiresAt: time.Now().UTC().Add(4 * time.Minute).Format(time.RFC3339Nano)})
	case "/v2/fabric/endpoint-keys":
		var input struct {
			Attestation json.RawMessage `json:"attestation"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			w.WriteHeader(400)
			return
		}
		state, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.root, f.client.nodeID))
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(500)
			return
		}
		retained, err := state.NativePairLocalAttestation(f.ctx, f.pairID, f.joined.Endpoint.ID, f.joined.BindingID, f.joined.BindingEpoch)
		_ = state.Close()
		if err != nil || !bytes.Equal(retained.Attestation, input.Attestation) {
			f.t.Error("candidate POST preceded exact durable attestation")
			w.WriteHeader(500)
			return
		}
		public, err := e2ee.VerifyEndpointKeyAttestation(input.Attestation, f.joined.Endpoint.ID, f.joined.Endpoint.PrincipalID, f.client.nodeID, f.joined.BindingID, f.joined.BindingEpoch)
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(400)
			return
		}
		f.publications++
		if f.dropPublications > 0 {
			f.dropPublications--
			w.WriteHeader(503)
			return
		}
		digest := sha256.Sum256(input.Attestation)
		_ = json.NewEncoder(w).Encode(store.EndpointKeyCandidate{EndpointID: f.joined.Endpoint.ID, PrincipalID: f.joined.Endpoint.PrincipalID, OwnerID: f.scope.Actor.OwnerID, NodeID: f.client.nodeID, BindingID: f.joined.BindingID, BindingEpoch: f.joined.BindingEpoch, KeyID: public.ID, Public: public, Version: 2, State: store.EndpointKeyCandidateStateCandidate, Proof: input.Attestation, ProofDigest: hex.EncodeToString(digest[:])})
	default:
		w.WriteHeader(404)
	}
}

func (f *nativePairConsumerFixture) nodeRPC(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxNativePairNodeReconcilePacketBytes+1))
	if err != nil {
		w.WriteHeader(400)
		return
	}
	opened, err := nodewire.OpenRequest(f.hubControl, f.binding.NodeKey, f.binding, raw)
	if err != nil {
		f.t.Error(err)
		w.WriteHeader(400)
		return
	}
	data, err := os.ReadFile(f.client.statePath)
	if err != nil {
		f.t.Error(err)
		w.WriteHeader(500)
		return
	}
	var persisted machineNodeControlState
	if json.Unmarshal(data, &persisted) != nil {
		f.t.Error("Node journal was unreadable before POST")
		w.WriteHeader(500)
		return
	}
	if nativePairNodeBusinessOperation(opened.Route.Operation) && (!bytes.Equal(persisted.PendingPacket, raw) || !bytes.Equal(persisted.PendingNativePairBody, opened.Plaintext)) {
		retained := false
		for _, receipt := range persisted.NativePairReceipts {
			if bytes.Equal(receipt.RequestPacket, raw) && bytes.Equal(receipt.RequestBody, opened.Plaintext) {
				retained = true
				break
			}
		}
		if !retained {
			f.t.Error("Node business POST preceded exact durable original")
			w.WriteHeader(500)
			return
		}
	}
	if previous, exists := f.packets[opened.Route.OperationID]; exists && !bytes.Equal(previous, raw) {
		f.t.Error("operation ID replaced original ciphertext")
		w.WriteHeader(409)
		return
	}
	f.packets[opened.Route.OperationID] = bytes.Clone(raw)
	if opened.Route.Operation == wire.OperationNativePairNodeJoin && f.rejectJoins > 0 && len(f.replies[opened.Route.OperationID]) == 0 {
		f.rejectJoins--
		body := nodeControlTestEnvelope(f.t, opened.Route, false, nil, wire.NativePairNodeJoinFenceCode)
		f.replies[opened.Route.OperationID], err = nodewire.SealResponse(f.hubControl, f.binding.NodeKey, f.binding, nodeControlTestResponseRoute(opened.Route), body)
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(500)
			return
		}
	}
	var result any
	if opened.Route.Operation == wire.OperationNativePairNodeDescribe {
		f.describes++
		result = wire.NativePairNodeDescription{ContractRevision: wire.NativePairContractRevision, PairID: f.pairID, HubIdentity: wire.HubIdentity{Contract: "android-hub-v1", HubID: f.binding.HubID, Public: f.appHub.Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}, BootstrapOwnerProof: f.bootstrap, SlotAGeneration: f.generation, SlotBGeneration: 1}
	} else if opened.Route.Operation == wire.OperationNativePairNodeJoin {
		f.joinRequests = append(f.joinRequests, bytes.Clone(raw))
		var q wire.NativePairNodeJoin
		if decodeMachineNodeControlJSON(opened.Plaintext, &q) != nil {
			w.WriteHeader(400)
			return
		}
		if _, exists := f.replies[opened.Route.OperationID]; !exists {
			if q.ExpectedGeneration != f.generation {
				f.t.Error("fresh Join did not use newly described generation")
				w.WriteHeader(400)
				return
			}
			f.joinEffects++
			f.joined = fabric.JoinResult{Endpoint: store.Endpoint{ID: "synthetic-endpoint-a", PrincipalID: "synthetic-principal-a", GroupID: "synthetic-pair-group", Owner: f.scope.Actor.OwnerID, Harness: "codex", NativeSessionID: q.NativeSessionID, MachineID: f.client.nodeID, Workspace: q.Workspace, Status: "online"}, NetworkCard: fabric.NetworkCard{EndpointID: "synthetic-endpoint-a", PrincipalID: "synthetic-principal-a", GroupID: "synthetic-pair-group", NodeID: f.client.nodeID, Harness: "codex", Workspace: q.Workspace, BindingID: "synthetic-group-binding-a", BindingEpoch: 10, Capabilities: map[string]any{"local_peer_delivery": "sealed_v1"}}, SessionToken: "cicada_session_synthetic_pair", BindingID: "synthetic-group-binding-a", BindingEpoch: 10, LeaseExpiresAt: time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano), NativeContextScope: store.NativeContextScopeMetadata{HubID: f.binding.HubID, NetworkID: "synthetic-pair-network", GroupID: "synthetic-pair-group", GroupContextPolicy: nodeinbox.NativeContextPolicyDedicatedThread}}
			if f.initialLease != "" {
				f.joined.LeaseExpiresAt = f.initialLease
			}
		}
		result = f.joined
	} else if opened.Route.Operation == wire.OperationNativePairNodeReconcile {
		f.diagnostics++
		if persisted.NativePairDiagnostic == nil || !bytes.Equal(persisted.NativePairDiagnostic.Packet, raw) {
			f.t.Error("diagnostic POST preceded durable original target")
			w.WriteHeader(500)
			return
		}
		if f.diagnosticHTTPStatus != 0 {
			w.WriteHeader(f.diagnosticHTTPStatus)
			return
		}
		var q wire.NativePairNodeReconcile
		if decodeMachineNodeControlJSON(opened.Plaintext, &q) != nil {
			w.WriteHeader(400)
			return
		}
		original, err := wire.DecodeNativePairNodePacket(q.OriginalPacket)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		result = wire.NativePairNodeReconciled{ContractRevision: wire.NativePairContractRevision, PairID: q.PairID, OriginalOperation: original.Route.Operation, OriginalOperationID: original.Route.OperationID, OriginalSequence: original.Route.Sequence, OriginalPacketDigest: wire.NativePairNodePacketDigest(q.OriginalPacket), State: "COMPLETED", ReceiptPacket: f.replies[original.Route.OperationID], ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	} else {
		w.WriteHeader(404)
		return
	}
	response := f.replies[opened.Route.OperationID]
	if len(response) == 0 {
		body := nodeControlTestEnvelope(f.t, opened.Route, true, result, "")
		response, err = nodewire.SealResponse(f.hubControl, f.binding.NodeKey, f.binding, nodeControlTestResponseRoute(opened.Route), body)
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(500)
			return
		}
		f.replies[opened.Route.OperationID] = response
	}
	if opened.Route.Operation == wire.OperationNativePairNodeJoin && f.dropJoinReplies > 0 {
		f.dropJoinReplies--
		w.WriteHeader(503)
		return
	}
	_, _ = w.Write(response)
}

func (f *nativePairConsumerFixture) mcp(t *testing.T) *mcpServer {
	t.Helper()
	f.workspace = prepareMCPJoinSessionRecord(t, "synthetic-existing-thread")
	t.Setenv("CICADA_NODE_STATE_DIR", f.root)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CODEX_THREAD_ID", "synthetic-existing-thread")
	t.Setenv("CODEX_SESSION_ID", "")
	t.Setenv("CICADA_MACHINE_ID", f.client.nodeID)
	m := newMCPServer(f.server.URL, "", filepath.Join(f.root, "mcp", "sessions.json"))
	m.hubStateDir = f.root
	t.Cleanup(func() { close(m.stop) })
	return m
}

func TestNativePairConsumerMCPOriginalPacketRecoveryAndPublicResult(t *testing.T) {
	f := newNativePairConsumerFixture(t)
	f.dropJoinReplies = 2
	// A late original receipt is history; current same-binding whoami/heartbeat,
	// rather than its initial cached lease, determine whether resume can proceed.
	f.initialLease = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	m := f.mcp(t)
	result, err := m.callTool("cicada_join", map[string]any{"pair_id": f.pairID, "slot": "A"})
	if err != nil {
		t.Fatal(err)
	}
	public, ok := result.(mcpPublicJoinResult)
	if !ok || public.Endpoint.NativeSessionID != "synthetic-existing-thread" || public.Endpoint.Workspace != f.workspace {
		t.Fatal("MCP changed original native context")
	}
	if public.Reused {
		t.Fatal("first completed Join was mislabeled as a prior cached Join")
	}
	if !time.Now().Before(parseMachineNativePairTime(public.LeaseExpiresAt)) || public.BindingID != f.joined.BindingID || public.BindingEpoch != f.joined.BindingEpoch {
		t.Fatal("late history replaced or failed to inspect the original binding")
	}
	raw, _ := json.Marshal(public)
	if bytes.Contains(raw, []byte(f.joined.SessionToken)) || bytes.Contains(raw, []byte("bootstrap_owner_proof")) || bytes.Contains(raw, []byte("signed_proof")) {
		t.Fatal("private Node transport material crossed MCP")
	}
	f.mu.Lock()
	if f.joinEffects != 1 || f.describes != 1 || f.diagnostics != 1 || len(f.joinRequests) != 2 || !bytes.Equal(f.joinRequests[0], f.joinRequests[1]) {
		t.Fatal("lost ACK replaced Join, re-described, or failed original reconciliation")
	}
	f.mu.Unlock()
	f.client.mu.Lock()
	if len(f.client.state.PendingPacket) != 0 || len(f.client.state.NativePairReceipts) != 2 {
		t.Fatal("original receipt was not retained before pending retirement")
	}
	f.client.mu.Unlock()
}

func TestNativePairConsumerReopenAfterCandidateAckLossKeepsBindingAndKey(t *testing.T) {
	f := newNativePairConsumerFixture(t)
	f.dropPublications = 1
	m := f.mcp(t)
	args := map[string]any{"pair_id": f.pairID, "slot": "A"}
	if _, err := m.callTool("cicada_join", args); err == nil {
		t.Fatal("lost candidate ACK reported ready")
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.root, f.client.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	before, err := state.NativePairLocalAttestation(f.ctx, f.pairID, f.joined.Endpoint.ID, f.joined.BindingID, f.joined.BindingEpoch)
	_ = state.Close()
	if err != nil || before.CandidateVersion != 0 {
		t.Fatal("lost ACK lost exact original publication", err)
	}
	machineNodeControlClients.Delete(f.client.statePath)
	result, err := m.callTool("cicada_join", args)
	if err != nil {
		t.Fatal(err)
	}
	public := result.(mcpPublicJoinResult)
	if !public.Reused {
		t.Fatal("retained original Join was not identified as reused")
	}
	if public.BindingID != f.joined.BindingID || public.BindingEpoch != f.joined.BindingEpoch {
		t.Fatal("reopen replaced original binding")
	}
	state, err = nodekeys.OpenCryptoState(machineNodeStateDir(f.root, f.client.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	after, err := state.NativePairLocalAttestation(f.ctx, f.pairID, f.joined.Endpoint.ID, f.joined.BindingID, f.joined.BindingEpoch)
	_ = state.Close()
	if err != nil || after.CandidateVersion != 2 || !bytes.Equal(before.Attestation, after.Attestation) || before.KeyID != after.KeyID {
		t.Fatal("recovery replaced original key or publication", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.joinEffects != 1 || f.describes != 1 || f.publications != 2 {
		t.Fatal("reopen restarted Join or failed exact publication retry")
	}
}

func TestNativePairConsumerUnavailableHasNoNewBusinessPacket(t *testing.T) {
	f := newNativePairConsumerFixture(t)
	f.available = false
	m := f.mcp(t)
	if _, err := m.callTool("cicada_join", map[string]any{"pair_id": f.pairID, "slot": "A"}); err == nil {
		t.Fatal("unavailable profile admitted Join")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.packets) != 0 || f.joinEffects != 0 {
		t.Fatal("unavailable profile emitted a business packet")
	}
}

func TestNativePairConsumerUnsignedDiagnosticErrorRetainsOriginalAcrossReopen(t *testing.T) {
	f := newNativePairConsumerFixture(t)
	f.dropJoinReplies, f.diagnosticHTTPStatus = 99, http.StatusForbidden
	m := f.mcp(t)
	args := map[string]any{"pair_id": f.pairID, "slot": "A"}
	if _, err := m.callTool("cicada_join", args); err == nil {
		t.Fatal("unsigned diagnostic denial settled original Join")
	}
	f.client.mu.Lock()
	original := bytes.Clone(f.client.state.PendingPacket)
	sequence := f.client.state.PendingSequence
	if len(original) == 0 || f.client.state.PendingOperation != wire.OperationNativePairNodeJoin || f.client.state.NativePairDiagnostic == nil {
		t.Fatal("unsigned denial discarded original or diagnostic")
	}
	f.client.mu.Unlock()
	f.mu.Lock()
	f.dropJoinReplies, f.diagnosticHTTPStatus, f.available = 0, 0, false
	f.mu.Unlock()
	machineNodeControlClients.Delete(f.client.statePath)
	result, err := m.callTool("cicada_join", args)
	if err != nil {
		t.Fatal(err)
	}
	if result.(mcpPublicJoinResult).BindingID != f.joined.BindingID {
		t.Fatal("resume replaced binding")
	}
	client, err := openMachineNodeControlClientMode(f.root, f.server.URL, f.client.nodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	if len(client.state.PendingPacket) != 0 || client.state.Sequence != sequence {
		t.Fatal("reopen reset original sequence or left receipt unapplied")
	}
	client.mu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.joinEffects != 1 || f.describes != 1 || f.diagnostics != 1 || !bytes.Equal(original, f.joinRequests[len(f.joinRequests)-1]) {
		t.Fatal("unsigned denial caused replacement Join/Describe")
	}
}

func TestNativePairConsumerMCPFenceReportsOnceBeforeNextExplicitIntent(t *testing.T) {
	for _, mode := range []string{"immediate", "pending-reopen"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativePairConsumerFixture(t)
			f.rejectJoins = 1
			if mode == "pending-reopen" {
				f.dropJoinReplies, f.diagnosticHTTPStatus = 2, http.StatusServiceUnavailable
			}
			m := f.mcp(t)
			args := map[string]any{"pair_id": f.pairID, "slot": "A"}
			if _, err := m.callTool("cicada_join", args); err == nil {
				t.Fatal("first refused/uncertain original reported success")
			}
			if mode == "pending-reopen" {
				f.client.mu.Lock()
				pending := len(f.client.state.PendingPacket) > 0
				f.client.mu.Unlock()
				if !pending {
					t.Fatal("unsigned failure consumed the original before its authenticated fence")
				}
				f.mu.Lock()
				f.dropJoinReplies, f.diagnosticHTTPStatus = 0, 0
				beforeEffects := f.joinEffects
				beforeReads := f.describes
				f.mu.Unlock()
				machineNodeControlClients.Delete(f.client.statePath)
				if _, err := m.callTool("cicada_join", args); err == nil || !strings.Contains(err.Error(), "authenticated terminal refusal") {
					t.Fatalf("first authenticated fence was not reported: %v", err)
				}
				f.mu.Lock()
				changed := f.joinEffects != beforeEffects || f.describes != beforeReads
				f.mu.Unlock()
				if changed {
					t.Fatal("same recovery call started a fresh Join/Describe")
				}
			}
			client, err := openMachineNodeControlClientMode(f.root, f.server.URL, f.client.nodeID, true)
			if err != nil {
				t.Fatal(err)
			}
			client.mu.Lock()
			var old machineNativePairReceipt
			var oldID string
			for id, record := range client.state.NativePairReceipts {
				if record.Operation == wire.OperationNativePairNodeJoin && record.Fenced {
					old = cloneMachineNativePairReceipt(record)
					oldID = id
				}
			}
			client.mu.Unlock()
			if oldID == "" || !old.Consumed {
				t.Fatal("first fence report was not durable")
			}
			f.mu.Lock()
			f.generation = 2
			f.mu.Unlock()
			result, err := m.callTool("cicada_join", args)
			if err != nil {
				t.Fatal("next explicit invocation remained permanently fenced", err)
			}
			public := result.(mcpPublicJoinResult)
			if public.Reused || public.Endpoint.NativeSessionID != "synthetic-existing-thread" {
				t.Fatal("fresh explicit intent changed original Thread or claimed cached Join")
			}
			client.mu.Lock()
			retained := cloneMachineNativePairReceipt(client.state.NativePairReceipts[oldID])
			client.mu.Unlock()
			if !bytes.Equal(retained.RequestPacket, old.RequestPacket) || !bytes.Equal(retained.ResponsePacket, old.ResponsePacket) || !retained.Fenced || !retained.Consumed {
				t.Fatal("fresh intent replaced its old permanent fence")
			}
			late, err := client.postPacket(f.ctx, f.token, old.RequestPacket)
			if err != nil || !bytes.Equal(late, old.ResponsePacket) {
				t.Fatal("late old original did not keep its exact fence", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.joinEffects != 1 || f.describes != 2 {
				t.Fatal("fence recovery repeated effects or omitted fresh Describe")
			}
		})
	}
}
