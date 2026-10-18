package main

import (
	"bytes"
	"context"
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
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubnodes"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// Real production Hub/SQLite/PQ and consumer code. Only native context records
// and queue subprocesses are synthetic. Capability stays false: fresh discovery
// is tested as unavailable; an explicit development probe obtains the original
// Node receipts that MCP is subsequently allowed to recover.
type nativePairTCPConsumerFixture struct {
	t                                        *testing.T
	mu                                       sync.Mutex
	root, nodeRoot, nodeID, token, workspace string
	native                                   [2]string
	db                                       *store.Store
	setup                                    *store.HubOwnerSetup
	hub                                      wire.HubIdentity
	server                                   *httptest.Server
	handler                                  http.Handler
	owner, device                            *e2ee.Identity
	session                                  wire.AppNodeSession
	scope                                    e2ee.OwnerNativePairScope
	bootstrap                                wire.NativePairBootstrapChallenge
	description                              wire.NativePairNodeDescription
	plan                                     wire.NativePairPlanChallenge
	ctx                                      context.Context
	cancel                                   context.CancelFunc
	client                                   *machineNodeControlClient
	bridge                                   *machineAgentJoinBridge
	history                                  *nodeinbox.NativeContextRegistry
	mcp                                      [2]*mcpServer
	joins                                    [2]fabric.JoinResult
	nodePackets                              map[string][][]byte
	posts                                    map[string]int
	dropJoin, dropCandidate                  int
	carrierEdit                              func(map[string]json.RawMessage)
}

func newNativePairTCPConsumerFixture(t *testing.T) *nativePairTCPConsumerFixture {
	t.Helper()
	root, err := os.MkdirTemp(os.TempDir(), "np-")
	if err != nil {
		t.Fatal(err)
	}
	f := &nativePairTCPConsumerFixture{t: t, root: root, nodeRoot: filepath.Join(root, "node"), nodeID: "synthetic-tcp-consumer-node", native: [2]string{"synthetic-tcp-consumer-original-a", "synthetic-tcp-consumer-original-b"}, nodePackets: map[string][][]byte{}, posts: map[string]int{}}
	t.Cleanup(func() {
		for _, m := range f.mcp {
			if m != nil {
				close(m.stop)
			}
		}
		if f.cancel != nil {
			f.cancel()
		}
		if f.bridge != nil {
			_ = f.bridge.Close()
		}
		if f.history != nil {
			_ = f.history.Close()
		}
		if f.server != nil {
			f.server.Close()
		}
		if f.db != nil {
			_ = f.db.Close()
		}
		if f.client != nil {
			machineNodeControlClients.Delete(f.client.statePath)
		}
		_ = os.RemoveAll(root)
	})
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.db, err = store.New(filepath.Join(root, "hub", "synthetic.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	f.setup, err = f.db.InitializeHubOwnerLocal("Synthetic TCP consumer Owner", "http://"+f.server.Listener.Addr().String(), true)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := hubidentity.LoadOrCreate(filepath.Join(root, "hub"), "")
	if err != nil {
		t.Fatal(err)
	}
	ownerService, err := hubowner.NewService(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := hubauth.NewServiceWithNodeAuthority(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := hubnodes.NewService(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	f.hub, err = auth.HubIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.handler = serverpkg.NewHubNodesHandler(ownerService, auth, nodes)
	f.server.Start()
	f.owner, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.device, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	material, err := auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := wire.AccountDeviceIDPrefix + id
	grant, err := f.owner.SignOwnerDeviceGrant(material.OwnerID, deviceID, f.device.Public(), material.HubID, e2ee.OwnerDevicePurposeControl, at, at.Add(9*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := wire.NewActivationPrepare(*material, f.hub, f.device.Public(), f.owner.Public(), deviceID, grant, at)
	if err != nil {
		t.Fatal(err)
	}
	var challenge wire.ActivationChallenge
	original := f.app(t, prepare, &challenge)
	if err := wire.ValidateActivationPreparedResponse(challenge, prepare, original, f.hub, f.device.Public(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	const username, password = "synthetic-tcp-consumer", "Synthetic consumer password 72!"
	complete, err := wire.NewActivationComplete(challenge, f.hub, f.device.Public(), f.owner, username, password, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	f.app(t, complete, &wire.ActivationResult{})
	login, err := wire.NewLoginPrepare(f.hub, f.setup.Origin, f.setup.AccountID, f.setup.OwnerID, deviceID, username, f.device.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var loginChallenge wire.LoginChallenge
	f.app(t, login, &loginChallenge)
	loginComplete, err := wire.NewLoginComplete(f.hub, loginChallenge, password, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var receipt wire.SessionReceipt
	f.app(t, loginComplete, &receipt)
	f.session = wire.AppNodeSession{Hub: f.hub, Origin: f.setup.Origin, AccountID: f.setup.AccountID, OwnerID: f.setup.OwnerID, DeviceID: deviceID, AccountEpoch: receipt.AccountEpoch, DeviceEpoch: receipt.DeviceEpoch, Token: receipt.SessionToken}
	status, err := wire.NewAppNodeStatus(f.session, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, initial := f.authority(t, status)
	f.token, _, err = fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	f.history, err = nodeinbox.OpenNativeContextRegistry(filepath.Join(f.nodeRoot, "native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	f.ctx, f.cancel = context.WithCancel(withMachineHubContext(context.Background(), machineHubContext{HubID: f.hub.HubID, Origin: f.server.URL, NodeID: f.nodeID, StateDir: f.nodeRoot, Token: f.token, WriterRoot: f.nodeRoot, WriterScope: "synthetic-tcp-consumer-account", NativeContexts: f.history, RequireNativeContext: true}))
	f.client, err = openMachineNodeControlClient(f.nodeRoot, f.server.URL, f.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	nodeHub, err := machineNodeControlGetHubIdentity(f.ctx, f.client)
	if err != nil {
		t.Fatal(err)
	}
	code, err := startMachineNodeControlPairing(f.ctx, f.client, nodeHub, "Synthetic consumer Node", f.token, hashNodeCredential(f.token), false)
	if err != nil {
		t.Fatal(err)
	}
	nodePrepare, err := wire.NewAppNodePrepare(f.session, initial.Result.Authority.Scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: code.UserCode}, f.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	nodeOriginal, preview := f.authority(t, nodePrepare)
	nodeComplete, err := wire.NewAppNodeComplete(f.session, nodePrepare, nodeOriginal, *preview.Challenge, f.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	f.authority(t, nodeComplete)
	confirm, err := wire.SealAppNodeConfirmation(f.device, f.hub, preview.Challenge.Claims, code.UserCode, initial.Result.Authority.Counters.LastRequestSequence+1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	response := f.http(t, http.MethodPost, "/v2/client/rpc", "", "", confirm, http.StatusOK)
	confirmed, err := wire.OpenAppNodeConfirmationResponse(f.device, f.hub, preview.Challenge.Claims, confirm, response, initial.Result.Authority.Counters.NextResponseSequence)
	if err != nil || !confirmed.OK || confirmed.Binding == nil {
		t.Fatalf("actual N3 Node confirmation: %v", err)
	}
	pairingStatus, err := pollMachineNodeControlPairingStatus(f.ctx, f.client, f.token, code.Candidate.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.client.installApprovedBinding(pairingStatus, code.Candidate.RequestID, code.Candidate, nodeHub); err != nil {
		t.Fatal(err)
	}
	actor := initial.Result.Authority.Scope
	actor.HeadVersion = 0
	f.scope = e2ee.OwnerNativePairScope{Actor: actor, Node: *confirmed.Binding}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.nodeRoot, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := nodekeys.PeerKeyFingerprint(f.owner.Public())
	_, err = state.TrustOwnerApprovalKeyLocal(f.setup.OwnerID, f.owner.Public().ID, f.owner.Public(), fp)
	closeErr := state.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("independent synthetic local pin: %v %v", err, closeErr)
	}
	f.bridge, err = startMachineAgentJoinBridge(f.ctx, f.nodeRoot, f.server.URL, f.nodeID, f.token)
	if err != nil {
		t.Fatal(err)
	}
	f.workspace, err = os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := filepath.Join(root, "synthetic-codex-home")
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_WORKSPACE", f.workspace)
	t.Setenv("CICADA_NODE_STATE_DIR", f.nodeRoot)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CODEX_SESSION_ID", "")
	t.Setenv("CICADA_MACHINE_ID", f.nodeID)
	t.Setenv("CICADA_HUB_ID", f.hub.HubID)
	for i, native := range f.native {
		writeCodexSessionRecord(t, codexHome, native, f.workspace)
		f.mcp[i] = newMCPServer(f.server.URL, "", filepath.Join(root, "mcp", native+".json"))
		f.mcp[i].hubStateDir = f.nodeRoot
	}
	f.bootstrapPair(t)
	return f
}

func (f *nativePairTCPConsumerFixture) serve(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	if r.Method == http.MethodPost {
		var err error
		raw, err = io.ReadAll(io.LimitReader(r.Body, wire.MaxPacketBytes+1))
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(500)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
	}
	f.mu.Lock()
	if r.Method == http.MethodPost {
		f.posts[r.URL.Path]++
	}
	drop := false
	if r.URL.Path == "/v2/node/control/rpc" {
		if packet, err := wire.DecodeNativePairNodePacket(raw); err == nil {
			f.nodePackets[packet.Route.Operation] = append(f.nodePackets[packet.Route.Operation], bytes.Clone(raw))
			if packet.Route.Operation == wire.OperationNativePairNodeJoin && f.dropJoin > 0 {
				f.dropJoin--
				drop = true
			}
		}
	}
	if r.URL.Path == "/v2/fabric/endpoint-keys" && f.dropCandidate > 0 {
		f.dropCandidate--
		drop = true
	}
	edit := f.carrierEdit
	f.mu.Unlock()
	if drop || edit != nil && (r.URL.Path == "/v2/relay/nodes/"+f.nodeID+"/group/sealed/peer-key" || strings.HasSuffix(r.URL.Path, "/authorization")) {
		buffer := httptest.NewRecorder()
		f.handler.ServeHTTP(buffer, r)
		if drop {
			if buffer.Code != http.StatusOK {
				f.t.Errorf("actual commit before synthetic ACK loss returned %d", buffer.Code)
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(buffer.Body.Bytes(), &fields) != nil {
			f.t.Error("actual peer carrier is not JSON")
			w.WriteHeader(500)
			return
		}
		edit(fields)
		body, _ := json.Marshal(fields)
		for key, values := range buffer.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(buffer.Code)
		_, _ = w.Write(body)
		return
	}
	f.handler.ServeHTTP(w, r)
}

func (f *nativePairTCPConsumerFixture) http(t *testing.T, method, path, authorization, group string, body []byte, want int) []byte {
	t.Helper()
	req, err := http.NewRequest(method, f.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", f.setup.Origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Cicada-Group-Scope", group)
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxPacketBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("actual synthetic TCP %s %s status %d wanted %d", method, path, response.StatusCode, want)
	}
	return raw
}

func (f *nativePairTCPConsumerFixture) app(t *testing.T, body, target any) []byte {
	t.Helper()
	packet, reply := f.appPacket(t, body)
	if err := wire.OpenClientResponse(f.device, f.hub, packet, reply, target); err != nil {
		t.Fatal(err)
	}
	return packet
}

func (f *nativePairTCPConsumerFixture) appPacket(t *testing.T, body any) ([]byte, []byte) {
	t.Helper()
	packet, err := wire.SealClientRequest(f.device, f.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	_, route, err := wire.NewClientRoute(f.hub, body, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	path := wire.ActivationHTTPPath(route.Operation)
	if path == "" {
		path = wire.AppNodeHTTPPath(route.Operation)
	}
	if path == "" {
		path = wire.NativePairHTTPPath(route.Operation)
	}
	if path == "" {
		switch route.Operation {
		case wire.OperationLoginPrepare:
			path = "/v2/owner/account/login/prepare"
		case wire.OperationLoginComplete:
			path = "/v2/owner/account/login/complete"
		default:
			t.Fatal("unexpected synthetic App operation")
		}
	}
	return packet, f.http(t, http.MethodPost, path, "", "", packet, http.StatusOK)
}

func (f *nativePairTCPConsumerFixture) authority(t *testing.T, body any) ([]byte, wire.AppNodeResponse) {
	t.Helper()
	original, reply := f.appPacket(t, body)
	response, err := wire.OpenAppNodeResponse(f.device, f.hub, original, reply)
	if err != nil {
		t.Fatal(err)
	}
	return original, response
}

func (f *nativePairTCPConsumerFixture) claims(t *testing.T, purpose string) (wire.NativePairRequestContext, e2ee.OwnerNativePairClaims) {
	t.Helper()
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	s := f.scope.Actor
	c := wire.NativePairRequestContext{Origin: s.Origin, HubID: s.HubID, AccountID: s.AccountID, OwnerID: s.OwnerID, DeviceID: s.DeviceID, AccountSessionID: s.AccountSessionID, AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch, ClientSessionEpoch: s.ClientSessionEpoch, RequestID: id, ClientNonce: nonce, IssuedAt: at.Format(time.RFC3339Nano)}
	return c, e2ee.OwnerNativePairClaims{Version: 1, Purpose: purpose, Scope: f.scope, RequestID: id, Nonce: hex.EncodeToString(nonce), IssuedAt: c.IssuedAt, ExpiresAt: at.Add(time.Minute).Format(time.RFC3339Nano)}
}

func (f *nativePairTCPConsumerFixture) bootstrapPair(t *testing.T) {
	t.Helper()
	c, claims := f.claims(t, e2ee.OwnerNativePairBootstrapPreview)
	claims.Bootstrap = &e2ee.NativePairBootstrapClaims{GroupLabel: "Synthetic consumer pair", Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy()}
	proof, err := e2ee.SignOwnerNativePair(f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairBootstrapPrepare{Format: wire.NativePairFormat, Context: c, SessionToken: f.session.Token, OwnerProof: proof}
	original := f.app(t, q, &f.bootstrap)
	if err := wire.ValidateNativePairBootstrapTarget(q, original, f.bootstrap, f.hub, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	f.scope = f.bootstrap.Scope
	c, claims = f.claims(t, e2ee.OwnerNativePairBootstrapCommit)
	claims.ExpiresAt = f.bootstrap.ProofExpiresAt
	claims.Bootstrap = &f.bootstrap.Bootstrap
	proof, err = e2ee.SignOwnerNativePair(f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	var result wire.NativePairResult
	f.app(t, wire.NativePairBootstrapComplete{Format: wire.NativePairFormat, Context: c, SessionToken: f.session.Token, OwnerProof: proof}, &result)
	if result.State != wire.NativePairWaitingJoin {
		t.Fatal("bootstrap inferred joined slots")
	}
}

func (f *nativePairTCPConsumerFixture) status(t *testing.T) wire.NativePairResult {
	t.Helper()
	c, _ := f.claims(t, e2ee.OwnerNativePairBootstrapPreview)
	var result wire.NativePairResult
	f.app(t, wire.NativePairStatusRequest{Format: wire.NativePairFormat, Context: c, SessionToken: f.session.Token, PairID: f.bootstrap.Bootstrap.PairID}, &result)
	return result
}

func (f *nativePairTCPConsumerFixture) prepareConsent(t *testing.T) {
	t.Helper()
	status := f.status(t)
	if status.SlotA == nil || status.SlotB == nil {
		t.Fatal("actual Node candidates absent")
	}
	ad, _ := wire.NativePairSlotDigest(*status.SlotA)
	bd, _ := wire.NativePairSlotDigest(*status.SlotB)
	c, claims := f.claims(t, e2ee.OwnerNativePairConsentPreview)
	claims.Consent = &e2ee.NativePairConsentClaims{PairID: status.PairID, ExpectedRevision: status.ControlRevision, SlotADigest: ad, SlotBDigest: bd, PeerExpiresAt: status.PeerExpiresAt}
	proof, err := e2ee.SignOwnerNativePair(f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairConsentPrepare{Format: wire.NativePairFormat, Context: c, SessionToken: f.session.Token, OwnerProof: proof}
	original := f.app(t, q, &f.plan)
	if err := wire.ValidateNativePairPlanTarget(q, original, f.plan, f.description.BootstrapOwnerProof, f.hub, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func (f *nativePairTCPConsumerFixture) consent(t *testing.T, index int) wire.NativePairResult {
	t.Helper()
	p := f.plan.Plan
	s, peer, m := p.SlotA, p.SlotB, p.SlotAKeyManifest
	if index == 1 {
		s, peer, m = p.SlotB, p.SlotA, p.SlotBKeyManifest
	}
	ad, _ := wire.NativePairSlotDigest(p.SlotA)
	bd, _ := wire.NativePairSlotDigest(p.SlotB)
	c, claims := f.claims(t, e2ee.OwnerNativePairSlotConsent)
	claims.Consent = &e2ee.NativePairConsentClaims{PairID: p.PairID, ExpectedRevision: p.ExpectedRevision, PlanID: p.PlanID, PlanDigest: p.Digest, SlotADigest: ad, SlotBDigest: bd, Slot: s.Slot, SlotGeneration: s.Generation, SlotAttemptID: s.AttemptID, NativeSessionID: s.NativeSessionID, PeerNativeSessionID: peer.NativeSessionID, ActivateWhenBoth: true, PlanExpiresAt: p.ExpiresAt, PeerExpiresAt: p.PeerExpiresAt}
	proof, err := e2ee.SignOwnerNativePair(f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	issued, _ := time.Parse(time.RFC3339Nano, m.IssuedAt)
	end, _ := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	groupProof, err := f.owner.SignOwnerLinkKeyGrant(m.OwnerID, m.Operation, m.Digest, m.CandidateBindingDigest, uint64(m.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issued, end)
	if err != nil {
		t.Fatal(err)
	}
	var result wire.NativePairResult
	f.app(t, wire.NativePairConsentComplete{Format: wire.NativePairFormat, Context: c, SessionToken: f.session.Token, OwnerProof: proof, GroupKeyProof: groupProof}, &result)
	return result
}

func (f *nativePairTCPConsumerFixture) explicitNodeJoinProbe(t *testing.T, index int) {
	t.Helper()
	if index == 0 || f.description.ContractRevision == "" {
		if err := f.client.call(f.ctx, f.token, wire.OperationNativePairNodeDescribe, wire.NativePairNodeDescribe{ContractRevision: wire.NativePairContractRevision, PairID: f.bootstrap.Bootstrap.PairID}, nil); err != nil {
			t.Fatal(err)
		}
		description, err := f.client.takeNativePairDescription(f.bootstrap.Bootstrap.PairID)
		if err != nil || description == nil {
			t.Fatalf("actual authenticated Describe: %v", err)
		}
		f.description = *description
		if err := f.client.acceptNativePairDescription(f.ctx, f.token, *description, f.bootstrap.Bootstrap.PairID); err != nil {
			t.Fatal(err)
		}
	}
	slot, generation := "A", f.description.SlotAGeneration
	if index == 1 {
		slot, generation = "B", f.description.SlotBGeneration
	}
	if err := verifyCodexSessionRecord(f.native[index], f.workspace); err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision, PairID: f.bootstrap.Bootstrap.PairID, Slot: slot, ExpectedGeneration: generation, BootstrapProofDigest: wire.NativePairProofDigest(f.description.BootstrapOwnerProof), Runtime: "codex", NativeSessionID: f.native[index], Workspace: f.workspace}
	if err := f.client.call(f.ctx, f.token, wire.OperationNativePairNodeJoin, q, nil); err != nil {
		if err := f.client.recoverNativePairOriginal(f.ctx, f.token); err != nil {
			t.Fatal(err)
		}
	}
	request := localNativePairJoinRequest{PairID: q.PairID, Slot: slot, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace}
	joined, err := f.client.retainedNativePairJoin(request)
	if err != nil || joined == nil {
		t.Fatalf("actual retained Node receipt: %v", err)
	}
	f.joins[index] = *joined
}

func (f *nativePairTCPConsumerFixture) recoverMCP(t *testing.T, index int) (any, error) {
	t.Helper()
	t.Setenv("CODEX_THREAD_ID", f.native[index])
	slot := "A"
	if index == 1 {
		slot = "B"
	}
	return f.mcp[index].callTool("cicada_join", map[string]any{"pair_id": f.bootstrap.Bootstrap.PairID, "slot": slot})
}
