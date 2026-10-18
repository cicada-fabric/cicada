package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/store"
)

func (f *nativePairTCPConsumerFixture) admittedPair(t *testing.T, loss bool) {
	t.Helper()
	// Actual public discovery remains unavailable. This is not a discovery shim.
	f.mu.Lock()
	before := len(f.nodePackets[wire.OperationNativePairNodeDescribe]) + len(f.nodePackets[wire.OperationNativePairNodeJoin])
	f.mu.Unlock()
	if _, err := f.recoverMCP(t, 0); err == nil {
		t.Fatal("actual unavailable Hub admitted a fresh MCP Pair Join")
	}
	f.mu.Lock()
	after := len(f.nodePackets[wire.OperationNativePairNodeDescribe]) + len(f.nodePackets[wire.OperationNativePairNodeJoin])
	f.mu.Unlock()
	if before != after {
		t.Fatal("fresh unavailable MCP emitted Describe/Join")
	}
	for i := 0; i < 2; i++ {
		if i == 0 && loss {
			f.mu.Lock()
			f.dropJoin, f.dropCandidate = 2, 1
			f.mu.Unlock()
		}
		f.explicitNodeJoinProbe(t, i)
		if i == 0 && loss {
			if _, err := f.recoverMCP(t, i); err == nil {
				t.Fatal("lost actual candidate acknowledgement reported ready")
			}
		}
		machineNodeControlClients.Delete(f.client.statePath)
		result, err := f.recoverMCP(t, i)
		if err != nil {
			t.Fatal(err)
		}
		public := result.(mcpPublicJoinResult)
		if !public.Reused || public.Endpoint.NativeSessionID != f.native[i] || public.Endpoint.Workspace != f.workspace || public.BindingID != f.joins[i].BindingID || public.BindingEpoch != f.joins[i].BindingEpoch {
			t.Fatal("actual MCP recovery replaced original context/binding")
		}
		if raw, _ := json.Marshal(public); bytes.Contains(raw, []byte(f.joins[i].SessionToken)) || bytes.Contains(raw, []byte("bootstrap_owner_proof")) {
			t.Fatal("private transport material entered actual public Join result")
		}
	}
	if loss {
		f.mu.Lock()
		packets := f.nodePackets[wire.OperationNativePairNodeJoin]
		valid := len(packets) == 3 && bytes.Equal(packets[0], packets[1]) && len(f.nodePackets[wire.OperationNativePairNodeReconcile]) == 1
		f.mu.Unlock()
		if !valid {
			t.Fatal("actual lost Join ACK did not reconcile the exact original")
		}
	}
	f.prepareConsent(t)
	if result := f.consent(t, 0); result.State != wire.NativePairWaitingConsent {
		t.Fatal("first real consent activated peer permission")
	}
	t.Setenv("CODEX_THREAD_ID", f.native[0])
	if result, err := f.mcp[0].callTool("cicada_ask", map[string]any{"target": f.joins[1].Endpoint.ID, "question": "SYNTHETIC_BEFORE_DUAL_CONSENT", "idempotency_key": "synthetic-before-consent"}); err == nil {
		public := result.(map[string]any)
		if public["status"] == mcpOutboxStatusSent || public["delivery"] == "RELAY_PERSISTED" {
			t.Fatal("actual caller sent before compatible second consent")
		}
	}
	if result := f.consent(t, 1); result.State != wire.NativePairActive {
		t.Fatal("real compatible second consent did not activate")
	}
	// No SQL writes construct ACTIVE or its old Group key grants.
	current := f.status(t)
	if current.State != wire.NativePairActive {
		t.Fatal("actual activated pair missing")
	}
}

func (f *nativePairTCPConsumerFixture) message(t *testing.T, index int, kind, requestID string) (string, string) {
	t.Helper()
	t.Setenv("CODEX_THREAD_ID", f.native[index])
	args := map[string]any{"body": "SYNTHETIC_NATIVE_PAIR_" + kind + " /resume 'quoted' `literal`\nsecond line", "idempotency_key": "synthetic-tcp-consumer-" + kind}
	if kind == "ASK" {
		args["question"] = args["body"]
		delete(args, "body")
		args["target"] = f.joins[1-index].Endpoint.ID
	} else {
		args["request_id"] = requestID
	}
	tool := "cicada_ask"
	if kind == "REPLY" {
		tool = "cicada_reply"
	}
	result, err := f.mcp[index].callTool(tool, args)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var public struct {
		MessageID string `json:"message_id"`
		RequestID string `json:"request_id"`
		Delivery  string `json:"delivery"`
		Status    string `json:"status"`
		Error     string `json:"error"`
	}
	if json.Unmarshal(raw, &public) != nil || public.MessageID == "" || public.RequestID == "" || public.Delivery != "RELAY_PERSISTED" {
		t.Fatalf("actual MCP did not report bounded sealed Relay acceptance: status=%s error=%s", public.Status, public.Error)
	}
	return public.MessageID, public.RequestID
}

func (f *nativePairTCPConsumerFixture) acceptOne(t *testing.T, inbox *nodeinbox.Inbox, journal *machineRelayJournal) (fabric.NodeSealedDelivery, nodeinbox.Claim, machineRelayJournalEntry) {
	t.Helper()
	body, _ := json.Marshal(fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(f.nodeID), Limit: 1})
	raw := f.http(t, http.MethodPost, "/v2/relay/nodes/"+f.nodeID+"/group/sealed/claim", "CicadaNode "+f.token, "", body, http.StatusOK)
	var result struct {
		Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Deliveries) != 1 {
		t.Fatal("actual Relay did not claim exactly one original message")
	}
	delivery := result.Deliveries[0]
	if err := acceptMachineCrossNodeGroupDelivery(f.ctx, f.server.URL, f.nodeID, f.nodeRoot, inbox, journal, delivery); err != nil {
		t.Fatal(err)
	}
	claim, err := inbox.Claim(f.ctx, machineRelayConsumerID(f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	entry := journal.entry(delivery.MessageID)
	if claim == nil || entry == nil {
		t.Fatal("actual inbound journal/claim absent")
	}
	return delivery, *claim, *entry
}

func (f *nativePairTCPConsumerFixture) inbox(t *testing.T) (*nodeinbox.Inbox, *machineRelayJournal) {
	t.Helper()
	inbox, err := nodeinbox.Open(machineNodeInboxPath(f.nodeRoot, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inbox.Close() })
	journal, err := openMachineRelayJournal(f.nodeRoot, f.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	return inbox, journal
}

func (f *nativePairTCPConsumerFixture) queue(t *testing.T, index int) (context.Context, nativeDeliveryProcessFixture) {
	t.Helper()
	hub, _ := machineHubFrom(f.ctx)
	stem := filepath.Join(f.root, "synthetic-queue-"+string(rune('a'+index)))
	process := nativeDeliveryProcessFixture{Root: f.nodeRoot, HubID: f.hub.HubID, NodeID: f.nodeID, Origin: f.server.URL, Token: f.token, WriterScope: hub.WriterScope, NativeID: f.native[index], ConfigPath: stem + ".json", CounterPath: stem + ".count", ArgsPath: stem + ".argv.json", WitnessPath: stem + ".witness"}
	nativeDeliverySaveConfig(t, process)
	return context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(process.ConfigPath)}), process
}

func TestNativePairConsumerRealTCPRecoveryDualConsentAndRelay(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	f.admittedPair(t, true)
	inbox, journal := f.inbox(t)
	message, request := f.message(t, 0, "ASK", "")
	delivery, claim, entry := f.acceptOne(t, inbox, journal)
	if delivery.MessageID != message || delivery.Route.RequestID != request {
		t.Fatal("actual ASK changed correlation")
	}
	ctx, process := f.queue(t, 1)
	if err := drainMachineCrossNodeGroupRelayClaim(ctx, f.server.URL, f.nodeID, f.nodeRoot, inbox, journal, claim, entry); err != nil {
		t.Fatal(err)
	}
	stored, err := inbox.Get(f.ctx, message)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, process.CounterPath) != 1 {
		t.Fatal("actual ASK lost exact synthetic queue outcome")
	}
	message, replyRequest := f.message(t, 1, "REPLY", request)
	if replyRequest != request {
		t.Fatal("actual REPLY changed ASK root")
	}
	_, claim, entry = f.acceptOne(t, inbox, journal)
	ctx, process = f.queue(t, 0)
	if err := drainMachineCrossNodeGroupRelayClaim(ctx, f.server.URL, f.nodeID, f.nodeRoot, inbox, journal, claim, entry); err != nil {
		t.Fatal(err)
	}
	stored, err = inbox.Get(f.ctx, message)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, process.CounterPath) != 1 {
		t.Fatal("actual REPLY lost exact synthetic queue outcome")
	}
	t.Log("real Hub PQ Node receipt recovery + actual dual consent + production MCP/IPC/Relay/inbox/writer; two synthetic queue subprocesses; Runtime consumption NOT_RUN")
}

func TestNativePairConsumerRealTCPCurrentAndExistingReservationCannotResendAfterLocalRevoke(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	f.admittedPair(t, false)
	inbox, journal := f.inbox(t)
	message, request := f.message(t, 0, "ASK", "")
	delivery, claim, entry := f.acceptOne(t, inbox, journal)
	peer, err := f.bridge.fetchCrossNodeGroupPeerKey(f.bootstrap.Bootstrap.GroupID, f.joins[0].Endpoint.ID, f.joins[1].Endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Existing local budgets are recovery history. The actual sender caller must
	// still reject independently mutated Current data, before another POST.
	for _, field := range []string{"missing-current", "missing-evidence", "native_session_id", "network_access_epoch", "generation", "attempt_id", "network_membership_revision", "endpoint_network_revision", "lease_owner"} {
		t.Run(field, func(t *testing.T) {
			f.mu.Lock()
			f.carrierEdit = func(fields map[string]json.RawMessage) {
				if field == "missing-current" {
					delete(fields, "native_pair_current")
					return
				}
				if field == "missing-evidence" {
					delete(fields, "native_pair_evidence")
					return
				}
				var current map[string]any
				_ = json.Unmarshal(fields["native_pair_current"], &current)
				receiver := current["receiver"].(map[string]any)
				switch field {
				case "native_session_id", "lease_owner":
					receiver[field] = "synthetic-replacement"
				case "attempt_id":
					receiver[field] = strings.Repeat("f", 32)
				default:
					receiver[field] = receiver[field].(float64) + 1
				}
				fields["native_pair_current"], _ = json.Marshal(current)
			}
			before := f.posts["/v2/relay/nodes/"+f.nodeID+"/group/sealed/ask"]
			f.mu.Unlock()
			bad, err := f.bridge.fetchCrossNodeGroupPeerKey(peer.GroupID, peer.Sender.EndpointID, peer.Receiver.EndpointID)
			if err == nil {
				_, err = f.bridge.sealAndSendCrossNodeGroup(crossNodeGroupRequest{GroupID: peer.GroupID, Body: "SYNTHETIC_NATIVE_PAIR_ASK /resume 'quoted' `literal`\nsecond line"}, bad, message, request, "", "REQUEST", time.Now().UTC().Add(time.Minute))
			}
			f.mu.Lock()
			after := f.posts["/v2/relay/nodes/"+f.nodeID+"/group/sealed/ask"]
			f.carrierEdit = nil
			f.mu.Unlock()
			if err == nil || before != after {
				t.Fatal("actual sender caller admitted changed live Current")
			}
		})
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.nodeRoot, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	trust, err := state.GetNodeOwnerKeyTrustLocal(f.setup.OwnerID, f.owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.RevokeNodeOwnerKeyTrustLocal(trust.OwnerID, trust.KeyID, trust.Version); err != nil {
		t.Fatal(err)
	}
	pairMessage, err := nativePairMessage(delivery.Route.Kind, message, request, "", peer.Sender.EndpointID, peer.Receiver.EndpointID, claim.Payload, delivery.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if existing, err := state.ReserveNativePairMessage(f.ctx, *peer.NativePairEvidence, pairMessage, time.Now().UTC()); !existing || err != nil {
		t.Fatalf("exact reservation history lost after local revoke: %t %v", existing, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	before := f.posts["/v2/relay/nodes/"+f.nodeID+"/group/sealed/ask"]
	f.mu.Unlock()
	_, err = f.bridge.sealAndSendCrossNodeGroup(crossNodeGroupRequest{GroupID: peer.GroupID, Body: string(claim.Payload)}, peer, message, request, "", "REQUEST", time.Now().UTC().Add(time.Minute))
	f.mu.Lock()
	after := f.posts["/v2/relay/nodes/"+f.nodeID+"/group/sealed/ask"]
	f.mu.Unlock()
	if err == nil || before != after {
		t.Fatal("historical reservation revived a revoked local Owner pin")
	}
	ctx, process := f.queue(t, 1)
	if err := drainMachineCrossNodeGroupRelayClaim(ctx, f.server.URL, f.nodeID, f.nodeRoot, inbox, journal, claim, entry); err != nil {
		t.Fatal(err)
	}
	stored, err := inbox.Get(f.ctx, message)
	if err != nil || stored.State != nodeinbox.FAILED || nativeDeliveryCount(t, process.CounterPath) != 0 {
		t.Fatal("actual fresh receiver queued after independent local revoke")
	}
}

func TestNativePairConsumerRealTCPInjectingHistoryCannotBecomeUnexecuted(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	f.admittedPair(t, false)
	inbox, _ := f.inbox(t)
	message, _ := f.message(t, 0, "ASK", "")
	journal, err := openMachineRelayJournal(f.nodeRoot, f.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, _ := f.acceptOne(t, inbox, journal)
	// Prepare another exact local claim before injection. It represents a
	// retained/recovered claim with the same immutable physical writer identity.
	shadow, err := nodeinbox.Open(filepath.Join(f.root, "synthetic-recovered-inbox.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close()
	shadowJournal, err := openMachineRelayJournal(filepath.Join(f.root, "synthetic-recovered-journal"), f.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := acceptMachineCrossNodeGroupDelivery(f.ctx, f.server.URL, f.nodeID, f.nodeRoot, shadow, shadowJournal, delivery); err != nil {
		t.Fatal(err)
	}
	claim, err := shadow.Claim(f.ctx, "synthetic-recovered-consumer")
	if err != nil || claim == nil {
		t.Fatal("exact recovered claim absent", err)
	}
	entry := shadowJournal.entry(message)
	if entry == nil {
		t.Fatal("exact recovered journal absent")
	}
	_, process := f.queue(t, 1)
	process.StopPhase = "queue_wait_succeeded"
	nativeDeliverySaveConfig(t, process)
	if err := inbox.Close(); err != nil {
		t.Fatal(err)
	}
	child := nativeDeliveryStartProcess(t, "n1-adapter", process)
	child.ready(t, "queue_wait_succeeded")
	if nativeDeliveryCount(t, process.CounterPath) != 1 || !reflect.DeepEqual(nativeDeliveryRawOutcomes(t, f.nodeRoot), []nodelock.NativeOutcomeState{nodelock.NativeInjecting}) {
		t.Fatal("real adapter did not reach original INJECTING after synthetic queue acceptance")
	}
	if err := child.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	child.wait(t, true)
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.nodeRoot, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	trust, err := state.GetNodeOwnerKeyTrustLocal(f.setup.OwnerID, f.owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = state.RevokeNodeOwnerKeyTrustLocal(trust.OwnerID, trust.KeyID, trust.Version)
	_ = state.Close()
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := f.queue(t, 1)
	err = drainMachineCrossNodeGroupRelayClaim(ctx, f.server.URL, f.nodeID, f.nodeRoot, shadow, shadowJournal, *claim, *entry)
	var historical *machineNativeHistoricalOutcomeError
	if !errors.As(err, &historical) || historical.Outcome != nodelock.NativeUncertain {
		t.Fatalf("reopened original INJECTING was not preserved as UNCERTAIN: %v", err)
	}
	stored, err := shadow.Get(f.ctx, message)
	if err != nil || stored.State != nodeinbox.NODE_RECEIVED || shadowJournal.entry(message) == nil || nativeDeliveryCount(t, process.CounterPath) != 1 || !reflect.DeepEqual(nativeDeliveryRawOutcomes(t, f.nodeRoot), []nodelock.NativeOutcomeState{nodelock.NativeUncertain}) {
		t.Fatal("current revoke rewrote original injection as unexecuted or queued again")
	}
	t.Log("real A3 caller: accepted synthetic queue then adapter SIGKILL while INJECTING; new writer retains UNCERTAIN, independent Owner revoke cannot emit FAILED/NO_EFFECT or requeue")
}

func TestNativePairConsumerRealTCPFencedGenerationAllowsExplicitNewProbe(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	f.explicitNodeJoinProbe(t, 1)
	if _, err := f.recoverMCP(t, 1); err != nil {
		t.Fatal(err)
	}
	originalB := f.joins[1]
	const wrongSID = "synthetic-tcp-consumer-wrong-c"
	writeCodexSessionRecord(t, os.Getenv("CODEX_HOME"), wrongSID, f.workspace)
	if err := verifyCodexSessionRecord(wrongSID, f.workspace); err != nil {
		t.Fatal(err)
	}
	join := wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision, PairID: f.bootstrap.Bootstrap.PairID, Slot: "A", ExpectedGeneration: f.description.SlotAGeneration, BootstrapProofDigest: wire.NativePairProofDigest(f.description.BootstrapOwnerProof), Runtime: "codex", NativeSessionID: wrongSID, Workspace: f.workspace}
	if err := f.client.call(f.ctx, f.token, wire.OperationNativePairNodeJoin, join, nil); err != nil {
		t.Fatal(err)
	}
	wrong, err := f.client.retainedNativePairJoin(localNativePairJoinRequest{PairID: join.PairID, Slot: join.Slot, NativeSessionID: wrongSID, Workspace: f.workspace})
	if err != nil || wrong == nil {
		t.Fatal("wrong synthetic SID did not occupy reserved g1", err)
	}
	if _, _, err := f.bridge.completeNativePairJoin(localNativePairJoinRequest{PairID: join.PairID, Slot: "A", Harness: "codex", NativeSessionID: wrongSID, Workspace: f.workspace}, wrong); err != nil {
		t.Fatal(err)
	}
	join.NativeSessionID = f.native[0]
	if err := f.client.call(f.ctx, f.token, wire.OperationNativePairNodeJoin, join, nil); !errors.Is(err, errNativePairNodeRejected) {
		t.Fatalf("original A did not receive exact g1 no-effect fence: %v", err)
	}
	var old machineNativePairReceipt
	var oldID string
	f.client.mu.Lock()
	for id, record := range f.client.state.NativePairReceipts {
		if record.Operation == wire.OperationNativePairNodeJoin && record.Fenced {
			old = cloneMachineNativePairReceipt(record)
			oldID = id
		}
	}
	f.client.mu.Unlock()
	if oldID == "" {
		t.Fatal("actual g1 fence not journaled")
	}
	f.mu.Lock()
	before := len(f.nodePackets[wire.OperationNativePairNodeDescribe]) + len(f.nodePackets[wire.OperationNativePairNodeJoin])
	f.mu.Unlock()
	machineNodeControlClients.Delete(f.client.statePath)
	if _, err := f.recoverMCP(t, 0); err == nil || !strings.Contains(err.Error(), "authenticated terminal refusal") {
		t.Fatalf("first g1 fence was not reported to actual MCP: %v", err)
	}
	f.mu.Lock()
	after := len(f.nodePackets[wire.OperationNativePairNodeDescribe]) + len(f.nodePackets[wire.OperationNativePairNodeJoin])
	f.mu.Unlock()
	if before != after {
		t.Fatal("reporting the original fence sent a fresh intent")
	}
	f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	f.client.mu.Lock()
	consumed := f.client.state.NativePairReceipts[oldID].Consumed
	f.client.mu.Unlock()
	if !consumed {
		t.Fatal("actual first fence report was not durable")
	}
	status := f.status(t)
	if status.SlotA == nil || status.SlotB == nil || status.SlotA.NativeSessionID != wrongSID || status.SlotB.NativeSessionID != f.native[1] {
		t.Fatal("actual g1 occupied slots changed")
	}
	digest, err := wire.NativePairSlotDigest(*status.SlotA)
	if err != nil {
		t.Fatal(err)
	}
	c, claims := f.claims(t, e2ee.OwnerNativePairSlotReject)
	claims.Reject = &e2ee.NativePairRejectClaims{PairID: status.PairID, ExpectedRevision: status.ControlRevision, Slot: "A", SlotGeneration: status.SlotA.Generation, SlotAttemptID: status.SlotA.AttemptID, SlotDigest: digest}
	proof, err := e2ee.SignOwnerNativePair(f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	var rejected wire.NativePairResult
	f.app(t, wire.NativePairSlotReject{Format: wire.NativePairFormat, Context: c, SessionToken: f.session.Token, OwnerProof: proof}, &rejected)
	if rejected.State != wire.NativePairWaitingJoin || rejected.SlotA != nil || rejected.SlotB == nil || rejected.SlotB.NativeSessionID != f.native[1] {
		t.Fatal("Owner rejection did not reserve a fresh A generation while retaining B")
	}
	// The next explicit MCP invocation must advance beyond the reported fence,
	// but actual capability=false still prevents fresh public discovery.
	if _, err := f.recoverMCP(t, 0); err == nil || !strings.Contains(err.Error(), "service is unavailable") {
		t.Fatalf("next explicit invocation stayed on old fence or bypassed unavailable discovery: %v", err)
	}
	f.explicitNodeJoinProbe(t, 0)
	if f.description.SlotAGeneration != 2 || f.description.SlotBGeneration != 1 {
		t.Fatal("fresh authenticated Describe did not see Owner's actual generations")
	}
	if _, err := f.recoverMCP(t, 0); err != nil {
		t.Fatal(err)
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.nodeRoot, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	key, err := state.NativePairOriginalLocalKey(f.ctx, f.joins[0].Endpoint.ID)
	_ = state.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.recoverMCP(t, 0); err != nil {
		t.Fatal(err)
	}
	state, err = nodekeys.OpenCryptoState(machineNodeStateDir(f.nodeRoot, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	keyAgain, err := state.NativePairOriginalLocalKey(f.ctx, f.joins[0].Endpoint.ID)
	_ = state.Close()
	if err != nil || !sameMCPKeyPublic(key, keyAgain) {
		t.Fatal("g2 original key changed during MCP recovery", err)
	}
	late, err := f.client.postPacket(f.ctx, f.token, old.RequestPacket)
	if err != nil || !bytes.Equal(late, old.ResponsePacket) {
		t.Fatal("late g1 original lost permanent no-effect fence", err)
	}
	current := f.status(t)
	if current.SlotA == nil || current.SlotB == nil || current.SlotA.NativeSessionID != f.native[0] || current.SlotA.Generation != 2 || current.SlotB.NativeSessionID != f.native[1] || current.SlotB.BindingID != originalB.BindingID || current.SlotB.BindingEpoch != originalB.BindingEpoch {
		t.Fatal("fresh explicit g2 intent changed original A/B identities")
	}
	endpoints, err := f.db.ListEndpointsV2(store.EndpointV2Filter{GroupID: f.bootstrap.Bootstrap.GroupID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, endpoint := range endpoints {
		if endpoint.NativeSessionID == f.native[0] {
			count++
			if endpoint.ID != f.joins[0].Endpoint.ID {
				t.Fatal("old late request replaced original A Endpoint")
			}
		}
	}
	if count != 1 {
		t.Fatalf("actual original A Endpoint count=%d", count)
	}
	f.client.mu.Lock()
	retained := cloneMachineNativePairReceipt(f.client.state.NativePairReceipts[oldID])
	f.client.mu.Unlock()
	if !retained.Fenced || !retained.Consumed || !bytes.Equal(retained.RequestPacket, old.RequestPacket) || !bytes.Equal(retained.ResponsePacket, old.ResponsePacket) {
		t.Fatal("fresh g2 intent discarded g1 history")
	}
	t.Log("actual PQ dev probe: C occupied g1, original A was fenced, Owner rejected C, explicit same-A g2 probe succeeded; B/key/old fence retained; fresh public MCP discovery remains unavailable")
}

func TestNativePairConsumerRealTCPRefreshesCurrentAfterWriterWait(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	f.admittedPair(t, false)
	inbox, journal := f.inbox(t)
	message, _ := f.message(t, 0, "ASK", "")
	_, claim, entry := f.acceptOne(t, inbox, journal)
	_, process := f.queue(t, 1)
	changed := false
	ctx := context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(process.ConfigPath), observe: func(phase string) {
		if phase != "writer_wait" {
			return
		}
		changed = true
		f.mu.Lock()
		f.carrierEdit = func(fields map[string]json.RawMessage) {
			var current wire.NativePairPeerCurrent
			if json.Unmarshal(fields["native_pair_current"], &current) != nil {
				t.Error("actual final Current missing")
				return
			}
			current.Receiver.NetworkAccessEpoch++
			fields["native_pair_current"], _ = json.Marshal(current)
		}
		f.mu.Unlock()
	}})
	if err := drainMachineCrossNodeGroupRelayClaim(ctx, f.server.URL, f.nodeID, f.nodeRoot, inbox, journal, claim, entry); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.carrierEdit = nil
	f.mu.Unlock()
	stored, err := inbox.Get(f.ctx, message)
	if !changed || err != nil || stored.State != nodeinbox.FAILED || nativeDeliveryCount(t, process.CounterPath) != 0 || len(nativeDeliveryRawOutcomes(t, f.nodeRoot)) != 0 {
		t.Fatal("receiver reused initial Current after writer wait or persisted an injection intent")
	}
	t.Log("actual initial Current verified, physical-writer preparation fetched changed access epoch and denied before synthetic queue/injection intent")
}
