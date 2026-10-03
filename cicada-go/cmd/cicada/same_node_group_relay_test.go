package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelocal"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestSameNodeGroupRelayMCPCurrentCallerAndCausalGuards(t *testing.T) {
	f := newLocalGroupFailureFixture(t)
	const nativeC = "native_same_node_relay_c"
	writeCodexSessionRecord(t, os.Getenv("CODEX_HOME"), nativeC, f.workspace)
	third := f.joinSession(t, nativeC)
	authorizeSameNodeRelayFixture(t, f, f.sourceMCP, f.targetMCP, third)
	service, err := fabric.NewService(f.store, f.ownerID, f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	handler := serverpkg.NewFabricHandler(service, "") // Control remains nil.
	var paths []string
	var pathsMu sync.Mutex
	var plaintextSeen bool
	f.hub.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		pathsMu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		if bytes.Contains(body, []byte("private-relay-question")) || bytes.Contains(body, []byte("private-relay-answer")) {
			plaintextSeen = true
		}
		pathsMu.Unlock()
		handler.ServeHTTP(w, r)
	})
	selectSession := func(m *mcpServer) {
		t.Helper()
		native := m.sessionContext
		t.Setenv("CODEX_THREAD_ID", native.NativeSessionID)
		t.Setenv("CODEX_SESSION_ID", "session-"+native.NativeSessionID)
	}
	ask := func(m, target *mcpServer, parent string) map[string]any {
		t.Helper()
		selectSession(m)
		args := map[string]any{"target": target.endpointID, "question": "private-relay-question"}
		if parent != "" {
			args["parent_request_id"] = parent
		}
		v, err := m.callTool("cicada_ask", args)
		if err != nil {
			t.Fatal(err)
		}
		result := v.(map[string]any)
		if result["status"] != mcpOutboxStatusSent || result["delivery"] != "RELAY_PERSISTED" {
			t.Fatalf("Relay ASK not persisted: %#v", result)
		}
		return result
	}
	original := ask(f.sourceMCP, f.targetMCP, "")
	requestID := original["request_id"].(string)
	get := func() *store.FabricRequest {
		t.Helper()
		r, err := f.store.GetSameGroupSealedV1RequestStatus(fabric.HashSessionCredential(f.nodeToken), requestID)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// Parent eligibility requires an actual exact-attempt receipt. Exercise the
	// production Hub claim/authorization/receipt path with a recording queue fake.
	t.Setenv("CICADA_NODE_TOKEN", f.nodeToken)
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	installMachineSealedFakeCodex(t, false, f.nodeToken)
	inbox, err := nodeinbox.Open(machineNodeInboxPath(f.stateDir, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	if err := processPinnedTestMachineFabricDeliveries(f.bridge.ctx, f.hub.URL, f.nodeID, inbox, f.stateDir); err != nil {
		_ = inbox.Close()
		t.Fatal(err)
	}
	_ = inbox.Close()
	cancelPosts := func() int {
		pathsMu.Lock()
		defer pathsMu.Unlock()
		n := 0
		for _, path := range paths {
			if strings.HasPrefix(path, "POST ") && strings.HasSuffix(path, "/cancel") {
				n++
			}
		}
		return n
	}
	originalPosts := cancelPosts()
	cryptoPath := machineNodeStateDir(f.stateDir, f.nodeID) + "/node-crypto-state.sqlite"
	cryptoBefore, err := os.ReadFile(cryptoPath)
	if err != nil {
		t.Fatal(err)
	}
	before := get()
	for _, m := range []*mcpServer{f.targetMCP, third} {
		selectSession(m)
		if _, err := m.callTool("cicada_request_cancel", map[string]any{"request_id": requestID}); err == nil {
			t.Fatal("non-sender cancelled original ASK")
		}
		if !reflect.DeepEqual(before, get()) || cancelPosts() != originalPosts {
			t.Fatal("denied cancel posted or changed request/state/timestamps")
		}
	}
	selectSession(third)
	if _, err := third.callTool("cicada_request_status", map[string]any{"request_id": requestID}); err == nil {
		t.Fatal("third Endpoint read unrelated request")
	}
	for _, m := range []*mcpServer{f.sourceMCP, f.targetMCP} {
		selectSession(m)
		if _, err := m.callTool("cicada_request_status", map[string]any{"request_id": requestID}); err != nil {
			t.Fatal(err)
		}
	}
	// Sharing a Principal is still insufficient: only original Endpoint can cancel.
	forged := third.sessionPublic.NetworkCard
	forged.PrincipalID = before.SenderPrincipalID
	if _, err := f.bridge.crossNodeGroupRequestControl(crossNodeGroupRequest{Operation: "cross_node_group_cancel", RequestID: requestID, GroupID: f.groupID}, forged); err == nil {
		t.Fatal("third same-Principal Endpoint inherited sender authority")
	}
	if !reflect.DeepEqual(before, get()) {
		t.Fatal("same-Principal denied cancel mutated request")
	}
	const samePrincipalNative = "native_same_principal_other_endpoint"
	writeCodexSessionRecord(t, os.Getenv("CODEX_HOME"), samePrincipalNative, f.workspace)
	joined, err := service.Join(fabric.JoinInput{PrincipalID: before.SenderPrincipalID, GroupID: f.groupID, EndpointName: "other same-Principal Endpoint", Harness: "codex", NativeSessionID: samePrincipalNative, NodeID: f.nodeID, Workspace: f.workspace, LeaseOwner: "synthetic-other-endpoint", Capabilities: map[string]any{"local_peer_delivery": "sealed_v1"}})
	if err != nil {
		t.Fatal(err)
	}
	otherBinding, err := f.store.GetActiveSessionBinding(joined.Endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	otherCaller := crossNodeGroupRequest{Version: crossNodeGroupProtocolVersion, Operation: "cross_node_group_cancel", Harness: "codex", NativeSessionID: samePrincipalNative, NodeID: f.nodeID, Workspace: f.workspace, SessionToken: joined.SessionToken, EndpointID: joined.Endpoint.ID, PrincipalID: before.SenderPrincipalID, OwnerID: f.ownerID, GroupID: f.groupID, BindingID: otherBinding.ID, BindingEpoch: otherBinding.Epoch, RequestID: requestID}
	if _, err := f.bridge.crossNodeGroup(otherCaller); err == nil {
		t.Fatal("verified same-Principal third Endpoint cancelled ASK")
	}
	otherCaller.Operation = "cross_node_group_status"
	if _, err := f.bridge.crossNodeGroup(otherCaller); err == nil {
		t.Fatal("verified same-Principal third Endpoint read ASK")
	}
	if !reflect.DeepEqual(before, get()) {
		t.Fatal("same-Principal caller changed original request")
	}
	if cancelPosts() != originalPosts {
		t.Fatal("non-sender cancellation posted before denial")
	}
	cryptoAfter, err := os.ReadFile(cryptoPath)
	if err != nil || !bytes.Equal(cryptoBefore, cryptoAfter) {
		t.Fatal("denied cancellation advanced cryptographic state/nonces")
	}
	old := otherCaller
	old.Operation = "cross_node_group_cancel"
	old.EndpointID = before.SenderEndpointID
	old.BindingID = before.SenderBindingID
	old.BindingEpoch = before.SenderBindingEpoch
	if _, err := f.bridge.crossNodeGroup(old); err == nil {
		t.Fatal("another native session transplanted original sender binding")
	}
	if !reflect.DeepEqual(before, get()) || cancelPosts() != originalPosts {
		t.Fatal("forged caller changed request")
	}
	child := ask(f.targetMCP, third, requestID)
	childStatus, err := f.store.GetSameGroupSealedV1RequestStatus(fabric.HashSessionCredential(f.nodeToken), child["request_id"].(string))
	if err != nil || childStatus.ParentRequestID != requestID {
		t.Fatalf("causal child not retained: %#v %v", childStatus, err)
	}
	selectSession(third)
	childReply, err := third.callTool("cicada_reply", map[string]any{"request_id": child["request_id"], "body": "private-relay-answer"})
	if err != nil || childReply.(map[string]any)["delivery"] != "RELAY_PERSISTED" {
		t.Fatalf("causal child reply failed: %#v %v", childReply, err)
	}
	childFinal, err := f.store.GetSameGroupSealedV1RequestStatus(fabric.HashSessionCredential(f.nodeToken), childStatus.RequestID)
	if err != nil || childFinal.State != store.FabricRequestReplied || childFinal.ParentRequestID != requestID {
		t.Fatalf("child correlation lost: %#v %v", childFinal, err)
	}
	opaque, err := f.store.GetRelaySealedV1(childFinal.ReplyMessageID)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := f.bridge.fetchCrossNodeGroupPeerKey(f.groupID, third.endpointID, f.targetMCP.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := nodekeys.LoadExisting(machineNodeStateDir(f.stateDir, f.nodeID), f.targetMCP.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	expected := crossNodeGroupEndpointContext(peer, peer.Sender, peer.Receiver, childFinal.ReplyMessageID, childFinal.RequestID, childFinal.MessageID, requestID, "REPLY")
	opened, _, err := e2ee.OpenEndpointMessage(recipient, peer.Sender.Candidate.Public, expected, opaque.Ciphertext)
	if err != nil || string(opened) != "private-relay-answer" {
		t.Fatalf("authenticated causal child reply failed to open: %v", err)
	}
	selectSession(f.targetMCP)
	cycleInput := map[string]any{"target": f.sourceMCP.endpointID, "question": "private-relay-question", "parent_request_id": requestID, "idempotency_key": "same-node-permanent-cycle"}
	cycle, err := f.targetMCP.callTool("cicada_ask", cycleInput)
	if err != nil {
		t.Fatal(err)
	}
	cyclePublic, ok := cycle.(map[string]any)
	if !ok || cyclePublic["status"] != mcpOutboxStatusFailed || cyclePublic["retryable"] != false {
		t.Fatalf("cycle did not become permanent FAILED: %#v", cycle)
	}
	cycleOperation := cyclePublic["operation_id"].(string)
	cycleMessage, cycleRequest, err := localSealedRPCIDs(cycleOperation)
	if err != nil {
		t.Fatal(err)
	}
	if record, err := f.store.GetRelayMessage(cycleMessage); record != nil || !errors.Is(err, store.ErrRelayMessageNotFound) {
		t.Fatalf("rejected cycle retained Hub body/ciphertext: %#v %v", record, err)
	}
	if record, err := f.store.GetSameGroupSealedV1RequestStatus(fabric.HashSessionCredential(f.nodeToken), cycleRequest); record != nil || !errors.Is(err, store.ErrSameGroupSealedV1NotFound) {
		t.Fatalf("rejected cycle created a new root: %#v %v", record, err)
	}
	pathsMu.Lock()
	pathCount := len(paths)
	pathsMu.Unlock()
	cryptoCycleBefore, err := os.ReadFile(cryptoPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, invoke := range []func() (any, error){func() (any, error) { return f.targetMCP.callTool("cicada_ask", cycleInput) }, func() (any, error) {
		return f.targetMCP.callTool("cicada_operation_retry", map[string]any{"operation_id": cycleOperation})
	}} {
		v, err := invoke()
		if err != nil {
			t.Fatal(err)
		}
		if result := v.(map[string]any); result["status"] != mcpOutboxStatusFailed || result["operation_id"] != cycleOperation || result["attempts"] != cyclePublic["attempts"] {
			t.Fatalf("permanent reject retried/reallocated operation: %#v", result)
		}
	}
	pathsMu.Lock()
	pathsAfter := len(paths)
	pathsMu.Unlock()
	// Context freshness can issue read-only whoami requests, never another ASK.
	pathsMu.Lock()
	for _, path := range paths[pathCount:] {
		if strings.HasPrefix(path, "POST ") && strings.HasSuffix(path, "/ask") {
			t.Fatal("permanent rejected operation posted another ASK")
		}
	}
	pathsMu.Unlock()
	_ = pathsAfter
	cryptoCycleAfter, err := os.ReadFile(cryptoPath)
	if err != nil || !bytes.Equal(cryptoCycleBefore, cryptoCycleAfter) {
		t.Fatal("permanent retry changed ciphertext/counters")
	}
	selectSession(third)
	deniedReply, err := third.callTool("cicada_reply", map[string]any{"request_id": requestID, "body": "private-relay-answer"})
	if err == nil {
		if result, ok := deniedReply.(map[string]any); !ok || result["status"] != mcpOutboxStatusFailed {
			t.Fatalf("third Endpoint reply was not rejected: %#v", deniedReply)
		}
	}
	if !reflect.DeepEqual(before, get()) {
		t.Fatal("third reply changed original request")
	}

	selectSession(f.targetMCP)
	reply, err := f.targetMCP.callTool("cicada_reply", map[string]any{"request_id": requestID, "body": "private-relay-answer"})
	if err != nil {
		t.Fatal(err)
	}
	if reply.(map[string]any)["delivery"] != "RELAY_PERSISTED" {
		t.Fatalf("reply not Relay: %#v", reply)
	}
	if get().State != store.FabricRequestReplied {
		t.Fatal("Hub did not retain original reply correlation")
	}
	cancelAsk := ask(f.sourceMCP, f.targetMCP, "")
	selectSession(f.sourceMCP)
	if _, err := f.sourceMCP.callTool("cicada_request_cancel", map[string]any{"request_id": cancelAsk["request_id"]}); err != nil {
		t.Fatal(err)
	}
	pathsMu.Lock()
	defer pathsMu.Unlock()
	if plaintextSeen {
		t.Fatal("Hub observed plaintext")
	}
	for _, suffix := range []string{"/group/sealed/ask", "/group/sealed/reply"} {
		found := false
		for _, p := range paths {
			if strings.HasSuffix(p, suffix) {
				found = true
			}
		}
		if !found {
			t.Fatal("missing actual HTTP route", suffix)
		}
	}
	t.Log("synthetic native records and production HTTP/MCP; no native injection or account/direct eligibility proof")
}

func TestSameNodeLegacyReplayOnlyAndNewLocalUnsupported(t *testing.T) {
	f := newLocalGroupFailureFixture(t)
	t.Setenv("CODEX_THREAD_ID", f.nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+f.nativeA)
	request, result := seedLegacyLocalAsk(t, f.bridge, f.sourceMCP, f.targetMCP.endpointID, "private historical question")
	replay, err := f.bridge.localGroup(request)
	if err != nil || replay.MessageID != result.MessageID {
		t.Fatalf("exact historical replay rejected: %#v %v", replay, err)
	}
	path := machineLocalGroupLedgerPath(f.stateDir, f.nodeID)
	bytesBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bad := request
	bad.Body = "changed plaintext"
	if _, err := f.bridge.localGroup(bad); !errors.Is(err, nodelocal.ErrMessageConflict) {
		t.Fatalf("changed body was not rejected: %v", err)
	}
	newer := request
	newer.OperationID = "op_fedcba9876543210fedcba9876543210"
	if _, err := f.bridge.localGroup(newer); err == nil || !strings.Contains(err.Error(), "UNSUPPORTED") {
		t.Fatalf("new direct operation not unsupported: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(bytesBefore, after) {
		t.Fatal("read-only replay/denial changed ledger bytes")
	}
	cross := crossNodeGroupRequest{Operation: "cross_node_group_ask", OperationID: request.OperationID, OperationCreatedAt: request.OperationCreatedAt, IdempotencyKey: request.IdempotencyKey, GroupID: request.GroupID, SessionToken: request.SessionToken, EndpointID: request.EndpointID, PrincipalID: request.PrincipalID, OwnerID: request.OwnerID, BindingID: request.BindingID, BindingEpoch: request.BindingEpoch, NativeSessionID: request.NativeSessionID, NodeID: request.NodeID, Harness: request.Harness, Workspace: request.Workspace, TargetEndpointID: request.Target, Body: request.Body, ParentRequestID: "forged-parent"}
	if _, err := f.bridge.crossNodeGroupSendAsk(cross, f.sourceMCP.sessionPublic.NetworkCard, nil); err == nil {
		t.Fatal("historical local ASK accepted new causal parent")
	}
	// Malformed read-only database is a lookup failure, never NOT_FOUND/Relay.
	fresh := &machineAgentJoinBridge{ctx: context.Background(), stateDir: t.TempDir(), nodeID: "node"}
	if _, err := fresh.replayLegacyLocalGroupMessage(newer, nil); !errors.Is(err, nodelocal.ErrMessageNotFound) {
		t.Fatal(err)
	}
	malformed := machineLocalGroupLedgerPath(fresh.stateDir, fresh.nodeID)
	if err := os.MkdirAll(filepath.Dir(malformed), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malformed, []byte("synthetic corrupt legacy database"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.replayLegacyLocalGroupMessage(newer, nil); err == nil || errors.Is(err, nodelocal.ErrMessageNotFound) {
		t.Fatalf("lookup failure incorrectly treated as NOT_FOUND: %v", err)
	}
	contents, err := os.ReadFile(malformed)
	if err != nil || string(contents) != "synthetic corrupt legacy database" {
		t.Fatal("failed read-only lookup changed database")
	}

}

func authorizeSameNodeRelayFixture(t *testing.T, f *localGroupFailureFixture, sessions ...*mcpServer) {
	t.Helper()
	var pairs []string
	for _, m := range sessions {
		card := m.sessionPublic.NetworkCard
		membership, err := f.store.GetMembershipByPrincipalGroup(card.PrincipalID, f.groupID)
		if err != nil {
			t.Fatal(err)
		}
		grants := append(append([]string(nil), membership.Grants...), "message.ask", "message.reply")
		if _, err := f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles, grants, membership.Authorization, membership.Version); err != nil {
			t.Fatal(err)
		}
		pairs = append(pairs, card.PrincipalID, card.EndpointID)
	}
	owner, key := grantGroupBroadcastSend(t, f.store, f.ownerID, f.groupID, pairs...)
	trustBroadcastOwnerKey(t, f.stateDir, f.nodeID, f.ownerID, owner, key.KeyID)

}
