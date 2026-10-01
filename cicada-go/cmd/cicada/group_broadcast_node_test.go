package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestGroupBroadcastFanoutUsesLocalAndRemoteRoutesAndStableChildIDs(t *testing.T) {
	request, snapshot, card := validGroupBroadcastFixture(t, 3)
	snapshot.Recipients[0].NodeID = "node-local"
	snapshot.Recipients[1].NodeID = "node-local"
	snapshot.Recipients[2].NodeID = "node-remote"
	setBroadcastTestSnapshotDigest(t, snapshot)
	var localCalls, remoteCalls int
	delivered := make(map[string]struct{})
	send := func(target *int) func(store.SameGroupBroadcastV2Endpoint, string) (string, error) {
		return func(recipient store.SameGroupBroadcastV2Endpoint, operationID string) (string, error) {
			*target = *target + 1
			messageID, _, err := localSealedRPCIDs(operationID)
			if err != nil {
				return "", err
			}
			delivered[messageID] = struct{}{}
			return messageID, nil
		}
	}
	localSend, remoteSend := send(&localCalls), send(&remoteCalls)
	for attempt := 0; attempt < 2; attempt++ {
		result, err := fanoutGroupBroadcastBatch(request, snapshot, "node-local", localSend, remoteSend)
		if err != nil {
			t.Fatalf("broadcast retry %d failed: %v", attempt, err)
		}
		if !result.Complete || result.NextOffset != 3 || len(result.Recipients) != 3 {
			t.Fatalf("three-recipient batch progress = %+v", result)
		}
		for _, recipient := range result.Recipients {
			if recipient.State != "ACCEPTED" || recipient.MessageID == "" {
				t.Fatalf("recipient was not durably accepted: %+v", recipient)
			}
		}
	}
	if localCalls != 4 || remoteCalls != 2 || len(delivered) != 3 {
		t.Fatalf("route/dedup counts local=%d remote=%d effective=%d, want 4/2/3", localCalls, remoteCalls, len(delivered))
	}
	if err := validateGroupBroadcastSnapshot(snapshot, request, card, "node-local"); err != nil {
		t.Fatalf("valid same-Group snapshot rejected: %v", err)
	}
}

func TestGroupBroadcastFanoutCapsEachBatchAtEightAndResumesByOffset(t *testing.T) {
	request, snapshot, _ := validGroupBroadcastFixture(t, 10)
	send := func(recipient store.SameGroupBroadcastV2Endpoint, operationID string) (string, error) {
		messageID, _, err := localSealedRPCIDs(operationID)
		return messageID, err
	}
	first, err := fanoutGroupBroadcastBatch(request, snapshot, "node-local", send, send)
	if err != nil {
		t.Fatal(err)
	}
	if first.Offset != 0 || first.NextOffset != groupBroadcastBatchSize || first.Complete ||
		len(first.Recipients) != groupBroadcastBatchSize {
		t.Fatalf("first batch exceeded or missed its bound: %+v", first)
	}
	request.Offset = first.NextOffset
	second, err := fanoutGroupBroadcastBatch(request, snapshot, "node-local", send, send)
	if err != nil {
		t.Fatal(err)
	}
	if second.Offset != 8 || second.NextOffset != 10 || !second.Complete || len(second.Recipients) != 2 {
		t.Fatalf("resumed batch progress = %+v", second)
	}
	request.Offset = 11
	if _, err := fanoutGroupBroadcastBatch(request, snapshot, "node-local", send, send); err == nil {
		t.Fatal("out-of-range snapshot offset was accepted")
	}
}

func TestGroupBroadcastRejectsSpoofedSourceAndCrossGroupRecipient(t *testing.T) {
	request, snapshot, card := validGroupBroadcastFixture(t, 2)
	tests := []struct {
		name   string
		mutate func(*groupBroadcastRequest, *store.SameGroupBroadcastV2Snapshot)
	}{
		{name: "spoofed native session", mutate: func(_ *groupBroadcastRequest, snapshot *store.SameGroupBroadcastV2Snapshot) {
			snapshot.Source.NativeSessionID = "other-thread"
		}},
		{name: "spoofed principal", mutate: func(_ *groupBroadcastRequest, snapshot *store.SameGroupBroadcastV2Snapshot) {
			snapshot.Source.PrincipalID = "other-principal"
		}},
		{name: "cross-Group recipient", mutate: func(_ *groupBroadcastRequest, snapshot *store.SameGroupBroadcastV2Snapshot) {
			snapshot.Recipients[0].GroupID = "group-other"
		}},
		{name: "cross-owner recipient", mutate: func(_ *groupBroadcastRequest, snapshot *store.SameGroupBroadcastV2Snapshot) {
			snapshot.Recipients[0].OwnerID = "owner-other"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestCopy, snapshotCopy := request, cloneGroupBroadcastSnapshot(t, snapshot)
			test.mutate(&requestCopy, snapshotCopy)
			if err := validateGroupBroadcastSnapshot(snapshotCopy, requestCopy, card, "node-local"); err == nil {
				t.Fatal("spoofed or cross-Group snapshot was accepted")
			}
		})
	}
}

func TestGroupBroadcastSnapshotRecipientLimitIsEnforced(t *testing.T) {
	request, snapshot, card := validGroupBroadcastFixture(t, 1)
	base := snapshot.Recipients[0]
	for index := 1; index <= groupBroadcastMaxRecipients; index++ {
		recipient := base
		recipient.EndpointID = fmt.Sprintf("ep-over-cap-%03d", index)
		recipient.KeyID = snapshot.Source.KeyID
		recipient.PublicKey = snapshot.Source.PublicKey
		snapshot.Recipients = append(snapshot.Recipients, recipient)
	}
	if err := validateGroupBroadcastSnapshot(snapshot, request, card, "node-local"); err == nil {
		t.Fatal("snapshot over the fixed recipient cap was accepted")
	}
	request.Offset = 0
	if _, err := fanoutGroupBroadcastBatch(request, snapshot, "node-local",
		func(store.SameGroupBroadcastV2Endpoint, string) (string, error) { return "", nil },
		func(store.SameGroupBroadcastV2Endpoint, string) (string, error) { return "", nil }); err == nil {
		t.Fatal("fanout bypassed the immutable snapshot recipient cap")
	}
}

func TestGroupBroadcastChildOperationIDIsScopedToBroadcastAndEndpoint(t *testing.T) {
	first := groupBroadcastChildOperationID("bc_aaaa", "ep_a")
	if first != groupBroadcastChildOperationID("bc_aaaa", "ep_a") {
		t.Fatal("same child identity changed across retries")
	}
	if first == groupBroadcastChildOperationID("bc_bbbb", "ep_a") ||
		first == groupBroadcastChildOperationID("bc_aaaa", "ep_b") {
		t.Fatal("child operation identity is not scoped to broadcast and recipient")
	}
	if _, _, err := localSealedRPCIDs(first); err != nil {
		t.Fatalf("child operation is not accepted by existing sealed SEND path: %v", err)
	}
}

func validGroupBroadcastFixture(t *testing.T, recipientCount int) (groupBroadcastRequest,
	*store.SameGroupBroadcastV2Snapshot, fabric.NetworkCard) {
	t.Helper()
	owner := "owner-broadcast-test"
	group := "group-broadcast-test"
	request := groupBroadcastRequest{
		Version: groupBroadcastProtocolVersion, Operation: "group_broadcast", Harness: "codex",
		NativeSessionID: "native-source", NodeID: "node-local", Workspace: "/work",
		SessionToken: "trusted-session-token", EndpointID: "ep-source", PrincipalID: "principal-source",
		OwnerID: owner, GroupID: group, BindingID: "binding-source", BindingEpoch: 1,
		OperationID: "op_0123456789abcdef0123456789abcdef",
		BroadcastID: "bc_0123456789abcdef0123456789abcdef", Body: "sealed later", Offset: 0,
	}
	card := fabric.NetworkCard{
		EndpointID: request.EndpointID, PrincipalID: request.PrincipalID, GroupID: group,
		NodeID: request.NodeID, Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		Workspace: request.Workspace, BindingID: request.BindingID, BindingEpoch: request.BindingEpoch,
	}
	sourceKey := newBroadcastTestPublicIdentity(t)
	snapshot := &store.SameGroupBroadcastV2Snapshot{
		BroadcastID: request.BroadcastID, GroupID: group, GroupRevision: 3,
		CapturedAt: "2026-09-24T12:00:00Z",
		Source: store.SameGroupBroadcastV2Endpoint{
			EndpointID: request.EndpointID, PrincipalID: request.PrincipalID,
			OwnerID: owner, NodeID: request.NodeID, GroupID: group, GroupRevision: 3,
			MembershipRevision: 1, GroupJoinRevision: 1, BindingID: request.BindingID,
			BindingEpoch: 1, BindingVersion: 1, KeyID: sourceKey.ID, KeyVersion: 1,
			KeyProofDigest: strings.Repeat("a", 64), PublicKey: sourceKey,
			NativeSessionID: request.NativeSessionID,
		},
		Recipients: make([]store.SameGroupBroadcastV2Endpoint, 0, recipientCount),
	}
	for index := 0; index < recipientCount; index++ {
		endpointID := fmt.Sprintf("ep-recipient-%03d", index)
		key := newBroadcastTestPublicIdentity(t)
		snapshot.Recipients = append(snapshot.Recipients, store.SameGroupBroadcastV2Endpoint{
			EndpointID: endpointID, PrincipalID: "principal-" + endpointID,
			OwnerID: owner, NodeID: "node-local", GroupID: group, GroupRevision: 3,
			MembershipRevision: 1, GroupJoinRevision: 1,
			BindingID: "binding-" + endpointID, BindingEpoch: 1, BindingVersion: 1,
			KeyID: key.ID, KeyVersion: 1, KeyProofDigest: strings.Repeat("b", 64), PublicKey: key,
		})
	}
	digest, err := groupBroadcastSnapshotDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.SnapshotDigest = digest
	return request, snapshot, card
}

func setBroadcastTestSnapshotDigest(t *testing.T, snapshot *store.SameGroupBroadcastV2Snapshot) {
	t.Helper()
	digest, err := groupBroadcastSnapshotDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.SnapshotDigest = digest
}

func newBroadcastTestPublicIdentity(t *testing.T) e2ee.PublicIdentity {
	t.Helper()
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return identity.Public()
}

func cloneGroupBroadcastSnapshot(t *testing.T, source *store.SameGroupBroadcastV2Snapshot) *store.SameGroupBroadcastV2Snapshot {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var copy store.SameGroupBroadcastV2Snapshot
	if err := json.Unmarshal(encoded, &copy); err != nil {
		t.Fatal(err)
	}
	return &copy
}

func TestGroupBroadcastSnapshotDigestDetectsMutation(t *testing.T) {
	request, snapshot, card := validGroupBroadcastFixture(t, 1)
	snapshot.Recipients[0].BindingEpoch++
	if err := validateGroupBroadcastSnapshot(snapshot, request, card, "node-local"); err == nil {
		t.Fatal("mutated snapshot retained validity under its old digest")
	}
}

func TestGroupBroadcastSnapshotDigestUsesSHA256Hex(t *testing.T) {
	_, snapshot, _ := validGroupBroadcastFixture(t, 1)
	digest, err := groupBroadcastSnapshotDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	copy := *snapshot
	copy.SnapshotDigest = ""
	encoded, err := json.Marshal(copy)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatal("snapshot digest is not canonical SHA-256 JSON digest")
	}
}

func TestMCPBroadcastLocalAndRemoteSealedFullChain(t *testing.T) {
	f := newLocalGroupFailureFixture(t)
	const remoteNodeID = "node_local_broadcast_remote"
	const remoteNativeID = "native_local_broadcast_remote"
	const body = "private group broadcast body"

	remoteToken, remoteDigest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	codeDigest := sha256.Sum256([]byte("broadcast-device-code-" + remoteNodeID))
	if _, err := f.store.CreatePendingNodeDeviceBinding(remoteNodeID, remoteNodeID, remoteDigest,
		hex.EncodeToString(codeDigest[:]), time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ConfirmPendingNodeDeviceBinding(f.ownerID,
		"client_"+f.nodeID, hex.EncodeToString(codeDigest[:])); err != nil {
		t.Fatalf("owner could not authorize the second Node: %v", err)
	}
	service, err := fabric.NewService(f.store, f.ownerID, f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	hubHandler := serverpkg.NewFabricHandler(service, "")
	var requestsMu sync.Mutex
	var paths []string
	var hubSawPlaintext bool
	hub := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestBody, readErr := io.ReadAll(io.LimitReader(request.Body, 2*1024*1024+1))
		if readErr != nil {
			t.Errorf("read Hub request body: %v", readErr)
			http.Error(response, "invalid body", http.StatusBadRequest)
			return
		}
		_ = request.Body.Close()
		requestsMu.Lock()
		paths = append(paths, request.URL.Path)
		if bytes.Contains(requestBody, []byte(body)) {
			hubSawPlaintext = true
		}
		requestsMu.Unlock()
		request.Body = io.NopCloser(bytes.NewReader(requestBody))
		hubHandler.ServeHTTP(response, request)
	}))
	defer hub.Close()
	hubID, err := f.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_HUB_ID", hubID)
	if err := f.bridge.Close(); err != nil {
		t.Fatal(err)
	}
	if f.bridgeCancel != nil {
		f.bridgeCancel()
	}
	f.bridgeCtx, f.bridgeCancel = context.WithCancel(f.machineContextForNodeAt(f.nodeID, f.nodeToken, hub.URL))
	f.bridge, err = startMachineAgentJoinBridge(f.bridgeCtx, f.stateDir, hub.URL, f.nodeID, f.nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	remoteBridgeCtx, cancelRemoteBridge := context.WithCancel(f.machineContextForNodeAt(remoteNodeID, remoteToken, hub.URL))
	t.Cleanup(cancelRemoteBridge)
	remoteBridge, err := startMachineAgentJoinBridge(remoteBridgeCtx, f.stateDir,
		hub.URL, remoteNodeID, remoteToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = remoteBridge.Close() })

	codexHome := os.Getenv("CODEX_HOME")
	writeCodexSessionRecord(t, codexHome, remoteNativeID, f.workspace)
	t.Setenv("CICADA_MACHINE_ID", remoteNodeID)
	t.Setenv("CODEX_THREAD_ID", remoteNativeID)
	t.Setenv("CODEX_SESSION_ID", "session-"+remoteNativeID)
	remoteMCP := newMCPServer(hub.URL, "", filepath.Join(t.TempDir(), "mcp", "remote.json"))
	t.Cleanup(func() {
		if remoteMCP.outbox != nil {
			_ = remoteMCP.outbox.close()
		}
		close(remoteMCP.stop)
	})
	joined, err := remoteMCP.callTool("cicada_join", map[string]any{"group_id": f.groupID})
	if err != nil {
		t.Fatalf("remote native Thread did not join: %v", err)
	}
	remoteJoin, ok := joined.(mcpPublicJoinResult)
	if !ok || remoteJoin.Endpoint.ID == "" {
		t.Fatalf("remote join did not return a bound Endpoint: %#v", joined)
	}
	remoteEndpointID := remoteJoin.Endpoint.ID
	f.sourceMCP.sessionMu.RLock()
	sourcePrincipalID := f.sourceMCP.sessionPublic.NetworkCard.PrincipalID
	f.sourceMCP.sessionMu.RUnlock()
	f.targetMCP.sessionMu.RLock()
	targetPrincipalID := f.targetMCP.sessionPublic.NetworkCard.PrincipalID
	f.targetMCP.sessionMu.RUnlock()
	broadcastOwner, broadcastOwnerKey := grantGroupBroadcastSend(t, f.store, f.ownerID, f.groupID,
		sourcePrincipalID, f.sourceMCP.endpointID,
		targetPrincipalID, f.targetMCP.endpointID,
		remoteJoin.NetworkCard.PrincipalID, remoteEndpointID)
	trustBroadcastOwnerKey(t, f.stateDir, f.nodeID, f.ownerID, broadcastOwner, broadcastOwnerKey.KeyID)
	trustBroadcastOwnerKey(t, f.stateDir, remoteNodeID, f.ownerID, broadcastOwner, broadcastOwnerKey.KeyID)

	t.Setenv("CICADA_MACHINE_ID", f.nodeID)
	t.Setenv("CODEX_THREAD_ID", f.nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+f.nativeA)
	resultValue, err := f.sourceMCP.callTool("cicada_broadcast", map[string]any{
		"group_id": f.groupID, "body": body,
	})
	if err != nil {
		t.Fatalf("MCP broadcast did not complete: %v", err)
	}
	result, ok := resultValue.(map[string]any)
	if !ok || result["status"] != mcpOutboxStatusSent || result["complete"] != true || result["recipient_count"] != float64(2) {
		t.Fatalf("broadcast did not report two independently accepted children: %#v", resultValue)
	}
	children, ok := result["recipients"].([]any)
	if !ok || len(children) != 2 {
		t.Fatalf("broadcast omitted per-recipient state: %#v", resultValue)
	}
	messageByEndpoint := make(map[string]string, len(children))
	for _, item := range children {
		child, ok := item.(map[string]any)
		if !ok || child["state"] != "ACCEPTED" {
			t.Fatalf("broadcast child was not durably accepted: %#v", item)
		}
		endpointID, _ := child["endpoint_id"].(string)
		messageID, _ := child["message_id"].(string)
		if endpointID == "" || messageID == "" {
			t.Fatalf("accepted child lacks stable endpoint/message identity: %#v", child)
		}
		messageByEndpoint[endpointID] = messageID
	}
	if messageByEndpoint[f.targetMCP.endpointID] == "" || messageByEndpoint[remoteEndpointID] == "" {
		t.Fatalf("broadcast did not include both local and remote members: %#v", messageByEndpoint)
	}

	localArgs, localCount := installMachineSealedFakeCodex(t, false, f.nodeToken)
	localInbox, err := nodeinbox.Open(machineLocalGroupInboxPath(f.stateDir, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	if err := processPinnedTestMachineLocalGroupDeliveries(context.Background(), f.bridge, localInbox); err != nil {
		t.Fatalf("local sealed broadcast delivery failed: %v", err)
	}
	_ = localInbox.Close()
	if count, err := os.ReadFile(localCount); err != nil || string(count) != "x" {
		t.Fatalf("local broadcast did not wake exactly B's existing session: %q, %v", count, err)
	}
	localQueueArgs, err := os.ReadFile(localArgs)
	if err != nil || !bytes.Contains(localQueueArgs, []byte("queue\n--thread\n"+f.nativeB+"\n--message\n")) {
		t.Fatalf("local delivery targeted a different native Thread: %q, %v", localQueueArgs, err)
	}
	t.Setenv("CICADA_MACHINE_ID", f.nodeID)
	t.Setenv("CODEX_THREAD_ID", f.nativeB)
	t.Setenv("CODEX_SESSION_ID", "session-"+f.nativeB)
	localReceived, err := f.targetMCP.callTool("cicada_receive", map[string]any{"limit": 8})
	if err != nil || !broadcastReceiveMatches(localReceived, messageByEndpoint[f.targetMCP.endpointID], body, f.sourceMCP.endpointID) {
		t.Fatalf("local Thread did not receive the sealed broadcast: result=%#v error=%v", localReceived, err)
	}

	remoteArgs, remoteCount := installMachineSealedFakeCodex(t, false, remoteToken)
	t.Setenv("CICADA_NODE_TOKEN", remoteToken)
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	remoteInbox, err := nodeinbox.Open(machineNodeInboxPath(f.stateDir, remoteNodeID))
	if err != nil {
		t.Fatal(err)
	}
	if err := processPinnedTestMachineFabricDeliveries(context.Background(), hub.URL,
		remoteNodeID, remoteInbox, f.stateDir); err != nil {
		t.Fatalf("remote sealed broadcast delivery failed: %v", err)
	}
	if count, err := os.ReadFile(remoteCount); err != nil || string(count) != "x" {
		t.Fatalf("remote broadcast did not wake its existing native Thread: %q, %v", count, err)
	}
	args, err := os.ReadFile(remoteArgs)
	if err != nil || !bytes.Contains(args, []byte("queue\n--thread\n"+remoteNativeID+"\n--message\n")) {
		t.Fatalf("remote delivery targeted a different native Thread: %q, %v", args, err)
	}
	t.Setenv("CICADA_MACHINE_ID", remoteNodeID)
	t.Setenv("CODEX_THREAD_ID", remoteNativeID)
	t.Setenv("CODEX_SESSION_ID", "session-"+remoteNativeID)
	remoteReceived, err := remoteMCP.callTool("cicada_receive", map[string]any{"limit": 8})
	if err != nil || !broadcastReceiveMatches(remoteReceived, messageByEndpoint[remoteEndpointID], body, f.sourceMCP.endpointID) {
		t.Fatalf("remote Thread did not read its exact inbox copy: result=%#v error=%v", remoteReceived, err)
	}

	requestsMu.Lock()
	defer requestsMu.Unlock()
	if hubSawPlaintext {
		t.Fatal("Hub HTTP observed broadcast plaintext")
	}
	wantSnapshotPath := "/v2/relay/nodes/" + f.nodeID + "/group/broadcast/snapshot"
	wantRemoteSendPath := "/v2/relay/nodes/" + f.nodeID + "/group/sealed/send"
	if !containsString(paths, wantSnapshotPath) || !containsString(paths, wantRemoteSendPath) {
		t.Fatalf("Hub did not observe snapshot plus sealed remote SEND: %v", paths)
	}
}

// Keep the native broadcast's all-local recipient shape covered without a
// paid Runtime. This exercises the production MCP outbox, Node bridge,
// snapshot authorization, and local sealed-send persistence; it does not
// inject into or consume from either recipient's Codex Thread.
func TestMCPBroadcastTwoLocalRecipientsSealedFullChain(t *testing.T) {
	f := newLocalGroupFailureFixture(t)
	const thirdNativeID = "native_local_failure_c"
	const body = "synthetic all-local broadcast body"
	writeCodexSessionRecord(t, os.Getenv("CODEX_HOME"), thirdNativeID, f.workspace)
	thirdMCP := f.joinSession(t, thirdNativeID)

	f.sourceMCP.sessionMu.RLock()
	sourceCard := f.sourceMCP.sessionPublic.NetworkCard
	f.sourceMCP.sessionMu.RUnlock()
	f.targetMCP.sessionMu.RLock()
	targetCard := f.targetMCP.sessionPublic.NetworkCard
	f.targetMCP.sessionMu.RUnlock()
	thirdMCP.sessionMu.RLock()
	thirdCard := thirdMCP.sessionPublic.NetworkCard
	thirdMCP.sessionMu.RUnlock()

	broadcastOwner, broadcastOwnerKey := grantGroupBroadcastSend(t, f.store, f.ownerID, f.groupID,
		sourceCard.PrincipalID, sourceCard.EndpointID,
		targetCard.PrincipalID, targetCard.EndpointID,
		thirdCard.PrincipalID, thirdCard.EndpointID)
	trustBroadcastOwnerKey(t, f.stateDir, f.nodeID, f.ownerID, broadcastOwner, broadcastOwnerKey.KeyID)

	t.Setenv("CICADA_MACHINE_ID", f.nodeID)
	t.Setenv("CODEX_THREAD_ID", f.nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+f.nativeA)
	resultValue, err := f.sourceMCP.callTool("cicada_broadcast", map[string]any{
		"group_id": f.groupID, "body": body,
	})
	if err != nil {
		t.Fatalf("MCP broadcast did not complete: %v", err)
	}
	result, ok := resultValue.(map[string]any)
	if !ok || result["status"] != mcpOutboxStatusSent || result["complete"] != true ||
		result["recipient_count"] != float64(2) {
		t.Fatalf("two-local broadcast did not report accepted delivery state: %#v", resultValue)
	}
	children, ok := result["recipients"].([]any)
	if !ok || len(children) != 2 {
		t.Fatalf("two-local broadcast omitted recipient state: %#v", resultValue)
	}
	states := make(map[string]string, len(children))
	for _, item := range children {
		child, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("invalid recipient result type: %T", item)
		}
		endpointID, _ := child["endpoint_id"].(string)
		state, _ := child["state"].(string)
		failureCode, _ := child["failure_code"].(string)
		if endpointID == "" || state != "ACCEPTED" || failureCode != "" {
			t.Fatalf("local child not durably accepted: state=%q failure_code=%q", state, failureCode)
		}
		states[endpointID] = state
	}
	if len(states) != 2 || states[targetCard.EndpointID] != "ACCEPTED" || states[thirdCard.EndpointID] != "ACCEPTED" {
		t.Fatalf("broadcast did not persist exactly both local recipients: states=%v", states)
	}
}

func grantGroupBroadcastSend(t *testing.T, state *store.Store, ownerID, groupID string,
	principalsAndEndpoints ...string) (*e2ee.Identity, *store.OwnerApprovalKey) {
	t.Helper()
	if len(principalsAndEndpoints) == 0 || len(principalsAndEndpoints)%2 != 0 {
		t.Fatal("broadcast test needs Principal/Endpoint pairs")
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := state.RegisterOwnerApprovalKeyLocal(ownerID, owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < len(principalsAndEndpoints); index += 2 {
		principalID, endpointID := principalsAndEndpoints[index], principalsAndEndpoints[index+1]
		membership, err := state.GetMembershipByPrincipalGroup(principalID, groupID)
		if err != nil {
			t.Fatalf("get broadcast membership %s: %v", endpointID, err)
		}
		grants := make(map[string]struct{}, len(membership.Grants)+3)
		for _, grant := range membership.Grants {
			grants[grant] = struct{}{}
		}
		grants["message.receive"] = struct{}{}
		if index == 0 {
			grants["message.send"] = struct{}{}
			grants["message.broadcast"] = struct{}{}
		}
		grantList := make([]string, 0, len(grants))
		for grant := range grants {
			grantList = append(grantList, grant)
		}
		sort.Strings(grantList)
		membership, err = state.UpdateMembershipAuthorization(membership.ID,
			membership.Roles, grantList, membership.Authorization, membership.Version)
		if err != nil {
			t.Fatalf("authorize broadcast delivery to %s: %v", endpointID, err)
		}
		manifest, err := state.PreviewGroupEndpointKeyGrant(ownerID, groupID, endpointID,
			ownerKey.KeyID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatalf("preview current Endpoint key grant for %s: %v", endpointID, err)
		}
		issuedAt, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := owner.SignOwnerLinkKeyGrant(manifest.OwnerID,
			store.GroupEndpointKeyGrantOperation, manifest.Digest, manifest.CandidateBindingDigest,
			uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.AcceptGroupEndpointKeyGrant(ownerID, groupID,
			endpointID, ownerKey.KeyID, proof); err != nil {
			t.Fatalf("accept current Endpoint key grant for %s: %v", endpointID, err)
		}
	}
	return owner, ownerKey
}

func trustBroadcastOwnerKey(t *testing.T, stateDir, nodeID, ownerID string,
	owner *e2ee.Identity, keyID string) {
	t.Helper()
	crypto, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, nodeID))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(owner.Public())
	if err != nil {
		_ = crypto.Close()
		t.Fatal(err)
	}
	if _, err := crypto.TrustOwnerApprovalKeyLocal(ownerID, keyID, owner.Public(), fingerprint); err != nil {
		_ = crypto.Close()
		t.Fatal(err)
	}
	if err := crypto.Close(); err != nil {
		t.Fatal(err)
	}
}

func broadcastReceiveMatches(value any, messageID, body, senderEndpointID string) bool {
	page, ok := value.(map[string]any)
	if !ok {
		return false
	}
	messages, ok := page["messages"].([]nodeinbox.VisibleMessage)
	if !ok || len(messages) != 1 {
		return false
	}
	message := messages[0]
	return message.MessageID == messageID && message.Body == body &&
		message.Kind == "SEND" && message.RequestID == "" &&
		message.ReplyTo == "" && message.SenderEndpointID == senderEndpointID
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
