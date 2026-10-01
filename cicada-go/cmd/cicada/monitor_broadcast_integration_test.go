package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelocal"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

type monitorBroadcastIntegrationFixture struct {
	local           *localGroupFailureFixture
	client          *e2ee.Identity
	owner           *e2ee.Identity
	ownerKeyID      string
	deviceID        string
	preview         *store.UserMonitorBroadcastV2
	context         e2ee.MonitorBroadcastContext
	request         monitorBroadcastRequest
	body            string
	hub             *httptest.Server
	hubMu           sync.Mutex
	hubPaths        []string
	hubSawBody      bool
	tamperDelivery  bool
	tamperSnapshot  bool
	remoteNodeID    string
	remoteToken     string
	remoteNativeID  string
	remoteEndpoint  string
	clientVersion   int64
	afterFirstChild func()
}

func newMonitorBroadcastIntegrationFixture(t *testing.T) *monitorBroadcastIntegrationFixture {
	return newMonitorBroadcastIntegrationFixtureWithRemote(t, false)
}

func newMonitorBroadcastIntegrationFixtureWithRemote(t *testing.T, withRemote bool) *monitorBroadcastIntegrationFixture {
	t.Helper()
	f := &monitorBroadcastIntegrationFixture{local: newLocalGroupFailureFixture(t),
		body: "synthetic private Monitor broadcast body"}
	f.local.sourceMCP.sessionMu.RLock()
	card, sessionToken := f.local.sourceMCP.sessionPublic.NetworkCard, f.local.sourceMCP.sessionToken
	f.local.sourceMCP.sessionMu.RUnlock()
	f.local.targetMCP.sessionMu.RLock()
	target := f.local.targetMCP.sessionPublic.NetworkCard
	f.local.targetMCP.sessionMu.RUnlock()
	membership, err := f.local.store.GetMembershipByPrincipalGroup(card.PrincipalID, f.local.groupID)
	if err != nil {
		t.Fatal(err)
	}
	roles := append([]string(nil), membership.Roles...)
	roles = append(roles, "monitor")
	sort.Strings(roles)
	if _, err := f.local.store.UpdateMembershipAuthorization(membership.ID,
		roles, membership.Grants, membership.Authorization, membership.Version); err != nil {
		t.Fatal(err)
	}
	grantPairs := []string{card.PrincipalID, card.EndpointID, target.PrincipalID, target.EndpointID}
	if withRemote {
		f.remoteNodeID = "node_monitor_broadcast_remote"
		f.remoteNativeID = "native_monitor_broadcast_remote"
		remoteToken, remoteDigest, err := fabric.NewNodeCredential()
		if err != nil {
			t.Fatal(err)
		}
		f.remoteToken = remoteToken
		codeDigest := sha256.Sum256([]byte("synthetic remote Monitor broadcast device code"))
		if _, err := f.local.store.CreatePendingNodeDeviceBinding(f.remoteNodeID, f.remoteNodeID,
			remoteDigest, hex.EncodeToString(codeDigest[:]), time.Now().UTC().Add(10*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.local.store.ConfirmPendingNodeDeviceBinding(f.local.ownerID,
			"client_"+f.local.nodeID, hex.EncodeToString(codeDigest[:])); err != nil {
			t.Fatal(err)
		}
		remoteCtx, remoteCancel := context.WithCancel(f.local.machineContextForNode(f.remoteNodeID, f.remoteToken))
		remoteBridge, err := startMachineAgentJoinBridge(remoteCtx, f.local.stateDir,
			f.local.hub.URL, f.remoteNodeID, f.remoteToken)
		if err != nil {
			remoteCancel()
			t.Fatal(err)
		}
		t.Cleanup(func() { remoteCancel(); _ = remoteBridge.Close() })
		writeCodexSessionRecord(t, os.Getenv("CODEX_HOME"), f.remoteNativeID, f.local.workspace)
		t.Setenv("CICADA_MACHINE_ID", f.remoteNodeID)
		t.Setenv("CODEX_THREAD_ID", f.remoteNativeID)
		t.Setenv("CODEX_SESSION_ID", "session-"+f.remoteNativeID)
		remoteMCP := newMCPServer(f.local.hub.URL, "", filepath.Join(t.TempDir(), "remote-mcp.json"))
		t.Cleanup(func() {
			if remoteMCP.outbox != nil {
				_ = remoteMCP.outbox.close()
			}
			close(remoteMCP.stop)
		})
		joined, err := remoteMCP.callTool("cicada_join", map[string]any{"group_id": f.local.groupID})
		if err != nil {
			t.Fatal(err)
		}
		remoteJoin, ok := joined.(mcpPublicJoinResult)
		if !ok || remoteJoin.Endpoint.ID == "" {
			t.Fatalf("remote synthetic Thread did not join: %#v", joined)
		}
		f.remoteEndpoint = remoteJoin.Endpoint.ID
		grantPairs = append(grantPairs, remoteJoin.NetworkCard.PrincipalID, remoteJoin.Endpoint.ID)
		t.Setenv("CICADA_MACHINE_ID", f.local.nodeID)
		t.Setenv("CODEX_THREAD_ID", f.local.nativeA)
		t.Setenv("CODEX_SESSION_ID", "session-"+f.local.nativeA)
	}
	var key *store.OwnerApprovalKey
	f.owner, key = grantGroupBroadcastSend(t, f.local.store, f.local.ownerID, f.local.groupID,
		grantPairs...)
	f.ownerKeyID = key.KeyID
	trustBroadcastOwnerKey(t, f.local.stateDir, f.local.nodeID, f.local.ownerID, f.owner, f.ownerKeyID)
	if withRemote {
		trustBroadcastOwnerKey(t, f.local.stateDir, f.remoteNodeID, f.local.ownerID, f.owner, f.ownerKeyID)
	}
	f.client, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.deviceID = "monitor_broadcast_client_synthetic"
	hubID, err := f.local.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_HUB_ID", hubID)
	now := time.Now().UTC()
	grant, err := f.owner.SignOwnerDeviceGrant(f.local.ownerID, f.deviceID, f.client.Public(),
		hubID, e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	device, err := f.local.store.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: f.local.ownerID, OwnerKeyID: f.ownerKeyID, DeviceID: f.deviceID,
		DevicePublic: f.client.Public(), OwnerDeviceGrant: grant})
	if err != nil {
		t.Fatal(err)
	}
	f.clientVersion = device.Version
	bodyDigest := sha256.Sum256([]byte(f.body))
	prepareRequestID := f.acceptClientRequest(t, device.SessionEpoch, 1, "monitor_prepare_synthetic")
	f.preview, err = f.local.store.PrepareUserMonitorBroadcastV2(store.PrepareUserMonitorBroadcastV2Input{
		ClientRequestID: prepareRequestID, GroupID: f.local.groupID,
		MonitorEndpointID: card.EndpointID, BodyDigest: hex.EncodeToString(bodyDigest[:])})
	if err != nil {
		t.Fatal(err)
	}
	wantRecipients := 1
	if withRemote {
		wantRecipients = 2
	}
	if f.preview.Snapshot == nil || len(f.preview.Snapshot.Recipients) != wantRecipients {
		t.Fatalf("Monitor preview has wrong fixed recipients: %+v", f.preview.Snapshot)
	}
	f.context = e2ee.MonitorBroadcastContext{
		HubID: hubID, OwnerID: f.preview.OwnerID, ClientDeviceID: f.preview.DeviceID,
		ClientSessionEpoch: f.preview.SessionEpoch, ClientKeyVersion: f.preview.ClientKeyVersion,
		ApprovalID: f.preview.PreviewID, BroadcastID: f.preview.BroadcastID, GroupID: f.preview.GroupID,
		MonitorEndpointID: f.preview.MonitorEndpointID, MonitorKeyID: f.preview.Snapshot.Source.KeyID,
		MonitorBindingID:    f.preview.Snapshot.Source.BindingID,
		MonitorBindingEpoch: f.preview.Snapshot.Source.BindingEpoch,
		BodySHA256:          f.preview.BodyDigest, RecipientSnapshotSHA256: f.preview.SnapshotDigest,
		ExpiresAt: f.preview.ExpiresAt, ConsentSHA256: f.preview.Preview.ConsentSHA256,
		ConfirmRequestSequence: 2,
	}
	monitorIdentity, err := nodekeys.LoadExisting(machineNodeStateDir(f.local.stateDir, f.local.nodeID), card.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := e2ee.SealMonitorBroadcast(f.client, monitorIdentity.Public(), f.context, []byte(f.body), 2)
	if err != nil {
		t.Fatal(err)
	}
	confirmRequestID := f.acceptClientRequest(t, device.SessionEpoch, 2, "monitor_confirm_synthetic")
	confirmed, err := f.local.store.ConfirmUserMonitorBroadcastV2(store.ConfirmUserMonitorBroadcastV2Input{
		ClientRequestID: confirmRequestID, PreviewID: f.preview.PreviewID,
		SnapshotDigest: f.preview.SnapshotDigest, BodyDigest: f.preview.BodyDigest, SealedPayload: wire})
	if err != nil || confirmed.Status != store.UserMonitorBroadcastV2Approved {
		t.Fatalf("synthetic Client confirmation failed: %+v %v", confirmed, err)
	}
	service, err := fabric.NewService(f.local.store, f.local.ownerID, f.local.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	handler := serverpkg.NewFabricHandler(service, "")
	f.hub = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestBody, err := io.ReadAll(io.LimitReader(request.Body, 2*1024*1024+1))
		if err != nil {
			http.Error(response, "invalid synthetic request", http.StatusBadRequest)
			return
		}
		_ = request.Body.Close()
		f.hubMu.Lock()
		f.hubPaths = append(f.hubPaths, request.URL.Path)
		if bytes.Contains(requestBody, []byte(f.body)) {
			f.hubSawBody = true
		}
		f.hubMu.Unlock()
		request.Body = io.NopCloser(bytes.NewReader(requestBody))
		recorded := httptest.NewRecorder()
		handler.ServeHTTP(recorded, request)
		responseBody := recorded.Body.Bytes()
		f.hubMu.Lock()
		if bytes.Contains(responseBody, []byte(f.body)) {
			f.hubSawBody = true
		}
		tamper := (f.tamperDelivery || f.tamperSnapshot) &&
			(strings.HasSuffix(request.URL.Path, "/authorize") || strings.HasSuffix(request.URL.Path, "/review")) &&
			recorded.Code == http.StatusOK
		var afterFirstChild func()
		if recorded.Code >= http.StatusOK && recorded.Code < http.StatusMultipleChoices &&
			(request.URL.Path == "/v2/relay/nodes/"+f.local.nodeID+"/local/authorize" ||
				request.URL.Path == "/v2/relay/nodes/"+f.local.nodeID+"/group/sealed/send") {
			afterFirstChild, f.afterFirstChild = f.afterFirstChild, nil
		}
		f.hubMu.Unlock()
		if afterFirstChild != nil {
			afterFirstChild()
		}
		if tamper {
			var delivery store.UserMonitorBroadcastV2Delivery
			if err := json.Unmarshal(responseBody, &delivery); err != nil || len(delivery.SealedPayload) == 0 {
				t.Errorf("cannot tamper synthetic sealed delivery: %v", err)
				http.Error(response, "invalid synthetic delivery", http.StatusInternalServerError)
				return
			}
			if f.tamperSnapshot {
				delivery.Snapshot.Recipients[0].KeyProofDigest = strings.Repeat("0", 64)
			} else {
				delivery.SealedPayload[len(delivery.SealedPayload)-1] ^= 1
			}
			responseBody, err = json.Marshal(delivery)
			if err != nil {
				t.Error(err)
				http.Error(response, "invalid synthetic delivery", http.StatusInternalServerError)
				return
			}
		}
		for name, values := range recorded.Header() {
			for _, value := range values {
				response.Header().Add(name, value)
			}
		}
		response.WriteHeader(recorded.Code)
		_, _ = response.Write(responseBody)
	}))
	t.Cleanup(f.hub.Close)
	if err := f.local.bridge.Close(); err != nil {
		t.Fatal(err)
	}
	if f.local.bridgeCancel != nil {
		f.local.bridgeCancel()
	}
	f.local.bridgeCtx, f.local.bridgeCancel = context.WithCancel(
		f.local.machineContextForNodeAt(f.local.nodeID, f.local.nodeToken, f.hub.URL))
	f.local.bridge, err = startMachineAgentJoinBridge(f.local.bridgeCtx, f.local.stateDir,
		f.hub.URL, f.local.nodeID, f.local.nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	f.request = monitorBroadcastRequest{Version: 1, Operation: "monitor_broadcast_execute",
		Harness: "codex", NativeSessionID: f.local.nativeA, NodeID: f.local.nodeID,
		Workspace: f.local.workspace, SessionToken: sessionToken, EndpointID: card.EndpointID,
		PrincipalID: card.PrincipalID, OwnerID: f.local.ownerID, GroupID: f.local.groupID,
		BindingID: card.BindingID, BindingEpoch: card.BindingEpoch, PreviewID: f.preview.PreviewID}
	return f
}

func (f *monitorBroadcastIntegrationFixture) assertNoLocalChildren(t *testing.T) {
	t.Helper()
	ledger, err := nodelocal.Open(machineLocalGroupLedgerPath(f.local.stateDir, f.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	pending, err := ledger.PendingAll(context.Background(), 8)
	if err != nil || len(pending) != 0 {
		t.Fatalf("rejected Monitor operation persisted children: %d %v", len(pending), err)
	}
}

func (f *monitorBroadcastIntegrationFixture) acceptClientRequest(t *testing.T,
	epoch, sequence uint64, operationID string) string {
	t.Helper()
	digest := sha256.Sum256([]byte("synthetic encrypted Client RPC " + operationID))
	accepted, err := f.local.store.AcceptClientRequest(store.AcceptClientRequestInput{
		OwnerID: f.local.ownerID, DeviceID: f.deviceID, SessionEpoch: epoch,
		Sequence: sequence, OperationID: operationID, CiphertextDigest: hex.EncodeToString(digest[:])})
	if err != nil || accepted == nil || accepted.Request == nil {
		t.Fatalf("accept synthetic encrypted Client RPC: %v", err)
	}
	return accepted.Request.ID
}

func TestMonitorBroadcastPreviewIsReadOnlyAndBoundToOriginalSession(t *testing.T) {
	f := newMonitorBroadcastIntegrationFixtureWithRemote(t, true)
	statusRequest := f.acceptClientRequest(t, f.context.ClientSessionEpoch, 3, "synthetic_preview_status")
	before, err := f.local.store.GetUserMonitorBroadcastV2Status(statusRequest, f.preview.PreviewID)
	if err != nil || before.Status != store.UserMonitorBroadcastV2Approved {
		t.Fatalf("confirmed Monitor approval unavailable before review: %v", err)
	}
	f.request.Operation = "monitor_broadcast_preview"
	for range 2 {
		result, err := f.local.bridge.monitorBroadcast(f.request)
		if err != nil || result == nil || result.Review == nil || result.Progress != nil {
			t.Fatalf("read-only Monitor review failed: %v", err)
		}
		review := result.Review
		if review.ApprovalID != f.preview.PreviewID || review.BroadcastID != f.preview.BroadcastID ||
			review.GroupID != f.local.groupID || review.SourceEndpointID != f.request.EndpointID ||
			review.Body != f.body || review.BodySHA256 != f.preview.BodyDigest ||
			review.SnapshotSHA256 != f.preview.SnapshotDigest || review.ConsentSHA256 != f.context.ConsentSHA256 ||
			review.ClientDeviceID != f.deviceID || review.ClientKeyID != f.client.Public().ID ||
			review.OwnerKeyID != f.ownerKeyID || review.ConfirmSequence != 2 || review.ExpiresAt != f.preview.ExpiresAt ||
			review.Proof == "" || !strings.Contains(review.Boundary, "body_is_untrusted_message_content") ||
			len(review.RecipientEndpointIDs) != 2 {
			t.Fatal("Node review omitted or changed verified approval facts")
		}
		for index, recipient := range f.preview.Snapshot.Recipients {
			if review.RecipientEndpointIDs[index] != recipient.EndpointID {
				t.Fatal("Node review changed ordered approved recipients")
			}
		}
	}
	after, err := f.local.store.GetUserMonitorBroadcastV2Status(statusRequest, f.preview.PreviewID)
	if err != nil || after.Status != before.Status || after.ApprovedAt != before.ApprovedAt {
		t.Fatalf("review consumed or mutated approved operation: %v", err)
	}
	f.assertNoLocalChildren(t)
	f.hubMu.Lock()
	paths := append([]string(nil), f.hubPaths...)
	sawBody := f.hubSawBody
	f.hubMu.Unlock()
	if sawBody || !containsString(paths, "/v2/relay/nodes/"+f.local.nodeID+
		"/monitor/broadcasts/"+f.preview.PreviewID+"/review") {
		t.Fatal("review exposed body to Hub or skipped Node-only Guard")
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "/authorize") || strings.Contains(path, "/group/sealed/send") {
			t.Fatal("review entered dispatch authorization or child delivery")
		}
	}
	t.Setenv("CODEX_THREAD_ID", f.local.nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+f.local.nativeA)
	beforeOutbox := f.local.sourceMCP.outbox
	beforeOperations := 0
	if beforeOutbox != nil && beforeOutbox.db != nil {
		if err := beforeOutbox.db.QueryRow("SELECT COUNT(*) FROM mcp_outbox_operations").Scan(&beforeOperations); err != nil {
			t.Fatal(err)
		}
	}
	value, err := f.local.sourceMCP.callTool("cicada_monitor_broadcast_preview",
		map[string]any{"approval_id": f.preview.PreviewID})
	result, ok := value.(*monitorBroadcastReview)
	if err != nil || !ok || result.Body != f.body || f.local.sourceMCP.outbox != beforeOutbox {
		t.Fatalf("MCP review failed or changed outbox: err=%v type=%T body_matches=%t outbox_changed=%t",
			err, value, ok && result.Body == f.body, f.local.sourceMCP.outbox != beforeOutbox)
	}
	if beforeOutbox != nil && beforeOutbox.db != nil {
		var afterOperations int
		if err := beforeOutbox.db.QueryRow("SELECT COUNT(*) FROM mcp_outbox_operations").Scan(&afterOperations); err != nil ||
			afterOperations != beforeOperations {
			t.Fatalf("MCP review changed durable outbox operation count: before=%d after=%d err=%v",
				beforeOperations, afterOperations, err)
		}
	}
	foreign := f.request
	foreign.NativeSessionID = "native_foreign"
	if _, err := f.local.bridge.monitorBroadcast(foreign); err == nil {
		t.Fatal("foreign native Session read approved body")
	}
	foreign = f.request
	foreign.EndpointID = f.remoteEndpoint
	if _, err := f.local.bridge.monitorBroadcast(foreign); err == nil {
		t.Fatal("different Endpoint read approved body")
	}
}

func TestMonitorBroadcastPreviewRejectsTamperedAndRevokedEvidence(t *testing.T) {
	for _, scenario := range []string{"sealed payload", "recipient snapshot", "revoked device"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMonitorBroadcastIntegrationFixture(t)
			f.request.Operation = "monitor_broadcast_preview"
			switch scenario {
			case "sealed payload":
				f.tamperDelivery = true
			case "recipient snapshot":
				f.tamperSnapshot = true
			case "revoked device":
				if _, err := f.local.store.RevokeClientDevice(f.local.ownerID, f.deviceID, f.clientVersion); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.local.bridge.monitorBroadcast(f.request); err == nil {
				t.Fatal("untrusted or revoked Monitor payload was previewed")
			}
			f.assertNoLocalChildren(t)
		})
	}
}

func TestMonitorBroadcastApprovedClientPayloadExecutesOneLocalSealedChild(t *testing.T) {
	f := newMonitorBroadcastIntegrationFixture(t)
	result, err := f.local.bridge.monitorBroadcast(f.request)
	if err != nil || result == nil || result.Progress == nil || !result.Progress.Complete ||
		len(result.Progress.Recipients) != 1 || result.Progress.Recipients[0].State != "ACCEPTED" {
		t.Fatalf("approved Monitor execution did not persist one sealed child: %+v %v", result, err)
	}
	childID := result.Progress.Recipients[0].MessageID
	wantID, _, err := localSealedRPCIDs(groupBroadcastChildOperationID(f.preview.BroadcastID,
		f.preview.Snapshot.Recipients[0].EndpointID))
	if err != nil || childID != wantID {
		t.Fatalf("Monitor child did not retain stable identity: %s vs %s (%v)", childID, wantID, err)
	}
	retry, err := f.local.bridge.monitorBroadcast(f.request)
	if err != nil || retry.Progress == nil || retry.Progress.Recipients[0].MessageID != childID {
		t.Fatalf("exact Monitor retry changed child identity: %+v %v", retry, err)
	}
	ledger, err := nodelocal.Open(machineLocalGroupLedgerPath(f.local.stateDir, f.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	pending, err := ledger.PendingAll(context.Background(), 8)
	if err != nil || len(pending) != 1 {
		t.Fatalf("Monitor retries created multiple local deliveries: %d %v", len(pending), err)
	}
	f.hubMu.Lock()
	defer f.hubMu.Unlock()
	if f.hubSawBody {
		t.Fatal("Hub HTTP observed Client broadcast plaintext")
	}
	if !containsString(f.hubPaths, "/v2/relay/nodes/"+f.local.nodeID+"/monitor/broadcasts/"+f.preview.PreviewID+"/authorize") ||
		!containsString(f.hubPaths, "/v2/relay/nodes/"+f.local.nodeID+"/local/authorize") {
		t.Fatalf("Monitor did not use Node-only approval and local sealed Guard: %v", f.hubPaths)
	}
	for _, path := range f.hubPaths {
		if strings.Contains(path, "/control/") {
			t.Fatalf("ordinary Monitor broadcast called Control business path: %s", path)
		}
	}
}

func TestMonitorBroadcastApprovedClientPayloadPersistsLocalAndRemoteChildren(t *testing.T) {
	f := newMonitorBroadcastIntegrationFixtureWithRemote(t, true)
	result, err := f.local.bridge.monitorBroadcast(f.request)
	if err != nil || result == nil || result.Progress == nil || !result.Progress.Complete ||
		len(result.Progress.Recipients) != 2 {
		t.Fatalf("Monitor did not fan out to fixed two-Node snapshot: %+v %v", result, err)
	}
	statusRequest := f.acceptClientRequest(t, f.context.ClientSessionEpoch, 3, "synthetic_outcome_status")
	status, err := f.local.store.GetUserMonitorBroadcastV2OutcomeStatus(statusRequest, f.preview.PreviewID)
	if err != nil || len(status.Recipients) != 2 {
		t.Fatalf("Hub did not retain per-recipient outcome evidence: %+v %v", status, err)
	}
	for ordinal, recipient := range status.Recipients {
		wantEvidence := store.UserMonitorBroadcastV2EvidenceNode
		if f.preview.Snapshot.Recipients[ordinal].NodeID != f.local.nodeID {
			wantEvidence = store.UserMonitorBroadcastV2EvidenceRelay
		}
		if recipient.Ordinal != ordinal || recipient.State != "ACCEPTED" ||
			recipient.Evidence != wantEvidence || recipient.MessageID == "" {
			t.Fatalf("Hub mixed local and authoritative Relay acceptance: %+v", recipient)
		}
	}
	messageByEndpoint := make(map[string]string)
	for _, child := range result.Progress.Recipients {
		if child.State != "ACCEPTED" || child.MessageID == "" {
			t.Fatalf("Monitor child was not durably accepted: %+v", child)
		}
		messageByEndpoint[child.EndpointID] = child.MessageID
	}
	if messageByEndpoint[f.local.targetMCP.endpointID] == "" || messageByEndpoint[f.remoteEndpoint] == "" {
		t.Fatalf("local or remote child missing: %+v", messageByEndpoint)
	}
	localArgs, localCount := installMachineSealedFakeCodex(t, false, f.local.nodeToken)
	localInbox, err := nodeinbox.Open(machineLocalGroupInboxPath(f.local.stateDir, f.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	if err := processPinnedTestMachineLocalGroupDeliveries(context.Background(), f.local.bridge, localInbox); err != nil {
		t.Fatal(err)
	}
	_ = localInbox.Close()
	if count, err := os.ReadFile(localCount); err != nil || string(count) != "x" {
		t.Fatalf("local Monitor child missed native queue: %q %v", count, err)
	}
	if args, err := os.ReadFile(localArgs); err != nil ||
		!bytes.Contains(args, []byte("queue\n--thread\n"+f.local.nativeB+"\n--message\n")) ||
		!bytes.Contains(args, []byte(f.body)) {
		t.Fatalf("local child reached wrong native queue: %q %v", args, err)
	}
	remoteArgs, remoteCount := installMachineSealedFakeCodex(t, false, f.remoteToken)
	t.Setenv("CICADA_NODE_TOKEN", f.remoteToken)
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	remoteInbox, err := nodeinbox.Open(machineNodeInboxPath(f.local.stateDir, f.remoteNodeID))
	if err != nil {
		t.Fatal(err)
	}
	if err := processPinnedTestMachineFabricDeliveries(context.Background(), f.hub.URL,
		f.remoteNodeID, remoteInbox, f.local.stateDir); err != nil {
		t.Fatal(err)
	}
	_ = remoteInbox.Close()
	if count, err := os.ReadFile(remoteCount); err != nil || string(count) != "x" {
		t.Fatalf("remote Monitor child missed native queue: %q %v", count, err)
	}
	if args, err := os.ReadFile(remoteArgs); err != nil ||
		!bytes.Contains(args, []byte("queue\n--thread\n"+f.remoteNativeID+"\n--message\n")) ||
		!bytes.Contains(args, []byte(f.body)) {
		t.Fatalf("remote child reached wrong native queue: %q %v", args, err)
	}
	f.hubMu.Lock()
	defer f.hubMu.Unlock()
	if f.hubSawBody || !containsString(f.hubPaths,
		"/v2/relay/nodes/"+f.local.nodeID+"/group/sealed/send") {
		t.Fatalf("Hub saw plaintext or did not persist sealed remote child: plaintext=%v paths=%v",
			f.hubSawBody, f.hubPaths)
	}
}

func TestMonitorBroadcastMCPUsesLocalSocketAndApprovalIDOnly(t *testing.T) {
	f := newMonitorBroadcastIntegrationFixture(t)
	t.Setenv("CODEX_THREAD_ID", f.local.nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+f.local.nativeA)
	resultValue, err := f.local.sourceMCP.callTool("cicada_monitor_broadcast",
		map[string]any{"approval_id": f.preview.PreviewID})
	if err != nil {
		t.Fatalf("joined Monitor MCP could not execute approved payload: %v", err)
	}
	result, ok := resultValue.(map[string]any)
	if !ok || result["status"] != mcpOutboxStatusSent || result["operation"] != "monitor_broadcast" ||
		result["broadcast_id"] != f.preview.BroadcastID || result["retryable"] != false {
		t.Fatalf("Monitor MCP did not report durable sealed execution: %#v", resultValue)
	}
	resultValue, err = f.local.sourceMCP.callTool("cicada_monitor_broadcast",
		map[string]any{"approval_id": f.preview.PreviewID})
	if err != nil || resultValue.(map[string]any)["operation_id"] != result["operation_id"] {
		t.Fatalf("Monitor MCP retry changed operation identity: %#v %v", resultValue, err)
	}
	ledger, err := nodelocal.Open(machineLocalGroupLedgerPath(f.local.stateDir, f.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	pending, err := ledger.PendingAll(context.Background(), 8)
	if err != nil || len(pending) != 1 {
		t.Fatalf("Monitor MCP retry created duplicate child: %d %v", len(pending), err)
	}
	f.hubMu.Lock()
	defer f.hubMu.Unlock()
	if f.hubSawBody {
		t.Fatal("Monitor MCP sent plaintext through Hub")
	}
}

func TestMonitorBroadcastDeviceRevocationBetweenChildrenStopsFanout(t *testing.T) {
	f := newMonitorBroadcastIntegrationFixtureWithRemote(t, true)
	f.hubMu.Lock()
	f.afterFirstChild = func() {
		if _, err := f.local.store.RevokeClientDevice(f.local.ownerID, f.deviceID, f.clientVersion); err != nil {
			t.Errorf("revoke synthetic Client after first child: %v", err)
		}
	}
	f.hubMu.Unlock()
	result, err := f.local.bridge.monitorBroadcast(f.request)
	if err != nil || result == nil || result.Progress == nil || len(result.Progress.Recipients) != 2 {
		t.Fatalf("revoked mid-batch Monitor progress missing: %+v %v", result, err)
	}
	if result.Progress.Recipients[0].State != "ACCEPTED" || result.Progress.Recipients[1].State != "FAILED" {
		t.Fatalf("Monitor sent later child after Client revocation: %+v", result.Progress.Recipients)
	}
	f.hubMu.Lock()
	defer f.hubMu.Unlock()
	if f.afterFirstChild != nil || f.hubSawBody {
		t.Fatalf("revocation hook did not run or Hub saw plaintext: hook=%v body=%v",
			f.afterFirstChild != nil, f.hubSawBody)
	}
}

func TestMonitorBroadcastRejectsWrongNativeMonitorAndBindingBeforeChildren(t *testing.T) {
	for _, scenario := range []string{"wrong native", "wrong Monitor", "wrong binding"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMonitorBroadcastIntegrationFixture(t)
			request := f.request
			switch scenario {
			case "wrong native":
				request.NativeSessionID = f.local.nativeB
			case "wrong Monitor":
				request.EndpointID = f.local.targetMCP.endpointID
			case "wrong binding":
				request.BindingEpoch++
			}
			if _, err := f.local.bridge.monitorBroadcast(request); err == nil {
				t.Fatal("wrong native Monitor identity executed approved broadcast")
			}
			f.assertNoLocalChildren(t)
		})
	}
}

func TestMonitorBroadcastRejectsTamperedPayloadAndMissingLocalOwnerTrust(t *testing.T) {
	for _, scenario := range []string{"tampered Hub payload", "tampered consent snapshot", "missing local Owner trust"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMonitorBroadcastIntegrationFixture(t)
			if scenario == "tampered Hub payload" || scenario == "tampered consent snapshot" {
				f.hubMu.Lock()
				f.tamperDelivery = scenario == "tampered Hub payload"
				f.tamperSnapshot = scenario == "tampered consent snapshot"
				f.hubMu.Unlock()
			} else {
				crypto, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.local.stateDir, f.local.nodeID))
				if err != nil {
					t.Fatal(err)
				}
				trust, err := crypto.GetNodeOwnerKeyTrustLocal(f.local.ownerID, f.ownerKeyID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := crypto.RevokeNodeOwnerKeyTrustLocal(f.local.ownerID, f.ownerKeyID, trust.Version); err != nil {
					t.Fatal(err)
				}
				_ = crypto.Close()
			}
			if _, err := f.local.bridge.monitorBroadcast(f.request); err == nil {
				t.Fatal("untrusted Monitor payload executed")
			}
			f.assertNoLocalChildren(t)
			if scenario == "tampered consent snapshot" {
				crypto, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.local.stateDir, f.local.nodeID))
				if err != nil {
					t.Fatal(err)
				}
				defer crypto.Close()
				replayID := func(domain, first, second string) string {
					sum := sha256.Sum256([]byte("cicada/node/monitor-broadcast-replay/v1\x00" + domain + "\x00" + first + "\x00" + second))
					return "umb_" + hex.EncodeToString(sum[:])
				}
				_, err = crypto.GetInbound(context.Background(),
					replayID("receiver", f.context.MonitorEndpointID, f.context.MonitorKeyID),
					f.client.Public().ID, replayID("message", f.context.ApprovalID, f.context.BroadcastID))
				if !errors.Is(err, nodekeys.ErrCryptoStateNotFound) {
					t.Fatal("tampered scope reached crypto inbox", err)
				}
			}
		})
	}
}

func TestMonitorBroadcastNoticeQueuesOnlyMetadataOnce(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		name := "accepted"
		if uncertain {
			name = "injection uncertain"
		}
		t.Run(name, func(t *testing.T) {
			f := newMonitorBroadcastIntegrationFixture(t)
			argumentsPath, countPath := installMachineSealedFakeCodex(t, uncertain, f.local.nodeToken)
			for attempt := 0; attempt < 2; attempt++ {
				inbox, err := nodeinbox.Open(machineMonitorBroadcastInboxPath(f.local.stateDir, f.local.nodeID))
				if err != nil {
					t.Fatal(err)
				}
				err = processPinnedTestMachineMonitorBroadcastNotifications(context.Background(), f.local.bridge, &inbox,
					machineMonitorBroadcastInboxPath(f.local.stateDir, f.local.nodeID))
				if closeErr := inbox.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
				if err != nil {
					t.Fatalf("process Monitor notice attempt %d: %v", attempt, err)
				}
			}
			count, err := os.ReadFile(countPath)
			if err != nil || string(count) != "x" {
				t.Fatalf("Monitor notice was blindly reinjected: count=%q err=%v", count, err)
			}
			arguments, err := os.ReadFile(argumentsPath)
			if err != nil || !bytes.Contains(arguments, []byte("queue\n--thread\n"+f.local.nativeA+"\n--message\n")) ||
				!bytes.Contains(arguments, []byte(f.preview.PreviewID)) || bytes.Contains(arguments, []byte(f.body)) {
				t.Fatalf("Monitor notice queued wrong native Thread or plaintext: %q err=%v", arguments, err)
			}
			inbox, err := nodeinbox.Open(machineMonitorBroadcastInboxPath(f.local.stateDir, f.local.nodeID))
			if err != nil {
				t.Fatal(err)
			}
			defer inbox.Close()
			delivery, err := inbox.Get(context.Background(), f.preview.PreviewID)
			want := nodeinbox.CONSUMPTION_UNCONFIRMED
			if uncertain {
				want = nodeinbox.INJECTION_UNCERTAIN
			}
			if err != nil || delivery.State != want {
				t.Fatalf("Monitor notice state=%v, want=%s err=%v", delivery, want, err)
			}
			f.assertNoLocalChildren(t)
		})
	}
}

func TestMonitorBroadcastLostOutcomeReceiptRetainsStableChildren(t *testing.T) {
	f := newMonitorBroadcastIntegrationFixture(t)
	var dropReceipt atomic.Bool
	dropReceipt.Store(true)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/outcomes") && dropReceipt.Swap(false) {
			recorded := httptest.NewRecorder()
			f.hub.Config.Handler.ServeHTTP(recorded, r)
			if recorded.Code != http.StatusOK {
				t.Errorf("upstream outcome was not persisted before losing reply: %d", recorded.Code)
			}
			http.Error(w, "synthetic lost receipt", http.StatusServiceUnavailable)
			return
		}
		f.hub.Config.Handler.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	bridge := &machineAgentJoinBridge{ctx: f.local.machineContextForNodeAt(f.local.nodeID, f.local.nodeToken, proxy.URL), baseURL: proxy.URL,
		nodeID: f.local.nodeID, nodeToken: f.local.nodeToken, stateDir: f.local.stateDir}
	first, firstErr := bridge.monitorBroadcast(f.request)
	if firstErr == nil || !localSealedSendRetryable(firstErr) {
		t.Fatalf("lost outcome receipt falsely reported a confirmed operation: %v", firstErr)
	}
	if first == nil || first.Progress == nil || len(first.Progress.Recipients) != 1 ||
		first.Progress.Recipients[0].State != "ACCEPTED" {
		t.Fatalf("synthetic lost receipt occurred before an accepted child: %+v", first)
	}
	result, err := bridge.monitorBroadcast(f.request)
	if err != nil || result == nil || result.Progress == nil || len(result.Progress.Recipients) != 1 ||
		result.Progress.Recipients[0].State != "ACCEPTED" {
		if result != nil && result.Progress != nil {
			f.hubMu.Lock()
			paths := append([]string(nil), f.hubPaths...)
			f.hubMu.Unlock()
			t.Fatalf("same operation could not recover after lost report receipt: progress=%+v first=%+v first_err=%v hub_paths=%v retry_err=%v",
				*result.Progress, first, firstErr, paths, err)
		}
		t.Fatalf("same operation could not recover after lost report receipt: result=%+v first=%+v first_err=%v retry_err=%v",
			result, first, firstErr, err)
	}
	ledger, err := nodelocal.Open(machineLocalGroupLedgerPath(f.local.stateDir, f.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	pending, err := ledger.PendingAll(context.Background(), 8)
	if err != nil || len(pending) != 1 {
		t.Fatalf("report retry duplicated the sealed child: count=%d err=%v", len(pending), err)
	}
	statusID := f.acceptClientRequest(t, f.context.ClientSessionEpoch, 3, "synthetic_recovered_status")
	status, err := f.local.store.GetUserMonitorBroadcastV2OutcomeStatus(statusID, f.preview.PreviewID)
	if err != nil || len(status.Recipients) != 1 || status.Recipients[0].MessageID != result.Progress.Recipients[0].MessageID ||
		status.Recipients[0].Evidence != store.UserMonitorBroadcastV2EvidenceNode {
		t.Fatalf("Hub did not retain correlated Node evidence: %+v %v", status, err)
	}
}
