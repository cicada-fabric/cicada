package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestMCPSealedSameGroupBroadcastNative uses three real Codex Threads on one
// disposable logical Node. Each Thread explicitly joins the Group; the sender
// invokes cicada_broadcast in its original Thread, and each recipient invokes
// cicada_receive after its own original Thread accepted a native queue item.
// It is opt-in because it creates persistent provider-backed Threads and makes
// real model calls. It does not claim multi-host delivery or automatic wake of
// a cold Thread.
func TestMCPSealedSameGroupBroadcastNative(t *testing.T) {
	if strings.TrimSpace(os.Getenv("CICADA_BROADCAST_NATIVE_E2E")) != "1" {
		t.Skip("set CICADA_BROADCAST_NATIVE_E2E=1 to run the real Codex same-Group broadcast test")
	}
	codexBinary, cicadaBinary := nativeE2EBinaries(t)
	if !nativeE2EHasCredentials() {
		t.Skip("Codex provider credentials are unavailable (expected API_KEY/OPENAI_API_KEY or CODEX_HOME/auth.json)")
	}

	ctx, cancel := nativeE2EContext(t)
	defer cancel()
	workspace := nativeE2EWorkspace(t, "same-group-broadcast-")
	model := strings.TrimSpace(os.Getenv("CICADA_NATIVE_MODEL"))
	if model == "" {
		model = "gpt-5.6-luna"
	}

	suffix, err := nativeE2ESuffix()
	if err != nil {
		t.Fatal("create synthetic native broadcast identities")
	}
	ownerID := "owner_native_broadcast_" + suffix
	groupID := "group_native_broadcast_" + suffix
	nodeID := "node_native_bcast_" + suffix[:8]
	stateDir := shortLocalJoinStateDir(t)
	storePath := filepath.Join(t.TempDir(), "native-broadcast-hub.sqlite3")
	persistence, err := store.New(storePath)
	if err != nil {
		t.Fatal("create disposable broadcast Hub Store")
	}
	t.Cleanup(func() { _ = persistence.Close() })
	owner, err := persistence.CreatePrincipal(store.Principal{
		ID: ownerID, Kind: store.PrincipalKindHuman, OwnerID: ownerID,
		TrustDomainID: ownerID, Name: "Disposable native broadcast owner",
	})
	if err != nil {
		t.Fatal("create disposable broadcast owner")
	}
	if _, err := persistence.CreateGroup(store.Group{
		ID: groupID, Name: "Disposable native broadcast Group",
		OwnerPrincipalID: owner.ID, TrustDomainID: owner.TrustDomainID,
		State: store.GroupStateActive,
	}); err != nil {
		t.Fatal("create disposable broadcast Group")
	}
	nodeToken, err := bindNativeE2ETestNode(persistence, ownerID, nodeID)
	if err != nil {
		t.Fatal("bind disposable broadcast Node to its owner")
	}
	service, err := fabric.NewService(persistence, ownerID, owner.TrustDomainID)
	if err != nil {
		t.Fatal("create disposable Fabric service")
	}
	fabricHandler := server.NewFabricHandler(service, "")

	senderContext := "CICADA_BROADCAST_SENDER_CONTEXT_" + suffix
	recipientOneContext := "CICADA_BROADCAST_RECIPIENT_ONE_CONTEXT_" + suffix
	recipientTwoContext := "CICADA_BROADCAST_RECIPIENT_TWO_CONTEXT_" + suffix
	broadcastBody := "CICADA_SYNTHETIC_GROUP_BROADCAST_" + suffix
	privateText := []string{senderContext, recipientOneContext, recipientTwoContext, broadcastBody}
	allowedPaths := map[string]bool{
		"/v2/fabric/node/join":                                    true,
		"/v2/fabric/whoami":                                       true,
		"/v2/fabric/heartbeat":                                    true,
		"/v2/fabric/endpoint-keys":                                true,
		"/v2/fabric/resolve":                                      true,
		"/v2/relay/nodes/" + nodeID + "/local/authorize":          true,
		"/v2/relay/nodes/" + nodeID + "/local/revalidate":         true,
		"/v2/relay/nodes/" + nodeID + "/group/broadcast/snapshot": true,
	}
	var captureMu sync.Mutex
	var hubPaths, unexpectedPaths []string
	var hubSawPlaintext bool
	var controlBusinessCalls int
	var capturedSnapshot *store.SameGroupBroadcastV2Snapshot
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024+1))
		_ = r.Body.Close()
		if readErr != nil || len(body) > 2*1024*1024 {
			http.Error(w, "invalid request", http.StatusRequestEntityTooLarge)
			return
		}
		path := r.URL.Path
		captureMu.Lock()
		hubPaths = append(hubPaths, r.Method+" "+path)
		if !allowedPaths[path] {
			unexpectedPaths = append(unexpectedPaths, r.Method+" "+path)
		}
		if strings.HasPrefix(path, "/v2/control/") {
			controlBusinessCalls++
		}
		for _, value := range privateText {
			if value != "" && bytes.Contains(body, []byte(value)) {
				hubSawPlaintext = true
			}
		}
		captureMu.Unlock()
		if !allowedPaths[path] {
			http.NotFound(w, r)
			return
		}

		recorder := httptest.NewRecorder()
		r.Body = io.NopCloser(bytes.NewReader(body))
		fabricHandler.ServeHTTP(recorder, r)
		responseBody := recorder.Body.Bytes()
		captureMu.Lock()
		for _, value := range privateText {
			if value != "" && bytes.Contains(responseBody, []byte(value)) {
				hubSawPlaintext = true
			}
		}
		if path == "/v2/relay/nodes/"+nodeID+"/group/broadcast/snapshot" && recorder.Code >= 200 && recorder.Code < 300 {
			var envelope groupBroadcastHubSnapshotResponse
			if json.Unmarshal(responseBody, &envelope) == nil {
				snapshotCopy := envelope.Snapshot
				capturedSnapshot = &snapshotCopy
			}
		}
		captureMu.Unlock()
		for name, values := range recorder.Header() {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(responseBody)
	}))
	defer hub.Close()
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal("read disposable Hub identity")
	}
	t.Setenv("CICADA_HUB_ID", hubID)
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	t.Setenv("CICADA_MCP_STATE_DIR", t.TempDir())
	t.Setenv("CICADA_MACHINE_ID", nodeID)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_API_URL", hub.URL)
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	t.Setenv("CICADA_NODE_TOKEN", "")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	t.Setenv("CICADA_ENDPOINT_ID", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CICADA_CODEX_BIN", codexBinary)
	mcpStateRoot := os.Getenv("CICADA_MCP_STATE_DIR")
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, hub.URL, nodeID, nodeToken)
	if err != nil {
		t.Fatal("start disposable local Node bridge")
	}
	defer func() { _ = bridge.Close() }()

	type nativeParticipant struct {
		name      string
		context   string
		threadID  string
		endpoint  *store.Endpoint
		mcpState  string
		codexConf []string
	}
	participants := []*nativeParticipant{
		{name: "sender", context: senderContext},
		{name: "recipient-one", context: recipientOneContext},
		{name: "recipient-two", context: recipientTwoContext},
	}
	for _, participant := range participants {
		participant.mcpState = filepath.Join(mcpStateRoot, participant.name)
		initialPrompt := fmt.Sprintf("This is synthetic public E2E fixture data, not a secret. Remember this unique context marker for a later response: %s. Do not use tools. Finish with the single word READY.", participant.context)
		initial, threadID, turnErr := runNativeCodexTurn(ctx, codexBinary, workspace, model,
			nativeBroadcastCodexConfig(cicadaBinary, hub.URL, stateDir, participant.mcpState, nodeID, false, ""),
			"", initialPrompt)
		if turnErr != nil {
			t.Fatalf("Codex %s initial Thread creation failed (%s); provider may be unavailable",
				participant.name, nativeThreadIDLabel(threadID))
		}
		if err := verifyCodexSessionRecord(threadID, workspace); err != nil {
			t.Fatalf("Codex %s thread.started UUID has no isolated CODEX_HOME session record: %v", participant.name, err)
		}
		if _, err := nativeCodexThreadStarted(initial); err != nil {
			t.Fatalf("Codex %s did not emit a real thread.started event: %v", participant.name, err)
		}
		participant.threadID = threadID
	}
	for left := range participants {
		for right := left + 1; right < len(participants); right++ {
			if participants[left].threadID == participants[right].threadID {
				t.Fatal("Codex reused a native Thread ID for distinct Group participants")
			}
		}
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("failed isolated native Thread labels: sender=%s recipient-one=%s recipient-two=%s",
				nativeThreadIDLabel(participants[0].threadID), nativeThreadIDLabel(participants[1].threadID), nativeThreadIDLabel(participants[2].threadID))
		}
	})

	for _, participant := range participants {
		participant.codexConf = nativeBroadcastCodexConfig(cicadaBinary, hub.URL, stateDir,
			participant.mcpState, nodeID, true, participant.threadID)
		joinPrompt := fmt.Sprintf("At this controlled safe point, explicitly join the owner's prepared Cicada Group. Use cicada_join exactly once with group_id %q. Do not call any other Cicada tool. Wait for the tool result, then finish with READY.", groupID)
		joined, resumedID, turnErr := runNativeCodexTurn(ctx, codexBinary, workspace, model,
			participant.codexConf, participant.threadID, joinPrompt)
		if turnErr != nil {
			t.Fatalf("Codex %s explicit Join failed (%s); events=%s; tool_failures=%s",
				participant.name, nativeThreadIDLabel(resumedID), nativeE2EEventSummary(joined), nativeE2EToolFailures(joined))
		}
		if resumedID != participant.threadID {
			t.Fatalf("Codex %s Join resumed a different native Thread", participant.name)
		}
		nativeCrossNodeRequireToolCompleted(t, joined, "cicada_join")
		if err := verifyCodexSessionRecord(resumedID, workspace); err != nil {
			t.Fatalf("Codex %s Join resume no longer matches its CODEX_HOME record", participant.name)
		}
		participant.endpoint, err = nativeE2ECurrentSession(persistence, participant.threadID,
			workspace, nodeID, groupID)
		if err != nil {
			t.Fatalf("Codex %s original native Thread did not establish a current Group SessionBinding", participant.name)
		}
		nativeBroadcastRequireCurrentMembership(t, persistence, participant.endpoint, groupID)
	}

	ownerIdentity, ownerKey := grantGroupBroadcastSend(t, persistence, ownerID, groupID,
		participants[0].endpoint.PrincipalID, participants[0].endpoint.ID,
		participants[1].endpoint.PrincipalID, participants[1].endpoint.ID,
		participants[2].endpoint.PrincipalID, participants[2].endpoint.ID)
	trustBroadcastOwnerKey(t, stateDir, nodeID, ownerID, ownerIdentity, ownerKey.KeyID)

	sender := participants[0]
	broadcastIdempotencyKey := "native-broadcast-" + suffix
	broadcastPrompt := fmt.Sprintf("At this controlled safe point, use Cicada MCP tool cicada_broadcast exactly once with group_id %q, body %q, and idempotency_key %q. Do not send a unicast, ask, or reply. Wait for its result and finish with ACCEPTED.", groupID, broadcastBody, broadcastIdempotencyKey)
	broadcastOutput, resumedSenderID, err := runNativeCodexTurn(ctx, codexBinary, workspace, model,
		sender.codexConf, sender.threadID, broadcastPrompt)
	if err != nil {
		t.Fatalf("Codex sender broadcast call failed (%s); events=%s; tool_failures=%s",
			nativeThreadIDLabel(resumedSenderID), nativeE2EEventSummary(broadcastOutput), nativeE2EToolFailures(broadcastOutput))
	}
	if resumedSenderID != sender.threadID {
		t.Fatal("broadcast was not invoked in the sender's original native Thread")
	}
	nativeCrossNodeRequireToolCompleted(t, broadcastOutput, "cicada_broadcast")
	if err := verifyCodexSessionRecord(resumedSenderID, workspace); err != nil {
		t.Fatal("sender broadcast turn no longer matches its original CODEX_HOME session record")
	}

	progress, operationID, err := nativeBroadcastReadPersistedProgress(sender.mcpState,
		sender.threadID, sender.endpoint.ID, groupID)
	if err != nil {
		t.Fatalf("sender's durable MCP outbox did not record a completed broadcast: %v", err)
	}
	broadcastID, err := mcpBroadcastID(operationID)
	if err != nil || broadcastID != progress.BroadcastID || progress.GroupID != groupID ||
		!progress.Complete || progress.RecipientCount != 2 || progress.NextOffset != 2 ||
		len(progress.Recipients) != 2 || progress.SnapshotDigest == "" {
		t.Fatal("broadcast outbox did not record the complete two-recipient immutable snapshot")
	}
	if progress.Status != mcpOutboxStatusSent {
		t.Fatalf("broadcast outbox status is %s, want SENT", progress.Status)
	}
	messageIDs := make(map[string]string, 2)
	for _, recipient := range progress.Recipients {
		if recipient.State != "ACCEPTED" || recipient.MessageID == "" ||
			(recipient.EndpointID != participants[1].endpoint.ID && recipient.EndpointID != participants[2].endpoint.ID) {
			t.Fatal("broadcast did not persist an accepted delivery for exactly the two joined recipients")
		}
		if _, duplicate := messageIDs[recipient.EndpointID]; duplicate {
			t.Fatal("broadcast returned a duplicate recipient delivery")
		}
		messageIDs[recipient.EndpointID] = recipient.MessageID
	}
	if messageIDs[participants[1].endpoint.ID] == "" || messageIDs[participants[2].endpoint.ID] == "" {
		t.Fatal("broadcast omitted one of the two current recipient Endpoints")
	}

	captureMu.Lock()
	snapshot := capturedSnapshot
	captureMu.Unlock()
	if snapshot == nil || snapshot.BroadcastID != broadcastID || snapshot.GroupID != groupID ||
		snapshot.Source.EndpointID != sender.endpoint.ID || snapshot.Source.NativeSessionID != sender.threadID ||
		snapshot.Source.GroupID != groupID || len(snapshot.Recipients) != 2 {
		t.Fatal("Hub did not capture the sender's current Group membership and exact two-recipient snapshot")
	}
	snapshotEndpoints := map[string]bool{}
	for _, recipient := range snapshot.Recipients {
		snapshotEndpoints[recipient.EndpointID] = true
	}
	if len(snapshotEndpoints) != 2 || !snapshotEndpoints[participants[1].endpoint.ID] || !snapshotEndpoints[participants[2].endpoint.ID] {
		t.Fatal("broadcast snapshot did not match the two explicitly joined current Group members")
	}
	for _, participant := range participants {
		nativeBroadcastRequireCurrentMembership(t, persistence, participant.endpoint, groupID)
	}
	for _, participant := range participants[1:] {
		binding, bindErr := persistence.GetSessionBindingForEndpoint(participant.endpoint.ID)
		if bindErr != nil || binding.NativeSessionID != participant.threadID || binding.EndpointID != participant.endpoint.ID {
			t.Fatalf("recipient %s snapshot membership is not bound to its real native Thread", participant.name)
		}
	}

	inbox, err := nodeinbox.Open(machineLocalGroupInboxPath(stateDir, nodeID))
	if err != nil {
		t.Fatal("open disposable Node-local broadcast inbox")
	}
	defer inbox.Close()
	if err := processPinnedTestMachineLocalGroupDeliveries(ctx, bridge, inbox); err != nil {
		t.Fatalf("Node could not queue the accepted broadcast to both native recipients (%T)", err)
	}
	for _, participant := range participants[1:] {
		messageID := messageIDs[participant.endpoint.ID]
		delivery, deliveryErr := inbox.Get(ctx, messageID)
		if deliveryErr != nil || delivery == nil || delivery.MessageID != messageID ||
			delivery.EndpointID != participant.endpoint.ID || delivery.SessionID != participant.threadID ||
			delivery.State != nodeinbox.CONSUMPTION_UNCONFIRMED {
			t.Fatalf("broadcast queue did not accept the exact original Thread for %s", participant.name)
		}
		binding, bindErr := persistence.GetSessionBindingForEndpoint(participant.endpoint.ID)
		if bindErr != nil || binding.NativeSessionID != participant.threadID {
			t.Fatalf("recipient %s lost its original native SessionBinding before receive", participant.name)
		}
		visible, visibleErr := inbox.ListInjectedForSession(ctx, participant.endpoint.ID,
			participant.threadID, binding.Epoch, groupID, 0, 8)
		if visibleErr != nil || len(visible) != 1 || visible[0].MessageID != messageID ||
			visible[0].Body != broadcastBody || visible[0].Kind != "SEND" ||
			visible[0].SenderEndpointID != sender.endpoint.ID {
			t.Fatalf("Node inbox did not retain the exact sealed Group broadcast for %s", participant.name)
		}
	}

	for _, participant := range participants[1:] {
		receivePrompt := fmt.Sprintf("At this controlled post-queue checkpoint, use cicada_receive exactly once with limit 8 in this existing Thread. Read the new Group message from sender Endpoint %q. In your final answer, report the synthetic broadcast marker you actually received and the private context marker you remembered when this Thread started. Do not use any other tool.", sender.endpoint.ID)
		received, resumedID, turnErr := runNativeCodexTurn(ctx, codexBinary, workspace, model,
			participant.codexConf, participant.threadID, receivePrompt)
		if turnErr != nil {
			t.Fatalf("Codex %s original Thread receive turn failed (%s); events=%s; tool_failures=%s",
				participant.name, nativeThreadIDLabel(resumedID), nativeE2EEventSummary(received), nativeE2EToolFailures(received))
		}
		if resumedID != participant.threadID {
			t.Fatalf("Codex %s receive resumed a different native Thread", participant.name)
		}
		nativeCrossNodeRequireToolCompleted(t, received, "cicada_receive")
		if err := verifyCodexSessionRecord(resumedID, workspace); err != nil {
			t.Fatalf("Codex %s receive turn no longer matches its original CODEX_HOME session record", participant.name)
		}
		toolResult, ok := nativeCodexCompletedMCPStructuredContent(received, "cicada_receive")
		if !ok || !nativeBroadcastReceiveResultMatches(toolResult,
			messageIDs[participant.endpoint.ID], broadcastBody, sender.endpoint.ID) {
			t.Fatalf("Codex %s cicada_receive result did not contain its exact scoped broadcast", participant.name)
		}
		if !nativeE2EResultContains(received, broadcastBody) || !nativeE2EResultContains(received, participant.context) {
			t.Fatalf("Codex %s original Thread did not consume the broadcast while retaining its initial context", participant.name)
		}
	}

	captureMu.Lock()
	finalPaths := append([]string(nil), hubPaths...)
	finalUnexpected := append([]string(nil), unexpectedPaths...)
	finalPlaintext := hubSawPlaintext
	finalControlCalls := controlBusinessCalls
	captureMu.Unlock()
	if finalPlaintext {
		t.Fatal("Hub HTTP request or response contained synthetic peer plaintext")
	}
	if finalControlCalls != 0 {
		t.Fatalf("ordinary Group broadcast invoked %d Control business routes", finalControlCalls)
	}
	if len(finalUnexpected) != 0 {
		t.Fatalf("same-Node broadcast used an unapproved Hub path: %s", strings.Join(finalUnexpected, ", "))
	}
	if nativeCrossNodeContainsPath(finalPaths, "/v2/fabric/send") ||
		nativeCrossNodeContainsPath(finalPaths, "/v2/fabric/receive") ||
		nativeCrossNodeContainsPath(finalPaths, "/group/sealed/send") ||
		nativeCrossNodeContainsPath(finalPaths, "/v2/control/") {
		t.Fatal("same-Node broadcast traversed Hub peer Relay, legacy receive, or Control")
	}
	if !nativeCrossNodeContainsPath(finalPaths, "/group/broadcast/snapshot") ||
		!nativeCrossNodeContainsPath(finalPaths, "/local/authorize") ||
		!nativeCrossNodeContainsPath(finalPaths, "/local/revalidate") {
		t.Fatal("real native broadcast omitted its Group snapshot or current local Guard checks")
	}
	if err := nativeE2EAssertDatabasePrivateTextAbsent(storePath,
		senderContext, recipientOneContext, recipientTwoContext, broadcastBody); err != nil {
		t.Fatal("Hub SQLite retained same-Group broadcast plaintext")
	}
	t.Logf("real Codex same-Group broadcast passed: Group=%s; sender endpoint=%s thread=%s; recipient-one endpoint=%s thread=%s; recipient-two endpoint=%s thread=%s; broadcast=%s; messages=%s,%s; local native queue acceptance followed by scoped cicada_receive; Hub saw no peer plaintext and no Control/Relay business call",
		groupID, sender.endpoint.ID, nativeThreadIDLabel(sender.threadID),
		participants[1].endpoint.ID, nativeThreadIDLabel(participants[1].threadID),
		participants[2].endpoint.ID, nativeThreadIDLabel(participants[2].threadID),
		broadcastID, messageIDs[participants[1].endpoint.ID], messageIDs[participants[2].endpoint.ID])
}

func nativeBroadcastCodexConfig(binary, apiURL, stateDir, mcpStateDir, nodeID string,
	enabled bool, nativeThreadID string) []string {
	config := nativeCodexConfig(binary, apiURL, stateDir, mcpStateDir, nodeID, enabled, nativeThreadID)
	if !enabled {
		return config
	}
	codexHome := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if codexHome == "" {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			codexHome = filepath.Join(home, ".codex")
		}
	}
	if codexHome != "" {
		config = append(config, "--config", fmt.Sprintf("mcp_servers.cicada.env.CODEX_HOME=%q", codexHome))
	}
	return append(config, "--config", `mcp_servers.cicada.omit_tools_from=["deferred"]`)
}

func nativeBroadcastRequireCurrentMembership(t *testing.T, persistence *store.Store,
	endpoint *store.Endpoint, groupID string) {
	t.Helper()
	if endpoint == nil || endpoint.ID == "" || endpoint.GroupID != groupID {
		t.Fatal("native Endpoint does not identify the explicitly selected Group")
	}
	active, err := persistence.IsEndpointGroupActive(endpoint.ID, groupID)
	if err != nil || !active {
		t.Fatal("native Endpoint Group membership is not currently active")
	}
	membership, err := persistence.GetMembershipByPrincipalGroup(endpoint.PrincipalID, groupID)
	if err != nil || membership.Status != store.MembershipStatusActive {
		t.Fatal("native Principal Group membership is not currently active")
	}
}

type nativeBroadcastStoredProgress struct {
	Status string `json:"-"`
	mcpBroadcastProgress
}

func nativeBroadcastReadPersistedProgress(mcpStateDir, nativeThreadID, endpointID,
	groupID string) (nativeBroadcastStoredProgress, string, error) {
	path := filepath.Join(mcpStateDir, "mcp", "outbox.sqlite3")
	outbox := newMCPOutbox(path)
	defer outbox.close()
	outbox.mu.Lock()
	db, err := outbox.withDBLocked()
	if err != nil {
		outbox.mu.Unlock()
		return nativeBroadcastStoredProgress{}, "", err
	}
	rows, err := db.Query(`SELECT operation_id, status, result_json
FROM mcp_outbox_operations
WHERE native_session_id = ? AND endpoint_id = ? AND group_id = ? AND kind = 'broadcast'
ORDER BY created_at`, nativeThreadID, endpointID, groupID)
	outbox.mu.Unlock()
	if err != nil {
		return nativeBroadcastStoredProgress{}, "", err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nativeBroadcastStoredProgress{}, "", err
		}
		return nativeBroadcastStoredProgress{}, "", errors.New("no persisted broadcast operation for the sender's current Thread")
	}
	var operationID, status, resultJSON string
	if err := rows.Scan(&operationID, &status, &resultJSON); err != nil {
		return nativeBroadcastStoredProgress{}, "", err
	}
	if rows.Next() {
		return nativeBroadcastStoredProgress{}, "", errors.New("sender Thread persisted more than one broadcast operation")
	}
	if err := rows.Err(); err != nil {
		return nativeBroadcastStoredProgress{}, "", err
	}
	var result mcpBroadcastProgress
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		return nativeBroadcastStoredProgress{}, "", errors.New("persisted broadcast progress is invalid")
	}
	return nativeBroadcastStoredProgress{Status: status, mcpBroadcastProgress: result}, operationID, nil
}

func TestNativeBroadcastReadPersistedProgressUsesMCPStatePath(t *testing.T) {
	stateDir := t.TempDir()
	scope := mcpOutboxScope{
		APIOrigin: "https://hub.synthetic.invalid", Scope: "scope-native-broadcast-fixture",
		Harness: "codex", NativeSessionID: "native-broadcast-fixture",
		NodeID: "node-broadcast-fixture", Workspace: "/tmp/workspace-broadcast-fixture",
		EndpointID: "ep-broadcast-fixture", GroupID: "group-broadcast-fixture",
	}
	fixtureOutbox := newMCPOutbox(filepath.Join(stateDir, "mcp", "outbox.sqlite3"))
	operation, _, err := fixtureOutbox.prepare(scope, "broadcast", "synthetic-idempotency-key",
		mcpOutboxInput{Body: "synthetic broadcast body"})
	if err != nil {
		t.Fatal("prepare synthetic broadcast outbox row")
	}
	broadcastID, err := mcpBroadcastID(operation.OperationID)
	if err != nil {
		t.Fatal("derive synthetic broadcast ID")
	}
	encodedProgress, err := json.Marshal(mcpBroadcastProgress{
		BroadcastID: broadcastID, GroupID: scope.GroupID,
		SnapshotDigest: strings.Repeat("a", 64), Complete: true,
	})
	if err != nil {
		t.Fatal("encode synthetic broadcast progress")
	}
	if _, err := fixtureOutbox.markResult(scope, operation.OperationID,
		mcpOutboxStatusSent, "", string(encodedProgress)); err != nil {
		t.Fatal("persist synthetic completed broadcast")
	}
	if err := fixtureOutbox.close(); err != nil {
		t.Fatal("close synthetic broadcast outbox")
	}

	progress, operationID, err := nativeBroadcastReadPersistedProgress(stateDir,
		scope.NativeSessionID, scope.EndpointID, scope.GroupID)
	if err != nil {
		t.Fatalf("read the real MCP outbox path: %v", err)
	}
	if operationID != operation.OperationID || progress.Status != mcpOutboxStatusSent ||
		progress.BroadcastID != broadcastID || progress.GroupID != scope.GroupID || !progress.Complete {
		t.Fatal("native broadcast fixture read a different or incomplete MCP outbox operation")
	}
}

func TestNativeBroadcastFindStructuredContentWrappedReceiveResults(t *testing.T) {
	const messageID = "msg_synthetic_broadcast"
	const body = "CICADA_SYNTHETIC_GROUP_BROADCAST"
	const senderEndpointID = "ep_synthetic_sender"
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "status wrapper with structuredContent",
			raw:  `{"status":"ok","structuredContent":{"messages":[{"message_id":"msg_synthetic_broadcast","body":"CICADA_SYNTHETIC_GROUP_BROADCAST","kind":"SEND","sender_endpoint_id":"ep_synthetic_sender"}]}}`,
		},
		{
			name: "content text JSON",
			raw:  `{"status":"ok","content":[{"type":"text","text":"{\"messages\":[{\"message_id\":\"msg_synthetic_broadcast\",\"body\":\"CICADA_SYNTHETIC_GROUP_BROADCAST\",\"kind\":\"SEND\",\"sender_endpoint_id\":\"ep_synthetic_sender\"}]}"}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, ok := nativeBroadcastFindStructuredContent([]byte(test.raw))
			if !ok || !nativeBroadcastReceiveResultMatches(result, messageID, body, senderEndpointID) {
				t.Fatal("wrapped receive result did not preserve its exact synthetic broadcast")
			}
		})
	}

	for _, optionalFields := range []map[string]any{
		{},
		{"request_id": "", "reply_to": ""},
	} {
		message := map[string]any{
			"message_id": messageID, "body": body, "kind": "SEND",
			"sender_endpoint_id": senderEndpointID,
		}
		for key, value := range optionalFields {
			message[key] = value
		}
		if !nativeBroadcastReceiveResultMatches(map[string]any{"messages": []any{message}},
			messageID, body, senderEndpointID) {
			t.Fatal("omitted or empty optional correlation fields changed SEND semantics")
		}
	}
	for _, key := range []string{"request_id", "reply_to"} {
		message := map[string]any{
			"message_id": messageID, "body": body, "kind": "SEND",
			"sender_endpoint_id": senderEndpointID, key: "unexpected",
		}
		if nativeBroadcastReceiveResultMatches(map[string]any{"messages": []any{message}},
			messageID, body, senderEndpointID) {
			t.Fatalf("non-empty %s must not match a SEND broadcast", key)
		}
	}
}

func nativeCodexCompletedMCPStructuredContent(output []byte, wanted string) (map[string]any, bool) {
	for _, line := range bytes.Split(output, []byte("\n")) {
		var event struct {
			Type string `json:"type"`
			Item struct {
				Type   string          `json:"type"`
				Name   string          `json:"name"`
				Tool   string          `json:"tool"`
				Status string          `json:"status"`
				Result json.RawMessage `json:"result"`
				Output json.RawMessage `json:"output"`
			} `json:"item"`
		}
		if json.Unmarshal(bytes.TrimSpace(line), &event) != nil || event.Type != "item.completed" ||
			event.Item.Type != "mcp_tool_call" || event.Item.Status != "completed" {
			continue
		}
		toolName := event.Item.Tool
		if toolName == "" {
			toolName = event.Item.Name
		}
		if toolName != wanted {
			continue
		}
		raw := event.Item.Result
		if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
			raw = event.Item.Output
		}
		if len(raw) == 0 {
			return nil, false
		}
		return nativeBroadcastFindStructuredContent(raw)
	}
	return nil, false
}

func nativeBroadcastFindStructuredContent(raw []byte) (map[string]any, bool) {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil, false
	}
	var visit func(any, int) (map[string]any, bool)
	visit = func(value any, depth int) (map[string]any, bool) {
		if depth > 5 {
			return nil, false
		}
		switch typed := value.(type) {
		case map[string]any:
			if _, hasMessages := typed["messages"]; hasMessages {
				return typed, true
			}
			if approvalID, ok := typed["approval_id"].(string); ok && approvalID != "" &&
				typed["proof"] == "verified_client_signature_and_recorded_owner_device_enrollment" {
				if _, hasBody := typed["body"].(string); hasBody {
					return typed, true
				}
			}
			if typed["operation"] == "monitor_broadcast" {
				status, hasStatus := typed["status"].(string)
				broadcastID, hasBroadcastID := typed["broadcast_id"].(string)
				if hasStatus && status != "" && hasBroadcastID && broadcastID != "" {
					return typed, true
				}
			}
			for _, key := range []string{"structuredContent", "structured_content", "result", "output"} {
				if nested, exists := typed[key]; exists {
					if found, ok := visit(nested, depth+1); ok {
						return found, true
					}
				}
			}
			if content, ok := typed["content"].([]any); ok {
				for _, item := range content {
					if part, ok := item.(map[string]any); ok {
						if text, ok := part["text"].(string); ok {
							if found, ok := visitJSONText(text, visit, depth+1); ok {
								return found, true
							}
						}
					}
				}
			}
		case []any:
			for _, item := range typed {
				if found, ok := visit(item, depth+1); ok {
					return found, true
				}
			}
		case string:
			return visitJSONText(typed, visit, depth+1)
		}
		return nil, false
	}
	return visit(value, 0)
}

func visitJSONText(value string, visit func(any, int) (map[string]any, bool), depth int) (map[string]any, bool) {
	var decoded any
	if json.Unmarshal([]byte(value), &decoded) != nil {
		return nil, false
	}
	return visit(decoded, depth+1)
}

func nativeBroadcastReceiveResultMatches(result map[string]any, messageID, body,
	senderEndpointID string) bool {
	messages, ok := result["messages"].([]any)
	if !ok || len(messages) != 1 {
		return false
	}
	message, ok := messages[0].(map[string]any)
	if !ok {
		return false
	}
	return message["message_id"] == messageID && message["body"] == body &&
		message["kind"] == "SEND" && nativeBroadcastOptionalFieldEmpty(message, "request_id") &&
		nativeBroadcastOptionalFieldEmpty(message, "reply_to") &&
		message["sender_endpoint_id"] == senderEndpointID
}

func nativeBroadcastOptionalFieldEmpty(message map[string]any, key string) bool {
	value, exists := message[key]
	if !exists {
		return true
	}
	stringValue, ok := value.(string)
	return ok && stringValue == ""
}
