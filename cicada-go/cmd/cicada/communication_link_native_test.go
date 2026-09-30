package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative uses real Codex
// Threads owned by separate users, the existing bilateral CommunicationLink
// fixture, the real MCP tools, and the production Node sealed-delivery path.
// It uses two logical Nodes and one disposable Hub in-process; it does not
// claim separate-host isolation or automatic wake of a cold Codex Thread.
// See docs/architecture-v2-native-validation.md for the opt-in native result
// and the synthetic post-Join Link authorization preflight.
// Ordinary runs without opt-in remain a Skip.
func TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative(t *testing.T) {
	if strings.TrimSpace(os.Getenv("CICADA_CROSS_OWNER_NATIVE_E2E")) != "1" {
		t.Skip("set CICADA_CROSS_OWNER_NATIVE_E2E=1 to run the real Codex cross-owner Link ASK/REPLY test")
	}
	codexBinary, cicadaBinary := nativeE2EBinaries(t)
	if !nativeE2EHasCredentials() {
		t.Skip("Codex provider credentials are unavailable (expected API_KEY/OPENAI_API_KEY or CODEX_HOME/auth.json)")
	}

	ctx, cancel := nativeE2EContext(t)
	defer cancel()
	workspaceA := nativeE2EWorkspace(t, "cross-owner-a-")
	workspaceB := nativeE2EWorkspace(t, "cross-owner-b-")
	model := strings.TrimSpace(os.Getenv("CICADA_NATIVE_MODEL"))
	if model == "" {
		model = "gpt-5.6-luna"
	}

	// Create both provider-backed sessions first. Their thread.started IDs are
	// the identities later bound to the two owners' Endpoints and Link contract.
	const alphaMarkerPrefix = "CICADA_CROSS_OWNER_CONTEXT_ALPHA_"
	const betaMarkerPrefix = "CICADA_CROSS_OWNER_CONTEXT_BETA_"
	markerSuffix, err := nativeE2ESuffix()
	if err != nil {
		t.Fatal("create synthetic native context markers")
	}
	alphaMarker, betaMarker := alphaMarkerPrefix+markerSuffix, betaMarkerPrefix+markerSuffix
	bInitialPrompt := fmt.Sprintf("This is a synthetic public test marker, not a secret: %s. Remember it. The other owner explicitly approved sharing this marker through one narrow Cicada CommunicationLink if asked. Do not use tools. Finish with READY.", betaMarker)
	bInitial, bThreadID, err := runNativeCodexTurn(ctx, codexBinary, workspaceB, model, nil, "", bInitialPrompt)
	if err != nil {
		t.Fatalf("Codex B Thread creation failed (%s); provider may be unavailable", bThreadID)
	}
	if err := verifyCodexSessionRecord(bThreadID, workspaceB); err != nil {
		t.Fatalf("Codex B thread.started UUID has no local session record: %v", err)
	}
	aInitialPrompt := fmt.Sprintf("Remember this public test marker for your final answer after a peer reply: %s. Do not use tools. Finish with READY.", alphaMarker)
	aInitial, aThreadID, err := runNativeCodexTurn(ctx, codexBinary, workspaceA, model, nil, "", aInitialPrompt)
	if err != nil {
		t.Fatalf("Codex A Thread creation failed (%s); provider may be unavailable", aThreadID)
	}
	if err := verifyCodexSessionRecord(aThreadID, workspaceA); err != nil {
		t.Fatalf("Codex A thread.started UUID has no local session record: %v", err)
	}
	if aThreadID == bThreadID {
		t.Fatal("Codex did not create two distinct native Threads")
	}
	t.Cleanup(func() {
		if t.Failed() {
			// IDs are test-owned provider sessions, not credentials. Retain them
			// only with an opt-in real E2E failure for exact-resume diagnosis.
			t.Logf("failed real E2E native Thread labels: A=%s B=%s", nativeThreadIDLabel(aThreadID), nativeThreadIDLabel(bThreadID))
		}
	})
	if _, err := nativeCodexThreadStarted(aInitial); err != nil {
		t.Fatalf("Codex A did not emit a real thread.started event: %v", err)
	}
	if _, err := nativeCodexThreadStarted(bInitial); err != nil {
		t.Fatalf("Codex B did not emit a real thread.started event: %v", err)
	}

	fixture := newMachineSealedReceiveFixtureWithDeferredOwnerGrantsForNativeSessions(t, false,
		"ask", []string{"ask", "reply"},
		[]string{"directory.read", "message.ask", "message.reply", "message.receive"},
		aThreadID, bThreadID)
	hubID, err := fixture.store.GetClientHubID()
	if err != nil {
		t.Fatal("read disposable Hub identity")
	}
	nodeTokens := map[string]string{
		fixture.sourceNodeID: fixture.sourceToken,
		fixture.targetNodeID: fixture.targetToken,
	}
	privateText := []string{
		alphaMarker, betaMarker,
		"synthetic cross-owner question " + markerSuffix,
		"synthetic cross-owner reply " + markerSuffix,
	}
	var captureMu sync.Mutex
	var hubPaths, unexpectedPaths []string
	var hubRouteStatuses []string
	var nodeCredentialsSeen = map[string]bool{}
	var hubSawPlaintext bool
	var controlBusinessCalls int
	var askWire fabric.NodeSealedLinkAskInput
	var replyWire fabric.NodeSealedLinkReplyInput
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		captureMu.Lock()
		statuses := append([]string(nil), hubRouteStatuses...)
		captureMu.Unlock()
		if len(statuses) != 0 {
			t.Logf("disposable Hub method/path/status trace: %s", strings.Join(statuses, "; "))
		}
	})
	fabricHandler := serverpkg.NewFabricHandler(fixture.service, "")
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024+1))
		_ = r.Body.Close()
		if readErr != nil || len(body) > 2*1024*1024 {
			http.Error(w, "invalid request", http.StatusRequestEntityTooLarge)
			return
		}
		path := r.URL.Path
		allowed := nativeCrossOwnerHubPathAllowed(path)
		captureMu.Lock()
		if strings.HasPrefix(path, "/v2/control/") {
			controlBusinessCalls++
		}
		hubPaths = append(hubPaths, r.Method+" "+path)
		if !allowed {
			unexpectedPaths = append(unexpectedPaths, r.Method+" "+path)
		}
		for _, value := range privateText {
			if value != "" && bytes.Contains(body, []byte(value)) {
				hubSawPlaintext = true
			}
		}
		if strings.HasPrefix(path, "/v2/relay/nodes/") {
			for nodeID, token := range nodeTokens {
				if r.Header.Get("Authorization") == "CicadaNode "+token {
					nodeCredentialsSeen[nodeID] = true
				}
			}
		}
		if strings.HasSuffix(path, "/sealed/ask") && r.Method == http.MethodPost {
			if err := json.Unmarshal(body, &askWire); err != nil {
				unexpectedPaths = append(unexpectedPaths, "invalid CommunicationLink ASK envelope")
			}
		}
		if strings.HasSuffix(path, "/sealed/reply") && r.Method == http.MethodPost {
			if err := json.Unmarshal(body, &replyWire); err != nil {
				unexpectedPaths = append(unexpectedPaths, "invalid CommunicationLink REPLY envelope")
			}
		}
		captureMu.Unlock()
		if !allowed {
			captureMu.Lock()
			hubRouteStatuses = append(hubRouteStatuses, fmt.Sprintf("%s %s -> %d", r.Method, path, http.StatusNotFound))
			captureMu.Unlock()
			http.NotFound(w, r)
			return
		}

		recorder := httptest.NewRecorder()
		r.Body = io.NopCloser(bytes.NewReader(body))
		fabricHandler.ServeHTTP(recorder, r)
		responseBody := recorder.Body.Bytes()
		captureMu.Lock()
		hubRouteStatuses = append(hubRouteStatuses, fmt.Sprintf("%s %s -> %d", r.Method, path, recorder.Code))
		for _, value := range privateText {
			if value != "" && bytes.Contains(responseBody, []byte(value)) {
				hubSawPlaintext = true
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

	bridgeA, err := startMachineAgentJoinBridge(ctx, fixture.stateDir, hub.URL,
		fixture.sourceNodeID, fixture.sourceToken)
	if err != nil {
		t.Fatalf("start source owner's logical Node bridge: %v", err)
	}
	defer func() { _ = bridgeA.Close() }()
	bridgeB, err := startMachineAgentJoinBridge(ctx, fixture.stateDir, hub.URL,
		fixture.targetNodeID, fixture.targetToken)
	if err != nil {
		t.Fatalf("start target owner's logical Node bridge: %v", err)
	}
	defer func() { _ = bridgeB.Close() }()

	t.Setenv("CICADA_HUB_ID", hubID)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	t.Setenv("CICADA_NODE_TOKEN", "")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CICADA_CODEX_BIN", codexBinary)
	mcpStateA, mcpStateB := t.TempDir(), t.TempDir()
	configA := nativeCrossOwnerNativeCodexConfig(cicadaBinary, hub.URL, fixture.stateDir, mcpStateA,
		fixture.sourceNodeID, aThreadID)
	configB := nativeCrossOwnerNativeCodexConfig(cicadaBinary, hub.URL, fixture.stateDir, mcpStateB,
		fixture.targetNodeID, bThreadID)

	joinNative := func(workspace, nativeID, groupID string, config []string) ([]byte, string, error) {
		t.Helper()
		prompt := fmt.Sprintf("You are at a controlled safe point in this existing Thread. The owner has already prepared the Cicada Group. Use the directly available Cicada MCP tool cicada_join exactly once with group_id %q; do not call cicada_ask or cicada_reply. Do not finish the turn until cicada_join returns, then finish with READY.", groupID)
		output, resumedID, turnErr := runNativeCodexTurn(ctx, codexBinary, workspace, model, config, nativeID, prompt)
		if turnErr == nil && !nativeCrossNodeToolCompleted(output, "cicada_join") &&
			!nativeCrossNodeToolAttempted(output, "") {
			prompt = fmt.Sprintf("Your previous turn made no Cicada tool call. Continue this same existing Thread. The Cicada tools are directly available: call cicada_join exactly once with group_id %q now. Do not finish or create another Thread before the call returns; then finish with READY.", groupID)
			return runNativeCodexTurn(ctx, codexBinary, workspace, model, config, nativeID, prompt)
		}
		return output, resumedID, turnErr
	}

	bJoined, resumedBID, err := joinNative(workspaceB, bThreadID, fixture.link.TargetGroupID, configB)
	if err != nil {
		t.Fatalf("Codex B exact-session Join failed (%s); events=%s; tool_failures=%s", nativeThreadIDLabel(resumedBID),
			nativeE2EEventSummary(bJoined), nativeE2EToolFailures(bJoined))
	}
	if resumedBID != bThreadID || verifyCodexSessionRecord(resumedBID, workspaceB) != nil {
		t.Fatal("Codex B Join did not retain its original native Thread")
	}
	nativeCrossNodeRequireToolCompleted(t, bJoined, "cicada_join")
	bEndpoint, err := nativeE2ECurrentSession(fixture.store, bThreadID, workspaceB,
		fixture.targetNodeID, fixture.link.TargetGroupID)
	if err != nil || bEndpoint.ID != fixture.targetEndpoint {
		t.Fatalf("B's original native Thread did not Join its owner's Group/Endpoint: endpoint=%#v err=%v", bEndpoint, err)
	}
	aJoined, resumedAID, err := joinNative(workspaceA, aThreadID, fixture.link.SourceGroupID, configA)
	if err != nil {
		t.Fatalf("Codex A exact-session Join failed (%s); events=%s; tool_failures=%s", nativeThreadIDLabel(resumedAID),
			nativeE2EEventSummary(aJoined), nativeE2EToolFailures(aJoined))
	}
	if resumedAID != aThreadID || verifyCodexSessionRecord(resumedAID, workspaceA) != nil {
		t.Fatal("Codex A Join did not retain its original native Thread")
	}
	nativeCrossNodeRequireToolCompleted(t, aJoined, "cicada_join")
	aEndpoint, err := nativeE2ECurrentSession(fixture.store, aThreadID, workspaceA,
		fixture.sourceNodeID, fixture.link.SourceGroupID)
	if err != nil || aEndpoint.ID != fixture.sourceEndpoint || aEndpoint.ID == bEndpoint.ID {
		t.Fatalf("A's original native Thread did not Join its separate owner's Group/Endpoint: endpoint=%#v err=%v", aEndpoint, err)
	}
	if aEndpoint.Owner == bEndpoint.Owner || fixture.link.SourceOwnerID == fixture.link.TargetOwnerID {
		t.Fatal("CommunicationLink endpoints do not belong to separate owners")
	}
	currentManifest := nativeCrossOwnerRecordCurrentOwnerGrants(t, fixture, aEndpoint, bEndpoint)
	nativeCrossOwnerRequireHTTPAuthorizationBundle(t, hub.URL, fixture.sourceNodeID,
		fixture.sourceToken, fixture.link.ID, currentManifest.Digest)
	nativeCrossOwnerRequireHTTPAuthorizationBundle(t, hub.URL, fixture.targetNodeID,
		fixture.targetToken, fixture.link.ID, currentManifest.Digest)

	question := "synthetic cross-owner question " + markerSuffix
	// B must recall this value from its initial native Thread turn. Do not put
	// the marker literal into a later B prompt; that would not prove continuity.
	answer := betaMarker
	askPrompt := fmt.Sprintf("Call cicada_ask exactly once with link_id %q, data_scope %q, and question %q. Do not wait for the answer in this turn. Finish with ACCEPTED.",
		fixture.link.ID, fixture.dataScope, question)
	aAsked, askedThreadID, err := runNativeCodexTurn(ctx, codexBinary, workspaceA, model, configA, aThreadID, askPrompt)
	if err != nil {
		t.Fatalf("Codex A exact-session Link ASK failed (%s); events=%s; tool_failures=%s", nativeThreadIDLabel(askedThreadID),
			nativeE2EEventSummary(aAsked), nativeE2EToolFailures(aAsked))
	}
	if !nativeCrossNodeToolCompleted(aAsked, "cicada_ask") && !nativeCrossNodeToolAttempted(aAsked, "") {
		askPrompt = fmt.Sprintf("Your preceding turn made no tool call. In this same existing Thread, call cicada_ask once with link_id %q, data_scope %q, and question %q. Finish with ACCEPTED after the tool returns.",
			fixture.link.ID, fixture.dataScope, question)
		aAsked, askedThreadID, err = runNativeCodexTurn(ctx, codexBinary, workspaceA, model, configA, aThreadID, askPrompt)
		if err != nil {
			t.Fatalf("Codex A did not submit Link ASK after no-call follow-up (%s); events=%s; tool_failures=%s", nativeThreadIDLabel(askedThreadID),
				nativeE2EEventSummary(aAsked), nativeE2EToolFailures(aAsked))
		}
	}
	if askedThreadID != aThreadID || verifyCodexSessionRecord(askedThreadID, workspaceA) != nil {
		t.Fatal("Codex A Link ASK did not continue the original native Thread")
	}
	nativeCrossNodeRequireToolCompleted(t, aAsked, "cicada_ask")
	captureMu.Lock()
	askSnapshot := askWire
	captureMu.Unlock()
	if askSnapshot.MessageID == "" || askSnapshot.RequestID == "" || askSnapshot.LinkID != fixture.link.ID ||
		askSnapshot.DataScope != fixture.dataScope {
		t.Fatal("Hub did not durably accept a scoped cross-owner sealed ASK from A's real Thread")
	}
	askRecord, err := fixture.store.GetRelaySealedV1(askSnapshot.MessageID)
	if err != nil || askRecord == nil || askRecord.PayloadMode != store.RelayPayloadModeSealedV1 ||
		askRecord.Route.Kind != "ask" || askRecord.Route.RequestID != askSnapshot.RequestID ||
		bytes.Contains(askRecord.Ciphertext, []byte(question)) {
		t.Fatal("Hub database does not contain the opaque cross-owner ASK ciphertext")
	}
	if err := nativeE2EAssertDatabasePrivateTextAbsent(fixture.databasePath, question, alphaMarker, betaMarker); err != nil {
		t.Fatalf("Hub database plaintext check failed: %v", err)
	}

	// The official Codex queue command durably adds the message to this exact
	// Thread. Queue acceptance is not treated as model consumption: the test
	// records the Node receipt, then resumes the same Thread at a controlled
	// safe point and requires a real MCP receive/reply turn.
	t.Setenv("CICADA_NODE_TOKEN", fixture.targetToken)
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	bInbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
	if err != nil {
		t.Fatal("open target Node durable inbox")
	}
	if err := processPinnedTestMachineFabricDeliveries(ctx, hub.URL, fixture.targetNodeID, bInbox, fixture.stateDir); err != nil {
		_ = bInbox.Close()
		t.Fatalf("target Node failed to queue the sealed ASK to B's original Thread: %v", err)
	}
	bDelivery, deliveryErr := bInbox.Get(ctx, askSnapshot.MessageID)
	bBinding, bindingErr := fixture.store.GetSessionBindingByNativeSession(bThreadID)
	if bindingErr != nil || bBinding == nil {
		_ = bInbox.Close()
		t.Fatalf("target Node Thread has no current B SessionBinding: %v", bindingErr)
	}
	bVisible, listErr := bInbox.ListInjectedForSession(ctx, fixture.targetEndpoint, bThreadID,
		bBinding.Epoch, fixture.link.TargetGroupID, 0, 8)
	_ = bInbox.Close()
	if deliveryErr != nil || listErr != nil || bDelivery == nil ||
		bDelivery.SessionID != bThreadID || bDelivery.EndpointID != fixture.targetEndpoint ||
		bDelivery.State != nodeinbox.CONSUMPTION_UNCONFIRMED || len(bVisible) != 1 ||
		bVisible[0].MessageID != askSnapshot.MessageID || !strings.Contains(bVisible[0].Body, question) {
		t.Fatal("target Node did not persist the request for the exact B Thread with consumption unconfirmed")
	}

	bReplyPrompt := fmt.Sprintf("At this controlled safe point, resume this same existing Thread after the Cicada request was queued. Select Group %q with cicada_use_group, call cicada_receive, then reply once using cicada_reply with the received request_id, link_id %q, and the synthetic marker you remembered from your original context. Do not create a Thread or use shell. Finish with the reply marker.",
		fixture.link.TargetGroupID, fixture.link.ID)
	bReplied, replyThreadID, err := runNativeCodexTurn(ctx, codexBinary, workspaceB, model, configB, bThreadID, bReplyPrompt)
	if err != nil {
		t.Fatalf("Codex B exact-session receive/reply failed (%s); events=%s; tool_failures=%s", nativeThreadIDLabel(replyThreadID),
			nativeE2EEventSummary(bReplied), nativeE2EToolFailures(bReplied))
	}
	bReceived := nativeCrossNodeToolCompleted(bReplied, "cicada_receive")
	if !nativeCrossNodeToolCompleted(bReplied, "cicada_reply") &&
		!nativeCrossNodeToolAttempted(bReplied, "cicada_reply") && bReceived {
		bReplyPrompt = fmt.Sprintf("Continue this existing Thread after the Cicada receive. Reply once with cicada_reply using request_id %q, link_id %q, and the synthetic marker you remembered from your original context.",
			askSnapshot.RequestID, fixture.link.ID)
		bReplied, replyThreadID, err = runNativeCodexTurn(ctx, codexBinary, workspaceB, model, configB, bThreadID, bReplyPrompt)
		if err != nil {
			t.Fatalf("Codex B did not submit Link REPLY after no-reply follow-up (%s); events=%s; tool_failures=%s", nativeThreadIDLabel(replyThreadID),
				nativeE2EEventSummary(bReplied), nativeE2EToolFailures(bReplied))
		}
	}
	if replyThreadID != bThreadID || verifyCodexSessionRecord(replyThreadID, workspaceB) != nil {
		t.Fatal("Codex B Link REPLY did not continue its original native Thread")
	}
	if !bReceived {
		t.Fatal("Codex B did not complete cicada_receive before its reply")
	}
	nativeCrossNodeRequireToolCompleted(t, bReplied, "cicada_reply")
	if !nativeE2EResultContains(bReplied, betaMarker) {
		t.Fatal("Codex B reply turn did not retain its original native context marker")
	}
	captureMu.Lock()
	replySnapshot := replyWire
	captureMu.Unlock()
	if replySnapshot.MessageID == "" || replySnapshot.RequestID != askSnapshot.RequestID {
		t.Fatal("B's MCP cicada_reply did not create the correlated sealed Link reply")
	}
	requestStatus, err := fixture.service.NodeSealedLinkRequestStatus(fixture.sourceToken, askSnapshot.RequestID)
	if err != nil || requestStatus == nil || requestStatus.State != store.FabricRequestReplied ||
		requestStatus.ReplyMessageID != replySnapshot.MessageID {
		t.Fatal("Hub did not retain B's correlated Link reply to A's request")
	}
	replyRecord, err := fixture.store.GetRelaySealedV1(replySnapshot.MessageID)
	if err != nil || replyRecord == nil || replyRecord.PayloadMode != store.RelayPayloadModeSealedV1 ||
		replyRecord.Route.Kind != "reply" || replyRecord.Route.RequestID != askSnapshot.RequestID ||
		replyRecord.Route.ReplyTo != askSnapshot.MessageID || bytes.Contains(replyRecord.Ciphertext, []byte(answer)) {
		t.Fatal("Hub database does not contain the opaque correlated Link REPLY ciphertext")
	}
	if err := nativeE2EAssertDatabasePrivateTextAbsent(fixture.databasePath, question, answer, alphaMarker, betaMarker); err != nil {
		t.Fatalf("Hub database plaintext check after REPLY failed: %v", err)
	}

	t.Setenv("CICADA_NODE_TOKEN", fixture.sourceToken)
	aInbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.sourceNodeID))
	if err != nil {
		t.Fatal("open source Node durable inbox")
	}
	if err := processPinnedTestMachineFabricDeliveries(ctx, hub.URL, fixture.sourceNodeID, aInbox, fixture.stateDir); err != nil {
		_ = aInbox.Close()
		t.Fatalf("source Node failed to queue B's reply to A's original Thread: %v", err)
	}
	aBinding, bindingErr := fixture.store.GetSessionBindingByNativeSession(aThreadID)
	if bindingErr != nil || aBinding == nil {
		_ = aInbox.Close()
		t.Fatalf("source Node Thread has no current A SessionBinding: %v", bindingErr)
	}
	aVisible, listErr := aInbox.ListInjectedForSession(ctx, fixture.sourceEndpoint, aThreadID,
		aBinding.Epoch, fixture.link.SourceGroupID, 0, 8)
	_ = aInbox.Close()
	if listErr != nil || len(aVisible) != 1 ||
		aVisible[0].MessageID != replySnapshot.MessageID || !strings.Contains(aVisible[0].Body, answer) {
		t.Fatal("source Node did not inject B's correlated reply into A's original Link-scoped Thread")
	}
	aResumePrompt := "Continue this original task using the newly queued Cicada reply. Preserve your own original context and report both public test markers. Do not create another Thread or use shell."
	aResumed, finalThreadID, err := runNativeCodexTurn(ctx, codexBinary, workspaceA, model, configA, aThreadID, aResumePrompt)
	if err != nil {
		t.Fatalf("Codex A exact-session resume after Link reply failed (%s)", nativeThreadIDLabel(finalThreadID))
	}
	if finalThreadID != aThreadID || verifyCodexSessionRecord(finalThreadID, workspaceA) != nil {
		t.Fatal("Codex A did not resume its original native Thread after the Link reply")
	}
	if !nativeE2EResultContains(aResumed, alphaMarker) || !nativeE2EResultContains(aResumed, betaMarker) {
		t.Fatal("Codex A final answer did not retain its original context and B's Link reply")
	}

	captureMu.Lock()
	paths := append([]string(nil), hubPaths...)
	unexpected := append([]string(nil), unexpectedPaths...)
	plaintextSeen := hubSawPlaintext
	controlCalls := controlBusinessCalls
	nodesSeen := map[string]bool{
		fixture.sourceNodeID: nodeCredentialsSeen[fixture.sourceNodeID],
		fixture.targetNodeID: nodeCredentialsSeen[fixture.targetNodeID],
	}
	captureMu.Unlock()
	if plaintextSeen {
		t.Fatal("Hub HTTP boundary observed cross-owner peer plaintext")
	}
	if len(unexpected) != 0 {
		t.Fatalf("cross-owner Link path used an unexpected Hub route: %v", unexpected)
	}
	if controlCalls != 0 {
		t.Fatalf("cross-owner peer ASK/REPLY invoked Control business HTTP %d times", controlCalls)
	}
	if !nodesSeen[fixture.sourceNodeID] || !nodesSeen[fixture.targetNodeID] {
		t.Fatal("both owner-bound Nodes did not independently authenticate to the shared Hub")
	}
	for _, suffix := range []string{"/links/" + fixture.link.ID + "/authorization", "/sealed/ask", "/sealed/reply", "/sealed/claim"} {
		if !nativeCrossNodeContainsPath(paths, suffix) {
			t.Fatalf("real cross-owner path did not exercise the Link sealed route %q", suffix)
		}
	}
	for _, forbidden := range []string{"/v2/fabric/send", "/v2/fabric/ask", "/v2/fabric/reply", "/v2/fabric/receive", "/v2/control/"} {
		if nativeCrossNodeContainsPath(paths, forbidden) {
			t.Fatalf("cross-owner peer path reached a plaintext, legacy receive, or Control route: %s", forbidden)
		}
	}
	t.Logf("real Codex cross-owner CommunicationLink ASK/REPLY passed: A owner=%s endpoint=%s thread=%s; B owner=%s endpoint=%s thread=%s; request=%s reply=%s; Node queue acceptance was followed by exact-thread resume for observed model consumption",
		fixture.link.SourceOwnerID, aEndpoint.ID, nativeThreadIDLabel(aThreadID),
		fixture.link.TargetOwnerID, bEndpoint.ID, nativeThreadIDLabel(bThreadID), askSnapshot.RequestID, replySnapshot.MessageID)
}

func nativeCrossOwnerNativeCodexConfig(binary, apiURL, stateDir, mcpStateDir, nodeID, nativeThreadID string) []string {
	config := nativeCodexConfig(binary, apiURL, stateDir, mcpStateDir, nodeID, true, nativeThreadID)
	codexHome := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if codexHome == "" {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			codexHome = filepath.Join(home, ".codex")
		}
	}
	if codexHome != "" {
		config = append(config, "--config", fmt.Sprintf("mcp_servers.cicada.env.CODEX_HOME=%q", codexHome))
	}
	// Codex may defer MCP tools behind tool search. Expose the server's tools
	// directly so the controlled Join/ASK/REPLY prompts can invoke them.
	return append(config, "--config", `mcp_servers.cicada.omit_tools_from=["deferred"]`)
}

func nativeThreadIDLabel(value string) string {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return value
	}
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:8])
}

func nativeCrossOwnerRecordCurrentOwnerGrants(t *testing.T, fixture *machineSealedReceiveFixture,
	sourceEndpoint, targetEndpoint *store.Endpoint) *store.CommunicationLinkKeyManifest {
	t.Helper()
	if fixture == nil || fixture.sourceOwnerIdentity == nil || fixture.targetOwnerIdentity == nil {
		t.Fatal("synthetic owner approval identities are unavailable")
	}
	manifest, err := fixture.store.GetCommunicationLinkKeyManifest(fixture.link.ID, fixture.link.SourceOwnerID)
	if err != nil {
		t.Fatalf("read post-Join CommunicationLink key manifest: %v", err)
	}
	sourceBinding, sourceBindingErr := fixture.store.GetSessionBindingForEndpoint(sourceEndpoint.ID)
	targetBinding, targetBindingErr := fixture.store.GetSessionBindingForEndpoint(targetEndpoint.ID)
	if sourceBindingErr != nil || targetBindingErr != nil {
		t.Fatal("read current SessionBindings for post-Join Link grant")
	}
	if manifest.Source.BindingID != sourceBinding.ID || manifest.Source.BindingEpoch != sourceBinding.Epoch ||
		manifest.Target.BindingID != targetBinding.ID || manifest.Target.BindingEpoch != targetBinding.Epoch {
		t.Fatal("post-Join manifest did not bind both real Threads' current SessionBindings")
	}
	linkExpiry, err := time.Parse(time.RFC3339, fixture.link.ExpiresAt)
	if err != nil {
		t.Fatal("parse synthetic Link expiry")
	}
	for _, owner := range []struct {
		ownerID  string
		keyID    string
		identity *e2ee.Identity
		side     e2ee.OwnerLinkGrantSide
	}{
		{fixture.link.SourceOwnerID, fixture.sourceOwnerKeyID, fixture.sourceOwnerIdentity, e2ee.OwnerLinkGrantSideSource},
		{fixture.link.TargetOwnerID, fixture.targetOwnerKeyID, fixture.targetOwnerIdentity, e2ee.OwnerLinkGrantSideTarget},
	} {
		proof, signErr := owner.identity.SignOwnerLinkKeyGrant(owner.ownerID, fixture.link.ID,
			fixture.link.ContractDigest, manifest.Digest, uint64(fixture.link.Version), owner.side,
			time.Now().UTC().Add(-time.Minute), linkExpiry)
		if signErr != nil {
			t.Fatalf("sign synthetic post-Join owner grant: %v", signErr)
		}
		if _, recordErr := fixture.store.RecordCommunicationLinkKeyGrant(owner.ownerID,
			fixture.link.ID, string(owner.side), owner.keyID, proof); recordErr != nil {
			t.Fatalf("record synthetic post-Join owner grant: %v", recordErr)
		}
	}
	for _, node := range []struct {
		token string
		owner string
	}{
		{fixture.sourceToken, fixture.link.SourceOwnerID},
		{fixture.targetToken, fixture.link.TargetOwnerID},
	} {
		bundle, bundleErr := fixture.service.NodeCommunicationLinkAuthorizationBundle(node.token, fixture.link.ID)
		if bundleErr != nil || bundle.Manifest.Digest != manifest.Digest || bundle.LinkState != store.CommunicationLinkProposed {
			t.Fatalf("post-Join Node authorization bundle is not current for owner %s", node.owner)
		}
	}
	return manifest
}

// TestSyntheticCrossOwnerLinkAuthorizationAfterJoin protects the native E2E
// fixture lifecycle without calling a model: each synthetic Node Join rotates
// its binding, current Endpoint candidates are republished, and owner proofs
// are signed only after the current manifest exists.
func TestSyntheticCrossOwnerLinkAuthorizationAfterJoin(t *testing.T) {
	fixture := newMachineSealedReceiveFixtureWithDeferredOwnerGrantsForNativeSessions(t, false,
		"ask", []string{"ask", "reply"},
		[]string{"directory.read", "message.ask", "message.reply", "message.receive"},
		"synthetic-native-source", "synthetic-native-target")
	hub := httptest.NewServer(serverpkg.NewFabricHandler(fixture.service, ""))
	defer hub.Close()
	sourceEndpoint := nativeCrossOwnerSyntheticJoinAndPublishCandidate(t, hub.URL, fixture,
		fixture.sourceNodeID, fixture.sourceToken, fixture.link.SourceGroupID,
		"synthetic-native-source", fixture.sourceKey)
	targetEndpoint := nativeCrossOwnerSyntheticJoinAndPublishCandidate(t, hub.URL, fixture,
		fixture.targetNodeID, fixture.targetToken, fixture.link.TargetGroupID,
		"synthetic-native-target", fixture.targetKey)
	manifest := nativeCrossOwnerRecordCurrentOwnerGrants(t, fixture, sourceEndpoint, targetEndpoint)
	nativeCrossOwnerRequireHTTPAuthorizationBundle(t, hub.URL, fixture.sourceNodeID,
		fixture.sourceToken, fixture.link.ID, manifest.Digest)
	nativeCrossOwnerRequireHTTPAuthorizationBundle(t, hub.URL, fixture.targetNodeID,
		fixture.targetToken, fixture.link.ID, manifest.Digest)
}

func nativeCrossOwnerSyntheticJoinAndPublishCandidate(t *testing.T, baseURL string,
	fixture *machineSealedReceiveFixture, nodeID, nodeToken, groupID, nativeSessionID string,
	identity *e2ee.Identity) *store.Endpoint {
	t.Helper()
	joinPayload, err := json.Marshal(struct {
		GroupID         string `json:"group_id"`
		Harness         string `json:"harness"`
		NativeSessionID string `json:"native_session_id"`
		Workspace       string `json:"workspace,omitempty"`
	}{
		GroupID: groupID, Harness: "codex", NativeSessionID: nativeSessionID,
		Workspace: "/tmp/" + nativeSessionID,
	})
	if err != nil {
		t.Fatal("encode synthetic Node Join")
	}
	joinRequest, err := http.NewRequest(http.MethodPost, baseURL+"/v2/fabric/node/join", bytes.NewReader(joinPayload))
	if err != nil {
		t.Fatal("create synthetic Node Join request")
	}
	joinRequest.Header.Set("Content-Type", "application/json")
	joinRequest.Header.Set("Authorization", "CicadaNode "+nodeToken)
	joinResponse, err := http.DefaultClient.Do(joinRequest)
	if err != nil {
		t.Fatal("send synthetic Node Join request")
	}
	defer joinResponse.Body.Close()
	if joinResponse.StatusCode != http.StatusCreated {
		t.Fatalf("synthetic Node Join returned HTTP %d", joinResponse.StatusCode)
	}
	var joined fabric.JoinResult
	if err := json.NewDecoder(joinResponse.Body).Decode(&joined); err != nil ||
		joined.SessionToken == "" || joined.BindingID == "" || joined.BindingEpoch == 0 {
		t.Fatal("synthetic Node Join returned an incomplete SessionBinding")
	}
	attestation, err := identity.SignEndpointKeyAttestation(joined.Endpoint.ID,
		joined.NetworkCard.PrincipalID, nodeID, joined.BindingID, joined.BindingEpoch)
	if err != nil {
		t.Fatal("sign synthetic current Endpoint key candidate")
	}
	keyPayload, err := json.Marshal(struct {
		Attestation json.RawMessage `json:"attestation"`
	}{Attestation: json.RawMessage(attestation)})
	if err != nil {
		t.Fatal("encode synthetic Endpoint key candidate")
	}
	keyRequest, err := http.NewRequest(http.MethodPost, baseURL+"/v2/fabric/endpoint-keys", bytes.NewReader(keyPayload))
	if err != nil {
		t.Fatal("create synthetic Endpoint key candidate request")
	}
	keyRequest.Header.Set("Content-Type", "application/json")
	keyRequest.Header.Set("Authorization", "CicadaSession "+joined.SessionToken)
	keyRequest.Header.Set("Cicada-Group-Scope", groupID)
	keyResponse, err := http.DefaultClient.Do(keyRequest)
	if err != nil {
		t.Fatal("send synthetic Endpoint key candidate request")
	}
	defer keyResponse.Body.Close()
	if keyResponse.StatusCode != http.StatusOK {
		t.Fatalf("synthetic Endpoint key candidate publication returned HTTP %d", keyResponse.StatusCode)
	}
	endpoint, err := fixture.store.GetEndpointV2(joined.Endpoint.ID)
	if err != nil || endpoint.BindingID != joined.BindingID || endpoint.NativeSessionID != nativeSessionID {
		t.Fatal("synthetic Node Join did not retain its current Endpoint binding")
	}
	return endpoint
}

func nativeCrossOwnerRequireHTTPAuthorizationBundle(t *testing.T, baseURL, nodeID, nodeToken,
	linkID, expectedManifestDigest string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+"/v2/relay/nodes/"+nodeID+
		"/links/"+linkID+"/authorization", nil)
	if err != nil {
		t.Fatal("create current Link authorization preflight request")
	}
	request.Header.Set("Authorization", "CicadaNode "+nodeToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal("send current Link authorization preflight request")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("post-Join Link authorization HTTP preflight returned %d", response.StatusCode)
	}
	var bundle store.CommunicationLinkAuthorizationBundle
	if err := json.NewDecoder(response.Body).Decode(&bundle); err != nil ||
		bundle.Manifest.Digest != expectedManifestDigest || bundle.LinkState != store.CommunicationLinkProposed ||
		bundle.SourceGrant.CurrentStatus != store.CommunicationLinkKeyGrantAccepted ||
		bundle.TargetGrant.CurrentStatus != store.CommunicationLinkKeyGrantAccepted {
		t.Fatal("post-Join Link authorization HTTP preflight returned stale or incomplete evidence")
	}
}

func nativeCrossOwnerHubPathAllowed(path string) bool {
	if strings.HasPrefix(path, "/v2/control/") || path == "/v2/fabric/send" ||
		path == "/v2/fabric/ask" || path == "/v2/fabric/reply" || path == "/v2/fabric/receive" {
		return false
	}
	if strings.HasPrefix(path, "/v2/fabric/") {
		return true
	}
	if !strings.HasPrefix(path, "/v2/relay/nodes/") {
		return false
	}
	return strings.Contains(path, "/links/") || strings.Contains(path, "/sealed/") ||
		strings.HasSuffix(path, "/claim") || strings.HasSuffix(path, "/receipts")
}
