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
	"github.com/cicada-ai/cicada/internal/nodekeys"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestMCPSealedCrossNodeGroupAskReplyNative runs the cross-Node ASK/REPLY path
// with two real Codex Threads and two independent logical Node state roots.
// Run it inside the Cicada Docker development environment with
// CICADA_CROSS_NODE_NATIVE_E2E=1. This test does not claim physical machine or
// kernel isolation; both logical Nodes use one process and one test Hub.
//
// It creates persistent Codex Threads and makes real provider calls, so it is
// opt-in. The test records native IDs only from thread.started and verifies
// each ID against Codex's local session record before Join and after resume.
func TestMCPSealedCrossNodeGroupAskReplyNative(t *testing.T) {
	if strings.TrimSpace(os.Getenv("CICADA_CROSS_NODE_NATIVE_E2E")) != "1" {
		t.Skip("set CICADA_CROSS_NODE_NATIVE_E2E=1 to run the real Codex cross-Node sealed ASK/REPLY test")
	}
	codexBinary, cicadaBinary := nativeE2EBinaries(t)
	if !nativeE2EHasCredentials() {
		t.Skip("Codex provider credentials are unavailable (expected API_KEY/OPENAI_API_KEY or CODEX_HOME/auth.json)")
	}

	suffix, err := nativeE2ESuffix()
	if err != nil {
		t.Fatal("create isolated native test identities")
	}
	ownerID := "owner_native_cross_node_" + suffix
	groupID := "group_native_cross_node_" + suffix
	// Unix-domain socket paths are capped (108 bytes on Linux). The test's
	// isolated temp root already supplies uniqueness, so keep Node IDs short.
	nodeA := "na_" + suffix[:8]
	nodeB := "nb_" + suffix[:8]
	if nodeA == nodeB {
		t.Fatal("logical Nodes must have distinct stable identities")
	}

	workspaceA := nativeE2EWorkspace(t, "cross-node-a-")
	workspaceB := nativeE2EWorkspace(t, "cross-node-b-")
	stateDirA, stateDirB := t.TempDir(), t.TempDir()
	mcpStateA, mcpStateB := t.TempDir(), t.TempDir()
	if stateDirA == stateDirB || mcpStateA == mcpStateB {
		t.Fatal("logical Nodes must not share local or MCP state directories")
	}

	databasePath := filepath.Join(t.TempDir(), "cross-node-hub.sqlite3")
	persistence, err := store.New(databasePath)
	if err != nil {
		t.Fatal("create disposable Hub Store")
	}
	t.Cleanup(func() { _ = persistence.Close() })
	owner, err := persistence.CreatePrincipal(store.Principal{
		ID: ownerID, Kind: store.PrincipalKindHuman, OwnerID: ownerID,
		TrustDomainID: ownerID, Name: "Disposable native cross-Node owner",
	})
	if err != nil {
		t.Fatal("create disposable owner")
	}
	group, err := persistence.CreateGroup(store.Group{
		ID: groupID, Name: "Disposable native cross-Node Group",
		OwnerPrincipalID: owner.ID, TrustDomainID: owner.TrustDomainID,
		State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal("create disposable Group")
	}

	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("create disposable owner signing key")
	}
	ownerKey, err := persistence.RegisterOwnerApprovalKeyLocal(ownerID, ownerIdentity.Public())
	if err != nil {
		t.Fatal("register disposable owner signing key")
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal("read test Hub identity")
	}
	clientIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("create disposable Node enrollment device")
	}
	deviceID := "client_native_cross_node_" + suffix
	deviceGrant, err := ownerIdentity.SignOwnerDeviceGrant(ownerID, deviceID,
		clientIdentity.Public(), hubID, e2ee.OwnerDevicePurposeControl,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal("sign disposable Node enrollment grant")
	}
	if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: ownerKey.KeyID, DeviceID: deviceID,
		DevicePublic: clientIdentity.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		t.Fatal("register disposable Node enrollment device")
	}
	bindNode := func(nodeID string) string {
		t.Helper()
		token, digest, err := fabric.NewNodeCredential()
		if err != nil {
			t.Fatal("create disposable Node credential")
		}
		code, err := nativeE2ESuffix()
		if err != nil {
			t.Fatal("create disposable Node confirmation code")
		}
		codeDigest := sha256.Sum256([]byte("native-cross-node-e2e-" + code))
		encodedDigest := hex.EncodeToString(codeDigest[:])
		if _, err := persistence.CreatePendingNodeDeviceBinding(nodeID, nodeID, digest,
			encodedDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
			t.Fatal("create disposable pending Node binding")
		}
		if _, err := persistence.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, encodedDigest); err != nil {
			t.Fatal("confirm disposable Node binding")
		}
		return token
	}
	tokenA, tokenB := bindNode(nodeA), bindNode(nodeB)
	service, err := fabric.NewService(persistence, ownerID, owner.TrustDomainID)
	if err != nil {
		t.Fatal("create Hub Fabric service")
	}
	fabricHandler := serverpkg.NewFabricHandler(service, "")

	alphaMarker := "CICADA_CROSS_NODE_CONTEXT_ALPHA_" + suffix
	betaMarker := "CICADA_CROSS_NODE_CONTEXT_BETA_" + suffix
	question := "What public end-to-end test marker did the user give you when this thread started? Reply with that marker only."
	privateText := []string{alphaMarker, betaMarker, question}
	var captureMu sync.Mutex
	var hubPaths []string
	var unexpectedPaths []string
	var hubSawPlaintext bool
	var controlBusinessCalls int
	var askRequest fabric.NodeSameGroupSealedV1AskInput
	var replyRequest fabric.NodeSameGroupSealedV1ReplyInput
	var nodeCredentialsSeen = map[string]bool{}
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024+1))
		_ = r.Body.Close()
		if readErr != nil || len(body) > 2*1024*1024 {
			http.Error(w, "invalid request", http.StatusRequestEntityTooLarge)
			return
		}
		path := r.URL.Path
		allowed := nativeCrossNodeHubPathAllowed(path)
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
			switch r.Header.Get("Authorization") {
			case "CicadaNode " + tokenA:
				nodeCredentialsSeen[nodeA] = true
			case "CicadaNode " + tokenB:
				nodeCredentialsSeen[nodeB] = true
			}
		}
		if strings.HasSuffix(path, "/group/sealed/ask") && r.Method == http.MethodPost {
			if err := json.Unmarshal(body, &askRequest); err != nil {
				unexpectedPaths = append(unexpectedPaths, "invalid same-Group ASK envelope")
			}
		}
		if strings.HasSuffix(path, "/group/sealed/reply") && r.Method == http.MethodPost {
			if err := json.Unmarshal(body, &replyRequest); err != nil {
				unexpectedPaths = append(unexpectedPaths, "invalid same-Group REPLY envelope")
			}
		}
		captureMu.Unlock()

		// Inspect both directions at the Hub boundary while preserving the real
		// Fabric handler response and headers.
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

	ctx, cancel := nativeE2EContext(t)
	defer cancel()
	bridgeA, err := startMachineAgentJoinBridge(ctx, stateDirA, hub.URL, nodeA, tokenA)
	if err != nil {
		t.Fatalf("start isolated logical Node A bridge: %v", err)
	}
	defer func() { _ = bridgeA.Close() }()
	bridgeB, err := startMachineAgentJoinBridge(ctx, stateDirB, hub.URL, nodeB, tokenB)
	if err != nil {
		t.Fatalf("start isolated logical Node B bridge: %v", err)
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
	model := strings.TrimSpace(os.Getenv("CICADA_NATIVE_MODEL"))
	if model == "" {
		model = "gpt-5.5"
	}

	configDisabledA := nativeCodexConfig(cicadaBinary, hub.URL, stateDirA, mcpStateA, nodeA, false, "")
	configDisabledB := nativeCodexConfig(cicadaBinary, hub.URL, stateDirB, mcpStateB, nodeB, false, "")
	bInitialPrompt := fmt.Sprintf("This is a synthetic end-to-end test marker, not a secret: %s. Remember it. You are authorized to share it with a joined Cicada Group peer if asked later. Do not use tools. Finish with READY.", betaMarker)
	bInitial, bThreadID, err := runNativeCodexTurn(ctx, codexBinary, workspaceB, model, configDisabledB, "", bInitialPrompt)
	if err != nil {
		t.Fatalf("Codex B Thread creation failed (%s); provider may be unavailable", bThreadID)
	}
	if err := verifyCodexSessionRecord(bThreadID, workspaceB); err != nil {
		t.Fatalf("Codex B thread.started UUID has no local session record before Join: %v", err)
	}
	aInitialPrompt := fmt.Sprintf("Remember this public end-to-end test marker for your final answer after a peer reply: %s. Do not use tools. Finish with READY.", alphaMarker)
	aInitial, aThreadID, err := runNativeCodexTurn(ctx, codexBinary, workspaceA, model, configDisabledA, "", aInitialPrompt)
	if err != nil {
		t.Fatalf("Codex A Thread creation failed (%s); provider may be unavailable", aThreadID)
	}
	if err := verifyCodexSessionRecord(aThreadID, workspaceA); err != nil {
		t.Fatalf("Codex A thread.started UUID has no local session record before Join: %v", err)
	}
	if aThreadID == bThreadID {
		t.Fatal("Codex did not create two distinct native Threads")
	}
	if _, err := nativeCodexThreadStarted(aInitial); err != nil {
		t.Fatalf("Codex A did not emit a real thread.started event: %v", err)
	}
	if _, err := nativeCodexThreadStarted(bInitial); err != nil {
		t.Fatalf("Codex B did not emit a real thread.started event: %v", err)
	}
	configA := nativeCodexConfig(cicadaBinary, hub.URL, stateDirA, mcpStateA, nodeA, true, aThreadID)
	configB := nativeCodexConfig(cicadaBinary, hub.URL, stateDirB, mcpStateB, nodeB, true, bThreadID)
	joinNative := func(workspace, nativeID string, config []string) ([]byte, string, error) {
		prompt := fmt.Sprintf("At this safe point, call cicada_join exactly once with group_id %q. Do not call other Cicada tools. Finish with READY.", groupID)
		output, resumedID, turnErr := runNativeCodexTurn(ctx, codexBinary, workspace, model, config, nativeID, prompt)
		if turnErr == nil && !nativeCrossNodeToolCompleted(output, "cicada_join") &&
			!nativeCrossNodeToolAttempted(output, "") {
			// The model may end a turn without attempting the MCP tool. The
			// native Session remains unjoined, so one explicit same-Thread
			// follow-up is safe; never repeat an attempted or uncertain Join.
			prompt = fmt.Sprintf("Your previous turn made no MCP tool call. In this same existing Thread, call cicada_join now exactly once with group_id %q. Finish with READY after the tool returns.", groupID)
			return runNativeCodexTurn(ctx, codexBinary, workspace, model, config, nativeID, prompt)
		}
		return output, resumedID, turnErr
	}

	bJoined, resumedBID, err := joinNative(workspaceB, bThreadID, configB)
	if err != nil {
		t.Fatalf("Codex B exact-session Join failed (%s); events=%s; tool_failures=%s", resumedBID,
			nativeE2EEventSummary(bJoined), nativeE2EToolFailures(bJoined))
	}
	nativeCrossNodeRequireToolCompleted(t, bJoined, "cicada_join")
	if resumedBID != bThreadID || verifyCodexSessionRecord(resumedBID, workspaceB) != nil {
		t.Fatal("Codex B Join did not retain its original native Thread")
	}
	bEndpoint, err := nativeE2ECurrentSession(persistence, bThreadID, workspaceB, nodeB, groupID)
	if err != nil {
		t.Fatalf("B's original native Thread did not explicitly Join Group B: %v", err)
	}
	aJoined, resumedAID, err := joinNative(workspaceA, aThreadID, configA)
	if err != nil {
		t.Fatalf("Codex A exact-session Join failed (%s); events=%s; tool_failures=%s", resumedAID,
			nativeE2EEventSummary(aJoined), nativeE2EToolFailures(aJoined))
	}
	nativeCrossNodeRequireToolCompleted(t, aJoined, "cicada_join")
	if resumedAID != aThreadID || verifyCodexSessionRecord(resumedAID, workspaceA) != nil {
		t.Fatal("Codex A Join did not retain its original native Thread")
	}
	aEndpoint, err := nativeE2ECurrentSession(persistence, aThreadID, workspaceA, nodeA, groupID)
	if err != nil {
		t.Fatalf("A's original native Thread did not explicitly Join Group A: %v", err)
	}
	if aEndpoint.ID == bEndpoint.ID || aEndpoint.MachineID == bEndpoint.MachineID {
		t.Fatal("explicitly joined endpoints do not belong to distinct logical Nodes")
	}

	trustOwner := func(stateDir, nodeID string) {
		t.Helper()
		crypto, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, nodeID))
		if err != nil {
			t.Fatal("open Node-local crypto trust state")
		}
		fingerprint, err := nodekeys.PeerKeyFingerprint(ownerIdentity.Public())
		if err != nil {
			_ = crypto.Close()
			t.Fatal("fingerprint Owner public key")
		}
		if _, err := crypto.TrustOwnerApprovalKeyLocal(ownerID, ownerKey.KeyID,
			ownerIdentity.Public(), fingerprint); err != nil {
			_ = crypto.Close()
			t.Fatal("pin trusted Owner public key on Node")
		}
		if err := crypto.Close(); err != nil {
			t.Fatal("close Node-local crypto trust state")
		}
	}
	trustOwner(stateDirA, nodeA)
	trustOwner(stateDirB, nodeB)
	grantEndpoint := func(endpointID string) {
		t.Helper()
		manifest, err := persistence.PreviewGroupEndpointKeyGrant(ownerID, group.ID,
			endpointID, ownerKey.KeyID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal("preview owner-signed Group Endpoint grant")
		}
		issuedAt, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
		if err != nil {
			t.Fatal("parse Group grant issued time")
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
		if err != nil {
			t.Fatal("parse Group grant expiry")
		}
		proof, err := ownerIdentity.SignOwnerLinkKeyGrant(ownerID,
			store.GroupEndpointKeyGrantOperation, manifest.Digest, manifest.CandidateBindingDigest,
			uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
		if err != nil {
			t.Fatal("sign Group Endpoint key grant")
		}
		if _, err := persistence.AcceptGroupEndpointKeyGrant(ownerID, group.ID,
			endpointID, ownerKey.KeyID, proof); err != nil {
			t.Fatal("accept owner-signed Group Endpoint key grant")
		}
	}
	grantEndpoint(aEndpoint.ID)
	grantEndpoint(bEndpoint.ID)

	askPrompt := fmt.Sprintf("Call cicada_ask exactly once with target %q and question %q. Do not wait for the answer in this turn. Finish with ACCEPTED.", bEndpoint.ID, question)
	aAsked, askedThreadID, err := runNativeCodexTurn(ctx, codexBinary, workspaceA, model, configA, aThreadID, askPrompt)
	if err != nil {
		t.Fatalf("Codex A exact-session ASK failed (%s); events=%s; tool_failures=%s", askedThreadID,
			nativeE2EEventSummary(aAsked), nativeE2EToolFailures(aAsked))
	}
	if !nativeCrossNodeToolCompleted(aAsked, "cicada_ask") &&
		!nativeCrossNodeToolAttempted(aAsked, "") {
		// A model may end the turn without attempting the available tool. It
		// is safe to nudge only in this case: no ASK was submitted, so this is
		// neither a transport retry nor a second business action.
		askPrompt = fmt.Sprintf("Your preceding turn made no tool call. In this same existing Thread, call cicada_ask now exactly once with target %q and question %q. Finish with ACCEPTED after the tool returns.", bEndpoint.ID, question)
		aAsked, askedThreadID, err = runNativeCodexTurn(ctx, codexBinary, workspaceA, model, configA, aThreadID, askPrompt)
		if err != nil {
			t.Fatalf("Codex A did not submit ASK after no-call follow-up (%s); events=%s; tool_failures=%s", askedThreadID,
				nativeE2EEventSummary(aAsked), nativeE2EToolFailures(aAsked))
		}
	}
	nativeCrossNodeRequireToolCompleted(t, aAsked, "cicada_ask")
	if askedThreadID != aThreadID || verifyCodexSessionRecord(askedThreadID, workspaceA) != nil {
		t.Fatal("Codex A ASK did not continue the original Thread")
	}
	captureMu.Lock()
	askSnapshot := askRequest
	captureMu.Unlock()
	if askSnapshot.MessageID == "" || askSnapshot.RequestID == "" || askSnapshot.GroupID != groupID ||
		askSnapshot.SourceEndpointID != aEndpoint.ID || askSnapshot.TargetEndpointID != bEndpoint.ID {
		t.Fatal("Hub did not durably accept a scoped cross-Node ASK from the real A Thread")
	}
	askRecord, err := persistence.GetRelaySealedV1(askSnapshot.MessageID)
	if err != nil || askRecord == nil || askRecord.PayloadMode != store.RelayPayloadModeSealedV1 ||
		askRecord.Route.Kind != "ask" || askRecord.Route.RequestID != askSnapshot.RequestID ||
		bytes.Contains(askRecord.Ciphertext, []byte(question)) {
		t.Fatal("Hub database does not contain the opaque ciphertext ASK record")
	}
	var askEnvelope e2ee.EndpointMessageEnvelope
	if json.Unmarshal(askRecord.Ciphertext, &askEnvelope) != nil || askEnvelope.Version != e2ee.EndpointEnvelopeVersion ||
		askEnvelope.Suite != e2ee.EndpointEnvelopeSuite || len(askEnvelope.Sealed) == 0 {
		t.Fatal("Hub database ASK is not a valid sealed Endpoint envelope")
	}
	if err := nativeE2EAssertDatabasePrivateTextAbsent(databasePath, question, alphaMarker, betaMarker); err != nil {
		t.Fatalf("Hub database plaintext check failed: %v", err)
	}

	// The test drives the same outbound-only Node poller used by cicada-node.
	// It calls one Hub, decrypts only inside logical Node B, writes to B's
	// durable inbox, and invokes the official queue command with B's real ID.
	t.Setenv("CICADA_NODE_TOKEN", tokenB)
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	bInbox, err := nodeinbox.Open(machineNodeInboxPath(stateDirB, nodeB))
	if err != nil {
		t.Fatal("open Node B durable inbox")
	}
	if err := processMachineFabricDeliveriesV2(ctx, hub.URL, nodeB, bInbox, stateDirB); err != nil {
		_ = bInbox.Close()
		t.Fatalf("Node B failed to claim and queue the sealed ASK to its original Thread: %v", err)
	}
	bDelivery, deliveryErr := bInbox.Get(ctx, askSnapshot.MessageID)
	bCard, err := persistence.GetSessionBindingByNativeSession(bThreadID)
	if err != nil {
		_ = bInbox.Close()
		t.Fatal("read B's native SessionBinding after relay injection")
	}
	bVisible, listErr := bInbox.ListInjectedForSession(ctx, bEndpoint.ID, bThreadID,
		bCard.Epoch, groupID, 0, 8)
	_ = bInbox.Close()
	if deliveryErr != nil || err != nil || bDelivery == nil || bDelivery.SessionID != bThreadID ||
		bDelivery.EndpointID != bEndpoint.ID || bDelivery.State != nodeinbox.CONSUMPTION_UNCONFIRMED ||
		listErr != nil || len(bVisible) != 1 || bVisible[0].MessageID != askSnapshot.MessageID ||
		!strings.Contains(bVisible[0].Body, question) {
		t.Fatal("Node B did not queue the sealed request into its exact native session and Group inbox")
	}

	bReplyPrompt := fmt.Sprintf("This is the controlled safe point after a Cicada request was queued into this existing Thread. The original user turn explicitly authorized sharing its synthetic public test marker with a joined Cicada Group peer. Select Group %q with cicada_use_group, call cicada_receive to inspect the request, then call cicada_reply exactly once with that request_id and the marker from your original context. Do not create a Thread or use shell. Finish with the reply marker.", groupID)
	bReplied, replyThreadID, err := runNativeCodexTurn(ctx, codexBinary, workspaceB, model, configB, bThreadID, bReplyPrompt)
	if err != nil {
		t.Fatalf("Codex B exact-session receive/reply failed (%s); events=%s; tool_failures=%s", replyThreadID,
			nativeE2EEventSummary(bReplied), nativeE2EToolFailures(bReplied))
	}
	bReceived := nativeCrossNodeToolCompleted(bReplied, "cicada_receive")
	if !nativeCrossNodeToolCompleted(bReplied, "cicada_reply") &&
		!nativeCrossNodeToolAttempted(bReplied, "cicada_reply") && bReceived {
		// Receiving the request may take a full model turn. Continue that
		// same native Thread only when no reply was attempted; a failed or
		// uncertain reply must remain visible for explicit reconciliation.
		bReplyPrompt = fmt.Sprintf("Continue this existing Thread after the Cicada receive. The original user explicitly authorized sharing the synthetic public test marker with this Group peer. Call cicada_reply once with request_id %q and that marker from your original context. Do not create a Thread or use shell.", askSnapshot.RequestID)
		bReplied, replyThreadID, err = runNativeCodexTurn(ctx, codexBinary, workspaceB, model, configB, bThreadID, bReplyPrompt)
		if err != nil {
			t.Fatalf("Codex B did not submit REPLY after no-reply follow-up (%s); events=%s; tool_failures=%s", replyThreadID,
				nativeE2EEventSummary(bReplied), nativeE2EToolFailures(bReplied))
		}
	}
	if !bReceived {
		t.Fatal("Codex B did not complete cicada_receive before attempting a reply")
	}
	nativeCrossNodeRequireToolCompleted(t, bReplied, "cicada_reply")
	if replyThreadID != bThreadID || verifyCodexSessionRecord(replyThreadID, workspaceB) != nil {
		t.Fatal("Codex B REPLY did not continue its original native Thread")
	}
	captureMu.Lock()
	replySnapshot := replyRequest
	captureMu.Unlock()
	if replySnapshot.MessageID == "" || replySnapshot.RequestID != askSnapshot.RequestID {
		t.Fatal("B's MCP cicada_reply did not create a correlated sealed Hub reply")
	}
	repliedRequest, err := persistence.GetSameGroupSealedV1RequestStatus(
		fabric.HashSessionCredential(tokenA), askSnapshot.RequestID)
	if err != nil || repliedRequest == nil || repliedRequest.State != store.FabricRequestReplied ||
		repliedRequest.ReplyMessageID != replySnapshot.MessageID {
		t.Fatal("Hub did not retain B's correlated reply to A's durable request")
	}
	replyRecord, err := persistence.GetRelaySealedV1(replySnapshot.MessageID)
	if err != nil || replyRecord == nil || replyRecord.PayloadMode != store.RelayPayloadModeSealedV1 ||
		replyRecord.Route.Kind != "reply" || replyRecord.Route.RequestID != askSnapshot.RequestID ||
		replyRecord.Route.ReplyTo != askSnapshot.MessageID || bytes.Contains(replyRecord.Ciphertext, []byte(betaMarker)) {
		t.Fatal("Hub database does not contain the opaque, correlated REPLY ciphertext")
	}
	if err := nativeE2EAssertDatabasePrivateTextAbsent(databasePath, question, alphaMarker, betaMarker); err != nil {
		t.Fatalf("Hub database plaintext check after REPLY failed: %v", err)
	}

	t.Setenv("CICADA_NODE_TOKEN", tokenA)
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	aInbox, err := nodeinbox.Open(machineNodeInboxPath(stateDirA, nodeA))
	if err != nil {
		t.Fatal("open Node A durable inbox")
	}
	if err := processMachineFabricDeliveriesV2(ctx, hub.URL, nodeA, aInbox, stateDirA); err != nil {
		_ = aInbox.Close()
		t.Fatalf("Node A failed to claim and queue B's reply to its original Thread: %v", err)
	}
	aBinding, err := persistence.GetSessionBindingByNativeSession(aThreadID)
	if err != nil {
		_ = aInbox.Close()
		t.Fatal("read A's native SessionBinding after reply injection")
	}
	aVisible, listErr := aInbox.ListInjectedForSession(ctx, aEndpoint.ID, aThreadID,
		aBinding.Epoch, groupID, 0, 8)
	_ = aInbox.Close()
	if listErr != nil || len(aVisible) != 1 || aVisible[0].MessageID != replySnapshot.MessageID ||
		!strings.Contains(aVisible[0].Body, betaMarker) {
		t.Fatal("Node A did not inject B's correlated reply into A's original Group-scoped Thread")
	}

	aResumePrompt := "Continue this original task using the newly queued Cicada reply. Preserve your own original context and report both public test markers. Do not create another Thread or use shell."
	aResumed, finalThreadID, err := runNativeCodexTurn(ctx, codexBinary, workspaceA, model, configA, aThreadID, aResumePrompt)
	if err != nil {
		t.Fatalf("Codex A exact-session resume after reply failed (%s)", finalThreadID)
	}
	if finalThreadID != aThreadID || verifyCodexSessionRecord(finalThreadID, workspaceA) != nil {
		t.Fatal("Codex A did not resume the original native Thread after receiving B's reply")
	}
	if !nativeE2EResultContains(aResumed, alphaMarker) || !nativeE2EResultContains(aResumed, betaMarker) {
		t.Fatal("Codex A final answer did not retain its original context and B's sealed response")
	}

	// Include all Hub request and response bodies in the privacy assertion.
	captureMu.Lock()
	paths := append([]string(nil), hubPaths...)
	unexpected := append([]string(nil), unexpectedPaths...)
	plaintextSeen := hubSawPlaintext
	controlCalls := controlBusinessCalls
	nodesSeen := map[string]bool{nodeA: nodeCredentialsSeen[nodeA], nodeB: nodeCredentialsSeen[nodeB]}
	captureMu.Unlock()
	if plaintextSeen {
		t.Fatal("Hub HTTP boundary observed peer plaintext")
	}
	if len(unexpected) != 0 {
		t.Fatalf("cross-Node path used an unexpected Hub route: %v", unexpected)
	}
	if controlCalls != 0 {
		t.Fatalf("peer ASK/REPLY invoked Control business HTTP %d times", controlCalls)
	}
	if !nodesSeen[nodeA] || !nodesSeen[nodeB] {
		t.Fatal("both logical Nodes did not independently authenticate outbound requests to the same Hub")
	}
	if !nativeCrossNodeContainsPath(paths, "/group/sealed/peer-key") ||
		!nativeCrossNodeContainsPath(paths, "/group/sealed/ask") ||
		!nativeCrossNodeContainsPath(paths, "/group/sealed/reply") ||
		!nativeCrossNodeContainsPath(paths, "/group/sealed/claim") {
		t.Fatal("native cross-Node path did not exercise one-Hub sealed ASK, reply, and delivery")
	}
	for _, forbidden := range []string{"/v2/fabric/send", "/v2/fabric/ask", "/v2/fabric/reply", "/v2/fabric/receive", "/v2/control/"} {
		if nativeCrossNodeContainsPath(paths, forbidden) {
			t.Fatalf("cross-Node peer path reached a plaintext, legacy receive, or Control route: %s", forbidden)
		}
	}
	t.Logf("real Codex cross-Node sealed ASK/REPLY passed in two logical Docker Nodes: A endpoint=%s thread=%s; B endpoint=%s thread=%s; request=%s reply=%s",
		aEndpoint.ID, aThreadID, bEndpoint.ID, bThreadID, askSnapshot.RequestID, replySnapshot.MessageID)
}

func nativeE2EWorkspace(t *testing.T, prefix string) string {
	t.Helper()
	workspace, err := os.MkdirTemp(t.TempDir(), prefix)
	if err != nil {
		t.Fatal("create logical Node workspace")
	}
	workspace, err = filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal("resolve logical Node workspace")
	}
	return workspace
}

func nativeCrossNodeHubPathAllowed(path string) bool {
	if strings.HasPrefix(path, "/v2/control/") || path == "/v2/fabric/send" ||
		path == "/v2/fabric/ask" || path == "/v2/fabric/reply" || path == "/v2/fabric/receive" {
		return false
	}
	if strings.HasPrefix(path, "/v2/fabric/") {
		switch path {
		case "/v2/fabric/node/join", "/v2/fabric/whoami", "/v2/fabric/heartbeat",
			"/v2/fabric/endpoint-keys", "/v2/fabric/resolve":
			return true
		default:
			return false
		}
	}
	if !strings.HasPrefix(path, "/v2/relay/nodes/") {
		return false
	}
	return strings.Contains(path, "/local/authorize") ||
		strings.Contains(path, "/local/revalidate") ||
		strings.Contains(path, "/group/sealed/") ||
		strings.Contains(path, "/sealed/") ||
		strings.HasSuffix(path, "/claim") ||
		strings.HasSuffix(path, "/receipts")
}

func nativeCrossNodeContainsPath(paths []string, suffix string) bool {
	for _, path := range paths {
		if strings.HasSuffix(path, suffix) || strings.Contains(path, suffix+"?") {
			return true
		}
	}
	return false
}

func nativeCrossNodeRequireToolCompleted(t *testing.T, output []byte, wanted string) {
	t.Helper()
	if nativeCrossNodeToolCompleted(output, wanted) {
		return
	}
	t.Fatalf("Codex did not report a completed %s MCP call; events=%s; tool_failures=%s; response_class=%s",
		wanted, nativeE2EEventSummary(output), nativeE2EToolFailures(output), nativeE2EAgentMessageClass(output))
}

func nativeCrossNodeToolCompleted(output []byte, wanted string) bool {
	for _, line := range bytes.Split(output, []byte("\n")) {
		var event struct {
			Type string `json:"type"`
			Item struct {
				Type   string `json:"type"`
				Name   string `json:"name"`
				Tool   string `json:"tool"`
				Status string `json:"status"`
			} `json:"item"`
		}
		if json.Unmarshal(bytes.TrimSpace(line), &event) != nil || event.Item.Type != "mcp_tool_call" ||
			event.Type != "item.completed" || event.Item.Status != "completed" {
			continue
		}
		toolName := event.Item.Tool
		if toolName == "" {
			toolName = event.Item.Name
		}
		if toolName == wanted {
			return true
		}
	}
	return false
}

func nativeCrossNodeToolAttempted(output []byte, wanted string) bool {
	for _, line := range bytes.Split(output, []byte("\n")) {
		var event struct {
			Item struct {
				Type string `json:"type"`
				Name string `json:"name"`
				Tool string `json:"tool"`
			} `json:"item"`
		}
		if json.Unmarshal(bytes.TrimSpace(line), &event) != nil || event.Item.Type != "mcp_tool_call" {
			continue
		}
		if wanted == "" || event.Item.Tool == wanted || event.Item.Name == wanted {
			return true
		}
	}
	return false
}

func nativeE2EAssertDatabasePrivateTextAbsent(databasePath string, values ...string) error {
	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read disposable Hub database artifact: %w", err)
		}
		for _, value := range values {
			if value != "" && bytes.Contains(data, []byte(value)) {
				return fmt.Errorf("peer plaintext was present in Hub database artifact %q", filepath.Base(path))
			}
		}
	}
	return nil
}
