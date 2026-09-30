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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// This fixture runs the real MCP JSON-RPC handler and owner-only Unix socket
// for two original Codex session records. No model or native queue is invoked.
func TestGroupSpacesMCPAcrossNodesWithLostCommitResponse(t *testing.T) {
	const (
		ownerID = "owner_spaces_mcp_synthetic"
		groupID = "group_spaces_mcp_synthetic"
		netID   = "net_spaces_mcp_synthetic"
		body    = "synthetic private journal checkpoint from original thread"
	)
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	codexHome := filepath.Join(root, "codex")
	stateDir := shortLocalJoinStateDir(t)
	for _, thread := range []string{"thread_spaces_a", "thread_spaces_b"} {
		writeCodexSessionRecord(t, codexHome, thread, workspace)
	}
	hubStateDir := filepath.Join(root, "hub-state")
	manager, err := control.New(control.Config{StateDir: hubStateDir,
		WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "synthetic-manager-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	dbPath := filepath.Join(hubStateDir, "cicada.sqlite3")
	persistence, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = persistence.Close() })
	owner, err := persistence.CreatePrincipal(store.Principal{ID: ownerID,
		Kind: store.PrincipalKindHuman, OwnerID: ownerID, TrustDomainID: ownerID,
		Name: "synthetic spaces owner", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(store.Group{ID: groupID, Name: groupID,
		OwnerPrincipalID: owner.ID, TrustDomainID: ownerID, State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	registeredOwner, err := persistence.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "client_spaces_synthetic"
	now := time.Now().UTC()
	deviceProof, err := ownerKey.SignOwnerDeviceGrant(ownerID, deviceID,
		clientKey.Public(), hubID, e2ee.OwnerDevicePurposeControl,
		now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: registeredOwner.KeyID, DeviceID: deviceID,
		DevicePublic: clientKey.Public(), OwnerDeviceGrant: deviceProof}); err != nil {
		t.Fatal(err)
	}
	bindNode := func(nodeID string) string {
		t.Helper()
		token, digest, err := fabric.NewNodeCredential()
		if err != nil {
			t.Fatal(err)
		}
		code := sha256.Sum256([]byte("synthetic-space-node-" + nodeID))
		codeDigest := hex.EncodeToString(code[:])
		if _, err := persistence.CreatePendingNodeDeviceBinding(nodeID, nodeID, digest,
			codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
			t.Fatal(err)
		}
		return token
	}
	const nodeA, nodeB = "node_spaces_a", "node_spaces_b"
	tokenA, tokenB := bindNode(nodeA), bindNode(nodeB)
	service, err := fabric.NewService(persistence, ownerID, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	handler := serverpkg.NewFabricHandler(service, "")
	clientHandler := serverpkg.NewHandler(manager)
	var proxyMu sync.Mutex
	var loseFirstCommit bool
	var lostCommit bool
	var hubSawBody bool
	var nodeSpaceCalls int
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024+1))
		if err != nil || len(data) > 4*1024*1024 {
			http.Error(w, "invalid fixture request", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		if bytes.Contains(data, []byte(body)) {
			proxyMu.Lock()
			hubSawBody = true
			proxyMu.Unlock()
		}
		r.Body = io.NopCloser(bytes.NewReader(data))
		if r.URL.Path == "/v2/client/rpc" {
			clientHandler.ServeHTTP(w, r)
			return
		}
		proxyMu.Lock()
		if strings.HasPrefix(r.URL.Path, "/v2/fabric/node/spaces/") {
			nodeSpaceCalls++
			if r.Header.Get("Authorization") != "CicadaNode "+tokenA &&
				r.Header.Get("Authorization") != "CicadaNode "+tokenB {
				t.Errorf("Node Space request omitted its Node credential")
			}
			if !strings.HasPrefix(r.Header.Get("Cicada-Space-Session"), "CicadaSession ") {
				t.Errorf("Node Space request omitted its joined Group credential")
			}
		}
		drop := r.URL.Path == "/v2/fabric/node/spaces/commit" && loseFirstCommit && !lostCommit
		if drop {
			lostCommit = true
		}
		proxyMu.Unlock()
		if drop {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, r)
			if response.Code != http.StatusCreated {
				t.Errorf("fixture first commit failed before response loss: %d %s", response.Code, response.Body.String())
			}
			http.Error(w, "synthetic lost commit response", http.StatusBadGateway)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer hub.Close()
	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelA()
	defer cancelB()
	bridgeA, err := startMachineAgentJoinBridge(ctxA, stateDir, hub.URL, nodeA, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	defer bridgeA.Close()
	bridgeB, err := startMachineAgentJoinBridge(ctxB, stateDir, hub.URL, nodeB, tokenB)
	if err != nil {
		t.Fatal(err)
	}
	defer bridgeB.Close()
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	t.Setenv("CICADA_WORKSPACE", workspace)
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_HUB_ID", hubID)
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_NODE_TOKEN", "")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	newJoined := func(nodeID, thread string) *mcpServer {
		t.Helper()
		t.Setenv("CICADA_MACHINE_ID", nodeID)
		t.Setenv("CODEX_THREAD_ID", thread)
		t.Setenv("CODEX_SESSION_ID", "")
		mcp := newMCPServer(hub.URL, "", filepath.Join(t.TempDir(), "mcp", "session.json"))
		result := spaceMCPCall(t, mcp, "cicada_join", map[string]any{"group_id": groupID})
		if result == nil {
			t.Fatal("MCP Join returned no result")
		}
		t.Cleanup(func() {
			if mcp.outbox != nil {
				_ = mcp.outbox.close()
			}
			close(mcp.stop)
		})
		return mcp
	}
	a := newJoined(nodeA, "thread_spaces_a")
	b := newJoined(nodeB, "thread_spaces_b")
	endpointA := a.currentPublicJoinResult().Endpoint
	endpointB := b.currentPublicJoinResult().Endpoint
	if endpointA.ID == "" || endpointB.ID == "" {
		t.Fatal("native joins did not create stable Endpoints")
	}
	if _, err := persistence.CreateNetwork(store.Network{ID: netID, HubID: hubID,
		Name: "synthetic spaces Network", OwnerID: ownerID}); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.PrepareGroupNetworkMapping(group.ID, netID,
		"synthetic explicit Group scope", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := persistence.ApproveGroupNetworkMapping(group.ID, netID, group.Version); err != nil {
		t.Fatal(err)
	}
	joinNetwork := func(nodeToken, nodeID, thread string) store.Endpoint {
		t.Helper()
		invite := "synthetic-spaces-invite-" + thread
		grants := []string{"directory.discover", "directory.publish"}
		if err := persistence.IssueNetworkInvitation(netID, ownerID, ownerID, invite,
			time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
			t.Fatal(err)
		}
		proof, err := ownerKey.SignOwnerNetworkJoinGrant(ownerID, hubID, netID, nodeID,
			thread, store.NetworkInvitationDigest(invite), ownerKey.Public().ID,
			grants, true, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		joined, err := service.JoinNetworkForNodeCredential(nodeToken, fabric.NetworkJoinInput{
			NetworkID: netID, InvitationToken: invite, OwnerJoinProof: string(proof),
			Harness: "codex", NativeSessionID: thread, EndpointName: thread})
		if err != nil {
			t.Fatal(err)
		}
		return joined.Endpoint
	}
	joinNetwork(tokenA, nodeA, "thread_spaces_a")
	joinNetwork(tokenB, nodeB, "thread_spaces_b")
	if err := persistence.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []store.Endpoint{endpointA, endpointB} {
		member, err := persistence.GetMembershipByPrincipalGroup(endpoint.PrincipalID, groupID)
		if err != nil {
			t.Fatal(err)
		}
		grants := append(append([]string(nil), member.Grants...), "space.read", "space.write")
		if endpoint.ID == endpointA.ID {
			grants = append(grants, "space.moderate")
		}
		if _, err := persistence.UpdateMembershipAuthorization(member.ID, member.Roles,
			grants, member.Authorization, member.Version); err != nil {
			t.Fatal(err)
		}
	}
	for _, nodeID := range []string{nodeA, nodeB} {
		crypto, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, nodeID))
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := nodekeys.PeerKeyFingerprint(ownerKey.Public())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := crypto.TrustOwnerApprovalKeyLocal(ownerID, registeredOwner.KeyID,
			ownerKey.Public(), fingerprint); err != nil {
			t.Fatal(err)
		}
		_ = crypto.Close()
	}
	for _, endpoint := range []store.Endpoint{endpointA, endpointB} {
		manifest, err := persistence.PreviewGroupEndpointKeyGrant(ownerID, groupID, endpoint.ID,
			registeredOwner.KeyID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		issued, _ := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
		expires, _ := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
		proof, err := ownerKey.SignOwnerLinkKeyGrant(ownerID,
			store.GroupEndpointKeyGrantOperation, manifest.Digest,
			manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
			e2ee.OwnerLinkGrantSideSource, issued, expires)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.AcceptGroupEndpointKeyGrant(ownerID, groupID,
			endpoint.ID, registeredOwner.KeyID, proof); err != nil {
			t.Fatal(err)
		}
	}
	setThread := func(nodeID, thread string) {
		t.Setenv("CICADA_MACHINE_ID", nodeID)
		t.Setenv("CODEX_THREAD_ID", thread)
	}
	setThread(nodeA, "thread_spaces_a")
	proxyMu.Lock()
	loseFirstCommit = true
	proxyMu.Unlock()
	first := spaceMCPCall(t, a, "cicada_journal_append", map[string]any{
		"body": body, "idempotency_key": "stable-synthetic-journal"})
	firstMap, ok := first.(map[string]any)
	if !ok || firstMap["status"] != "UNKNOWN" {
		t.Fatalf("lost commit response should leave durable UNKNOWN operation: %#v", first)
	}
	opID, _ := firstMap["operation_id"].(string)
	if opID == "" {
		t.Fatal("lost commit response omitted operation ID")
	}
	cachePath := groupSpaceCachePath(stateDir, nodeA, groupID, opID)
	cacheBefore, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal("lost response did not leave durable exact ciphertext cache: ", err)
	}
	reserveNext := func() uint64 {
		t.Helper()
		crypto, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, nodeA))
		if err != nil {
			t.Fatal(err)
		}
		defer crypto.Close()
		identity, err := nodekeys.LoadOrCreate(machineNodeStateDir(stateDir, nodeA), endpointA.ID)
		if err != nil {
			t.Fatal(err)
		}
		sequence, err := crypto.ReserveOutboundSequence(context.Background(), endpointA.ID, identity.Public().ID)
		if err != nil {
			t.Fatal(err)
		}
		return sequence
	}
	beforeRetrySequence := reserveNext()
	retried := spaceMCPCall(t, a, "cicada_operation_retry", map[string]any{"operation_id": opID})
	retryMap, ok := retried.(map[string]any)
	if !ok || retryMap["status"] != "SENT" {
		t.Fatalf("original ciphertext retry failed: %#v", retried)
	}
	cacheAfter, err := os.ReadFile(cachePath)
	if err != nil || !bytes.Equal(cacheBefore, cacheAfter) || reserveNext() != beforeRetrySequence+1 {
		t.Fatalf("lost commit retry resealed or advanced outbound crypto sequence: %v", err)
	}
	// B joined before the append and has never called space_sync. No SSE
	// stream is running in this fixture, so a background reconciliation must
	// recover the durable commit watermark without native wake or mark-read.
	watchBefore, err := bridgeB.loadSpaceSubscriptions()
	if err != nil || len(watchBefore.Items) != 1 || watchBefore.Items[0].FetchedSeq != 0 {
		t.Fatalf("Join did not register an unread Group Space watch: %#v %v", watchBefore, err)
	}
	readBefore, err := service.GetGroupSpaceReadState(tokenB, b.sessionToken,
		fabric.GroupSpaceReadStateInput{GroupID: groupID})
	if err != nil {
		t.Fatal(err)
	}
	if err := bridgeB.reconcileGroupSpaces(); err != nil {
		t.Fatal(err)
	}
	watchAfter, err := bridgeB.loadSpaceSubscriptions()
	if err != nil || len(watchAfter.Items) != 1 || watchAfter.Items[0].FetchedSeq < 1 ||
		watchAfter.Items[0].Watermark != "commit_v1" || watchAfter.Items[0].HubID != hubID {
		t.Fatalf("lost SSE did not recover B's guarded commit cursor: %#v %v", watchAfter, err)
	}
	readAfter, err := service.GetGroupSpaceReadState(tokenB, b.sessionToken,
		fabric.GroupSpaceReadStateInput{GroupID: groupID})
	if err != nil || readAfter.ReadSeq != readBefore.ReadSeq || readAfter.UnreadCount == 0 ||
		readAfter.LatestSeq < watchAfter.Items[0].FetchedSeq {
		t.Fatalf("background sync incorrectly marked read or lost unread: %#v %#v %v", readBefore, readAfter, err)
	}
	setThread(nodeB, "thread_spaces_b")
	page := spaceMCPCall(t, b, "cicada_journal_list", map[string]any{"limit": float64(16)})
	pageJSON, _ := json.Marshal(page)
	if !bytes.Contains(pageJSON, []byte(body)) {
		t.Fatalf("authorized second Node did not decrypt Journal: %s", pageJSON)
	}
	var pageResult groupSpaceLocalResult
	if err := json.Unmarshal(pageJSON, &pageResult); err != nil || len(pageResult.Records) != 1 {
		t.Fatalf("authorized Journal page is incomplete: %s err=%v", pageJSON, err)
	}
	setThread(nodeA, "thread_spaces_a")
	self := spaceMCPCall(t, a, "cicada_journal_get", map[string]any{"record_id": pageResult.Records[0].RecordID})
	selfJSON, _ := json.Marshal(self)
	if !bytes.Contains(selfJSON, []byte(body)) {
		t.Fatalf("author could not decrypt its own persisted record: %s", selfJSON)
	}
	if bytes.Contains(pageJSON, []byte(tokenA)) || bytes.Contains(pageJSON, []byte(tokenB)) {
		t.Fatal("MCP Group Space result leaked a Node credential")
	}
	createdTopic := spaceMCPCall(t, a, "cicada_discussion_topic_create", map[string]any{
		"body": "synthetic Discussion topic", "idempotency_key": "topic-cas-create"})
	createdTopicMap, _ := createdTopic.(map[string]any)
	createdTopicRecord, _ := createdTopicMap["record"].(map[string]any)
	topicID, _ := createdTopicRecord["record_id"].(string)
	if createdTopicMap["status"] != "SENT" || topicID == "" {
		t.Fatalf("topic create did not expose its immutable ID: %#v", createdTopic)
	}
	resolved := spaceMCPCall(t, a, "cicada_discussion_resolve", map[string]any{
		"topic_id": topicID, "expected_topic_version": float64(1),
		"idempotency_key": "topic-cas-resolve"})
	if value, _ := resolved.(map[string]any); value["status"] != "SENT" {
		t.Fatalf("topic resolve failed: %#v", resolved)
	}
	currentTopic := spaceMCPCall(t, a, "cicada_discussion_get", map[string]any{"record_id": topicID})
	currentJSON, _ := json.Marshal(currentTopic)
	var currentResult groupSpaceLocalResult
	if json.Unmarshal(currentJSON, &currentResult) != nil || currentResult.Record == nil ||
		currentResult.Record.CurrentTopicVersion != 2 || currentResult.Record.CurrentTopicStatus != "RESOLVED" {
		t.Fatalf("topic get hid current CAS state: %s", currentJSON)
	}
	reopened := spaceMCPCall(t, a, "cicada_discussion_reopen", map[string]any{
		"topic_id": topicID, "expected_topic_version": float64(2),
		"idempotency_key": "topic-cas-reopen"})
	if value, _ := reopened.(map[string]any); value["status"] != "SENT" {
		t.Fatalf("topic reopen failed: %#v", reopened)
	}
	proxyMu.Lock()
	sawPlain, calls, lost := hubSawBody, nodeSpaceCalls, lostCommit
	proxyMu.Unlock()
	if sawPlain || !lost || calls < 4 {
		t.Fatalf("Group Space chain failed ciphertext isolation/retry: hub_plain=%t lost=%t node_calls=%d", sawPlain, lost, calls)
	}
	readerMember, err := persistence.GetMembershipByPrincipalGroup(endpointB.PrincipalID, groupID)
	if err != nil {
		t.Fatal(err)
	}
	readerOnlyGrants := make([]string, 0, len(readerMember.Grants))
	for _, grant := range readerMember.Grants {
		if grant != "space.write" {
			readerOnlyGrants = append(readerOnlyGrants, grant)
		}
	}
	if _, err := persistence.UpdateMembershipAuthorization(readerMember.ID, readerMember.Roles,
		readerOnlyGrants, readerMember.Authorization, readerMember.Version); err != nil {
		t.Fatal(err)
	}
	setThread(nodeB, "thread_spaces_b")
	denied := spaceMCPCall(t, b, "cicada_journal_append", map[string]any{
		"body": "synthetic read-only writer attempt", "idempotency_key": "readonly-denied"})
	if deniedMap, ok := denied.(map[string]any); !ok || deniedMap["status"] != "FAILED" {
		t.Fatalf("read-only Group member wrote a Journal entry: %#v", denied)
	}
	setThread(nodeA, "thread_spaces_a")
	if spoof := spaceMCPCallError(t, a, "cicada_journal_append", map[string]any{
		"body": "spoof", "sender_endpoint_id": endpointB.ID}); !spoof {
		t.Fatal("MCP accepted model-supplied sender identity")
	}
	// B was an original reader, but a lost and regained space.read grant must
	// establish a new cutoff. Only a single-record Owner grant plus Node-local
	// rewrap may restore this earlier entry.
	readerMember, err = persistence.GetMembershipByPrincipalGroup(endpointB.PrincipalID, groupID)
	if err != nil {
		t.Fatal(err)
	}
	withoutRead := make([]string, 0, len(readerMember.Grants))
	for _, grant := range readerMember.Grants {
		if grant != "space.read" {
			withoutRead = append(withoutRead, grant)
		}
	}
	if _, err := persistence.UpdateMembershipAuthorization(readerMember.ID, readerMember.Roles,
		withoutRead, readerMember.Authorization, readerMember.Version); err != nil {
		t.Fatal(err)
	}
	readerMember, err = persistence.GetMembershipByPrincipalGroup(endpointB.PrincipalID, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.UpdateMembershipAuthorization(readerMember.ID, readerMember.Roles,
		append(readerMember.Grants, "space.read"), readerMember.Authorization, readerMember.Version); err != nil {
		t.Fatal(err)
	}
	manifestB, err := persistence.PreviewGroupEndpointKeyGrant(ownerID, groupID, endpointB.ID,
		registeredOwner.KeyID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	issuedB, _ := time.Parse(time.RFC3339Nano, manifestB.IssuedAt)
	expiresB, _ := time.Parse(time.RFC3339Nano, manifestB.ExpiresAt)
	proofB, err := ownerKey.SignOwnerLinkKeyGrant(ownerID,
		store.GroupEndpointKeyGrantOperation, manifestB.Digest,
		manifestB.CandidateBindingDigest, uint64(manifestB.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, issuedB, expiresB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.AcceptGroupEndpointKeyGrant(ownerID, groupID,
		endpointB.ID, registeredOwner.KeyID, proofB); err != nil {
		t.Fatal(err)
	}
	setThread(nodeB, "thread_spaces_b")
	if !spaceMCPCallError(t, b, "cicada_journal_get", map[string]any{"record_id": pageResult.Records[0].RecordID}) {
		t.Fatal("regained reader accessed pre-cutoff record without history grant")
	}
	setThread(nodeA, "thread_spaces_a")
	historyManifest := spaceMCPCall(t, a, "cicada_space_history_manifest", map[string]any{
		"record_id":             pageResult.Records[0].RecordID,
		"recipient_endpoint_id": endpointB.ID, "owner_key_id": registeredOwner.KeyID})
	historyJSON, _ := json.Marshal(historyManifest)
	manifestPath := filepath.Join(root, "synthetic-history-manifest.json")
	if err := os.WriteFile(manifestPath, historyJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	ownerPrivate, err := ownerKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	ownerPath := filepath.Join(root, "synthetic-owner-private.json")
	if err := os.WriteFile(ownerPath, ownerPrivate, 0o600); err != nil {
		t.Fatal(err)
	}
	var ownerOutput bytes.Buffer
	if err := ownerSpaceCommand([]string{"space-history-sign", "--private", ownerPath,
		"--manifest", manifestPath, "--expect-owner-id", ownerID,
		"--expect-record-id", pageResult.Records[0].RecordID,
		"--expect-recipient-endpoint-id", endpointB.ID}, &ownerOutput); err != nil {
		t.Fatal(err)
	}
	var signed struct {
		OwnerProof string `json:"owner_proof"`
	}
	if err := json.Unmarshal(ownerOutput.Bytes(), &signed); err != nil || signed.OwnerProof == "" {
		t.Fatalf("offline Owner signing did not return bounded proof: %v", err)
	}
	beforeHistorySequence := reserveNext()
	shared := spaceMCPCall(t, a, "cicada_space_history_share", map[string]any{
		"owner_proof": signed.OwnerProof})
	if shared == nil {
		t.Fatal("history share returned no result")
	}
	if reserveNext() != beforeHistorySequence+2 {
		t.Fatal("history rewrap did not reserve one durable outbound crypto sequence")
	}
	setThread(nodeB, "thread_spaces_b")
	historical := spaceMCPCall(t, b, "cicada_journal_get", map[string]any{
		"record_id": pageResult.Records[0].RecordID})
	historicalJSON, _ := json.Marshal(historical)
	if !bytes.Contains(historicalJSON, []byte(body)) {
		t.Fatalf("Owner-granted later reader could not locally decrypt historical record: %s", historicalJSON)
	}
	// M4: a real Monitor MCP proposal, encrypted Owner delegation, guarded
	// Monitor MCP apply, then the Owner's encrypted topology projection.
	monitorMember, err := persistence.GetMembershipByPrincipalGroup(endpointA.PrincipalID, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.UpdateMembershipAuthorization(monitorMember.ID, []string{"monitor"},
		monitorMember.Grants, monitorMember.Authorization, monitorMember.Version); err != nil {
		t.Fatal(err)
	}
	currentGroup, err := persistence.GetGroup(groupID)
	if err != nil {
		t.Fatal(err)
	}
	setThread(nodeA, "thread_spaces_a")
	proposedValue := spaceMCPCall(t, a, "cicada_regroup_propose", map[string]any{
		"network_id": netID, "target_group_id": groupID, "action": "CREATE_CHILD",
		"new_group_name": "synthetic delegated child", "expected_source_version": float64(currentGroup.Version),
		"expected_target_version": float64(currentGroup.Version), "idempotency_key": "synthetic-m4-regroup"})
	proposedJSON, _ := json.Marshal(proposedValue)
	var proposed groupSpaceLocalResult
	if err := json.Unmarshal(proposedJSON, &proposed); err != nil || proposed.RegroupProposal == nil ||
		proposed.RegroupProposal.ProposalID == "" {
		t.Fatalf("Monitor MCP proposal: %s %v", proposedJSON, err)
	}
	ownerRPCSequence := uint64(0)
	ownerRPC := func(operation string, input any, output any) {
		t.Helper()
		ownerRPCSequence++
		binding := clientwire.Binding{HubID: hubID, OwnerID: ownerID, DeviceID: deviceID,
			SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
		route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
			HubID: hubID, OwnerID: ownerID, DeviceID: deviceID, SessionEpoch: 1,
			Sequence: ownerRPCSequence, OperationID: fmt.Sprintf("synthetic-regroup-rpc-%d", ownerRPCSequence),
			Operation: operation, SenderKeyID: clientKey.Public().ID, SenderKeyVersion: 1,
			ReceiverKeyID: manager.ClientControlPublicIdentity().ID, ReceiverKeyVersion: 1}
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := clientwire.SealRequest(clientKey, manager.ClientControlPublicIdentity(), binding, route, body)
		if err != nil {
			t.Fatal(err)
		}
		response, err := hub.Client().Post(hub.URL+"/v2/client/rpc", "application/json", bytes.NewReader(packet))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		responseData, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("encrypted %s: %d %v %s", operation, response.StatusCode, err, responseData)
		}
		opened, err := clientwire.OpenResponse(clientKey, manager.ClientControlPublicIdentity(), binding, responseData)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
			Error  any             `json:"error"`
		}
		if err := json.Unmarshal(opened.Plaintext, &result); err != nil || !result.OK {
			t.Fatalf("encrypted %s rejected: %s %v", operation, opened.Plaintext, err)
		}
		if err := json.Unmarshal(result.Result, output); err != nil {
			t.Fatal(err)
		}
	}
	var delegation store.RegroupDelegation
	ownerRPC("topology.delegation_issue", map[string]any{
		"proposal_id": proposed.RegroupProposal.ProposalID,
		"expires_at":  time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), "max_uses": 1}, &delegation)
	if delegation.ProposalID != proposed.RegroupProposal.ProposalID || delegation.DelegationID == "" {
		t.Fatalf("Owner delegation is not bound to Monitor proposal: %+v", delegation)
	}
	appliedValue := spaceMCPCall(t, a, "cicada_regroup_apply", map[string]any{
		"proposal_id": proposed.RegroupProposal.ProposalID, "delegation_id": delegation.DelegationID})
	appliedJSON, _ := json.Marshal(appliedValue)
	var applied groupSpaceLocalResult
	if err := json.Unmarshal(appliedJSON, &applied); err != nil || applied.RegroupApply == nil ||
		applied.RegroupApply.Group.ParentGroupID != groupID || applied.RegroupApply.AuditID == "" {
		t.Fatalf("Monitor MCP apply: %s %v", appliedJSON, err)
	}
	var topology control.ClientTopologySnapshot
	ownerRPC("topology.snapshot", map[string]any{}, &topology)
	found := false
	for _, card := range topology.Groups {
		if card.GroupID == applied.RegroupApply.Group.ID && card.ParentGroupID == groupID && card.NetworkID == netID {
			found = true
		}
	}
	if !found {
		t.Fatalf("Owner snapshot omitted delegated child: %#v", topology.Groups)
	}
}

func TestGroupSpaceCachePersistsLegalThirtyTwoReaderWireSize(t *testing.T) {
	// Genuine 32-reader crypto fixtures serialize above 2 MiB. The private
	// durable retry cache must survive that size without changing the bytes.
	path := filepath.Join(t.TempDir(), "group-spaces", "synthetic-32.json")
	cache := groupSpaceSealedCache{ReservationID: "synthetic-reservation",
		RecordID: "synthetic-record", OperationID: "synthetic-operation",
		GroupID: "synthetic-group", BodyDigest: "synthetic-body",
		SnapshotDigest: "synthetic-snapshot"}
	for index := 0; index < 32; index++ {
		cache.ReaderCiphertexts = append(cache.ReaderCiphertexts,
			store.GroupSpaceReaderCiphertext{
				EndpointID: fmt.Sprintf("synthetic-reader-%02d", index),
				KeyID:      "synthetic-key", Wire: bytes.Repeat([]byte{byte(index)}, 50*1024),
			})
	}
	encoded, err := json.Marshal(cache)
	if err != nil || len(encoded) <= 2<<20 || len(encoded) >= groupSpaceCacheMaxBytes {
		t.Fatalf("synthetic maximum cache size invalid: %d %v", len(encoded), err)
	}
	stored, err := persistGroupSpaceCache(path, cache)
	if err != nil || stored == nil {
		t.Fatalf("legal 32-reader cache rejected: %v", err)
	}
	loaded, err := loadGroupSpaceCache(path)
	if err != nil || loaded == nil || len(loaded.ReaderCiphertexts) != 32 {
		t.Fatalf("legal 32-reader cache could not be reopened: %v", err)
	}
	for index := range cache.ReaderCiphertexts {
		if !bytes.Equal(cache.ReaderCiphertexts[index].Wire, loaded.ReaderCiphertexts[index].Wire) {
			t.Fatalf("reader %d sealed retry bytes changed", index)
		}
	}
}

func spaceMCPCall(t *testing.T, server *mcpServer, name string, args map[string]any) any {
	t.Helper()
	params, err := json.Marshal(map[string]any{"name": name, "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	response, send := server.handle(mcpRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`),
		Method: "tools/call", Params: params})
	if !send || response.Error != nil {
		t.Fatalf("MCP %s protocol failure: %+v", name, response)
	}
	value, ok := response.Result.(map[string]any)
	if !ok || value["isError"] == true {
		t.Fatalf("MCP %s failed: %+v", name, response.Result)
	}
	return value["structuredContent"]
}

func spaceMCPCallError(t *testing.T, server *mcpServer, name string, args map[string]any) bool {
	t.Helper()
	params, err := json.Marshal(map[string]any{"name": name, "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	response, _ := server.handle(mcpRequest{JSONRPC: "2.0", ID: json.RawMessage(`2`),
		Method: "tools/call", Params: params})
	value, ok := response.Result.(map[string]any)
	return ok && value["isError"] == true
}
