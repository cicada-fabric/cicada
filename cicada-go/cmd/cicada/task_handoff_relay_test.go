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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelocal"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

func taskRelayActor(t *testing.T, f *localGroupFailureFixture, m *mcpServer) store.NativeActorScope {
	t.Helper()
	card := m.sessionPublic.NetworkCard
	membership, err := f.store.GetMembershipByPrincipalGroup(card.PrincipalID, f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := f.store.GetActiveSessionBinding(card.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	return store.NativeActorScope{PrincipalID: card.PrincipalID, EndpointID: card.EndpointID, GroupID: f.groupID,
		MembershipID: membership.ID, MembershipRevision: membership.Revision, BindingID: binding.ID, BindingEpoch: binding.Epoch, LeaseOwner: binding.LeaseOwner}
}

func TestTaskHandoffSameNodeRelayLostAcknowledgmentsAndNoControl(t *testing.T) {
	fixtureRoot := t.TempDir()
	t.Setenv("TMPDIR", fixtureRoot)
	f := newLocalGroupFailureFixture(t)
	for _, m := range []*mcpServer{f.sourceMCP, f.targetMCP} {
		membership, err := f.store.GetMembershipByPrincipalGroup(m.sessionPublic.NetworkCard.PrincipalID, f.groupID)
		if err != nil {
			t.Fatal(err)
		}
		grants := append(append([]string(nil), membership.Grants...), "task.read", "task.claim", "task.submit", "artifact.read")
		if _, err := f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles, grants, membership.Authorization, membership.Version); err != nil {
			t.Fatal(err)
		}
	}
	authorizeSameNodeRelayFixture(t, f, f.sourceMCP, f.targetMCP)
	service, err := fabric.NewService(f.store, f.ownerID, f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	handler := serverpkg.NewFabricHandler(service, "") // absent Control business service
	var mu sync.Mutex
	counts := map[string]int{}
	lostProposal, lostAccept := true, true
	plaintextSeen := false
	const secret = "SYNTHETIC_PRIVATE_HANDOFF_BODY_NOT_TASK_METADATA"
	f.hub.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		mu.Lock()
		counts[r.Method+" "+r.URL.Path]++
		plaintextSeen = plaintextSeen || bytes.Contains(body, []byte(secret))
		mu.Unlock()
		proposal := r.Method == http.MethodPost && r.URL.Path == "/v2/fabric/tasks/sealed-handoffs"
		accept := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/accept")
		mu.Lock()
		lose := proposal && lostProposal || accept && lostAccept
		if lose {
			if proposal {
				lostProposal = false
			} else {
				lostAccept = false
			}
		}
		mu.Unlock()
		if lose {
			record := httptest.NewRecorder()
			handler.ServeHTTP(record, r)
			if record.Code != http.StatusOK && record.Code != http.StatusCreated && record.Code != http.StatusAccepted {
				t.Errorf("fixture mutation failed: %d %s", record.Code, record.Body.String())
				record.Result().Body.Close()
			}
			http.Error(w, "synthetic lost durable response", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	})
	selectSession := func(m *mcpServer) {
		t.Helper()
		t.Setenv("CODEX_THREAD_ID", m.sessionContext.NativeSessionID)
		t.Setenv("CODEX_SESSION_ID", "session-"+m.sessionContext.NativeSessionID)
	}
	source := taskRelayActor(t, f, f.sourceMCP)
	task, err := f.store.CreateSharedTask(store.SharedTask{ID: "task_synthetic_relay_handoff", GroupID: f.groupID, Objective: "synthetic EXISTING plaintext Task metadata", AcceptanceCriteria: "synthetic existing criteria"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.ReadySharedTask(task.ID, task.Revision, "synthetic-fixture")
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.ClaimSharedTaskForActor(source, task.ID, task.Revision, "synthetic-claim", 600)
	if err != nil {
		t.Fatal(err)
	}
	selectSession(f.sourceMCP)
	args := map[string]any{"task_id": task.ID, "target": f.targetMCP.endpointID, "body": secret, "expires_at": time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond).Format(time.RFC3339Nano), "idempotency_key": "synthetic-stable-handoff"}
	sent, err := f.sourceMCP.callTool("cicada_task_handoff_send", args)
	if err != nil {
		t.Fatal(err)
	}
	public := sent.(map[string]any)
	if public["status"] != mcpOutboxStatusUnknown {
		t.Fatalf("lost receipt status %#v", public)
	}
	handoffID := public["handoff_id"].(string)
	targetActor := taskRelayActor(t, f, f.targetMCP)
	claims, err := f.store.ClaimSameGroupSealedV1Inbox(fabric.HashSessionCredential(f.nodeToken), store.RelayClaimInput{
		RecipientEndpointID: targetActor.EndpointID, ConsumerID: "synthetic-task-receiver", BindingID: targetActor.BindingID, BindingEpoch: targetActor.BindingEpoch, Limit: 1})
	if err != nil || len(claims) != 1 {
		t.Fatalf("receiver claim failed: %v %#v", err, claims)
	}
	authorization, err := f.store.AuthorizeClaimedSameGroupSealedV1Delivery(fabric.HashSessionCredential(f.nodeToken), claims[0].MessageID, claims[0].AttemptID)
	if err != nil || authorization.TaskHandoff == nil {
		t.Fatal("receiver current handoff authorization missing", err)
	}
	peer, err := f.bridge.fetchCrossNodeGroupTaskHandoffPeerKey(f.groupID, f.sourceMCP.endpointID, f.targetMCP.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := nodekeys.LoadExisting(machineNodeStateDir(f.stateDir, f.nodeID), f.targetMCP.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	expected := crossNodeGroupEndpointContext(peer, peer.Sender, peer.Receiver, claims[0].MessageID, "", "", "", "SEND")
	opened, _, err := e2ee.OpenEndpointMessage(receiver, peer.Sender.Candidate.Public, expected, claims[0].Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSealedTaskHandoffPayload(authorization.TaskHandoff, claims[0].MessageID, claims[0].Route, opened); err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSealedTaskHandoffPayload(opened)
	if err != nil || decoded.Body != secret {
		t.Fatal("receiver did not recover exact private handoff body", err)
	}
	selectSession(f.targetMCP)
	acceptedArgs := map[string]any{"handoff_id": handoffID, "expected_version": int64(1), "lease_seconds": int64(300)}
	if _, err := f.targetMCP.callTool("cicada_task_handoff_accept", acceptedArgs); err == nil {
		t.Fatal("lost acceptance response was not injected")
	}
	before, err := f.store.GetSharedTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if before.OwnerEndpointID != f.targetMCP.endpointID || before.OwnerEpoch != task.OwnerEpoch+1 || before.Revision != task.Revision+1 {
		t.Fatal("transfer failed", before)
	}
	if _, err := f.targetMCP.callTool("cicada_task_handoff_accept", acceptedArgs); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.GetSharedTask(task.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("acceptance retry wrote Task")
	}
	selectSession(f.sourceMCP)
	retry, err := f.sourceMCP.callTool("cicada_operation_retry", map[string]any{"operation_id": public["operation_id"]})
	if err != nil {
		t.Fatal(err)
	}
	if retry.(map[string]any)["status"] != mcpOutboxStatusSent || retry.(map[string]any)["handoff_id"] != handoffID {
		t.Fatal("exact transferred history was not recovered", retry)
	}
	after, err = f.store.GetSharedTask(task.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("proposal history recovery wrote Task")
	}
	if _, err := f.store.SubmitSharedTaskResultForActor(source, task.ID, task.OwnerEpoch, task.Revision, "synthetic stale result", []string{"synthetic"}); err == nil {
		t.Fatal("old owner was not fenced")
	}
	// Exact socket dispatcher accepts only the intended operation and trusted
	// native identity. Denial happens before any new crypto/Relay write.
	card := f.sourceMCP.sessionPublic.NetworkCard
	wireRequest := crossNodeGroupRequest{Operation: "cross_node_task_handoff", Harness: "codex", NativeSessionID: f.nativeA, NodeID: f.nodeID, Workspace: f.workspace,
		SessionToken: f.sourceMCP.sessionToken, EndpointID: card.EndpointID, PrincipalID: card.PrincipalID, OwnerID: f.ownerID, GroupID: f.groupID, BindingID: card.BindingID, BindingEpoch: card.BindingEpoch,
		TargetEndpointID: f.targetMCP.endpointID, IdempotencyKey: "synthetic-denied-task", TaskHandoffID: "synthetic_denied_task", TaskID: task.ID, ExpectedRevision: task.Revision, OwnerEpoch: task.OwnerEpoch, Body: secret, ExpiresAt: args["expires_at"].(string)}
	deadline, _ := time.Parse(time.RFC3339Nano, wireRequest.ExpiresAt)
	wireRequest.HandoffMessageID = "shared-task-handoff.v1:" + strconv.FormatInt(deadline.UnixMilli(), 10) + ":" + wireRequest.TaskHandoffID
	beforeFiles := taskHistoryFiles(t, f.stateDir)
	for _, kind := range []string{"unknown", "forged-principal"} {
		bad := wireRequest
		if kind == "unknown" {
			bad.Operation = "cross_node_task_handoff_unknown"
		} else {
			bad.PrincipalID = "synthetic-forged-principal"
		}
		if _, err := requestMachineAgentCrossNodeGroup(machineAgentJoinSocketPath(f.stateDir, f.nodeID), bad); err == nil {
			t.Fatal("socket accepted", kind)
		}
	}
	if afterFiles := taskHistoryFiles(t, f.stateDir); !reflect.DeepEqual(beforeFiles, afterFiles) {
		t.Fatal("socket denial changed Node keys/crypto/history")
	}
	dbFiles := 0
	if err := filepath.WalkDir(filepath.Dir(fixtureRoot), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "hub.sqlite3") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		dbFiles++
		if bytes.Contains(data, []byte(secret)) {
			t.Error("persisted Hub DB contains handoff plaintext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if dbFiles == 0 {
		t.Fatal("Hub database canary scan had no database files")
	}
	mu.Lock()
	defer mu.Unlock()
	if plaintextSeen {
		t.Fatal("Hub saw handoff plaintext")
	}
	if counts["POST /v2/relay/nodes/"+f.nodeID+"/group/sealed/send"] != 1 || counts["POST /v2/fabric/tasks/sealed-handoffs"] != 1 {
		t.Fatal("history recovery reposted", counts)
	}
	for path := range counts {
		if strings.HasSuffix(path, "/sealed-handoffs/local") || strings.Contains(path, "/local/revalidate") {
			t.Fatal("Task used local delivery", path)
		}
	}
	if _, err := os.Stat(machineLocalGroupLedgerPath(f.stateDir, f.nodeID)); !os.IsNotExist(err) {
		t.Fatal("Task created legacy local ledger", err)
	}
	data, _ := json.Marshal(after)
	if bytes.Contains(data, []byte(secret)) {
		t.Fatal("handoff body leaked into authoritative Task")
	}
	t.Log("synthetic HTTP/MCP/socket one-Hub Relay; nil Control; no model/provider/native injection")
}

func TestTaskHandoffLocalCreationAndNotifyDeniedBeforeLedgerOpen(t *testing.T) {
	f := newLocalGroupFailureFixture(t)
	card := f.sourceMCP.sessionPublic.NetworkCard
	req := localGroupRequest{Version: localGroupProtocolVersion, Harness: "codex", NativeSessionID: f.nativeA, NodeID: f.nodeID, Workspace: f.workspace, SessionToken: f.sourceMCP.sessionToken, EndpointID: card.EndpointID, PrincipalID: card.PrincipalID, OwnerID: f.ownerID, GroupID: f.groupID, BindingID: card.BindingID, BindingEpoch: card.BindingEpoch}
	base := req
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	req.Operation = "local_task_handoff"
	req.OperationID = "op_12345678901234567890123456789012"
	req.OperationCreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	req.IdempotencyKey, req.TaskHandoffID, req.TaskID = "synthetic-local-key", req.OperationID, "synthetic-task"
	req.Target, req.Body, req.ExpectedRevision, req.OwnerEpoch = f.targetMCP.endpointID, "synthetic sealed body", 3, 1
	req.ExpiresAt = expires.Format(time.RFC3339Nano)
	req.HandoffMessageID = "shared-task-handoff.v1:" + strconv.FormatInt(expires.UnixMilli(), 10) + ":" + req.TaskHandoffID
	if err := validateLocalGroupRequest(req, f.nodeID); err != nil {
		t.Fatal("invalid denial fixture", err)
	}
	if _, err := f.bridge.localGroup(req); err != errGenericNativeDirectUnsupported {
		t.Fatal("new valid local handoff was not retired", err)
	}
	req = base
	req.Operation, req.TaskHandoffID = "local_task_handoff_notify", "synthetic-old-handoff"
	if err := validateLocalGroupRequest(req, f.nodeID); err != nil {
		t.Fatal("invalid notify fixture", err)
	}
	if _, err := f.bridge.localGroup(req); err != errGenericNativeDirectUnsupported {
		t.Fatal("valid local notify was not retired", err)
	}
	req = base
	req.Operation = "local_task_handoff_recover"
	req.TaskHandoffID = "synthetic_absent"
	req.HandoffMessageID = "shared-task-handoff.v1:9999999999999:synthetic_absent"
	if _, err := f.bridge.localGroup(req); err != nodelocal.ErrMessageNotFound {
		t.Fatal("missing history did not fail closed", err)
	}
	if _, err := os.Stat(machineLocalGroupLedgerPath(f.stateDir, f.nodeID)); !os.IsNotExist(err) {
		t.Fatal("denial/recovery created ledger", err)
	}
}

func taskHistoryFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		result[path] = info.Mode().String() + ":" + hex.EncodeToString(digest[:])
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

// Synthetic historical Hub metadata is an immutable fixture, while both the
// local signed envelope and the Unix socket reader use production code.
func TestTaskHandoffHistoricalLocalSignedPacketReadOnlyWAL(t *testing.T) {
	for _, closed := range []bool{false, true} {
		name := "active-WAL"
		if closed {
			name = "checkpointed"
		}
		t.Run(name, func(t *testing.T) {
			f := newLocalGroupFailureFixture(t)
			authorizeSameNodeRelayFixture(t, f, f.sourceMCP, f.targetMCP)
			authorization, err := f.bridge.fetchLocalGroupAuthorization(f.sourceMCP.sessionToken, store.LocalDeliveryAuthorizationInput{GroupID: f.groupID, Target: f.targetMCP.endpointID, Action: "message.send"})
			if err != nil {
				t.Fatal(err)
			}
			source, target, err := f.bridge.loadLocalGroupIdentitiesMode(*authorization, true)
			if err != nil {
				t.Fatal(err)
			}
			expiry := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
			id := "synthetic_historical_task_handoff"
			message := "shared-task-handoff.v1:" + strconv.FormatInt(expiry.UnixMilli(), 10) + ":" + id
			packet := sealedTaskHandoffPayload{Type: sealedTaskHandoffPayloadType, Version: 1, HandoffID: id, TaskID: "synthetic_historical_task", GroupID: f.groupID, FromPrincipalID: authorization.Source.PrincipalID, FromEndpointID: authorization.Source.EndpointID, ToPrincipalID: authorization.Target.PrincipalID, ToEndpointID: authorization.Target.EndpointID, TaskRevision: 7, FromOwnerEpoch: 3, MessageID: message, ExpiresAt: expiry.Format(time.RFC3339Nano), RequiredArtifactRefs: []store.SealedTaskHandoffArtifactRef{}, Body: "synthetic historical private handoff"}
			plaintext, err := marshalSealedTaskHandoffPayload(packet)
			if err != nil {
				t.Fatal(err)
			}
			route := localGroupEndpointRoute(*authorization, message, "SEND", "", "")
			wire, err := e2ee.SealEndpointMessage(source, target.Public(), route, plaintext, 77)
			if err != nil {
				t.Fatal(err)
			}
			ledgerRoute, err := localGroupLedgerRoute(*authorization, f.nativeA)
			if err != nil {
				t.Fatal(err)
			}
			ledgerRoute.Action = "SEND"
			ledgerPath := machineLocalGroupLedgerPath(f.stateDir, f.nodeID)
			ledger, err := nodelocal.Open(ledgerPath)
			if err != nil {
				t.Fatal(err)
			}
			// Checkpoint the empty schema first, leaving the signed receipt only
			// in WAL for the active-reader case.
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			ledger, err = nodelocal.Open(ledgerPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ledger.AcceptSend(context.Background(), nodelocal.MessageInput{MessageID: message, Route: ledgerRoute, Ciphertext: wire}); err != nil {
				ledger.Close()
				t.Fatal(err)
			}
			if closed {
				if err := ledger.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				defer ledger.Close()
				info, err := os.Stat(ledgerPath + "-wal")
				if err != nil || info.Size() == 0 {
					t.Fatal("fixture did not retain committed WAL history", err)
				}
			}
			digest := sha256.Sum256(wire)
			history := store.SealedSharedTaskHandoff{ID: id, TaskID: packet.TaskID, GroupID: f.groupID, FromPrincipalID: packet.FromPrincipalID, FromEndpointID: packet.FromEndpointID, ToPrincipalID: packet.ToPrincipalID, ToEndpointID: packet.ToEndpointID, TaskRevision: 7, FromOwnerEpoch: 3, MessageID: message, MessageDigest: hex.EncodeToString(digest[:]), RequiredArtifactRefs: packet.RequiredArtifactRefs, ExpiresAt: packet.ExpiresAt, Status: store.SealedTaskHandoffProposed, Version: 1, Transport: "LOCAL_NODE", LocalRoute: &store.LocalSealedTaskHandoffRoute{NodeID: f.nodeID, FromBindingID: ledgerRoute.SourceBindingID, FromBindingEpoch: ledgerRoute.SourceBindingEpoch, ToBindingID: ledgerRoute.TargetBindingID, ToBindingEpoch: ledgerRoute.TargetBindingEpoch}}
			var historyMu sync.Mutex
			relayPosts := 0
			history.LocalRoute.FromMembershipRevision = int64(ledgerRoute.SourceMembershipRevision)
			history.LocalRoute.ToMembershipRevision = int64(ledgerRoute.TargetMembershipRevision)
			history.LocalRoute.FromJoinRevision = int64(ledgerRoute.SourceJoinRevision)
			history.LocalRoute.ToJoinRevision = int64(ledgerRoute.TargetJoinRevision)
			history.LocalRoute.FromKeyID, history.LocalRoute.ToKeyID = ledgerRoute.SourceKeyID, ledgerRoute.TargetKeyID
			history.LocalRoute.FromKeyVersion, history.LocalRoute.ToKeyVersion = int64(ledgerRoute.SourceCandidateVersion), int64(ledgerRoute.TargetCandidateVersion)
			refsHash, err := store.SealedTaskHandoffArtifactRefsDigest(packet.RequiredArtifactRefs)
			if err != nil {
				t.Fatal(err)
			}
			claims := e2ee.LocalTaskHandoffProofClaims{Version: 1, Purpose: "LOCAL_NODE", HandoffID: id, TaskID: packet.TaskID, HubID: f.hubID, GroupID: f.groupID,
				FromPrincipalID: packet.FromPrincipalID, FromOwnerID: f.ownerID, FromEndpointID: packet.FromEndpointID, FromBindingID: ledgerRoute.SourceBindingID, FromBindingEpoch: ledgerRoute.SourceBindingEpoch, FromMembershipRevision: history.LocalRoute.FromMembershipRevision, FromJoinRevision: history.LocalRoute.FromJoinRevision, FromKeyID: ledgerRoute.SourceKeyID, FromKeyVersion: history.LocalRoute.FromKeyVersion,
				ToPrincipalID: packet.ToPrincipalID, ToOwnerID: f.ownerID, ToEndpointID: packet.ToEndpointID, ToBindingID: ledgerRoute.TargetBindingID, ToBindingEpoch: ledgerRoute.TargetBindingEpoch, ToMembershipRevision: history.LocalRoute.ToMembershipRevision, ToJoinRevision: history.LocalRoute.ToJoinRevision, ToKeyID: ledgerRoute.TargetKeyID, ToKeyVersion: history.LocalRoute.ToKeyVersion, TaskRevision: 7, FromOwnerEpoch: 3, MessageID: message, MessageDigest: history.MessageDigest, ExpiresAt: packet.ExpiresAt, RequiredArtifactRefsHash: refsHash, IssuedAt: expiry.Add(-time.Hour).Format(time.RFC3339Nano)}
			proof, err := source.SignLocalTaskHandoffProof(claims)
			if err != nil {
				t.Fatal(err)
			}
			proofHash := sha256.Sum256(proof)
			history.LocalRoute.SenderProofDigest = hex.EncodeToString(proofHash[:])
			originalHandler := f.hub.Config.Handler
			f.hub.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/fabric/tasks/sealed-handoffs/"+id {
					if r.Method != http.MethodGet || r.Header.Get("Authorization") != "CicadaSession "+f.sourceMCP.sessionToken || r.Header.Get("Cicada-Group-Scope") != f.groupID {
						http.Error(w, "synthetic historical read denied", http.StatusForbidden)
						return
					}
					historyMu.Lock()
					_ = json.NewEncoder(w).Encode(history)
					historyMu.Unlock()
					return
				}
				if strings.HasPrefix(r.URL.Path, "/v2/fabric/tasks/sealed-handoffs/") {
					http.NotFound(w, r)
					return
				}
				if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/group/sealed/send") {
					historyMu.Lock()
					relayPosts++
					historyMu.Unlock()
				}
				if r.URL.Path == "/v2/fabric/resolve" {
					// Simulate a Directory route that has moved to another Node.
					// Source history remains authoritative regardless of this hint.
					recorded := httptest.NewRecorder()
					originalHandler.ServeHTTP(recorded, r)
					if recorded.Code != http.StatusOK {
						w.WriteHeader(recorded.Code)
						w.Write(recorded.Body.Bytes())
						return
					}
					var resolved fabric.NetworkCard
					if err := json.Unmarshal(recorded.Body.Bytes(), &resolved); err != nil {
						t.Error(err)
						http.Error(w, "bad synthetic directory", 500)
						return
					}
					resolved.NodeID = "synthetic-target-other-node"
					_ = json.NewEncoder(w).Encode(resolved)
					return
				}
				originalHandler.ServeHTTP(w, r)
			})
			card := f.sourceMCP.sessionPublic.NetworkCard
			request := localGroupRequest{Operation: "local_task_handoff_recover", Harness: "codex", NativeSessionID: f.nativeA, NodeID: f.nodeID, Workspace: f.workspace, SessionToken: f.sourceMCP.sessionToken, EndpointID: card.EndpointID, PrincipalID: card.PrincipalID, OwnerID: f.ownerID, GroupID: f.groupID, BindingID: card.BindingID, BindingEpoch: card.BindingEpoch, TaskHandoffID: id, HandoffMessageID: message}
			before := taskHistoryFiles(t, f.stateDir)
			result, err := requestMachineAgentLocalGroup(machineAgentJoinSocketPath(f.stateDir, f.nodeID), request)
			if err != nil || result.Delivery != "LOCAL_HISTORICAL" || result.MessageDigest != history.MessageDigest {
				t.Fatalf("expired authentic history did not recover: %#v %v", result, err)
			}
			if after := taskHistoryFiles(t, f.stateDir); !reflect.DeepEqual(before, after) {
				t.Fatal("historical reader changed local DB/key/context/sidecar bytes or modes")
			}
			absent := request
			absent.TaskHandoffID = "synthetic_missing"
			absent.HandoffMessageID = "shared-task-handoff.v1:" + strconv.FormatInt(expiry.UnixMilli(), 10) + ":" + absent.TaskHandoffID
			_, err = requestMachineAgentLocalGroup(machineAgentJoinSocketPath(f.stateDir, f.nodeID), absent)
			if err == nil {
				t.Fatal("missing history manufactured receipt")
			}
			if !closed && err.Error() == nodelocal.ErrMessageNotFound.Error() {
				t.Fatal("existing WAL absence enabled new Relay fallback")
			}
			if after := taskHistoryFiles(t, f.stateDir); !reflect.DeepEqual(before, after) {
				t.Fatal("missing history lookup changed source files")
			}
			// A genuine old local packet whose metadata is absent cannot trigger
			// a new Remote proposal through the ordinary operation_retry tool.
			t.Setenv("CODEX_THREAD_ID", f.nativeA)
			t.Setenv("CODEX_SESSION_ID", "session-"+f.nativeA)
			scope, err := f.sourceMCP.currentMCPOutboxScope()
			if err != nil {
				t.Fatal(err)
			}
			outbox, err := f.sourceMCP.ensureMCPOutbox()
			if err != nil {
				t.Fatal(err)
			}
			orphanExpiry := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
			input := mcpOutboxInput{TaskID: packet.TaskID, Target: f.targetMCP.endpointID, RequestedTarget: f.targetMCP.endpointID, ExpectedRevision: 7, OwnerEpoch: 3, Body: "synthetic authenticated orphan local handoff", ExpiresAt: orphanExpiry.Format(time.RFC3339Nano), RequiredArtifactRefsJSON: "[]"}
			op, _, err := outbox.prepare(scope, "sealed_task_handoff", "synthetic-orphan-history", input)
			if err != nil {
				t.Fatal(err)
			}
			orphan := packet
			orphan.HandoffID = op.OperationID
			orphan.Body = input.Body
			orphan.ExpiresAt = input.ExpiresAt
			orphan.MessageID = "shared-task-handoff.v1:" + strconv.FormatInt(orphanExpiry.UnixMilli(), 10) + ":" + op.OperationID
			body, err := marshalSealedTaskHandoffPayload(orphan)
			if err != nil {
				t.Fatal(err)
			}
			orphanRoute := localGroupEndpointRoute(*authorization, orphan.MessageID, "SEND", "", "")
			orphanWire, err := e2ee.SealEndpointMessage(source, target.Public(), orphanRoute, body, 78)
			if err != nil {
				t.Fatal(err)
			}
			seedLedger := ledger
			if closed {
				seedLedger, err = nodelocal.Open(ledgerPath)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := seedLedger.AcceptSend(context.Background(), nodelocal.MessageInput{MessageID: orphan.MessageID, Route: ledgerRoute, Ciphertext: orphanWire}); err != nil {
				t.Fatal(err)
			}
			if closed {
				if err := seedLedger.Close(); err != nil {
					t.Fatal(err)
				}
			}
			before = taskHistoryFiles(t, f.stateDir)
			v, err := f.sourceMCP.callTool("cicada_operation_retry", map[string]any{"operation_id": op.OperationID})
			if err == nil && v.(map[string]any)["status"] == mcpOutboxStatusSent {
				t.Fatal("orphan local history enabled new Remote packet")
			}
			historyMu.Lock()
			posts := relayPosts
			historyMu.Unlock()
			if posts != 0 {
				t.Fatal("orphan recovery posted Relay ciphertext")
			}
			if after := taskHistoryFiles(t, f.stateDir); !reflect.DeepEqual(before, after) {
				t.Fatal("orphan recovery mutated local history/keys")
			}
			// Inconsistent immutable Hub metadata cannot become a receipt.
			originalHistory := history
			originalRoute := *history.LocalRoute
			for _, field := range []string{"digest", "membership", "key-version", "node", "principal"} {
				historyMu.Lock()
				history = originalHistory
				routeCopy := originalRoute
				history.LocalRoute = &routeCopy
				switch field {
				case "digest":
					history.MessageDigest = strings.Repeat("0", 64)
				case "membership":
					history.LocalRoute.ToMembershipRevision++
				case "key-version":
					history.LocalRoute.FromKeyVersion++
				case "node":
					history.LocalRoute.NodeID = "synthetic-other-node"
				case "principal":
					history.ToPrincipalID = "synthetic-other-principal"
				}
				historyMu.Unlock()
				if _, err := requestMachineAgentLocalGroup(machineAgentJoinSocketPath(f.stateDir, f.nodeID), request); err == nil {
					t.Fatal("changed history accepted", field)
				}
				if after := taskHistoryFiles(t, f.stateDir); !reflect.DeepEqual(before, after) {
					t.Fatal("conflicting history changed source files", field)
				}
			}
			if !closed {
				wal, err := os.ReadFile(ledgerPath + "-wal")
				if err != nil || len(wal) < 32 {
					t.Fatal("missing WAL corruption fixture", err)
				}
				corrupt := append([]byte(nil), wal...)
				corrupt[0] ^= 255
				if err := os.WriteFile(ledgerPath+"-wal", corrupt, 0600); err != nil {
					t.Fatal(err)
				}
				before = taskHistoryFiles(t, f.stateDir)
				if _, err := requestMachineAgentLocalGroup(machineAgentJoinSocketPath(f.stateDir, f.nodeID), absent); err == nil || err.Error() == nodelocal.ErrMessageNotFound.Error() {
					t.Fatal("modernc corrupt WAL absence allowed fallback", err)
				}
				if after := taskHistoryFiles(t, f.stateDir); !reflect.DeepEqual(before, after) {
					t.Fatal("corrupt WAL read changed source bytes")
				}
			}

		})
	}
}

func TestTaskHandoffRetiredLocalDeliveryAndCorruptHistoryFailClosed(t *testing.T) {
	record := nodelocal.MessageRecord{MessageID: "shared-task-handoff.v1:9999999999999:synthetic_old_handoff"}
	authorization := store.LocalDeliveryAuthorization{TaskHandoff: &store.SealedTaskHandoffDeliveryAuthorization{HandoffID: "synthetic_old_handoff", Transport: "LOCAL_NODE", Status: store.SealedTaskHandoffProposed}}
	if err := validateLocalTaskHandoffAuthorization(record, authorization); err == nil {
		t.Fatal("old LOCAL history authorized delivery")
	}
	if err := localTaskHandoffPayloadMatches(record, authorization, []byte("synthetic old plaintext")); err == nil {
		t.Fatal("old LOCAL history authorized native payload")
	}
	f := newLocalGroupFailureFixture(t)
	path := machineLocalGroupLedgerPath(f.stateDir, f.nodeID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("visibly synthetic corrupt local Task database"), 0600); err != nil {
		t.Fatal(err)
	}
	card := f.sourceMCP.sessionPublic.NetworkCard
	request := localGroupRequest{Operation: "local_task_handoff_recover", Harness: "codex", NativeSessionID: f.nativeA, NodeID: f.nodeID, Workspace: f.workspace, SessionToken: f.sourceMCP.sessionToken, EndpointID: card.EndpointID, PrincipalID: card.PrincipalID, OwnerID: f.ownerID, GroupID: f.groupID, BindingID: card.BindingID, BindingEpoch: card.BindingEpoch, TaskHandoffID: "synthetic_missing", HandoffMessageID: "shared-task-handoff.v1:9999999999999:synthetic_missing"}
	before := taskHistoryFiles(t, f.stateDir)
	if _, err := requestMachineAgentLocalGroup(machineAgentJoinSocketPath(f.stateDir, f.nodeID), request); err == nil || err.Error() == nodelocal.ErrMessageNotFound.Error() {
		t.Fatal("corrupt history became permission for new Relay", err)
	}
	if after := taskHistoryFiles(t, f.stateDir); !reflect.DeepEqual(before, after) {
		t.Fatal("corrupt history recovery changed original files")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(path+suffix, []byte("synthetic orphan Task sidecar"), 0600); err != nil {
			t.Fatal(err)
		}
		before = taskHistoryFiles(t, f.stateDir)
		if _, err := requestMachineAgentLocalGroup(machineAgentJoinSocketPath(f.stateDir, f.nodeID), request); err == nil || err.Error() == nodelocal.ErrMessageNotFound.Error() {
			t.Fatal("orphan sidecar proved absent history", err)
		}
		if after := taskHistoryFiles(t, f.stateDir); !reflect.DeepEqual(before, after) {
			t.Fatal("orphan sidecar recovery changed original files")
		}
		if err := os.Remove(path + suffix); err != nil {
			t.Fatal(err)
		}
	}

}
