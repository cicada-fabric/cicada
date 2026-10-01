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
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

type localSealedRPCTestFixture struct {
	bundle         nodekeys.PeerKeyAuthorizationBundle
	ownerKeys      map[string]*e2ee.Identity
	sourceIdentity *e2ee.Identity
	targetIdentity *e2ee.Identity
	linkExpiry     time.Time
}

func prepareLocalSealedRPCNode(t *testing.T, nativeID, nodeID string) string {
	t.Helper()
	workspace := prepareLocalSealedBridgeSession(t, nativeID)
	t.Setenv("CICADA_MACHINE_ID", nodeID)
	return workspace
}

func newLocalSealedRPCTestFixture(t *testing.T, stateDir string) localSealedRPCTestFixture {
	t.Helper()
	sourceIdentity, err := nodekeys.LoadOrCreate(machineNodeStateDir(stateDir, "node-a"), "ep-source")
	if err != nil {
		t.Fatal(err)
	}
	targetIdentity, err := nodekeys.LoadOrCreate(machineNodeStateDir(stateDir, "node-b"), "ep-target")
	if err != nil {
		t.Fatal(err)
	}
	sourceOwnerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	targetOwnerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(2 * time.Hour)
	contract := localLinkContract{
		LinkID:           "link-local-rpc",
		SourceEndpointID: "ep-source", SourcePrincipalID: "pr-source", SourceGroupID: "group-source",
		SourceOwnerID: "owner-source", SourceNodeID: "node-a",
		TargetEndpointID: "ep-target", TargetPrincipalID: "pr-target", TargetGroupID: "group-target",
		TargetOwnerID: "owner-target", TargetNodeID: "node-b",
		Direction: "forward", Actions: []string{"ask", "reply"}, DataScopes: []string{"thread.message"},
		TransportHubID: "hub-local-rpc", ExpiresAt: expires.Format(time.RFC3339),
		ScopeSnapshot: store.CommunicationLinkScopeSnapshot{
			SourceMembershipRevision: 1, SourceJoinRevision: 1, SourceGroupVersion: 1,
			TargetMembershipRevision: 1, TargetJoinRevision: 1, TargetGroupVersion: 1,
		},
	}
	canonical, err := json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	contractHash := sha256.Sum256(append([]byte("cicada/communication-link/proposal/v1\x00"), canonical...))
	contractDigest := hex.EncodeToString(contractHash[:])
	sourceSide := localSealedSendTestManifestSide(t, "ep-source", "group-source", "pr-source",
		"owner-source", "node-a", "binding-source", 3, sourceIdentity)
	targetSide := localSealedSendTestManifestSide(t, "ep-target", "group-target", "pr-target",
		"owner-target", "node-b", "binding-target", 4, targetIdentity)
	manifest := nodekeys.PeerKeyAuthorizationManifest{
		Version: 2, LinkID: contract.LinkID, LinkVersion: 1,
		ContractDigest: contractDigest, ContractCanonical: canonical,
		Source: sourceSide, Target: targetSide,
	}
	type claims struct {
		Version           int                          `json:"version"`
		LinkID            string                       `json:"link_id"`
		LinkVersion       int64                        `json:"link_version"`
		ContractDigest    string                       `json:"contract_digest"`
		ContractCanonical []byte                       `json:"contract_canonical"`
		Source            nodekeys.PeerKeyManifestSide `json:"source"`
		Target            nodekeys.PeerKeyManifestSide `json:"target"`
	}
	manifestBytes, err := json.Marshal(claims{
		Version: manifest.Version, LinkID: manifest.LinkID, LinkVersion: manifest.LinkVersion,
		ContractDigest: manifest.ContractDigest, ContractCanonical: manifest.ContractCanonical,
		Source: manifest.Source, Target: manifest.Target,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestHash := sha256.Sum256(append([]byte("cicada/communication-link/key-manifest/v2\x00"), manifestBytes...))
	manifest.Digest = hex.EncodeToString(manifestHash[:])
	sourceGrant, err := sourceOwnerKey.SignOwnerLinkKeyGrant("owner-source", contract.LinkID,
		contractDigest, manifest.Digest, uint64(manifest.LinkVersion), e2ee.OwnerLinkGrantSideSource,
		now.Add(-time.Minute), expires)
	if err != nil {
		t.Fatal(err)
	}
	targetGrant, err := targetOwnerKey.SignOwnerLinkKeyGrant("owner-target", contract.LinkID,
		contractDigest, manifest.Digest, uint64(manifest.LinkVersion), e2ee.OwnerLinkGrantSideTarget,
		now.Add(-time.Minute), expires)
	if err != nil {
		t.Fatal(err)
	}
	bundle := nodekeys.PeerKeyAuthorizationBundle{
		Manifest: manifest, LinkState: "PROPOSED",
		SourceContextScope: nodekeys.PeerNativeContextScope{HubID: contract.TransportHubID,
			GroupID: contract.SourceGroupID, GroupContextPolicy: "group_scoped"},
		TargetContextScope: nodekeys.PeerNativeContextScope{HubID: contract.TransportHubID,
			GroupID: contract.TargetGroupID, GroupContextPolicy: "group_scoped"},
		SourceGrant: nodekeys.PeerOwnerKeyGrantEvidence{
			Side: string(e2ee.OwnerLinkGrantSideSource), OwnerID: "owner-source",
			OwnerKeyID: sourceOwnerKey.Public().ID, OwnerPublicIdentity: sourceOwnerKey.Public(),
			OwnerKeyState: "ACTIVE", OwnerKeyVersion: 1, CurrentStatus: "ACCEPTED", SignedProof: sourceGrant,
		},
		TargetGrant: nodekeys.PeerOwnerKeyGrantEvidence{
			Side: string(e2ee.OwnerLinkGrantSideTarget), OwnerID: "owner-target",
			OwnerKeyID: targetOwnerKey.Public().ID, OwnerPublicIdentity: targetOwnerKey.Public(),
			OwnerKeyState: "ACTIVE", OwnerKeyVersion: 1, CurrentStatus: "ACCEPTED", SignedProof: targetGrant,
		},
	}
	return localSealedRPCTestFixture{
		bundle: bundle, ownerKeys: map[string]*e2ee.Identity{
			"owner-source": sourceOwnerKey, "owner-target": targetOwnerKey,
		},
		sourceIdentity: sourceIdentity, targetIdentity: targetIdentity, linkExpiry: expires,
	}
}

func trustLocalSealedRPCTestOwners(t *testing.T, stateDir, nodeID string,
	ownerKeys map[string]*e2ee.Identity) {
	t.Helper()
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	for ownerID, ownerKey := range ownerKeys {
		fingerprint, err := nodekeys.PeerKeyFingerprint(ownerKey.Public())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.TrustOwnerApprovalKeyLocal(ownerID, ownerKey.Public().ID,
			ownerKey.Public(), fingerprint); err != nil {
			t.Fatal(err)
		}
	}
}

func localSealedRPCRequestFor(workspace, nativeID, nodeID, operation, endpointID,
	principalID, ownerID, groupID, bindingID string, epoch uint64) localSealedRPCRequest {
	return localSealedRPCRequest{
		Version: localSealedRPCProtocolVersion, Operation: operation, Harness: "codex",
		NativeSessionID: nativeID, NodeID: nodeID, Workspace: workspace,
		SessionToken: "cicada_session_rpc-test", EndpointID: endpointID,
		PrincipalID: principalID, OwnerID: ownerID, GroupID: groupID,
		BindingID: bindingID, BindingEpoch: epoch,
	}
}

func localSealedRPCOriginalRequest(bundle nodekeys.PeerKeyAuthorizationBundle) store.FabricRequest {
	return store.FabricRequest{
		RequestID: "rq_original-request", MessageID: "msg_original-request",
		SenderEndpointID:     bundle.Manifest.Source.EndpointID,
		SenderPrincipalID:    bundle.Manifest.Source.PrincipalID,
		SenderGroupID:        bundle.Manifest.Source.GroupID,
		SenderBindingID:      bundle.Manifest.Source.BindingID,
		SenderBindingEpoch:   bundle.Manifest.Source.BindingEpoch,
		ReceiverEndpointID:   bundle.Manifest.Target.EndpointID,
		ReceiverPrincipalID:  bundle.Manifest.Target.PrincipalID,
		ReceiverGroupID:      bundle.Manifest.Target.GroupID,
		ReceiverBindingID:    bundle.Manifest.Target.BindingID,
		ReceiverBindingEpoch: bundle.Manifest.Target.BindingEpoch,
		Digest:               strings.Repeat("a", 64), VisibilityPolicyRef: "thread.message",
		AuthorizationRef: localSealedAuthorizationRef + bundle.Manifest.LinkID,
		State:            store.FabricRequestOpen, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	}
}

func startLocalSealedRPCBridge(t *testing.T, stateDir, nodeID, nodeToken string,
	handler http.Handler) (*machineAgentJoinBridge, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, nodeID, nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridge.Close() })
	return bridge, server
}

func TestLocalSealedAskBridgePinsSealsAndRetriesExactRequest(t *testing.T) {
	const nativeID, nodeID = "thread-sealed-ask", "node-a"
	workspace := prepareLocalSealedRPCNode(t, nativeID, nodeID)
	stateDir := shortLocalJoinStateDir(t)
	fixture := newLocalSealedRPCTestFixture(t, stateDir)
	trustLocalSealedRPCTestOwners(t, stateDir, nodeID, fixture.ownerKeys)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	card := fabricpkg.NetworkCard{
		EndpointID: "ep-source", PrincipalID: "pr-source", GroupID: "group-source",
		NodeID: nodeID, Harness: "codex", Workspace: workspace,
		BindingID: "binding-source", BindingEpoch: 3, NativeSessionID: nativeID,
	}
	operationCreated := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	var observed []fabricpkg.NodeSealedLinkAskInput
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			if request.Header.Get("Authorization") != "CicadaSession cicada_session_rpc-test" ||
				request.Header.Get("Cicada-Group-Scope") != "group-source" {
				t.Errorf("ASK binding probe did not use current source session: %s", request.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(response).Encode(card)
		case "/v2/relay/nodes/node-a/links/link-local-rpc/authorization":
			if request.Header.Get("Authorization") != "CicadaNode "+nodeToken {
				t.Errorf("Link authorization lookup did not use Node credential")
			}
			_ = json.NewEncoder(response).Encode(fixture.bundle)
		case "/v2/relay/nodes/node-a/sealed/ask":
			data, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read sealed ASK: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			if bytes.Contains(data, []byte("private ask body")) {
				t.Error("Hub received ASK plaintext")
			}
			var input fabricpkg.NodeSealedLinkAskInput
			if err := json.Unmarshal(data, &input); err != nil {
				t.Errorf("decode sealed ASK: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			observed = append(observed, input)
			var envelope e2ee.EndpointMessageEnvelope
			if err := json.Unmarshal(input.Ciphertext, &envelope); err != nil || envelope.Context.Kind != "REQUEST" ||
				envelope.Context.RequestID != "rq_0123456789abcdef0123456789abcdef" ||
				envelope.Context.MessageID != "msg_0123456789abcdef0123456789abcdef" ||
				envelope.Context.SenderEndpointID != "ep-source" || envelope.Context.ReceiverEndpointID != "ep-target" {
				t.Errorf("sealed ASK did not contain the derived forward REQUEST route: %+v, err=%v", envelope.Context, err)
			}
			_ = json.NewEncoder(response).Encode(localSealedAskReceipt{
				RequestID: input.RequestID, MessageID: input.MessageID,
				State: store.FabricRequestOpen, ExpiresAt: input.ExpiresAt,
				ReplyMode: "asynchronous", PayloadMode: store.RelayPayloadModeSealedV1,
			})
		default:
			t.Errorf("unexpected Hub request %s %s", request.Method, request.URL.Path)
			http.NotFound(response, request)
		}
	})
	bridge, _ := startLocalSealedRPCBridge(t, stateDir, nodeID, nodeToken, handler)
	request := localSealedRPCRequestFor(workspace, nativeID, nodeID, "sealed_ask",
		"ep-source", "pr-source", "owner-source", "group-source", "binding-source", 3)
	request.OperationID = "op_0123456789abcdef0123456789abcdef"
	request.OperationCreatedAt = operationCreated.Format(time.RFC3339Nano)
	request.IdempotencyKey = "ask-idempotency-stable"
	request.LinkID = fixture.bundle.Manifest.LinkID
	request.DataScope = "thread.message"
	request.Body = "private ask body"

	first, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), request)
	if err != nil {
		t.Fatalf("first sealed ASK: %v", err)
	}
	second, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), request)
	if err != nil {
		t.Fatalf("retry sealed ASK: %v", err)
	}
	wantDeadline := operationCreated.Add(localSealedAskDefaultLifetime).Format(time.RFC3339Nano)
	if first.RequestID != "rq_0123456789abcdef0123456789abcdef" ||
		first.MessageID != "msg_0123456789abcdef0123456789abcdef" || first.Status != store.FabricRequestOpen ||
		first.Delivery != "RELAY_PERSISTED" || first.ReplyMode != "asynchronous" ||
		first.ExpiresAt != wantDeadline || second.ExpiresAt != first.ExpiresAt {
		t.Fatalf("unexpected ASK result/default deadline: first=%+v second=%+v", first, second)
	}
	if len(observed) != 2 || !bytes.Equal(observed[0].Ciphertext, observed[1].Ciphertext) ||
		observed[0].ExpiresAt != observed[1].ExpiresAt || observed[0].RequestID != observed[1].RequestID ||
		observed[0].MessageID != observed[1].MessageID || observed[0].DataScope != "thread.message" {
		t.Fatalf("retry changed durable ASK input/ciphertext: %#v", observed)
	}
	if first.Sequence == 0 || first.Sequence != second.Sequence || first.CiphertextReused || !second.CiphertextReused {
		t.Fatalf("unexpected durable ASK retry metadata: first=%+v second=%+v", first, second)
	}
	_ = bridge
}

func TestLocalSealedReplyDerivesReverseRouteFromNodeStatus(t *testing.T) {
	const nativeID, nodeID = "thread-sealed-reply", "node-b"
	workspace := prepareLocalSealedRPCNode(t, nativeID, nodeID)
	stateDir := shortLocalJoinStateDir(t)
	fixture := newLocalSealedRPCTestFixture(t, stateDir)
	trustLocalSealedRPCTestOwners(t, stateDir, nodeID, fixture.ownerKeys)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	card := fabricpkg.NetworkCard{
		EndpointID: "ep-target", PrincipalID: "pr-target", GroupID: "group-target",
		NodeID: nodeID, Harness: "codex", Workspace: workspace,
		BindingID: "binding-target", BindingEpoch: 4, NativeSessionID: nativeID,
	}
	original := localSealedRPCOriginalRequest(fixture.bundle)
	var replyCalls atomic.Int32
	var observed fabricpkg.NodeSealedLinkReplyInput
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			_ = json.NewEncoder(response).Encode(card)
		case "/v2/relay/nodes/node-b/sealed/requests/rq_original-request":
			_ = json.NewEncoder(response).Encode(original)
		case "/v2/relay/nodes/node-b/links/link-local-rpc/authorization":
			_ = json.NewEncoder(response).Encode(fixture.bundle)
		case "/v2/relay/nodes/node-b/sealed/reply":
			replyCalls.Add(1)
			data, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read sealed REPLY: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			if bytes.Contains(data, []byte("private reply body")) {
				t.Error("Hub received REPLY plaintext")
			}
			if err := json.Unmarshal(data, &observed); err != nil {
				t.Errorf("decode sealed REPLY: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			var envelope e2ee.EndpointMessageEnvelope
			if err := json.Unmarshal(observed.Ciphertext, &envelope); err != nil || envelope.Context.Kind != "REPLY" ||
				envelope.Context.RequestID != original.RequestID || envelope.Context.ReplyTo != original.MessageID ||
				envelope.Context.SenderEndpointID != "ep-target" || envelope.Context.ReceiverEndpointID != "ep-source" ||
				envelope.Context.MessageID != "msg_abcdefabcdefabcdefabcdefabcdefab" {
				t.Errorf("REPLY route was not derived from original request status: %+v, err=%v", envelope.Context, err)
			}
			_ = json.NewEncoder(response).Encode(localSealedReplyReceipt{
				RequestID: original.RequestID, MessageID: observed.MessageID,
				State: store.FabricRequestReplied, PayloadMode: store.RelayPayloadModeSealedV1,
			})
		default:
			t.Errorf("unexpected Hub request %s %s", request.Method, request.URL.Path)
			http.NotFound(response, request)
		}
	})
	_, _ = startLocalSealedRPCBridge(t, stateDir, nodeID, nodeToken, handler)
	request := localSealedRPCRequestFor(workspace, nativeID, nodeID, "sealed_reply",
		"ep-target", "pr-target", "owner-target", "group-target", "binding-target", 4)
	request.OperationID = "op_abcdefabcdefabcdefabcdefabcdefab"
	request.IdempotencyKey = "reply-idempotency-stable"
	request.LinkID = fixture.bundle.Manifest.LinkID
	request.RequestID = original.RequestID
	request.Body = "private reply body"
	contract, err := parseLocalLinkContract(fixture.bundle.Manifest.ContractCanonical)
	if err != nil {
		t.Fatal(err)
	}
	if !sealedRequestMatchesManifest(&original, fixture.bundle.Manifest, contract.Direction) {
		t.Fatalf("synthetic original request does not match its signed Link route: sender=%s/%s receiver=%s/%s direction=%s",
			original.SenderEndpointID, original.SenderBindingID, original.ReceiverEndpointID,
			original.ReceiverBindingID, contract.Direction)
	}
	if !localCardMatchesStatusReceiver(card, request, &original, nodeID) {
		t.Fatalf("synthetic responder card does not match original route: endpoint=%s binding=%s epoch=%d native_session_match=%t workspace_match=%t",
			card.EndpointID, card.BindingID, card.BindingEpoch,
			card.NativeSessionID == request.NativeSessionID,
			filepath.Clean(card.Workspace) == filepath.Clean(request.Workspace))
	}
	result, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), request)
	if err != nil {
		t.Fatalf("sealed REPLY: %v", err)
	}
	if result.RequestID != original.RequestID || result.MessageID != "msg_abcdefabcdefabcdefabcdefabcdefab" ||
		result.LinkID != fixture.bundle.Manifest.LinkID || result.Status != store.FabricRequestReplied ||
		result.Delivery != "RELAY_PERSISTED" || result.PayloadMode != store.RelayPayloadModeSealedV1 || replyCalls.Load() != 1 {
		t.Fatalf("unexpected sealed REPLY result: %+v calls=%d", result, replyCalls.Load())
	}
	if observed.RequestID != original.RequestID || observed.DataScope != original.VisibilityPolicyRef ||
		observed.MessageID != result.MessageID {
		t.Fatalf("Hub REPLY input did not use status-derived correlation/scope: %+v", observed)
	}
}

func TestLocalSealedReplyLateResultIsNotReportedAsDelivered(t *testing.T) {
	const nativeID, nodeID = "thread-sealed-late-reply", "node-b"
	workspace := prepareLocalSealedRPCNode(t, nativeID, nodeID)
	stateDir := shortLocalJoinStateDir(t)
	fixture := newLocalSealedRPCTestFixture(t, stateDir)
	trustLocalSealedRPCTestOwners(t, stateDir, nodeID, fixture.ownerKeys)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	card := fabricpkg.NetworkCard{
		EndpointID: "ep-target", PrincipalID: "pr-target", GroupID: "group-target",
		NodeID: nodeID, Harness: "codex", Workspace: workspace,
		BindingID: "binding-target", BindingEpoch: 4, NativeSessionID: nativeID,
	}
	original := localSealedRPCOriginalRequest(fixture.bundle)
	original.State = store.FabricRequestExpired
	original.ExpiredAt = time.Now().UTC().Format(time.RFC3339Nano)
	var replyCalls atomic.Int32
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			_ = json.NewEncoder(response).Encode(card)
		case "/v2/relay/nodes/node-b/sealed/requests/rq_original-request":
			_ = json.NewEncoder(response).Encode(original)
		case "/v2/relay/nodes/node-b/links/link-local-rpc/authorization":
			_ = json.NewEncoder(response).Encode(fixture.bundle)
		case "/v2/relay/nodes/node-b/sealed/reply":
			replyCalls.Add(1)
			_ = json.NewEncoder(response).Encode(localSealedReplyReceipt{
				RequestID: original.RequestID, MessageID: "msg_abcdefabcdefabcdefabcdefabcdefab",
				State: store.FabricRequestLateResult, PayloadMode: store.RelayPayloadModeSealedV1,
			})
		default:
			http.NotFound(response, request)
		}
	})
	_, _ = startLocalSealedRPCBridge(t, stateDir, nodeID, nodeToken, handler)
	request := localSealedRPCRequestFor(workspace, nativeID, nodeID, "sealed_reply",
		"ep-target", "pr-target", "owner-target", "group-target", "binding-target", 4)
	request.OperationID = "op_abcdefabcdefabcdefabcdefabcdefab"
	request.IdempotencyKey = "late-reply-idempotency"
	request.RequestID = original.RequestID
	request.Body = "late private evidence"
	result, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), request)
	if err != nil {
		t.Fatalf("late sealed REPLY: %v", err)
	}
	if result.Status != store.FabricRequestLateResult || result.Delivery != "LATE_RESULT_RETAINED" ||
		strings.Contains(strings.ToLower(result.Delivery), "delivered") || replyCalls.Load() != 1 {
		t.Fatalf("late sealed REPLY was reported with the wrong delivery semantics: %+v", result)
	}
}

func TestLocalSealedRPCRejectsForgedSessionWrongScopeAndExpiredAsk(t *testing.T) {
	const nativeID, nodeID = "thread-sealed-validation", "node-a"
	workspace := prepareLocalSealedRPCNode(t, nativeID, nodeID)
	stateDir := shortLocalJoinStateDir(t)
	fixture := newLocalSealedRPCTestFixture(t, stateDir)
	trustLocalSealedRPCTestOwners(t, stateDir, nodeID, fixture.ownerKeys)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	card := fabricpkg.NetworkCard{
		EndpointID: "ep-source", PrincipalID: "pr-source", GroupID: "group-source",
		NodeID: nodeID, Harness: "codex", Workspace: workspace,
		BindingID: "binding-source", BindingEpoch: 3, NativeSessionID: nativeID,
	}
	var authorizationCalls, askCalls atomic.Int32
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			_ = json.NewEncoder(response).Encode(card)
		case "/v2/relay/nodes/node-a/links/link-local-rpc/authorization":
			authorizationCalls.Add(1)
			_ = json.NewEncoder(response).Encode(fixture.bundle)
		case "/v2/relay/nodes/node-a/sealed/ask":
			askCalls.Add(1)
			_ = json.NewEncoder(response).Encode(localSealedAskReceipt{
				RequestID: "rq_0123456789abcdef0123456789abcdef",
				MessageID: "msg_0123456789abcdef0123456789abcdef",
				State:     store.FabricRequestOpen, ReplyMode: "asynchronous",
				PayloadMode: store.RelayPayloadModeSealedV1,
			})
		default:
			http.NotFound(response, request)
		}
	})
	_, _ = startLocalSealedRPCBridge(t, stateDir, nodeID, nodeToken, handler)
	request := localSealedRPCRequestFor(workspace, nativeID, nodeID, "sealed_ask",
		"ep-source", "pr-source", "owner-source", "group-source", "binding-source", 3)
	request.OperationID = "op_0123456789abcdef0123456789abcdef"
	request.OperationCreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	request.IdempotencyKey = "validation-key"
	request.LinkID = fixture.bundle.Manifest.LinkID
	request.DataScope = "thread.message"
	request.Body = "validation body"

	forged := request
	forged.EndpointID = "ep-forged"
	if _, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), forged); err == nil {
		t.Fatal("forged endpoint passed current whoami binding")
	}
	if authorizationCalls.Load() != 0 || askCalls.Load() != 0 {
		t.Fatalf("forged endpoint reached Link/ASK endpoints: auth=%d ask=%d", authorizationCalls.Load(), askCalls.Load())
	}

	wrongScope := request
	wrongScope.DataScope = "not-authorized"
	if _, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), wrongScope); err == nil {
		t.Fatal("ASK with an unauthorized Link scope was accepted")
	}
	expired := request
	expired.ExpiresAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), expired); err == nil {
		t.Fatal("ASK with an expired deadline was accepted")
	}
	beyondLink := request
	beyondLink.ExpiresAt = fixture.linkExpiry.Add(time.Minute).Format(time.RFC3339Nano)
	if _, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), beyondLink); err == nil {
		t.Fatal("ASK deadline later than the signed Link expiry was accepted")
	}
	if askCalls.Load() != 0 {
		t.Fatalf("invalid ASK reached Hub acceptance endpoint: calls=%d", askCalls.Load())
	}
}

func TestLocalSealedReplyRejectsWrongLinkResponderAndMissingReplyGrant(t *testing.T) {
	const nativeID, nodeID = "thread-sealed-reply-deny", "node-b"
	workspace := prepareLocalSealedRPCNode(t, nativeID, nodeID)
	stateDir := shortLocalJoinStateDir(t)
	fixture := newLocalSealedRPCTestFixture(t, stateDir)
	trustLocalSealedRPCTestOwners(t, stateDir, nodeID, fixture.ownerKeys)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	card := fabricpkg.NetworkCard{
		EndpointID: "ep-target", PrincipalID: "pr-target", GroupID: "group-target",
		NodeID: nodeID, Harness: "codex", Workspace: workspace,
		BindingID: "binding-target", BindingEpoch: 4, NativeSessionID: nativeID,
	}
	original := localSealedRPCOriginalRequest(fixture.bundle)
	var authorizationCalls, replyCalls atomic.Int32
	activeBundle := fixture.bundle
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			_ = json.NewEncoder(response).Encode(card)
		case "/v2/relay/nodes/node-b/sealed/requests/rq_original-request":
			_ = json.NewEncoder(response).Encode(original)
		case "/v2/relay/nodes/node-b/links/link-local-rpc/authorization":
			authorizationCalls.Add(1)
			_ = json.NewEncoder(response).Encode(activeBundle)
		case "/v2/relay/nodes/node-b/sealed/reply":
			replyCalls.Add(1)
			_ = json.NewEncoder(response).Encode(localSealedReplyReceipt{
				RequestID: original.RequestID, MessageID: "msg_abcdefabcdefabcdefabcdefabcdefab",
				State: store.FabricRequestReplied, PayloadMode: store.RelayPayloadModeSealedV1,
			})
		default:
			http.NotFound(response, request)
		}
	})
	_, _ = startLocalSealedRPCBridge(t, stateDir, nodeID, nodeToken, handler)
	request := localSealedRPCRequestFor(workspace, nativeID, nodeID, "sealed_reply",
		"ep-target", "pr-target", "owner-target", "group-target", "binding-target", 4)
	request.OperationID = "op_abcdefabcdefabcdefabcdefabcdefab"
	request.IdempotencyKey = "reply-denial-key"
	request.LinkID = "link-other"
	request.RequestID = original.RequestID
	request.Body = "denied response"
	if _, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), request); err == nil {
		t.Fatal("reply with a mismatched Link selector was accepted")
	}
	if authorizationCalls.Load() != 0 || replyCalls.Load() != 0 {
		t.Fatalf("mismatched Link selector reached authorization or reply endpoint: auth=%d reply=%d", authorizationCalls.Load(), replyCalls.Load())
	}
	request.LinkID = fixture.bundle.Manifest.LinkID

	// A Source-side session cannot respond, even though that Node can read the
	// request lifecycle metadata for cancellation/status.
	request.EndpointID, request.PrincipalID = "ep-source", "pr-source"
	request.OwnerID, request.GroupID = "owner-source", "group-source"
	request.BindingID, request.BindingEpoch = "binding-source", 3
	card.EndpointID, card.PrincipalID, card.GroupID = "ep-source", "pr-source", "group-source"
	card.BindingID, card.BindingEpoch = "binding-source", 3
	if _, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), request); err == nil {
		t.Fatal("original requester was allowed to answer its own request as responder")
	}
	if replyCalls.Load() != 0 {
		t.Fatal("wrong Link/responder reached sealed REPLY Hub endpoint")
	}

	// Restore the actual target binding, then remove the reverse reply action.
	request.EndpointID, request.PrincipalID = "ep-target", "pr-target"
	request.OwnerID, request.GroupID = "owner-target", "group-target"
	request.BindingID, request.BindingEpoch = "binding-target", 4
	card.EndpointID, card.PrincipalID, card.GroupID = "ep-target", "pr-target", "group-target"
	card.BindingID, card.BindingEpoch = "binding-target", 4
	contract, err := parseLocalLinkContract(activeBundle.Manifest.ContractCanonical)
	if err != nil {
		t.Fatal(err)
	}
	contract.Actions = []string{"ask"}
	activeBundle.Manifest.ContractCanonical, err = json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), request); err == nil {
		t.Fatal("sealed REPLY without the Link's reply action was accepted")
	}
	if replyCalls.Load() != 0 {
		t.Fatal("missing reply grant reached sealed REPLY Hub endpoint")
	}
}

func TestLocalSealedRPCClassifiesHubRejectionAsDefinitive(t *testing.T) {
	const nativeID, nodeID = "thread-sealed-hub-deny", "node-a"
	workspace := prepareLocalSealedRPCNode(t, nativeID, nodeID)
	stateDir := shortLocalJoinStateDir(t)
	fixture := newLocalSealedRPCTestFixture(t, stateDir)
	trustLocalSealedRPCTestOwners(t, stateDir, nodeID, fixture.ownerKeys)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	card := fabricpkg.NetworkCard{
		EndpointID: "ep-source", PrincipalID: "pr-source", GroupID: "group-source",
		NodeID: nodeID, Harness: "codex", Workspace: workspace,
		BindingID: "binding-source", BindingEpoch: 3, NativeSessionID: nativeID,
	}
	var status int32 = http.StatusForbidden
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			_ = json.NewEncoder(response).Encode(card)
		case "/v2/relay/nodes/node-a/links/link-local-rpc/authorization":
			_ = json.NewEncoder(response).Encode(fixture.bundle)
		case "/v2/relay/nodes/node-a/sealed/ask":
			http.Error(response, "denied", int(atomic.LoadInt32(&status)))
		default:
			http.NotFound(response, request)
		}
	})
	_, _ = startLocalSealedRPCBridge(t, stateDir, nodeID, nodeToken, handler)
	request := localSealedRPCRequestFor(workspace, nativeID, nodeID, "sealed_ask",
		"ep-source", "pr-source", "owner-source", "group-source", "binding-source", 3)
	request.OperationID = "op_0123456789abcdef0123456789abcdef"
	request.OperationCreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	request.IdempotencyKey = "hub-rejection-key"
	request.LinkID = fixture.bundle.Manifest.LinkID
	request.DataScope = "thread.message"
	request.Body = "body rejected by Hub"
	_, err = requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), request)
	if err == nil || localSealedSendRetryable(err) {
		t.Fatalf("definitive Hub authorization rejection should not be marked retryable: %v", err)
	}
}

func TestLocalSealedRPCSocketRejectsUnknownCallerControlledCorrelationFields(t *testing.T) {
	workspace := prepareLocalSealedRPCNode(t, "thread-sealed-strict", "node-a")
	stateDir := shortLocalJoinStateDir(t)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	var hubCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		hubCalls.Add(1)
		http.NotFound(response, request)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-a", nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	connection, err := netDialLocalBridge(machineAgentJoinSocketPath(stateDir, "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(connection, `{"version":1,"operation":"sealed_reply","harness":"codex","native_session_id":"thread-sealed-strict","node_id":"node-a","workspace":"`+strings.ReplaceAll(filepath.ToSlash(workspace), `\`, `\\`)+`","session_token":"cicada_session","endpoint_id":"ep","principal_id":"pr","owner_id":"owner","group_id":"group","binding_id":"binding","binding_epoch":1,"operation_id":"op_0123456789abcdef0123456789abcdef","idempotency_key":"k","request_id":"rq_x","body":"answer","reply_to":"model-controlled"}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(connection)
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error == "" || hubCalls.Load() != 0 {
		t.Fatalf("unknown caller-controlled reply_to was not rejected before Hub access: response=%+v calls=%d", response, hubCalls.Load())
	}
}

func TestLocalSealedStatusAndCancelUseNodeCredentialAndCurrentSession(t *testing.T) {
	const nativeID, nodeID = "thread-sealed-status", "node-a"
	workspace := prepareLocalSealedRPCNode(t, nativeID, nodeID)
	stateDir := shortLocalJoinStateDir(t)
	fixture := newLocalSealedRPCTestFixture(t, stateDir)
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	card := fabricpkg.NetworkCard{
		EndpointID: "ep-source", PrincipalID: "pr-source", GroupID: "group-source",
		NodeID: nodeID, Harness: "codex", Workspace: workspace,
		BindingID: "binding-source", BindingEpoch: 3, NativeSessionID: nativeID,
	}
	original := localSealedRPCOriginalRequest(fixture.bundle)
	var cancelCalls atomic.Int32
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/fabric/whoami":
			if request.Header.Get("Authorization") != "CicadaSession cicada_session_rpc-test" {
				t.Errorf("status/cancel whoami did not use session credential")
			}
			_ = json.NewEncoder(response).Encode(card)
		case "/v2/relay/nodes/node-a/sealed/requests/rq_original-request":
			if request.Header.Get("Authorization") != "CicadaNode "+nodeToken {
				t.Errorf("request status did not use private Node credential")
			}
			_ = json.NewEncoder(response).Encode(original)
		case "/v2/relay/nodes/node-a/sealed/requests/rq_original-request/cancel":
			cancelCalls.Add(1)
			if request.Header.Get("Authorization") != "CicadaNode "+nodeToken {
				t.Errorf("request cancellation did not use private Node credential")
			}
			var input struct {
				Reason string `json:"reason,omitempty"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.Reason != "stop waiting" {
				t.Errorf("unexpected cancellation body: %+v err=%v", input, err)
			}
			cancelled := original
			cancelled.State = store.FabricRequestCancelRequested
			_ = json.NewEncoder(response).Encode(cancelled)
		default:
			http.NotFound(response, request)
		}
	})
	_, _ = startLocalSealedRPCBridge(t, stateDir, nodeID, nodeToken, handler)
	base := localSealedRPCRequestFor(workspace, nativeID, nodeID, "sealed_status",
		"ep-source", "pr-source", "owner-source", "group-source", "binding-source", 3)
	base.RequestID = original.RequestID
	status, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), base)
	if err != nil {
		t.Fatalf("sealed request status: %v", err)
	}
	if status.RequestID != original.RequestID || status.MessageID != original.MessageID ||
		status.LinkID != fixture.bundle.Manifest.LinkID || status.Status != store.FabricRequestOpen ||
		status.PayloadMode != store.RelayPayloadModeSealedV1 {
		t.Fatalf("unexpected sealed status metadata: %+v", status)
	}
	cancel := base
	cancel.Operation = "sealed_cancel"
	cancel.Reason = "stop waiting"
	cancelled, err := requestMachineAgentSealedRPC(machineAgentJoinSocketPath(stateDir, nodeID), cancel)
	if err != nil {
		t.Fatalf("sealed request cancel: %v", err)
	}
	if cancelled.RequestID != original.RequestID || cancelled.Status != store.FabricRequestCancelRequested || cancelCalls.Load() != 1 {
		t.Fatalf("unexpected sealed cancellation metadata: %+v calls=%d", cancelled, cancelCalls.Load())
	}
}
