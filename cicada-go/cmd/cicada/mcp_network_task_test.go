package main

import (
	"encoding/json"
	"errors"
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
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestMCPNetworkTaskToolsAreRegisteredAndRejectCallerAuthorityClaims(t *testing.T) {
	want := map[string]struct{}{
		"cicada_network_task_offer": {}, "cicada_network_task_list": {}, "cicada_network_task_get": {},
		"cicada_network_task_claim": {}, "cicada_network_task_result": {}, "cicada_network_task_accept": {},
	}
	got := make(map[string]map[string]any)
	for _, raw := range cicadaMCPTools() {
		name, _ := raw["name"].(string)
		if _, ok := want[name]; ok {
			got[name] = raw
		}
	}
	if len(got) != len(want) {
		t.Fatalf("registered Network Task tools = %v, want %v", got, want)
	}
	for name := range want {
		if !isCicadaMCPTool(name) || !isMCPNetworkTaskTool(name) {
			t.Fatalf("%s is not routed through the common MCP tool gate", name)
		}
		input, ok := got[name]["inputSchema"].(map[string]any)
		if !ok || input["additionalProperties"] != false {
			t.Fatalf("%s lacks a closed argument schema", name)
		}
	}
	for _, name := range []string{"cicada_network_task_offer", "cicada_network_task_result"} {
		properties, _ := got[name]["inputSchema"].(map[string]any)["properties"].(map[string]any)
		if _, ok := properties["record_refs"]; !ok {
			t.Fatalf("%s does not expose exact GroupSpace references inside the sealed body", name)
		}
	}
	claimSchema := got["cicada_network_task_claim"]["inputSchema"].(map[string]any)
	required, _ := claimSchema["required"].([]string)
	if len(required) == 0 {
		// JSON-shaped schemas use []any when returned through a generic map.
		if values, ok := claimSchema["required"].([]any); ok {
			for _, value := range values {
				if value == "lease_seconds" {
					return
				}
			}
		}
		t.Fatal("Network Task claim schema does not require lease_seconds")
	}
	for _, key := range required {
		if key == "lease_seconds" {
			return
		}
	}
	t.Fatal("Network Task claim schema does not require lease_seconds")
}

func TestMCPNetworkTaskArgumentsRejectForgedIdentityAndUnknownFields(t *testing.T) {
	for _, key := range []string{"sender_endpoint_id", "principal_id", "owner_epoch", "role", "user_approved", "group_id", "session_token"} {
		if err := validateMCPArguments("cicada_network_task_offer", map[string]any{
			"network_id": "net_synthetic", "targets": []any{"ep_synthetic_peer"},
			"body": "synthetic", "expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
			"idempotency_key": "synthetic-key", key: "forged",
		}); err == nil {
			t.Fatalf("Network Task tool accepted caller authority field %q", key)
		}
	}
	if err := validateMCPArguments("cicada_network_task_offer", map[string]any{
		"network_id": "net_synthetic", "targets": []any{"ep_synthetic_peer"},
		"body": "synthetic", "expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		"idempotency_key": "synthetic-key", "debug": true,
	}); err == nil {
		t.Fatal("Network Task tool accepted an unknown argument")
	}
}

func TestMCPNetworkTaskIntegerArgumentsRejectLossyValuesBeforeHTTP(t *testing.T) {
	var calls int
	hub := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method == http.MethodGet {
			_ = json.NewEncoder(response).Encode(map[string]any{"tasks": []any{}})
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"status": "ok"})
	}))
	defer hub.Close()
	mcp := &mcpServer{baseURL: hub.URL}
	state := networkCLIState{NetworkID: "net_synthetic", SessionToken: "synthetic-network-token"}
	taskID := "ntask_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	invalid := []struct {
		name string
		tool string
		args map[string]any
	}{
		{"claim fractional revision", "cicada_network_task_claim", map[string]any{"task_id": taskID,
			"expected_revision": 1.5, "lease_seconds": 300, "idempotency_key": "synthetic-key"}},
		{"claim string revision", "cicada_network_task_claim", map[string]any{"task_id": taskID,
			"expected_revision": "1", "lease_seconds": 300, "idempotency_key": "synthetic-key"}},
		{"claim fractional lease", "cicada_network_task_claim", map[string]any{"task_id": taskID,
			"expected_revision": int64(1), "lease_seconds": 1.5, "idempotency_key": "synthetic-key"}},
		{"claim string lease", "cicada_network_task_claim", map[string]any{"task_id": taskID,
			"expected_revision": int64(1), "lease_seconds": "300", "idempotency_key": "synthetic-key"}},
		{"claim boolean lease", "cicada_network_task_claim", map[string]any{"task_id": taskID,
			"expected_revision": int64(1), "lease_seconds": true, "idempotency_key": "synthetic-key"}},
		{"claim missing lease", "cicada_network_task_claim", map[string]any{"task_id": taskID,
			"expected_revision": int64(1), "idempotency_key": "synthetic-key"}},
		{"accept fractional revision", "cicada_network_task_accept", map[string]any{"task_id": taskID,
			"result_id": "result_synthetic", "expected_revision": 2.5}},
		{"accept overflow revision", "cicada_network_task_accept", map[string]any{"task_id": taskID,
			"result_id": "result_synthetic", "expected_revision": uint64(^uint64(0))}},
		{"list fractional limit", "cicada_network_task_list", map[string]any{"limit": 2.5}},
		{"list string limit", "cicada_network_task_list", map[string]any{"limit": "12"}},
		{"list boolean limit", "cicada_network_task_list", map[string]any{"limit": false}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := mcp.networkTaskToolLocked(test.tool, test.args, harness.SessionContext{}, state); err == nil {
				t.Fatal("invalid integer input was accepted")
			}
		})
	}
	if calls != 0 {
		t.Fatalf("invalid MCP integer inputs reached Hub %d times", calls)
	}
	if _, err := mcp.networkTaskToolLocked("cicada_network_task_claim", map[string]any{
		"task_id": taskID, "expected_revision": int64(7), "lease_seconds": int64(300),
		"idempotency_key": "synthetic-key",
	}, harness.SessionContext{}, state); err != nil {
		t.Fatalf("valid integer claim failed: %v", err)
	}
	if _, err := mcp.networkTaskToolLocked("cicada_network_task_list", map[string]any{}, harness.SessionContext{}, state); err != nil {
		t.Fatalf("default bounded Task list failed: %v", err)
	}
	if calls != 2 {
		t.Fatalf("valid MCP integer inputs reached Hub %d times, want 2", calls)
	}
}

func TestMCPNetworkTaskOutboxConcurrentOfferKeyHasOneStableTaskAndRouteIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.sqlite3")
	scope := mcpOutboxScope{APIOrigin: "http://synthetic-hub", Scope: "synthetic-native-scope", Harness: "codex",
		NativeSessionID: "thread_synthetic", NodeID: "node_synthetic", Workspace: "/synthetic",
		EndpointID: "ep_synthetic_publisher", NetworkID: "net_synthetic"}
	input := mcpOutboxInput{NetworkID: scope.NetworkID, Targets: "ep_synthetic_a,ep_synthetic_b",
		Body: "synthetic task body", ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)}
	boxes := []*mcpOutboxStore{newMCPOutbox(path), newMCPOutbox(path)}
	t.Cleanup(func() {
		for _, box := range boxes {
			_ = box.close()
		}
	})
	for _, box := range boxes {
		if _, err := box.findByIdempotencyKey(scope, "schema-initialization"); err != nil {
			t.Fatalf("initialize independent outbox handle: %v", err)
		}
	}
	start := make(chan struct{})
	results := make([]mcpOutboxOperation, len(boxes))
	errs := make([]error, len(boxes))
	var group sync.WaitGroup
	for index, box := range boxes {
		group.Add(1)
		go func(index int, box *mcpOutboxStore) {
			defer group.Done()
			<-start
			results[index], errs[index] = (&mcpServer{}).prepareNetworkTaskOperation(box, scope,
				"network_task_offer", "synthetic-stable-offer-key", input, true)
		}(index, box)
	}
	close(start)
	group.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("concurrent offer prepare %d: %v", index, err)
		}
	}
	if results[0].OperationID != results[1].OperationID {
		t.Fatalf("same idempotency key reserved different operation IDs: %q / %q", results[0].OperationID, results[1].OperationID)
	}
	var first, second mcpOutboxInput
	if json.Unmarshal([]byte(results[0].InputJSON), &first) != nil || json.Unmarshal([]byte(results[1].InputJSON), &second) != nil ||
		!validNetworkTaskID(first.TaskID) || first.TaskID != second.TaskID {
		t.Fatalf("same idempotency key reserved different Task IDs: %#v %#v", first, second)
	}
	for _, target := range []string{"ep_synthetic_a", "ep_synthetic_b"} {
		if networkTaskChildOperationID(results[0].OperationID, target) != networkTaskChildOperationID(results[1].OperationID, target) {
			t.Fatal("retry would use a different sealed route identity")
		}
	}
	for name, changed := range map[string]mcpOutboxInput{
		"body":     {NetworkID: input.NetworkID, Targets: input.Targets, Body: "different body", ExpiresAt: input.ExpiresAt},
		"targets":  {NetworkID: input.NetworkID, Targets: "ep_synthetic_a,ep_synthetic_c", Body: input.Body, ExpiresAt: input.ExpiresAt},
		"deadline": {NetworkID: input.NetworkID, Targets: input.Targets, Body: input.Body, ExpiresAt: time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339Nano)},
	} {
		if _, err := (&mcpServer{}).prepareNetworkTaskOperation(boxes[0], scope,
			"network_task_offer", "synthetic-stable-offer-key", changed, true); !errors.Is(err, errMCPOutboxConflict) {
			t.Errorf("same offer key with changed %s returned %v", name, err)
		}
	}
}

func TestMCPNetworkOnlyTaskListNeedsNoGroupAndRejectsOtherNetwork(t *testing.T) {
	const nativeID = "thread-network-task-only"
	workspace := prepareMCPJoinSessionRecord(t, nativeID)
	t.Setenv("CODEX_THREAD_ID", nativeID)
	t.Setenv("CODEX_SESSION_ID", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_MACHINE_ID", "node-network-task-only")
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_NETWORK_SESSION_DIR", stateRoot)
	var networkCalls int
	hub := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/fabric/networks/net_task_only/tasks/list" || request.Method != http.MethodGet ||
			request.Header.Get("Authorization") != "Cicada-Network-Session synthetic-network-credential" {
			http.Error(response, "wrong request", http.StatusForbidden)
			return
		}
		networkCalls++
		_ = json.NewEncoder(response).Encode(map[string]any{"tasks": []any{}})
	}))
	defer hub.Close()
	context := harness.SessionContext{Harness: "codex", NativeSessionID: nativeID,
		MachineID: "node-network-task-only", Workspace: workspace}
	scope, _, err := mcpSessionScope(hub.URL, context)
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := privateNetworkScopeDir(stateRoot, scope, true)
	if err != nil {
		t.Fatal(err)
	}
	statePath, err := mcpNetworkFile(stateDir, "net_task_only", ".session.json")
	if err != nil {
		t.Fatal(err)
	}
	origin, err := normalizeMCPAPIOrigin(hub.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := networkCLIState{Version: 1, APIOrigin: origin, NetworkID: "net_task_only",
		EndpointID: "ep_task_only", Harness: "codex", NativeSessionID: nativeID,
		NodeID: context.MachineID, Workspace: workspace, SessionToken: "synthetic-network-credential"}
	if err := writeNewPrivateNetworkFile(statePath, mustJSON(state)); err != nil {
		t.Fatal(err)
	}
	mcp := newMCPServer(hub.URL, "", "")
	defer close(mcp.stop)
	if _, err := mcp.callTool("cicada_network_task_list", map[string]any{"network_id": "net_task_only"}); err != nil {
		t.Fatalf("Network-only Task list required a Group session: %v", err)
	}
	if networkCalls != 1 {
		t.Fatalf("Network Task list calls=%d, want 1", networkCalls)
	}
	if _, err := mcp.callTool("cicada_network_task_list", map[string]any{"network_id": "net_other"}); err == nil {
		t.Fatal("Network Task request reused another Network's private credential")
	}
	if networkCalls != 1 {
		t.Fatalf("other Network selection reached Hub: calls=%d", networkCalls)
	}
}

func TestMachineNetworkTaskOfferWinnerFreshAuthorizationAndPayloadEpoch(t *testing.T) {
	taskID := "ntask_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	deadline := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	makeAttempt := func(receiver, messageSuffix string, status, owner string, epoch int64) (fabric.NetworkDirectDelivery, store.NetworkDirectDeliveryAuthorization) {
		messageID := taskID + ":offer:" + messageSuffix
		route := store.RelaySealedV1Route{MessageID: messageID, SenderEndpointID: "ep_publisher",
			ReceiverEndpointID: receiver, Kind: "send"}
		context := e2ee.NetworkDirectContext{HubID: "hub_synthetic", NetworkID: "net_synthetic",
			MessageID: messageID, Kind: "SEND", SenderEndpointID: "ep_publisher", ReceiverEndpointID: receiver}
		delivery := fabric.NetworkDirectDelivery{NetworkID: "net_synthetic", RelaySealedV1DeliveryAttempt: store.RelaySealedV1DeliveryAttempt{
			MessageID: messageID, RecipientEndpointID: receiver, Route: route,
		}}
		return delivery, store.NetworkDirectDeliveryAuthorization{NetworkID: "net_synthetic", EndpointID: receiver,
			Context: context, Bundle: store.NetworkDirectPeerBundle{Purpose: e2ee.NetworkCollaborationPurposeTask},
			CollaborationContext: &e2ee.NetworkCollaborationMessageContext{Purpose: e2ee.NetworkCollaborationPurposeTask, Route: context},
			NetworkTask: &store.NetworkTaskDeliveryAuthorization{NetworkID: "net_synthetic", MessageID: messageID,
				TaskID: taskID, Kind: "offer", SenderEndpointID: "ep_publisher", ReceiverEndpointID: receiver,
				OwnerEndpointID: owner, OwnerEpoch: epoch, Revision: 2, Status: status, ExpiresAt: deadline}}
	}
	readyDelivery, readyAuth := makeAttempt("ep_winner", "ready", "READY", "", 0)
	if err := verifyMachineNetworkTaskAuthorization(readyDelivery, readyAuth); err != nil {
		t.Fatalf("valid pre-claim offer rejected: %v", err)
	}
	claimedDelivery, claimedAuth := makeAttempt("ep_winner", "winner", "CLAIMED", "ep_winner", 4)
	if err := verifyMachineNetworkTaskAuthorization(claimedDelivery, claimedAuth); err != nil {
		t.Fatalf("winner could not finish its already-claimed offer delivery: %v", err)
	}
	loserDelivery, loserAuth := makeAttempt("ep_loser", "loser", "CLAIMED", "ep_winner", 4)
	if err := verifyMachineNetworkTaskAuthorization(loserDelivery, loserAuth); err == nil {
		t.Fatal("another recipient decrypted the offer after a different Endpoint won the claim")
	}
	groupPayload, err := json.Marshal(groupSpaceMessagePayload{Type: groupSpaceMessagePayloadType,
		Version: groupSpaceMessagePayloadV1, Body: "inspect the selected record",
		RecordRefs: []groupSpaceMessageReference{{GroupID: "group_synthetic", RecordID: "journal_synthetic",
			Sequence: 3, Kind: "JOURNAL"}}})
	if err != nil {
		t.Fatal(err)
	}
	claimedPlaintext, err := marshalNetworkTaskSealedPayload("offer", taskID, 0, string(groupPayload))
	if err != nil {
		t.Fatal(err)
	}
	claimedPayload := []byte(claimedPlaintext)
	if err := verifyMachineNetworkTaskPayload(claimedDelivery, claimedAuth, claimedPayload); err != nil {
		t.Fatalf("claim epoch was incorrectly required inside the original offer payload: %v", err)
	}
	prompt := machineNetworkDirectPrompt(machineRelayJournalEntry{NetworkID: "net_synthetic", MessageID: claimedDelivery.MessageID,
		SenderEndpointID: "ep_publisher", EndpointID: "ep_winner", Kind: "send"}, claimedPayload)
	if strings.Contains(prompt, "record ciphertext") || !strings.Contains(prompt, `"record_id":"journal_synthetic"`) ||
		!strings.Contains(prompt, "must dereference") {
		t.Fatalf("Task reference was not shown only as an exact pointer with current-Guard guidance: %s", prompt)
	}
	wrongPurpose := claimedAuth
	wrongPurpose.Bundle.Purpose = e2ee.NetworkCollaborationPurposeBroadcast
	if err := verifyMachineNetworkTaskAuthorization(claimedDelivery, wrongPurpose); err == nil {
		t.Fatal("Network Task delivery accepted BROADCAST key purpose")
	}
	missingCollaboration := claimedAuth
	missingCollaboration.CollaborationContext = nil
	if err := verifyMachineNetworkTaskAuthorization(claimedDelivery, missingCollaboration); err == nil {
		t.Fatal("Network Task delivery fell back to ordinary direct envelope")
	}
}

func TestMachineNetworkTaskResultRequiresExactSubmittedEpoch(t *testing.T) {
	taskID := "ntask_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	messageID := taskID + ":result:7:cccccccccccccccccccccccccccccccc"
	deadline := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	delivery := fabric.NetworkDirectDelivery{NetworkID: "net_synthetic", RelaySealedV1DeliveryAttempt: store.RelaySealedV1DeliveryAttempt{
		MessageID: messageID, RecipientEndpointID: "ep_publisher",
		Route: store.RelaySealedV1Route{MessageID: messageID, SenderEndpointID: "ep_worker",
			ReceiverEndpointID: "ep_publisher", Kind: "send"},
	}}
	auth := store.NetworkDirectDeliveryAuthorization{NetworkID: "net_synthetic", EndpointID: "ep_publisher",
		Context: e2ee.NetworkDirectContext{HubID: "hub_synthetic", NetworkID: "net_synthetic",
			MessageID: messageID, Kind: "SEND", SenderEndpointID: "ep_worker", ReceiverEndpointID: "ep_publisher"},
		Bundle: store.NetworkDirectPeerBundle{Purpose: e2ee.NetworkCollaborationPurposeTask},
		CollaborationContext: &e2ee.NetworkCollaborationMessageContext{Purpose: e2ee.NetworkCollaborationPurposeTask,
			Route: e2ee.NetworkDirectContext{HubID: "hub_synthetic", NetworkID: "net_synthetic",
				MessageID: messageID, Kind: "SEND", SenderEndpointID: "ep_worker", ReceiverEndpointID: "ep_publisher"}},
		NetworkTask: &store.NetworkTaskDeliveryAuthorization{NetworkID: "net_synthetic", MessageID: messageID,
			TaskID: taskID, Kind: "result", SenderEndpointID: "ep_worker", ReceiverEndpointID: "ep_publisher",
			OwnerEndpointID: "ep_worker", OwnerEpoch: 7, Revision: 4, Status: "RESULT_SUBMITTED", ExpiresAt: deadline}}
	if err := verifyMachineNetworkTaskAuthorization(delivery, auth); err != nil {
		t.Fatalf("current result route rejected: %v", err)
	}
	if err := verifyMachineNetworkTaskPayload(delivery, auth, []byte(`{"kind":"result","task_id":"`+taskID+`","owner_epoch":7,"body":"synthetic result"}`)); err != nil {
		t.Fatalf("current result epoch rejected: %v", err)
	}
	if err := verifyMachineNetworkTaskPayload(delivery, auth, []byte(`{"kind":"result","task_id":"`+taskID+`","owner_epoch":6,"body":"synthetic result"}`)); err == nil {
		t.Fatal("sealed result from an old owner epoch was accepted")
	}
}

func TestMachineNetworkBroadcastRequiresExactPurposeRouteAndPayload(t *testing.T) {
	broadcastID := "nbroadcast_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	messageID := broadcastID + ":reader:ep_reader"
	deadline := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	context := e2ee.NetworkDirectContext{HubID: "hub_synthetic", NetworkID: "net_synthetic",
		MessageID: messageID, Kind: "SEND", SenderEndpointID: "ep_publisher", ReceiverEndpointID: "ep_reader"}
	delivery := fabric.NetworkDirectDelivery{NetworkID: "net_synthetic", RelaySealedV1DeliveryAttempt: store.RelaySealedV1DeliveryAttempt{
		MessageID: messageID, RecipientEndpointID: "ep_reader",
		Route: store.RelaySealedV1Route{MessageID: messageID, SenderEndpointID: "ep_publisher",
			ReceiverEndpointID: "ep_reader", Kind: "send"},
	}}
	auth := store.NetworkDirectDeliveryAuthorization{NetworkID: "net_synthetic", EndpointID: "ep_reader",
		Context: context, Bundle: store.NetworkDirectPeerBundle{Purpose: e2ee.NetworkCollaborationPurposeBroadcast},
		CollaborationContext: &e2ee.NetworkCollaborationMessageContext{Purpose: e2ee.NetworkCollaborationPurposeBroadcast, Route: context},
		NetworkBroadcast: &store.NetworkBroadcastDeliveryAuthorization{NetworkID: "net_synthetic",
			BroadcastID: broadcastID, MessageID: messageID, SenderEndpointID: "ep_publisher",
			ReceiverEndpointID: "ep_reader", Revision: 1, ExpiresAt: deadline, Status: "PUBLISHED"}}
	if err := verifyMachineNetworkTaskAuthorization(delivery, auth); err != nil {
		t.Fatalf("valid current Network Broadcast authorization rejected: %v", err)
	}
	groupPayload, err := json.Marshal(groupSpaceMessagePayload{Type: groupSpaceMessagePayloadType,
		Version: groupSpaceMessagePayloadV1, Body: "inspect the selected topic",
		RecordRefs: []groupSpaceMessageReference{{GroupID: "group_synthetic", RecordID: "topic_synthetic",
			Sequence: 9, Kind: "TOPIC", TopicID: "topic_synthetic"}}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := marshalNetworkBroadcastSealedPayload(broadcastID, string(groupPayload))
	if err != nil || verifyMachineNetworkTaskPayload(delivery, auth, []byte(payload)) != nil {
		t.Fatalf("valid Network Broadcast sealed payload rejected: %v", err)
	}
	prompt := machineNetworkDirectPrompt(machineRelayJournalEntry{NetworkID: "net_synthetic", MessageID: messageID,
		SenderEndpointID: "ep_publisher", EndpointID: "ep_reader", Kind: "send"}, []byte(payload))
	if !strings.Contains(prompt, `"record_id":"topic_synthetic"`) || !strings.Contains(prompt, "must dereference") {
		t.Fatalf("Broadcast reference was not shown with current-Guard guidance: %s", prompt)
	}
	wrongPurpose := auth
	wrongPurpose.Bundle.Purpose = e2ee.NetworkCollaborationPurposeTask
	if err := verifyMachineNetworkTaskAuthorization(delivery, wrongPurpose); err == nil {
		t.Fatal("Network Broadcast delivery accepted TASK key purpose")
	}
	wrongRoute := auth
	wrongRoute.NetworkBroadcast = &store.NetworkBroadcastDeliveryAuthorization{NetworkID: "net_synthetic",
		BroadcastID: broadcastID, MessageID: messageID, SenderEndpointID: "ep_other",
		ReceiverEndpointID: "ep_reader", Revision: 1, ExpiresAt: deadline, Status: "PUBLISHED"}
	if err := verifyMachineNetworkTaskAuthorization(delivery, wrongRoute); err == nil {
		t.Fatal("Network Broadcast delivery accepted mismatched publisher")
	}
	if err := verifyMachineNetworkTaskPayload(delivery, auth,
		[]byte(`{"version":1,"broadcast_id":"nbroadcast_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","body":"synthetic"}`)); err == nil {
		t.Fatal("Network Broadcast delivery accepted a payload for another broadcast")
	}
}
