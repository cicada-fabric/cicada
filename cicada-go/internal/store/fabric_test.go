package store

import (
	"errors"
	"testing"
)

func TestFabricEndpointIdentityAndMessageClaimAreDurable(t *testing.T) {
	persistence, err := New(t.TempDir() + "/state/cicada.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()

	first, err := persistence.UpsertEndpoint(Endpoint{
		Name: "planner", Role: "thread", Harness: "codex", NativeSessionID: "thread-planner",
		MachineID: "gpu1", Workspace: "~/AAA/le-wm", Status: "online",
		Capabilities: map[string]any{"wake": "codex_queue"}, Tags: []string{"planner"},
		Owner: "alice", Visibility: "private",
	})
	if err != nil {
		t.Fatal(err)
	}
	rejoined, err := persistence.UpsertEndpoint(Endpoint{
		Name: "planner-renamed", Role: "thread", Harness: "codex", NativeSessionID: "thread-planner",
		MachineID: "gpu2", Workspace: "~/AAA/le-wm", Status: "online",
		Capabilities: map[string]any{"wake": "codex_queue"}, Owner: "alice", Visibility: "private",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != rejoined.ID || rejoined.MachineID != "gpu2" || rejoined.Name != "planner-renamed" {
		t.Fatalf("native session did not retain stable endpoint identity: first=%#v rejoined=%#v", first, rejoined)
	}
	peer, err := persistence.UpsertEndpoint(Endpoint{
		Name: "benchmark", Role: "thread", Harness: "codex", NativeSessionID: "thread-benchmark",
		MachineID: "gpu3", Status: "online", Owner: "alice", Visibility: "private",
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := persistence.CreateFabricMessage(FabricMessage{
		RequestID: "rq_test", FromEndpointID: rejoined.ID, ToEndpointID: peer.ID,
		Kind: "ask", Body: "What is the best result?",
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := persistence.ClaimFabricMessages(peer.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].ID != message.ID || claimed[0].Status != "received" {
		t.Fatalf("unexpected claimed messages: %#v", claimed)
	}
	again, err := persistence.ClaimFabricMessages(peer.ID, 10)
	if err != nil || len(again) != 0 {
		t.Fatalf("message was claimed twice: %#v err=%v", again, err)
	}
}

func TestLegacyFabricAPIsRejectReadyEndpointsAndRelayEnvelopes(t *testing.T) {
	persistence, err := New(t.TempDir() + "/state/cicada.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()

	source, err := persistence.UpsertEndpoint(Endpoint{
		ID: "ep-source", Name: "source", Harness: "codex", NativeSessionID: "native-source",
		MachineID: "node-legacy", Status: "online",
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := persistence.UpsertEndpoint(Endpoint{
		ID: "ep-legacy-target", Name: "legacy-target", Harness: "codex", NativeSessionID: "native-target",
		MachineID: "node-legacy", Status: "online",
	})
	if err != nil {
		t.Fatal(err)
	}
	ready, err := persistence.UpsertEndpoint(Endpoint{
		ID: "ep-ready", Name: "ready", Harness: "codex", NativeSessionID: "native-ready",
		MachineID: "node-ready", Status: "online",
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := persistence.CreatePrincipal(Principal{
		ID: "principal-ready", Kind: PrincipalKindAgent, Name: "ready",
		Status: PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(Group{
		ID: "group-ready", OwnerPrincipalID: principal.ID, Name: "ready",
		State: GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMembership(Membership{
		PrincipalID: principal.ID, GroupID: group.ID, Role: "member",
		Status: MembershipStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.AssociateEndpoint(ready.ID, principal.ID, group.ID, ""); err != nil {
		t.Fatal(err)
	}

	if got, err := persistence.GetEndpoint(ready.ID); err != nil || got != nil {
		t.Fatalf("legacy endpoint lookup exposed READY row: %#v err=%v", got, err)
	}
	if got, err := persistence.GetEndpointBySession(ready.Harness, ready.NativeSessionID); err != nil || got != nil {
		t.Fatalf("legacy session lookup exposed READY row: %#v err=%v", got, err)
	}
	endpoints, err := persistence.ListEndpoints(EndpointFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("legacy endpoint list did not preserve pending rows: %#v", endpoints)
	}
	if _, err := persistence.CreateFabricMessage(FabricMessage{
		ID: "msg-for-ready", FromEndpointID: source.ID, ToEndpointID: ready.ID,
		Kind: "send", Body: "must be rejected",
	}); !errors.Is(err, ErrEndpointMigrationRequired) {
		t.Fatalf("legacy store write accepted READY endpoint: %v", err)
	}

	legacyMessage, err := persistence.CreateFabricMessage(FabricMessage{
		ID: "msg-legacy", FromEndpointID: source.ID, ToEndpointID: legacy.ID,
		Kind: "send", Body: "legacy body",
	})
	if err != nil {
		t.Fatal(err)
	}
	relayRequest, err := persistence.CreateFabricRequest(FabricRequest{
		RequestID: "rq-ready-relay", MessageID: "msg-ready-relay",
		SenderEndpointID: ready.ID, SenderPrincipalID: principal.ID,
		SenderGroupID: group.ID, ReceiverEndpointID: legacy.ID,
		ReceiverGroupID: group.ID, Body: "relay body",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := persistence.GetFabricMessage(relayRequest.MessageID); err != nil || got != nil {
		t.Fatalf("legacy message lookup exposed relay envelope: %#v err=%v", got, err)
	}
	if got, err := persistence.GetFabricRequest(relayRequest.RequestID); err != nil || got != nil {
		t.Fatalf("legacy request lookup exposed relay envelope: %#v err=%v", got, err)
	}
	allMessages, err := persistence.ListFabricMessages("", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range allMessages {
		if message.ID == relayRequest.MessageID {
			t.Fatalf("legacy global list exposed relay envelope: %#v", allMessages)
		}
	}
	claimed, err := persistence.ClaimFabricMessagesForMachine(legacy.MachineID, 10)
	if err != nil || len(claimed) != 1 || claimed[0].ID != legacyMessage.ID {
		t.Fatalf("machine claim did not preserve pending legacy message while excluding relay: %#v err=%v", claimed, err)
	}
}
