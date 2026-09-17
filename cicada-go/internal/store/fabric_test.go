package store

import "testing"

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
