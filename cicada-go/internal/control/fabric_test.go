package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func markFabricEndpointReady(t *testing.T, controlPlane *Control, endpointID string) {
	t.Helper()
	principal, err := controlPlane.store.CreatePrincipal(store.Principal{
		ID: "principal-" + endpointID, Kind: store.PrincipalKindAgent,
		Name: "principal-" + endpointID, Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := controlPlane.store.CreateGroup(store.Group{
		ID: "group-" + endpointID, OwnerPrincipalID: principal.ID,
		Name: "group-" + endpointID, State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.store.CreateMembership(store.Membership{
		PrincipalID: principal.ID, GroupID: group.ID, Role: "member",
		Status: store.MembershipStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.store.AssociateEndpoint(endpointID, principal.ID, group.ID, ""); err != nil {
		t.Fatal(err)
	}
}

func TestFabricJoinResolveAskAndReply(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())

	planner, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		Name: "planner", Harness: "codex", NativeSessionID: "thread-planner",
		MachineID: "gpu1", Workspace: "~/AAA/le-wm", Visibility: "fabric", Owner: "spoofed-owner",
		Tags: []string{"planning"}, Capabilities: map[string]any{"wake": "codex_queue"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if planner.Owner != controlPlane.Identity().ID {
		t.Fatalf("endpoint owner was not derived from Control identity: %q", planner.Owner)
	}
	rejoined, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		Harness: "codex", NativeSessionID: "thread-planner",
	})
	if err != nil || rejoined.ID != planner.ID {
		t.Fatalf("join was not idempotent: first=%#v second=%#v err=%v", planner, rejoined, err)
	}
	if rejoined.Name != "planner" || rejoined.MachineID != "gpu1" || rejoined.Workspace != "~/AAA/le-wm" || rejoined.Visibility != "fabric" || len(rejoined.Tags) != 1 || rejoined.Tags[0] != "planning" {
		t.Fatalf("sparse rejoin lost stable Endpoint metadata: %#v", rejoined)
	}
	benchmark, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		Name: "benchmark", Harness: "codex", NativeSessionID: "thread-benchmark",
		MachineID: "gpu2", Workspace: "/data/le-wm", Visibility: "private",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		EndpointID: planner.ID, Name: "wrong", Harness: "codex", NativeSessionID: "thread-benchmark",
		MachineID: "gpu1", Visibility: "private",
	}); err == nil {
		t.Fatal("join accepted an Endpoint ID bound to another native session")
	}
	resolved, err := controlPlane.ResolveEndpoint(EndpointResolveInput{Query: "benchmark", RequesterEndpointID: planner.ID})
	if err != nil || resolved.ID != benchmark.ID || resolved.Address != "benchmark@gpu2:/data/le-wm" {
		t.Fatalf("unexpected resolution: endpoint=%#v err=%v", resolved, err)
	}
	ask, err := controlPlane.AskFabric(FabricAskInput{
		FromEndpointID: planner.ID, Target: "benchmark@gpu2", Question: "What is the best benchmark?",
	})
	if err != nil || ask.RequestID == "" || ask.Status != "queued" {
		t.Fatalf("ask failed: message=%#v err=%v", ask, err)
	}
	inbox, err := controlPlane.ClaimFabricMessages(benchmark.ID, 10)
	if err != nil || len(inbox) != 1 || inbox[0].RequestID != ask.RequestID {
		t.Fatalf("request did not reach target inbox: %#v err=%v", inbox, err)
	}
	reply, err := controlPlane.ReplyFabric(FabricReplyInput{
		FromEndpointID: benchmark.ID, RequestID: ask.RequestID, Message: "2.31 ms",
	})
	if err != nil || reply.ReplyTo != ask.ID {
		t.Fatalf("reply failed: reply=%#v err=%v", reply, err)
	}
	responses, err := controlPlane.ClaimFabricMessages(planner.ID, 10)
	if err != nil || len(responses) != 1 || responses[0].Kind != "reply" || responses[0].Body != "2.31 ms" {
		t.Fatalf("reply did not reach original endpoint: %#v err=%v", responses, err)
	}
}

func TestFabricResolverNeverGuessesAmbiguousAlias(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	for _, machine := range []string{"gpu1", "gpu2"} {
		if _, err := controlPlane.JoinEndpoint(EndpointJoinInput{
			Name: "benchmark", Harness: "codex", NativeSessionID: "thread-" + machine,
			MachineID: machine, Workspace: "/data/" + machine, Visibility: "fabric",
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = controlPlane.ResolveEndpoint(EndpointResolveInput{Query: "benchmark"})
	if !errors.Is(err, ErrEndpointAmbiguous) {
		t.Fatalf("ambiguous alias was not rejected: %v", err)
	}
	resolved, err := controlPlane.ResolveEndpoint(EndpointResolveInput{Query: "benchmark@gpu2"})
	if err != nil || resolved.MachineID != "gpu2" {
		t.Fatalf("qualified alias did not resolve: endpoint=%#v err=%v", resolved, err)
	}
	if _, err := controlPlane.ResolveEndpoint(EndpointResolveInput{Query: "missing"}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing alias returned %v", err)
	}
}

func TestFabricEventsTrackEndpointAndMessageLifecycle(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())

	source, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		Name: "planner", Harness: "codex", NativeSessionID: "thread-planner",
		MachineID: "gpu1", Workspace: "/work/project", Visibility: "fabric",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		Name: "planner", Harness: "codex", NativeSessionID: "thread-planner",
		MachineID: "gpu2", Workspace: "/work/moved", Visibility: "fabric",
	}); err != nil {
		t.Fatal(err)
	}
	target, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		Name: "benchmark", Harness: "codex", NativeSessionID: "thread-benchmark",
		MachineID: "gpu2", Workspace: "/work/project", Visibility: "fabric",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.SendFabricMessage(FabricSendInput{
		FromEndpointID: source.ID, Target: target.ID, Message: "hello",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.LeaveEndpoint(target.ID); err != nil {
		t.Fatal(err)
	}
	events, err := controlPlane.FabricEvents("", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, event := range events {
		seen[event.Type] = true
		if len(event.Payload) == 0 {
			t.Fatalf("event %d has no payload", event.ID)
		}
	}
	for _, eventType := range []string{"EndpointJoined", "EndpointMoved", "FabricMessageQueued", "FabricMessageEnqueued", "EndpointLeft"} {
		if !seen[eventType] {
			t.Fatalf("missing Fabric event %q in %#v", eventType, events)
		}
	}
	if len(events) < 5 {
		t.Fatalf("expected lifecycle events, got %#v", events)
	}
	lastID := events[len(events)-1].ID
	if next, err := controlPlane.FabricEvents("", lastID, 100); err != nil || len(next) != 0 {
		t.Fatalf("event cursor did not advance: next=%#v err=%v", next, err)
	}
}

func TestRemoteMachineClaimsExactNativeSessionDelivery(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	source, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		Name: "planner", Harness: "codex", NativeSessionID: "thread-planner",
		MachineID: "gpu1", Visibility: "fabric",
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		Name: "benchmark", Harness: "codex", NativeSessionID: "thread-benchmark",
		MachineID: "gpu2", Visibility: "fabric",
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := controlPlane.AskFabric(FabricAskInput{FromEndpointID: source.ID, Target: target.ID, Question: "best result?"})
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := controlPlane.MachineFabricDeliveries("gpu2", 10)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("remote delivery missing: %#v err=%v", deliveries, err)
	}
	if deliveries[0].NativeSessionID != "thread-benchmark" || !strings.Contains(deliveries[0].Prompt, message.RequestID) {
		t.Fatalf("delivery does not target exact request/session: %#v", deliveries[0])
	}
	updated, err := controlPlane.CompleteMachineFabricDelivery("gpu2", message.ID, "")
	if err != nil || updated.Status != "delivered" {
		t.Fatalf("delivery completion failed: %#v err=%v", updated, err)
	}
}

func TestLegacyFabricRejectsReadyV2EndpointsAndRelayMessages(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())

	legacy, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		Name: "legacy", Harness: "codex", NativeSessionID: "thread-legacy",
		MachineID: "legacy-machine", Visibility: "fabric",
	})
	if err != nil {
		t.Fatal(err)
	}
	ready, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		Name: "ready", Harness: "codex", NativeSessionID: "thread-ready",
		MachineID: "ready-machine", Visibility: "fabric",
	})
	if err != nil {
		t.Fatal(err)
	}
	markFabricEndpointReady(t, controlPlane, ready.ID)

	listed, err := controlPlane.ListEndpoints(EndpointListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != legacy.ID {
		t.Fatalf("legacy list exposed a READY endpoint: %#v", listed)
	}
	if got, err := controlPlane.Endpoint(ready.ID); err != nil || got != nil {
		t.Fatalf("legacy endpoint lookup exposed READY endpoint: endpoint=%#v err=%v", got, err)
	}
	if got, err := controlPlane.EndpointBySession("codex", ready.NativeSessionID); err != nil || got != nil {
		t.Fatalf("legacy session lookup exposed READY endpoint: endpoint=%#v err=%v", got, err)
	}
	if _, err := controlPlane.ResolveEndpoint(EndpointResolveInput{Query: ready.ID}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy resolve accepted READY endpoint: %v", err)
	}
	if _, err := controlPlane.WhoAmI(ready.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy whoami accepted READY endpoint: %v", err)
	}
	if _, err := controlPlane.HeartbeatEndpoint(ready.ID, "online"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy heartbeat accepted READY endpoint: %v", err)
	}
	if _, err := controlPlane.LeaveEndpoint(ready.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy leave accepted READY endpoint: %v", err)
	}
	if current, err := controlPlane.store.GetEndpointV2(ready.ID); err != nil || current.Status != "online" || current.MigrationState != store.EndpointMigrationReady {
		t.Fatalf("legacy endpoint operation changed READY row: %#v err=%v", current, err)
	}

	if _, err := controlPlane.SendFabricMessage(FabricSendInput{
		FromEndpointID: legacy.ID, Target: ready.ID, Message: "blocked",
	}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy send reached READY target: %v", err)
	}
	if _, err := controlPlane.AskFabric(FabricAskInput{
		FromEndpointID: ready.ID, Target: legacy.ID, Question: "blocked",
	}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy ask accepted READY source: %v", err)
	}
	if _, err := controlPlane.FabricMessages(ready.ID, "", 10); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy message listing accepted READY endpoint: %v", err)
	}
	if _, err := controlPlane.ClaimFabricMessages(ready.ID, 10); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy claim accepted READY endpoint: %v", err)
	}
	if _, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		EndpointID: ready.ID, Harness: "codex", NativeSessionID: ready.NativeSessionID,
	}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy join updated READY endpoint: %v", err)
	}

	// A legacy endpoint without a current Group association is not a valid
	// receiver route, even for a Store-level sealed-envelope visibility test.
	if _, err := controlPlane.store.CreateFabricRequest(store.FabricRequest{
		RequestID: "rq-ready-v2-unjoined", MessageID: "msg-ready-v2-unjoined",
		SenderEndpointID: ready.ID, SenderPrincipalID: "principal-" + ready.ID,
		SenderGroupID: "group-" + ready.ID, ReceiverEndpointID: legacy.ID,
		ReceiverGroupID: "missing-receiver-group", Body: "blocked unjoined route",
	}); !errors.Is(err, store.ErrNetworkPermission) {
		t.Fatalf("endpoint route with no current receiver Group was accepted: %v", err)
	}

	readyReceiver, err := controlPlane.JoinEndpoint(EndpointJoinInput{
		Name: "ready-receiver", Harness: "codex", NativeSessionID: "thread-ready-receiver",
		MachineID: "ready-receiver-machine", Visibility: "fabric",
	})
	if err != nil {
		t.Fatal(err)
	}
	markFabricEndpointReady(t, controlPlane, readyReceiver.ID)
	request, err := controlPlane.store.CreateFabricRequest(store.FabricRequest{
		RequestID: "rq-ready-v2", MessageID: "msg-ready-v2",
		SenderEndpointID: ready.ID, SenderPrincipalID: "principal-" + ready.ID,
		SenderGroupID: "group-" + ready.ID, ReceiverEndpointID: readyReceiver.ID,
		ReceiverPrincipalID: "principal-" + readyReceiver.ID,
		ReceiverGroupID:     "group-" + readyReceiver.ID, Body: "v2 envelope",
	})
	if err != nil {
		t.Fatal(err)
	}
	if message, err := controlPlane.FabricMessage(request.MessageID); err != nil || message != nil {
		t.Fatalf("legacy message read exposed v2 relay envelope: message=%#v err=%v", message, err)
	}
	if messages, err := controlPlane.FabricMessages("", "", 100); err != nil {
		t.Fatal(err)
	} else {
		for _, message := range messages {
			if message.ID == request.MessageID {
				t.Fatalf("global legacy message list exposed v2 relay envelope: %#v", messages)
			}
		}
	}
	if _, err := controlPlane.ReplyFabric(FabricReplyInput{
		FromEndpointID: legacy.ID, RequestID: request.RequestID, Message: "blocked",
	}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy reply reached v2 relay request: %v", err)
	}
	if deliveries, err := controlPlane.MachineFabricDeliveries(legacy.MachineID, 10); err != nil {
		t.Fatal(err)
	} else if len(deliveries) != 0 {
		t.Fatalf("machine delivery claimed v2 relay envelope: %#v", deliveries)
	}
	if _, err := controlPlane.CompleteMachineFabricDelivery(legacy.MachineID, request.MessageID, ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy machine completion accepted v2 relay envelope: %v", err)
	}
}
