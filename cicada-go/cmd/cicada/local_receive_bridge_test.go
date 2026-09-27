package main

import (
	"context"
	"testing"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

func TestLocalReceiveMergesScopedNodeInboxesWithIndependentCursors(t *testing.T) {
	stateDir, nodeID := t.TempDir(), "node_receive_merge"
	bridge := &machineAgentJoinBridge{ctx: context.Background(), stateDir: stateDir, nodeID: nodeID}
	request := localGroupRequest{
		EndpointID: "ep_receive", NativeSessionID: "native_receive",
		BindingID: "binding_receive", BindingEpoch: 7, GroupID: "group_one",
	}
	inject := func(path, id, group, body string, route nodeinbox.RouteMetadata) {
		t.Helper()
		inbox, err := nodeinbox.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer inbox.Close()
		message := nodeinbox.Message{
			MessageID: id, Digest: "digest_" + id,
			EndpointID: request.EndpointID, SessionID: request.NativeSessionID,
			BindingEpoch: request.BindingEpoch, GroupID: group, Route: route, Payload: []byte(body),
		}
		if _, _, err := inbox.Save(context.Background(), message); err != nil {
			t.Fatal(err)
		}
		claim, err := inbox.Claim(context.Background(), "test-node")
		if err != nil || claim.MessageID != id {
			t.Fatalf("claim %s: %+v, %v", id, claim, err)
		}
		if _, err := inbox.BeginInjection(context.Background(), claim.AttemptID); err != nil {
			t.Fatal(err)
		}
		receipt := nodeinbox.Receipt{
			MessageID: id, Digest: message.Digest, EndpointID: request.EndpointID,
			SessionID: request.NativeSessionID, BindingEpoch: request.BindingEpoch,
			AttemptID: claim.AttemptID, State: nodeinbox.RUNTIME_INJECTED,
		}
		if _, err := inbox.RecordRuntimeInjected(context.Background(), receipt); err != nil {
			t.Fatal(err)
		}
	}
	inject(machineLocalGroupInboxPath(stateDir, nodeID), "msg_local", "group_one", "local secret",
		nodeinbox.RouteMetadata{Kind: "REQUEST", RequestID: "rq_local", SenderEndpointID: "ep_local_sender"})
	inject(machineNodeInboxPath(stateDir, nodeID), "msg_relay", "group_one", "relay secret",
		nodeinbox.RouteMetadata{Kind: "REPLY", RequestID: "rq_relay", ReplyTo: "msg_relay_ask", SenderEndpointID: "ep_remote_sender"})
	request.Limit = 1
	first, err := bridge.receiveLocalGroup(request)
	if err != nil || len(first.Messages) != 1 || first.Messages[0].MessageID != "msg_local" ||
		first.Messages[0].Kind != "REQUEST" || first.Messages[0].RequestID != "rq_local" ||
		first.Messages[0].ReplyTo != "" || first.Messages[0].SenderEndpointID != "ep_local_sender" {
		t.Fatalf("first scoped page: %+v, %v", first, err)
	}
	request.Cursor = first.NextCursor
	second, err := bridge.receiveLocalGroup(request)
	if err != nil || len(second.Messages) != 1 || second.Messages[0].MessageID != "msg_relay" ||
		second.Messages[0].Kind != "REPLY" || second.Messages[0].RequestID != "rq_relay" ||
		second.Messages[0].ReplyTo != "msg_relay_ask" || second.Messages[0].SenderEndpointID != "ep_remote_sender" {
		t.Fatalf("second scoped page: %+v, %v", second, err)
	}
	request.Cursor = second.NextCursor
	last, err := bridge.receiveLocalGroup(request)
	if err != nil || len(last.Messages) != 0 {
		t.Fatalf("inbox cursor did not exhaust both stores: %+v, %v", last, err)
	}
	request.GroupID = "group_two"
	if _, err := bridge.receiveLocalGroup(request); err == nil {
		t.Fatal("Group switch accepted the previous Group's inbox cursor")
	}
	request.GroupID = "group_one"
	request.BindingEpoch++
	if _, err := bridge.receiveLocalGroup(request); err == nil {
		t.Fatal("binding switch accepted the previous native inbox cursor")
	}
}
