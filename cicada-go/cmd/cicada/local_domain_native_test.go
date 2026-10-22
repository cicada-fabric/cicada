package main

import (
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

// This exercises the Node-owned layers independently of the contextual MCP
// consumer. All native records and queue subprocesses remain synthetic.
func TestLocalDomainPrivatePeerAndNativeCallbackRealTCP(t *testing.T) {
	f := newNativePeerTCPConsumerFixture(t, false)
	activateLocalDomainConsumer(t, f)
	for i := 0; i < 2; i++ {
		q := localDomainEndpointCommand(t, f, i)
		result, err := requestMachineAgentEndpoint(f.bridge.path, q)
		if err != nil {
			t.Fatal(err)
		}
		f.joins[i] = *result.Join
	}
	request := func(index int, operation, requestID string) crossNodeGroupRequest {
		j := f.joins[index]
		id, err := newMCPOutboxID("op")
		if err != nil {
			t.Fatal(err)
		}
		return crossNodeGroupRequest{Version: crossNodeGroupProtocolVersion, Operation: operation, Harness: "codex", NativeSessionID: f.native[index], NodeID: f.nodeID, Workspace: f.workspace, SessionToken: j.SessionToken, EndpointID: j.Endpoint.ID, PrincipalID: j.Endpoint.PrincipalID, OwnerID: j.Endpoint.Owner, GroupID: j.Endpoint.GroupID, BindingID: j.BindingID, BindingEpoch: j.BindingEpoch, TargetEndpointID: f.joins[1-index].Endpoint.ID, OperationID: id, OperationCreatedAt: time.Now().UTC().Format(time.RFC3339Nano), IdempotencyKey: id, RequestID: requestID, Body: "SYNTHETIC_DOMAIN_PRIVATE_MESSAGE"}
	}
	ask, err := requestMachineAgentCrossNodeGroup(f.bridge.path, request(0, "cross_node_group_ask", ""))
	if err != nil {
		t.Fatal("Node delegated peer/ASK", err)
	}
	inbox, journal := f.inbox(t)
	_, claim, entry := f.acceptOne(t, inbox, journal)
	ctx, process := f.queue(t, 1)
	if err = drainMachineCrossNodeGroupRelayClaim(ctx, f.server.URL, f.nodeID, f.nodeRoot, inbox, journal, claim, entry); err != nil {
		t.Fatal("Node delegated ASK native callback", err)
	}
	stored, err := inbox.Get(f.ctx, ask.MessageID)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, process.CounterPath) != 1 {
		t.Fatal("ASK native result was not preserved")
	}
	replyRequest := request(1, "cross_node_group_reply", ask.RequestID)
	replyRequest.TargetEndpointID = ""
	replyRequest.OperationCreatedAt = ""
	reply, err := requestMachineAgentCrossNodeGroup(f.bridge.path, replyRequest)
	if err != nil {
		t.Fatal("Node delegated peer/REPLY", err)
	}
	_, claim, entry = f.acceptOne(t, inbox, journal)
	ctx, process = f.queue(t, 0)
	if err = drainMachineCrossNodeGroupRelayClaim(ctx, f.server.URL, f.nodeID, f.nodeRoot, inbox, journal, claim, entry); err != nil {
		t.Fatal("Node delegated REPLY native callback", err)
	}
	stored, err = inbox.Get(f.ctx, reply.MessageID)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, process.CounterPath) != 1 {
		t.Fatal("REPLY native result was not preserved")
	}
}
