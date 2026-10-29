package n3_test

import (
	"testing"
	"time"
)

type ownerGroupsCrossActor struct {
	node     *ownerGroupsCrossNode
	index    int
	identity ownerGroupsIdentity
}

// These are existing Host calls, not another message transport. Splitting the
// original ASK from receive/reply permits Node B to go offline after arming its
// receiver and recover the same request without another ASK or new body.
type ownerGroupsCrossExchange struct {
	source, target                 ownerGroupsCrossActor
	label, group, question, answer string
	request, operation             string
}

func ownerGroupsCrossOriginalActor(t *testing.T, n *ownerGroupsCrossNode, originals []ownerGroupsIdentity, index int) ownerGroupsCrossActor {
	t.Helper()
	if n == nil || n.host == nil || len(originals) != 4 || len(n.host.originalSIDs) != 4 || index < 0 || index >= 4 {
		t.Fatal("cross-Node actor lacks its four original actual Host identities")
	}
	id := originals[index]
	if id.NodeID != n.id || id.SID != n.host.originalSIDs[index] || id.Workspace != n.actors.workspaces[index] || id.Endpoint == "" || id.BindingID == "" || id.PublicKeySHA256 == "" {
		t.Fatal("cross-Node actor changed its original Node, SID, workspace or key")
	}
	return ownerGroupsCrossActor{node: n, index: index, identity: id}
}

func prepareOwnerGroupsCrossExchange(t *testing.T, source, target ownerGroupsCrossActor, group, label string) *ownerGroupsCrossExchange {
	t.Helper()
	if source.node == nil || target.node == nil || source.node.shared != target.node.shared || source.node == target.node ||
		source.node.host == target.node.host || source.identity.NodeID == target.identity.NodeID || source.identity.SID == target.identity.SID ||
		source.identity.Endpoint == target.identity.Endpoint || group == "" || label == "" || len(label) > 48 {
		t.Fatal("cross-Node exchange needs two independent original Nodes on one Hub/App")
	}
	source.node.shared.requireIndependentOriginals(t)
	for _, actor := range []ownerGroupsCrossActor{source, target} {
		ownerGroupsSelect(t, actor.node.host, actor.index, label+"-select", group)
	}
	e := &ownerGroupsCrossExchange{source: source, target: target, label: label, group: group,
		question: "SYNTHETIC_CROSS_NODE_QUESTION_" + source.node.host.fixtureScope + "_" + label,
		answer:   "SYNTHETIC_CROSS_NODE_ANSWER_" + target.node.host.fixtureScope + "_" + label}
	// Register the expectation on the receiver's own actual Host. This never
	// POSTs a queue turn; only the real receiving Node may perform delivery.
	target.node.host.command(t, ownerGroupsHostCommand{Action: "checkpoint", Actor: target.index,
		Queue: []ownerGroupsQueueInput{{Body: e.question, SID: target.identity.SID, Sender: source.identity.Endpoint,
			Receiver: target.identity.Endpoint, GroupID: group, Kind: "ask"}}})
	return e
}

func (e *ownerGroupsCrossExchange) sendASK(t *testing.T) {
	t.Helper()
	if e.request != "" || e.operation != "" {
		t.Fatal("cross-Node recovery must retain the original ASK, not send another")
	}
	h := e.source.node.host
	ask := h.command(t, ownerGroupsHostCommand{Action: "call", Actor: e.source.index, Label: e.label + "-ask", Tool: "cicada_ask",
		Arguments:     map[string]any{"target": e.target.identity.Endpoint, "question": e.question, "idempotency_key": h.fixtureScope + "-" + e.label},
		ObserveFields: []string{"request_id", "operation_id"}})
	if ask.OperationStatus == "FAILED" && ask.OperationRetryable != nil && !*ask.OperationRetryable {
		t.Fatalf("actual cross-Node ASK is terminal FAILED: diagnostic=%s", ask.Diagnostic)
	}
	e.request, e.operation = ask.Public["request_id"], ask.Public["operation_id"]
	for attempt := 0; e.request == "" && e.operation != "" && attempt < 30; attempt++ {
		time.Sleep(250 * time.Millisecond)
		status := h.command(t, ownerGroupsHostCommand{Action: "call", Actor: e.source.index, Label: e.label + "-status", Tool: "cicada_operation_status",
			Arguments: map[string]any{"operation_id": e.operation}, ObserveFields: []string{"request_id"}})
		if status.OperationStatus == "FAILED" && status.OperationRetryable != nil && !*status.OperationRetryable {
			t.Fatalf("original cross-Node ASK reached terminal FAILED: diagnostic=%s", status.Diagnostic)
		}
		e.request = status.Public["request_id"]
	}
	if e.request == "" {
		t.Fatal("actual cross-Node ASK has no settled original request ID; do not replace it")
	}
}

func (e *ownerGroupsCrossExchange) receiveReply(t *testing.T) {
	t.Helper()
	if e.request == "" {
		t.Fatal("cross-Node receive requires the original durable ASK request")
	}
	source, target := e.source, e.target
	received := target.node.host.command(t, ownerGroupsHostCommand{Action: "receive_match", Actor: target.index,
		Label: e.label + "-request-receive", Tool: "cicada_receive", Arguments: map[string]any{"limit": 16},
		ExpectedRequestID: e.request, ExpectedBodyMarker: e.question, BindQueue: map[string]string{e.question: e.request}})
	if received.QueuePosts[e.question] != 1 {
		t.Fatal("original cross-Node ASK did not reach its exact receiver native Runtime once")
	}
	source.node.host.command(t, ownerGroupsHostCommand{Action: "checkpoint", Actor: source.index,
		Queue: []ownerGroupsQueueInput{{Body: e.answer, SID: source.identity.SID, Sender: target.identity.Endpoint,
			Receiver: source.identity.Endpoint, GroupID: e.group, Kind: "reply"}}, BindQueue: map[string]string{e.answer: e.request}})
	reply := target.node.host.command(t, ownerGroupsHostCommand{Action: "call", Actor: target.index, Label: e.label + "-reply", Tool: "cicada_reply",
		Arguments:     map[string]any{"request_id": e.request, "body": e.answer, "idempotency_key": target.node.host.fixtureScope + "-reply-" + e.label},
		ObserveFields: []string{"operation_id", "request_id"}})
	if reply.Public["operation_id"] == "" || (reply.Public["request_id"] != "" && reply.Public["request_id"] != e.request) ||
		(reply.OperationStatus != "PENDING" && reply.OperationStatus != "UNKNOWN" && reply.OperationStatus != "SENT") {
		t.Fatalf("cross-Node REPLY lacks its original accepted operation: diagnostic=%s", reply.Diagnostic)
	}
	returned := source.node.host.command(t, ownerGroupsHostCommand{Action: "receive_match", Actor: source.index,
		Label: e.label + "-reply-receive", Tool: "cicada_receive", Arguments: map[string]any{"limit": 16},
		ExpectedRequestID: e.request, ExpectedBodyMarker: e.answer})
	if returned.QueuePosts[e.answer] != 1 {
		t.Fatal("cross-Node reply did not reach its exact original requester native Runtime once")
	}
	t.Logf("OWNER_GROUPS_CROSS_NODE_ROUNDTRIP source_node_sha256=%s target_node_sha256=%s request_sha256=%s distinct_nodes=true original_SIDs=true native_each_once=true",
		hash([]byte(source.identity.NodeID)), hash([]byte(target.identity.NodeID)), hash([]byte(e.request)))
}
