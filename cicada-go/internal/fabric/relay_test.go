package fabric

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func joinFabricPeer(t *testing.T, service *Service, groupID, name, session, node string) (*JoinResult, Actor) {
	t.Helper()
	joined, err := service.Join(JoinInput{
		GroupID: groupID, PrincipalName: name, EndpointName: name,
		Harness: "codex", NativeSessionID: session, NodeID: node,
	})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	return joined, actor
}

func TestControlBusinessDisabledPeerRPC(t *testing.T) {
	// This fixture deliberately constructs only Store + Fabric Service. There
	// is no Control, planner, scheduler, intent handler, or reporting object in
	// the dependency graph exercised below.
	service, _, group := newFabricTestService(t)
	a, actorA := joinFabricPeer(t, service, group.ID, "frontend", "native-a", "node-a")
	b, actorB := joinFabricPeer(t, service, group.ID, "benchmark", "native-b", "node-b")

	request, err := service.Ask(actorA, AskInput{
		Target: b.Endpoint.ID, Question: "best result?", IdempotencyKey: "ask-best-result",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.RequestID == "" || request.MessageID == "" || request.State != store.FabricRequestOpen {
		t.Fatalf("ask was not durably accepted: %#v", request)
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil || !deadline.After(time.Now().UTC()) || deadline.After(time.Now().UTC().Add(store.DefaultRelayAskLifetime+time.Minute)) {
		t.Fatalf("Ask did not receive its bounded finite default deadline: %q %v", request.ExpiresAt, err)
	}
	if _, err := service.Ask(actorA, AskInput{Target: b.Endpoint.ID, Question: "overlong synthetic wait",
		ExpiresAt: time.Now().UTC().Add(store.MaxRelayAskLifetime + time.Hour).Format(time.RFC3339Nano)}); err == nil {
		t.Fatal("Ask accepted a deadline beyond the 24-hour bound")
	}
	mailboxB, err := service.Receive(actorB, ReceiveInput{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(mailboxB.Messages) != 1 || mailboxB.Messages[0].Message == nil ||
		mailboxB.Messages[0].Message.RequestID != request.RequestID || mailboxB.Messages[0].Message.Body != "best result?" {
		t.Fatalf("B did not receive correlated request: %#v", mailboxB)
	}
	replied, err := service.Reply(actorB, ReplyInput{RequestID: request.RequestID, Body: "42.7"})
	if err != nil {
		t.Fatal(err)
	}
	if replied.State != store.FabricRequestReplied || replied.ReplyMessageID == "" {
		t.Fatalf("reply was not correlated: %#v", replied)
	}
	mailboxA, err := service.Receive(actorA, ReceiveInput{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(mailboxA.Messages) != 1 || mailboxA.Messages[0].Message == nil ||
		mailboxA.Messages[0].Message.Kind != "reply" || mailboxA.Messages[0].Message.RequestID != request.RequestID ||
		mailboxA.Messages[0].Message.ToEndpointID != a.Endpoint.ID {
		t.Fatalf("reply did not return to A: %#v", mailboxA)
	}
}

func TestRelayIdempotencyOfflineQueueAndRejoinFencing(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	_, actorA := joinFabricPeer(t, service, group.ID, "sender", "native-sender", "node-a")
	b, actorB := joinFabricPeer(t, service, group.ID, "offline", "native-offline", "node-b")
	if _, err := persistence.TouchEndpoint(b.Endpoint.ID, "offline"); err != nil {
		t.Fatal(err)
	}
	first, err := service.Send(actorA, SendInput{Target: b.Endpoint.ID, Body: "queued payload", IdempotencyKey: "operation-1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Send(actorA, SendInput{Target: b.Endpoint.ID, Body: "queued payload", IdempotencyKey: "operation-1"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Message.ID != second.Message.ID {
		t.Fatalf("idempotent retry created a second message: %s != %s", first.Message.ID, second.Message.ID)
	}
	rejoined, err := service.Join(JoinInput{
		GroupID: group.ID, EndpointID: b.Endpoint.ID, EndpointName: "offline",
		Harness: "codex", NativeSessionID: "native-offline", NodeID: "node-b",
	})
	if err != nil {
		t.Fatal(err)
	}
	actorB2, err := service.Authenticate(rejoined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if actorB2.EndpointID != actorB.EndpointID || actorB2.BindingEpoch <= actorB.BindingEpoch {
		t.Fatalf("rejoin lost stable endpoint or did not fence old epoch: old=%#v new=%#v", actorB, actorB2)
	}
	if _, err := service.Receive(actorB, ReceiveInput{Limit: 10}); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("old binding remained usable: %v", err)
	}
	mailbox, err := service.Receive(actorB2, ReceiveInput{Limit: 10})
	if err != nil || len(mailbox.Messages) != 1 || mailbox.Messages[0].Message.ID != first.Message.ID {
		t.Fatalf("offline queue did not survive reconnect: %#v err=%v", mailbox, err)
	}
}

func TestDirectCrossGroupMessageIsDenied(t *testing.T) {
	service, persistence, groupA := newFabricTestService(t)
	_, actorA := joinFabricPeer(t, service, groupA.ID, "a", "native-a", "node-a")
	owner, err := persistence.GetPrincipal("owner")
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := persistence.CreateGroup(store.Group{
		Name: "group-b", OwnerPrincipalID: owner.ID, TrustDomainID: "domain", State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := joinFabricPeer(t, service, groupB.ID, "b", "native-b", "node-b")
	if _, err := service.Send(actorA, SendInput{Target: b.Endpoint.ID, Body: "bypass"}); !errors.Is(err, ErrCrossGroupDirectDenied) {
		t.Fatalf("cross-group stable endpoint bypass was not denied: %v", err)
	}
	if _, err := service.Send(actorA, SendInput{Target: "b", Body: "enumerate"}); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("cross-group alias enumeration leaked: %v", err)
	}
}

func TestNodeClaimUsesExactNativeBindingAndLayeredReceipt(t *testing.T) {
	service, _, group := newFabricTestService(t)
	_, actorA := joinFabricPeer(t, service, group.ID, "a", "native-a-exact", "node-a")
	b, _ := joinFabricPeer(t, service, group.ID, "b", "native-b-exact", "node-b")
	request, err := service.Ask(actorA, AskInput{Target: b.Endpoint.ID, Question: "wake exact thread"})
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := service.ClaimNodeDeliveries("node-b", NodeClaimInput{ConsumerID: "node-b-agent", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].RequestID != request.RequestID ||
		deliveries[0].NativeSessionID != "native-b-exact" || deliveries[0].EndpointID != b.Endpoint.ID {
		t.Fatalf("node claim did not preserve exact binding: %#v", deliveries)
	}
	if _, err := service.RecordNodeReceipt("node-a", NodeReceiptInput{
		AttemptID: deliveries[0].AttemptID, MessageID: deliveries[0].MessageID,
		Digest: deliveries[0].Digest, EndpointID: deliveries[0].EndpointID,
		BindingID: deliveries[0].BindingID, BindingEpoch: deliveries[0].BindingEpoch,
		Layer: ReceiptRuntimeInjected,
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("wrong node was allowed to acknowledge delivery: %v", err)
	}
	for _, layer := range []string{ReceiptRelayAccepted, ReceiptApplicationAcked, ReceiptResultAccepted} {
		if _, err := service.RecordNodeReceipt("node-b", NodeReceiptInput{
			AttemptID: deliveries[0].AttemptID, MessageID: deliveries[0].MessageID,
			Digest: deliveries[0].Digest, EndpointID: deliveries[0].EndpointID,
			BindingID: deliveries[0].BindingID, BindingEpoch: deliveries[0].BindingEpoch,
			Layer: layer,
		}); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("Node credential was allowed to report non-Node receipt layer %q: %v", layer, err)
		}
	}
	nodeReceipt, err := service.RecordNodeReceipt("node-b", NodeReceiptInput{
		AttemptID: deliveries[0].AttemptID, MessageID: deliveries[0].MessageID,
		Digest: deliveries[0].Digest, EndpointID: deliveries[0].EndpointID,
		BindingID: deliveries[0].BindingID, BindingEpoch: deliveries[0].BindingEpoch,
		Layer: ReceiptNodeReceived,
	})
	if err != nil || nodeReceipt.Layer != ReceiptNodeReceived {
		t.Fatalf("node durable receipt was not persisted: %#v err=%v", nodeReceipt, err)
	}
	for _, layer := range []string{ReceiptCodexQueueAccepted, ReceiptNativeThreadResumed} {
		if got, err := service.RecordNodeReceipt("node-b", NodeReceiptInput{
			AttemptID: deliveries[0].AttemptID, MessageID: deliveries[0].MessageID,
			Digest: deliveries[0].Digest, EndpointID: deliveries[0].EndpointID,
			BindingID: deliveries[0].BindingID, BindingEpoch: deliveries[0].BindingEpoch,
			Layer: layer,
		}); err != nil || got.Layer != layer {
			t.Fatalf("operational stage %s was not persisted: %#v err=%v", layer, got, err)
		}
	}
	receipt, err := service.RecordNodeReceipt("node-b", NodeReceiptInput{
		AttemptID: deliveries[0].AttemptID, MessageID: deliveries[0].MessageID,
		Digest: deliveries[0].Digest, EndpointID: deliveries[0].EndpointID,
		BindingID: deliveries[0].BindingID, BindingEpoch: deliveries[0].BindingEpoch,
		Layer: ReceiptRuntimeInjected,
	})
	if err != nil || receipt.Layer != ReceiptRuntimeInjected {
		t.Fatalf("runtime receipt was not persisted: %#v err=%v", receipt, err)
	}
	again, err := service.ClaimNodeDeliveries("node-b", NodeClaimInput{ConsumerID: "node-b-agent", Limit: 10})
	if err != nil || len(again) != 0 {
		t.Fatalf("injected message was claimed twice: %#v err=%v", again, err)
	}
}

func TestNodeOldBindingCanReconcileUncertaintyButCannotClaimInjection(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	_, actorA := joinFabricPeer(t, service, group.ID, "a", "native-a-old-epoch", "node-a")
	b, _ := joinFabricPeer(t, service, group.ID, "b", "native-b-old-epoch", "node-b")
	if _, err := service.Ask(actorA, AskInput{Target: b.Endpoint.ID, Question: "old epoch recovery"}); err != nil {
		t.Fatal(err)
	}
	deliveries, err := service.ClaimNodeDeliveries("node-b", NodeClaimInput{ConsumerID: "node-b-old", Limit: 1})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim=%#v err=%v", deliveries, err)
	}
	old := deliveries[0]
	receipt := func(layer string) NodeReceiptInput {
		return NodeReceiptInput{AttemptID: old.AttemptID, MessageID: old.MessageID, Digest: old.Digest,
			EndpointID: old.EndpointID, BindingID: old.BindingID, BindingEpoch: old.BindingEpoch, Layer: layer}
	}
	if _, err := service.RecordNodeReceipt("node-b", receipt(ReceiptNodeReceived)); err != nil {
		t.Fatal(err)
	}
	newBinding, err := service.Join(JoinInput{
		GroupID: group.ID, EndpointID: b.Endpoint.ID, EndpointName: "b",
		Harness: "codex", NativeSessionID: "native-b-old-epoch", NodeID: "node-b",
	})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := persistence.GetRelayDeliveryAttempt(old.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if newBinding.BindingEpoch <= old.BindingEpoch {
		t.Fatalf("rejoin did not invalidate old epoch: old=%d new=%d", old.BindingEpoch, newBinding.BindingEpoch)
	}
	item, err := persistence.GetRelayInboxItem(old.EndpointID, attempt.Sequence)
	if err != nil || item.State != store.RelayInboxClaimed || item.AttemptID != old.AttemptID {
		t.Fatalf("old attempt no longer occupies inbox before reconciliation: %#v err=%v", item, err)
	}
	for _, layer := range []string{ReceiptCodexQueueAccepted, ReceiptNativeThreadResumed,
		ReceiptRuntimeInjected, ReceiptConsumptionUncertain} {
		if _, err := service.RecordNodeReceipt("node-b", receipt(layer)); !errors.Is(err, ErrStaleBinding) {
			t.Fatalf("expired epoch was allowed to first report %s: %v", layer, err)
		}
	}
	if got, err := service.RecordNodeReceipt("node-b", receipt(ReceiptNodeReceived)); err != nil || got.Layer != ReceiptNodeReceived {
		t.Fatalf("exact historical receipt could not be reconciled: %#v err=%v", got, err)
	}
	if got, err := service.RecordNodeReceipt("node-b", receipt(ReceiptInjectionUncertain)); err != nil || got.Layer != ReceiptInjectionUncertain {
		t.Fatalf("stale attempt could not be safely marked uncertain: %#v err=%v", got, err)
	}
	item, err = persistence.GetRelayInboxItem(old.EndpointID, attempt.Sequence)
	if err != nil || item.State != store.RelayInboxUncertain || item.AttemptID != old.AttemptID {
		t.Fatalf("stale reconciliation advanced or released the old claim: %#v err=%v", item, err)
	}
	if _, err := service.RecordNodeReceipt("node-b", receipt(ReceiptRuntimeInjected)); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("stale epoch claimed injection after recording uncertainty: %v", err)
	}
	if got, err := service.ClaimNodeDeliveries("node-b", NodeClaimInput{ConsumerID: "node-b-new", Limit: 1}); err != nil || len(got) != 0 {
		t.Fatalf("uncertain old attempt was redelivered to new binding: %#v err=%v", got, err)
	}
}

func TestNodeClaimAndReceiptRejectExpiredBindingLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cicada.sqlite3")
	service, _, group := newFabricTestServiceAtPath(t, path)
	_, actorA := joinFabricPeer(t, service, group.ID, "a", "native-a-expiry", "node-a")
	b, actorB := joinFabricPeer(t, service, group.ID, "b", "native-b-expiry", "node-b")
	if _, err := service.Ask(actorA, AskInput{Target: b.Endpoint.ID, Question: "lease boundary"}); err != nil {
		t.Fatal(err)
	}
	deliveries, err := service.ClaimNodeDeliveries("node-b", NodeClaimInput{ConsumerID: "node-b-agent", Limit: 1})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim=%#v err=%v", deliveries, err)
	}
	expireBindingLeaseForTest(t, path, actorB.BindingID)
	if _, err := service.RecordNodeReceipt("node-b", NodeReceiptInput{
		AttemptID: deliveries[0].AttemptID, MessageID: deliveries[0].MessageID,
		Digest: deliveries[0].Digest, EndpointID: deliveries[0].EndpointID,
		BindingID: deliveries[0].BindingID, BindingEpoch: deliveries[0].BindingEpoch,
		Layer: ReceiptNodeReceived,
	}); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("expired binding submitted receipt: %v", err)
	}
	if _, err := service.Ask(actorA, AskInput{Target: b.Endpoint.ID, Question: "must remain queued"}); err != nil {
		t.Fatal(err)
	}
	if got, err := service.ClaimNodeDeliveries("node-b", NodeClaimInput{ConsumerID: "node-b-other", Limit: 1}); err != nil || len(got) != 0 {
		t.Fatalf("expired binding remained claimable: %#v err=%v", got, err)
	}
}
