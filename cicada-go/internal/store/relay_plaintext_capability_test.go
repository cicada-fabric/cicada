package store

import (
	"errors"
	"testing"
)

func TestStorePlaintextWritesFailClosedForCurrentEndpointCapability(t *testing.T) {
	persistence := newRelayV2TestStore(t)
	defer persistence.Close()
	for _, endpoint := range []Endpoint{
		{ID: "ep-a", Name: "a", Harness: "codex", NativeSessionID: "native-a", Capabilities: map[string]any{"local_peer_delivery": "sealed_v1"}},
		{ID: "ep-b", Name: "b", Harness: "codex", NativeSessionID: "native-b"},
	} {
		if _, err := persistence.UpsertEndpoint(endpoint); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := createPreparingRelayMessageFixture(t, persistence, RelayMessageInput{
		Message: FabricMessage{ID: "msg-downgrade", FromEndpointID: "ep-a", ToEndpointID: "ep-b", Kind: "send", Body: "private body"},
		Security: RelayMessageSecurity{SenderEndpointID: "ep-a", SenderPrincipalID: "principal-a", SenderGroupID: "group-a",
			ReceiverEndpointID: "ep-b", ReceiverPrincipalID: "principal-b", ReceiverGroupID: "group-a"},
	}); !errors.Is(err, ErrRelayPlaintextSealedPeer) {
		t.Fatalf("plaintext SEND bypassed Store capability guard: %v", err)
	}
	if _, err := persistence.GetRelayMessage("msg-downgrade"); !errors.Is(err, ErrRelayMessageNotFound) {
		t.Fatalf("denied plaintext SEND persisted a Relay message: %v", err)
	}

	legacyEndpoint, err := persistence.GetEndpointV2("ep-a")
	if err != nil || legacyEndpoint == nil {
		t.Fatalf("load source endpoint: %#v err=%v", legacyEndpoint, err)
	}
	legacyEndpoint.Capabilities = map[string]any{}
	if _, err := persistence.UpsertEndpoint(*legacyEndpoint); err != nil {
		t.Fatal(err)
	}
	request := relayTestAsk("rq-downgrade", "msg-ask-downgrade", "", "ask-key", "private question")
	created, err := persistence.CreateFabricRequest(request)
	if err != nil || created == nil {
		t.Fatalf("legacy ASK setup failed: %#v err=%v", created, err)
	}
	history, err := persistence.ListRelayInbox("ep-b", 0, 10)
	if err != nil || len(history) != 1 || history[0].Message == nil || history[0].Message.Body != "private question" {
		t.Fatalf("legacy plaintext inbox history was not readable: %#v err=%v", history, err)
	}

	sealedTarget, err := persistence.GetEndpointV2("ep-b")
	if err != nil || sealedTarget == nil {
		t.Fatalf("load target endpoint: %#v err=%v", sealedTarget, err)
	}
	sealedTarget.Capabilities = map[string]any{"local_peer_delivery": "future-sealed-version"}
	if _, err := persistence.UpsertEndpoint(*sealedTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateFabricRequest(request); !errors.Is(err, ErrRelayPlaintextSealedPeer) {
		t.Fatalf("plaintext ASK retry bypassed a present future capability: %v", err)
	}
	if _, err := persistence.SubmitFabricReply(FabricReply{
		RequestID: request.RequestID, ResponderEndpointID: "ep-b", ResponderPrincipalID: "principal-b",
		ResponderGroupID: "group-a", Body: "private answer",
	}); !errors.Is(err, ErrRelayPlaintextSealedPeer) {
		t.Fatalf("plaintext REPLY bypassed target capability: %v", err)
	}
	current, err := persistence.GetRelayFabricRequest(request.RequestID)
	if err != nil || current == nil || current.State != FabricRequestOpen {
		t.Fatalf("denied plaintext attempts changed the legacy request: %#v err=%v", current, err)
	}
	history, err = persistence.ListRelayInbox("ep-b", 0, 10)
	if err != nil || len(history) != 1 || history[0].Message == nil || history[0].Message.Body != "private question" {
		t.Fatalf("sealed capability blocked historical inbox reads: %#v err=%v", history, err)
	}
}
