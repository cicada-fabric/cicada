package nodekeys

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestLocalSameGroupEndpointMessageIsDurableAuthenticatedAndReplaySafe(t *testing.T) {
	stateDir := t.TempDir()
	state, err := OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	sender, receiver := newTestIdentity(t), newTestIdentity(t)
	route := e2ee.EndpointMessageContext{
		MessageID: "msg_local_1", Kind: "REQUEST", RequestID: "rq_local_1",
		SenderEndpointID: "ep_source", SenderPrincipalID: "pr_source", SenderOwnerID: "owner_one",
		SenderGroupID: "group_one", SenderMembershipRevision: 2, SenderBindingEpoch: 3,
		SenderKeyID:        sender.Public().ID,
		ReceiverEndpointID: "ep_target", ReceiverPrincipalID: "pr_target", ReceiverOwnerID: "owner_one",
		ReceiverGroupID: "group_one", ReceiverMembershipRevision: 4, ReceiverBindingEpoch: 5,
		ReceiverKeyID: receiver.Public().ID,
	}
	ctx := context.Background()
	first, err := state.SealLocalSameGroupMessage(ctx, sender, receiver, sender.Public(), receiver.Public(),
		route, []byte("private local question"))
	if err != nil || first.Reused || first.Sequence != 1 {
		t.Fatalf("first seal: reused=%v sequence=%d err=%v", first.Reused, first.Sequence, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	retry, err := state.SealLocalSameGroupMessage(ctx, sender, receiver, sender.Public(), receiver.Public(),
		route, []byte("private local question"))
	if err != nil || !retry.Reused || retry.Sequence != first.Sequence || !bytes.Equal(retry.Envelope, first.Envelope) {
		t.Fatalf("restart retry changed sealed bytes: reused=%v sequence=%d err=%v", retry.Reused, retry.Sequence, err)
	}
	opened, err := state.OpenLocalSameGroupMessage(ctx, receiver, sender, receiver.Public(), sender.Public(),
		route, first.Envelope)
	if err != nil || opened.Duplicate || string(opened.Plaintext) != "private local question" {
		t.Fatalf("first open: duplicate=%v err=%v", opened.Duplicate, err)
	}
	again, err := state.OpenLocalSameGroupMessage(ctx, receiver, sender, receiver.Public(), sender.Public(),
		route, first.Envelope)
	if err != nil || !again.Duplicate || !bytes.Equal(again.Plaintext, opened.Plaintext) {
		t.Fatalf("duplicate open: duplicate=%v err=%v", again.Duplicate, err)
	}
	stored, err := state.GetInbound(ctx, route.ReceiverEndpointID, sender.Public().ID, route.MessageID)
	if err != nil || !bytes.Equal(stored.Envelope, first.Envelope) {
		t.Fatalf("durable local ciphertext missing: %v", err)
	}
	tampered := append([]byte(nil), first.Envelope...)
	tampered[len(tampered)-2] ^= 1
	if _, err := state.OpenLocalSameGroupMessage(ctx, receiver, sender, receiver.Public(), sender.Public(), route, tampered); err == nil {
		t.Fatal("tampered envelope opened")
	}
}

func TestLocalSameGroupEndpointMessageRejectsCrossScopeAndCandidateSubstitution(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	sender, receiver, stranger := newTestIdentity(t), newTestIdentity(t), newTestIdentity(t)
	route := e2ee.EndpointMessageContext{
		MessageID: "msg_local_scope", Kind: "SEND",
		SenderEndpointID: "ep_source", SenderPrincipalID: "pr_source", SenderOwnerID: "owner_one",
		SenderGroupID: "group_one", SenderMembershipRevision: 1, SenderBindingEpoch: 1,
		SenderKeyID:        sender.Public().ID,
		ReceiverEndpointID: "ep_target", ReceiverPrincipalID: "pr_target", ReceiverOwnerID: "owner_one",
		ReceiverGroupID: "group_one", ReceiverMembershipRevision: 1, ReceiverBindingEpoch: 1,
		ReceiverKeyID: receiver.Public().ID,
	}
	seal := func(r e2ee.EndpointMessageContext, target e2ee.PublicIdentity) error {
		_, err := state.SealLocalSameGroupMessage(context.Background(), sender, receiver,
			sender.Public(), target, r, []byte("sensitive"))
		return err
	}
	if err := seal(route, stranger.Public()); !errors.Is(err, ErrEndpointKeyIdentity) {
		t.Fatalf("substituted target candidate: %v", err)
	}
	wrongGroup := route
	wrongGroup.ReceiverGroupID = "group_other"
	if err := seal(wrongGroup, receiver.Public()); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("cross-group route: %v", err)
	}
	wrongOwner := route
	wrongOwner.ReceiverOwnerID = "owner_other"
	if err := seal(wrongOwner, receiver.Public()); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("cross-owner route: %v", err)
	}
	linked := route
	linked.LinkID = "link_other"
	linked.LinkRevision = 1
	if err := seal(linked, receiver.Public()); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("unauthorized Link route: %v", err)
	}
	stale := route
	stale.ReceiverMembershipRevision = 0
	if err := seal(stale, receiver.Public()); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("missing membership revision: %v", err)
	}
}
