package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestSealOutboundEndpointMessagePersistsAndReusesExactEnvelope(t *testing.T) {
	stateDir := t.TempDir()
	state, err := OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	local, peerIdentity := newTestIdentity(t), newTestIdentity(t)
	scope, peer := outboundTestScopeAndPeer()
	peerPinCandidate(t, state, scope, peer, peerIdentity, "binding_peer", 7)
	route := outboundTestRoute(local.Public(), peerIdentity.Public())
	plaintext := []byte("private request")
	operationID := testEndpointOperationID(t, route, plaintext)

	first, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		operationID, route, plaintext)
	if err != nil || first.Reused || first.Sequence != 1 {
		t.Fatalf("first send: reused=%v sequence=%d err=%v", first.Reused, first.Sequence, err)
	}
	stored, err := state.GetOutbound(context.Background(), operationID, local.Public().ID)
	if err != nil || !bytes.Equal(first.Envelope, stored.Envelope) {
		t.Fatalf("returned envelope was not committed before return: err=%v", err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	// A restart between persistence and transport must recover the exact bytes.
	state, err = OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	retry, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		operationID, route, plaintext)
	if err != nil || !retry.Reused || retry.Sequence != first.Sequence || !bytes.Equal(retry.Envelope, first.Envelope) {
		t.Fatalf("restart retry changed envelope: reused=%v sequence=%d err=%v", retry.Reused, retry.Sequence, err)
	}

	changed := route
	changed.MessageID = "msg_other"
	changed.RequestID = "rq_other"
	if _, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		operationID, changed, plaintext); !errors.Is(err, ErrOutboundConflict) {
		t.Fatalf("reused operation ID with a changed context error = %v", err)
	}
	if _, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		operationID, route, []byte("different request")); !errors.Is(err, ErrOutboundConflict) {
		t.Fatalf("reused operation ID with a changed plaintext error = %v", err)
	}
	next := route
	next.MessageID = "msg_send_2"
	next.RequestID = "rq_send_2"
	nextOperationID := testEndpointOperationID(t, next, []byte("second request"))
	second, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		nextOperationID, next, []byte("second request"))
	if err != nil || second.Sequence != 2 {
		t.Fatalf("next send after retry: sequence=%d err=%v", second.Sequence, err)
	}
}

func TestSealOutboundEndpointMessageRejectsCorruptRecoveredSignature(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	local, peerIdentity := newTestIdentity(t), newTestIdentity(t)
	scope, peer := outboundTestScopeAndPeer()
	peerPinCandidate(t, state, scope, peer, peerIdentity, "binding_peer", 7)
	route := outboundTestRoute(local.Public(), peerIdentity.Public())
	plaintext := []byte("private request")
	operationID := testEndpointOperationID(t, route, plaintext)
	if _, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		operationID, route, plaintext); err != nil {
		t.Fatal(err)
	}
	stored, err := state.GetOutbound(context.Background(), operationID, local.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	var envelope e2ee.EndpointMessageEnvelope
	if err := json.Unmarshal(stored.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signature[0] ^= 1
	corrupt, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(corrupt)
	if _, err := state.db.Exec(`UPDATE node_crypto_outbox SET envelope = ?, digest = ?
WHERE operation_id = ? AND source_key_id = ?`, corrupt, digest[:], operationID, local.Public().ID); err != nil {
		t.Fatal(err)
	}
	if _, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		operationID, route, plaintext); !errors.Is(err, ErrOutboundConflict) {
		t.Fatalf("recovered envelope with altered signature error = %v", err)
	}
}

func TestSealOutboundEndpointMessageRequiresActivePinAndCurrentBinding(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	local, peerIdentity := newTestIdentity(t), newTestIdentity(t)
	scope, peer := outboundTestScopeAndPeer()
	route := outboundTestRoute(local.Public(), peerIdentity.Public())
	plaintext := []byte("body")
	if _, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		testEndpointOperationID(t, route, plaintext), route, plaintext); !errors.Is(err, ErrPeerPinNotFound) {
		t.Fatalf("send without a pin error = %v", err)
	}
	peerPinCandidate(t, state, scope, peer, peerIdentity, "binding_peer", 7)
	route.ReceiverBindingEpoch++
	if _, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		testEndpointOperationID(t, route, plaintext), route, plaintext); !errors.Is(err, ErrEndpointBindingEpoch) {
		t.Fatalf("send with stale peer binding epoch error = %v", err)
	}
	wrongRoute := outboundTestRoute(local.Public(), peerIdentity.Public())
	wrongRoute.ReceiverOwnerID = "owner_other"
	if _, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		testEndpointOperationID(t, wrongRoute, plaintext), wrongRoute, plaintext); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("send with context outside pin scope error = %v", err)
	}
}

func TestSealOutboundEndpointMessageLeavesSequenceGapAfterSealFailure(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	local, peerIdentity := newTestIdentity(t), newTestIdentity(t)
	scope, peer := outboundTestScopeAndPeer()
	peerPinCandidate(t, state, scope, peer, peerIdentity, "binding_peer", 7)
	route := outboundTestRoute(local.Public(), peerIdentity.Public())
	oversized := make([]byte, 64*1024+1)
	if _, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		testEndpointOperationID(t, route, oversized), route, oversized); err == nil {
		t.Fatal("oversized plaintext was sealed")
	}
	route.MessageID = "msg_after_gap"
	route.RequestID = "rq_after_gap"
	plaintext := []byte("body")
	message, err := state.SealOutboundEndpointMessage(context.Background(), local, scope, peer,
		testEndpointOperationID(t, route, plaintext), route, plaintext)
	if err != nil || message.Sequence != 2 {
		t.Fatalf("sequence after failed seal: sequence=%d err=%v", message.Sequence, err)
	}
}

func TestOpenInboundEndpointMessagePersistsCiphertextAndReportsReplayPrecisely(t *testing.T) {
	stateDir := t.TempDir()
	state, err := OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	local, sender := newTestIdentity(t), newTestIdentity(t)
	scope, peer := inboundTestScopeAndPeer()
	peerPinCandidate(t, state, scope, peer, sender, "binding_sender", 4)
	route := inboundTestRoute(sender.Public(), local.Public())
	wire, err := e2ee.SealEndpointMessage(sender, local.Public(), route, []byte("private result"), 11)
	if err != nil {
		t.Fatal(err)
	}

	opened, err := state.OpenInboundEndpointMessage(context.Background(), local, scope, peer, route, wire)
	if err != nil || opened.Duplicate || opened.Sequence != 11 || !bytes.Equal(opened.Plaintext, []byte("private result")) {
		t.Fatalf("first inbound: duplicate=%v sequence=%d plaintext=%q err=%v", opened.Duplicate, opened.Sequence, opened.Plaintext, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	retried, err := state.OpenInboundEndpointMessage(context.Background(), local, scope, peer, route, wire)
	if err != nil || !retried.Duplicate || retried.Sequence != 11 || !bytes.Equal(retried.Plaintext, opened.Plaintext) {
		t.Fatalf("persisted inbound retry: duplicate=%v sequence=%d err=%v", retried.Duplicate, retried.Sequence, err)
	}
	stored, err := state.GetInbound(context.Background(), scope.LocalEndpointID, sender.Public().ID, route.MessageID)
	if err != nil || stored.Sequence != 11 || !bytes.Equal(stored.Envelope, wire) {
		t.Fatalf("inbound ciphertext was not durably stored: record=%+v err=%v", stored, err)
	}

	staleEpoch := route
	staleEpoch.SenderBindingEpoch++
	if _, err := state.OpenInboundEndpointMessage(context.Background(), local, scope, peer, staleEpoch, wire); !errors.Is(err, ErrEndpointBindingEpoch) {
		t.Fatalf("inbound stale pin epoch error = %v", err)
	}

	changedCiphertext, err := e2ee.SealEndpointMessage(sender, local.Public(), route, []byte("replacement"), 11)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.OpenInboundEndpointMessage(context.Background(), local, scope, peer, route, changedCiphertext); !errors.Is(err, ErrInboundReplayConflict) {
		t.Fatalf("same message ID with new valid ciphertext error = %v", err)
	}

	otherMessage := route
	otherMessage.MessageID = "msg_same_sequence"
	otherCiphertext, err := e2ee.SealEndpointMessage(sender, local.Public(), otherMessage, []byte("another message"), 11)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.OpenInboundEndpointMessage(context.Background(), local, scope, peer, otherMessage, otherCiphertext); !errors.Is(err, ErrInboundReplayConflict) {
		t.Fatalf("same sequence under another message ID error = %v", err)
	}

	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)-1] ^= 1
	if _, err := state.OpenInboundEndpointMessage(context.Background(), local, scope, peer, route, tampered); err == nil {
		t.Fatal("tampered envelope was accepted")
	}
}

func TestOpenInboundEndpointMessageRejectsUnpinnedAndWrongIdentityContexts(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	local, sender := newTestIdentity(t), newTestIdentity(t)
	scope, peer := inboundTestScopeAndPeer()
	route := inboundTestRoute(sender.Public(), local.Public())
	wire, err := e2ee.SealEndpointMessage(sender, local.Public(), route, []byte("body"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.OpenInboundEndpointMessage(context.Background(), local, scope, peer, route, wire); !errors.Is(err, ErrPeerPinNotFound) {
		t.Fatalf("receive without a pin error = %v", err)
	}
	peerPinCandidate(t, state, scope, peer, sender, "binding_sender", 4)
	wrongRoute := route
	wrongRoute.ReceiverKeyID = newTestIdentity(t).Public().ID
	if _, err := state.OpenInboundEndpointMessage(context.Background(), local, scope, peer, wrongRoute, wire); !errors.Is(err, ErrEndpointKeyIdentity) {
		t.Fatalf("receive with wrong local key error = %v", err)
	}
	wrongPeer := peer
	wrongPeer.PrincipalID = "pr_other"
	if _, err := state.OpenInboundEndpointMessage(context.Background(), local, scope, wrongPeer, route, wire); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("receive under another peer identity error = %v", err)
	}
}

func newTestIdentity(t *testing.T) *e2ee.Identity {
	t.Helper()
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testEndpointOperationID(t *testing.T, route e2ee.EndpointMessageContext, plaintext []byte) string {
	t.Helper()
	operationID, err := EndpointMessageOperationID(route, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return operationID
}

func peerPinCandidate(t *testing.T, state *CryptoState, scope PeerPinScope, peer PeerPinIdentity,
	identity *e2ee.Identity, bindingID string, epoch uint64) {
	t.Helper()
	proof, err := identity.SignEndpointKeyAttestation(peer.EndpointID, peer.PrincipalID, "node_peer", bindingID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	candidate := PeerKeyCandidate{EndpointID: peer.EndpointID, PrincipalID: peer.PrincipalID,
		OwnerID: peer.OwnerID, NodeID: "node_peer", Public: identity.Public(),
		BindingID: bindingID, BindingEpoch: epoch, Attestation: proof}
	fingerprint, err := PeerKeyFingerprint(candidate.Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		candidate.Public.ID, fingerprint, candidate); err != nil {
		t.Fatal(err)
	}
}

func outboundTestScopeAndPeer() (PeerPinScope, PeerPinIdentity) {
	peer := PeerPinIdentity{EndpointID: "ep_peer", GroupID: "group_local", PrincipalID: "pr_peer", OwnerID: "owner_peer"}
	scope := PeerPinScope{LocalEndpointID: "ep_local", LocalGroupID: "group_local",
		PeerEndpointID: peer.EndpointID, PeerGroupID: peer.GroupID, CommunicationLinkID: "link_1"}
	return scope, peer
}

func inboundTestScopeAndPeer() (PeerPinScope, PeerPinIdentity) {
	peer := PeerPinIdentity{EndpointID: "ep_sender", GroupID: "group_receiver", PrincipalID: "pr_sender", OwnerID: "owner_sender"}
	scope := PeerPinScope{LocalEndpointID: "ep_receiver", LocalGroupID: "group_receiver",
		PeerEndpointID: peer.EndpointID, PeerGroupID: peer.GroupID, CommunicationLinkID: "link_1"}
	return scope, peer
}

func outboundTestRoute(sender, receiver e2ee.PublicIdentity) e2ee.EndpointMessageContext {
	return e2ee.EndpointMessageContext{
		MessageID: "msg_send_1", Kind: "REQUEST", RequestID: "rq_send_1",
		SenderEndpointID: "ep_local", SenderPrincipalID: "pr_local", SenderOwnerID: "owner_local",
		SenderGroupID: "group_local", SenderMembershipRevision: 3, SenderBindingEpoch: 2, SenderKeyID: sender.ID,
		ReceiverEndpointID: "ep_peer", ReceiverPrincipalID: "pr_peer", ReceiverOwnerID: "owner_peer",
		ReceiverGroupID: "group_local", ReceiverMembershipRevision: 4, ReceiverBindingEpoch: 7, ReceiverKeyID: receiver.ID,
		LinkID: "link_1", LinkRevision: 8, TransportHubID: "hub_route",
	}
}

func inboundTestRoute(sender, receiver e2ee.PublicIdentity) e2ee.EndpointMessageContext {
	return e2ee.EndpointMessageContext{
		MessageID: "msg_in_1", Kind: "SEND",
		SenderEndpointID: "ep_sender", SenderPrincipalID: "pr_sender", SenderOwnerID: "owner_sender",
		SenderGroupID: "group_receiver", SenderMembershipRevision: 5, SenderBindingEpoch: 4, SenderKeyID: sender.ID,
		ReceiverEndpointID: "ep_receiver", ReceiverPrincipalID: "pr_receiver", ReceiverOwnerID: "owner_receiver",
		ReceiverGroupID: "group_receiver", ReceiverMembershipRevision: 6, ReceiverBindingEpoch: 9, ReceiverKeyID: receiver.ID,
		LinkID: "link_1", LinkRevision: 8, TransportHubID: "hub_route",
	}
}
