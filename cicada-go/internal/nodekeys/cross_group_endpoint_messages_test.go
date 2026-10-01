package nodekeys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestOwnerGrantedCrossGroupOutboundMessageIsDurableAndExactOnRetry(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f := newCrossGroupPinFixture(t, "owner-a", "owner-b")
	installFixtureOwnerTrust(t, state, f)
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), f.scope,
		f.local, f.peer, f.bundle); err != nil {
		t.Fatal(err)
	}
	source, target := f.bundle.Manifest.Source, f.bundle.Manifest.Target
	route := e2ee.EndpointMessageContext{
		MessageID: "msg_outbound_cross_group", Kind: "SEND",
		SenderEndpointID: source.EndpointID, SenderPrincipalID: source.PrincipalID,
		SenderOwnerID: source.OwnerID, SenderGroupID: source.GroupID,
		SenderMembershipRevision: 2, SenderBindingEpoch: source.BindingEpoch,
		SenderKeyID:        source.KeyID,
		ReceiverEndpointID: target.EndpointID, ReceiverPrincipalID: target.PrincipalID,
		ReceiverOwnerID: target.OwnerID, ReceiverGroupID: target.GroupID,
		ReceiverMembershipRevision: 5, ReceiverBindingEpoch: target.BindingEpoch,
		ReceiverKeyID: target.KeyID, LinkID: f.bundle.Manifest.LinkID,
		LinkRevision: f.bundle.Manifest.LinkVersion, TransportHubID: "hub_cross_group_pin",
	}
	plaintext := []byte("private cross-group result")
	operationID, err := EndpointMessageOperationID(route, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	first, err := state.SealOwnerGrantedCrossGroupOutboundEndpointMessage(context.Background(),
		f.localKey, f.scope, f.local, f.peer, f.bundle, "benchmark.public_result",
		operationID, route, plaintext)
	if err != nil || first.Reused || first.Sequence == 0 {
		t.Fatalf("first cross-Group Seal failed: result=%#v err=%v", first, err)
	}
	second, err := state.SealOwnerGrantedCrossGroupOutboundEndpointMessage(context.Background(),
		f.localKey, f.scope, f.local, f.peer, f.bundle, "benchmark.public_result",
		operationID, route, plaintext)
	if err != nil || !second.Reused || second.Sequence != first.Sequence ||
		!bytes.Equal(second.Envelope, first.Envelope) {
		t.Fatalf("retry changed the durable ciphertext: result=%#v err=%v", second, err)
	}
	opened, _, err := e2ee.OpenEndpointMessage(f.peerKey, f.localKey.Public(), route, first.Envelope)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("recipient could not authenticate exact outbound envelope: err=%v", err)
	}
	if _, err := state.SealOwnerGrantedCrossGroupOutboundEndpointMessage(context.Background(),
		f.localKey, f.scope, f.local, f.peer, f.bundle, "ungranted.scope",
		operationID, route, plaintext); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("ungranted scope reused sealed envelope: %v", err)
	}
	if _, err := state.RevokeNodeOwnerKeyTrustLocal(f.targetTrust.OwnerID,
		f.targetTrust.KeyID, f.targetTrust.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := state.SealOwnerGrantedCrossGroupOutboundEndpointMessage(context.Background(),
		f.localKey, f.scope, f.local, f.peer, f.bundle, "benchmark.public_result",
		operationID, route, plaintext); err == nil {
		t.Fatal("revoked Owner trust still allowed ciphertext reuse for transport")
	}
}

func TestOwnerGrantedCrossGroupInboundMessageRequiresCurrentTrustAndExactRoute(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f := newCrossGroupPinFixture(t, "owner-a", "owner-b")
	installFixtureOwnerTrust(t, state, f)
	source := f.bundle.Manifest.Source
	target := f.bundle.Manifest.Target
	scope := PeerPinScope{LocalEndpointID: target.EndpointID, LocalGroupID: target.GroupID,
		PeerEndpointID: source.EndpointID, PeerGroupID: source.GroupID,
		CommunicationLinkID: f.bundle.Manifest.LinkID}
	local := PeerPinLocalEndpoint{EndpointID: target.EndpointID, GroupID: target.GroupID,
		PrincipalID: target.PrincipalID, OwnerID: target.OwnerID, NodeID: target.NodeID,
		BindingID: target.BindingID, BindingEpoch: target.BindingEpoch,
		KeyID: f.peerKey.Public().ID, Public: f.peerKey.Public()}
	peer := PeerPinIdentity{EndpointID: source.EndpointID, GroupID: source.GroupID,
		PrincipalID: source.PrincipalID, OwnerID: source.OwnerID}
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), scope,
		local, peer, f.bundle); err != nil {
		t.Fatal(err)
	}
	route := e2ee.EndpointMessageContext{
		MessageID: "msg_cross_group_send", Kind: "SEND",
		SenderEndpointID: source.EndpointID, SenderPrincipalID: source.PrincipalID,
		SenderOwnerID: source.OwnerID, SenderGroupID: source.GroupID,
		SenderMembershipRevision: 2, SenderBindingEpoch: source.BindingEpoch,
		SenderKeyID:        source.KeyID,
		ReceiverEndpointID: target.EndpointID, ReceiverPrincipalID: target.PrincipalID,
		ReceiverOwnerID: target.OwnerID, ReceiverGroupID: target.GroupID,
		ReceiverMembershipRevision: 5, ReceiverBindingEpoch: target.BindingEpoch,
		ReceiverKeyID: target.KeyID, LinkID: f.bundle.Manifest.LinkID,
		LinkRevision: f.bundle.Manifest.LinkVersion, TransportHubID: "hub_cross_group_pin",
	}
	wire, err := e2ee.SealEndpointMessage(f.localKey, f.peerKey.Public(), route,
		[]byte("private result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := state.OpenOwnerGrantedCrossGroupInboundEndpointMessage(context.Background(),
		f.peerKey, scope, local, peer, f.bundle, "benchmark.public_result", route, wire)
	if err != nil || opened.Duplicate || string(opened.Plaintext) != "private result" {
		t.Fatalf("valid owner-granted message did not open once: message=%#v err=%v", opened, err)
	}
	duplicate, err := state.OpenOwnerGrantedCrossGroupInboundEndpointMessage(context.Background(),
		f.peerKey, scope, local, peer, f.bundle, "benchmark.public_result", route, wire)
	if err != nil || !duplicate.Duplicate || string(duplicate.Plaintext) != "private result" {
		t.Fatalf("exact retry did not preserve authenticated replay identity: message=%#v err=%v", duplicate, err)
	}
	if _, err := state.OpenOwnerGrantedCrossGroupInboundEndpointMessage(context.Background(),
		f.peerKey, scope, local, peer, f.bundle, "other.scope", route, wire); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("ungranted data scope opened: %v", err)
	}
	wrongRoute := route
	wrongRoute.ReceiverMembershipRevision++
	if _, err := state.OpenOwnerGrantedCrossGroupInboundEndpointMessage(context.Background(),
		f.peerKey, scope, local, peer, f.bundle, "benchmark.public_result", wrongRoute, wire); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("wrong Group membership revision opened: %v", err)
	}
	wrongRoute = route
	wrongRoute.ReceiverPrincipalID = "pr_other"
	if _, err := state.OpenOwnerGrantedCrossGroupInboundEndpointMessage(context.Background(),
		f.peerKey, scope, local, peer, f.bundle, "benchmark.public_result", wrongRoute, wire); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("wrong receiver Principal opened: %v", err)
	}
	if _, err := state.RevokeNodeOwnerKeyTrustLocal(f.sourceTrust.OwnerID,
		f.sourceTrust.KeyID, f.sourceTrust.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := state.OpenOwnerGrantedCrossGroupInboundEndpointMessage(context.Background(),
		f.peerKey, scope, local, peer, f.bundle, "benchmark.public_result", route, wire); err == nil {
		t.Fatal("revoked local Owner trust still opened the message")
	}
}

func TestOwnerGrantedCrossGroupRequestRequiresAskGrantAndExactCorrelation(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f := newCrossGroupPinFixture(t, "owner-a", "owner-b")
	installFixtureOwnerTrust(t, state, f)
	source, target := f.bundle.Manifest.Source, f.bundle.Manifest.Target
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), f.scope,
		f.local, f.peer, f.bundle); err != nil {
		t.Fatal(err)
	}
	requestRoute := e2ee.EndpointMessageContext{
		MessageID: "msg_cross_group_request", Kind: "REQUEST", RequestID: "rq_exact_request",
		SenderEndpointID: source.EndpointID, SenderPrincipalID: source.PrincipalID,
		SenderOwnerID: source.OwnerID, SenderGroupID: source.GroupID,
		SenderMembershipRevision: 2, SenderBindingEpoch: source.BindingEpoch,
		SenderKeyID:        source.KeyID,
		ReceiverEndpointID: target.EndpointID, ReceiverPrincipalID: target.PrincipalID,
		ReceiverOwnerID: target.OwnerID, ReceiverGroupID: target.GroupID,
		ReceiverMembershipRevision: 5, ReceiverBindingEpoch: target.BindingEpoch,
		ReceiverKeyID: target.KeyID, LinkID: f.bundle.Manifest.LinkID,
		LinkRevision: f.bundle.Manifest.LinkVersion, TransportHubID: "hub_cross_group_pin",
	}
	plaintext := []byte("What is the current result?")
	operationID, err := EndpointMessageOperationID(requestRoute, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := state.SealOwnerGrantedCrossGroupOutboundEndpointMessage(context.Background(),
		f.localKey, f.scope, f.local, f.peer, f.bundle, "benchmark.public_result",
		operationID, requestRoute, plaintext)
	if err != nil || sealed.Reused || sealed.Sequence == 0 {
		t.Fatalf("authorized request was not sealed durably: %#v err=%v", sealed, err)
	}
	retried, err := state.SealOwnerGrantedCrossGroupOutboundEndpointMessage(context.Background(),
		f.localKey, f.scope, f.local, f.peer, f.bundle, "benchmark.public_result",
		operationID, requestRoute, plaintext)
	if err != nil || !retried.Reused || !bytes.Equal(retried.Envelope, sealed.Envelope) {
		t.Fatalf("request retry changed the immutable ciphertext: %#v err=%v", retried, err)
	}
	wrong := requestRoute
	wrong.RequestID = "rq_other_request"
	if _, err := state.SealOwnerGrantedCrossGroupOutboundEndpointMessage(context.Background(),
		f.localKey, f.scope, f.local, f.peer, f.bundle, "benchmark.public_result",
		operationID, wrong, plaintext); !errors.Is(err, ErrOutboundConflict) {
		t.Fatalf("changed request correlation reused the original operation: %v", err)
	}
	wrong = requestRoute
	wrong.ReplyTo = "msg_forbidden_parent"
	if err := validateOwnerGrantedMessageRoute(f.bundle, "benchmark.public_result", wrong); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("request with reply_to passed route validation: %v", err)
	}
	wrong = requestRoute
	wrong.Kind = "REPLY"
	if err := validateOwnerGrantedMessageRoute(f.bundle, "benchmark.public_result", wrong); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("unimplemented reply was accepted as a request: %v", err)
	}
	var contract peerLinkContract
	if err := json.Unmarshal(f.bundle.Manifest.ContractCanonical, &contract); err != nil {
		t.Fatal(err)
	}
	contract.Actions = []string{"send"}
	withoutAsk := f.bundle
	withoutAsk.Manifest.ContractCanonical, err = json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnerGrantedMessageRoute(withoutAsk, "benchmark.public_result", requestRoute); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("SEND-only contract allowed REQUEST: %v", err)
	}
	if err := validateOwnerGrantedMessageRoute(f.bundle, "ungranted.scope", requestRoute); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("ungranted request data scope was accepted: %v", err)
	}

	targetScope := PeerPinScope{LocalEndpointID: target.EndpointID, LocalGroupID: target.GroupID,
		PeerEndpointID: source.EndpointID, PeerGroupID: source.GroupID,
		CommunicationLinkID: f.bundle.Manifest.LinkID}
	targetLocal := PeerPinLocalEndpoint{EndpointID: target.EndpointID, GroupID: target.GroupID,
		PrincipalID: target.PrincipalID, OwnerID: target.OwnerID, NodeID: target.NodeID,
		BindingID: target.BindingID, BindingEpoch: target.BindingEpoch,
		KeyID: f.peerKey.Public().ID, Public: f.peerKey.Public()}
	sourcePeer := PeerPinIdentity{EndpointID: source.EndpointID, GroupID: source.GroupID,
		PrincipalID: source.PrincipalID, OwnerID: source.OwnerID}
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), targetScope,
		targetLocal, sourcePeer, f.bundle); err != nil {
		t.Fatal(err)
	}
	opened, err := state.OpenOwnerGrantedCrossGroupInboundEndpointMessage(context.Background(),
		f.peerKey, targetScope, targetLocal, sourcePeer, f.bundle,
		"benchmark.public_result", requestRoute, sealed.Envelope)
	if err != nil || opened.Duplicate || !bytes.Equal(opened.Plaintext, plaintext) {
		t.Fatalf("exact request was not opened and recorded once: %#v err=%v", opened, err)
	}
	opened, err = state.OpenOwnerGrantedCrossGroupInboundEndpointMessage(context.Background(),
		f.peerKey, targetScope, targetLocal, sourcePeer, f.bundle,
		"benchmark.public_result", requestRoute, sealed.Envelope)
	if err != nil || !opened.Duplicate {
		t.Fatalf("request retry created a second effective inbox item: %#v err=%v", opened, err)
	}
	wrong = requestRoute
	wrong.RequestID = "rq_other_request"
	if _, err := state.OpenOwnerGrantedCrossGroupInboundEndpointMessage(context.Background(),
		f.peerKey, targetScope, targetLocal, sourcePeer, f.bundle,
		"benchmark.public_result", wrong, sealed.Envelope); err == nil {
		t.Fatal("wrong request ID decrypted the original envelope")
	}
}

func TestOwnerGrantedCrossGroupReplyUsesReverseRouteAndExplicitReplyGrant(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f := newCrossGroupPinFixture(t, "owner-a", "owner-b")
	installFixtureOwnerTrust(t, state, f)
	source, target := f.bundle.Manifest.Source, f.bundle.Manifest.Target
	targetScope := PeerPinScope{LocalEndpointID: target.EndpointID, LocalGroupID: target.GroupID,
		PeerEndpointID: source.EndpointID, PeerGroupID: source.GroupID,
		CommunicationLinkID: f.bundle.Manifest.LinkID}
	targetLocal := PeerPinLocalEndpoint{EndpointID: target.EndpointID, GroupID: target.GroupID,
		PrincipalID: target.PrincipalID, OwnerID: target.OwnerID, NodeID: target.NodeID,
		BindingID: target.BindingID, BindingEpoch: target.BindingEpoch,
		KeyID: f.peerKey.Public().ID, Public: f.peerKey.Public()}
	sourcePeer := PeerPinIdentity{EndpointID: source.EndpointID, GroupID: source.GroupID,
		PrincipalID: source.PrincipalID, OwnerID: source.OwnerID}
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), targetScope,
		targetLocal, sourcePeer, f.bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := state.PinOwnerGrantedCrossGroupPeerKey(context.Background(), f.scope,
		f.local, f.peer, f.bundle); err != nil {
		t.Fatal(err)
	}
	route := e2ee.EndpointMessageContext{
		MessageID: "msg_cross_group_reply", Kind: "REPLY", RequestID: "rq_cross_group_reply",
		ReplyTo:          "msg_cross_group_request",
		SenderEndpointID: target.EndpointID, SenderPrincipalID: target.PrincipalID,
		SenderOwnerID: target.OwnerID, SenderGroupID: target.GroupID,
		SenderMembershipRevision: 5, SenderBindingEpoch: target.BindingEpoch,
		SenderKeyID:        target.KeyID,
		ReceiverEndpointID: source.EndpointID, ReceiverPrincipalID: source.PrincipalID,
		ReceiverOwnerID: source.OwnerID, ReceiverGroupID: source.GroupID,
		ReceiverMembershipRevision: 2, ReceiverBindingEpoch: source.BindingEpoch,
		ReceiverKeyID: source.KeyID, LinkID: f.bundle.Manifest.LinkID,
		LinkRevision: f.bundle.Manifest.LinkVersion, TransportHubID: "hub_cross_group_pin",
	}
	plaintext := []byte("result from the original responder")
	operationID, err := EndpointMessageOperationID(route, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := state.SealOwnerGrantedCrossGroupOutboundEndpointMessage(context.Background(),
		f.peerKey, targetScope, targetLocal, sourcePeer, f.bundle,
		"benchmark.public_result", operationID, route, plaintext)
	if err != nil || sealed.Reused {
		t.Fatalf("reverse reply was not sealed: %#v err=%v", sealed, err)
	}
	opened, err := state.OpenOwnerGrantedCrossGroupInboundEndpointMessage(context.Background(),
		f.localKey, f.scope, f.local, f.peer, f.bundle,
		"benchmark.public_result", route, sealed.Envelope)
	if err != nil || opened.Duplicate || !bytes.Equal(opened.Plaintext, plaintext) {
		t.Fatalf("original requester could not open correlated reply: %#v err=%v", opened, err)
	}
	wrong := route
	wrong.ReplyTo = "msg_other_request"
	if _, err := state.OpenOwnerGrantedCrossGroupInboundEndpointMessage(context.Background(),
		f.localKey, f.scope, f.local, f.peer, f.bundle,
		"benchmark.public_result", wrong, sealed.Envelope); err == nil {
		t.Fatal("different reply_to decrypted the original reply")
	}
	wrong = route
	wrong.ReplyTo = ""
	if err := validateOwnerGrantedMessageRoute(f.bundle, "benchmark.public_result", wrong); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("reply without parent request passed route validation: %v", err)
	}
	var contract peerLinkContract
	if err := json.Unmarshal(f.bundle.Manifest.ContractCanonical, &contract); err != nil {
		t.Fatal(err)
	}
	contract.Direction = "forward"
	contract.Actions = []string{"ask", "reply"}
	forward := f.bundle
	forward.Manifest.ContractCanonical, err = json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnerGrantedMessageRoute(forward, "benchmark.public_result", route); err != nil {
		t.Fatalf("explicit reverse reply to forward Ask was rejected: %v", err)
	}
	contract.Actions = []string{"ask"}
	noReply := f.bundle
	noReply.Manifest.ContractCanonical, err = json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnerGrantedMessageRoute(noReply, "benchmark.public_result", route); !errors.Is(err, ErrEndpointContextScope) {
		t.Fatalf("ASK-only contract allowed a reverse reply: %v", err)
	}
}
