package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestEndpointGroupsHTTPReplyPreservesReverseCurrentAndOriginalBinding(t *testing.T) {
	f := endpointGroupsRealHTTP(t)
	a := f.a
	q, original, _, review := f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, Name: "Synthetic reply Group"})
	_, _, _, created := f.apply(t, q, original, review, nil)
	group := created.Operation.Target.GroupID
	for i := range f.joins {
		f.activate(t, group, i)
	}
	var peer store.SameGroupSealedV1PeerKey
	if err := json.Unmarshal(a.pairHTTP(t, http.MethodGet, endpointGroupsHTTPPeerPath(f, group), "CicadaNode "+a.nodeToken, "", nil, http.StatusOK), &peer); err != nil || peer.EndpointGroupCurrent == nil {
		t.Fatal("actual manual peer current unavailable", err)
	}
	newID := func() string {
		t.Helper()
		id, err := wire.NewRequestID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	requestID, askID, replyID := newID(), newID(), newID()
	seal := func(from, to store.SameGroupSealedV1EndpointEvidence, sender, receiver int, message, kind, replyTo string) []byte {
		t.Helper()
		context := e2ee.EndpointMessageContext{MessageID: message, Kind: kind, RequestID: requestID, ReplyTo: replyTo, SenderEndpointID: from.EndpointID, SenderPrincipalID: from.PrincipalID, SenderOwnerID: from.OwnerID, SenderGroupID: group, SenderMembershipRevision: from.MembershipRevision, SenderBindingEpoch: from.BindingEpoch, SenderKeyID: f.keys[sender].Public().ID, ReceiverEndpointID: to.EndpointID, ReceiverPrincipalID: to.PrincipalID, ReceiverOwnerID: to.OwnerID, ReceiverGroupID: group, ReceiverMembershipRevision: to.MembershipRevision, ReceiverBindingEpoch: to.BindingEpoch, ReceiverKeyID: f.keys[receiver].Public().ID, TransportHubID: a.f.hub.HubID}
		raw, err := e2ee.SealEndpointMessage(f.keys[sender], f.keys[receiver].Public(), context, []byte("synthetic original Group request/reply"), 1)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	base := "/v2/relay/nodes/" + url.PathEscape(f.domain.Policy.Node.NodeID) + "/group/sealed/"
	expires := time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano)
	ask := fabric.NodeSameGroupSealedV1AskInput{GroupID: group, SourceEndpointID: peer.Sender.EndpointID, TargetEndpointID: peer.Receiver.EndpointID, MessageID: askID, RequestID: requestID, DataScope: store.SameGroupSealedV1DataScope, ExpiresAt: expires, Ciphertext: seal(peer.Sender, peer.Receiver, 0, 1, askID, "REQUEST", "")}
	var accepted struct {
		State     string `json:"state"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(a.pairHTTP(t, http.MethodPost, base+"ask", "CicadaNode "+a.nodeToken, "", ask, http.StatusAccepted), &accepted); err != nil || accepted.State != store.FabricRequestOpen || accepted.ExpiresAt != expires {
		t.Fatal("actual ASK changed its original thirty-minute deadline", err)
	}
	claim := func(want string) fabric.NodeSealedDelivery {
		t.Helper()
		var result struct {
			Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
		}
		if err := json.Unmarshal(a.pairHTTP(t, http.MethodPost, base+"claim", "CicadaNode "+a.nodeToken, "", fabric.NodeClaimInput{ConsumerID: "synthetic-owner-reply-consumer", Limit: 1}, http.StatusOK), &result); err != nil || len(result.Deliveries) != 1 || result.Deliveries[0].MessageID != want {
			t.Fatal("actual Group claim did not return the correlated message", err)
		}
		return result.Deliveries[0]
	}
	claim(askID)
	reply := fabric.NodeSameGroupSealedV1ReplyInput{RequestID: requestID, MessageID: replyID, Ciphertext: seal(peer.Receiver, peer.Sender, 1, 0, replyID, "REPLY", askID)}
	if err := json.Unmarshal(a.pairHTTP(t, http.MethodPost, base+"reply", "CicadaNode "+a.nodeToken, "", reply, http.StatusAccepted), &accepted); err != nil || accepted.State != store.FabricRequestReplied {
		t.Fatal("actual reply became a late result", err)
	}
	delivery := claim(replyID)
	path := base + "deliveries/" + replyID + "/authorization?attempt_id=" + url.QueryEscape(delivery.AttemptID)
	var authorization store.SameGroupSealedV1DeliveryAuthorization
	if err := json.Unmarshal(a.pairHTTP(t, http.MethodGet, path, "CicadaNode "+a.nodeToken, "", nil, http.StatusOK), &authorization); err != nil {
		t.Fatal(err)
	}
	current := authorization.EndpointGroupCurrent
	if current == nil {
		t.Fatal("accepted and claimed REPLY omitted the mandatory Endpoint Group current before Node Inbox admission")
	}
	if wire.ValidateEndpointGroupCurrent(*current, "native_delivery", delivery.AttemptID, time.Now().UTC()) != nil || current.Sender != peer.EndpointGroupCurrent.Receiver || current.Receiver != peer.EndpointGroupCurrent.Sender || current.GroupID != group || authorization.Sender.EndpointID != f.joins[1].Member.EndpointID || authorization.Receiver.EndpointID != f.joins[0].Member.EndpointID || authorization.BindingID != f.joins[0].Member.BindingID || authorization.BindingEpoch != f.joins[0].Member.BindingEpoch || authorization.NativeSessionID != f.joins[0].Member.NativeSessionID {
		t.Fatal("reply current did not reverse the exact sources and preserve the original native binding")
	}
	for _, side := range []struct {
		grant *wire.EndpointGroupDelegatedGrant
		now   wire.EndpointGroupCurrentEndpoint
	}{{authorization.Sender.EndpointGroupGrant, current.Sender}, {authorization.Receiver.EndpointGroupGrant, current.Receiver}} {
		if _, err := wire.VerifyEndpointGroupPeerSource(wire.EndpointGroupPeerSource{EndpointGroupGrant: side.grant}, side.now, a.f.hub, a.scope.Actor.OwnerID, a.owner.Public(), time.Now().UTC()); err != nil {
			t.Fatal("reply source did not independently verify against the original Owner pin", err)
		}
	}
	remove, packet, _, removeReview := f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: group, EndpointID: f.joins[0].Member.EndpointID})
	head := current.Receiver.OwnerControl
	f.apply(t, remove, packet, removeReview, &head)
	a.pairHTTP(t, http.MethodGet, path, "CicadaNode "+a.nodeToken, "", nil, http.StatusNotFound)
}
