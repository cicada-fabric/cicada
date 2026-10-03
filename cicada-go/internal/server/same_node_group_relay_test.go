package server

import (
	"encoding/json"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestSameNodeGroupRelayHTTPMetadataAndBodyBlind(t *testing.T) {
	f := newSameGroupSealedHTTPFixture(t)
	if f.handler.(*Handler).control != nil {
		t.Fatal("Control unexpectedly enabled")
	}
	joined, err := f.service.Join(fabricpkg.JoinInput{GroupID: f.groupID, PrincipalName: "same-node-target", EndpointName: "same-node-target", Harness: "codex", NativeSessionID: "native-same-node-target", NodeID: f.sourceNodeID, LeaseOwner: "same-node-target-lease"})
	if err != nil {
		t.Fatal(err)
	}
	f.targetEndpoint = joined.Endpoint
	f.targetKey = addAndGrantSameGroupSealedTestEndpointKey(t, f.persistence, f.ownerID, f.groupID, f.ownerKeyID, f.ownerIdentity, f.targetEndpoint)
	base := "/v2/relay/nodes/" + f.sourceNodeID + "/group/sealed/"
	peerFor := func(source, target string) store.SameGroupSealedV1PeerKey {
		t.Helper()
		q := url.Values{"group_id": {f.groupID}, "source_endpoint_id": {source}, "target_endpoint_id": {target}}
		r := f.call(t, http.MethodGet, base+"peer-key?"+q.Encode(), f.sourceNodeAuth, nil)
		if r.Code != http.StatusOK {
			t.Fatalf("peer %d %s", r.Code, r.Body.String())
		}
		var peer store.SameGroupSealedV1PeerKey
		if err := json.Unmarshal(r.Body.Bytes(), &peer); err != nil {
			t.Fatal(err)
		}
		return peer
	}
	peer := peerFor(f.sourceEndpoint.ID, f.targetEndpoint.ID)
	messageID, requestID := "same-node-http-message", "same-node-http-request"
	wire := f.seal(t, peer, f.sourceKey, messageID, "REQUEST", requestID, "")
	r := f.call(t, http.MethodPost, base+"ask", f.sourceNodeAuth, map[string]any{"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID, "target_endpoint_id": f.targetEndpoint.ID, "message_id": messageID, "request_id": requestID, "idempotency_key": "same-node-http-idem", "data_scope": store.SameGroupSealedV1DataScope, "expires_at": time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano), "ciphertext": wire})
	if r.Code != http.StatusAccepted {
		t.Fatalf("ASK %d %s", r.Code, r.Body.String())
	}
	reverse := peerFor(f.targetEndpoint.ID, f.sourceEndpoint.ID)
	replyWire := f.seal(t, reverse, f.targetKey, "same-node-http-reply", "REPLY", requestID, messageID)
	reply := f.call(t, http.MethodPost, base+"reply", f.sourceNodeAuth, map[string]any{"request_id": requestID, "message_id": "same-node-http-reply", "idempotency_key": "same-node-http-reply-idem", "ciphertext": replyWire})
	if reply.Code != http.StatusAccepted {
		t.Fatalf("REPLY %d %s", reply.Code, reply.Body.String())
	}
	status := f.call(t, http.MethodGet, base+"requests/"+requestID, f.sourceNodeAuth, nil)
	var recorded store.FabricRequest
	if status.Code != http.StatusOK || json.Unmarshal(status.Body.Bytes(), &recorded) != nil || recorded.State != store.FabricRequestReplied || recorded.ReplyMessageID != "same-node-http-reply" {
		t.Fatalf("correlation %d %s", status.Code, status.Body.String())
	}
	self := url.Values{"group_id": {f.groupID}, "source_endpoint_id": {f.sourceEndpoint.ID}, "target_endpoint_id": {f.sourceEndpoint.ID}}
	if got := f.call(t, http.MethodGet, base+"peer-key?"+self.Encode(), f.sourceNodeAuth, nil); got.Code == http.StatusOK {
		t.Fatal("self Endpoint peer accepted")
	}
	membership, err := f.persistence.GetMembershipByPrincipalGroup(f.targetEndpoint.PrincipalID, f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.persistence.RevokeMembership(membership.ID, "synthetic same-node revoke"); err != nil {
		t.Fatal(err)
	}
	if got := f.call(t, http.MethodPost, base+"send", f.sourceNodeAuth, map[string]any{"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID, "target_endpoint_id": f.targetEndpoint.ID, "message_id": "same-node-after-revoke", "data_scope": store.SameGroupSealedV1DataScope, "ciphertext": wire}); got.Code != http.StatusForbidden {
		t.Fatalf("revoked same-node peer accepted %d", got.Code)
	}
}
