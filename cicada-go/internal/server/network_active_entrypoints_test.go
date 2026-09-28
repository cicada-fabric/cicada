package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// This is an ACTIVE Network over an actual HTTP listener with no Control
// object. The Node credential and Owner signature are separate inputs, while
// the Group and Network sessions remain separate after the same Thread joins.
func TestActiveNetworkHTTPWorksWithoutControlAndSeparatesCredentials(t *testing.T) {
	service, persistence, group := newRelayNodeTestService(t)
	nodeToken, nodeDigest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	const nodeID = "node-active-http"
	bindRelayNodeTestCredential(t, persistence, nodeID, nodeDigest)
	groupJoined, err := service.JoinForNodeCredential(nodeToken, fabric.JoinInput{
		GroupID: group.ID, Harness: "codex", NativeSessionID: "native-active-http",
		Workspace: "/synthetic/active-http",
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterOwnerApprovalKeyLocal("owner", ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	const networkID = "network_active_http"
	if _, err := persistence.CreateNetwork(store.Network{ID: networkID, HubID: hubID, Name: "synthetic active", OwnerID: "owner"}); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.PrepareGroupNetworkMapping(group.ID, networkID, "synthetic explicit mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := persistence.ApproveGroupNetworkMapping(group.ID, networkID, group.Version); err != nil {
		t.Fatal(err)
	}
	joinNetwork := func(nativeID string) fabric.NetworkJoinResult {
		t.Helper()
		invite := "synthetic-active-http-invite-" + nativeID
		grants := []string{"directory.discover", "directory.publish"}
		if err := persistence.IssueNetworkInvitation(networkID, "owner", "owner", invite,
			time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
			t.Fatal(err)
		}
		proof, err := ownerKey.SignOwnerNetworkJoinGrant("owner", hubID, networkID, nodeID, nativeID,
			store.NetworkInvitationDigest(invite), ownerKey.Public().ID, grants, true,
			time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		joined, err := service.JoinNetworkForNodeCredential(nodeToken, fabric.NetworkJoinInput{
			NetworkID: networkID, InvitationToken: invite, OwnerJoinProof: string(proof),
			Harness: "codex", NativeSessionID: nativeID, EndpointName: nativeID,
		})
		if err != nil {
			t.Fatal(err)
		}
		return *joined
	}
	joinedWithGroup := joinNetwork("native-active-http")
	joinedNetworkOnly := joinNetwork("native-network-only-http")
	if err := persistence.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}

	hub := httptest.NewServer(NewFabricHandler(service, "synthetic-operator-token"))
	defer hub.Close()
	call := func(method, path, authorization, groupScope string, body any) int {
		t.Helper()
		var encoded []byte
		if body != nil {
			var err error
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		request, err := http.NewRequest(method, hub.URL+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", authorization)
		if groupScope != "" {
			request.Header.Set("Cicada-Group-Scope", groupScope)
		}
		response, err := hub.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	networkAuth := "Cicada-Network-Session " + joinedWithGroup.SessionToken
	groupAuth := "CicadaSession " + groupJoined.SessionToken
	if got := call(http.MethodGet, "/v2/fabric/networks/"+networkID+"/directory", networkAuth, "", nil); got != http.StatusOK {
		t.Fatalf("Control-free Network directory status=%d", got)
	}
	if got := call(http.MethodGet, "/v2/fabric/whoami", groupAuth, group.ID, nil); got != http.StatusOK {
		t.Fatalf("Control-free Group whoami status=%d", got)
	}
	if got := call(http.MethodGet, "/v1/groups", "Bearer synthetic-operator-token", "", nil); got != http.StatusServiceUnavailable {
		t.Fatalf("Control business route remained available: %d", got)
	}
	if got := call(http.MethodGet, "/v2/fabric/whoami", "Cicada-Network-Session "+joinedNetworkOnly.SessionToken, group.ID, nil); got != http.StatusUnauthorized {
		t.Fatalf("Network-only access credential reached Group whoami: %d", got)
	}
	if got := call(http.MethodGet, "/v2/fabric/networks/"+networkID+"/directory", groupAuth, group.ID, nil); got != http.StatusUnauthorized {
		t.Fatalf("Group credential reached Network directory: %d", got)
	}
	if got := call(http.MethodPost, "/v2/fabric/send", groupAuth, group.ID, map[string]string{"body": "retired"}); got != http.StatusGone {
		t.Fatalf("authenticated legacy plaintext send status=%d, want 410", got)
	}
	member, err := persistence.GetMembershipByPrincipalGroup(groupJoined.Endpoint.PrincipalID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	grants := append(append([]string(nil), member.Grants...), "task.read")
	if _, err := persistence.UpdateMembershipAuthorization(member.ID, member.Roles,
		grants, member.Authorization, member.Version); err != nil {
		t.Fatal(err)
	}
	groupActor, err := service.AuthenticateForGroup(groupJoined.SessionToken, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListTasks(groupActor, 10); err != nil {
		t.Fatalf("current Group actor lost legitimate Task read: %v", err)
	}
	networkActor, err := service.AuthenticateForNetwork(joinedWithGroup.SessionToken, networkID)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.LeaveNetwork(networkActor, "synthetic scoped leave"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListTasks(groupActor, 10); !errors.Is(err, fabric.ErrPermissionDenied) {
		t.Fatalf("stale Group actor Task read returned %v, want permission denial", err)
	}
	if got := call(http.MethodGet, "/v2/fabric/tasks", groupAuth, group.ID, nil); got != http.StatusForbidden {
		t.Fatalf("stale Group actor Task HTTP status=%d, want 403", got)
	}
}

func TestNetworkStoreGuardErrorIsPermissionDeniedAtFabricHTTP(t *testing.T) {
	response := httptest.NewRecorder()
	fabricV2Error(response, store.ErrNetworkPermission)
	if response.Code != http.StatusForbidden {
		t.Fatalf("Network Store guard became HTTP %d, want 403", response.Code)
	}
}

// The sealed peer routes are Fabric transport, not Control business methods.
// This runs them on a mapped ACTIVE Network over a real HTTP listener.
func TestActiveNetworkSealedAskReplyWithoutControl(t *testing.T) {
	f := newSameGroupSealedHTTPFixture(t)
	handler, ok := f.handler.(*Handler)
	if !ok || handler.control != nil {
		t.Fatal("sealed peer fixture unexpectedly has Control business enabled")
	}
	hubID, err := f.persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	const networkID = "network_active_sealed_http"
	if _, err := f.persistence.CreateNetwork(store.Network{ID: networkID, HubID: hubID,
		Name: "synthetic sealed HTTP", OwnerID: f.ownerID}); err != nil {
		t.Fatal(err)
	}
	group, err := f.persistence.GetGroup(f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.persistence.PrepareGroupNetworkMapping(group.ID, networkID,
		"synthetic sealed mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := f.persistence.ApproveGroupNetworkMapping(group.ID, networkID, group.Version); err != nil {
		t.Fatal(err)
	}
	otherGroup, err := f.persistence.GetGroup(f.otherGroupID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.persistence.QuarantineGroupNetwork(otherGroup.ID,
		"synthetic unrelated Group quarantine", otherGroup.Version); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []struct {
		nodeAuth, nodeID, nativeID, name string
	}{
		{f.sourceNodeAuth, f.sourceNodeID, "native-same-group-source", "same-group-source"},
		{f.targetNodeAuth, f.targetNodeID, "native-same-group-target", "same-group-target"},
	} {
		invite := strings.Repeat("s", 32) + peer.nodeID
		grants := []string{"directory.discover", "directory.publish"}
		if err := f.persistence.IssueNetworkInvitation(networkID, f.ownerID, f.ownerID,
			invite, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
			t.Fatal(err)
		}
		proof, err := f.ownerIdentity.SignOwnerNetworkJoinGrant(f.ownerID, hubID, networkID,
			peer.nodeID, peer.nativeID, store.NetworkInvitationDigest(invite), f.ownerKeyID,
			grants, true, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.JoinNetworkForNodeCredential(strings.TrimPrefix(peer.nodeAuth, "CicadaNode "),
			fabric.NetworkJoinInput{NetworkID: networkID, InvitationToken: invite,
				OwnerJoinProof: string(proof), Harness: "codex", NativeSessionID: peer.nativeID,
				EndpointName: peer.name}); err != nil {
			t.Fatalf("enroll %s in ACTIVE test Network: %v", peer.name, err)
		}
	}
	if err := f.persistence.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	// Mapping advances Group authorization revision. Fresh Owner signatures
	// bind both existing Endpoint keys to the now-mapped scope.
	for _, endpoint := range []store.Endpoint{f.sourceEndpoint, f.targetEndpoint} {
		refreshSameGroupSealedTestEndpointKeyGrant(t, f.persistence, f.ownerID,
			f.groupID, f.ownerKeyID, f.ownerIdentity, endpoint)
	}
	hub := httptest.NewServer(f.handler)
	defer hub.Close()
	call := func(method, path, authorization string, body any) (int, []byte) {
		t.Helper()
		var encoded []byte
		if body != nil {
			var err error
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		request, err := http.NewRequest(method, hub.URL+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", authorization)
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := hub.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result json.RawMessage
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, result
	}
	base := "/v2/relay/nodes/" + f.sourceNodeID + "/group/sealed/"
	targetBase := "/v2/relay/nodes/" + f.targetNodeID + "/group/sealed/"
	peerQuery := url.Values{"group_id": {f.groupID}, "source_endpoint_id": {f.sourceEndpoint.ID},
		"target_endpoint_id": {f.targetEndpoint.ID}}
	status, body := call(http.MethodGet, base+"peer-key?"+peerQuery.Encode(), f.sourceNodeAuth, nil)
	var peer store.SameGroupSealedV1PeerKey
	if status != http.StatusOK || json.Unmarshal(body, &peer) != nil || peer.Receiver.EndpointID != f.targetEndpoint.ID {
		t.Fatalf("ACTIVE sealed peer evidence status=%d body=%s", status, body)
	}
	const requestID, askID, replyID = "active-sealed-request", "active-sealed-ask", "active-sealed-reply"
	status, body = call(http.MethodPost, base+"ask", f.sourceNodeAuth, map[string]any{
		"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
		"target_endpoint_id": f.targetEndpoint.ID, "message_id": askID,
		"request_id": requestID, "data_scope": sameGroupSealedTestDataScope,
		"expires_at": time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
		"ciphertext": f.seal(t, peer, f.sourceKey, askID, "REQUEST", requestID, ""),
	})
	if status != http.StatusAccepted {
		t.Fatalf("ACTIVE Control-free sealed ASK status=%d body=%s", status, body)
	}
	status, body = call(http.MethodPost, targetBase+"claim", f.targetNodeAuth,
		map[string]any{"consumer_id": "active-target", "limit": 10})
	var claimed struct {
		Deliveries []store.RelaySealedV1DeliveryAttempt `json:"deliveries"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &claimed) != nil ||
		len(claimed.Deliveries) != 1 || claimed.Deliveries[0].MessageID != askID {
		t.Fatalf("ACTIVE sealed ASK was not claimable: status=%d body=%s", status, body)
	}
	status, body = call(http.MethodGet, targetBase+"deliveries/"+askID+
		"/authorization?"+url.Values{"attempt_id": {claimed.Deliveries[0].AttemptID}}.Encode(), f.targetNodeAuth, nil)
	if status != http.StatusOK {
		t.Fatalf("ACTIVE sealed ASK lacked current delivery authorization: status=%d body=%s", status, body)
	}
	reverseQuery := url.Values{"group_id": {f.groupID}, "source_endpoint_id": {f.targetEndpoint.ID},
		"target_endpoint_id": {f.sourceEndpoint.ID}}
	status, body = call(http.MethodGet, targetBase+"peer-key?"+reverseQuery.Encode(), f.targetNodeAuth, nil)
	var reverse store.SameGroupSealedV1PeerKey
	if status != http.StatusOK || json.Unmarshal(body, &reverse) != nil {
		t.Fatalf("ACTIVE reverse peer evidence status=%d body=%s", status, body)
	}
	// Keep a second valid Ask open so revocation can be checked at the reply
	// enqueue boundary, not only at peer-key discovery.
	const pendingID, pendingAskID = "active-sealed-pending", "active-sealed-pending-ask"
	pendingAsk := map[string]any{
		"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
		"target_endpoint_id": f.targetEndpoint.ID, "message_id": pendingAskID,
		"request_id": pendingID, "idempotency_key": "active-pending-ask-idem",
		"data_scope": sameGroupSealedTestDataScope,
		"expires_at": time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
		"ciphertext": f.seal(t, peer, f.sourceKey, pendingAskID, "REQUEST", pendingID, ""),
	}
	status, body = call(http.MethodPost, base+"ask", f.sourceNodeAuth, pendingAsk)
	if status != http.StatusAccepted {
		t.Fatalf("pre-revocation pending ASK status=%d body=%s", status, body)
	}
	const sendID = "active-sealed-send-before-revoke"
	preRevokeSend := map[string]any{
		"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
		"target_endpoint_id": f.targetEndpoint.ID, "message_id": sendID,
		"idempotency_key": "active-send-idem", "data_scope": sameGroupSealedTestDataScope,
		"ciphertext": f.seal(t, peer, f.sourceKey, sendID, "SEND", "", ""),
	}
	status, body = call(http.MethodPost, base+"send", f.sourceNodeAuth, preRevokeSend)
	if status != http.StatusAccepted {
		t.Fatalf("pre-revocation sealed SEND status=%d body=%s", status, body)
	}
	status, body = call(http.MethodPost, targetBase+"reply", f.targetNodeAuth, map[string]any{
		"request_id": requestID, "message_id": replyID,
		"ciphertext": f.seal(t, reverse, f.targetKey, replyID, "REPLY", requestID, askID),
	})
	if status != http.StatusAccepted {
		t.Fatalf("ACTIVE Control-free sealed REPLY status=%d body=%s", status, body)
	}
	status, body = call(http.MethodGet, base+"requests/"+requestID, f.sourceNodeAuth, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"state":"REPLIED"`)) {
		t.Fatalf("ACTIVE sealed request did not complete: status=%d body=%s", status, body)
	}
	member, err := f.persistence.GetNetworkMembership(networkID, f.targetEndpoint.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.persistence.RevokeNetworkMembership(networkID, f.targetEndpoint.PrincipalID, member.Revision); err != nil {
		t.Fatal(err)
	}
	status, body = call(http.MethodGet, targetBase+"peer-key?"+reverseQuery.Encode(), f.targetNodeAuth, nil)
	if status != http.StatusNotFound {
		t.Fatalf("revoked ACTIVE Network peer evidence status=%d body=%s", status, body)
	}
	for _, attempt := range []struct {
		name, path, auth string
		body             any
	}{
		{"SEND retry", base + "send", f.sourceNodeAuth, preRevokeSend},
		{"ASK retry", base + "ask", f.sourceNodeAuth, pendingAsk},
		{"new SEND", base + "send", f.sourceNodeAuth, map[string]any{
			"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
			"target_endpoint_id": f.targetEndpoint.ID, "message_id": "active-revoked-send",
			"data_scope": sameGroupSealedTestDataScope,
			"ciphertext": f.seal(t, peer, f.sourceKey, "active-revoked-send", "SEND", "", ""),
		}},
		{"new ASK", base + "ask", f.sourceNodeAuth, map[string]any{
			"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
			"target_endpoint_id": f.targetEndpoint.ID, "message_id": "active-revoked-ask",
			"request_id": "active-revoked-request", "data_scope": sameGroupSealedTestDataScope,
			"expires_at": time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
			"ciphertext": f.seal(t, peer, f.sourceKey, "active-revoked-ask", "REQUEST", "active-revoked-request", ""),
		}},
		{"REPLY", targetBase + "reply", f.targetNodeAuth, map[string]any{
			"request_id": pendingID, "message_id": "active-revoked-reply",
			"ciphertext": f.seal(t, reverse, f.targetKey, "active-revoked-reply", "REPLY", pendingID, pendingAskID),
		}},
	} {
		status, body = call(http.MethodPost, attempt.path, attempt.auth, attempt.body)
		if status != http.StatusForbidden && status != http.StatusNotFound {
			t.Fatalf("revoked Network %s enqueue status=%d body=%s", attempt.name, status, body)
		}
	}
	// The sealed-only read reports mode mismatch for an absent ID because its
	// historical plaintext fallback is checked before the message row.
	for _, messageID := range []string{"active-revoked-send", "active-revoked-ask", "active-revoked-reply"} {
		if _, err := f.persistence.GetRelaySealedV1(messageID); !errors.Is(err, store.ErrRelayPayloadModeMismatch) {
			t.Fatalf("revoked %s reached sealed message ledger: %v", messageID, err)
		}
	}
	if _, err := f.persistence.GetRelaySealedV1(sendID); err != nil {
		t.Fatalf("revoked SEND retry corrupted original accepted message: %v", err)
	}
	if _, err := f.persistence.GetRelaySealedV1(pendingAskID); err != nil {
		t.Fatalf("revoked ASK retry corrupted original accepted request: %v", err)
	}
}
