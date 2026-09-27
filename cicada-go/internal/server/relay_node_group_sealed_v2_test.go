package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

const sameGroupSealedTestDataScope = store.SameGroupSealedV1DataScope

type sameGroupSealedHTTPFixture struct {
	service            *fabricpkg.Service
	persistence        *store.Store
	handler            http.Handler
	ownerID            string
	groupID            string
	otherGroupID       string
	sourceNodeID       string
	targetNodeID       string
	sourceNodeAuth     string
	targetNodeAuth     string
	sourceSessionToken string
	targetSessionToken string
	sourceEndpoint     store.Endpoint
	targetEndpoint     store.Endpoint
	sourceKey          *e2ee.Identity
	targetKey          *e2ee.Identity
	ownerIdentity      *e2ee.Identity
	ownerKeyID         string
}

func newSameGroupSealedHTTPFixture(t *testing.T) *sameGroupSealedHTTPFixture {
	t.Helper()
	persistence, err := store.New(filepath.Join(t.TempDir(), "same-group-sealed.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = persistence.Close() })
	ownerID := "same_group_owner"
	owner, err := persistence.CreatePrincipal(store.Principal{
		ID: ownerID, Kind: store.PrincipalKindHuman, OwnerID: ownerID,
		TrustDomainID: ownerID, Name: ownerID, Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(store.Group{
		ID: "grp_same_group_sealed", Name: "Same Group", OwnerPrincipalID: owner.ID,
		TrustDomainID: owner.TrustDomainID, State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherGroup, err := persistence.CreateGroup(store.Group{
		ID: "grp_other_same_group_sealed", Name: "Other Group", OwnerPrincipalID: owner.ID,
		TrustDomainID: owner.TrustDomainID, State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := persistence.RegisterOwnerApprovalKeyLocal(ownerID, ownerIdentity.Public())
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	clientIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "same-group-sealed-client"
	deviceGrant, err := ownerIdentity.SignOwnerDeviceGrant(ownerID, deviceID,
		clientIdentity.Public(), hubID, e2ee.OwnerDevicePurposeControl,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: ownerKey.KeyID, DeviceID: deviceID,
		DevicePublic: clientIdentity.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		t.Fatal(err)
	}
	service, err := fabricpkg.NewService(persistence, ownerID, owner.TrustDomainID)
	if err != nil {
		t.Fatal(err)
	}
	sourceNodeToken, sourceNodeID := bindSameGroupSealedTestNode(t, persistence,
		ownerID, deviceID, "node_same_group_source")
	targetNodeToken, targetNodeID := bindSameGroupSealedTestNode(t, persistence,
		ownerID, deviceID, "node_same_group_target")
	join := func(groupID, name, nodeID string) *fabricpkg.JoinResult {
		t.Helper()
		joined, err := service.Join(fabricpkg.JoinInput{
			GroupID: groupID, PrincipalName: name, EndpointName: name,
			Harness: "codex", NativeSessionID: "native-" + name,
			NodeID: nodeID, LeaseOwner: "lease-" + name,
		})
		if err != nil {
			t.Fatal(err)
		}
		return joined
	}
	sourceJoin := join(group.ID, "same-group-source", sourceNodeID)
	targetJoin := join(group.ID, "same-group-target", targetNodeID)
	sourceEndpoint := sourceJoin.Endpoint
	targetEndpoint := targetJoin.Endpoint
	sourceKey := addAndGrantSameGroupSealedTestEndpointKey(t, persistence,
		ownerID, group.ID, ownerKey.KeyID, ownerIdentity, sourceEndpoint)
	targetKey := addAndGrantSameGroupSealedTestEndpointKey(t, persistence,
		ownerID, group.ID, ownerKey.KeyID, ownerIdentity, targetEndpoint)
	handler := NewFabricHandler(service, "management-bearer")
	return &sameGroupSealedHTTPFixture{
		service: service, persistence: persistence, handler: handler, ownerID: ownerID,
		groupID: group.ID, otherGroupID: otherGroup.ID, sourceNodeID: sourceNodeID,
		targetNodeID: targetNodeID, sourceNodeAuth: "CicadaNode " + sourceNodeToken,
		targetNodeAuth: "CicadaNode " + targetNodeToken, sourceEndpoint: sourceEndpoint,
		targetEndpoint: targetEndpoint, sourceKey: sourceKey, targetKey: targetKey,
		sourceSessionToken: sourceJoin.SessionToken, targetSessionToken: targetJoin.SessionToken,
		ownerIdentity: ownerIdentity, ownerKeyID: ownerKey.KeyID,
	}
}

func bindSameGroupSealedTestNode(t *testing.T, persistence *store.Store,
	ownerID, deviceID, nodeID string) (string, string) {
	t.Helper()
	token, digest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	code := sha256.Sum256([]byte("same-group-test-code-" + nodeID))
	codeDigest := hex.EncodeToString(code[:])
	if _, err := persistence.CreatePendingNodeDeviceBinding(nodeID, nodeID, digest,
		codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	return token, nodeID
}

func addAndGrantSameGroupSealedTestEndpointKey(t *testing.T, persistence *store.Store,
	ownerID, groupID, ownerKeyID string, ownerIdentity *e2ee.Identity,
	endpoint store.Endpoint) *e2ee.Identity {
	t.Helper()
	binding, err := persistence.GetActiveSessionBinding(endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := key.SignEndpointKeyAttestation(endpoint.ID, endpoint.PrincipalID,
		endpoint.MachineID, binding.ID, binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterEndpointKeyCandidate(endpoint.ID, endpoint.PrincipalID,
		binding.ID, binding.Epoch, attestation); err != nil {
		t.Fatal(err)
	}
	manifest, err := persistence.PreviewGroupEndpointKeyGrant(ownerID, groupID, endpoint.ID,
		ownerKeyID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ownerIdentity.SignOwnerLinkKeyGrant(ownerID,
		store.GroupEndpointKeyGrantOperation, manifest.Digest, manifest.CandidateBindingDigest,
		uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.AcceptGroupEndpointKeyGrant(ownerID, groupID, endpoint.ID,
		ownerKeyID, proof); err != nil {
		t.Fatal(err)
	}
	return key
}

func (f *sameGroupSealedHTTPFixture) call(t *testing.T, method, path, authorization string,
	body any) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	request.Header.Set("Authorization", authorization)
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

func (f *sameGroupSealedHTTPFixture) seal(t *testing.T,
	peer store.SameGroupSealedV1PeerKey, sourceKey *e2ee.Identity,
	messageID, kind, requestID, replyTo string) []byte {
	t.Helper()
	context := e2ee.EndpointMessageContext{
		MessageID: messageID, Kind: kind, RequestID: requestID, ReplyTo: replyTo,
		SenderEndpointID: peer.Sender.EndpointID, SenderPrincipalID: peer.Sender.PrincipalID,
		SenderOwnerID: peer.Sender.OwnerID, SenderGroupID: peer.Sender.GroupID,
		SenderMembershipRevision: peer.Sender.MembershipRevision,
		SenderBindingEpoch:       peer.Sender.BindingEpoch, SenderKeyID: peer.Sender.Candidate.KeyID,
		ReceiverEndpointID: peer.Receiver.EndpointID, ReceiverPrincipalID: peer.Receiver.PrincipalID,
		ReceiverOwnerID: peer.Receiver.OwnerID, ReceiverGroupID: peer.Receiver.GroupID,
		ReceiverMembershipRevision: peer.Receiver.MembershipRevision,
		ReceiverBindingEpoch:       peer.Receiver.BindingEpoch, ReceiverKeyID: peer.Receiver.Candidate.KeyID,
		TransportHubID: peer.HubID,
	}
	wire, err := e2ee.SealEndpointMessage(sourceKey, peer.Receiver.Candidate.Public,
		context, []byte("encrypted same Group message"), 1)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestNodeSameGroupSealedHTTPRoutesAuthorizeOpaqueTrafficWithoutControl(t *testing.T) {
	f := newSameGroupSealedHTTPFixture(t)
	handler, ok := f.handler.(*Handler)
	if !ok || handler.control != nil {
		t.Fatal("same-Group Relay test must run with Control business disabled")
	}
	base := "/v2/relay/nodes/" + f.sourceNodeID + "/group/sealed/"
	receiverBase := "/v2/relay/nodes/" + f.targetNodeID + "/group/sealed/"
	query := url.Values{"group_id": {f.groupID}, "source_endpoint_id": {f.sourceEndpoint.ID},
		"target_endpoint_id": {f.targetEndpoint.ID}}
	peerResponse := f.call(t, http.MethodGet, base+"peer-key?"+query.Encode(), f.sourceNodeAuth, nil)
	if peerResponse.Code != http.StatusOK {
		t.Fatalf("current peer key evidence failed: %d %s", peerResponse.Code, peerResponse.Body.String())
	}
	var peer store.SameGroupSealedV1PeerKey
	if err := json.Unmarshal(peerResponse.Body.Bytes(), &peer); err != nil ||
		peer.GroupID != f.groupID || peer.Sender.EndpointID != f.sourceEndpoint.ID ||
		peer.Receiver.EndpointID != f.targetEndpoint.ID || peer.Receiver.Grant == nil ||
		peer.Receiver.Grant.CurrentStatus != store.GroupEndpointKeyGrantCurrent ||
		bytes.Contains(peerResponse.Body.Bytes(), []byte("native-same-group-target")) ||
		peer.Receiver.Candidate.Public.ID != f.targetKey.Public().ID {
		t.Fatalf("peer evidence was incomplete or not current: evidence=%#v err=%v", peer, err)
	}

	messageID := "same-group-http-send-1"
	ciphertext := f.seal(t, peer, f.sourceKey, messageID, "SEND", "", "")
	sendResponse := f.call(t, http.MethodPost, base+"send", f.sourceNodeAuth,
		map[string]any{"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
			"target_endpoint_id": f.targetEndpoint.ID, "message_id": messageID,
			"idempotency_key": "same-group-send-idem-1", "data_scope": sameGroupSealedTestDataScope,
			"ciphertext": ciphertext})
	if sendResponse.Code != http.StatusAccepted || !bytes.Contains(sendResponse.Body.Bytes(), []byte(`"payload_mode":"SEALED_V1"`)) {
		t.Fatalf("same-Group SEND failed: %d %s", sendResponse.Code, sendResponse.Body.String())
	}
	genericClaim := f.call(t, http.MethodPost,
		"/v2/relay/nodes/"+f.targetNodeID+"/sealed/claim", f.targetNodeAuth,
		map[string]any{"consumer_id": "generic-target", "limit": 10})
	if genericClaim.Code != http.StatusOK {
		t.Fatalf("generic sealed claim failed: %d %s", genericClaim.Code, genericClaim.Body.String())
	}
	var genericClaimed struct {
		Deliveries []store.RelaySealedV1DeliveryAttempt `json:"deliveries"`
	}
	if err := json.Unmarshal(genericClaim.Body.Bytes(), &genericClaimed); err != nil || len(genericClaimed.Deliveries) != 0 {
		t.Fatalf("generic sealed claim selected same-Group rows: %#v err=%v", genericClaimed, err)
	}
	claimResponse := f.call(t, http.MethodPost, receiverBase+"claim", f.targetNodeAuth,
		map[string]any{"consumer_id": "native-target", "limit": 10})
	if claimResponse.Code != http.StatusOK {
		t.Fatalf("same-Group sealed claim failed: %d %s", claimResponse.Code, claimResponse.Body.String())
	}
	var claimed struct {
		Deliveries []store.RelaySealedV1DeliveryAttempt `json:"deliveries"`
	}
	if err := json.Unmarshal(claimResponse.Body.Bytes(), &claimed); err != nil || len(claimed.Deliveries) != 1 ||
		claimed.Deliveries[0].MessageID != messageID {
		t.Fatalf("same-Group claim returned wrong inbox: %#v err=%v", claimed, err)
	}
	attemptID := claimed.Deliveries[0].AttemptID
	authQuery := url.Values{"attempt_id": {attemptID}}
	authorization := f.call(t, http.MethodGet, receiverBase+"deliveries/"+messageID+
		"/authorization?"+authQuery.Encode(), f.targetNodeAuth, nil)
	if authorization.Code != http.StatusOK || !bytes.Contains(authorization.Body.Bytes(), []byte(f.groupID)) ||
		!bytes.Contains(authorization.Body.Bytes(), []byte("native-same-group-target")) ||
		bytes.Contains(authorization.Body.Bytes(), []byte("native-same-group-source")) {
		t.Fatalf("pre-injection evidence failed: %d %s", authorization.Code, authorization.Body.String())
	}
	wrongReceiverGuard := f.call(t, http.MethodGet, receiverBase+"deliveries/"+messageID+
		"/authorization?"+authQuery.Encode(), f.sourceNodeAuth, nil)
	if wrongReceiverGuard.Code != http.StatusForbidden && wrongReceiverGuard.Code != http.StatusNotFound {
		t.Fatalf("sender Node used target-side pre-injection evidence: %d %s", wrongReceiverGuard.Code, wrongReceiverGuard.Body.String())
	}

	wrongCredential := f.call(t, http.MethodPost, base+"send", "Bearer management-bearer", map[string]any{})
	if wrongCredential.Code != http.StatusUnauthorized {
		t.Fatalf("manager bearer authorized Node-only sealed route: %d %s", wrongCredential.Code, wrongCredential.Body.String())
	}
	wrongNode := f.call(t, http.MethodPost, receiverBase+"claim", f.sourceNodeAuth, map[string]any{"consumer_id": "forged"})
	if wrongNode.Code != http.StatusForbidden {
		t.Fatalf("source Node claimed through target Node route: %d %s", wrongNode.Code, wrongNode.Body.String())
	}

	otherGroupCiphertext := f.seal(t, peer, f.sourceKey, "same-group-http-cross-group",
		"SEND", "", "")
	crossGroup := f.call(t, http.MethodPost, base+"send", f.sourceNodeAuth,
		map[string]any{"group_id": f.otherGroupID, "source_endpoint_id": f.sourceEndpoint.ID,
			"target_endpoint_id": f.targetEndpoint.ID, "message_id": "same-group-http-cross-group",
			"data_scope": sameGroupSealedTestDataScope, "ciphertext": otherGroupCiphertext})
	if crossGroup.Code != http.StatusForbidden {
		t.Fatalf("cross-Group SEND was accepted: %d %s", crossGroup.Code, crossGroup.Body.String())
	}
	spoofSource := f.call(t, http.MethodPost, base+"send", f.sourceNodeAuth,
		map[string]any{"group_id": f.groupID, "source_endpoint_id": f.targetEndpoint.ID,
			"target_endpoint_id": f.sourceEndpoint.ID, "message_id": "same-group-http-spoof-source",
			"data_scope": sameGroupSealedTestDataScope, "ciphertext": ciphertext})
	if spoofSource.Code != http.StatusForbidden {
		t.Fatalf("Node credential selected another Node's source Endpoint: %d %s", spoofSource.Code, spoofSource.Body.String())
	}
	plainFallback := f.call(t, http.MethodPost, base+"send", f.sourceNodeAuth,
		map[string]any{"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
			"target_endpoint_id": f.targetEndpoint.ID, "message_id": "plaintext-fallback",
			"data_scope": sameGroupSealedTestDataScope, "plaintext": "not encrypted"})
	if plainFallback.Code != http.StatusBadRequest {
		t.Fatalf("plaintext peer message was accepted: %d %s", plainFallback.Code, plainFallback.Body.String())
	}

	askMessageID, requestID := "same-group-http-ask-message", "same-group-http-ask-request"
	askCiphertext := f.seal(t, peer, f.sourceKey, askMessageID, "REQUEST", requestID, "")
	askResponse := f.call(t, http.MethodPost, base+"ask", f.sourceNodeAuth,
		map[string]any{"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
			"target_endpoint_id": f.targetEndpoint.ID, "message_id": askMessageID,
			"request_id": requestID, "idempotency_key": "same-group-ask-idem",
			"data_scope": sameGroupSealedTestDataScope,
			"expires_at": time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
			"ciphertext": askCiphertext})
	if askResponse.Code != http.StatusAccepted {
		t.Fatalf("same-Group ASK failed: %d %s", askResponse.Code, askResponse.Body.String())
	}
	statusResponse := f.call(t, http.MethodGet, base+"requests/"+requestID, f.sourceNodeAuth, nil)
	if statusResponse.Code != http.StatusOK || !bytes.Contains(statusResponse.Body.Bytes(), []byte(`"state":"OPEN"`)) {
		t.Fatalf("same-Group ASK status failed: %d %s", statusResponse.Code, statusResponse.Body.String())
	}

	reverseQuery := url.Values{"group_id": {f.groupID}, "source_endpoint_id": {f.targetEndpoint.ID},
		"target_endpoint_id": {f.sourceEndpoint.ID}}
	reverseResponse := f.call(t, http.MethodGet, receiverBase+"peer-key?"+reverseQuery.Encode(), f.targetNodeAuth, nil)
	if reverseResponse.Code != http.StatusOK {
		t.Fatalf("reverse peer evidence failed: %d %s", reverseResponse.Code, reverseResponse.Body.String())
	}
	var reversePeer store.SameGroupSealedV1PeerKey
	if err := json.Unmarshal(reverseResponse.Body.Bytes(), &reversePeer); err != nil {
		t.Fatal(err)
	}
	replyMessageID := "same-group-http-reply-message"
	replyCiphertext := f.seal(t, reversePeer, f.targetKey, replyMessageID,
		"REPLY", requestID, askMessageID)
	replyResponse := f.call(t, http.MethodPost, receiverBase+"reply", f.targetNodeAuth,
		map[string]any{"request_id": requestID, "message_id": replyMessageID,
			"idempotency_key": "same-group-reply-idem", "ciphertext": replyCiphertext})
	if replyResponse.Code != http.StatusAccepted {
		t.Fatalf("same-Group REPLY failed: %d %s", replyResponse.Code, replyResponse.Body.String())
	}
	completedStatus := f.call(t, http.MethodGet, base+"requests/"+requestID, f.sourceNodeAuth, nil)
	if completedStatus.Code != http.StatusOK || !bytes.Contains(completedStatus.Body.Bytes(), []byte(`"state":"REPLIED"`)) {
		t.Fatalf("same-Group request did not reach REPLIED: %d %s", completedStatus.Code, completedStatus.Body.String())
	}

	cancelRequestID, cancelMessageID := "same-group-http-cancel-request", "same-group-http-cancel-message"
	cancelCiphertext := f.seal(t, peer, f.sourceKey, cancelMessageID, "REQUEST", cancelRequestID, "")
	cancelAsk := f.call(t, http.MethodPost, base+"ask", f.sourceNodeAuth,
		map[string]any{"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
			"target_endpoint_id": f.targetEndpoint.ID, "message_id": cancelMessageID,
			"request_id": cancelRequestID, "data_scope": sameGroupSealedTestDataScope,
			"expires_at": time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
			"ciphertext": cancelCiphertext})
	if cancelAsk.Code != http.StatusAccepted {
		t.Fatalf("cancellable ASK failed: %d %s", cancelAsk.Code, cancelAsk.Body.String())
	}
	cancelResponse := f.call(t, http.MethodPost, base+"requests/"+cancelRequestID+"/cancel",
		f.sourceNodeAuth, map[string]any{})
	if cancelResponse.Code != http.StatusOK || !bytes.Contains(cancelResponse.Body.Bytes(), []byte(`"state":"CANCEL_REQUESTED"`)) {
		t.Fatalf("same-Group request cancellation failed: %d %s", cancelResponse.Code, cancelResponse.Body.String())
	}
	terminalCancel := f.call(t, http.MethodPost, base+"requests/"+requestID+"/cancel", f.sourceNodeAuth, map[string]any{})
	if terminalCancel.Code != http.StatusConflict {
		t.Fatalf("replied request cancellation did not return conflict: %d %s", terminalCancel.Code, terminalCancel.Body.String())
	}

	revokedMessageID := "same-group-http-revoked-message"
	revokedCiphertext := f.seal(t, peer, f.sourceKey, revokedMessageID, "SEND", "", "")
	revokedSend := f.call(t, http.MethodPost, base+"send", f.sourceNodeAuth,
		map[string]any{"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
			"target_endpoint_id": f.targetEndpoint.ID, "message_id": revokedMessageID,
			"data_scope": sameGroupSealedTestDataScope, "ciphertext": revokedCiphertext})
	if revokedSend.Code != http.StatusAccepted {
		t.Fatalf("pre-revocation sealed message failed: %d %s", revokedSend.Code, revokedSend.Body.String())
	}
	targetMembership, err := f.persistence.GetMembershipByPrincipalGroup(
		f.targetEndpoint.PrincipalID, f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.persistence.RevokeMembership(targetMembership.ID, "same-group transport revoke test"); err != nil {
		t.Fatal(err)
	}
	revokedClaim := f.call(t, http.MethodPost, receiverBase+"claim", f.targetNodeAuth,
		map[string]any{"consumer_id": "native-target-after-revoke", "limit": 10})
	if revokedClaim.Code != http.StatusOK || bytes.Contains(revokedClaim.Body.Bytes(), []byte(revokedMessageID)) {
		t.Fatalf("revoked Group membership left sealed ciphertext claimable: %d %s", revokedClaim.Code, revokedClaim.Body.String())
	}
	postRevoke := f.call(t, http.MethodPost, base+"send", f.sourceNodeAuth,
		map[string]any{"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
			"target_endpoint_id": f.targetEndpoint.ID, "message_id": "same-group-after-revoke",
			"data_scope": sameGroupSealedTestDataScope, "ciphertext": revokedCiphertext})
	if postRevoke.Code != http.StatusForbidden {
		t.Fatalf("revoked receiver remained authorized for sealed traffic: %d %s", postRevoke.Code, postRevoke.Body.String())
	}

	badRoute := f.call(t, http.MethodPost, base+"send", f.sourceNodeAuth,
		map[string]any{"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
			"target_endpoint_id": f.targetEndpoint.ID, "message_id": "same-group-bad-scope",
			"data_scope": "model-selected-scope", "ciphertext": ciphertext})
	if badRoute.Code != http.StatusBadRequest {
		t.Fatalf("caller-selected data scope was accepted: %d %s", badRoute.Code, badRoute.Body.String())
	}
}
