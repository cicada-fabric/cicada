package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

type monitorBroadcastHTTPApproval struct {
	record        *store.UserMonitorBroadcastV2
	clientKey     *e2ee.Identity
	clientDevice  *store.ClientDevice
	sealedPayload []byte
	ownerGrant    []byte
}

func prepareRelayNodeMonitorBroadcastHTTPApproval(t *testing.T,
	f *sameGroupSealedHTTPFixture, body []byte) *monitorBroadcastHTTPApproval {
	t.Helper()
	sourceMembership, err := f.persistence.GetMembershipByPrincipalGroup(f.sourceEndpoint.PrincipalID, f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	sourceGrants := append([]string(nil), sourceMembership.Grants...)
	for _, action := range []string{"message.broadcast", "message.send"} {
		found := false
		for _, current := range sourceGrants {
			if current == action {
				found = true
				break
			}
		}
		if !found {
			sourceGrants = append(sourceGrants, action)
		}
	}
	if _, err := f.persistence.UpdateMembershipAuthorization(sourceMembership.ID,
		[]string{"monitor"}, sourceGrants, sourceMembership.Authorization, sourceMembership.Version); err != nil {
		t.Fatal(err)
	}
	grantSameGroupAuthorization(t, f.persistence, f.targetEndpoint.PrincipalID, f.groupID, "message.receive")
	refreshSameGroupSealedTestEndpointKeyGrant(t, f.persistence, f.ownerID, f.groupID,
		f.ownerKeyID, f.ownerIdentity, f.sourceEndpoint)
	refreshSameGroupSealedTestEndpointKeyGrant(t, f.persistence, f.ownerID, f.groupID,
		f.ownerKeyID, f.ownerIdentity, f.targetEndpoint)

	clientKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := f.persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "monitor-broadcast-synthetic-client"
	ownerGrant, err := f.ownerIdentity.SignOwnerDeviceGrant(f.ownerID, deviceID,
		clientKey.Public(), hubID, e2ee.OwnerDevicePurposeControl,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	clientDevice, err := f.persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: f.ownerID, OwnerKeyID: f.ownerKeyID, DeviceID: deviceID,
		DevicePublic: clientKey.Public(), OwnerDeviceGrant: ownerGrant,
	})
	if err != nil {
		t.Fatal(err)
	}
	accept := func(sequence uint64) string {
		t.Helper()
		ciphertextDigest := sha256.Sum256([]byte("synthetic monitor Client request " + strconv.FormatUint(sequence, 10)))
		accepted, err := f.persistence.AcceptClientRequest(store.AcceptClientRequestInput{
			OwnerID: f.ownerID, DeviceID: clientDevice.DeviceID,
			SessionEpoch: clientDevice.SessionEpoch, Sequence: sequence,
			OperationID: store.NewID("synthetic_rpc"), CiphertextDigest: hex.EncodeToString(ciphertextDigest[:]),
		})
		if err != nil {
			t.Fatal(err)
		}
		return accepted.Request.ID
	}
	bodyDigest := sha256.Sum256(body)
	clientRequestID := accept(1)
	preview, err := f.persistence.PrepareUserMonitorBroadcastV2(store.PrepareUserMonitorBroadcastV2Input{
		ClientRequestID: clientRequestID, GroupID: f.groupID, MonitorEndpointID: f.sourceEndpoint.ID,
		BodyDigest: hex.EncodeToString(bodyDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := e2ee.MonitorBroadcastContext{
		HubID: hubID, OwnerID: preview.OwnerID, ClientDeviceID: preview.DeviceID,
		ClientSessionEpoch: preview.SessionEpoch, ClientKeyVersion: preview.ClientKeyVersion,
		ApprovalID: preview.PreviewID, BroadcastID: preview.BroadcastID, GroupID: preview.GroupID,
		MonitorEndpointID: preview.MonitorEndpointID, MonitorKeyID: preview.Snapshot.Source.KeyID,
		MonitorBindingID:    preview.Snapshot.Source.BindingID,
		MonitorBindingEpoch: preview.Snapshot.Source.BindingEpoch,
		BodySHA256:          preview.BodyDigest, RecipientSnapshotSHA256: preview.SnapshotDigest,
		ExpiresAt:     preview.ExpiresAt,
		ConsentSHA256: preview.Preview.ConsentSHA256, ConfirmRequestSequence: 2,
	}
	sealed, err := e2ee.SealMonitorBroadcast(clientKey, f.sourceKey.Public(), ctx, body, 2)
	if err != nil {
		t.Fatal(err)
	}
	confirmRequestID := accept(2)
	approved, err := f.persistence.ConfirmUserMonitorBroadcastV2(store.ConfirmUserMonitorBroadcastV2Input{
		ClientRequestID: confirmRequestID, PreviewID: preview.PreviewID,
		SnapshotDigest: preview.SnapshotDigest, BodyDigest: preview.BodyDigest,
		SealedPayload: sealed,
	})
	if err != nil || approved.Status != store.UserMonitorBroadcastV2Approved {
		t.Fatalf("synthetic sealed Client approval failed: record=%#v err=%v", approved, err)
	}
	return &monitorBroadcastHTTPApproval{record: approved, clientKey: clientKey,
		clientDevice: clientDevice, sealedPayload: sealed, ownerGrant: ownerGrant}
}

func TestRelayNodeMonitorBroadcastRoutesBindNodeSessionAndCurrentSnapshot(t *testing.T) {
	f := newSameGroupSealedHTTPFixture(t)
	body := []byte("synthetic monitor broadcast body")
	approval := prepareRelayNodeMonitorBroadcastHTTPApproval(t, f, body)
	handler, ok := f.handler.(*Handler)
	if !ok || handler.control != nil {
		t.Fatal("Monitor broadcast Node routes must run without Control business")
	}
	path := "/v2/relay/nodes/" + f.sourceNodeID + "/monitor/broadcasts"
	call := func(method, route, authorization, session string, requestBody []byte) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, route, bytes.NewReader(requestBody))
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		if session != "" {
			request.Header.Set("X-Cicada-Session", session)
		}
		response := httptest.NewRecorder()
		f.handler.ServeHTTP(response, request)
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("Monitor broadcast route %s omitted no-store: %v", route, response.Header())
		}
		return response
	}
	jsonBody := func(value any) []byte {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	preview := approval.record
	authorizeBody := map[string]string{
		"broadcast_id":    preview.BroadcastID,
		"operation_id":    "op_" + strings.TrimPrefix(preview.BroadcastID, "bc_"),
		"body_sha256":     preview.BodyDigest,
		"snapshot_digest": preview.SnapshotDigest,
	}
	wrongNodePath := "/v2/relay/nodes/" + f.sourceNodeID + "/monitor/broadcasts"
	if response := call(http.MethodGet, path, "Bearer invalid", "", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("non-Node auth read notifications: %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, wrongNodePath, f.targetNodeAuth, "", nil); response.Code != http.StatusForbidden {
		t.Fatalf("different Node credential crossed Node path: %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, path+"?limit=17", f.sourceNodeAuth, "", nil); response.Code != http.StatusBadRequest {
		t.Fatalf("unbounded notification page was accepted: %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, path+"/"+preview.PreviewID+"/authorize",
		f.sourceNodeAuth, "", jsonBody(authorizeBody)); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing Session header authorized sealed delivery: %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, path+"/"+preview.PreviewID+"/authorize",
		f.sourceNodeAuth, f.sourceSessionToken, []byte(`{"broadcast_id":"x","operation_id":"y","body_sha256":"z","snapshot_digest":"z","session_token":"forged"}`)); response.Code != http.StatusBadRequest {
		t.Fatalf("caller supplied a credential field in JSON: %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, path+"/"+preview.PreviewID+"/authorize",
		f.sourceNodeAuth, f.targetSessionToken, jsonBody(authorizeBody)); response.Code != http.StatusNotFound {
		t.Fatalf("Session bound to another Node/Endpoint authorized delivery: %d %s", response.Code, response.Body.String())
	}

	list := call(http.MethodGet, path, f.sourceNodeAuth, "", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("notification list status=%d body=%s", list.Code, list.Body.String())
	}
	var listing struct {
		HubID         string                                     `json:"hub_id"`
		Notifications []store.UserMonitorBroadcastV2Notification `json:"notifications"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	hubID, err := f.persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	if listing.HubID != hubID || len(listing.Notifications) != 1 ||
		listing.Notifications[0].PreviewID != preview.PreviewID ||
		listing.Notifications[0].NativeSessionID != "native-same-group-source" ||
		listing.Notifications[0].BindingID != preview.Snapshot.Source.BindingID ||
		listing.Notifications[0].ReceiptState != store.UserMonitorBroadcastV2NoticePending {
		t.Fatalf("Node notification omitted exact Hub/Monitor target binding: %#v", listing)
	}
	detailPath := path + "/" + preview.PreviewID
	detail := call(http.MethodGet, detailPath, f.sourceNodeAuth, "", nil)
	if detail.Code != http.StatusOK || bytes.Contains(detail.Body.Bytes(), approval.sealedPayload) ||
		bytes.Contains(detail.Body.Bytes(), []byte(f.sourceSessionToken)) {
		t.Fatalf("metadata-only detail leaked opaque delivery data or failed: %d %s", detail.Code, detail.Body.String())
	}
	if bytes.Contains(detail.Body.Bytes(), []byte(base64.StdEncoding.EncodeToString(approval.sealedPayload))) {
		t.Fatal("metadata-only detail included the sealed Client payload")
	}

	receiptPath := detailPath + "/receipt"
	receiptBody := map[string]any{
		"broadcast_id": preview.BroadcastID, "snapshot_digest": preview.SnapshotDigest,
		"binding_id": preview.Snapshot.Source.BindingID, "binding_epoch": preview.Snapshot.Source.BindingEpoch,
		"state": store.UserMonitorBroadcastV2NoticeNodeAccepted,
	}
	badReceipt := map[string]any{}
	for key, value := range receiptBody {
		badReceipt[key] = value
	}
	badReceipt["snapshot_digest"] = strings.Repeat("0", 64)
	if response := call(http.MethodPost, receiptPath, f.sourceNodeAuth, "", jsonBody(badReceipt)); response.Code != http.StatusNotFound {
		t.Fatalf("receipt with mismatched digest was accepted: %d %s", response.Code, response.Body.String())
	}
	badReceipt["snapshot_digest"] = preview.SnapshotDigest
	badReceipt["binding_id"] = preview.Snapshot.Recipients[0].BindingID
	if response := call(http.MethodPost, receiptPath, f.sourceNodeAuth, "", jsonBody(badReceipt)); response.Code != http.StatusNotFound {
		t.Fatalf("receipt for another Endpoint binding was accepted: %d %s", response.Code, response.Body.String())
	}
	badReceipt["binding_id"] = preview.Snapshot.Source.BindingID
	badReceipt["binding_epoch"] = preview.Snapshot.Source.BindingEpoch + 1
	if response := call(http.MethodPost, receiptPath, f.sourceNodeAuth, "", jsonBody(badReceipt)); response.Code != http.StatusNotFound {
		t.Fatalf("receipt for another binding epoch was accepted: %d %s", response.Code, response.Body.String())
	}
	badReceipt["binding_epoch"] = preview.Snapshot.Source.BindingEpoch
	firstReceipt := call(http.MethodPost, receiptPath, f.sourceNodeAuth, "", jsonBody(receiptBody))
	if firstReceipt.Code != http.StatusOK {
		t.Fatalf("Node notification receipt failed: %d %s", firstReceipt.Code, firstReceipt.Body.String())
	}
	retryReceipt := call(http.MethodPost, receiptPath, f.sourceNodeAuth, "", jsonBody(receiptBody))
	if retryReceipt.Code != http.StatusOK || !bytes.Equal(retryReceipt.Body.Bytes(), firstReceipt.Body.Bytes()) {
		t.Fatalf("exact receipt retry changed result: first=%d retry=%d", firstReceipt.Code, retryReceipt.Code)
	}
	receiptBody["state"] = store.UserMonitorBroadcastV2NoticeQueueAccepted
	queued := call(http.MethodPost, receiptPath, f.sourceNodeAuth, "", jsonBody(receiptBody))
	if queued.Code != http.StatusOK {
		t.Fatalf("durable queue receipt failed: %d %s", queued.Code, queued.Body.String())
	}
	terminalList := call(http.MethodGet, path, f.sourceNodeAuth, "", nil)
	var terminal struct {
		Notifications []store.UserMonitorBroadcastV2Notification `json:"notifications"`
	}
	if terminalList.Code != http.StatusOK || json.Unmarshal(terminalList.Body.Bytes(), &terminal) != nil || len(terminal.Notifications) != 0 {
		t.Fatalf("terminal queue receipt remained in notification list: %d %s", terminalList.Code, terminalList.Body.String())
	}
	queuedDetail := call(http.MethodGet, detailPath, f.sourceNodeAuth, "", nil)
	var queuedMetadata struct {
		HubID        string                                   `json:"hub_id"`
		Notification store.UserMonitorBroadcastV2Notification `json:"notification"`
	}
	if queuedDetail.Code != http.StatusOK || json.Unmarshal(queuedDetail.Body.Bytes(), &queuedMetadata) != nil ||
		queuedMetadata.HubID != hubID || queuedMetadata.Notification.ReceiptState != store.UserMonitorBroadcastV2NoticeQueueAccepted {
		t.Fatalf("queued metadata was unavailable to native MCP: %d %s", queuedDetail.Code, queuedDetail.Body.String())
	}
	if bytes.Contains(queuedDetail.Body.Bytes(), []byte(base64.StdEncoding.EncodeToString(approval.sealedPayload))) {
		t.Fatal("queued metadata read included the sealed Client payload")
	}

	// Queue acceptance is management notification evidence only. The original
	// Monitor MCP still needs its current Session to reserve delivery.
	authorizePath := detailPath + "/authorize"
	first := call(http.MethodPost, authorizePath, f.sourceNodeAuth, f.sourceSessionToken, jsonBody(authorizeBody))
	if first.Code != http.StatusOK {
		t.Fatalf("current authorized Node delivery failed after notification queueing: %d %s", first.Code, first.Body.String())
	}
	retry := call(http.MethodPost, authorizePath, f.sourceNodeAuth, f.sourceSessionToken, jsonBody(authorizeBody))
	if retry.Code != http.StatusOK || !bytes.Equal(retry.Body.Bytes(), first.Body.Bytes()) {
		t.Fatalf("exact authorization retry changed the delivery bundle: first=%d retry=%d", first.Code, retry.Code)
	}
	var delivery store.UserMonitorBroadcastV2Delivery
	if err := json.Unmarshal(first.Body.Bytes(), &delivery); err != nil {
		t.Fatal(err)
	}
	if delivery.Context.HubID != hubID || delivery.Context.ApprovalID != preview.PreviewID ||
		delivery.Context.BroadcastID != preview.BroadcastID || delivery.ClientPublic.ID != approval.clientKey.Public().ID ||
		delivery.OwnerKeyID != f.ownerKeyID ||
		delivery.EnrolledAt != approval.clientDevice.CreatedAt ||
		!bytes.Equal(delivery.SealedPayload, approval.sealedPayload) ||
		delivery.SealedPayloadDigest != preview.SealedPayloadDigest || delivery.OperationID != authorizeBody["operation_id"] {
		t.Fatalf("Node bundle lost the signed Client/Owner binding or exact sealed payload: %#v", delivery)
	}
	enrolledAt, err := time.Parse(time.RFC3339Nano, delivery.EnrolledAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2ee.VerifyOwnerDeviceGrant(delivery.OwnerDeviceGrant, f.ownerIdentity.Public(),
		delivery.ClientPublic, f.ownerID, delivery.OwnerKeyID, approval.clientDevice.DeviceID,
		hubID, e2ee.OwnerDevicePurposeControl, enrolledAt); err != nil {
		t.Fatalf("Node bundle did not retain the original Owner enrollment proof: %v", err)
	}
}

func TestRelayNodeMonitorBroadcastRoutesHideRevokedSnapshot(t *testing.T) {
	f := newSameGroupSealedHTTPFixture(t)
	approval := prepareRelayNodeMonitorBroadcastHTTPApproval(t, f, []byte("synthetic monitor broadcast body"))
	preview := approval.record
	if _, err := f.persistence.RevokeMembershipForPrincipalGroup(f.targetEndpoint.PrincipalID,
		f.groupID, "synthetic recipient revocation"); err != nil {
		t.Fatal(err)
	}
	path := "/v2/relay/nodes/" + f.sourceNodeID + "/monitor/broadcasts"
	call := func(method, route string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, route, bytes.NewReader(body))
		request.Header.Set("Authorization", f.sourceNodeAuth)
		request.Header.Set("X-Cicada-Session", f.sourceSessionToken)
		response := httptest.NewRecorder()
		f.handler.ServeHTTP(response, request)
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("revoked Monitor route omitted no-store: %v", response.Header())
		}
		return response
	}
	authorizeBody, err := json.Marshal(map[string]string{
		"broadcast_id": preview.BroadcastID,
		"operation_id": "op_" + strings.TrimPrefix(preview.BroadcastID, "bc_"),
		"body_sha256":  preview.BodyDigest, "snapshot_digest": preview.SnapshotDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response := call(http.MethodPost, path+"/"+preview.PreviewID+"/authorize", authorizeBody); response.Code != http.StatusNotFound {
		t.Fatalf("revoked recipient snapshot was authorized: %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, path+"/"+preview.PreviewID, nil); response.Code != http.StatusNotFound {
		t.Fatalf("revoked recipient snapshot remained visible as current Guard: %d %s", response.Code, response.Body.String())
	}
	listing := call(http.MethodGet, path, nil)
	if listing.Code != http.StatusOK {
		t.Fatalf("revoked notification list status=%d body=%s", listing.Code, listing.Body.String())
	}
	var result struct {
		Notifications []store.UserMonitorBroadcastV2Notification `json:"notifications"`
	}
	if err := json.Unmarshal(listing.Body.Bytes(), &result); err != nil || len(result.Notifications) != 0 {
		t.Fatalf("revoked snapshot remained in current Node notification list: %#v err=%v", result, err)
	}
}

func TestRelayNodeMonitorBroadcastReviewIsReadOnlyAndRequiresOriginalSession(t *testing.T) {
	f := newSameGroupSealedHTTPFixture(t)
	body := []byte("synthetic monitor review plaintext stays on Client and Node")
	approval := prepareRelayNodeMonitorBroadcastHTTPApproval(t, f, body)
	preview := approval.record
	base := "/v2/relay/nodes/" + f.sourceNodeID + "/monitor/broadcasts/" + preview.PreviewID
	assertNoSecretError := func(response *httptest.ResponseRecorder) {
		t.Helper()
		if response.Code < 400 {
			return
		}
		for _, secret := range [][]byte{[]byte(f.sourceSessionToken), []byte(f.targetSessionToken),
			approval.sealedPayload, approval.ownerGrant} {
			if len(secret) != 0 && bytes.Contains(response.Body.Bytes(), secret) {
				t.Fatal("review error response exposed a credential, proof, or sealed payload")
			}
		}
	}
	call := func(session, suffix string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, base+suffix, nil)
		request.Header.Set("Authorization", f.sourceNodeAuth)
		if session != "" {
			request.Header.Set("X-Cicada-Session", session)
		}
		response := httptest.NewRecorder()
		f.handler.ServeHTTP(response, request)
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("Monitor review omitted no-store: %v", response.Header())
		}
		assertNoSecretError(response)
		return response
	}
	if got := call("", "/review"); got.Code != http.StatusUnauthorized {
		t.Fatalf("review without original Session was accepted: %d %s", got.Code, got.Body.String())
	}
	if got := call(f.targetSessionToken, "/review"); got.Code != http.StatusNotFound {
		t.Fatalf("review with another endpoint Session was accepted: %d %s", got.Code, got.Body.String())
	}
	wrongNode := httptest.NewRequest(http.MethodGet, base+"/review", nil)
	wrongNode.Header.Set("Authorization", f.targetNodeAuth)
	wrongNode.Header.Set("X-Cicada-Session", f.sourceSessionToken)
	wrongNodeResponse := httptest.NewRecorder()
	f.handler.ServeHTTP(wrongNodeResponse, wrongNode)
	if wrongNodeResponse.Code != http.StatusForbidden {
		t.Fatalf("review ignored the Node ID in the route: %d %s", wrongNodeResponse.Code, wrongNodeResponse.Body.String())
	}
	assertNoSecretError(wrongNodeResponse)
	duplicateSession := httptest.NewRequest(http.MethodGet, base+"/review", nil)
	duplicateSession.Header.Set("Authorization", f.sourceNodeAuth)
	duplicateSession.Header.Add("X-Cicada-Session", f.sourceSessionToken)
	duplicateSession.Header.Add("X-Cicada-Session", f.targetSessionToken)
	duplicateSessionResponse := httptest.NewRecorder()
	f.handler.ServeHTTP(duplicateSessionResponse, duplicateSession)
	if duplicateSessionResponse.Code != http.StatusUnauthorized {
		t.Fatalf("review accepted multiple Session credentials: %d %s", duplicateSessionResponse.Code, duplicateSessionResponse.Body.String())
	}
	assertNoSecretError(duplicateSessionResponse)
	if got := call(f.sourceSessionToken, "/review?operation_id=forged"); got.Code != http.StatusBadRequest {
		t.Fatalf("review accepted query-supplied permission claims: %d %s", got.Code, got.Body.String())
	}
	bodyRequest := httptest.NewRequest(http.MethodGet, base+"/review",
		strings.NewReader(`{"approved":true,"operation_id":"forged"}`))
	bodyRequest.Header.Set("Authorization", f.sourceNodeAuth)
	bodyRequest.Header.Set("X-Cicada-Session", f.sourceSessionToken)
	bodyResponse := httptest.NewRecorder()
	f.handler.ServeHTTP(bodyResponse, bodyRequest)
	if bodyResponse.Code != http.StatusBadRequest ||
		bodyResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("review accepted a JSON permission claim: %d %s", bodyResponse.Code, bodyResponse.Body.String())
	}
	assertNoSecretError(bodyResponse)
	first := call(f.sourceSessionToken, "/review")
	if first.Code != http.StatusOK {
		t.Fatalf("current approved review unavailable: %d %s", first.Code, first.Body.String())
	}
	second := call(f.sourceSessionToken, "/review")
	if second.Code != http.StatusOK || !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatalf("repeated review changed or consumed the sealed evidence: first=%d second=%d", first.Code, second.Code)
	}
	if bytes.Contains(first.Body.Bytes(), body) || bytes.Contains(first.Body.Bytes(), []byte(f.sourceSessionToken)) {
		t.Fatal("review response included plaintext or Session credential")
	}
	var delivery store.UserMonitorBroadcastV2Delivery
	if err := json.Unmarshal(first.Body.Bytes(), &delivery); err != nil {
		t.Fatal(err)
	}
	if delivery.Context.ApprovalID != preview.PreviewID || delivery.Context.BroadcastID != preview.BroadcastID ||
		delivery.OperationID != "op_"+strings.TrimPrefix(preview.BroadcastID, "bc_") ||
		!bytes.Equal(delivery.SealedPayload, approval.sealedPayload) || delivery.Snapshot.SnapshotDigest != preview.SnapshotDigest {
		t.Fatalf("review did not return the exact sealed approval evidence: %+v", delivery.Context)
	}
	authorizeBody, err := json.Marshal(map[string]string{
		"broadcast_id":    preview.BroadcastID,
		"operation_id":    delivery.OperationID,
		"body_sha256":     preview.BodyDigest,
		"snapshot_digest": preview.SnapshotDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorized := httptest.NewRequest(http.MethodPost, base+"/authorize", bytes.NewReader(authorizeBody))
	authorized.Header.Set("Authorization", f.sourceNodeAuth)
	authorized.Header.Set("X-Cicada-Session", f.sourceSessionToken)
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, authorized)
	if response.Code != http.StatusOK || !bytes.Equal(first.Body.Bytes(), response.Body.Bytes()) {
		t.Fatalf("read-only review changed subsequent exact authorization: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRelayNodeMonitorBroadcastOutcomeReportRequiresBoundDispatch(t *testing.T) {
	f := newSameGroupSealedHTTPFixture(t)
	approval := prepareRelayNodeMonitorBroadcastHTTPApproval(t, f, []byte("synthetic outcome-only body"))
	r := approval.record
	opID := "op_" + strings.TrimPrefix(r.BroadcastID, "bc_")
	recipient := r.Snapshot.Recipients[0]
	childID, messageID, err := store.UserMonitorBroadcastV2ChildIDs(r.BroadcastID, recipient.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	base := "/v2/relay/nodes/" + f.sourceNodeID + "/monitor/broadcasts/" + r.PreviewID
	call := func(route, nodeAuth, session string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, route, bytes.NewReader(body))
		if nodeAuth != "" {
			request.Header.Set("Authorization", nodeAuth)
		}
		if session != "" {
			request.Header.Set("X-Cicada-Session", session)
		}
		response := httptest.NewRecorder()
		f.handler.ServeHTTP(response, request)
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("outcome route omitted no-store: %v", response.Header())
		}
		return response
	}
	encode := func(value any) []byte {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	report := map[string]any{
		"broadcast_id": r.BroadcastID, "operation_id": opID, "snapshot_digest": r.SnapshotDigest,
		"results": []store.UserMonitorBroadcastV2RecipientReport{{Ordinal: 0,
			EndpointID: recipient.EndpointID, ChildOperationID: childID, MessageID: messageID,
			State: store.UserMonitorBroadcastV2OutcomeFailed, FailureCode: "DELIVERY_REJECTED"}},
	}
	reportPath := base + "/outcomes"
	if response := call(reportPath, f.sourceNodeAuth, f.sourceSessionToken, encode(report)); response.Code != http.StatusNotFound {
		t.Fatalf("report before dispatch authorization was accepted: %d %s", response.Code, response.Body.String())
	}
	if response := call(reportPath, f.sourceNodeAuth, "", encode(report)); response.Code != http.StatusUnauthorized {
		t.Fatalf("report without native Session was accepted: %d %s", response.Code, response.Body.String())
	}
	if response := call(reportPath, f.targetNodeAuth, f.sourceSessionToken, encode(report)); response.Code != http.StatusForbidden {
		t.Fatalf("wrong Node credential crossed route path: %d %s", response.Code, response.Body.String())
	}
	for name, body := range map[string][]byte{
		"body credential": []byte(`{"node_credential_digest":"forged","results":[]}`),
		"path spoof": encode(map[string]any{"preview_id": r.PreviewID, "broadcast_id": r.BroadcastID,
			"operation_id": opID, "snapshot_digest": r.SnapshotDigest, "results": report["results"]}),
		"oversize": bytes.Repeat([]byte("x"), 16*1024+1),
	} {
		if response := call(reportPath, f.sourceNodeAuth, f.sourceSessionToken, body); response.Code != http.StatusBadRequest {
			t.Fatalf("%s report was accepted: %d %s", name, response.Code, response.Body.String())
		}
	}
	authorizeBody := encode(map[string]string{"broadcast_id": r.BroadcastID, "operation_id": opID,
		"body_sha256": r.BodyDigest, "snapshot_digest": r.SnapshotDigest})
	if response := call(base+"/authorize", f.sourceNodeAuth, f.sourceSessionToken, authorizeBody); response.Code != http.StatusOK {
		t.Fatalf("could not reserve original Monitor dispatch: %d %s", response.Code, response.Body.String())
	}
	if response := call(reportPath, f.sourceNodeAuth, f.targetSessionToken, encode(report)); response.Code != http.StatusNotFound {
		t.Fatalf("foreign native Session reported outcome: %d %s", response.Code, response.Body.String())
	}
	first := call(reportPath, f.sourceNodeAuth, f.sourceSessionToken, encode(report))
	if first.Code != http.StatusOK {
		t.Fatalf("bound Node failed to record factual outcome: %d %s", first.Code, first.Body.String())
	}
	retry := call(reportPath, f.sourceNodeAuth, f.sourceSessionToken, encode(report))
	if retry.Code != http.StatusOK || !bytes.Equal(first.Body.Bytes(), retry.Body.Bytes()) {
		t.Fatalf("exact outcome retry was not stable: first=%d retry=%d", first.Code, retry.Code)
	}
	var result struct {
		HubID          string                                         `json:"hub_id"`
		PreviewID      string                                         `json:"preview_id"`
		BroadcastID    string                                         `json:"broadcast_id"`
		OperationID    string                                         `json:"operation_id"`
		SnapshotDigest string                                         `json:"snapshot_digest"`
		Results        []store.UserMonitorBroadcastV2RecipientOutcome `json:"results"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	hubID, err := f.persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	if result.HubID != hubID || result.PreviewID != r.PreviewID || result.BroadcastID != r.BroadcastID ||
		result.OperationID != opID || result.SnapshotDigest != r.SnapshotDigest || len(result.Results) != 1 ||
		result.Results[0].State != store.UserMonitorBroadcastV2OutcomeFailed ||
		bytes.Contains(first.Body.Bytes(), []byte(base64.StdEncoding.EncodeToString(approval.sealedPayload))) {
		t.Fatalf("outcome response leaked payload or lost correlation: %+v", result)
	}
	bad := report["results"].([]store.UserMonitorBroadcastV2RecipientReport)[0]
	bad.EndpointID = f.sourceEndpoint.ID
	report["results"] = []store.UserMonitorBroadcastV2RecipientReport{bad}
	if response := call(reportPath, f.sourceNodeAuth, f.sourceSessionToken, encode(report)); response.Code != http.StatusNotFound {
		t.Fatalf("spoofed recipient report was accepted: %d %s", response.Code, response.Body.String())
	}
	bindings, err := f.persistence.ListNodeDeviceBindings(f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	var sourceBinding *store.NodeDeviceBinding
	for i := range bindings {
		if bindings[i].NodeID == f.sourceNodeID {
			sourceBinding = &bindings[i]
		}
	}
	if sourceBinding == nil {
		t.Fatal("source Node owner binding missing")
	}
	if _, err := f.persistence.RevokeNodeDeviceBinding(f.ownerID, sourceBinding.ID, sourceBinding.Version); err != nil {
		t.Fatal(err)
	}
	if response := call(reportPath, f.sourceNodeAuth, f.sourceSessionToken, encode(report)); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked Node binding reported outcome: %d %s", response.Code, response.Body.String())
	}
}
