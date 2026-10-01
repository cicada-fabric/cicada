package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestClientV2OwnerGrantAndEncryptedSnapshotAcrossRestart(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	config := control.Config{StateDir: stateDir, WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "legacy-manager-secret"}
	manager, err := control.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreateGroup(control.GroupCreateInput{Name: "my group"}); err != nil {
		t.Fatal(err)
	}
	ownerID := manager.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	persistence, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	_ = persistence.Close()
	handler := NewHandler(manager)
	identityResult := httptest.NewRecorder()
	handler.ServeHTTP(identityResult, httptest.NewRequest(http.MethodGet, "/v2/client/identity", nil))
	if identityResult.Code != http.StatusOK {
		t.Fatalf("identity status=%d body=%s", identityResult.Code, identityResult.Body.String())
	}
	var identity struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if err := json.Unmarshal(identityResult.Body.Bytes(), &identity); err != nil || identity.HubID == "" {
		t.Fatalf("decode Hub identity: %v %#v", err, identity)
	}
	deviceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "phone-a", deviceKey.Public(), identity.HubID,
		e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "phone-a", "device_public_identity": deviceKey.Public(),
		"owner_device_grant": grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrolled := httptest.NewRecorder()
	handler.ServeHTTP(enrolled, httptest.NewRequest(http.MethodPost, "/v2/client/devices/enroll", bytes.NewReader(enrollment)))
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", enrolled.Code, enrolled.Body.String())
	}
	// The old management bearer cannot replace an owner signature, and an
	// attacker cannot turn an unrelated device key into the enrolled key.
	forgedKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	forgedEnrollment, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "phone-forged", "device_public_identity": forgedKey.Public(),
		"owner_device_grant": grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	forgedRequest := httptest.NewRequest(http.MethodPost, "/v2/client/devices/enroll", bytes.NewReader(forgedEnrollment))
	forgedRequest.Header.Set("Authorization", "Bearer legacy-manager-secret")
	forgedResponse := httptest.NewRecorder()
	handler.ServeHTTP(forgedResponse, forgedRequest)
	if forgedResponse.Code != http.StatusForbidden {
		t.Fatalf("manager bearer enrolled forged device: status=%d", forgedResponse.Code)
	}
	binding := clientwire.Binding{HubID: identity.HubID, OwnerID: ownerID, DeviceID: "phone-a",
		SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
		HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
		SessionEpoch: binding.SessionEpoch, Sequence: 1, OperationID: "op-snapshot-1",
		Operation: "status.snapshot", SenderKeyID: deviceKey.Public().ID,
		SenderKeyVersion: 1, ReceiverKeyID: identity.ControlPublicIdentity.ID, ReceiverKeyVersion: 1}
	packet, err := clientwire.SealRequest(deviceKey, identity.ControlPublicIdentity, binding, route, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(packet)))
	if first.Code != http.StatusOK {
		t.Fatalf("encrypted snapshot status=%d body=%s", first.Code, first.Body.String())
	}
	opened, err := clientwire.OpenResponse(deviceKey, identity.ControlPublicIdentity, binding, first.Body.Bytes())
	if err != nil {
		t.Fatalf("decrypt Hub response: %v", err)
	}
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			OwnerID string `json:"owner_principal_id"`
			Groups  []any  `json:"groups"`
		} `json:"result"`
	}
	if err := json.Unmarshal(opened.Plaintext, &result); err != nil || !result.OK || result.Result.OwnerID != ownerID || len(result.Result.Groups) != 1 {
		t.Fatalf("invalid decrypted snapshot: err=%v result=%#v", err, result)
	}
	retry := httptest.NewRecorder()
	handler.ServeHTTP(retry, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(packet)))
	if retry.Code != http.StatusOK || !bytes.Equal(retry.Body.Bytes(), first.Body.Bytes()) {
		t.Fatalf("exact retry changed response: status=%d", retry.Code)
	}
	conflictingPacket, err := clientwire.SealRequest(deviceKey, identity.ControlPublicIdentity, binding, route, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	conflict := httptest.NewRecorder()
	handler.ServeHTTP(conflict, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(conflictingPacket)))
	if conflict.Code != http.StatusConflict {
		t.Fatalf("same sequence accepted with different ciphertext: status=%d", conflict.Code)
	}
	forgedPacket, err := clientwire.SealRequest(forgedKey, identity.ControlPublicIdentity, binding,
		clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
			HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
			SessionEpoch: 1, Sequence: 2, OperationID: "op-forged", Operation: "status.snapshot",
			SenderKeyID: forgedKey.Public().ID, SenderKeyVersion: 1,
			ReceiverKeyID: identity.ControlPublicIdentity.ID, ReceiverKeyVersion: 1}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	forgery := httptest.NewRecorder()
	handler.ServeHTTP(forgery, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(forgedPacket)))
	if forgery.Code != http.StatusForbidden {
		t.Fatalf("unregistered key authenticated as phone-a: status=%d", forgery.Code)
	}
	intentRoute := route
	intentRoute.Sequence = 2
	intentRoute.OperationID = "op-idea-1"
	intentRoute.Operation = "intent.submit"
	intentPacket, err := clientwire.SealRequest(deviceKey, identity.ControlPublicIdentity, binding, intentRoute,
		[]byte(`{"text":"idea: a device-origin idea","kind":"idea"}`))
	if err != nil {
		t.Fatal(err)
	}
	intentResponse := httptest.NewRecorder()
	handler.ServeHTTP(intentResponse, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(intentPacket)))
	if intentResponse.Code != http.StatusOK {
		t.Fatalf("intent submission status=%d body=%s", intentResponse.Code, intentResponse.Body.String())
	}
	openedIntent, err := clientwire.OpenResponse(deviceKey, identity.ControlPublicIdentity, binding, intentResponse.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var intentResult struct {
		OK     bool `json:"ok"`
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(openedIntent.Plaintext, &intentResult); err != nil || !intentResult.OK || intentResult.Result.ID == "" {
		t.Fatalf("intent response invalid: err=%v response=%s", err, openedIntent.Plaintext)
	}
	intentRetry := httptest.NewRecorder()
	handler.ServeHTTP(intentRetry, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(intentPacket)))
	if intentRetry.Code != http.StatusOK || !bytes.Equal(intentRetry.Body.Bytes(), intentResponse.Body.Bytes()) {
		t.Fatalf("intent retry changed cached response: status=%d", intentRetry.Code)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		progress, err := manager.ClientIntentStatus(ownerID, intentResult.Result.ID)
		if err != nil {
			t.Fatal(err)
		}
		if progress.Job.State == store.ClientIntentDone && progress.Intent.Status == "resolved" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("accepted Client intent did not finish: %#v", progress)
		}
		time.Sleep(10 * time.Millisecond)
	}
	intents, err := manager.Intents("")
	if err != nil || len(intents) != 1 || intents[0].ID != intentResult.Result.ID {
		t.Fatalf("intent executed more than once: intents=%#v err=%v", intents, err)
	}
	secondKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	secondGrant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "phone-b", secondKey.Public(), identity.HubID,
		e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	secondEnrollment, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "phone-b", "device_public_identity": secondKey.Public(),
		"owner_device_grant": secondGrant,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondEnrolled := httptest.NewRecorder()
	handler.ServeHTTP(secondEnrolled, httptest.NewRequest(http.MethodPost, "/v2/client/devices/enroll", bytes.NewReader(secondEnrollment)))
	if secondEnrolled.Code != http.StatusCreated {
		t.Fatalf("second device enrollment status=%d body=%s", secondEnrolled.Code, secondEnrolled.Body.String())
	}
	listRoute := route
	listRoute.Sequence = 3
	listRoute.OperationID = "op-devices-list"
	listRoute.Operation = "devices.list"
	listPacket, err := clientwire.SealRequest(deviceKey, identity.ControlPublicIdentity, binding, listRoute, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(listPacket)))
	if listed.Code != http.StatusOK {
		t.Fatalf("device list status=%d body=%s", listed.Code, listed.Body.String())
	}
	openedList, err := clientwire.OpenResponse(deviceKey, identity.ControlPublicIdentity, binding, listed.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var listedResult struct {
		OK     bool                 `json:"ok"`
		Result []store.ClientDevice `json:"result"`
	}
	if err := json.Unmarshal(openedList.Plaintext, &listedResult); err != nil || !listedResult.OK || len(listedResult.Result) != 2 {
		t.Fatalf("invalid owner-scoped device list: err=%v result=%s", err, openedList.Plaintext)
	}
	revokeRoute := route
	revokeRoute.Sequence = 4
	revokeRoute.OperationID = "op-devices-revoke"
	revokeRoute.Operation = "devices.revoke"
	revokePacket, err := clientwire.SealRequest(deviceKey, identity.ControlPublicIdentity, binding, revokeRoute,
		[]byte(`{"device_id":"phone-b","expected_version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	revocation := httptest.NewRecorder()
	handler.ServeHTTP(revocation, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(revokePacket)))
	if revocation.Code != http.StatusOK {
		t.Fatalf("device revocation status=%d body=%s", revocation.Code, revocation.Body.String())
	}
	openedRevocation, err := clientwire.OpenResponse(deviceKey, identity.ControlPublicIdentity, binding, revocation.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var revokedResult struct {
		OK     bool               `json:"ok"`
		Result store.ClientDevice `json:"result"`
	}
	if err := json.Unmarshal(openedRevocation.Plaintext, &revokedResult); err != nil || !revokedResult.OK ||
		revokedResult.Result.DeviceID != "phone-b" || revokedResult.Result.State != store.ClientDeviceRevoked {
		t.Fatalf("invalid device revocation: err=%v result=%s", err, openedRevocation.Plaintext)
	}
	selfRevokeRoute := route
	selfRevokeRoute.Sequence = 5
	selfRevokeRoute.OperationID = "op-devices-self-revoke"
	selfRevokeRoute.Operation = "devices.revoke"
	selfRevokePacket, err := clientwire.SealRequest(deviceKey, identity.ControlPublicIdentity, binding, selfRevokeRoute,
		[]byte(`{"device_id":"phone-a","expected_version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	selfRevoke := httptest.NewRecorder()
	handler.ServeHTTP(selfRevoke, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(selfRevokePacket)))
	if selfRevoke.Code != http.StatusOK {
		t.Fatalf("self-revoke response was not sealed: status=%d", selfRevoke.Code)
	}
	openedSelfRevoke, err := clientwire.OpenResponse(deviceKey, identity.ControlPublicIdentity, binding, selfRevoke.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var selfRevokeResult struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(openedSelfRevoke.Plaintext, &selfRevokeResult); err != nil || selfRevokeResult.OK {
		t.Fatalf("current session revoked itself: err=%v result=%s", err, openedSelfRevoke.Plaintext)
	}
	statusRoute := route
	statusRoute.Sequence = 6
	statusRoute.OperationID = "op-intent-status"
	statusRoute.Operation = "intent.status"
	statusBody, err := json.Marshal(map[string]string{"intent_id": intentResult.Result.ID})
	if err != nil {
		t.Fatal(err)
	}
	statusPacket, err := clientwire.SealRequest(deviceKey, identity.ControlPublicIdentity, binding, statusRoute, statusBody)
	if err != nil {
		t.Fatal(err)
	}
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(statusPacket)))
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("intent status response=%d body=%s", statusResponse.Code, statusResponse.Body.String())
	}
	openedStatus, err := clientwire.OpenResponse(deviceKey, identity.ControlPublicIdentity, binding, statusResponse.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var statusResult struct {
		OK     bool                         `json:"ok"`
		Result control.ClientIntentProgress `json:"result"`
	}
	if err := json.Unmarshal(openedStatus.Plaintext, &statusResult); err != nil || !statusResult.OK ||
		statusResult.Result.Job == nil || statusResult.Result.Job.State != store.ClientIntentDone ||
		statusResult.Result.Intent == nil || statusResult.Result.Intent.ID != intentResult.Result.ID {
		t.Fatalf("invalid intent status: err=%v result=%s", err, openedStatus.Plaintext)
	}
	topologyRoute := route
	topologyRoute.Sequence = 7
	topologyRoute.OperationID = "op-topology-create"
	topologyRoute.Operation = "topology.apply"
	topologyPacket, err := clientwire.SealRequest(deviceKey, identity.ControlPublicIdentity, binding, topologyRoute,
		[]byte(`{"kind":"group.create","create_group":{"group":{"name":"phone-managed"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	topologyResponse := httptest.NewRecorder()
	handler.ServeHTTP(topologyResponse, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(topologyPacket)))
	if topologyResponse.Code != http.StatusOK {
		t.Fatalf("encrypted topology change status=%d body=%s", topologyResponse.Code, topologyResponse.Body.String())
	}
	openedTopology, err := clientwire.OpenResponse(deviceKey, identity.ControlPublicIdentity, binding, topologyResponse.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var topologyResult struct {
		OK     bool `json:"ok"`
		Result struct {
			Group *control.ClientTopologyGroup `json:"group"`
		} `json:"result"`
	}
	if err := json.Unmarshal(openedTopology.Plaintext, &topologyResult); err != nil || !topologyResult.OK ||
		topologyResult.Result.Group == nil || topologyResult.Result.Group.Name != "phone-managed" {
		t.Fatalf("invalid encrypted topology change: err=%v result=%s", err, openedTopology.Plaintext)
	}
	topologyRetry := httptest.NewRecorder()
	handler.ServeHTTP(topologyRetry, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(topologyPacket)))
	if topologyRetry.Code != http.StatusOK || !bytes.Equal(topologyRetry.Body.Bytes(), topologyResponse.Body.Bytes()) {
		t.Fatal("topology change was replayed instead of returning its cached sealed response")
	}
	topologySnapshotRoute := route
	topologySnapshotRoute.Sequence = 8
	topologySnapshotRoute.OperationID = "op-topology-snapshot"
	topologySnapshotRoute.Operation = "topology.snapshot"
	topologySnapshotPacket, err := clientwire.SealRequest(deviceKey, identity.ControlPublicIdentity, binding,
		topologySnapshotRoute, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	topologySnapshotResponse := httptest.NewRecorder()
	handler.ServeHTTP(topologySnapshotResponse, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(topologySnapshotPacket)))
	if topologySnapshotResponse.Code != http.StatusOK {
		t.Fatalf("encrypted topology snapshot status=%d body=%s", topologySnapshotResponse.Code, topologySnapshotResponse.Body.String())
	}
	openedTopologySnapshot, err := clientwire.OpenResponse(deviceKey, identity.ControlPublicIdentity, binding, topologySnapshotResponse.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var topologySnapshotResult struct {
		OK     bool                           `json:"ok"`
		Result control.ClientTopologySnapshot `json:"result"`
	}
	if err := json.Unmarshal(openedTopologySnapshot.Plaintext, &topologySnapshotResult); err != nil ||
		!topologySnapshotResult.OK || len(topologySnapshotResult.Result.Groups) != 2 ||
		topologySnapshotResult.Result.OwnerPrincipalID != ownerID {
		t.Fatalf("invalid encrypted topology snapshot: err=%v result=%s", err, openedTopologySnapshot.Plaintext)
	}
	pairRequest := func(method, path string, body []byte) (int, []byte) {
		t.Helper()
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, path, bytes.NewReader(body)))
		return recorder.Code, recorder.Body.Bytes()
	}
	nodeToken, nodeDigest, _, _, challenge, startBody := startPQNodeDeviceCodeFixture(t, pairRequest,
		"phone-linked-node", "Phone linked node")
	tooFast := httptest.NewRecorder()
	handler.ServeHTTP(tooFast, httptest.NewRequest(http.MethodPost, "/v2/nodes/device-code", bytes.NewReader(startBody)))
	if tooFast.Code != http.StatusTooManyRequests {
		t.Fatalf("public Node code reissue bypassed cooldown: status=%d body=%s", tooFast.Code, tooFast.Body.String())
	}
	if _, err := manager.Fabric().AuthenticateNode(nodeToken); err == nil {
		t.Fatal("Node token authenticated before owner confirmation")
	}
	callNodeRPC := func(sequence uint64, operation string, body []byte) []byte {
		t.Helper()
		nodeRoute := route
		nodeRoute.Sequence = sequence
		nodeRoute.OperationID = "op-node-" + operation + "-" + strconv.FormatUint(sequence, 10)
		nodeRoute.Operation = operation
		nodePacket, err := clientwire.SealRequest(deviceKey, identity.ControlPublicIdentity, binding, nodeRoute, body)
		if err != nil {
			t.Fatal(err)
		}
		nodeResponse := httptest.NewRecorder()
		handler.ServeHTTP(nodeResponse, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(nodePacket)))
		if nodeResponse.Code != http.StatusOK {
			t.Fatalf("Node RPC %s status=%d body=%s", operation, nodeResponse.Code, nodeResponse.Body.String())
		}
		openedNode, err := clientwire.OpenResponse(deviceKey, identity.ControlPublicIdentity, binding, nodeResponse.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return openedNode.Plaintext
	}
	codeBody, err := json.Marshal(map[string]string{"user_code": challenge.UserCode})
	if err != nil {
		t.Fatal(err)
	}
	preview := callNodeRPC(9, "nodes.preview", codeBody)
	var previewEnvelope struct {
		OK     bool                          `json:"ok"`
		Result store.NodeControlKeyCandidate `json:"result"`
	}
	if err := json.Unmarshal(preview, &previewEnvelope); err != nil || !previewEnvelope.OK ||
		previewEnvelope.Result.NodeID != "phone-linked-node" ||
		previewEnvelope.Result.RequestID != challenge.Candidate.RequestID ||
		previewEnvelope.Result.CandidateDigest == "" || previewEnvelope.Result.Version <= 0 ||
		bytes.Contains(preview, []byte(nodeDigest)) {
		t.Fatalf("owner preview lacked exact Node candidate or leaked credential: err=%v result=%s", err, preview)
	}
	confirmBody, err := json.Marshal(map[string]any{"user_code": challenge.UserCode,
		"candidate_digest":  previewEnvelope.Result.CandidateDigest,
		"candidate_version": previewEnvelope.Result.Version})
	if err != nil {
		t.Fatal(err)
	}
	confirmation := callNodeRPC(10, "nodes.confirm", confirmBody)
	var confirmed struct {
		OK     bool                        `json:"ok"`
		Result store.NodeControlKeyBinding `json:"result"`
	}
	if err := json.Unmarshal(confirmation, &confirmed); err != nil || !confirmed.OK ||
		confirmed.Result.State != store.NodeControlKeyActive || confirmed.Result.OwnerID != ownerID ||
		confirmed.Result.NodeID != "phone-linked-node" || confirmed.Result.ApprovedCandidateDigest != previewEnvelope.Result.CandidateDigest {
		t.Fatalf("owner confirmation failed: err=%v result=%s", err, confirmation)
	}
	statusRequest := httptest.NewRequest(http.MethodGet,
		"/v2/node/device-code/"+previewEnvelope.Result.RequestID+"/status?node_id=phone-linked-node", nil)
	statusRequest.Header.Set("Authorization", "CicadaNode "+nodeToken)
	nodePairingResponse := httptest.NewRecorder()
	handler.ServeHTTP(nodePairingResponse, statusRequest)
	var pairingStatus store.NodeControlKeyCandidate
	if nodePairingResponse.Code != http.StatusOK || json.Unmarshal(nodePairingResponse.Body.Bytes(), &pairingStatus) != nil ||
		pairingStatus.State != store.NodeControlPairingConfirmed || pairingStatus.BindingID != confirmed.Result.OwnerBindingID ||
		pairingStatus.BindingVersion != confirmed.Result.BindingVersion {
		t.Fatalf("Node pairing status omitted confirmed binding: status=%d body=%s", nodePairingResponse.Code, nodePairingResponse.Body.String())
	}
	if authenticated, err := manager.Fabric().AuthenticateNode(nodeToken); err != nil || authenticated != "phone-linked-node" {
		t.Fatalf("confirmed Node not authenticated: id=%q err=%v", authenticated, err)
	}
	bindings := callNodeRPC(11, "nodes.list", []byte(`{}`))
	if !bytes.Contains(bindings, []byte(confirmed.Result.OwnerBindingID)) || bytes.Contains(bindings, []byte(nodeDigest)) {
		t.Fatalf("binding list missing Node or leaked digest: %s", bindings)
	}
	revokeBody, err := json.Marshal(map[string]any{
		"binding_id": confirmed.Result.OwnerBindingID, "expected_version": confirmed.Result.BindingVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	nodeRevocation := callNodeRPC(12, "nodes.revoke", revokeBody)
	if !bytes.Contains(nodeRevocation, []byte(`"state":"REVOKED"`)) {
		t.Fatalf("binding revocation failed: %s", nodeRevocation)
	}
	if _, err := manager.Fabric().AuthenticateNode(nodeToken); err == nil {
		t.Fatal("revoked Node still authenticated")
	}
	changes := callNodeRPC(13, "status.changes", []byte(`{}`))
	var changed struct {
		OK     bool                            `json:"ok"`
		Result control.ClientStatusChangesPage `json:"result"`
	}
	if err := json.Unmarshal(changes, &changed); err != nil || !changed.OK ||
		changed.Result.Completeness != "partial" || len(changed.Result.Events) == 0 ||
		changed.Result.OwnerPrincipalID != ownerID || changed.Result.Cursor == "" {
		t.Fatalf("encrypted status changes failed: err=%v result=%s", err, changes)
	}
	changesBody, err := json.Marshal(map[string]string{"cursor": changed.Result.Cursor})
	if err != nil {
		t.Fatal(err)
	}
	unchanged := callNodeRPC(14, "status.changes", changesBody)
	var next struct {
		OK     bool                            `json:"ok"`
		Result control.ClientStatusChangesPage `json:"result"`
	}
	if err := json.Unmarshal(unchanged, &next); err != nil || !next.OK || len(next.Result.Events) != 0 {
		t.Fatalf("stable snapshot emitted repeated changes: err=%v result=%s", err, unchanged)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager, err = control.New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	if manager.ClientControlPublicIdentity().ID != identity.ControlPublicIdentity.ID {
		t.Fatal("Hub Client-Control key changed after restart")
	}
	if hubID, err := manager.ClientHubID(); err != nil || hubID != identity.HubID {
		t.Fatalf("Hub ID changed after restart: %q %v", hubID, err)
	}
	retryAfterRestart := httptest.NewRecorder()
	NewHandler(manager).ServeHTTP(retryAfterRestart, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(packet)))
	if retryAfterRestart.Code != http.StatusOK || !bytes.Equal(retryAfterRestart.Body.Bytes(), first.Body.Bytes()) {
		t.Fatalf("restart replay changed response: status=%d body=%s", retryAfterRestart.Code, retryAfterRestart.Body.String())
	}
	intentRetryAfterRestart := httptest.NewRecorder()
	NewHandler(manager).ServeHTTP(intentRetryAfterRestart, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(intentPacket)))
	if intentRetryAfterRestart.Code != http.StatusOK || !bytes.Equal(intentRetryAfterRestart.Body.Bytes(), intentResponse.Body.Bytes()) {
		t.Fatalf("intent replay after restart changed result: status=%d", intentRetryAfterRestart.Code)
	}
	persistence, err = store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RevokeClientDevice(ownerID, "phone-a", 1); err != nil {
		t.Fatal(err)
	}
	_ = persistence.Close()
	revoked := httptest.NewRecorder()
	NewHandler(manager).ServeHTTP(revoked, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(packet)))
	if revoked.Code != http.StatusForbidden {
		t.Fatalf("revoked device replayed request: status=%d", revoked.Code)
	}
}
