package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

type monitorHTTPOutcome struct {
	RequestID   string          `json:"request_id"`
	OperationID string          `json:"operation_id"`
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Error       string          `json:"error"`
}

func sendMonitorEncryptedHTTP(t *testing.T, client *groupKeyHTTPTestClient,
	operation string, input any, discardResponse ...bool) (int, monitorHTTPOutcome, int, string) {
	t.Helper()
	plaintext, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	client.sequence++
	operationID := fmt.Sprintf("monitor-http-%s-%d", client.deviceID, client.sequence)
	binding := clientwire.Binding{HubID: client.hubID, OwnerID: client.ownerID,
		DeviceID: client.deviceID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
		HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
		SessionEpoch: binding.SessionEpoch, Sequence: client.sequence,
		OperationID: operationID, Operation: operation,
		SenderKeyID: client.device.Public().ID, SenderKeyVersion: 1,
		ReceiverKeyID: client.hubPublic.ID, ReceiverKeyVersion: 1}
	packet, err := clientwire.SealRequest(client.device, client.hubPublic, binding, route, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	status, response := clientNodeChainHTTP(t, client.http, client.serverURL,
		http.MethodPost, "/v2/client/rpc", packet, "")
	if status != http.StatusOK {
		return status, monitorHTTPOutcome{}, 0, operationID
	}
	if len(discardResponse) != 0 && discardResponse[0] {
		// Simulate a transport consumer losing the accepted response bytes.
		return status, monitorHTTPOutcome{}, 0, operationID
	}
	opened, err := clientwire.OpenResponse(client.device, client.hubPublic, binding, response)
	if err != nil {
		t.Fatal(err)
	}
	var outcome monitorHTTPOutcome
	if err := json.Unmarshal(opened.Plaintext, &outcome); err != nil {
		t.Fatal(err)
	}
	if outcome.OperationID != operationID || outcome.RequestID == "" {
		t.Fatal("uncorrelated encrypted Monitor response")
	}
	return status, outcome, len(opened.Plaintext), operationID
}

func decodeMonitorHTTPResult(t *testing.T, outcome monitorHTTPOutcome) control.ClientMonitorBroadcastResult {
	t.Helper()
	if !outcome.OK {
		t.Fatalf("Monitor RPC failed: %s", outcome.Error)
	}
	var result control.ClientMonitorBroadcastResult
	if err := json.Unmarshal(outcome.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

// A real TCP Hub handles encrypted Client packets; all identities, Nodes and
// Endpoints remain synthetic Store fixtures. No native Runtime is invoked.
func TestClientMonitorBroadcastEncryptedHTTPLifecycle(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	manager, err := control.New(control.Config{StateDir: stateDir,
		WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "synthetic-monitor-manager-token"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.Shutdown(ctx); err != nil {
			t.Errorf("shutdown Control: %v", err)
		}
	})
	group, err := manager.CreateGroup(control.GroupCreateInput{Name: "synthetic Monitor HTTP Group"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewHandler(manager))
	t.Cleanup(server.Close)
	httpClient := server.Client()
	status, identityBody := clientNodeChainHTTP(t, httpClient, server.URL,
		http.MethodGet, "/v2/client/identity", nil, "")
	if status != http.StatusOK {
		t.Fatalf("Hub identity HTTP %d", status)
	}
	var hub struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if err := json.Unmarshal(identityBody, &hub); err != nil || hub.HubID == "" {
		t.Fatal("invalid Hub identity", err)
	}
	ownerID := manager.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	const deviceID = "monitor_http_device_synthetic"
	database, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	enrollSyntheticGroupKeyHTTPDevice(t, httpClient, server.URL, ownerID,
		ownerKey, deviceKey, deviceID, hub.HubID)
	client := &groupKeyHTTPTestClient{serverURL: server.URL, http: httpClient,
		ownerID: ownerID, deviceID: deviceID, device: deviceKey,
		hubID: hub.HubID, hubPublic: hub.ControlPublicIdentity}
	const sourceNodeID = "node_monitor_http_synthetic"
	nodeToken, _ := bindSameGroupSealedTestNode(t, database, ownerID, deviceID, sourceNodeID)
	const targetNodeID = "node_monitor_http_target_synthetic"
	_, _ = bindSameGroupSealedTestNode(t, database, ownerID, deviceID, targetNodeID)
	join := func(name, nodeID string) *fabric.JoinResult {
		t.Helper()
		joined, err := manager.Fabric().Join(fabric.JoinInput{GroupID: group.ID,
			PrincipalName: name, EndpointName: name, Harness: "codex",
			NativeSessionID: "native_" + name, NodeID: nodeID, LeaseOwner: "lease_" + name})
		if err != nil {
			t.Fatal(err)
		}
		return joined
	}
	source := join("monitor_http_source_synthetic", sourceNodeID)
	target := join("monitor_http_target_synthetic", targetNodeID)
	sourceMembership, err := database.GetMembershipByPrincipalGroup(source.Endpoint.PrincipalID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	grants := append([]string(nil), sourceMembership.Grants...)
	for _, action := range []string{"message.receive", "message.send", "message.broadcast"} {
		found := false
		for _, current := range grants {
			if current == action {
				found = true
			}
		}
		if !found {
			grants = append(grants, action)
		}
	}
	if _, err := database.UpdateMembershipAuthorization(sourceMembership.ID, []string{"monitor"},
		grants, sourceMembership.Authorization, sourceMembership.Version); err != nil {
		t.Fatal(err)
	}
	grantSameGroupAuthorization(t, database, target.Endpoint.PrincipalID, group.ID, "message.receive")
	sourceKey := addAndGrantSameGroupSealedTestEndpointKey(t, database, ownerID, group.ID,
		ownerKey.Public().ID, ownerKey, source.Endpoint)
	_ = addAndGrantSameGroupSealedTestEndpointKey(t, database, ownerID, group.ID,
		ownerKey.Public().ID, ownerKey, target.Endpoint)
	foreignGroup, err := database.CreateGroup(store.Group{ID: "group_monitor_http_foreign_synthetic",
		OwnerPrincipalID: "owner_foreign_synthetic", TrustDomainID: "owner_foreign_synthetic",
		Name: "foreign", State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}

	wake, unsubscribe := manager.Fabric().SubscribeNodeEvents(sourceNodeID)
	defer unsubscribe()
	body := []byte("PUBLIC SYNTHETIC Monitor broadcast body")
	bodyHash := sha256.Sum256(body)
	bodyDigest := hex.EncodeToString(bodyHash[:])
	prepareInput := map[string]string{"group_id": group.ID,
		"monitor_endpoint_id": source.Endpoint.ID, "body_sha256": bodyDigest}
	if _, rejected, _, _ := sendMonitorEncryptedHTTP(t, client, "monitor.broadcast_prepare",
		map[string]string{"group_id": foreignGroup.ID, "monitor_endpoint_id": source.Endpoint.ID,
			"body_sha256": bodyDigest}); rejected.OK {
		t.Fatal("foreign owner Group prepared")
	}
	if _, rejected, _, _ := sendMonitorEncryptedHTTP(t, client, "monitor.broadcast_prepare",
		map[string]string{"group_id": group.ID, "monitor_endpoint_id": source.Endpoint.ID,
			"body_sha256": bodyDigest, "unexpected": "denied"}); rejected.OK {
		t.Fatal("unknown request field prepared")
	}
	if _, rejected, _, _ := sendMonitorEncryptedHTTP(t, client, "monitor.broadcast_prepare",
		map[string]string{"group_id": group.ID, "monitor_endpoint_id": target.Endpoint.ID,
			"body_sha256": bodyDigest}); rejected.OK {
		t.Fatal("non-Monitor Endpoint prepared")
	}
	prepareStatus, _, _, originalPrepareOperationID := sendMonitorEncryptedHTTP(t, client,
		"monitor.broadcast_prepare", prepareInput, true)
	if prepareStatus != http.StatusOK {
		t.Fatalf("prepare transport failed: %d", prepareStatus)
	}
	// Simulate losing the accepted response: only its original operation ID is
	// retained. A fresh read-only operation must recover the same preview.
	_, recoveredOutcome, recoverySize, _ := sendMonitorEncryptedHTTP(t, client,
		"monitor.broadcast_recover", map[string]string{"operation_id": originalPrepareOperationID})
	recovered := decodeMonitorHTTPResult(t, recoveredOutcome)
	if recovered.Preview == nil || recoverySize >= 64*1024 || recovered.Status != store.UserMonitorBroadcastV2Prepared {
		t.Fatalf("read-only recovery lost consent or exceeded budget: %+v (%d bytes)", recovered, recoverySize)
	}
	if bytes.Contains(recoveredOutcome.Result, []byte("native_session_id")) ||
		bytes.Contains(recoveredOutcome.Result, []byte("workspace")) ||
		bytes.Contains(recoveredOutcome.Result, []byte(`"snapshot":`)) {
		t.Fatal("public preview exposed private locator")
	}
	actualDigest, err := e2ee.MonitorBroadcastConsentDigest(recovered.Preview.ConsentScope)
	if err != nil || actualDigest != recovered.Preview.ConsentSHA256 {
		t.Fatal("unverifiable public consent digest", err)
	}
	manifest := recovered.Preview.MonitorGrantManifest
	attested, err := e2ee.VerifyEndpointKeyAttestation(manifest.CandidateAttestation,
		manifest.EndpointID, manifest.PrincipalID, manifest.NodeID, manifest.BindingID, manifest.BindingEpoch)
	if err != nil || attested.ID != sourceKey.Public().ID {
		t.Fatal("Monitor attestation failed", err)
	}
	var signed e2ee.OwnerLinkKeyGrant
	if err := json.Unmarshal(recovered.Preview.MonitorGrantSignedProof, &signed); err != nil {
		t.Fatal(err)
	}
	issued, err := time.Parse(time.RFC3339Nano, signed.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2ee.VerifyOwnerLinkKeyGrant(recovered.Preview.MonitorGrantSignedProof,
		ownerKey.Public(), ownerID, store.GroupEndpointKeyGrantOperation, manifest.Digest,
		manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, issued); err != nil {
		t.Fatal("Owner proof failed", err)
	}
	if _, outcome, _, _ := sendMonitorEncryptedHTTP(t, client, "monitor.broadcast_recover",
		map[string]string{"operation_id": "foreign_prepare_operation"}); outcome.OK {
		t.Fatal("foreign operation recovered")
	}
	if _, outcome, _, _ := sendMonitorEncryptedHTTP(t, client, "monitor.broadcast_status",
		map[string]string{"preview_id": recovered.PreviewID}); !outcome.OK {
		t.Fatal("prepared status unavailable", outcome.Error)
	}

	buildContext := func(sequence uint64) e2ee.MonitorBroadcastContext {
		return e2ee.MonitorBroadcastContext{HubID: hub.HubID, OwnerID: ownerID,
			ClientDeviceID: deviceID, ClientSessionEpoch: 1, ClientKeyVersion: 1,
			ApprovalID: recovered.PreviewID, BroadcastID: recovered.BroadcastID,
			GroupID: group.ID, MonitorEndpointID: source.Endpoint.ID,
			MonitorKeyID:     sourceKey.Public().ID,
			MonitorBindingID: manifest.BindingID, MonitorBindingEpoch: manifest.BindingEpoch,
			BodySHA256: bodyDigest, RecipientSnapshotSHA256: recovered.SnapshotDigest,
			ExpiresAt: recovered.ExpiresAt, ConsentSHA256: recovered.Preview.ConsentSHA256,
			ConfirmRequestSequence: sequence}
	}
	badContext := buildContext(client.sequence + 2)
	badSealed, err := e2ee.SealMonitorBroadcast(deviceKey, sourceKey.Public(), badContext, body,
		badContext.ConfirmRequestSequence)
	if err != nil {
		t.Fatal(err)
	}
	confirmInput := map[string]any{"preview_id": recovered.PreviewID,
		"snapshot_digest": recovered.SnapshotDigest, "body_sha256": bodyDigest,
		"sealed_payload": badSealed}
	if _, outcome, _, _ := sendMonitorEncryptedHTTP(t, client, "monitor.broadcast_confirm", confirmInput); outcome.OK {
		t.Fatal("wrong outer confirm sequence accepted")
	}
	select {
	case <-wake:
		t.Fatal("failed confirm emitted Node wake")
	default:
	}
	context := buildContext(client.sequence + 1)
	sealed, err := e2ee.SealMonitorBroadcast(deviceKey, sourceKey.Public(), context, body,
		context.ConfirmRequestSequence)
	if err != nil {
		t.Fatal(err)
	}
	nodeDigest := sha256.Sum256([]byte(nodeToken))
	nodeCredentialDigest := base64.RawURLEncoding.EncodeToString(nodeDigest[:])
	wakeNotice := make(chan error, 1)
	go func() {
		select {
		case <-wake:
			// Read at wake observation time, before the HTTP caller receives
			// its response, to prove the hint follows the durable notice.
			notice, err := database.GetUserMonitorBroadcastV2Notification(nodeCredentialDigest, recovered.PreviewID)
			if err == nil && (notice == nil || notice.BroadcastID != recovered.BroadcastID) {
				err = fmt.Errorf("wake did not expose the durable Monitor notice")
			}
			wakeNotice <- err
		case <-time.After(5 * time.Second):
			wakeNotice <- fmt.Errorf("durable confirm did not emit generic Node wake")
		}
	}()
	confirmInput["sealed_payload"] = sealed
	_, confirmedOutcome, _, _ := sendMonitorEncryptedHTTP(t, client,
		"monitor.broadcast_confirm", confirmInput)
	confirmed := decodeMonitorHTTPResult(t, confirmedOutcome)
	var confirmedFields map[string]json.RawMessage
	if err := json.Unmarshal(confirmedOutcome.Result, &confirmedFields); err != nil {
		t.Fatal(err)
	}
	for _, privateOrRedundant := range []string{"preview", "snapshot", "sealed_payload"} {
		if _, found := confirmedFields[privateOrRedundant]; found {
			t.Fatalf("confirm response exposed %s", privateOrRedundant)
		}
	}
	if confirmed.Status != store.UserMonitorBroadcastV2Approved {
		t.Fatal("confirm did not durably approve", confirmed.Status)
	}
	if err := <-wakeNotice; err != nil {
		t.Fatal("wake preceded durable Node notice", err)
	}
	sessionDigest := sha256.Sum256([]byte(source.SessionToken))
	_, err = database.AuthorizeUserMonitorBroadcastV2Delivery(store.AuthorizeUserMonitorBroadcastV2Input{
		NodeCredentialDigest:    nodeCredentialDigest,
		SessionCredentialDigest: base64.RawURLEncoding.EncodeToString(sessionDigest[:]),
		PreviewID:               confirmed.PreviewID, BroadcastID: confirmed.BroadcastID,
		OperationID: "op_" + strings.TrimPrefix(confirmed.BroadcastID, "bc_"),
		BodyDigest:  bodyDigest, SnapshotDigest: confirmed.SnapshotDigest})
	if err != nil {
		t.Fatal("Node dispatch reservation failed", err)
	}
	_, statusOutcome, _, _ := sendMonitorEncryptedHTTP(t, client, "monitor.broadcast_status",
		map[string]string{"preview_id": confirmed.PreviewID})
	if !statusOutcome.OK {
		t.Fatal("outcome status unavailable", statusOutcome.Error)
	}
	var outcomeStatus store.UserMonitorBroadcastV2OutcomeStatus
	if err := json.Unmarshal(statusOutcome.Result, &outcomeStatus); err != nil {
		t.Fatal(err)
	}
	if outcomeStatus.ApprovalStatus != store.UserMonitorBroadcastV2DispatchAuthorized ||
		len(outcomeStatus.Recipients) != 1 || outcomeStatus.Recipients[0].State != store.UserMonitorBroadcastV2OutcomePending {
		t.Fatalf("recipient outcome did not follow durable dispatch: %+v", outcomeStatus)
	}
	device, err := database.GetClientDevice(ownerID, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RevokeClientDevice(ownerID, deviceID, device.Version); err != nil {
		t.Fatal(err)
	}
	status, _, _, _ = sendMonitorEncryptedHTTP(t, client, "monitor.broadcast_status",
		map[string]string{"preview_id": confirmed.PreviewID})
	if status == http.StatusOK {
		t.Fatal("revoked device used encrypted Monitor RPC")
	}
}
