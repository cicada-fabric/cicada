package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestClientRPCRecoveryDoesNotReplayBusinessOrSkipResponseSequence(t *testing.T) {
	root := t.TempDir()
	config := control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")}
	manager, err := control.New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if manager != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = manager.Shutdown(ctx)
		}
	})
	dbPath := filepath.Join(config.StateDir, "cicada.sqlite3")
	ownerID := manager.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	hubID, err := db.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "phone-recover", deviceKey.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "phone-recover", "device_public_identity": deviceKey.Public(), "owner_device_grant": grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(manager)
	post := func(path string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
		return result
	}
	if result := post("/v2/client/devices/enroll", enrollment); result.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", result.Code, result.Body.String())
	}
	binding := clientwire.Binding{HubID: hubID, OwnerID: ownerID, DeviceID: "phone-recover",
		SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	hubPublic := manager.ClientControlPublicIdentity()
	seal := func(seq uint64, operationID string) ([]byte, clientwire.Route) {
		t.Helper()
		route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
			HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
			SessionEpoch: binding.SessionEpoch, Sequence: seq, OperationID: operationID,
			Operation: "session.capabilities", SenderKeyID: deviceKey.Public().ID,
			SenderKeyVersion: 1, ReceiverKeyID: hubPublic.ID, ReceiverKeyVersion: 1}
		packet, err := clientwire.SealRequest(deviceKey, hubPublic, binding, route, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		return packet, route
	}
	firstPacket, _ := seal(1, "op-first")
	first := post("/v2/client/rpc", firstPacket)
	if first.Code != http.StatusOK {
		t.Fatalf("initial RPC status=%d body=%s", first.Code, first.Body.String())
	}
	completed := post("/v2/client/rpc/recover", firstPacket)
	if completed.Code != http.StatusOK || !bytes.Equal(completed.Body.Bytes(), first.Body.Bytes()) {
		t.Fatalf("completed recovery changed cached response: status=%d", completed.Code)
	}

	// Simulate a process crash after durable request acceptance and response
	// sequence reservation, but before sealing and caching the response.
	secondPacket, secondRoute := seal(2, "op-interrupted")
	digest := sha256.Sum256(secondPacket)
	requestBinding := store.AcceptClientRequestInput{OwnerID: ownerID, DeviceID: binding.DeviceID,
		SessionEpoch: binding.SessionEpoch, Sequence: secondRoute.Sequence,
		OperationID: secondRoute.OperationID, CiphertextDigest: hex.EncodeToString(digest[:])}
	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := db.AcceptClientRequest(requestBinding)
	if err != nil || accepted.Outcome != store.ClientRequestOutcomeNew {
		t.Fatalf("durable acceptance=%+v err=%v", accepted, err)
	}
	if accepted.Request.Status != store.ClientRequestProcessing {
		t.Fatalf("newly accepted request status=%q, want PROCESSING", accepted.Request.Status)
	}
	deviceBeforeProcessingRecovery, err := db.GetClientDevice(ownerID, binding.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	stillProcessing := post("/v2/client/rpc/recover", secondPacket)
	var stillProcessingBody struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(stillProcessing.Body.Bytes(), &stillProcessingBody); err != nil ||
		stillProcessing.Code != http.StatusConflict || stillProcessingBody.Code != "STILL_PROCESSING" {
		t.Fatalf("processing recovery status=%d body=%s err=%v", stillProcessing.Code, stillProcessing.Body.String(), err)
	}
	processingState, err := manager.LookupClientControlRequestRecovery(requestBinding)
	if err != nil || processingState.Request.ID != accepted.Request.ID ||
		processingState.Request.Status != store.ClientRequestProcessing ||
		processingState.ReservedResponseSequence != 0 || len(processingState.RecoveryPacket) != 0 {
		t.Fatalf("processing recovery changed request state: recovery=%+v err=%v", processingState, err)
	}
	deviceAfterProcessingRecovery, err := db.GetClientDevice(ownerID, binding.DeviceID)
	if err != nil || deviceAfterProcessingRecovery.LastRequestSeq != deviceBeforeProcessingRecovery.LastRequestSeq ||
		deviceAfterProcessingRecovery.NextResponseSeq != deviceBeforeProcessingRecovery.NextResponseSeq {
		t.Fatalf("processing recovery changed replay counters: before=%+v after=%+v err=%v",
			deviceBeforeProcessingRecovery, deviceAfterProcessingRecovery, err)
	}
	reserved, err := db.ReserveClientRequestResponseSequence(requestBinding)
	if err != nil || reserved != 2 {
		t.Fatalf("durable response reservation=%d err=%v", reserved, err)
	}
	_ = db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := manager.Shutdown(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	manager = nil
	manager, err = control.New(config)
	if err != nil {
		t.Fatal(err)
	}
	handler = NewHandler(manager)
	processing := post("/v2/client/rpc", secondPacket)
	if processing.Code != http.StatusConflict {
		t.Fatalf("interrupted RPC was dispatched again: status=%d", processing.Code)
	}
	recovered := post("/v2/client/rpc/recover", secondPacket)
	if recovered.Code != http.StatusOK {
		t.Fatalf("recovery status=%d body=%s", recovered.Code, recovered.Body.String())
	}
	opened, err := clientwire.OpenResponse(deviceKey, hubPublic, binding, recovered.Body.Bytes())
	if err != nil || opened.Route.Sequence != reserved || opened.Route.OperationID != secondRoute.OperationID {
		t.Fatalf("recovery signed route=%+v err=%v", opened.Route, err)
	}
	var notice struct {
		OK        bool   `json:"ok"`
		ErrorCode string `json:"error_code"`
		Recovery  struct {
			State           string `json:"state"`
			RequestSequence uint64 `json:"request_sequence"`
		} `json:"recovery"`
	}
	if err := json.Unmarshal(opened.Plaintext, &notice); err != nil || notice.OK ||
		notice.ErrorCode != "OUTCOME_UNCERTAIN" || notice.Recovery.State != "UNCERTAIN" ||
		notice.Recovery.RequestSequence != 2 {
		t.Fatalf("wrong uncertainty notice: %+v err=%v", notice, err)
	}
	repeated := post("/v2/client/rpc/recover", secondPacket)
	if repeated.Code != http.StatusOK || !bytes.Equal(repeated.Body.Bytes(), recovered.Body.Bytes()) {
		t.Fatalf("recovery was not byte-for-byte idempotent: status=%d", repeated.Code)
	}
	forged, _ := seal(2, secondRoute.OperationID)
	if result := post("/v2/client/rpc/recover", forged); result.Code != http.StatusConflict {
		t.Fatalf("different ciphertext recovered as same request: status=%d", result.Code)
	}
	thirdPacket, _ := seal(3, "op-after-recovery")
	third := post("/v2/client/rpc", thirdPacket)
	if third.Code != http.StatusOK {
		t.Fatalf("next RPC status=%d body=%s", third.Code, third.Body.String())
	}
	openedThird, err := clientwire.OpenResponse(deviceKey, hubPublic, binding, third.Body.Bytes())
	if err != nil || openedThird.Route.Sequence != 3 {
		t.Fatalf("next RPC skipped response sequence: route=%+v err=%v", openedThird.Route, err)
	}

	// Reproduce a pre-v29 database: the accepted request row survives, but its
	// response-reservation table and migration marker do not. On upgrade the
	// request must be fenced as uncertain without inventing recovery metadata.
	legacyPacket, legacyRoute := seal(4, "op-legacy-interrupted")
	legacyDigest := sha256.Sum256(legacyPacket)
	legacyBinding := store.AcceptClientRequestInput{OwnerID: ownerID, DeviceID: binding.DeviceID,
		SessionEpoch: binding.SessionEpoch, Sequence: legacyRoute.Sequence,
		OperationID: legacyRoute.OperationID, CiphertextDigest: hex.EncodeToString(legacyDigest[:])}
	legacyAccepted, err := manager.AcceptClientControlRequest(legacyBinding)
	if err != nil || legacyAccepted.Outcome != store.ClientRequestOutcomeNew ||
		legacyAccepted.Request.Status != store.ClientRequestProcessing {
		t.Fatalf("legacy fixture acceptance=%+v err=%v", legacyAccepted, err)
	}
	legacyCountersBeforeUpgrade, err := manager.ClientDevice(ownerID, binding.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	if err := manager.Shutdown(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	manager = nil
	legacyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec(`DROP TABLE client_device_request_recovery_v2`); err != nil {
		_ = legacyDB.Close()
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec(`DELETE FROM schema_migrations_v2 WHERE version=29`); err != nil {
		_ = legacyDB.Close()
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}
	manager, err = control.New(config)
	if err != nil {
		t.Fatal(err)
	}
	handler = NewHandler(manager)
	legacyRecovery := post("/v2/client/rpc/recover", legacyPacket)
	var legacyRecoveryBody struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(legacyRecovery.Body.Bytes(), &legacyRecoveryBody); err != nil ||
		legacyRecovery.Code != http.StatusConflict || legacyRecoveryBody.Code != "RECOVERY_UNAVAILABLE" {
		t.Fatalf("legacy recovery status=%d body=%s err=%v", legacyRecovery.Code, legacyRecovery.Body.String(), err)
	}
	legacyState, err := manager.LookupClientControlRequestRecovery(legacyBinding)
	if err != nil || legacyState.Request.ID != legacyAccepted.Request.ID ||
		legacyState.Request.Status != store.ClientRequestUncertain || legacyState.Supported {
		t.Fatalf("legacy recovery changed or inferred request state: recovery=%+v err=%v", legacyState, err)
	}
	legacyCountersAfterRecovery, err := manager.ClientDevice(ownerID, binding.DeviceID)
	if err != nil || legacyCountersAfterRecovery.LastRequestSeq != legacyCountersBeforeUpgrade.LastRequestSeq ||
		legacyCountersAfterRecovery.NextResponseSeq != legacyCountersBeforeUpgrade.NextResponseSeq {
		t.Fatalf("legacy recovery changed durable replay counters: before=%+v after=%+v err=%v",
			legacyCountersBeforeUpgrade, legacyCountersAfterRecovery, err)
	}

	// Current device authority must still apply to cached recovery responses.
	device, err := manager.ClientDevice(ownerID, binding.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RevokeClientDevice(ownerID, binding.DeviceID, device.Version); err != nil {
		t.Fatal(err)
	}
	if result := post("/v2/client/rpc/recover", secondPacket); result.Code != http.StatusForbidden {
		t.Fatalf("revoked device accessed cached recovery: status=%d", result.Code)
	}
}
