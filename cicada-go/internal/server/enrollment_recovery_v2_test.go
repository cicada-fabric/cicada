package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

type enrollmentResponseDropper struct {
	header http.Header
	status int
}

func (w *enrollmentResponseDropper) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *enrollmentResponseDropper) WriteHeader(status int) { w.status = status }

func (w *enrollmentResponseDropper) Write([]byte) (int, error) {
	return 0, errors.New("simulated lost enrollment response")
}

func TestClientEnrollmentLostHTTPResponseRecoversAfterHubRestart(t *testing.T) {
	root := t.TempDir()
	config := control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		APIToken: "test-manager-token",
	}
	var manager *control.Control
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
	ownerID := manager.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(config.StateDir, "cicada.sqlite3")
	persistence, err := store.New(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		_ = persistence.Close()
		t.Fatal(err)
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		_ = persistence.Close()
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "android-phone", device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollmentBody, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "android-phone", "device_public_identity": device.Public(),
		"owner_device_grant": grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstHandler := NewHandler(manager)
	lostResponse := &enrollmentResponseDropper{}
	firstHandler.ServeHTTP(lostResponse, httptest.NewRequest(http.MethodPost,
		"/v2/client/devices/enroll", bytes.NewReader(enrollmentBody)))
	if lostResponse.status != http.StatusCreated {
		t.Fatalf("initial enrollment did not commit a created response before simulated loss: status=%d", lostResponse.status)
	}

	// The caller discarded the first response. Reopen the same persisted Hub
	// state, then retry the exact request bytes through a new HTTP Handler.
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
	secondHandler := NewHandler(manager)
	recovered := httptest.NewRecorder()
	secondHandler.ServeHTTP(recovered, httptest.NewRequest(http.MethodPost,
		"/v2/client/devices/enroll", bytes.NewReader(enrollmentBody)))
	if recovered.Code != http.StatusCreated {
		t.Fatalf("exact enrollment retry status=%d body=%s", recovered.Code, recovered.Body.String())
	}
	var response struct {
		OwnerID      string `json:"owner_id"`
		DeviceID     string `json:"device_id"`
		SessionEpoch uint64 `json:"session_epoch"`
		DeviceKeyVer uint64 `json:"device_key_version"`
		State        string `json:"state"`
	}
	if err := json.Unmarshal(recovered.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.OwnerID != ownerID || response.DeviceID != "android-phone" ||
		response.SessionEpoch != 1 || response.DeviceKeyVer != 1 || response.State != store.ClientDeviceActive {
		t.Fatalf("retry returned the wrong persisted device binding: %+v", response)
	}

	post := func(body []byte) *httptest.ResponseRecorder {
		t.Helper()
		result := httptest.NewRecorder()
		secondHandler.ServeHTTP(result, httptest.NewRequest(http.MethodPost,
			"/v2/client/devices/enroll", bytes.NewReader(body)))
		return result
	}
	newGrant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "android-phone", device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	changedGrantBody, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "android-phone", "device_public_identity": device.Public(),
		"owner_device_grant": newGrant,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rejected := post(changedGrantBody); rejected.Code != http.StatusForbidden {
		t.Fatalf("different owner grant was accepted as recovery: status=%d body=%s", rejected.Code, rejected.Body.String())
	}
	crossOwnerBody, err := json.Marshal(map[string]any{
		"owner_id": "another-owner", "owner_key_id": ownerKey.Public().ID,
		"device_id": "android-phone", "device_public_identity": device.Public(),
		"owner_device_grant": grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rejected := post(crossOwnerBody); rejected.Code != http.StatusForbidden {
		t.Fatalf("grant replayed across owners: status=%d body=%s", rejected.Code, rejected.Body.String())
	}
	otherDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	changedIdentityBody, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "android-phone", "device_public_identity": otherDevice.Public(),
		"owner_device_grant": grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rejected := post(changedIdentityBody); rejected.Code != http.StatusForbidden {
		t.Fatalf("changed device identity was accepted as recovery: status=%d body=%s", rejected.Code, rejected.Body.String())
	}
	wrongHubGrant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "android-phone", device.Public(), "another-hub",
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	wrongHubBody, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "android-phone", "device_public_identity": device.Public(),
		"owner_device_grant": wrongHubGrant,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rejected := post(wrongHubBody); rejected.Code != http.StatusForbidden {
		t.Fatalf("grant for another Hub was accepted as recovery: status=%d body=%s", rejected.Code, rejected.Body.String())
	}
	if _, err := manager.RevokeClientDevice(ownerID, "android-phone", 1); err != nil {
		t.Fatal(err)
	}
	if rejected := post(enrollmentBody); rejected.Code != http.StatusForbidden {
		t.Fatalf("revoked device recovered through HTTP enrollment: status=%d body=%s", rejected.Code, rejected.Body.String())
	}
}
