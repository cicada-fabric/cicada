package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestSignedConnectorWebhookIsDurable(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		WebhookSecret: "connector-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	payload := []byte(`{"subject":"hello"}`)
	mac := hmac.New(sha256.New, []byte("connector-secret"))
	_, _ = mac.Write(payload)
	request := httptest.NewRequest(http.MethodPost, "/v1/connectors/events", strings.NewReader(string(payload)))
	request.Header.Set("X-Cicada-Connector", "mail")
	request.Header.Set("X-Cicada-Event-ID", "mail-1")
	request.Header.Set("X-Cicada-Event-Type", "message.created")
	request.Header.Set("X-Cicada-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response := httptest.NewRecorder()
	NewHandler(controlPlane).ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("webhook status=%d body=%s", response.Code, response.Body.String())
	}
	list := httptest.NewRequest(http.MethodGet, "/v1/connectors/events?connector=mail", nil)
	listResponse := httptest.NewRecorder()
	NewHandler(controlPlane).ServeHTTP(listResponse, list)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), "mail-1") {
		t.Fatalf("webhook event missing from list: status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
}

func TestEmbeddedClientIsServed(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	NewHandler(controlPlane).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Cicada Control") {
		t.Fatalf("client was not served: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestSignedContactAnnouncementEndpoint(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/v1/identity/announcement", strings.NewReader(`{"label":"Alice"}`))
	request.Header.Set("content-type", "application/json")
	response := httptest.NewRecorder()
	NewHandler(controlPlane).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("announcement status=%d body=%s", response.Code, response.Body.String())
	}
	if _, label, err := e2ee.VerifyContactAnnouncement(response.Body.Bytes()); err != nil || label != "Alice" {
		t.Fatalf("invalid signed announcement body=%s err=%v label=%q", response.Body.String(), err, label)
	}
}

func TestPermissionAPIIsDurableAndDeletable(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	create := httptest.NewRequest(http.MethodPost, "/v1/permissions", strings.NewReader(`{"subject_type":"contact","subject_id":"contact_bob","action":"peer.message","effect":"deny"}`))
	create.Header.Set("content-type", "application/json")
	createdResponse := httptest.NewRecorder()
	handler.ServeHTTP(createdResponse, create)
	if createdResponse.Code != http.StatusOK {
		t.Fatalf("permission create status=%d body=%s", createdResponse.Code, createdResponse.Body.String())
	}
	var permission struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &permission); err != nil || permission.ID == "" {
		t.Fatalf("invalid permission response: %s err=%v", createdResponse.Body.String(), err)
	}
	list := httptest.NewRequest(http.MethodGet, "/v1/permissions?subject_type=contact&subject_id=contact_bob", nil)
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, list)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), permission.ID) {
		t.Fatalf("permission list missing created rule: status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	remove := httptest.NewRequest(http.MethodDelete, "/v1/permissions/"+permission.ID, nil)
	removeResponse := httptest.NewRecorder()
	handler.ServeHTTP(removeResponse, remove)
	if removeResponse.Code != http.StatusNoContent {
		t.Fatalf("permission delete status=%d body=%s", removeResponse.Code, removeResponse.Body.String())
	}
}

func TestConfiguredAPITokenProtectsControlRoutes(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		APIToken: "test-api-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	unauthorized := httptest.NewRequest(http.MethodGet, "/v1/machines", nil)
	unauthorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized API request status=%d body=%s", unauthorizedResponse.Code, unauthorizedResponse.Body.String())
	}
	wrong := httptest.NewRequest(http.MethodGet, "/v1/machines", nil)
	wrong.Header.Set("Authorization", "Bearer wrong")
	wrongResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongResponse, wrong)
	if wrongResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-token API request status=%d body=%s", wrongResponse.Code, wrongResponse.Body.String())
	}
	authorized := httptest.NewRequest(http.MethodGet, "/v1/machines", nil)
	authorized.Header.Set("Authorization", "Bearer test-api-token")
	authorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(authorizedResponse, authorized)
	if authorizedResponse.Code != http.StatusOK {
		t.Fatalf("authorized API request status=%d body=%s", authorizedResponse.Code, authorizedResponse.Body.String())
	}
	health := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, health)
	if healthResponse.Code != http.StatusOK {
		t.Fatalf("health probe should remain public: status=%d", healthResponse.Code)
	}
}
