package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
)

func TestPushSubscriptionAPIIsApprovalFreeButAuthenticated(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		APIToken: "token", PushVAPIDPublicKey: "public", PushVAPIDPrivateKey: "private", PushVAPIDSubject: "mailto:test@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	unauthorized := httptest.NewRequest(http.MethodGet, "/v1/notifications/push/config", nil)
	unauthorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized push config status=%d", unauthorizedResponse.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/notifications/push/config", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("push config status=%d body=%s", response.Code, response.Body.String())
	}
	var config map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if config["enabled"] != true || config["public_key"] != "public" {
		t.Fatalf("unexpected push config %#v", config)
	}
	if _, found := config["private_key"]; found {
		t.Fatal("push config leaked private key")
	}

	body := `{"endpoint":"https://push.example.test/sub","keys":{"p256dh":"p256dh","auth":"auth"}}`
	register := httptest.NewRequest(http.MethodPost, "/v1/notifications/push/subscriptions", strings.NewReader(body))
	register.Header.Set("Authorization", "Bearer token")
	register.Header.Set("Content-Type", "application/json")
	registerResponse := httptest.NewRecorder()
	handler.ServeHTTP(registerResponse, register)
	if registerResponse.Code != http.StatusCreated {
		t.Fatalf("push registration status=%d body=%s", registerResponse.Code, registerResponse.Body.String())
	}
}
