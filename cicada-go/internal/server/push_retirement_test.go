package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
)

func TestLegacyBrowserPushRoutesReturnGone(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		APIToken: "token",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)

	for _, test := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/notifications/push/config", ""},
		{http.MethodPost, "/v1/notifications/push/subscriptions", `{"endpoint":"https://push.example.test/synthetic","keys":{"p256dh":"synthetic","auth":"synthetic"}}`},
		{http.MethodDelete, "/v1/notifications/push/subscriptions/synthetic-id", ""},
		{http.MethodGet, "/v1/notifications/push/subscriptions/", ""},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusGone {
				t.Fatalf("legacy Push route status=%d body=%s, want 410", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "retired") {
				t.Fatalf("retired-route response has no migration hint: %s", response.Body.String())
			}
		})
	}

	unauthorized := httptest.NewRequest(http.MethodGet, "/v1/notifications/push/config", nil)
	unauthorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated legacy request status=%d, want existing bearer gate 401", unauthorizedResponse.Code)
	}
}
