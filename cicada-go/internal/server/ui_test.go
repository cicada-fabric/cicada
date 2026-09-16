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

func TestEmbeddedClientAssets(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)

	tests := []struct {
		path        string
		contentType string
		contains    string
	}{
		{path: "/", contentType: "text/html", contains: "Ask Cicada"},
		{path: "/assets/app.css", contentType: "text/css", contains: ".stats"},
		{path: "/assets/app.js", contentType: "text/javascript", contains: "sessionStorage"},
		{path: "/assets/goal-detail.js", contentType: "text/javascript", contains: "artifacts"},
		{path: "/assets/attachments.js", contentType: "text/javascript", contains: "content_base64"},
		{path: "/assets/events.js", contentType: "text/javascript", contains: "EventSource"},
		{path: "/assets/push.js", contentType: "text/javascript", contains: "PushManager"},
		{path: "/manifest.webmanifest", contentType: "application/manifest+json", contains: "Cicada Control"},
		{path: "/sw.js", contentType: "text/javascript", contains: "cicada-static-v2"},
		{path: "/icon.svg", contentType: "image/svg+xml", contains: "#70d5ae"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if !strings.HasPrefix(response.Header().Get("Content-Type"), test.contentType) {
				t.Fatalf("content type=%q", response.Header().Get("Content-Type"))
			}
			if !strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("response does not contain %q", test.contains)
			}
			if response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("embedded client asset is missing nosniff")
			}
			if !strings.Contains(response.Header().Get("Content-Security-Policy"), "script-src 'self'") {
				t.Fatal("embedded client asset is missing its content security policy")
			}
		})
	}
}

func TestServiceWorkerDoesNotCachePrivateRoutes(t *testing.T) {
	data, err := clientFiles.ReadFile("ui/sw.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	if strings.Contains(script, "'/v1") || strings.Contains(script, "\"/v1") {
		t.Fatal("service worker must not cache Control API routes")
	}
	if !strings.Contains(script, "'/icon.svg'") {
		t.Fatal("service worker must cache the install icon")
	}
	if !strings.Contains(script, "addEventListener('push'") || !strings.Contains(script, "showNotification") {
		t.Fatal("service worker push delivery integration is missing")
	}
}

func TestClientIncludesProgressiveVoiceInput(t *testing.T) {
	data, err := clientFiles.ReadFile("ui/voice.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "SpeechRecognition") || !strings.Contains(string(data), "webkitSpeechRecognition") {
		t.Fatal("client voice input integration is missing")
	}
}

func TestClientIncludesPushSubscriptionIntegration(t *testing.T) {
	data, err := clientFiles.ReadFile("ui/push.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "pushManager.subscribe") || !strings.Contains(string(data), "/v1/notifications/push/subscriptions") {
		t.Fatal("client push subscription integration is missing")
	}
}

func TestEmbeddedClientBootstrapsWithAPITokenEnabled(t *testing.T) {
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

	for _, path := range []string{"/", "/assets/app.css", "/assets/app.js", "/assets/goal-detail.js", "/assets/attachments.js", "/assets/voice.js", "/assets/push.js", "/assets/events.js", "/manifest.webmanifest", "/sw.js", "/icon.svg"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("public client path %q status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/identity", nil)
	response := httptest.NewRecorder()
	response.Body.Reset()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("protected API status=%d body=%s", response.Code, response.Body.String())
	}
}
