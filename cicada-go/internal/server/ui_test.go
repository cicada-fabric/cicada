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

	for _, path := range []string{"/", "/assets/app.css", "/assets/app.js", "/assets/goal-detail.js", "/assets/attachments.js"} {
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
