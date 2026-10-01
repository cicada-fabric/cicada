package server

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
)

func TestEmbeddedHubPanelAssetsAndFailClosedCryptoBuild(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	for _, test := range []struct{ path, contentType, contains string }{
		{"/", "text/html", "CICADA Hub"},
		{"/assets/panel.css", "text/css", ".stage"},
		{"/assets/panel.js", "text/javascript", "fetchAndValidateHubIdentity"},
		{"/assets/panel-bootstrap.js", "text/javascript", "WebAssembly.instantiate"},
		{"/assets/panel-client.js", "text/javascript", "indexedDB"},
		{"/assets/panel-model.js", "text/javascript", "screenPointToWorld"},
		{"/assets/panel-canvas.js", "text/javascript", "installCanvasControls"},
		{"/assets/panel-canvas-controls.js", "text/javascript", "Shared Thread memory"},
		{"/assets/panel-dom.js", "text/javascript", "createElementNS"},
		{"/icon.svg", "image/svg+xml", "<svg"},
	} {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), test.contentType) ||
				!strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("status=%d content-type=%q body prefix=%q", response.Code, response.Header().Get("Content-Type"), response.Body.String()[:min(120, response.Body.Len())])
			}
			if response.Header().Get("X-Content-Type-Options") != "nosniff" ||
				response.Header().Get("Referrer-Policy") != "no-referrer" ||
				!strings.Contains(response.Header().Get("Content-Security-Policy"), "'wasm-unsafe-eval'") {
				t.Fatal("Hub panel response is missing the restrictive security headers")
			}
		})
	}
	for _, path := range []string{"/assets/panel.manifest.json", "/assets/wasm_exec.js", "/assets/cicada-webcrypto.wasm"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		_, assetErr := clientFiles.ReadFile(clientAssets[path].file)
		if errors.Is(assetErr, nil) {
			if response.Code != http.StatusOK {
				t.Fatalf("generated asset %q exists but status=%d", path, response.Code)
			}
		} else if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("missing generated asset %q returned %d, want fail-closed 503", path, response.Code)
		}
	}
}

func TestHubPanelDoesNotExposeOldBearerUIOrUnsafeDOMSinks(t *testing.T) {
	for _, path := range []string{"/assets/voice.js", "/assets/management.js", "/assets/push.js", "/sw.js", "/manifest.webmanifest"} {
		if isPublicClientPath(path) {
			t.Fatalf("obsolete panel route %q remains public", path)
		}
		response := httptest.NewRecorder()
		serveClient(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("obsolete panel route %q status=%d", path, response.Code)
		}
	}
	for _, path := range []string{"ui/panel.js", "ui/panel-bootstrap.js", "ui/panel-client.js", "ui/panel-model.js", "ui/panel-canvas.js", "ui/panel-canvas-controls.js", "ui/panel-dom.js"} {
		data, err := clientFiles.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		script := string(data)
		for _, forbidden := range []string{"innerHTML", "localStorage", "Authorization: Bearer", "/v1/"} {
			if strings.Contains(script, forbidden) {
				t.Fatalf("%s contains forbidden unsafe/legacy integration %q", path, forbidden)
			}
		}
	}
}

func TestHubPanelRelativeModuleImportsHavePublicRoutes(t *testing.T) {
	imports := regexp.MustCompile(`from\s+['"]\./([^'"]+)['"]`)
	for _, asset := range clientAssets {
		if !strings.HasPrefix(asset.file, "ui/") || !strings.HasSuffix(asset.file, ".js") {
			continue
		}
		source, err := clientFiles.ReadFile(asset.file)
		if err != nil {
			if strings.HasPrefix(asset.file, "ui/generated/") && errors.Is(err, fs.ErrNotExist) {
				// Generated assets are optional in a clean source checkout;
				// TestEmbeddedHubPanelAssetsAndFailClosedCryptoBuild checks their 503 response.
				continue
			}
			t.Fatalf("read module %q: %v", asset.file, err)
		}
		for _, match := range imports.FindAllSubmatch(source, -1) {
			path := "/assets/" + string(match[1])
			target, ok := clientAssets[path]
			if !ok {
				t.Fatalf("module %q imports %q without a Hub asset route", asset.file, path)
			}
			if _, err := clientFiles.ReadFile(target.file); err != nil {
				t.Fatalf("module %q imports unavailable asset %q: %v", asset.file, path, err)
			}
		}
	}
}

func TestHubPanelRemainsPublicWithManagementBearerConfigured(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "synthetic-panel-test-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	for _, path := range []string{"/", "/assets/panel.js", "/assets/panel-bootstrap.js", "/assets/panel-canvas.js",
		"/assets/panel-canvas-controls.js", "/assets/panel-dom.js"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("panel asset %q status=%d", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/identity", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("legacy Control API remains unprotected: %d", response.Code)
	}
}
