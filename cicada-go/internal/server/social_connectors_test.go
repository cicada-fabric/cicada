package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/connectors/social"
	"github.com/cicada-ai/cicada/internal/control"
)

func TestSocialConnectorRoutesNormalizeAndDeduplicate(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		ConnectorSecrets: map[string]string{"x": "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	body := []byte(`{"data":{"id":"tweet-1","text":"benchmark is ready","author_id":"alice"}}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/connectors/x", strings.NewReader(string(body)))
	request.Header.Set("X-Cicada-Signature", social.Signature("secret", body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"connector":"x"`) {
		t.Fatalf("x connector status=%d body=%s", response.Code, response.Body.String())
	}
	duplicate := httptest.NewRequest(http.MethodPost, "/v1/connectors/x", strings.NewReader(string(body)))
	duplicate.Header.Set("X-Cicada-Signature", social.Signature("secret", body))
	duplicateResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateResponse, duplicate)
	if duplicateResponse.Code != http.StatusAccepted || duplicateResponse.Body.String() != response.Body.String() {
		t.Fatalf("duplicate x event was not idempotent: first=%s duplicate=%s", response.Body, duplicateResponse.Body)
	}
}

func TestDiscordConnectorRoute(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		ConnectorSecrets: map[string]string{"discord": "discord-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	body := []byte(`{"data":{"id":"discord-1","content":"hello","author":{"id":"alice"}}}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/connectors/discord", strings.NewReader(string(body)))
	request.Header.Set("X-Cicada-Signature", social.Signature("discord-secret", body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"connector":"discord"`) {
		t.Fatalf("discord connector status=%d body=%s", response.Code, response.Body.String())
	}
}
