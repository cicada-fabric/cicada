package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
)

func TestManualThreadSessionAndQueueAPI(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	argsFile := filepath.Join(root, "args")
	codex := filepath.Join(root, "fake-codex")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + "'" + strings.ReplaceAll(argsFile, "'", "'\\''") + "'\n"
	if err := os.WriteFile(codex, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: workspace, CodexBinary: codex,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	post := func(path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("content-type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := post("/v1/threads/sessions", `{"thread_id":"11111111-1111-4111-8111-111111111111","label":"A","workspace":"`+filepath.ToSlash(filepath.Join(workspace, "a"))+`"}`); response.Code != http.StatusCreated {
		t.Fatalf("register A status=%d body=%s", response.Code, response.Body.String())
	}
	if response := post("/v1/threads/sessions", `{"thread_id":"22222222-2222-4222-8222-222222222222","label":"B","workspace":"`+filepath.ToSlash(filepath.Join(workspace, "b"))+`"}`); response.Code != http.StatusCreated {
		t.Fatalf("register B status=%d body=%s", response.Code, response.Body.String())
	}
	queued := post("/v1/threads/queue", `{"from_thread_id":"11111111-1111-4111-8111-111111111111","to_thread_id":"22222222-2222-4222-8222-222222222222","message":"hello from A"}`)
	if queued.Code != http.StatusAccepted || !strings.Contains(queued.Body.String(), `"status":"delivered"`) {
		t.Fatalf("queue status=%d body=%s", queued.Code, queued.Body.String())
	}
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/threads/deliveries?limit=10", nil)
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), "hello from A") {
		t.Fatalf("delivery list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
}
