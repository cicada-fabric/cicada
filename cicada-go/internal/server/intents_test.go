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
	"github.com/cicada-ai/cicada/internal/store"
)

func TestIntentEndpointReturnsDurableClarification(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)

	request := httptest.NewRequest(http.MethodPost, "/v1/intents", strings.NewReader(`{"text":"rerun it","kind":"command"}`))
	request.Header.Set("content-type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("intent status=%d body=%s", response.Code, response.Body.String())
	}
	var intent store.Intent
	if err := json.Unmarshal(response.Body.Bytes(), &intent); err != nil {
		t.Fatal(err)
	}
	if intent.Status != "needs_input" || !strings.Contains(intent.Question, "target_id") {
		t.Fatalf("unexpected clarification: %#v", intent)
	}

	get := httptest.NewRequest(http.MethodGet, "/v1/intents/"+intent.ID, nil)
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), "needs_input") {
		t.Fatalf("stored intent status=%d body=%s", getResponse.Code, getResponse.Body.String())
	}
}
