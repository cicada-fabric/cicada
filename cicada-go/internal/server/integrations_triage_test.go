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
)

func TestExternalEventTriageEndpoint(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), WebhookSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	payload := []byte(`{"text":"needs review"}`)
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write(payload)
	receive := httptest.NewRequest(http.MethodPost, "/v1/connectors/events", strings.NewReader(string(payload)))
	receive.Header.Set("X-Cicada-Connector", "mail")
	receive.Header.Set("X-Cicada-Event-ID", "mail:triage-1")
	receive.Header.Set("X-Cicada-Event-Type", "message.created")
	receive.Header.Set("X-Cicada-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	receiveResponse := httptest.NewRecorder()
	handler := NewHandler(controlPlane)
	handler.ServeHTTP(receiveResponse, receive)
	if receiveResponse.Code != http.StatusAccepted {
		t.Fatalf("receive status=%d body=%s", receiveResponse.Code, receiveResponse.Body.String())
	}
	var received struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(receiveResponse.Body.Bytes(), &received); err != nil {
		t.Fatal(err)
	}
	triage := httptest.NewRequest(http.MethodPost, "/v1/connectors/events/"+received.ID+"/triage", strings.NewReader(`{"status":"action_required"}`))
	triage.Header.Set("Content-Type", "application/json")
	triageResponse := httptest.NewRecorder()
	handler.ServeHTTP(triageResponse, triage)
	if triageResponse.Code != http.StatusOK || !strings.Contains(triageResponse.Body.String(), `"status":"action_required"`) {
		t.Fatalf("triage status=%d body=%s", triageResponse.Code, triageResponse.Body.String())
	}
}
