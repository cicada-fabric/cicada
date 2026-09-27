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

func TestExternalEventClassifierRequiresDecisionMarker(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), WebhookSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	for _, sample := range []struct {
		id     string
		body   string
		status string
	}{
		{"classifier-ordinary", `{"text":"status update"}`, "classified"},
		{"classifier-action", `{"text":"please approve the deployment"}`, "action_required"},
	} {
		body := []byte(sample.body)
		mac := hmac.New(sha256.New, []byte("secret"))
		_, _ = mac.Write(body)
		receive := httptest.NewRequest(http.MethodPost, "/v1/connectors/events", strings.NewReader(sample.body))
		receive.Header.Set("X-Cicada-Connector", "mail")
		receive.Header.Set("X-Cicada-Event-ID", sample.id)
		receive.Header.Set("X-Cicada-Event-Type", "message.created")
		receive.Header.Set("X-Cicada-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		receiveResponse := httptest.NewRecorder()
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
		classify := httptest.NewRequest(http.MethodPost, "/v1/connectors/events/"+received.ID+"/classify", nil)
		classifyResponse := httptest.NewRecorder()
		handler.ServeHTTP(classifyResponse, classify)
		if classifyResponse.Code != http.StatusOK || !strings.Contains(classifyResponse.Body.String(), `"status":"`+sample.status+`"`) {
			t.Fatalf("classify status=%d body=%s", classifyResponse.Code, classifyResponse.Body.String())
		}
	}
}
