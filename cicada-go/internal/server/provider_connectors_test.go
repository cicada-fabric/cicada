package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/connectors/calendar"
	"github.com/cicada-ai/cicada/internal/connectors/email"
	"github.com/cicada-ai/cicada/internal/control"
)

func TestEmailConnectorVerifiesRawAndStoresNormalizedPayload(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		ConnectorSecrets: map[string]string{"email": "email-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	raw := []byte(`{"message_id":"mail-1","subject":"hello","body":"private body","provider_token":"drop"}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/connectors/email", strings.NewReader(string(raw)))
	request.Header.Set("X-Cicada-Signature", email.Signature("email-secret", raw))
	response := httptest.NewRecorder()
	NewHandler(controlPlane).ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || strings.Contains(response.Body.String(), "provider_token") {
		t.Fatalf("email connector status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "drop") {
		t.Fatalf("provider credential leaked in response: %s", response.Body.String())
	}
}

func TestCalendarConnectorSupportsICSAndRejectsBadSignature(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		ConnectorSecrets: map[string]string{"calendar": "calendar-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	raw := []byte("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:event-1\r\nSUMMARY:Review\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	bad := httptest.NewRequest(http.MethodPost, "/v1/connectors/calendar", strings.NewReader(string(raw)))
	bad.Header.Set("X-Cicada-Signature", "sha256=bad")
	badResponse := httptest.NewRecorder()
	NewHandler(controlPlane).ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("bad calendar signature status=%d body=%s", badResponse.Code, badResponse.Body.String())
	}
	good := httptest.NewRequest(http.MethodPost, "/v1/connectors/calendar", strings.NewReader(string(raw)))
	good.Header.Set("X-Cicada-Signature", calendar.Signature("calendar-secret", raw))
	goodResponse := httptest.NewRecorder()
	NewHandler(controlPlane).ServeHTTP(goodResponse, good)
	if goodResponse.Code != http.StatusAccepted || !strings.Contains(goodResponse.Body.String(), "event-1") {
		t.Fatalf("calendar connector status=%d body=%s", goodResponse.Code, goodResponse.Body.String())
	}
}
