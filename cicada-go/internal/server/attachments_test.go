package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestAttachmentEndpointStoresAndReturnsMetadata(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	payload := `{"name":"photo.txt","mime_type":"text/plain","content_base64":"` + base64.StdEncoding.EncodeToString([]byte("photo")) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/attachments", strings.NewReader(payload))
	request.Header.Set("content-type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("attachment status=%d body=%s", response.Code, response.Body.String())
	}
	var attachment store.Attachment
	if err := json.Unmarshal(response.Body.Bytes(), &attachment); err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "/v1/attachments/"+attachment.ID, nil)
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), "photo.txt") {
		t.Fatalf("attachment lookup status=%d body=%s", getResponse.Code, getResponse.Body.String())
	}
}
