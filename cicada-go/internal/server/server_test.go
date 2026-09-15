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
)

func TestEmbeddedClientIsServed(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	NewHandler(controlPlane).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Cicada Control") {
		t.Fatalf("client was not served: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestPermissionAPIIsDurableAndDeletable(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	create := httptest.NewRequest(http.MethodPost, "/v1/permissions", strings.NewReader(`{"subject_type":"contact","subject_id":"contact_bob","action":"peer.message","effect":"deny"}`))
	create.Header.Set("content-type", "application/json")
	createdResponse := httptest.NewRecorder()
	handler.ServeHTTP(createdResponse, create)
	if createdResponse.Code != http.StatusOK {
		t.Fatalf("permission create status=%d body=%s", createdResponse.Code, createdResponse.Body.String())
	}
	var permission struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &permission); err != nil || permission.ID == "" {
		t.Fatalf("invalid permission response: %s err=%v", createdResponse.Body.String(), err)
	}
	list := httptest.NewRequest(http.MethodGet, "/v1/permissions?subject_type=contact&subject_id=contact_bob", nil)
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, list)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), permission.ID) {
		t.Fatalf("permission list missing created rule: status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	remove := httptest.NewRequest(http.MethodDelete, "/v1/permissions/"+permission.ID, nil)
	removeResponse := httptest.NewRecorder()
	handler.ServeHTTP(removeResponse, remove)
	if removeResponse.Code != http.StatusNoContent {
		t.Fatalf("permission delete status=%d body=%s", removeResponse.Code, removeResponse.Body.String())
	}
}
