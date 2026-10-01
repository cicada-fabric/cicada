package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
)

func TestLegacyManagerAPIFailsClosedWhenBearerIsNotConfigured(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())

	const privateMarker = "private-manager-record-marker"
	if _, err := manager.CreateContact(privateMarker, manager.Identity()); err != nil {
		t.Fatalf("seed private contact: %v", err)
	}
	if _, err := manager.CreateGoal(control.GoalInput{Objective: privateMarker}); err != nil {
		t.Fatalf("seed private goal: %v", err)
	}
	handler := NewHandler(manager)

	for _, path := range []string{`/v1/goals`, `/v1/contacts`, `/v1/approvals?pending=false`, `/v2/management/endpoints`} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), privateMarker) {
			t.Fatalf("anonymous manager read %s: status=%d body=%s", path, response.Code, response.Body.String())
		}
	}

	before, err := manager.Goals()
	if err != nil {
		t.Fatal(err)
	}
	create := httptest.NewRequest(http.MethodPost, "/v1/goals", strings.NewReader(`{"objective":"must-not-be-created"}`))
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, create)
	after, err := manager.Goals()
	if err != nil {
		t.Fatal(err)
	}
	if createResponse.Code != http.StatusServiceUnavailable || len(after) != len(before) {
		t.Fatalf("anonymous manager write was not rejected before mutation: status=%d before=%d after=%d body=%s",
			createResponse.Code, len(before), len(after), createResponse.Body.String())
	}

	oldJoin := httptest.NewRequest(http.MethodPost, "/v2/fabric/join", strings.NewReader(`{"group_id":"forged","native_session_id":"model-supplied"}`))
	oldJoinResponse := httptest.NewRecorder()
	handler.ServeHTTP(oldJoinResponse, oldJoin)
	if oldJoinResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("legacy model-supplied Fabric join remained available: status=%d body=%s", oldJoinResponse.Code, oldJoinResponse.Body.String())
	}

	for _, tc := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodOptions, "/v1/goals", http.StatusNoContent},
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/", http.StatusOK},
		{http.MethodGet, "/assets/panel.js", http.StatusOK},
		{http.MethodGet, "/v2/client/capabilities", http.StatusOK},
		{http.MethodGet, "/v2/client/identity", http.StatusOK},
		{http.MethodGet, "/v2/client/rpc", http.StatusMethodNotAllowed},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
		if response.Code != tc.want || strings.Contains(response.Body.String(), privateMarker) {
			t.Fatalf("public/bootstrap route %s %s: status=%d want=%d body=%s", tc.method, tc.path, response.Code, tc.want, response.Body.String())
		}
		if tc.path == "/v2/client/capabilities" {
			var capabilities map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &capabilities); err != nil {
				t.Fatal(err)
			}
			if capabilities["legacy_management_api_available"] != false {
				t.Fatalf("capabilities advertised anonymous legacy Manager API: %#v", capabilities)
			}
		}
	}
}

func TestNodeAndArtifactSessionRoutesKeepTheirOwnAuthenticationBoundary(t *testing.T) {
	service, _, group, nodeToken, _ := newGuestNodeJoinFixture(t)
	handler := NewFabricHandler(service, "")
	body, err := json.Marshal(map[string]any{
		"group_id": group.ID, "endpoint_name": "node-without-manager-bearer",
		"harness": "codex", "native_session_id": "native-node-without-manager-bearer",
	})
	if err != nil {
		t.Fatal(err)
	}
	join := httptest.NewRequest(http.MethodPost, "/v2/fabric/node/join", bytes.NewReader(body))
	join.Header.Set("Authorization", "CicadaNode "+nodeToken)
	joinResponse := httptest.NewRecorder()
	handler.ServeHTTP(joinResponse, join)
	if joinResponse.Code != http.StatusCreated {
		t.Fatalf("authenticated Node join depended on legacy Manager token: status=%d body=%s", joinResponse.Code, joinResponse.Body.String())
	}

	unauthenticatedArtifact := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticatedArtifact, httptest.NewRequest(http.MethodGet, "/v2/artifacts", nil))
	if unauthenticatedArtifact.Code != http.StatusUnauthorized {
		t.Fatalf("Artifact route did not apply its Session boundary: status=%d body=%s", unauthenticatedArtifact.Code, unauthenticatedArtifact.Body.String())
	}
	wrongSession := httptest.NewRequest(http.MethodGet, "/v2/artifacts", nil)
	wrongSession.Header.Set("Authorization", "Bearer "+nodeToken)
	wrongSessionResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongSessionResponse, wrongSession)
	if wrongSessionResponse.Code != http.StatusUnauthorized {
		t.Fatalf("Node credential crossed into Artifact Session API: status=%d body=%s", wrongSessionResponse.Code, wrongSessionResponse.Body.String())
	}
	if isLegacyManagerPath("/v2/fabric/node/join", http.MethodPost) || isLegacyManagerPath("/v2/client/rpc", http.MethodPost) ||
		isLegacyManagerPath("/v2/artifacts", http.MethodGet) || isLegacyManagerPath("/v2/relay/nodes/node-a/heartbeat", http.MethodPost) {
		t.Fatal("an independently authenticated Client, Node, Relay, or Artifact route entered the legacy Manager gate")
	}
	for _, path := range []string{"/v1/goals", "/v1/contacts", "/v1/approvals", "/v2/fabric/join"} {
		if !isLegacyManagerPath(path, http.MethodGet) {
			t.Fatalf("legacy data route %s escaped the empty-token gate", path)
		}
	}
}
