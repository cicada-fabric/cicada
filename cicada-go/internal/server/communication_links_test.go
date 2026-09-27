package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestLinkProposalCannotOpenPlaintextCrossGroupPath(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspaces"),
		APIToken: "manager-test-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	groupA, err := manager.CreateGroup(control.GroupCreateInput{Name: "A"})
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := manager.CreateGroup(control.GroupCreateInput{Name: "B"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := manager.Fabric().Join(fabric.JoinInput{GroupID: groupA.ID, PrincipalName: "A1",
		EndpointName: "A1", Harness: "codex", NativeSessionID: "native-a", NodeID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := manager.Fabric().Join(fabric.JoinInput{GroupID: groupB.ID, PrincipalName: "B1",
		EndpointName: "B1", Harness: "codex", NativeSessionID: "native-b", NodeID: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := manager.ClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	link, err := manager.ProposeCommunicationLink(control.CommunicationLinkProposalInput{
		SourceEndpointID: a.Endpoint.ID, SourceGroupID: groupA.ID,
		TargetEndpointID: b.Endpoint.ID, TargetGroupID: groupB.ID,
		Direction: "bidirectional", Actions: []string{"ask", "reply"},
		DataScopes: []string{"benchmark.public_result"}, TransportHubID: hubID,
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil || link.State != store.CommunicationLinkProposed {
		t.Fatalf("proposal failed or became routable: link=%#v err=%v", link, err)
	}
	handler := NewHandler(manager)
	call := func(method, path, auth string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", auth)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	for _, legacy := range []struct{ method, path string }{
		{http.MethodGet, "/v1/communication-links"},
		{http.MethodGet, "/v1/communication-links/" + link.ID},
		{http.MethodPost, "/v1/communication-links"},
		{http.MethodPost, "/v1/communication-links/" + link.ID + "/revoke"},
		{http.MethodPost, "/v1/communication-links/" + link.ID + "/approve"},
	} {
		response := call(legacy.method, legacy.path, "Bearer manager-test-token", []byte(`{}`))
		if response.Code != http.StatusNotFound {
			t.Fatalf("retired management Link route %s %s remained available: %d",
				legacy.method, legacy.path, response.Code)
		}
	}
	ask := call(http.MethodPost, "/v2/fabric/ask", "CicadaSession "+a.SessionToken,
		[]byte(`{"target":"`+b.Endpoint.ID+`","question":"private result?"}`))
	if ask.Code != http.StatusForbidden {
		t.Fatalf("unapproved Link opened plaintext cross-group peer path: %d %s", ask.Code, ask.Body.String())
	}
	revoked, err := manager.RevokeCommunicationLink(link.ID, link.Version, "scope changed")
	if err != nil || revoked.State != store.CommunicationLinkRevoked || revoked.Version != link.Version+1 {
		t.Fatalf("management revoke failed: link=%#v err=%v", revoked, err)
	}
}
