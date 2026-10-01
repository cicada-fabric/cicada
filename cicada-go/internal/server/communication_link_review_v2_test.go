package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/fabric"
)

func TestLinkReviewHTTPRequiresSelectedActiveSessionAndReviewerGrant(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"),
		WorkspaceRoot: filepath.Join(root, "workspaces"), APIToken: "review-http-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	group, err := manager.CreateGroup(control.GroupCreateInput{Name: "reviewer scope"})
	if err != nil {
		t.Fatal(err)
	}
	joined, err := manager.Fabric().Join(fabric.JoinInput{GroupID: group.ID,
		PrincipalName: "ordinary-member", EndpointName: "ordinary-member", Harness: "codex",
		NativeSessionID: "native-review-http", NodeID: "node-review-http"})
	if err != nil {
		t.Fatal(err)
	}
	// Build the HTTP surface with Fabric only: the review route must not depend
	// on the Control planner/reporting plane.
	handler := NewFabricHandler(manager.Fabric(), "review-http-test")
	callPath := func(auth, scope, path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if scope != "" {
			req.Header.Set("Cicada-Group-Scope", scope)
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	call := func(auth, scope string) *httptest.ResponseRecorder {
		return callPath(auth, scope, "/v2/fabric/link-reviews?limit=10")
	}
	if got := call("", group.ID); got.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous review queue request returned %d", got.Code)
	}
	if got := call("CicadaSession "+joined.SessionToken, group.ID); got.Code != http.StatusForbidden {
		t.Fatalf("member without link.review received queue access: %d %s", got.Code, got.Body.String())
	}
	if got := call("CicadaSession "+joined.SessionToken, "group_forged"); got.Code != http.StatusForbidden {
		t.Fatalf("session was allowed to select an unjoined Group: %d %s", got.Code, got.Body.String())
	}
	if got := callPath("CicadaSession "+joined.SessionToken, group.ID, "/v2/fabric/link-reviews?limit=101"); got.Code != http.StatusBadRequest {
		t.Fatalf("out-of-range review page limit was not rejected: %d %s", got.Code, got.Body.String())
	}
	if got := callPath("CicadaSession "+joined.SessionToken, group.ID,
		"/v2/fabric/link-reviews?limit=10&limit=11"); got.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous duplicate review query parameter was not rejected: %d %s", got.Code, got.Body.String())
	}
	managerReq := httptest.NewRequest(http.MethodGet, "/v1/goals", nil)
	managerReq.Header.Set("Authorization", "Bearer review-http-test")
	managerRes := httptest.NewRecorder()
	handler.ServeHTTP(managerRes, managerReq)
	if managerRes.Code != http.StatusServiceUnavailable {
		t.Fatalf("Fabric-only handler unexpectedly served Control management: %d %s", managerRes.Code, managerRes.Body.String())
	}
}
