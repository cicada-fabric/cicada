package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestGroupManagementHTTPIsSeparateFromPeerFabric(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	handler := NewHandler(manager)

	create := httptest.NewRequest(http.MethodPost, "/v1/groups", bytes.NewBufferString(`{"name":"kernel","purpose":"test"}`))
	create.Header.Set("Content-Type", "application/json")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var group store.Group
	if err := json.Unmarshal(created.Body.Bytes(), &group); err != nil {
		t.Fatal(err)
	}
	if group.ID == "" {
		t.Fatal("group ID was not returned")
	}

	members := httptest.NewRequest(http.MethodGet, "/v1/groups/"+group.ID+"/members", nil)
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, members)
	if listed.Code != http.StatusOK {
		t.Fatalf("members status=%d body=%s", listed.Code, listed.Body.String())
	}
	var result struct {
		Memberships []store.Membership `json:"memberships"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Memberships) != 1 || result.Memberships[0].Role != "owner" {
		t.Fatalf("unexpected memberships: %#v", result.Memberships)
	}
}

func TestV2ManagementRoutesRequireBearerAndVersionedRoleBinding(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "management-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	handler := NewHandler(manager)

	unauthorized := httptest.NewRequest(http.MethodPost, "/v1/groups", bytes.NewBufferString(`{"name":"secure"}`))
	unauthorized.Header.Set("Content-Type", "application/json")
	unauthorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("management route bypassed bearer protection: status=%d body=%s", unauthorizedResponse.Code, unauthorizedResponse.Body.String())
	}

	group, err := manager.CreateGroup(control.GroupCreateInput{Name: "secure"})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := manager.AddGroupMember(group.ID, control.GroupMemberInput{Name: "monitor"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"role": "monitor", "version": membership.Version})
	roleRequest := httptest.NewRequest(http.MethodPost, "/v1/groups/"+group.ID+"/members/"+membership.ID+"/role", bytes.NewReader(body))
	roleRequest.Header.Set("Authorization", "Bearer management-token")
	roleRequest.Header.Set("Content-Type", "application/json")
	roleResponse := httptest.NewRecorder()
	handler.ServeHTTP(roleResponse, roleRequest)
	if roleResponse.Code != http.StatusOK || !bytes.Contains(roleResponse.Body.Bytes(), []byte(`"role":"monitor"`)) {
		t.Fatalf("role binding status=%d body=%s", roleResponse.Code, roleResponse.Body.String())
	}

	wrongScope := httptest.NewRequest(http.MethodPost, "/v1/groups/other-group/members/"+membership.ID+"/role", bytes.NewReader(body))
	wrongScope.Header.Set("Authorization", "Bearer management-token")
	wrongScope.Header.Set("Content-Type", "application/json")
	wrongScopeResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongScopeResponse, wrongScope)
	if wrongScopeResponse.Code < http.StatusBadRequest {
		t.Fatalf("membership from another group was accepted: status=%d body=%s", wrongScopeResponse.Code, wrongScopeResponse.Body.String())
	}

	cardRequest := httptest.NewRequest(http.MethodPost, "/v1/groups/"+group.ID+"/cards", bytes.NewBufferString(`{"version":1,"public_capabilities":["benchmark.read"]}`))
	cardRequest.Header.Set("Authorization", "Bearer management-token")
	cardRequest.Header.Set("Content-Type", "application/json")
	cardResponse := httptest.NewRecorder()
	handler.ServeHTTP(cardResponse, cardRequest)
	if cardResponse.Code != http.StatusCreated {
		t.Fatalf("group card route status=%d body=%s", cardResponse.Code, cardResponse.Body.String())
	}
}

func TestGroupParentManagementRequiresBearerAndVersion(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"),
		WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "management-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	handler := NewHandler(manager)
	parent, err := manager.CreateGroup(control.GroupCreateInput{Name: "parent"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := manager.CreateGroup(control.GroupCreateInput{Name: "child"})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/groups/" + child.ID + "/parent"
	body, _ := json.Marshal(map[string]any{"parent_group_id": parent.ID, "expected_version": child.Version})
	call := func(auth bool, input []byte) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPatch, path, bytes.NewReader(input))
		request.Header.Set("Content-Type", "application/json")
		if auth {
			request.Header.Set("Authorization", "Bearer management-token")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if got := call(false, body); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized parent edit status=%d", got.Code)
	}
	updated := call(true, body)
	if updated.Code != http.StatusOK {
		t.Fatalf("parent edit status=%d body=%s", updated.Code, updated.Body.String())
	}
	var result store.Group
	if err := json.Unmarshal(updated.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ParentGroupID != parent.ID || result.Version != child.Version+1 {
		t.Fatalf("unexpected updated topology: %#v", result)
	}
	if got := call(true, body); got.Code != http.StatusConflict {
		t.Fatalf("stale parent edit status=%d", got.Code)
	}
}
