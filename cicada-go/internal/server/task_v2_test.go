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
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestSharedTaskManagementAndPeerClaimUseSeparateAuthorizedEntrypoints(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "manager-only"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	handler := NewHandler(manager)
	group, err := manager.CreateGroup(control.GroupCreateInput{Name: "tasks"})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, credential string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var payload []byte
		if body != nil {
			payload, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if credential != "" {
			req.Header.Set("Authorization", credential)
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	path := "/v1/groups/" + group.ID + "/tasks"
	createBody := map[string]any{"objective": "measure benchmark", "acceptance_criteria": "test log with digest"}
	if got := call(http.MethodPost, path, "", createBody); got.Code != http.StatusUnauthorized {
		t.Fatalf("unprotected Task create: %d", got.Code)
	}
	created := call(http.MethodPost, path, "Bearer manager-only", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var task store.SharedTask
	if err = json.Unmarshal(created.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	ready := call(http.MethodPost, path+"/"+task.ID+"/ready", "Bearer manager-only", map[string]any{"expected_revision": task.Revision})
	if ready.Code != http.StatusOK {
		t.Fatalf("ready: %d %s", ready.Code, ready.Body.String())
	}
	if err = json.Unmarshal(ready.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	join := call(http.MethodPost, "/v2/fabric/join", "Bearer manager-only", map[string]any{
		"group_id": group.ID, "principal_name": "worker", "endpoint_name": "worker", "harness": "codex", "native_session_id": "native-worker", "node_id": "node-a",
	})
	if join.Code != http.StatusCreated {
		t.Fatalf("join: %d %s", join.Code, join.Body.String())
	}
	var joined fabric.JoinResult
	if err = json.Unmarshal(join.Body.Bytes(), &joined); err != nil {
		t.Fatal(err)
	}
	actor, err := manager.Fabric().Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if got := call(http.MethodPost, "/v2/fabric/tasks/claim", "CicadaSession "+joined.SessionToken,
		map[string]any{"task_id": task.ID, "expected_revision": task.Revision, "idempotency_key": "claim-1"}); got.Code != http.StatusForbidden {
		t.Fatalf("unbound member claimed: %d %s", got.Code, got.Body.String())
	}
	memberships, err := manager.GroupMembers(group.ID)
	if err != nil {
		t.Fatal(err)
	}
	var membership *store.Membership
	for i := range memberships {
		if memberships[i].ID == actor.MembershipID {
			membership = &memberships[i]
			break
		}
	}
	if membership == nil {
		t.Fatal("joined membership missing")
	}
	if _, err = manager.BindMembershipRole(group.ID, membership.ID, "worker", membership.Version); err != nil {
		t.Fatal(err)
	}
	forged := call(http.MethodPost, "/v2/fabric/tasks/claim", "CicadaSession "+joined.SessionToken,
		map[string]any{"task_id": task.ID, "expected_revision": task.Revision, "idempotency_key": "claim-1", "owner_endpoint_id": "forged"})
	if forged.Code != http.StatusBadRequest {
		t.Fatalf("forged Task identity accepted: %d %s", forged.Code, forged.Body.String())
	}
	claimed := call(http.MethodPost, "/v2/fabric/tasks/claim", "CicadaSession "+joined.SessionToken,
		map[string]any{"task_id": task.ID, "expected_revision": task.Revision, "idempotency_key": "claim-1"})
	if claimed.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", claimed.Code, claimed.Body.String())
	}
	var won store.SharedTask
	if err = json.Unmarshal(claimed.Body.Bytes(), &won); err != nil {
		t.Fatal(err)
	}
	if won.OwnerEndpointID != joined.Endpoint.ID || won.Status != store.SharedTaskClaimed {
		t.Fatalf("wrong claim owner: %#v", won)
	}
}
