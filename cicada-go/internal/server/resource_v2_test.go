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

func TestManagedResourceHTTPExecutesOnlyCurrentFencedLease(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "manager-secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	group, err := manager.CreateGroup(control.GroupCreateInput{Name: "resource-test"})
	if err != nil {
		t.Fatal(err)
	}
	joined, err := manager.Fabric().Join(fabric.JoinInput{GroupID: group.ID, PrincipalName: "worker", EndpointName: "worker", Harness: "codex", NativeSessionID: "native-worker", NodeID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := manager.Fabric().Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	members, err := manager.GroupMembers(group.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, membership := range members {
		if membership.ID == actor.MembershipID {
			_, err = manager.BindMembershipRole(group.ID, membership.ID, "worker", membership.Version)
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	actor, err = manager.Fabric().Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	task, err := manager.CreateSharedTask(group.ID, store.SharedTask{Objective: "write bounded result", AcceptanceCriteria: "digest verification"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = manager.ReadySharedTask(group.ID, task.ID, task.Revision)
	if err != nil {
		t.Fatal(err)
	}
	task, err = manager.Fabric().ClaimTask(actor, fabric.TaskClaimInput{TaskID: task.ID, ExpectedRevision: task.Revision, IdempotencyKey: "claim-1"})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(manager)
	call := func(path, auth string, body any) *httptest.ResponseRecorder {
		t.Helper()
		encoded, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	acquireBody := store.ResourceLeaseRequest{ResourceID: "managed_blob/synthetic-result/write", GroupID: group.ID, TaskID: task.ID, PrincipalID: actor.PrincipalID}
	if got := call("/v1/resource-leases", "CicadaSession "+joined.SessionToken, acquireBody); got.Code != http.StatusUnauthorized {
		t.Fatalf("peer session acquired management lease: %d", got.Code)
	}
	created := call("/v1/resource-leases", "Bearer manager-secret", acquireBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("management acquire: %d %s", created.Code, created.Body.String())
	}
	var first store.ResourceLease
	if err = json.Unmarshal(created.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	path := "/v2/fabric/leases/" + first.ID + "/write-managed-blob"
	if got := call(path, "Bearer manager-secret", map[string]any{"fencing_epoch": first.FencingEpoch, "value": "first"}); got.Code != http.StatusUnauthorized {
		t.Fatalf("manager bearer impersonated peer writer: %d", got.Code)
	}
	if got := call(path, "CicadaSession "+joined.SessionToken, map[string]any{"fencing_epoch": first.FencingEpoch, "value": "first"}); got.Code != http.StatusOK {
		t.Fatalf("current write: %d %s", got.Code, got.Body.String())
	}
	if _, err = manager.Fabric().QuarantineResourceLease(actor, first.ID, first.FencingEpoch); err != nil {
		t.Fatal(err)
	}
	if err = manager.ReconcileResourceLease(first.ResourceID, first.FencingEpoch, true, "bounded managed write completed and no external process exists"); err != nil {
		t.Fatal(err)
	}
	second, err := manager.AcquireResourceLease(acquireBody)
	if err != nil {
		t.Fatal(err)
	}
	if got := call(path, "CicadaSession "+joined.SessionToken, map[string]any{"fencing_epoch": first.FencingEpoch, "value": "stale"}); got.Code != http.StatusConflict {
		t.Fatalf("stale executor wrote after new epoch: %d %s", got.Code, got.Body.String())
	}
	if got := call("/v2/fabric/leases/"+second.ID+"/write-managed-blob", "CicadaSession "+joined.SessionToken, map[string]any{"fencing_epoch": second.FencingEpoch, "value": "second"}); got.Code != http.StatusOK {
		t.Fatalf("new executor write: %d %s", got.Code, got.Body.String())
	}
}
