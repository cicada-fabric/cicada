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

func TestResourceLeaseReleaseHTTPGuardAndSuccessor(t *testing.T) {
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
	_, err = manager.Fabric().ClaimTask(actor, fabric.TaskClaimInput{TaskID: task.ID, ExpectedRevision: task.Revision, IdempotencyKey: "claim-1"})
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

	acquire := store.ResourceLeaseRequest{ResourceID: "managed_blob/http-release/write", GroupID: group.ID, TaskID: task.ID, PrincipalID: actor.PrincipalID, TTLSeconds: 300}
	first, err := manager.AcquireResourceLease(acquire)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v2/fabric/leases/" + first.ID + "/release"
	auth := "CicadaSession " + joined.SessionToken
	input := map[string]any{"fencing_epoch": first.FencingEpoch}
	for _, invalidAuth := range []string{"", "Bearer manager-secret"} {
		if got := call(path, invalidAuth, input); got.Code != http.StatusUnauthorized {
			t.Fatalf("non-peer release: %d", got.Code)
		}
	}
	if got := call(path, auth, map[string]any{"fencing_epoch": first.FencingEpoch, "stopped_confirmed": true}); got.Code != http.StatusBadRequest {
		t.Fatalf("unknown caller proof accepted: %d", got.Code)
	}
	if got := call(path, auth, map[string]any{"fencing_epoch": first.FencingEpoch + 1}); got.Code != http.StatusConflict {
		t.Fatalf("stale epoch: %d", got.Code)
	}
	releasedResponse := call(path, auth, input)
	if releasedResponse.Code != http.StatusOK {
		t.Fatalf("release: %d %s", releasedResponse.Code, releasedResponse.Body.String())
	}
	var released store.ResourceLease
	if err := json.Unmarshal(releasedResponse.Body.Bytes(), &released); err != nil {
		t.Fatal(err)
	}
	if released.State != store.LeaseReleased || released.FencingEpoch != first.FencingEpoch || released.ExpiresAt != first.ExpiresAt {
		t.Fatal("release changed deadline/epoch or failed terminal state")
	}
	retryResponse := call(path, auth, input)
	if retryResponse.Code != http.StatusOK || !bytes.Equal(retryResponse.Body.Bytes(), releasedResponse.Body.Bytes()) {
		t.Fatal("exact retry was not a no-op")
	}
	writePath := "/v2/fabric/leases/" + first.ID + "/write-managed-blob"
	if got := call(writePath, auth, map[string]any{"fencing_epoch": first.FencingEpoch, "value": "stale"}); got.Code != http.StatusConflict {
		t.Fatalf("released write: %d", got.Code)
	}
	next, err := manager.AcquireResourceLease(acquire)
	if err != nil || next.FencingEpoch != first.FencingEpoch+1 {
		t.Fatalf("next acquire: %v", err)
	}
	if got := call(path, auth, input); got.Code != http.StatusConflict {
		t.Fatalf("retry after reacquire: %d", got.Code)
	}
	if got := call("/v2/fabric/leases/"+next.ID+"/write-managed-blob", auth, map[string]any{"fencing_epoch": next.FencingEpoch, "value": "current"}); got.Code != http.StatusOK {
		t.Fatalf("current write: %d %s", got.Code, got.Body.String())
	}
	for _, resourceID := range []string{"machine/http-synthetic/gpu/0", "workspace/http-synthetic/write", "managed_blob/http-quarantined/write"} {
		request := acquire
		request.ResourceID = resourceID
		lease, err := manager.AcquireResourceLease(request)
		if err != nil {
			t.Fatal(err)
		}
		if lease.Enforcement == store.LeaseExecutorEnforced {
			if _, err = manager.Fabric().QuarantineResourceLease(actor, lease.ID, lease.FencingEpoch); err != nil {
				t.Fatal(err)
			}
		}
		if got := call("/v2/fabric/leases/"+lease.ID+"/release", auth, map[string]any{"fencing_epoch": lease.FencingEpoch}); got.Code != http.StatusConflict {
			t.Fatalf("unconfirmed %s release: %d", resourceID, got.Code)
		}
	}
	unbound, err := manager.Fabric().Join(fabric.JoinInput{GroupID: group.ID, PrincipalName: "unbound", EndpointName: "unbound", Harness: "codex", NativeSessionID: "unbound-native", NodeID: "unbound-node"})
	if err != nil {
		t.Fatal(err)
	}
	if got := call("/v2/fabric/leases/"+next.ID+"/release", "CicadaSession "+unbound.SessionToken, map[string]any{"fencing_epoch": next.FencingEpoch}); got.Code != http.StatusForbidden {
		t.Fatalf("unbound action grant: %d", got.Code)
	}
	current, err := manager.ResourceLease(next.ID)
	if err != nil || current.State != store.LeaseActive {
		t.Fatalf("denied actor changed current authority: %v", err)
	}
}
