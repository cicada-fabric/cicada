package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

	receiverJoin := call(http.MethodPost, "/v2/fabric/join", "Bearer manager-only", map[string]any{
		"group_id": group.ID, "principal_name": "receiver", "endpoint_name": "receiver", "harness": "codex", "native_session_id": "native-receiver", "node_id": "node-b",
	})
	if receiverJoin.Code != http.StatusCreated {
		t.Fatalf("receiver join: %d %s", receiverJoin.Code, receiverJoin.Body.String())
	}
	var receiver fabric.JoinResult
	if err = json.Unmarshal(receiverJoin.Body.Bytes(), &receiver); err != nil {
		t.Fatal(err)
	}
	receiverActor, err := manager.Fabric().Authenticate(receiver.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	receiverMemberships, err := manager.GroupMembers(group.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, receiverMembership := range receiverMemberships {
		if receiverMembership.ID == receiverActor.MembershipID {
			if _, err = manager.BindMembershipRole(group.ID, receiverMembership.ID, "worker", receiverMembership.Version); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	receiverActor, err = manager.Fabric().Authenticate(receiver.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	taskOwnerActor, err := manager.Fabric().Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	historical, err := manager.Fabric().ProposeTaskHandoff(taskOwnerActor, fabric.TaskHandoffProposeInput{
		TaskID: won.ID, Target: receiver.Endpoint.ID, ExpectedRevision: won.Revision, OwnerEpoch: won.OwnerEpoch,
		PendingWork: "preserve this historical proposal",
	})
	if err != nil {
		t.Fatalf("prepare historical handoff row: %v", err)
	}
	retiredRoutes := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/v2/fabric/tasks/handoffs", map[string]any{"task_id": won.ID, "target": receiver.Endpoint.ID, "pending_work": "must never persist this prose"}},
		{http.MethodGet, "/v2/fabric/tasks/handoffs/" + historical.ID, nil},
		{http.MethodPost, "/v2/fabric/tasks/handoffs/" + historical.ID + "/accept", map[string]any{"lease_seconds": 300}},
	}
	for _, route := range retiredRoutes {
		response := call(route.method, route.path, "CicadaSession "+joined.SessionToken, route.body)
		if response.Code != http.StatusGone || !bytes.Contains(response.Body.Bytes(), []byte(retiredPeerTaskHandoffMessage)) ||
			bytes.Contains(response.Body.Bytes(), []byte("must never persist this prose")) {
			t.Fatalf("retired route %s %s was not a stable, non-echoing 410: %d %s", route.method, route.path, response.Code, response.Body.String())
		}
	}
	preserved, err := manager.Fabric().GetTaskHandoff(receiverActor, historical.ID)
	if err != nil || preserved.Status != store.HandoffProposed || preserved.PendingWork != "preserve this historical proposal" {
		t.Fatalf("retired compatibility routes changed historical proposal: %#v err=%v", preserved, err)
	}
	database, err := sql.Open("sqlite", filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var handoffCount int
	if err = database.QueryRow(`SELECT count(*) FROM shared_task_v2_handoffs WHERE task_id=?`, won.ID).Scan(&handoffCount); err != nil {
		t.Fatal(err)
	}
	if handoffCount != 1 {
		t.Fatalf("retired POST created or removed historical handoff rows: count=%d", handoffCount)
	}
	var after store.SharedTask
	afterResponse := call(http.MethodGet, "/v2/fabric/tasks/"+won.ID, "CicadaSession "+joined.SessionToken, nil)
	if afterResponse.Code != http.StatusOK || json.Unmarshal(afterResponse.Body.Bytes(), &after) != nil {
		t.Fatalf("read Task after retired routes: %d %s", afterResponse.Code, afterResponse.Body.String())
	}
	if after.Revision != won.Revision || after.Status != won.Status || after.OwnerEndpointID != won.OwnerEndpointID || after.OwnerEpoch != won.OwnerEpoch {
		t.Fatalf("retired routes changed Task responsibility: before=%#v after=%#v", won, after)
	}
	if _, err = manager.Fabric().AcceptTaskHandoff(taskOwnerActor, historical.ID, 300); !errors.Is(err, fabric.ErrNotFoundOrNotAuthorized) {
		t.Fatalf("test fixture handoff was not still awaiting its target: %v", err)
	}
}

func TestSharedTaskPeerManagementAssignmentRequiresConfiguredBearer(t *testing.T) {
	for _, token := range []string{"", "synthetic-manager-bearer"} {
		t.Run("configured-"+token, func(t *testing.T) {
			root := t.TempDir()
			manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: token})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Shutdown(context.Background())
			group, err := manager.CreateGroup(control.GroupCreateInput{Name: "synthetic privacy management"})
			if err != nil {
				t.Fatal(err)
			}
			task, err := manager.CreateSharedTask(group.ID, store.SharedTask{Objective: "legal management history", AcceptanceCriteria: "legal management criteria"})
			if err != nil {
				t.Fatal(err)
			}
			handler := NewHandler(manager)
			for _, path := range []string{"/v1/groups/" + group.ID + "/tasks/peer-shell", "/v1/groups/" + group.ID + "/tasks/" + task.ID + "/peer-assignment"} {
				for _, credential := range []string{"", "Bearer wrong-bearer", "CicadaSession synthetic-peer-credential"} {
					request := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{"publisher_endpoint_id":"untrusted","result_recipient_endpoint_id":"untrusted"}`))
					request.Header.Set("Authorization", credential)
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					want := http.StatusUnauthorized
					if token == "" {
						want = http.StatusServiceUnavailable
					}
					if response.Code != want {
						t.Fatalf("management guard: got %d want %d", response.Code, want)
					}
				}
			}
			tasks, err := manager.SharedTasks(group.ID, 100)
			if err != nil || len(tasks) != 1 || tasks[0].ID != task.ID || tasks[0].Revision != task.Revision || tasks[0].OwnerEpoch != task.OwnerEpoch || tasks[0].Objective != task.Objective || tasks[0].AcceptanceCriteria != task.AcceptanceCriteria {
				t.Fatal("denied assignment changed management Task history")
			}
		})
	}
}
