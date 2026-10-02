package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestGroupManagementReadViewsShowTaskEvidenceAndUnknownReceipt(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "manager-read-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())

	source, err := manager.CreateGroup(control.GroupCreateInput{Name: "source", Purpose: "Build and verify the result"})
	if err != nil {
		t.Fatal(err)
	}
	target, err := manager.CreateGroup(control.GroupCreateInput{Name: "target", Purpose: "Review incoming work"})
	if err != nil {
		t.Fatal(err)
	}

	task, err := manager.CreateSharedTask(source.ID, store.SharedTask{Objective: "Measure throughput", AcceptanceCriteria: "Attach the raw run and summary"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = manager.ReadySharedTask(source.ID, task.ID, task.Revision)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := manager.Fabric().Join(fabric.JoinInput{
		GroupID: source.ID, PrincipalName: "test-worker", EndpointName: "test-worker",
		Harness: "codex", NativeSessionID: "native-test-worker", NodeID: "node-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := manager.Fabric().Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	memberships, err := manager.GroupMembers(source.ID)
	if err != nil {
		t.Fatal(err)
	}
	var workerMembership *store.Membership
	for i := range memberships {
		if memberships[i].ID == actor.MembershipID {
			workerMembership = &memberships[i]
			break
		}
	}
	if workerMembership == nil {
		t.Fatal("joined worker membership was not recorded")
	}
	if _, err := manager.BindMembershipRole(source.ID, workerMembership.ID, "worker", workerMembership.Version); err != nil {
		t.Fatal(err)
	}
	actor, err = manager.Fabric().Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := manager.Fabric().ClaimTask(actor, fabric.TaskClaimInput{
		TaskID: task.ID, ExpectedRevision: task.Revision, IdempotencyKey: "management-view-claim",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Plain peer submissions cannot populate the legitimate management view.
	if _, err = manager.Fabric().SubmitTaskResult(actor, fabric.TaskResultInput{
		TaskID: task.ID, ExpectedRevision: claimed.Revision, OwnerEpoch: claimed.OwnerEpoch,
		Summary: "unclassified peer summary", Evidence: []string{"synthetic"},
	}); !errors.Is(err, store.ErrSharedTaskPeerPlaintext) {
		t.Fatalf("plaintext peer submit: %v", err)
	}
	persistence, err := store.New(filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	// This fixture is an explicit trusted management write, not a peer API.
	result, err := persistence.SubmitSharedTaskResult(task.ID, actor.PrincipalID, actor.EndpointID,
		claimed.OwnerEpoch, claimed.Revision, "Throughput measured", []string{"artifact://run-17", "event://benchmark-17"})
	if err != nil {
		t.Fatal(err)
	}

	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	contract, err := persistence.CreateFederationContract(store.FederationContract{
		ID: "view-contract", SourceGroupID: source.ID, TargetGroupID: target.ID,
		Capability: "benchmark.review", Scopes: []string{"summary.read"}, State: store.FederationContractActive,
		ExpiresAt: expires, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceRep, err := persistence.CreateRepresentativeAssignment(store.RepresentativeAssignment{
		ID: "view-source-rep", GroupID: source.ID, PrincipalID: manager.Identity().ID, EndpointID: "endpoint-source-monitor",
		Scopes: []string{"summary.read"}, ContractID: contract.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	targetRep, err := persistence.CreateRepresentativeAssignment(store.RepresentativeAssignment{
		ID: "view-target-rep", GroupID: target.ID, PrincipalID: manager.Identity().ID, EndpointID: "endpoint-target-monitor",
		Scopes: []string{"summary.read"}, ContractID: contract.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	representativeRequest, err := persistence.CreateFederationRequest(store.FederationRequest{
		ID: "view-request", OriginRequestID: "origin-ask", SourceGroupID: source.ID, TargetGroupID: target.ID,
		SourceRepresentativeEndpointID: sourceRep.EndpointID, TargetRepresentativeEndpointID: targetRep.EndpointID,
		SourceRepresentativeAssignmentID: sourceRep.ID, TargetRepresentativeAssignmentID: targetRep.ID,
		OriginPrincipalID: manager.Identity().ID, Capability: contract.Capability, ContractID: contract.ID,
		Scopes: []string{"summary.read"}, ArtifactRefs: []string{"artifact://request-input"},
		EvidenceRefs: []string{"evidence://source-note"}, ProvenanceRefs: []string{"event://source-ask"},
		Deadline: expires, MaxHops: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(manager)
	call := func(method, path, authorization string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, nil)
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	taskBeforeRead, err := manager.SharedTasks(source.ID, 10)
	if err != nil || len(taskBeforeRead) != 1 {
		t.Fatalf("load task state before read: tasks=%#v err=%v", taskBeforeRead, err)
	}
	resultsPath := "/v1/groups/" + source.ID + "/tasks/results"
	if got := call(http.MethodGet, resultsPath, ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("task evidence view status without management auth=%d body=%s", got.Code, got.Body.String())
	}
	resultsResponse := call(http.MethodGet, resultsPath, "Bearer manager-read-token")
	if resultsResponse.Code != http.StatusOK {
		t.Fatalf("task evidence view status=%d body=%s", resultsResponse.Code, resultsResponse.Body.String())
	}
	var resultEnvelope map[string]json.RawMessage
	if err := json.Unmarshal(resultsResponse.Body.Bytes(), &resultEnvelope); err != nil {
		t.Fatal(err)
	}
	var resultView []store.SharedTaskResult
	if err := json.Unmarshal(resultEnvelope["results"], &resultView); err != nil {
		t.Fatal(err)
	}
	if len(resultView) != 1 || resultView[0].ID != result.ID ||
		resultView[0].Authority != "PENDING" || len(resultView[0].Evidence) != 2 {
		t.Fatalf("task evidence view lost authority or evidence references: %#v", resultView)
	}
	if got := call(http.MethodPost, resultsPath, "Bearer manager-read-token"); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("task results route is not read-only: status=%d body=%s", got.Code, got.Body.String())
	}
	taskAfterRead, err := manager.SharedTasks(source.ID, 10)
	if err != nil || len(taskAfterRead) != 1 || taskAfterRead[0].Revision != taskBeforeRead[0].Revision {
		t.Fatalf("read changed task state: before=%#v after=%#v err=%v", taskBeforeRead, taskAfterRead, err)
	}

	requestPath := "/v1/groups/" + source.ID + "/representative-requests"
	requestsResponse := call(http.MethodGet, requestPath, "Bearer manager-read-token")
	if requestsResponse.Code != http.StatusOK {
		t.Fatalf("representative request view status=%d body=%s", requestsResponse.Code, requestsResponse.Body.String())
	}
	var requestEnvelope map[string]json.RawMessage
	if err := json.Unmarshal(requestsResponse.Body.Bytes(), &requestEnvelope); err != nil {
		t.Fatal(err)
	}
	var requestItems []json.RawMessage
	if err := json.Unmarshal(requestEnvelope["requests"], &requestItems); err != nil {
		t.Fatal(err)
	}
	if len(requestItems) != 1 {
		t.Fatalf("expected one scoped representative request, got %#v", requestItems)
	}
	var visibleRequest store.FederationRequest
	if err := json.Unmarshal(requestItems[0], &visibleRequest); err != nil {
		t.Fatal(err)
	}
	var receiptState string
	var requestFields map[string]json.RawMessage
	if err := json.Unmarshal(requestItems[0], &requestFields); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(requestFields["receipt_state"], &receiptState); err != nil {
		t.Fatal(err)
	}
	if visibleRequest.ID != representativeRequest.ID || visibleRequest.State != store.FederationRequestPending ||
		receiptState != "UNKNOWN" || len(visibleRequest.EvidenceRefs) != 1 ||
		len(visibleRequest.ProvenanceRefs) != 1 || len(visibleRequest.ArtifactRefs) != 1 {
		t.Fatalf("representative view hid lifecycle, evidence, or receipt uncertainty: request=%#v receipt=%q", visibleRequest, receiptState)
	}
	incomingResponse := call(http.MethodGet, "/v1/groups/"+target.ID+"/representative-requests", "Bearer manager-read-token")
	if incomingResponse.Code != http.StatusOK {
		t.Fatalf("incoming representative request view status=%d body=%s", incomingResponse.Code, incomingResponse.Body.String())
	}
	var incomingEnvelope map[string]json.RawMessage
	if err := json.Unmarshal(incomingResponse.Body.Bytes(), &incomingEnvelope); err != nil {
		t.Fatal(err)
	}
	var incomingItems []json.RawMessage
	if err := json.Unmarshal(incomingEnvelope["requests"], &incomingItems); err != nil {
		t.Fatal(err)
	}
	if len(incomingItems) != 1 {
		t.Fatalf("target Group did not see its incoming request: %s", incomingResponse.Body.String())
	}
	if got := call(http.MethodPost, requestPath, "Bearer manager-read-token"); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("representative request route is not read-only: status=%d body=%s", got.Code, got.Body.String())
	}
}
