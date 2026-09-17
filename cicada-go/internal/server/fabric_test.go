package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestFabricHTTPJoinDirectoryAndRequestReply(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)

	join := func(name, session, machine string) store.Endpoint {
		t.Helper()
		body, _ := json.Marshal(control.EndpointJoinInput{
			Name: name, Harness: "codex", NativeSessionID: session, MachineID: machine,
			Workspace: "/work/project", Visibility: "fabric",
		})
		request := httptest.NewRequest(http.MethodPost, "/v1/endpoints", bytes.NewReader(body))
		request.Header.Set("content-type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusCreated {
			t.Fatalf("join status=%d body=%s", response.Code, response.Body.String())
		}
		var endpoint store.Endpoint
		if err := json.Unmarshal(response.Body.Bytes(), &endpoint); err != nil {
			t.Fatal(err)
		}
		return endpoint
	}
	planner := join("planner", "thread-planner", "gpu1")
	benchmark := join("benchmark", "thread-benchmark", "gpu2")

	directoryResponse := httptest.NewRecorder()
	handler.ServeHTTP(directoryResponse, httptest.NewRequest(http.MethodGet, "/v1/fabric/list?endpoint_id="+planner.ID, nil))
	if directoryResponse.Code != http.StatusOK || !bytes.Contains(directoryResponse.Body.Bytes(), []byte("benchmark@gpu2")) {
		t.Fatalf("directory status=%d body=%s", directoryResponse.Code, directoryResponse.Body.String())
	}
	if bytes.Contains(directoryResponse.Body.Bytes(), []byte("native_session_id")) || bytes.Contains(directoryResponse.Body.Bytes(), []byte("thread-benchmark")) {
		t.Fatalf("directory leaked native session routing data: %s", directoryResponse.Body.String())
	}
	askBody, _ := json.Marshal(control.FabricAskInput{FromEndpointID: planner.ID, Target: "benchmark", Question: "best result?"})
	askResponse := httptest.NewRecorder()
	handler.ServeHTTP(askResponse, httptest.NewRequest(http.MethodPost, "/v1/fabric/ask", bytes.NewReader(askBody)))
	if askResponse.Code != http.StatusAccepted {
		t.Fatalf("ask status=%d body=%s", askResponse.Code, askResponse.Body.String())
	}
	var ask store.FabricMessage
	if err := json.Unmarshal(askResponse.Body.Bytes(), &ask); err != nil || ask.RequestID == "" {
		t.Fatalf("invalid ask response=%s err=%v", askResponse.Body.String(), err)
	}
	claimResponse := httptest.NewRecorder()
	handler.ServeHTTP(claimResponse, httptest.NewRequest(http.MethodPost, "/v1/endpoints/"+benchmark.ID+"/messages", nil))
	if claimResponse.Code != http.StatusOK || !bytes.Contains(claimResponse.Body.Bytes(), []byte(ask.RequestID)) {
		t.Fatalf("claim status=%d body=%s", claimResponse.Code, claimResponse.Body.String())
	}
	replyBody, _ := json.Marshal(control.FabricReplyInput{FromEndpointID: benchmark.ID, RequestID: ask.RequestID, Message: "2.31 ms"})
	replyResponse := httptest.NewRecorder()
	handler.ServeHTTP(replyResponse, httptest.NewRequest(http.MethodPost, "/v1/fabric/reply", bytes.NewReader(replyBody)))
	if replyResponse.Code != http.StatusAccepted {
		t.Fatalf("reply status=%d body=%s", replyResponse.Code, replyResponse.Body.String())
	}
	plannerInbox := httptest.NewRecorder()
	handler.ServeHTTP(plannerInbox, httptest.NewRequest(http.MethodPost, "/v1/endpoints/"+planner.ID+"/messages", nil))
	if plannerInbox.Code != http.StatusOK || !bytes.Contains(plannerInbox.Body.Bytes(), []byte("2.31 ms")) {
		t.Fatalf("planner inbox status=%d body=%s", plannerInbox.Code, plannerInbox.Body.String())
	}
}

func TestFabricHTTPReturnsConflictForAmbiguousEndpoint(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	for _, machine := range []string{"gpu1", "gpu2"} {
		if _, err := controlPlane.JoinEndpoint(control.EndpointJoinInput{
			Name: "benchmark", Harness: "codex", NativeSessionID: "thread-" + machine,
			MachineID: machine, Visibility: "fabric",
		}); err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/fabric/resolve?q=benchmark", nil)
	response := httptest.NewRecorder()
	NewHandler(controlPlane).ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("ambiguous resolution status=%d body=%s", response.Code, response.Body.String())
	}
	var ambiguity struct {
		Candidates []string `json:"candidates"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &ambiguity); err != nil || len(ambiguity.Candidates) != 2 {
		t.Fatalf("ambiguous resolution did not return candidates: body=%s err=%v", response.Body.String(), err)
	}
	if bytes.Contains(response.Body.Bytes(), []byte("native_session_id")) || bytes.Contains(response.Body.Bytes(), []byte("thread-gpu")) {
		t.Fatalf("ambiguity response leaked native session routing data: %s", response.Body.String())
	}
}

func TestFabricHTTPListsEventHistoryWithCursor(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)

	body, _ := json.Marshal(control.EndpointJoinInput{
		Name: "planner", Harness: "codex", NativeSessionID: "thread-planner",
		MachineID: "gpu1", Workspace: "/work/project", Visibility: "fabric",
	})
	joinRequest := httptest.NewRequest(http.MethodPost, "/v1/endpoints", bytes.NewReader(body))
	joinRequest.Header.Set("content-type", "application/json")
	joinResponse := httptest.NewRecorder()
	handler.ServeHTTP(joinResponse, joinRequest)
	if joinResponse.Code != http.StatusCreated {
		t.Fatalf("join status=%d body=%s", joinResponse.Code, joinResponse.Body.String())
	}

	eventsResponse := httptest.NewRecorder()
	handler.ServeHTTP(eventsResponse, httptest.NewRequest(http.MethodGet, "/v1/fabric/events?limit=10", nil))
	if eventsResponse.Code != http.StatusOK || !bytes.Contains(eventsResponse.Body.Bytes(), []byte("EndpointJoined")) {
		t.Fatalf("events status=%d body=%s", eventsResponse.Code, eventsResponse.Body.String())
	}
	var payload struct {
		Events []store.FabricEvent `json:"events"`
	}
	if err := json.Unmarshal(eventsResponse.Body.Bytes(), &payload); err != nil || len(payload.Events) == 0 {
		t.Fatalf("invalid event response=%s err=%v", eventsResponse.Body.String(), err)
	}
	lastID := payload.Events[len(payload.Events)-1].ID
	cursorResponse := httptest.NewRecorder()
	handler.ServeHTTP(cursorResponse, httptest.NewRequest(http.MethodGet, "/v1/fabric/events?after="+strconv.FormatInt(lastID, 10), nil))
	if cursorResponse.Code != http.StatusOK || !bytes.Contains(cursorResponse.Body.Bytes(), []byte(`"events":[]`)) {
		t.Fatalf("cursor status=%d body=%s", cursorResponse.Code, cursorResponse.Body.String())
	}
}
