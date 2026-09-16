package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
)

func TestRemoteWorkerDispatchAPICompletesGoal(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	if _, err := controlPlane.RegisterMachine("remote-test", "Remote test", map[string]any{"harnesses": []string{"shell"}}, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := controlPlane.CreateGoal(control.GoalInput{
		Objective: "run on the remote machine", MachineID: "remote-test", Harness: "shell",
		Resources: map[string]any{"argv": []any{"/usr/bin/printf", "REMOTE_READY"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if goal.Worker == nil || goal.Worker.Status != "queued" {
		t.Fatalf("remote worker was not queued: %#v", goal.Worker)
	}
	additional, err := controlPlane.AddWorker(goal.ID, control.WorkerInput{
		MachineID: "remote-test", Harness: "shell", Prompt: "custom remote branch prompt",
	})
	if err != nil {
		t.Fatal(err)
	}
	additionalJobs, err := controlPlane.MachineJobs("remote-test")
	if err != nil {
		t.Fatal(err)
	}
	foundCustomPrompt := false
	for _, job := range additionalJobs {
		if job.WorkerID == additional.ID && job.Prompt == "custom remote branch prompt" {
			foundCustomPrompt = true
		}
	}
	if !foundCustomPrompt {
		t.Fatalf("remote worker lost its custom prompt: %#v", additionalJobs)
	}
	if _, err := controlPlane.ClaimRemoteWorker(additional.ID, "remote-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.CompleteRemoteWorker(additional.ID, "remote-test", "completed", "CUSTOM_READY", "", ""); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(controlPlane)
	jobsResponse := httptest.NewRecorder()
	handler.ServeHTTP(jobsResponse, httptest.NewRequest(http.MethodGet, "/v1/machines/remote-test/jobs", nil))
	if jobsResponse.Code != http.StatusOK || !strings.Contains(jobsResponse.Body.String(), goal.Worker.ID) {
		t.Fatalf("jobs status=%d body=%s", jobsResponse.Code, jobsResponse.Body.String())
	}
	post := func(path string, payload any) *httptest.ResponseRecorder {
		body, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
		request.Header.Set("content-type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	claim := post("/v1/workers/"+goal.Worker.ID+"/claim", map[string]any{"machine_id": "remote-test"})
	if claim.Code != http.StatusOK || !strings.Contains(claim.Body.String(), `"attempt":1`) {
		t.Fatalf("claim status=%d body=%s", claim.Code, claim.Body.String())
	}
	duplicate := post("/v1/workers/"+goal.Worker.ID+"/claim", map[string]any{"machine_id": "remote-test"})
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate claim status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	result := post("/v1/workers/"+goal.Worker.ID+"/result", map[string]any{
		"machine_id": "remote-test", "status": "completed", "summary": "REMOTE_READY",
	})
	if result.Code != http.StatusOK {
		t.Fatalf("result status=%d body=%s", result.Code, result.Body.String())
	}
	completed, err := controlPlane.Goal(goal.ID)
	if err != nil || completed.Status != "completed" ||
		!strings.Contains(completed.Summary, "REMOTE_READY") || !strings.Contains(completed.Summary, "CUSTOM_READY") {
		t.Fatalf("remote result did not complete goal: %#v err=%v", completed, err)
	}
}
