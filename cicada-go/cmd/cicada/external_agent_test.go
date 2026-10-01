package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/server"
)

func TestExternalAgentCompletesApprovedBrowserAction(t *testing.T) {
	root := t.TempDir()
	const managerToken = "synthetic-external-agent-manager-token"
	t.Setenv("CICADA_API_TOKEN", managerToken)
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		APIToken: managerToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	if _, err := controlPlane.RegisterMachine("browser-machine", "Browser machine", map[string]any{
		"harnesses": []string{"shell"},
	}, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := controlPlane.CreateGoal(control.GoalInput{
		Objective: "browser action test", MachineID: "browser-machine", Harness: "shell",
		Resources: map[string]any{"argv": []any{"/bin/true"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	workers, err := controlPlane.Workers()
	if err != nil || len(workers) != 1 {
		t.Fatalf("worker fixture failed: %#v err=%v", workers, err)
	}
	action, err := controlPlane.RequestExternalAction(control.ExternalActionInput{
		GoalID: goal.ID, WorkerID: workers[0].ID, Kind: "form_fill", Method: "POST",
		URL: "https://example.com/form", Payload: json.RawMessage(`{"field":"value"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	approvals, err := controlPlane.Approvals(true)
	if err != nil || len(approvals) != 1 {
		t.Fatalf("approval fixture failed: %#v err=%v", approvals, err)
	}
	if _, err := controlPlane.ResolveApproval(approvals[0].ID, "approve"); err != nil {
		t.Fatal(err)
	}

	runner := filepath.Join(root, "runner.sh")
	if err := os.WriteFile(runner, []byte("#!/bin/sh\nif [ -n \"$API_KEY\" ]; then exit 3; fi\ncat >/dev/null\nprintf '{\"ok\":true}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "profile")
	t.Setenv("CICADA_BROWSER_PROFILE_DIR", profile)
	controlHandler := server.NewHandler(controlPlane)
	api := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		recorded := httptest.NewRecorder()
		controlHandler.ServeHTTP(recorded, request)
		if recorded.Code >= http.StatusInternalServerError {
			t.Errorf("synthetic External Agent request %s %s returned %d: %s",
				request.Method, request.URL.Path, recorded.Code, strings.TrimSpace(recorded.Body.String()))
		}
		for name, values := range recorded.Header() {
			for _, value := range values {
				response.Header().Add(name, value)
			}
		}
		response.WriteHeader(recorded.Code)
		_, _ = response.Write(recorded.Body.Bytes())
	}))
	defer api.Close()
	if err := runExternalAgent([]string{"--once", "--control-url", api.URL, "--browser-bin", runner}); err != nil {
		t.Fatal(err)
	}
	completed, err := controlPlane.ExternalAction(action.ID)
	if err != nil || completed.Status != "completed" || string(completed.Result) != `{"ok":true}` {
		t.Fatalf("browser action did not complete: %#v err=%v", completed, err)
	}
	events, err := controlPlane.Events(goal.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, event := range events {
		seen[event.Type] = true
	}
	if !seen["ExternalActionClaimed"] || !seen["ExternalActionCompleted"] {
		t.Fatalf("missing browser audit events: %#v", events)
	}
}
