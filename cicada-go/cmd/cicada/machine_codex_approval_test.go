package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fakeApprovalCodex(t *testing.T, root string) (string, string) {
	t.Helper()
	path := filepath.Join(root, "codex")
	capture := filepath.Join(root, "codex-approval-result.json")
	// This is a protocol fixture. Real native Codex approval continuity must
	// be validated separately with an installed CLI and a live Worker.
	script := `#!/bin/sh
set -eu
test "$1" = app-server
test "$2" = --stdio
test -z "${CICADA_NODE_TOKEN:-}"
test -z "${CICADA_NODE_TOKEN_FILE:-}"
test -z "${CICADA_API_TOKEN:-}"
test -z "${CICADA_API_TOKEN_FILE:-}"
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*) printf '%s\n' '{"id":1,"result":{}}' ;;
    *'"method":"thread/start"'*) printf '%s\n' '{"id":2,"result":{"thread":{"id":"native-thread-a"}}}' ;;
    *'"method":"thread/resume"'*) printf '%s\n' '{"id":2,"result":{"thread":{"id":"native-thread-a"}}}' ;;
    *'"method":"turn/start"'*)
      printf '%s\n' '{"id":3,"result":{"turn":{"id":"native-turn-a","status":"inProgress"}}}'
      printf '%s\n' '{"id":77,"method":"item/commandExecution/requestApproval","params":{"threadId":"native-thread-a","turnId":"native-turn-a","itemId":"native-item-a","startedAtMs":1,"availableDecisions":["accept","decline"],"command":"echo approved"}}'
      ;;
    *'"id":77'* )
      printf '%s\n' "$line" > "$CICADA_TEST_APPROVAL_CAPTURE"
      case "$line" in
        *'"decision":"accept"'*)
          printf '%s\n' '{"method":"turn/completed","params":{"turn":{"status":"completed"},"item":{"type":"agentMessage","text":"APPROVED_DONE"}}}'
          ;;
        *)
          printf '%s\n' '{"method":"turn/completed","params":{"turn":{"status":"failed"}}}'
          ;;
      esac
      ;;
  esac
done
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path, capture
}

func TestRemoteCodexApprovalReturnsToOriginalAppServerTurn(t *testing.T) {
	root := t.TempDir()
	bin, capture := fakeApprovalCodex(t, root)
	t.Setenv("CICADA_CODEX_BIN", bin)
	t.Setenv("CICADA_TEST_APPROVAL_CAPTURE", capture)
	t.Setenv("CICADA_WORKSPACE_ROOT", root)
	t.Setenv("CICADA_API_TOKEN", "should-never-reach-child")
	t.Setenv("CICADA_NODE_TOKEN", "should-never-reach-child")
	job := machineJob{GoalID: "goal-a", WorkerID: "worker-a", MachineID: "node-a",
		Harness: "codex", Workspace: filepath.Join(root, "goal-a"), Attempt: 3,
		Prompt: "perform one approval-gated action"}
	var mu sync.Mutex
	var posts, polls int
	var firstID string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "CicadaNode node-secret" {
			t.Errorf("Node approval authorization=%q", got)
		}
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost && request.URL.Path == "/v2/relay/nodes/node-a/jobs/worker-a/approvals" {
			var input struct {
				Attempt   int            `json:"attempt"`
				RequestID string         `json:"request_id"`
				Method    string         `json:"method"`
				Request   map[string]any `json:"request"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.Attempt != 3 ||
				input.RequestID == "" || input.Method != "item/commandExecution/requestApproval" ||
				input.Request["threadId"] != "native-thread-a" || input.Request["turnId"] != "native-turn-a" {
				t.Errorf("invalid Node approval submission: %#v err=%v", input, err)
			}
			mu.Lock()
			posts++
			if firstID == "" {
				firstID = input.RequestID
			} else if firstID != input.RequestID {
				t.Errorf("retry changed Node approval request ID")
			}
			count := posts
			mu.Unlock()
			if count == 1 {
				response.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = response.Write([]byte(`{"approval_id":"approval-a","goal_id":"goal-a","worker_id":"worker-a","attempt":3,"status":"pending"}`))
			return
		}
		if request.Method == http.MethodGet && request.URL.Path == "/v2/relay/nodes/node-a/jobs/worker-a/approvals/approval-a" {
			if request.URL.Query().Get("attempt") != "3" || request.URL.Query().Get("wait_ms") != "20000" {
				t.Errorf("approval poll query=%s", request.URL.RawQuery)
			}
			mu.Lock()
			polls++
			count := polls
			mu.Unlock()
			if count == 1 {
				_, _ = response.Write([]byte(`{"approval_id":"approval-a","goal_id":"goal-a","worker_id":"worker-a","attempt":3,"status":"pending"}`))
			} else {
				_, _ = response.Write([]byte(`{"approval_id":"approval-a","goal_id":"goal-a","worker_id":"worker-a","attempt":3,"status":"resolved","decision":"accept"}`))
			}
			return
		}
		t.Errorf("unexpected Node approval route: %s %s", request.Method, request.URL.Path)
		response.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := executeMachineJobWithApproval(ctx, job, &machineApprovalBridge{
		BaseURL: server.URL, NodeID: "node-a", NodeToken: "node-secret"})
	if result.Status != "completed" || result.ThreadID != "native-thread-a" ||
		result.Summary != "APPROVED_DONE" {
		t.Fatalf("approval did not continue the same native turn: %#v", result)
	}
	mu.Lock()
	if posts != 2 || polls != 2 || firstID == "" {
		t.Errorf("approval retry/poll counts: posts=%d polls=%d request=%q", posts, polls, firstID)
	}
	mu.Unlock()
	data, err := os.ReadFile(capture)
	if err != nil || !strings.Contains(string(data), `"id":77`) ||
		!strings.Contains(string(data), `"decision":"accept"`) {
		t.Fatalf("native app-server approval reply missing: %s err=%v", data, err)
	}
}

func TestRemoteCodexApprovalRejectsStaleHubAttempt(t *testing.T) {
	root := t.TempDir()
	bin, capture := fakeApprovalCodex(t, root)
	t.Setenv("CICADA_CODEX_BIN", bin)
	t.Setenv("CICADA_TEST_APPROVAL_CAPTURE", capture)
	t.Setenv("CICADA_WORKSPACE_ROOT", root)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusConflict)
		_, _ = response.Write([]byte(`{"error":"stale Worker attempt"}`))
	}))
	defer server.Close()
	job := machineJob{GoalID: "goal-a", WorkerID: "worker-a", MachineID: "node-a",
		Harness: "codex", Workspace: filepath.Join(root, "goal-a"), Attempt: 3}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := executeMachineJobWithApproval(ctx, job, &machineApprovalBridge{
		BaseURL: server.URL, NodeID: "node-a", NodeToken: "node-secret"})
	if result.Status != "failed" || result.ThreadID != "native-thread-a" || result.Error == "" {
		t.Fatalf("stale approval did not fail closed: %#v", result)
	}
	data, err := os.ReadFile(capture)
	if err != nil || !strings.Contains(string(data), `"decision":"decline"`) {
		t.Fatalf("Codex did not receive explicit decline on stale approval: %s err=%v", data, err)
	}
}
