package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
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
	var hubKey *e2ee.Identity
	var binding nodewire.Binding
	var mu sync.Mutex
	var packets [][]byte
	var createCount, polls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/node/control/rpc" ||
			request.Header.Get("Authorization") != "CicadaNode synthetic-node-token" {
			t.Errorf("Node-Control request did not use the pinned RPC route and Node credential: %s %s auth=%q",
				request.Method, request.URL.Path, request.Header.Get("Authorization"))
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		packet, err := ioReadAllBounded(request)
		if err != nil {
			t.Errorf("read Node-Control request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		opened, err := nodewire.OpenRequest(hubKey, binding.NodeKey, binding, packet)
		if err != nil {
			t.Errorf("open sealed Node-Control request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		packets = append(packets, append([]byte(nil), packet...))
		packetCount := len(packets)
		mu.Unlock()
		if opened.Route.Operation == "node.approvals.create" {
			if packetCount == 1 {
				response.WriteHeader(http.StatusServiceUnavailable) // Simulate a lost create response.
				return
			}
			var input struct {
				WorkerID  string         `json:"worker_id"`
				Attempt   int            `json:"attempt"`
				RequestID string         `json:"request_id"`
				Method    string         `json:"method"`
				Request   map[string]any `json:"request"`
			}
			if err := decodeMachineNodeControlJSON(opened.Plaintext, &input); err != nil || input.WorkerID != "worker-a" ||
				input.Attempt != 3 || input.RequestID == "" || input.Method != "item/commandExecution/requestApproval" ||
				input.Request["threadId"] != "native-thread-a" || input.Request["turnId"] != "native-turn-a" {
				t.Errorf("invalid Node-Control approval submission: %#v err=%v", input, err)
			}
			mu.Lock()
			createCount++
			mu.Unlock()
			result := map[string]any{"approval_id": "approval-a", "goal_id": "goal-a",
				"worker_id": "worker-a", "attempt": 3, "status": "pending", "created": true}
			sealed, err := nodewire.SealResponse(hubKey, binding.NodeKey, binding,
				nodeControlTestResponseRoute(opened.Route), nodeControlTestEnvelope(t, opened.Route, true, result, ""))
			if err != nil {
				t.Errorf("seal approval create response: %v", err)
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write(sealed)
			return
		}
		if opened.Route.Operation == "node.approvals.status" {
			var input struct {
				WorkerID   string `json:"worker_id"`
				Attempt    int    `json:"attempt"`
				ApprovalID string `json:"approval_id"`
			}
			if err := decodeMachineNodeControlJSON(opened.Plaintext, &input); err != nil ||
				input.WorkerID != "worker-a" || input.Attempt != 3 || input.ApprovalID != "approval-a" {
				t.Errorf("invalid Node-Control approval status request: %#v err=%v", input, err)
			}
			mu.Lock()
			polls++
			count := polls
			mu.Unlock()
			status, decision := "pending", ""
			if count > 1 {
				status, decision = "resolved", "accept"
			}
			result := map[string]any{"approval_id": "approval-a", "goal_id": "goal-a",
				"worker_id": "worker-a", "attempt": 3, "status": status, "decision": decision}
			sealed, err := nodewire.SealResponse(hubKey, binding.NodeKey, binding,
				nodeControlTestResponseRoute(opened.Route), nodeControlTestEnvelope(t, opened.Route, true, result, ""))
			if err != nil {
				t.Errorf("seal approval status response: %v", err)
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write(sealed)
			return
		}
		t.Errorf("unexpected sealed Node-Control operation: %s", opened.Route.Operation)
		response.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	_, ctx, hubKey, binding := newMachineNodeControlRecoveryFixture(t, server.URL)
	root := t.TempDir()
	bin, capture := fakeApprovalCodex(t, root)
	t.Setenv("CICADA_CODEX_BIN", bin)
	t.Setenv("CICADA_TEST_APPROVAL_CAPTURE", capture)
	t.Setenv("CICADA_WORKSPACE_ROOT", root)
	t.Setenv("CICADA_API_TOKEN", "should-never-reach-child")
	t.Setenv("CICADA_NODE_TOKEN", "should-never-reach-child")
	job := machineJob{GoalID: "goal-a", WorkerID: "worker-a", MachineID: "node-recovery-test",
		Harness: "codex", Workspace: filepath.Join(root, "goal-a"), Attempt: 3,
		Prompt: "perform one approval-gated action", executionID: "execution-approval",
		providerID: "codex", leaseID: "lease-approval"}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := executeMachineJobWithApproval(ctx, job, &machineApprovalBridge{
		BaseURL: server.URL, NodeID: "node-recovery-test", NodeToken: "synthetic-node-token"})
	if result.Status != "completed" || result.ThreadID != "native-thread-a" || result.Summary != "APPROVED_DONE" {
		t.Fatalf("Node-Control approval did not resume the original native turn: %#v", result)
	}
	mu.Lock()
	if createCount != 1 || polls != 2 || len(packets) != 4 || !bytes.Equal(packets[0], packets[1]) {
		t.Errorf("sealed approval retry/poll state: creates=%d polls=%d packets=%d exact_retry=%v",
			createCount, polls, len(packets), len(packets) >= 2 && bytes.Equal(packets[0], packets[1]))
	}
	mu.Unlock()
	data, err := os.ReadFile(capture)
	if err != nil || !strings.Contains(string(data), `"id":77`) ||
		!strings.Contains(string(data), `"decision":"accept"`) {
		t.Fatalf("native app-server approval reply was not delivered to its request: %s err=%v", data, err)
	}
}

func TestRemoteCodexApprovalRejectsStaleHubAttempt(t *testing.T) {
	var hubKey *e2ee.Identity
	var binding nodewire.Binding
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/node/control/rpc" ||
			request.Header.Get("Authorization") != "CicadaNode synthetic-node-token" {
			t.Errorf("stale approval used the wrong Node-Control route/credential: %s %s auth=%q",
				request.Method, request.URL.Path, request.Header.Get("Authorization"))
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		packet, err := ioReadAllBounded(request)
		if err != nil {
			t.Errorf("read sealed stale approval request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		opened, err := nodewire.OpenRequest(hubKey, binding.NodeKey, binding, packet)
		if err != nil || opened.Route.Operation != "node.approvals.create" {
			t.Errorf("stale test did not receive the sealed approval create: route=%#v err=%v", opened.Route, err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		var input struct {
			WorkerID  string         `json:"worker_id"`
			Attempt   int            `json:"attempt"`
			RequestID string         `json:"request_id"`
			Method    string         `json:"method"`
			Request   map[string]any `json:"request"`
		}
		if err := decodeMachineNodeControlJSON(opened.Plaintext, &input); err != nil ||
			input.WorkerID != "worker-a" || input.Attempt != 3 || input.RequestID == "" ||
			input.Method != "item/commandExecution/requestApproval" ||
			input.Request["threadId"] != "native-thread-a" {
			t.Errorf("stale test received a different Worker claim: %#v err=%v", input, err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.WriteHeader(http.StatusConflict)
		_, _ = response.Write([]byte(`{"error":"stale Worker attempt"}`))
	}))
	defer server.Close()
	_, ctx, hubKey, binding := newMachineNodeControlRecoveryFixture(t, server.URL)
	root := t.TempDir()
	bin, capture := fakeApprovalCodex(t, root)
	t.Setenv("CICADA_CODEX_BIN", bin)
	t.Setenv("CICADA_TEST_APPROVAL_CAPTURE", capture)
	t.Setenv("CICADA_WORKSPACE_ROOT", root)
	job := machineJob{GoalID: "goal-a", WorkerID: "worker-a", MachineID: "node-recovery-test",
		Harness: "codex", Workspace: filepath.Join(root, "goal-a"), ThreadID: "native-thread-a", Attempt: 3,
		Prompt: "reject stale approval", executionID: "execution-stale-approval",
		providerID: "codex", leaseID: "lease-stale-approval"}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := executeMachineJobWithApproval(ctx, job, &machineApprovalBridge{
		BaseURL: server.URL, NodeID: "node-recovery-test", NodeToken: "synthetic-node-token"})
	if result.Status != "failed" || result.ThreadID != "native-thread-a" || result.Error == "" {
		t.Fatalf("stale approval did not fail closed: %#v", result)
	}
	data, err := os.ReadFile(capture)
	if err != nil || !strings.Contains(string(data), `"decision":"decline"`) {
		t.Fatalf("Codex did not receive explicit decline on stale approval: %s err=%v", data, err)
	}
}

func TestMachineApprovalStateDecodesNodeControlCreateAndStatusDTOs(t *testing.T) {
	job := machineJob{GoalID: "goal-a", WorkerID: "worker-a", Attempt: 4}
	cases := []struct {
		name string
		body string
		want machineApprovalState
	}{
		{
			name: "created response includes creation result",
			body: `{"approval_id":"approval-a","goal_id":"goal-a","worker_id":"worker-a","attempt":4,"status":"pending","decision":"","created":true}`,
			want: machineApprovalState{ApprovalID: "approval-a", GoalID: "goal-a", WorkerID: "worker-a",
				Attempt: 4, Status: "pending", Created: true},
		},
		{
			name: "status response omits creation result",
			body: `{"approval_id":"approval-a","goal_id":"goal-a","worker_id":"worker-a","attempt":4,"status":"resolved","decision":"accept"}`,
			want: machineApprovalState{ApprovalID: "approval-a", GoalID: "goal-a", WorkerID: "worker-a",
				Attempt: 4, Status: "resolved", Decision: "accept"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var got machineApprovalState
			if err := decodeMachineNodeControlJSON([]byte(test.body), &got); err != nil {
				t.Fatalf("decode production Node-Control DTO: %v", err)
			}
			if got != test.want {
				t.Fatalf("decoded DTO=%#v want=%#v", got, test.want)
			}
			if err := validateMachineApprovalState(got, job); err != nil {
				t.Fatalf("validate production Node-Control DTO: %v", err)
			}
		})
	}
	var unknown machineApprovalState
	if err := decodeMachineNodeControlJSON([]byte(`{"approval_id":"approval-a","goal_id":"goal-a","worker_id":"worker-a","attempt":4,"status":"pending","new_field":"unreviewed"}`), &unknown); err == nil {
		t.Fatal("strict Node-Control approval decoder accepted an unknown field")
	}
}
