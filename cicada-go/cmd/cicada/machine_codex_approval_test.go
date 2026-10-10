package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/codexapp"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
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
      if [ "${CICADA_TEST_APPROVAL_BEFORE_TURN_RESPONSE:-}" = 1 ]; then
        printf '%s\n' '{"id":77,"method":"item/commandExecution/requestApproval","params":{"threadId":"native-thread-a","turnId":"native-turn-a","itemId":"native-item-a","startedAtMs":1,"availableDecisions":["accept","decline"],"command":"echo approved"}}'
      fi
      printf '%s\n' '{"id":3,"result":{"turn":{"id":"native-turn-a","items":[],"status":"inProgress"}}}'
      if [ "${CICADA_TEST_APPROVAL_BEFORE_TURN_RESPONSE:-}" != 1 ]; then
        printf '%s\n' '{"id":77,"method":"item/commandExecution/requestApproval","params":{"threadId":"native-thread-a","turnId":"native-turn-a","itemId":"native-item-a","startedAtMs":1,"availableDecisions":["accept","decline"],"command":"echo approved"}}'
      fi
      ;;
    *'"id":77'* )
      printf '%s\n' "$line" > "$CICADA_TEST_APPROVAL_CAPTURE"
      case "$line" in
        *'"decision":"accept"'*)
          printf '%s\n' '{"method":"turn/completed","params":{"threadId":"native-thread-a","turn":{"id":"native-turn-a","items":[{"type":"agentMessage","text":"APPROVED_DONE"}],"status":"completed"}}}'
          ;;
        *)
          printf '%s\n' '{"method":"turn/completed","params":{"threadId":"native-thread-a","turn":{"id":"native-turn-a","items":[],"status":"failed"}}}'
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

func machineApprovalDecisionFixture(t *testing.T) (machineApprovalBridge, context.Context, func() int) {
	t.Helper()
	var hubKey *e2ee.Identity
	var binding nodewire.Binding
	var callsMu sync.Mutex
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		if request.Method != http.MethodPost || request.URL.Path != "/v2/node/control/rpc" ||
			request.Header.Get("Authorization") != "CicadaNode synthetic-node-token" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		packet, err := ioReadAllBounded(request)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		opened, err := nodewire.OpenRequest(hubKey, binding.NodeKey, binding, packet)
		if err != nil || opened.Route.Operation != "node.approvals.create" {
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
			input.WorkerID != "worker-approval-test" || input.Attempt != 2 || input.RequestID == "" ||
			input.Method != "item/commandExecution/requestApproval" ||
			input.Request["threadId"] != "native-thread-a" || input.Request["turnId"] != "native-turn-a" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		result := machineApprovalState{ApprovalID: "approval-test", GoalID: "goal-approval-test",
			WorkerID: input.WorkerID, Attempt: input.Attempt, Status: "resolved", Decision: "accept"}
		envelope, err := json.Marshal(map[string]any{"ok": true, "operation_id": opened.Route.OperationID,
			"sequence": opened.Route.Sequence, "result": result})
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		sealed, err := nodewire.SealResponse(hubKey, binding.NodeKey, binding,
			nodeControlTestResponseRoute(opened.Route), envelope)
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(sealed)
	}))
	t.Cleanup(server.Close)
	_, ctx, hubKey, binding := newMachineNodeControlRecoveryFixture(t, server.URL)
	bridge := machineApprovalBridge{BaseURL: server.URL, NodeID: "node-recovery-test", NodeToken: "synthetic-node-token"}
	return bridge, ctx, func() int {
		callsMu.Lock()
		defer callsMu.Unlock()
		return calls
	}
}

func machineApprovalTestParams(threadID, turnID string) map[string]any {
	return map[string]any{"threadId": threadID, "turnId": turnID, "itemId": "native-item-test",
		"availableDecisions": []any{"accept", "decline"}}
}

type observedApprovalWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (ctx *observedApprovalWaitContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.entered) })
	return ctx.Context.Done()
}

type machineApprovalTestResult struct {
	decision string
	err      error
}

func TestMachineCodexApprovalRequiresConfirmedThreadAndTurn(t *testing.T) {
	bridge, ctx, calls := machineApprovalDecisionFixture(t)
	job := machineJob{GoalID: "goal-approval-test", WorkerID: "worker-approval-test", Attempt: 2}
	method := "item/commandExecution/requestApproval"
	cases := []struct {
		name     string
		identity *machineCodexApprovalIdentity
		params   map[string]any
	}{
		{
			name: "different thread",
			identity: func() *machineCodexApprovalIdentity {
				identity := newMachineCodexApprovalIdentity()
				_ = identity.confirmThread("native-thread-a")
				_ = identity.confirmTurn("native-turn-a")
				return identity
			}(),
			params: machineApprovalTestParams("native-thread-b", "native-turn-a"),
		},
		{
			name: "different turn",
			identity: func() *machineCodexApprovalIdentity {
				identity := newMachineCodexApprovalIdentity()
				_ = identity.confirmThread("native-thread-a")
				_ = identity.confirmTurn("native-turn-a")
				return identity
			}(),
			params: machineApprovalTestParams("native-thread-a", "native-turn-b"),
		},
		{
			name: "missing request turn",
			identity: func() *machineCodexApprovalIdentity {
				identity := newMachineCodexApprovalIdentity()
				_ = identity.confirmThread("native-thread-a")
				_ = identity.confirmTurn("native-turn-a")
				return identity
			}(),
			params: map[string]any{"threadId": "native-thread-a", "itemId": "native-item-test"},
		},
		{
			name: "unconfirmed turn",
			identity: func() *machineCodexApprovalIdentity {
				identity := newMachineCodexApprovalIdentity()
				_ = identity.confirmThread("native-thread-a")
				_ = identity.confirmTurn("")
				return identity
			}(),
			params: machineApprovalTestParams("native-thread-a", "native-turn-a"),
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			decision, err := machineCodexApprovalDecision(ctx, test.identity, bridge, job, 77, method, test.params)
			if err == nil || decision != "" {
				t.Fatalf("approval decision=%q err=%v, want rejection", decision, err)
			}
		})
	}
	if got := calls(); got != 0 {
		t.Fatalf("Hub was called %d times for unconfirmed or mismatched identity", got)
	}
}

func TestMachineCodexApprovalWaitsForTurnStartResponse(t *testing.T) {
	bridge, baseCtx, calls := machineApprovalDecisionFixture(t)
	identity := newMachineCodexApprovalIdentity()
	if err := identity.confirmThread("native-thread-a"); err != nil {
		t.Fatal("confirm synthetic Thread:", err)
	}
	ctx, cancel := context.WithTimeout(baseCtx, 3*time.Second)
	defer cancel()
	observed := &observedApprovalWaitContext{Context: ctx, entered: make(chan struct{})}
	job := machineJob{GoalID: "goal-approval-test", WorkerID: "worker-approval-test", Attempt: 2}
	result := make(chan machineApprovalTestResult, 1)
	go func() {
		decision, err := machineCodexApprovalDecision(observed, identity, bridge, job, 77,
			"item/commandExecution/requestApproval", machineApprovalTestParams("native-thread-a", "native-turn-a"))
		result <- machineApprovalTestResult{decision: decision, err: err}
	}()
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		t.Fatal("approval callback did not wait for the turn response")
	}
	if got := calls(); got != 0 {
		t.Fatalf("Hub was called before turn/start response: %d", got)
	}
	if err := identity.confirmTurn("native-turn-a"); err != nil {
		t.Fatal("confirm synthetic Turn:", err)
	}
	select {
	case got := <-result:
		if got.err != nil || got.decision != "accept" {
			t.Fatalf("approval after Turn confirmation: decision=%q err=%v", got.decision, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("approval callback did not finish after turn/start response")
	}
	if got := calls(); got != 1 {
		t.Fatalf("Hub calls=%d, want one after exact identity confirmation", got)
	}
}

func TestMachineCodexApprovalWaitHonorsCancellation(t *testing.T) {
	bridge, baseCtx, calls := machineApprovalDecisionFixture(t)
	identity := newMachineCodexApprovalIdentity()
	if err := identity.confirmThread("native-thread-a"); err != nil {
		t.Fatal("confirm synthetic Thread:", err)
	}
	ctx, cancel := context.WithCancel(baseCtx)
	observed := &observedApprovalWaitContext{Context: ctx, entered: make(chan struct{})}
	job := machineJob{GoalID: "goal-approval-test", WorkerID: "worker-approval-test", Attempt: 2}
	result := make(chan machineApprovalTestResult, 1)
	go func() {
		decision, err := machineCodexApprovalDecision(observed, identity, bridge, job, 77,
			"item/commandExecution/requestApproval", machineApprovalTestParams("native-thread-a", "native-turn-a"))
		result <- machineApprovalTestResult{decision: decision, err: err}
	}()
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("approval callback did not reach the bounded Turn wait")
	}
	cancel()
	select {
	case got := <-result:
		if got.err == nil || got.decision != "" {
			t.Fatalf("canceled approval decision=%q err=%v, want bounded cancellation", got.decision, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("approval callback remained blocked after context cancellation")
	}
	if got := calls(); got != 0 {
		t.Fatalf("Hub was called %d times for canceled unconfirmed identity", got)
	}
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
	t.Setenv("CICADA_TEST_APPROVAL_BEFORE_TURN_RESPONSE", "1")
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

// Captured wire only: fake stored policy is not native filesystem enforcement.
func TestManagedCodexSandboxPolicyWire(t *testing.T) {
	for _, mode := range []string{"fresh", "resumed-read-only", "resumed-named-profile"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			binary, capture := fakeApprovalCodex(t, root)
			original, err := os.ReadFile(binary)
			if err != nil {
				t.Fatal("read owned protocol fixture")
			}
			script := string(original)
			script = strings.Replace(script, "while IFS= read -r line; do", "while IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> \"$CICADA_TEST_POLICY_WIRE\"", 1)
			// No approval or business HTTP: this fake completes the one wire-observed turn.
			if mode == "resumed-read-only" {
				script = strings.ReplaceAll(script, `"result":{"thread":{"id":"native-thread-a"}}`, `"result":{"thread":{"id":"native-thread-a"},"sandbox":{"type":"readOnly"}}`)
			}
			if mode == "resumed-named-profile" {
				script = strings.ReplaceAll(script, `"result":{"thread":{"id":"native-thread-a"}}`, `"result":{"thread":{"id":"native-thread-a"},"activePermissionProfile":{"id":"synthetic-restricted-profile"}}`)
			}
			caseStart := strings.Index(script, `    *'"method":"turn/start"'*)`)
			if caseStart < 0 {
				t.Fatal("protocol fixture shape changed")
			}
			bodyStart := strings.Index(script[caseStart:], "\n") + caseStart + 1
			bodyEnd := strings.Index(script[bodyStart:], "      ;;\n")
			if bodyStart <= caseStart || bodyEnd < 0 {
				t.Fatal("protocol fixture shape changed")
			}
			bodyEnd += bodyStart
			turnBody := "      printf '%s\\n' '{\"id\":3,\"result\":{\"turn\":{\"id\":\"native-turn-a\",\"items\":[],\"status\":\"inProgress\"}}}'\n" +
				"      printf '%s\\n' '{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"native-thread-a\",\"turn\":{\"id\":\"native-turn-a\",\"items\":[],\"status\":\"completed\"}}}'\n"
			script = script[:bodyStart] + turnBody + script[bodyEnd:]
			if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
				t.Fatal("write owned protocol fixture")
			}
			wire := filepath.Join(root, "wire.jsonl")
			t.Setenv("CICADA_TEST_POLICY_WIRE", wire)
			t.Setenv("CICADA_TEST_APPROVAL_CAPTURE", capture)
			t.Setenv("CICADA_CODEX_BIN", binary)
			t.Setenv("CICADA_WORKSPACE_ROOT", root)
			t.Setenv("CICADA_CODEX_MODEL", "synthetic-wire-model")
			_, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, "http://127.0.0.1:1")
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			job := machineJob{GoalID: "goal-wire", WorkerID: "worker-wire", MachineID: "node-recovery-test", Harness: "codex", Workspace: filepath.Join(root, "goal-wire"), Prompt: "PUBLIC_SYNTHETIC_PROTOCOL", Attempt: 1, executionID: "execution-wire", providerID: "codex", leaseID: "lease-wire"}
			if mode != "fresh" {
				job.ThreadID = "native-thread-a"
			}
			result := executeMachineJobWithApproval(ctx, job, &machineApprovalBridge{})
			if result.Status != "completed" || result.ThreadID != "native-thread-a" {
				t.Fatalf("synthetic wire fixture failed: %#v", result)
			}
			data, err := os.ReadFile(wire)
			if err != nil || len(data) > 65536 {
				t.Fatal("wire capture unavailable")
			}
			seenThread, seenTurn := false, false
			for _, line := range bytes.Split(data, []byte("\n")) {
				if len(line) == 0 {
					continue
				}
				var request struct {
					Method string         `json:"method"`
					Params map[string]any `json:"params"`
				}
				if json.Unmarshal(line, &request) != nil {
					t.Fatal("wire malformed")
				}
				p := request.Params
				switch request.Method {
				case "thread/start", "thread/resume":
					seenThread = true
					if p["approvalsReviewer"] != "user" {
						t.Fatal("thread must use the managed user approval reviewer")
					}
					if p["approvalPolicy"] != "on-request" || p["cwd"] != job.Workspace || p["model"] != "synthetic-wire-model" {
						t.Fatal("thread management fields changed")
					}
					if mode == "fresh" {
						if request.Method != "thread/start" || p["sandbox"] != "workspace-write" {
							t.Fatal("new Worker default changed")
						}
					} else {
						if request.Method != "thread/resume" || p["threadId"] != job.ThreadID {
							t.Fatal("original Thread changed")
						}
						if _, present := p["permissions"]; present {
							t.Fatal("resume overwrote named permissions")
						}
						if _, present := p["sandbox"]; present {
							t.Fatal("resume overwrote stored sandbox")
						}
					}
				case "turn/start":
					seenTurn = true
					if p["approvalsReviewer"] != "user" {
						t.Fatal("turn must use the managed user approval reviewer")
					}
					if p["threadId"] != "native-thread-a" || p["approvalPolicy"] != "on-request" || p["cwd"] != job.Workspace || p["model"] != "synthetic-wire-model" {
						t.Fatal("turn fields changed")
					}
					if _, present := p["permissions"]; present {
						t.Fatal("turn overwrote named permissions")
					}
					if _, present := p["sandboxPolicy"]; present {
						t.Fatal("turn overwrote sandbox")
					}
				}
			}
			if !seenThread || !seenTurn {
				t.Fatal("required requests not observed")
			}
		})
	}
}

func TestManagedCodexOrdinaryRuntimeOutcome(t *testing.T) {
	for _, tc := range []struct {
		name                                string
		started, completed, stopUnconfirmed bool
		state                               string
	}{
		{"prestart-failure", false, false, false, nodeinbox.ProviderAdmissionFailed},
		{"initialize-failure", true, false, false, nodeinbox.ProviderAdmissionInjectionUncertain},
		{"turn-start-failure", true, false, false, nodeinbox.ProviderAdmissionInjectionUncertain},
		{"partial-start-failure", true, false, false, nodeinbox.ProviderAdmissionInjectionUncertain},
		{"completed-stop-unconfirmed", true, false, true, nodeinbox.ProviderAdmissionInjectionUncertain},
		{"completed-custom-exit-error", true, false, true, nodeinbox.ProviderAdmissionInjectionUncertain},
		{"partial-start-stop-unconfirmed", true, false, true, nodeinbox.ProviderAdmissionInjectionUncertain},
		{"normal-stop", true, true, false, nodeinbox.ProviderAdmissionCompleted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(root, "app-server")
			script := `#!/bin/sh
set -eu
while IFS= read -r line; do
 case "$line" in
  *'"method":"initialize"'*) printf '%s\n' '{"id":1,"result":{}}' ;;
  *'"method":"thread/start"'*) printf '%s\n' '{"id":2,"result":{"thread":{"id":"runtime-thread"}}}' ;;
  *'"method":"turn/start"'*)
   printf '%s\n' '{"id":3,"result":{"turn":{"id":"runtime-turn","items":[],"status":"inProgress"}}}'
   printf '%s\n' '{"method":"turn/completed","params":{"threadId":"runtime-thread","turn":{"id":"runtime-turn","items":[{"type":"agentMessage","text":"SYNTHETIC_DONE"}],"status":"completed"}}}' ;;
 esac
done
`
			if tc.name == "completed-custom-exit-error" {
				script += "exec sleep 30\n"
			}
			if tc.name == "initialize-failure" {
				script = strings.Replace(script, `{"id":1,"result":{}}`, `{"id":1,"error":{"code":-1,"message":"synthetic init failure"}}`, 1)
			}
			if tc.name == "turn-start-failure" {
				script = strings.Replace(script, `{"id":3,"result":{"turn":{"id":"runtime-turn","items":[],"status":"inProgress"}}}`, `{"id":3,"error":{"code":-1,"message":"synthetic turn failure"}}`, 1)
			}
			if tc.started {
				if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("CICADA_CODEX_BIN", binary)
			t.Setenv("CICADA_CODEX_MODEL", "synthetic-no-model")
			hub := machineHubContext{HubID: "synthetic-hub", NodeID: "synthetic-node", WriterRoot: filepath.Join(root, "writers"), WriterScope: "synthetic-account"}
			ledger, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(root, "provider.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.Close()
			hub.ProviderAdmissions = ledger
			ctx, cancel := context.WithTimeout(withMachineHubContext(context.Background(), hub), 5*time.Second)
			defer cancel()
			request := nodeinbox.ProviderAdmissionRequest{ExecutionID: "synthetic-execution", ProviderID: "codex", AdmissionIntent: strings.Repeat("a", 64)}
			admission, err := ledger.AdmitProviderAttempt(ctx, request)
			if err != nil || !admission.Admitted {
				t.Fatalf("admission=%#v err=%v", admission, err)
			}
			job := machineJob{MachineID: hub.NodeID, Harness: "codex", Attempt: 1, executionID: request.ExecutionID, providerID: request.ProviderID, providerAttempt: admission.Attempt, leaseID: "synthetic-lease"}
			if tc.name == "partial-start-stop-unconfirmed" {
				job.ThreadID = "runtime-thread"
			}
			var startCalls, startedPID int
			starter := func(cmd *exec.Cmd) error {
				startCalls++
				err := cmd.Start()
				if cmd.Process != nil {
					startedPID = cmd.Process.Pid
				}
				if err == nil && strings.HasPrefix(tc.name, "partial-start-") {
					return errors.New("synthetic partial start failure")
				}
				return err
			}
			var waiter codexapp.ProcessWaiter
			var waitedPID int
			if tc.stopUnconfirmed {
				waiter = func(cmd *exec.Cmd) error {
					waitedPID = cmd.Process.Pid
					waitErr := cmd.Wait()
					if tc.name == "completed-custom-exit-error" || tc.name == "partial-start-stop-unconfirmed" {
						return waitErr
					}
					return errors.Join(waitErr, errors.New("synthetic STOP_UNVERIFIED"))
				}
			}
			quarantinedMachineNativeWriters.Lock()
			previousLocks := make(map[*nodelock.NativeWriterLock]bool)
			for _, w := range quarantinedMachineNativeWriters.locks {
				previousLocks[w] = true
			}
			quarantinedMachineNativeWriters.Unlock()
			response := filepath.Join(root, "response")
			result := executeMachineCodexWithApprovalWaiter(ctx, job, root, response, machineApprovalBridge{}, starter, waiter)
			if startCalls != 1 || (startedPID > 0) != tc.started {
				t.Fatalf("actual START callback=%d pid=%d", startCalls, startedPID)
			}
			if result.providerStarted != tc.started || (result.Status == "completed") != tc.completed {
				t.Fatalf("false lifecycle result: %#v", result)
			}
			if !tc.completed && result.Summary != "" {
				t.Fatal("failed lifecycle retained successful business summary")
			}
			if tc.stopUnconfirmed {
				if waitedPID <= 0 || result.Error == "" {
					t.Fatal("actual process wait/stop failure evidence missing")
				}
				lockCtx, stop := context.WithTimeout(withMachineHubContext(context.Background(), hub), 50*time.Millisecond)
				defer stop()
				if writer, err := acquireManagedMachineCodexWriter(lockCtx, job, "runtime-thread"); err == nil {
					writer.Close()
					t.Fatal("unconfirmed stop released native writer")
				}
				// Only this test's exact quarantine is released after the assertion.
				quarantinedMachineNativeWriters.Lock()
				for i, w := range quarantinedMachineNativeWriters.locks {
					if !previousLocks[w] && w.CheckCurrent() == nil {
						w.Close()
						quarantinedMachineNativeWriters.locks = append(quarantinedMachineNativeWriters.locks[:i], quarantinedMachineNativeWriters.locks[i+1:]...)
						break
					}
				}
				quarantinedMachineNativeWriters.Unlock()
			} else if tc.started && tc.name != "initialize-failure" && tc.name != "partial-start-failure" {
				writer, err := acquireManagedMachineCodexWriter(ctx, job, "runtime-thread")
				if err != nil {
					t.Fatalf("writer not released after actual stop: result=%#v err=%v", result, err)
				}
				writer.Close()
			}
			if err := recordMachineNodeProviderOutcome(ctx, job, result); err != nil {
				t.Fatal(err)
			}
			saved, err := ledger.InspectProviderAttempt(ctx, request)
			if err != nil || saved.State != tc.state || saved.Retryable {
				t.Fatalf("provider state=%#v err=%v", saved, err)
			}
		})
	}
}
