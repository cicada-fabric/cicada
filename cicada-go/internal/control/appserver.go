package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/cicada-ai/cicada/internal/buildinfo"
	"github.com/cicada-ai/cicada/internal/store"
	workspaceprep "github.com/cicada-ai/cicada/internal/workspace"
)

// appServer is the small JSON-RPC client needed by the current Codex adapter. The protocol is
// intentionally kept here instead of importing Happy's UI/runtime packages;
// its message shapes are compatible with the Codex app-server reference used
// by Happy's codexAppServerClient.
type appServer struct {
	process   *exec.Cmd
	stdin     io.WriteCloser
	scanner   *bufio.Scanner
	writeMu   sync.Mutex
	nextID    int64
	onEvent   func(method string, params map[string]any)
	onRequest func(method string, params map[string]any) any
}

type appServerResult struct {
	ExitCode int
	ThreadID string
	Summary  string
	Output   string
}

func newAppServer(ctx context.Context, binary, cwd string, onEvent func(string, map[string]any), onRequest func(string, map[string]any) any) (*appServer, error) {
	// Plugins are outside Cicada's current trust boundary. Disabling them keeps a
	// worker startup deterministic and prevents the app-server from trying to
	// clone/update plugin repositories before it can accept a Goal turn.
	if strings.TrimSpace(binary) == "" {
		binary = "codex"
	}
	process := exec.CommandContext(ctx, binary, "app-server", "--stdio", "--disable", "plugins")
	process.Dir = cwd
	process.Env = append(os.Environ(), "CODEX_HOME="+envOr("CODEX_HOME", "/state"))
	stdout, err := process.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := process.StdinPipe()
	if err != nil {
		return nil, err
	}
	// App-server diagnostics are already represented as Codex events where
	// possible. Keep stderr attached to the container log without buffering it.
	process.Stderr = os.Stderr
	if err := process.Start(); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	return &appServer{process: process, stdin: stdin, scanner: scanner, nextID: 1, onEvent: onEvent, onRequest: onRequest}, nil
}

func (a *appServer) close() {
	_ = a.stdin.Close()
	if a.process.Process != nil {
		_ = a.process.Process.Kill()
	}
	_ = a.process.Wait()
}

func (a *appServer) write(message map[string]any) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	_, err = fmt.Fprintln(a.stdin, string(data))
	return err
}

func (a *appServer) notify(method string, params any) error {
	return a.write(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

func (a *appServer) request(ctx context.Context, method string, params any) (map[string]any, error) {
	id := a.nextID
	a.nextID++
	if err := a.write(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for a.scanner.Scan() {
		line := strings.TrimSpace(a.scanner.Text())
		if line == "" {
			continue
		}
		message := map[string]any{}
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			continue
		}
		if responseID, ok := numberAsInt64(message["id"]); ok && responseID == id {
			if errorPayload, exists := message["error"]; exists {
				return nil, fmt.Errorf("codex %s: %v", method, errorPayload)
			}
			if result, ok := message["result"].(map[string]any); ok {
				return result, nil
			}
			return map[string]any{}, nil
		}
		a.handleMessage(message)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	if err := a.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("codex app-server closed stdout")
}

func (a *appServer) handleMessage(message map[string]any) {
	method, _ := message["method"].(string)
	if method == "" {
		return
	}
	params, _ := message["params"].(map[string]any)
	if message["id"] != nil {
		result := any(map[string]any{})
		if a.onRequest != nil {
			result = a.onRequest(method, params)
		}
		_ = a.write(map[string]any{"jsonrpc": "2.0", "id": message["id"], "result": result})
		return
	}
	if a.onEvent != nil {
		a.onEvent(method, params)
	}
}

func (a *appServer) waitTurn(ctx context.Context) (string, string, error) {
	var summary string
	var status string
	for a.scanner.Scan() {
		line := strings.TrimSpace(a.scanner.Text())
		if line == "" {
			continue
		}
		message := map[string]any{}
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			continue
		}
		if method, _ := message["method"].(string); method != "" {
			params, _ := message["params"].(map[string]any)
			if item, ok := params["item"].(map[string]any); ok && item["type"] == "agentMessage" {
				if text, ok := item["text"].(string); ok && strings.TrimSpace(text) != "" {
					summary = strings.TrimSpace(text)
				}
			}
			if method == "turn/completed" {
				status = turnStatus(params)
				a.handleMessage(message)
				return summary, status, nil
			}
			if method == "thread/status/changed" {
				if statusPayload, ok := params["status"].(map[string]any); ok && statusPayload["type"] == "idle" {
					a.handleMessage(message)
					return summary, "completed", nil
				}
			}
		}
		a.handleMessage(message)
		select {
		case <-ctx.Done():
			return summary, "interrupted", ctx.Err()
		default:
		}
	}
	if err := a.scanner.Err(); err != nil {
		return summary, "failed", err
	}
	return summary, "failed", errors.New("codex app-server closed before turn completion")
}

func turnStatus(params map[string]any) string {
	if turn, ok := params["turn"].(map[string]any); ok {
		if value, ok := turn["status"].(string); ok {
			return value
		}
	}
	if value, ok := params["status"].(string); ok {
		return value
	}
	return "completed"
}

func numberAsInt64(value any) (int64, bool) {
	if number, ok := value.(float64); ok {
		return int64(number), true
	}
	if number, ok := value.(int64); ok {
		return number, true
	}
	return 0, false
}

func (c *Control) runAppServer(parent context.Context, goal store.Goal, workerID, prompt string) appServerResult {
	worker, err := c.store.GetWorker(workerID)
	if err != nil || worker == nil {
		return appServerResult{ExitCode: 1, Output: "worker not found"}
	}
	workspace := goal.Workspace
	if worker.Workspace != "" {
		workspace = worker.Workspace
	}
	workspace, err = workspaceprep.ResolveWithin(c.config.WorkspaceRoot, workspace)
	if err != nil {
		return appServerResult{ExitCode: 1, Output: "resolve workspace: " + err.Error()}
	}
	ctx, cancel := context.WithTimeout(parent, c.config.WorkerTimeout)
	defer cancel()
	var approvalErr error
	onEvent := func(method string, params map[string]any) {
		if method == "thread/started" {
			if thread, ok := params["thread"].(map[string]any); ok {
				if threadID, ok := thread["id"].(string); ok && threadID != "" {
					_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{ThreadID: &threadID})
				}
			}
		}
		_, _ = c.store.AppendEvent(goal.ID, workerID, "CodexEvent", map[string]any{"method": method, "params": params})
		_ = c.store.TouchMonitor(goal.MonitorID, "active")
	}
	onRequest := func(method string, params map[string]any) any {
		if method == "item/commandExecution/requestApproval" || method == "item/fileChange/requestApproval" || method == "mcpServer/elicitation/request" {
			return c.handleApprovalRequest(ctx, goal.ID, workerID, method, params, &approvalErr)
		}
		return map[string]any{}
	}
	app, err := newAppServer(ctx, c.config.CodexBinary, workspace, onEvent, onRequest)
	if err != nil {
		return appServerResult{ExitCode: 1, Output: err.Error()}
	}
	defer app.close()
	pid := app.process.Process.Pid
	_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{PID: &pid})
	initialized, err := app.request(ctx, "initialize", map[string]any{
		"clientInfo":   map[string]any{"name": "cicada-control", "title": "Cicada Control", "version": buildinfo.Version},
		"capabilities": map[string]any{"experimentalApi": true},
	})
	_ = initialized
	if err != nil {
		return appServerResult{ExitCode: 1, Output: err.Error()}
	}
	if err := app.notify("initialized", map[string]any{}); err != nil {
		return appServerResult{ExitCode: 1, Output: err.Error()}
	}
	threadID := worker.ThreadID
	if threadID == "" {
		result, requestErr := app.request(ctx, "thread/start", map[string]any{
			"model": "gpt-5.5", "modelProvider": nil, "profile": nil, "cwd": workspace,
			"approvalPolicy": "on-request", "sandbox": "workspace-write", "config": nil,
			"baseInstructions": nil, "developerInstructions": nil, "compactPrompt": nil,
			"includeApplyPatchTool": nil, "experimentalRawEvents": false, "persistExtendedHistory": true,
		})
		if requestErr != nil {
			return appServerResult{ExitCode: 1, Output: requestErr.Error()}
		}
		threadID = nestedString(result, "thread", "id")
		if threadID != "" {
			_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{ThreadID: &threadID})
		}
	} else {
		if _, err := app.request(ctx, "thread/resume", map[string]any{
			"threadId": threadID, "model": "gpt-5.5", "modelProvider": nil, "cwd": workspace,
			"approvalPolicy": "on-request", "sandbox": "workspace-write", "config": nil,
			"baseInstructions": nil, "developerInstructions": nil, "persistExtendedHistory": true,
		}); err != nil {
			return appServerResult{ExitCode: 1, Output: err.Error()}
		}
	}
	if threadID == "" {
		return appServerResult{ExitCode: 1, Output: "Codex did not return a thread id"}
	}
	if _, err := app.request(ctx, "turn/start", map[string]any{
		"threadId":       threadID,
		"input":          []any{map[string]any{"type": "text", "text": prompt}},
		"cwd":            workspace,
		"approvalPolicy": "on-request",
		"sandboxPolicy":  map[string]any{"type": "workspaceWrite"},
		"model":          "gpt-5.5",
		"effort":         nil,
		"summary":        "none",
		"outputSchema":   nil,
	}); err != nil {
		return appServerResult{ExitCode: 1, ThreadID: threadID, Output: err.Error()}
	}
	summary, status, waitErr := app.waitTurn(ctx)
	if approvalErr != nil {
		return appServerResult{ExitCode: 1, ThreadID: threadID, Summary: summary, Output: approvalErr.Error()}
	}
	if waitErr != nil {
		return appServerResult{ExitCode: 1, ThreadID: threadID, Summary: summary, Output: waitErr.Error()}
	}
	if status != "completed" && status != "complete" && status != "idle" {
		return appServerResult{ExitCode: 1, ThreadID: threadID, Summary: summary, Output: "turn status: " + status}
	}
	if summary != "" {
		_ = os.WriteFile(worker.ResponseFile, []byte(summary+"\n"), 0o644)
	}
	return appServerResult{ExitCode: 0, ThreadID: threadID, Summary: summary}
}

func nestedString(value map[string]any, keys ...string) string {
	current := any(value)
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = object[key]
	}
	result, _ := current.(string)
	return result
}

func (c *Control) handleApprovalRequest(ctx context.Context, goalID, workerID, method string, params map[string]any, approvalErr *error) any {
	approvalID := store.NewID("approval")
	approval, err := c.store.CreateApproval(approvalID, goalID, workerID, method, params)
	if err != nil {
		*approvalErr = err
		return map[string]any{"decision": "decline"}
	}
	_, _ = c.store.AppendEvent(goalID, workerID, "ApprovalRequested", map[string]any{"approval_id": approval.ID, "method": method, "request": params})
	c.notify(goalID, "approval.requested", "P1", "Approval required", "Codex is waiting for a human decision for "+method+" (approval "+approval.ID+").")
	waiter := make(chan string, 1)
	c.approvalMu.Lock()
	c.approvalWaiters[approvalID] = waiter
	c.approvalMu.Unlock()
	// A client can resolve an approval immediately after it is created and
	// before the in-memory waiter is registered. Re-read durable state to close
	// that race and let the Codex request continue without hanging.
	if current, lookupErr := c.store.GetApproval(approvalID); lookupErr != nil {
		*approvalErr = lookupErr
	} else if current != nil && current.Status == "resolved" {
		waiter <- current.Decision
	}
	defer func() {
		c.approvalMu.Lock()
		delete(c.approvalWaiters, approvalID)
		c.approvalMu.Unlock()
	}()
	decision := "decline"
	select {
	case decision = <-waiter:
	case <-ctx.Done():
		*approvalErr = ctx.Err()
	}
	if decision != "accept" && decision != "acceptForSession" {
		decision = "decline"
	}
	if _, err := c.store.ResolveApproval(approvalID, decision); err != nil {
		*approvalErr = err
	}
	_, _ = c.store.AppendEvent(goalID, workerID, "ApprovalResolved", map[string]any{"approval_id": approvalID, "decision": decision})
	if method == "mcpServer/elicitation/request" {
		action := "decline"
		if decision == "accept" || decision == "acceptForSession" {
			action = "accept"
		}
		return map[string]any{"action": action, "content": map[string]any{}, "_meta": nil}
	}
	return map[string]any{"decision": decision}
}
