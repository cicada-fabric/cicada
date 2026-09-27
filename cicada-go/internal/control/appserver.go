package control

import (
	"context"
	"os"

	"github.com/cicada-ai/cicada/internal/buildinfo"
	"github.com/cicada-ai/cicada/internal/codexapp"
	"github.com/cicada-ai/cicada/internal/store"
	workspaceprep "github.com/cicada-ai/cicada/internal/workspace"
)

// appServerResult records one local Codex Worker turn.
type appServerResult struct {
	ExitCode int
	ThreadID string
	Summary  string
	Output   string
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
	model := envOr("CICADA_CODEX_MODEL", "gpt-5.6-luna")
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
	app, err := codexapp.Start(ctx, c.config.CodexBinary, workspace,
		append(os.Environ(), "CODEX_HOME="+envOr("CODEX_HOME", "/state")), onEvent,
		func(_ any, method string, params map[string]any) any { return onRequest(method, params) })
	if err != nil {
		return appServerResult{ExitCode: 1, Output: err.Error()}
	}
	defer app.Close()
	pid := app.PID()
	_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{PID: &pid})
	initialized, err := app.Request(ctx, "initialize", map[string]any{
		"clientInfo":   map[string]any{"name": "cicada-control", "title": "Cicada Control", "version": buildinfo.Version},
		"capabilities": map[string]any{"experimentalApi": true},
	})
	_ = initialized
	if err != nil {
		return appServerResult{ExitCode: 1, Output: err.Error()}
	}
	if err := app.Notify("initialized", map[string]any{}); err != nil {
		return appServerResult{ExitCode: 1, Output: err.Error()}
	}
	threadID := worker.ThreadID
	if threadID == "" {
		result, requestErr := app.Request(ctx, "thread/start", map[string]any{
			"model": model, "cwd": workspace,
			"approvalPolicy": "on-request", "sandbox": "workspace-write",
		})
		if requestErr != nil {
			return appServerResult{ExitCode: 1, Output: requestErr.Error()}
		}
		threadID = nestedString(result, "thread", "id")
		if threadID != "" {
			_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{ThreadID: &threadID})
		}
	} else {
		result, err := app.Request(ctx, "thread/resume", map[string]any{
			"threadId": threadID, "model": model, "cwd": workspace,
			"approvalPolicy": "on-request", "sandbox": "workspace-write",
		})
		if err != nil {
			return appServerResult{ExitCode: 1, Output: err.Error()}
		}
		if nestedString(result, "thread", "id") != threadID {
			return appServerResult{ExitCode: 1, ThreadID: threadID, Output: "Codex did not confirm the exact native Thread on resume"}
		}
	}
	if threadID == "" {
		return appServerResult{ExitCode: 1, Output: "Codex did not return a thread id"}
	}
	if _, err := app.Request(ctx, "turn/start", map[string]any{
		"threadId":       threadID,
		"input":          []any{map[string]any{"type": "text", "text": prompt}},
		"cwd":            workspace,
		"approvalPolicy": "on-request",
		"sandboxPolicy":  map[string]any{"type": "workspaceWrite"},
		"model":          model,
	}); err != nil {
		return appServerResult{ExitCode: 1, ThreadID: threadID, Output: err.Error()}
	}
	summary, status, waitErr := app.WaitTurn(ctx)
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
	_, _ = c.store.AppendEvent(goalID, workerID, "ApprovalRequested", map[string]any{
		"approval_id": approval.ID, "method": method,
	})
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
