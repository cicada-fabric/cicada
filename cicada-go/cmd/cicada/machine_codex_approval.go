package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/buildinfo"
	"github.com/cicada-ai/cicada/internal/codexapp"
)

// A Node owns the live Codex process. The Hub owns durable approval state and
// the Client remains the only source of a human decision. This bridge carries
// neither a management bearer nor an approval supplied by model text.
type machineApprovalBridge struct {
	BaseURL   string
	NodeID    string
	NodeToken string
}

type machineApprovalState struct {
	ApprovalID string `json:"approval_id"`
	GoalID     string `json:"goal_id"`
	WorkerID   string `json:"worker_id"`
	Attempt    int    `json:"attempt"`
	Status     string `json:"status"`
	Decision   string `json:"decision,omitempty"`
}

func (b machineApprovalBridge) endpoint(job machineJob) string {
	return nodeWorkerJobEndpoint(b.BaseURL, b.NodeID, job.WorkerID, "approvals")
}

func machineApprovalRequestID(job machineJob, rpcID any, params map[string]any) (string, error) {
	if rpcID == nil {
		return "", errors.New("Codex approval request has no stable JSON-RPC ID")
	}
	for _, field := range []string{"threadId", "turnId", "itemId"} {
		if value, ok := params[field].(string); !ok || strings.TrimSpace(value) == "" {
			return "", errors.New("Codex approval request has incomplete native identity")
		}
	}
	encoded, err := json.Marshal(map[string]any{
		"rpc_id": rpcID, "thread_id": params["threadId"],
		"turn_id": params["turnId"], "item_id": params["itemId"],
	})
	if err != nil || len(encoded) == 0 || string(encoded) == "null" {
		return "", errors.New("Codex approval request has no stable JSON-RPC ID")
	}
	seed := fmt.Sprintf("cicada/node/worker-approval/v1\x00%s\x00%d\x00%s", job.WorkerID, job.Attempt, encoded)
	digest := sha256.Sum256([]byte(seed))
	return "codex_" + hex.EncodeToString(digest[:]), nil
}

func (b machineApprovalBridge) requestDecision(ctx context.Context, job machineJob,
	rpcID any, method string, params map[string]any) (string, error) {
	if method != "item/commandExecution/requestApproval" &&
		method != "item/fileChange/requestApproval" {
		return "", errors.New("unsupported Codex approval request")
	}
	if job.WorkerID == "" || job.Attempt <= 0 || b.NodeID == "" || b.NodeToken == "" {
		return "", errors.New("Node Worker approval has no active assignment")
	}
	requestID, err := machineApprovalRequestID(job, rpcID, params)
	if err != nil {
		return "", err
	}
	if encoded, err := json.Marshal(params); err != nil || len(encoded) > 64*1024 {
		return "", errors.New("Codex approval request exceeds the bounded Node limit")
	}
	input := map[string]any{"attempt": job.Attempt, "request_id": requestID,
		"method": method, "request": params}
	var state machineApprovalState
	// A lost POST response is safe to retry only because the Hub binds this
	// request ID and the exact payload to the current Worker attempt.
	for {
		state = machineApprovalState{}
		err = machineNodeAPIJSON(ctx, b.endpoint(job), http.MethodPost, b.NodeToken, input, &state)
		if err == nil {
			break
		}
		if !retryableMachineApprovalError(err) {
			return "", err
		}
		if err := waitMachineApprovalRetry(ctx); err != nil {
			return "", err
		}
	}
	for {
		if err := validateMachineApprovalState(state, job); err != nil {
			return "", err
		}
		if state.Status == "resolved" {
			if !codexApprovalDecisionAvailable(params, state.Decision) {
				return "", errors.New("Client decision is not offered by the native Codex request")
			}
			return state.Decision, nil
		}
		endpoint := b.endpoint(job) + "/" + url.PathEscape(state.ApprovalID) +
			"?attempt=" + fmt.Sprint(job.Attempt) + "&wait_ms=20000"
		var next machineApprovalState
		err = machineNodeAPIJSON(ctx, endpoint, http.MethodGet, b.NodeToken, nil, &next)
		if err != nil {
			if !retryableMachineApprovalError(err) {
				return "", err
			}
			if err := waitMachineApprovalRetry(ctx); err != nil {
				return "", err
			}
			continue
		}
		if next.ApprovalID != state.ApprovalID {
			return "", errors.New("Hub changed the pending Codex approval identity")
		}
		state = next
	}
}

func codexApprovalDecisionAvailable(params map[string]any, decision string) bool {
	available, present := params["availableDecisions"]
	if !present || available == nil {
		return true
	}
	list, ok := available.([]any)
	if !ok || len(list) == 0 {
		return false
	}
	for _, item := range list {
		if value, ok := item.(string); ok && value == decision {
			return true
		}
	}
	return false
}

func validateMachineApprovalState(state machineApprovalState, job machineJob) error {
	if state.ApprovalID == "" || state.GoalID != job.GoalID ||
		state.WorkerID != job.WorkerID || state.Attempt != job.Attempt {
		return errors.New("Hub returned an approval for a different Worker attempt")
	}
	switch state.Status {
	case "pending":
		if state.Decision != "" {
			return errors.New("pending approval already contains a decision")
		}
	case "resolved":
		if state.Decision != "accept" && state.Decision != "acceptForSession" && state.Decision != "decline" {
			return errors.New("Hub returned an invalid Codex approval decision")
		}
	default:
		return errors.New("Hub returned an unknown Codex approval state")
	}
	return nil
}

func retryableMachineApprovalError(err error) bool {
	var apiErr *machineAPIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500
	}
	var networkErr *url.Error
	return errors.As(err, &networkErr)
}

func waitMachineApprovalRetry(ctx context.Context) error {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func executeMachineCodexWithApproval(ctx context.Context, job machineJob, workspace, responseFile string,
	bridge machineApprovalBridge) machineJobResult {
	runCtx, cancel := context.WithCancel(ctx)
	var approvalErr error
	var approvalMu sync.Mutex
	threadID := job.ThreadID
	model := envOr("CICADA_CODEX_MODEL", "gpt-5.6-luna")
	childEnv := append(machineWorkerEnvironment(os.Environ(), true),
		"CODEX_HOME="+envOr("CODEX_HOME", "/state"))
	onRequest := func(id any, method string, params map[string]any) any {
		var decision string
		var err error
		if method != "item/commandExecution/requestApproval" &&
			method != "item/fileChange/requestApproval" {
			err = errors.New("unsupported Codex server request: " + method)
			cancel()
		} else if params["threadId"] != threadID {
			err = errors.New("Codex approval targets a different native Thread")
		} else {
			decision, err = bridge.requestDecision(runCtx, job, id, method, params)
		}
		if err != nil {
			approvalMu.Lock()
			approvalErr = err
			approvalMu.Unlock()
			decision = "decline"
		}
		return map[string]any{"decision": decision}
	}
	app, err := codexapp.StartAsync(runCtx, envOr("CICADA_CODEX_BIN", "codex"), workspace,
		childEnv, nil, onRequest)
	if err != nil {
		cancel()
		return machineJobResult{Status: "failed", Error: err.Error()}
	}
	defer func() {
		cancel()
		app.Close()
	}()
	if _, err := app.Request(runCtx, "initialize", map[string]any{
		"clientInfo": map[string]any{"name": "cicada-node", "title": "Cicada Node",
			"version": buildinfo.Version},
		"capabilities": map[string]any{"experimentalApi": true},
	}); err != nil {
		return machineJobResult{Status: "failed", Error: err.Error()}
	}
	if err := app.Notify("initialized", map[string]any{}); err != nil {
		return machineJobResult{Status: "failed", Error: err.Error()}
	}
	if threadID == "" {
		result, err := app.Request(runCtx, "thread/start", map[string]any{
			"model": model, "cwd": workspace,
			"approvalPolicy": "on-request", "sandbox": "workspace-write",
		})
		if err != nil {
			return machineJobResult{Status: "failed", Error: err.Error()}
		}
		threadID = nestedMachineString(result, "thread", "id")
	} else {
		result, err := app.Request(runCtx, "thread/resume", map[string]any{
			"threadId": threadID, "model": model, "cwd": workspace,
			"approvalPolicy": "on-request", "sandbox": "workspace-write",
		})
		if err != nil {
			return machineJobResult{Status: "failed", ThreadID: threadID, Error: err.Error()}
		}
		if actual := nestedMachineString(result, "thread", "id"); actual != threadID {
			return machineJobResult{Status: "failed", ThreadID: threadID,
				Error: "Codex did not confirm the exact native Thread on resume"}
		}
	}
	if threadID == "" {
		return machineJobResult{Status: "failed", Error: "Codex did not return a native Thread ID"}
	}
	if _, err := app.Request(runCtx, "turn/start", map[string]any{
		"threadId": threadID,
		"input":    []any{map[string]any{"type": "text", "text": job.Prompt}},
		"cwd":      workspace, "approvalPolicy": "on-request",
		"sandboxPolicy": map[string]any{"type": "workspaceWrite"},
		"model":         model,
	}); err != nil {
		return machineJobResult{Status: "failed", ThreadID: threadID, Error: err.Error()}
	}
	summary, status, err := app.WaitTurn(runCtx)
	approvalMu.Lock()
	requestErr := approvalErr
	approvalMu.Unlock()
	if requestErr != nil {
		return machineJobResult{Status: "failed", ThreadID: threadID,
			Summary: limitText(summary, 16000), Error: requestErr.Error()}
	}
	if err != nil {
		return machineJobResult{Status: "failed", ThreadID: threadID,
			Summary: limitText(summary, 16000), Error: err.Error()}
	}
	if status != "completed" && status != "complete" && status != "idle" {
		return machineJobResult{Status: "failed", ThreadID: threadID,
			Summary: limitText(summary, 16000), Error: "turn status: " + status}
	}
	if summary != "" {
		if err := os.WriteFile(responseFile, []byte(summary+"\n"), 0o600); err != nil {
			return machineJobResult{Status: "failed", ThreadID: threadID, Error: err.Error()}
		}
	}
	return machineJobResult{Status: "completed", ThreadID: threadID,
		Summary: limitText(strings.TrimSpace(summary), 16000)}
}

func nestedMachineString(value map[string]any, keys ...string) string {
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
