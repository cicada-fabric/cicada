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
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/buildinfo"
	"github.com/cicada-ai/cicada/internal/codexapp"
	"github.com/cicada-ai/cicada/internal/nodelock"
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
	Created    bool   `json:"created,omitempty"`
}

const machineCodexApprovalTurnIdentityWait = 15 * time.Second

// machineCodexApprovalIdentity records only identities confirmed by the
// app-server responses. Approval callbacks may run before turn/start returns,
// so they wait on turnReady while the main Request call continues reading.
type machineCodexApprovalIdentity struct {
	mu           sync.RWMutex
	threadID     string
	turnID       string
	turnReady    chan struct{}
	turnResolved bool
	turnErr      error
}

func newMachineCodexApprovalIdentity() *machineCodexApprovalIdentity {
	return &machineCodexApprovalIdentity{turnReady: make(chan struct{})}
}

func validMachineCodexIdentity(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}

func (identity *machineCodexApprovalIdentity) confirmThread(threadID string) error {
	if identity == nil || !validMachineCodexIdentity(threadID) {
		return errors.New("Codex did not return a valid native Thread ID")
	}
	identity.mu.Lock()
	defer identity.mu.Unlock()
	if identity.threadID != "" && identity.threadID != threadID {
		return errors.New("Codex changed the confirmed native Thread ID")
	}
	identity.threadID = threadID
	return nil
}

func (identity *machineCodexApprovalIdentity) confirmTurn(turnID string) error {
	if identity == nil {
		return errors.New("Codex native Thread or Turn identity is unavailable")
	}
	identity.mu.Lock()
	defer identity.mu.Unlock()
	if identity.turnResolved {
		return errors.New("Codex native Turn identity was already resolved")
	}
	identity.turnResolved = true
	if identity.threadID == "" || !validMachineCodexIdentity(turnID) {
		identity.turnErr = errors.New("Codex did not confirm a valid native Turn ID")
	} else {
		identity.turnID = turnID
	}
	close(identity.turnReady)
	return identity.turnErr
}

func (identity *machineCodexApprovalIdentity) abortTurn() {
	if identity == nil {
		return
	}
	identity.mu.Lock()
	defer identity.mu.Unlock()
	if identity.turnResolved {
		return
	}
	identity.turnResolved = true
	identity.turnErr = errors.New("Codex did not confirm the native Turn ID")
	close(identity.turnReady)
}

func (identity *machineCodexApprovalIdentity) confirmed(ctx context.Context) (string, string, error) {
	if identity == nil {
		return "", "", errors.New("Codex native Thread or Turn identity is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	timer := time.NewTimer(machineCodexApprovalTurnIdentityWait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	case <-timer.C:
		return "", "", errors.New("timed out waiting for native Turn confirmation")
	case <-identity.turnReady:
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	identity.mu.RLock()
	defer identity.mu.RUnlock()
	if identity.turnErr != nil {
		return "", "", identity.turnErr
	}
	if !validMachineCodexIdentity(identity.threadID) || !validMachineCodexIdentity(identity.turnID) {
		return "", "", errors.New("Codex native Thread or Turn identity is unavailable")
	}
	return identity.threadID, identity.turnID, nil
}

func machineCodexApprovalDecision(ctx context.Context, identity *machineCodexApprovalIdentity,
	bridge machineApprovalBridge, job machineJob, rpcID any, method string, params map[string]any) (string, error) {
	requestThread, threadOK := params["threadId"].(string)
	requestTurn, turnOK := params["turnId"].(string)
	if !threadOK || !turnOK || !validMachineCodexIdentity(requestThread) ||
		!validMachineCodexIdentity(requestTurn) {
		return "", errors.New("Codex approval request has incomplete native Thread or Turn identity")
	}
	threadID, turnID, err := identity.confirmed(ctx)
	if err != nil {
		return "", err
	}
	if requestThread != threadID || requestTurn != turnID {
		return "", errors.New("Codex approval targets a different native Thread or Turn")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return bridge.requestDecision(ctx, job, rpcID, method, params)
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

func acquireManagedMachineCodexWriter(ctx context.Context, job machineJob,
	nativeID string) (*nodelock.NativeWriterLock, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok || hub.HubID == "" || hub.NodeID == "" || hub.WriterRoot == "" || hub.WriterScope == "" ||
		(job.MachineID != "" && job.MachineID != hub.NodeID) {
		return nil, errors.New("managed Codex execution lacks its trusted Hub writer scope")
	}
	writer, err := nodelock.AcquireNativeWriter(ctx, hub.WriterRoot, hub.WriterScope, "codex", nativeID)
	if err != nil {
		return nil, fmt.Errorf("acquire managed native writer: %w", err)
	}
	return writer, nil
}

func executeMachineCodexWithApproval(ctx context.Context, job machineJob, workspace, responseFile string,
	bridge machineApprovalBridge) (result machineJobResult) {
	runCtx, cancel := context.WithCancel(ctx)
	approvalIdentity := newMachineCodexApprovalIdentity()
	var approvalErr error
	var approvalMu sync.Mutex
	threadID := job.ThreadID
	var app *codexapp.Client
	var nativeWriter *nodelock.NativeWriterLock
	var resourceExecution *nodelock.ResourceExecution
	var resourceRequest nodelock.ResourceExecutionRequest
	releaseWriter := true
	defer func() {
		approvalIdentity.abortTurn()
		cancel()
		var stopErr error
		if app != nil {
			stopErr = app.CloseAndWait()
			app = nil
		}
		if resourceExecution != nil {
			result.providerStarted = true
			if stopErr == nil {
				stopErr = confirmMachineNodeResourceStop(resourceExecution, resourceRequest)
			}
			if stopErr != nil {
				_ = resourceExecution.Quarantine()
				result.ResourceStopState = machineResourceStopUnverified
			}
		}
		if stopErr != nil {
			quarantineMachineNativeWriter(nativeWriter)
			releaseWriter = false
			if result.Status != "completed" && result.Error == "" {
				result.Error = "Codex app-server stopped producing a business result; resource stop remains unverified"
			}
		}
		if result.ResourceStopState == machineResourceStopUnverified {
			quarantineMachineNativeWriter(nativeWriter)
			releaseWriter = false
		}
		if nativeWriter != nil && releaseWriter {
			if err := nativeWriter.CheckCurrent(); err != nil {
				result = machineJobResult{Status: "failed", ThreadID: threadID,
					Error: "native writer ownership changed before Worker result publication"}
			}
			_ = nativeWriter.Close()
		}
	}()
	acquireWriter := func(nativeID string) error {
		writer, err := acquireManagedMachineCodexWriter(runCtx, job, nativeID)
		if err != nil {
			return err
		}
		nativeWriter = writer
		return nil
	}
	// Existing native IDs are locked before the app-server can resume them.
	// New threads receive unique IDs from the Runtime, then acquire the same
	// shared lease before turn/start.
	if threadID != "" {
		if err := acquireWriter(threadID); err != nil {
			return machineJobResult{Status: "failed", ThreadID: threadID, Error: err.Error()}
		}
	}
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
		} else {
			decision, err = machineCodexApprovalDecision(runCtx, approvalIdentity,
				bridge, job, id, method, params)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Node approval request failed cause=%s\n", machineApprovalFailureCause(err))
			approvalMu.Lock()
			approvalErr = err
			approvalMu.Unlock()
			decision = "decline"
		}
		return map[string]any{"decision": decision}
	}
	var starter codexapp.ProcessStarter
	var waiter codexapp.ProcessWaiter
	if hub, managed := machineHubFrom(runCtx); managed {
		if job.executionID == "" || job.providerID == "" || job.leaseID == "" ||
			(job.resourceID == "" && job.fencingEpoch != 0) {
			return machineJobResult{Status: "failed", ThreadID: threadID,
				Error: "managed Codex app-server lacks its durable provider execution identity"}
		}
		if job.resourceID != "" {
			if hub.ResourceExecutions == nil || job.fencingEpoch <= 0 {
				return machineJobResult{Status: "failed", ThreadID: threadID,
					Error: "managed Codex app-server physical-resource lease lacks its trusted execution fence"}
			}
			resourceRequest = nodelock.ResourceExecutionRequest{ResourceID: job.resourceID,
				LeaseID: job.leaseID, FencingEpoch: job.fencingEpoch, ExecutionID: job.executionID}
			starter = func(command *exec.Cmd) error {
				var startErr error
				resourceExecution, startErr = hub.ResourceExecutions.StartCommand(resourceRequest, command)
				return startErr
			}
			waiter = func(_ *exec.Cmd) error {
				if resourceExecution == nil {
					return errors.New("managed Codex root process has no resource execution owner")
				}
				return resourceExecution.Wait()
			}
		}
	}
	var err error
	app, err = codexapp.StartAsyncWithLifecycle(runCtx, envOr("CICADA_CODEX_BIN", "codex"), workspace,
		childEnv, nil, onRequest, starter, waiter)
	if err != nil {
		return machineJobResult{Status: "failed", Error: err.Error()}
	}
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
			"approvalsReviewer": "user",
		})
		if err != nil {
			return machineJobResult{Status: "failed", Error: err.Error()}
		}
		threadID = nestedMachineString(result, "thread", "id")
		if err := approvalIdentity.confirmThread(threadID); err != nil {
			return machineJobResult{Status: "failed", Error: err.Error()}
		}
		if err := acquireWriter(threadID); err != nil {
			return machineJobResult{Status: "failed", ThreadID: threadID, Error: err.Error()}
		}
	} else {
		result, err := app.Request(runCtx, "thread/resume", map[string]any{
			"threadId": threadID, "model": model, "cwd": workspace,
			"approvalPolicy": "on-request", "approvalsReviewer": "user",
		})
		if err != nil {
			return machineJobResult{Status: "failed", ThreadID: threadID, Error: err.Error()}
		}
		actual := nestedMachineString(result, "thread", "id")
		if actual != threadID {
			return machineJobResult{Status: "failed", ThreadID: threadID,
				Error: "Codex did not confirm the exact native Thread on resume"}
		}
		if err := approvalIdentity.confirmThread(actual); err != nil {
			return machineJobResult{Status: "failed", ThreadID: threadID, Error: err.Error()}
		}
	}
	turnResult, err := app.Request(runCtx, "turn/start", map[string]any{
		"threadId": threadID,
		"input":    []any{map[string]any{"type": "text", "text": job.Prompt}},
		"cwd":      workspace, "approvalPolicy": "on-request",
		"model": model, "approvalsReviewer": "user",
	})
	if err != nil {
		return machineJobResult{Status: "failed", ThreadID: threadID, Error: err.Error()}
	}
	if err := approvalIdentity.confirmTurn(nestedMachineString(turnResult, "turn", "id")); err != nil {
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
		if err := nativeWriter.CheckCurrent(); err != nil {
			return machineJobResult{Status: "failed", ThreadID: threadID,
				Error: "native writer ownership changed before Worker result publication"}
		}
		if err := os.WriteFile(responseFile, []byte(summary+"\n"), 0o600); err != nil {
			return machineJobResult{Status: "failed", ThreadID: threadID, Error: err.Error()}
		}
	}
	return machineJobResult{Status: "completed", ThreadID: threadID,
		Summary: limitText(strings.TrimSpace(summary), 16000)}
}

func machineApprovalFailureCause(err error) string {
	if err == nil {
		return "none"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "different worker attempt"):
		return "worker_attempt_mismatch"
	case strings.Contains(message, "different native thread") ||
		strings.Contains(message, "native thread or turn") ||
		strings.Contains(message, "incomplete native identity") ||
		strings.Contains(message, "native turn id") ||
		strings.Contains(message, "native thread id"):
		return "native_identity_mismatch"
	case strings.Contains(message, "not offered"):
		return "decision_not_offered"
	case strings.Contains(message, "approval") && strings.Contains(message, "unavailable"):
		return "approval_unavailable"
	case strings.Contains(message, "http 401") || strings.Contains(message, "unauthorized"):
		return "node_authorization"
	case strings.Contains(message, "http 409") || strings.Contains(message, "conflict") || strings.Contains(message, "stale"):
		return "stale_or_conflict"
	case strings.Contains(message, "http "):
		return "hub_http_error"
	case strings.Contains(message, "retry") || strings.Contains(message, "context deadline") ||
		strings.Contains(message, "timed out waiting") || strings.Contains(message, "context canceled"):
		return "retry_or_timeout"
	default:
		return "approval_protocol"
	}
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
