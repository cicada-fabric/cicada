package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type machineJob struct {
	WorkerID                string         `json:"worker_id"`
	GoalID                  string         `json:"goal_id"`
	MachineID               string         `json:"machine_id"`
	WorkspaceID             string         `json:"workspace_id,omitempty"`
	Harness                 string         `json:"harness"`
	WorkspaceSnapshotDigest string         `json:"workspace_snapshot_digest,omitempty"`
	Workspace               string         `json:"workspace"`
	ResponseFile            string         `json:"response_file"`
	ThreadID                string         `json:"thread_id"`
	Prompt                  string         `json:"prompt"`
	Resources               map[string]any `json:"resources"`
	Attempt                 int            `json:"attempt"`
}

type machineJobResult struct {
	Status, Summary, ThreadID, Error, WorkspaceRevision, WorkspaceSnapshotDigest string
}

type machineAPIError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *machineAPIError) Error() string {
	return fmt.Sprintf("Hub API returned %s: %s", e.Status, e.Body)
}

func pollMachineJobs(ctx context.Context, base, nodeID, nodeToken string) ([]machineJob, error) {
	var payload struct {
		Jobs []machineJob `json:"jobs"`
	}
	err := machineNodeAPIJSON(ctx, nodeWorkerJobsEndpoint(base, nodeID), http.MethodGet, nodeToken, nil, &payload)
	return payload.Jobs, err
}

func claimMachineJob(ctx context.Context, base, nodeID, nodeToken string, job machineJob) (machineJob, error) {
	var claimed machineJob
	endpoint := nodeWorkerJobEndpoint(base, nodeID, job.WorkerID, "claim")
	err := machineNodeAPIJSON(ctx, endpoint, http.MethodPost, nodeToken, map[string]string{}, &claimed)
	return claimed, err
}

func reportMachineJob(ctx context.Context, base, nodeID, nodeToken string, job machineJob, result machineJobResult) error {
	payload := map[string]any{
		"attempt": job.Attempt, "status": result.Status,
		"summary": limitText(result.Summary, 16000), "thread_id": result.ThreadID,
		"error":              limitText(result.Error, 4000),
		"workspace_revision": result.WorkspaceRevision,
	}
	endpoint := nodeWorkerJobEndpoint(base, nodeID, job.WorkerID, "result")
	return machineNodeAPIJSON(ctx, endpoint, http.MethodPost, nodeToken, payload, nil)
}

// reportMachineJobReliably keeps ownership of a completed execution while the
// Hub Node-scoped API is temporarily unavailable. A 404/409 means Hub has
// already moved the Worker forward, so repeating the result is unnecessary.
func reportMachineJobReliably(ctx context.Context, base, nodeID, nodeToken string, job machineJob, result machineJobResult, interval time.Duration) error {
	retryAfter := interval
	if retryAfter > 5*time.Second {
		retryAfter = 5 * time.Second
	}
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	for {
		err := reportMachineJob(ctx, base, nodeID, nodeToken, job, result)
		if err == nil || machineAPIHasStatus(err, http.StatusNotFound, http.StatusConflict) {
			return nil
		}
		var apiErr *machineAPIError
		if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
			return err
		}
		fmt.Fprintln(os.Stderr, "report machine job:", err)
		heartbeatErr := sendMachineNodeWorkerHeartbeat(ctx, base, nodeID, nodeToken, "busy", nil)
		if machineAPIHasStatus(heartbeatErr, http.StatusUnauthorized, http.StatusForbidden) {
			return nodeCredentialRevokedError(heartbeatErr)
		}
		timer := time.NewTimer(retryAfter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func nodeWorkerJobsEndpoint(base, nodeID string) string {
	return strings.TrimRight(base, "/") + "/v2/relay/nodes/" + urlPath(nodeID) + "/jobs"
}

func nodeWorkerJobEndpoint(base, nodeID, workerID, action string) string {
	return strings.TrimRight(base, "/") + "/v2/relay/nodes/" + urlPath(nodeID) + "/jobs/" + urlPath(workerID) + "/" + action
}

// machineNodeAPIJSON sends only the explicitly supplied Node bearer. These
// owner-scoped endpoints must never fall back to the Hub-wide API token.
func machineNodeAPIJSON(ctx context.Context, endpoint, method, nodeToken string, payload, target any) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(parsed.Path, "/v2/relay/nodes/") {
		return errors.New("Node bearer is restricted to Node-scoped Relay APIs")
	}
	nodeToken = strings.TrimSpace(nodeToken)
	if nodeToken == "" {
		return errors.New("Node credential is required for Node-scoped Worker APIs")
	}
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	if !machineHubOriginMatches(ctx, endpoint) {
		return errors.New("Node request escaped its pinned Hub origin")
	}
	request.Header.Set("Authorization", "CicadaNode "+nodeToken)
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: rejectNodeRedirect}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return &machineAPIError{StatusCode: response.StatusCode, Status: response.Status,
			Body: strings.TrimSpace(string(data))}
	}
	if target != nil && len(data) > 0 {
		return json.Unmarshal(data, target)
	}
	return nil
}

func sendMachineNodeWorkerHeartbeat(ctx context.Context, base, nodeID, nodeToken, status string, capabilities map[string]any) error {
	payload := map[string]any{}
	if status != "" {
		payload["status"] = status
	}
	if capabilities != nil {
		payload["capabilities"] = capabilities
	}
	return machineNodeAPIJSON(ctx, strings.TrimRight(base, "/")+"/v2/relay/nodes/"+urlPath(nodeID)+"/heartbeat",
		http.MethodPost, nodeToken, payload, nil)
}

func nodeCredentialRevokedError(err error) error {
	return fmt.Errorf("Node credential was revoked or rotated; stopping machine agent: %w", err)
}

func machineAPIHasStatus(err error, statuses ...int) bool {
	var apiErr *machineAPIError
	if !errors.As(err, &apiErr) {
		return false
	}
	for _, status := range statuses {
		if apiErr.StatusCode == status {
			return true
		}
	}
	return false
}

func machineAPIJSON(ctx context.Context, endpoint, method string, payload, target any) error {
	if !machineHubOriginMatches(ctx, endpoint) {
		return errors.New("Node request escaped its pinned Hub origin")
	}
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	nodeRoute := strings.Contains(request.URL.Path, "/v2/relay/nodes/") ||
		strings.HasPrefix(request.URL.Path, "/v2/fabric/node/networks/direct/")
	if nodeRoute {
		token := machineNodeTokenFor(ctx)
		if token == "" {
			return errors.New("CICADA_NODE_TOKEN or CICADA_NODE_TOKEN_FILE is required for Relay Node APIs")
		}
		request.Header.Set("Authorization", "CicadaNode "+token)
	} else {
		if hub, ok := machineHubFrom(ctx); ok && hub.MultiHub {
			return errors.New("Control management is unavailable in multi-Hub relay-only mode")
		}
		setMachineAuth(request)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if nodeRoute {
		client.CheckRedirect = rejectNodeRedirect
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &machineAPIError{
			StatusCode: response.StatusCode, Status: response.Status,
			Body: strings.TrimSpace(string(data)),
		}
	}
	if target != nil && len(data) > 0 {
		return json.Unmarshal(data, target)
	}
	return nil
}

func limitText(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[len(value)-max:]
}

func setMachineAuth(request *http.Request) {
	if token := clientAPIToken(); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
}

func machineNodeToken() string {
	if token := strings.TrimSpace(os.Getenv("CICADA_NODE_TOKEN")); token != "" {
		return token
	}
	path := strings.TrimSpace(os.Getenv("CICADA_NODE_TOKEN_FILE"))
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
func urlPath(value string) string { return url.PathEscape(value) }
