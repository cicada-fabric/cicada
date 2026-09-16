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
	WorkerID     string         `json:"worker_id"`
	GoalID       string         `json:"goal_id"`
	MachineID    string         `json:"machine_id"`
	Harness      string         `json:"harness"`
	Workspace    string         `json:"workspace"`
	ResponseFile string         `json:"response_file"`
	ThreadID     string         `json:"thread_id"`
	Prompt       string         `json:"prompt"`
	Resources    map[string]any `json:"resources"`
	Attempt      int            `json:"attempt"`
}

type machineJobResult struct {
	Status, Summary, ThreadID, Error string
}

type machineAPIError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *machineAPIError) Error() string {
	return fmt.Sprintf("Control returned %s: %s", e.Status, e.Body)
}

func pollMachineJobs(ctx context.Context, base, machineID string) ([]machineJob, error) {
	var payload struct {
		Jobs []machineJob `json:"jobs"`
	}
	err := machineAPIJSON(ctx, base+"/v1/machines/"+urlPath(machineID)+"/jobs", http.MethodGet, nil, &payload)
	return payload.Jobs, err
}

func claimMachineJob(ctx context.Context, base string, job machineJob) (machineJob, error) {
	var claimed machineJob
	err := machineAPIJSON(ctx, base+"/v1/workers/"+urlPath(job.WorkerID)+"/claim", http.MethodPost,
		map[string]string{"machine_id": job.MachineID}, &claimed)
	return claimed, err
}

func reportMachineJob(ctx context.Context, base string, job machineJob, result machineJobResult) error {
	payload := map[string]string{
		"machine_id": job.MachineID, "status": result.Status,
		"summary": limitText(result.Summary, 16000), "thread_id": result.ThreadID,
		"error": limitText(result.Error, 4000),
	}
	return machineAPIJSON(ctx, base+"/v1/workers/"+urlPath(job.WorkerID)+"/result", http.MethodPost, payload, nil)
}

// reportMachineJobReliably keeps ownership of a completed execution while the
// Control API is temporarily unavailable. A 404/409 means Control has already
// moved the worker forward, so repeating the result is unnecessary.
func reportMachineJobReliably(ctx context.Context, base string, job machineJob, result machineJobResult, interval time.Duration) error {
	retryAfter := interval
	if retryAfter > 5*time.Second {
		retryAfter = 5 * time.Second
	}
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	for {
		err := reportMachineJob(ctx, base, job, result)
		if err == nil || machineAPIHasStatus(err, http.StatusNotFound, http.StatusConflict) {
			return nil
		}
		var apiErr *machineAPIError
		if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
			return err
		}
		fmt.Fprintln(os.Stderr, "report machine job:", err)
		_ = machineAPI(ctx, base+"/v1/machines/"+urlPath(job.MachineID)+"/heartbeat", http.MethodPost, map[string]any{"status": "busy"})
		timer := time.NewTimer(retryAfter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
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
	if token := strings.TrimSpace(os.Getenv("CICADA_API_TOKEN")); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
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
func urlPath(value string) string { return url.PathEscape(value) }
