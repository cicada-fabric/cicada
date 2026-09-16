package control

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

const (
	externalRequestTimeout = 20 * time.Second
	maxExternalResponse    = 512 * 1024
)

// ExecuteExternalAction is the credential-free HTTP executor for read-only
// external actions. Authenticated browser and mutating actions remain queued
// for a separately isolated executor after their approval has been resolved.
func (c *Control) ExecuteExternalAction(ctx context.Context, id string) (*store.ExternalAction, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	action, err := c.store.GetExternalAction(strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	if action == nil {
		return nil, errors.New("external action not found")
	}
	if action.Status != "queued" {
		return action, fmt.Errorf("external action is %s", action.Status)
	}
	if !readOnlyExternalAction(action.Kind, action.Method) {
		return action, errors.New("action kind and method require an isolated executor")
	}
	target, err := validateExternalURL(action.URL)
	if err != nil {
		return action, err
	}
	if err := validateResolvedHost(ctx, target); err != nil {
		return action, err
	}
	claimed, err := c.ClaimExternalAction(action.ID)
	if err != nil {
		return action, err
	}
	if claimed == nil || claimed.Status != "running" {
		return claimed, fmt.Errorf("external action could not be claimed")
	}
	requestContext, cancel := context.WithTimeout(ctx, externalRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, action.Method, target.String(), nil)
	if err != nil {
		return c.failExternalAction(action.ID, err)
	}
	request.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.1")
	request.Header.Set("User-Agent", "cicada-control/0.3")
	client := safeExternalHTTPClient()
	response, err := client.Do(request)
	if err != nil {
		return c.failExternalAction(action.ID, err)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxExternalResponse+1))
	if readErr != nil {
		return c.failExternalAction(action.ID, readErr)
	}
	truncated := len(body) > maxExternalResponse
	if truncated {
		body = body[:maxExternalResponse]
	}
	result, marshalErr := json.Marshal(map[string]any{
		"status_code":  response.StatusCode,
		"content_type": response.Header.Get("Content-Type"),
		"body_base64":  base64.RawStdEncoding.EncodeToString(body),
		"sha256":       digest(body),
		"truncated":    truncated,
	})
	if marshalErr != nil {
		return c.failExternalAction(action.ID, marshalErr)
	}
	completed, completeErr := c.CompleteExternalAction(action.ID, result, responseError(response))
	if completeErr != nil {
		return nil, completeErr
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return completed, fmt.Errorf("external action returned %s", response.Status)
	}
	return completed, nil
}

func readOnlyExternalAction(kind, method string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	switch kind {
	case "fetch", "search", "download":
		return true
	default:
		return false
	}
}

func (c *Control) failExternalAction(id string, actionErr error) (*store.ExternalAction, error) {
	failed, err := c.CompleteExternalAction(id, json.RawMessage(`{}`), actionErr.Error())
	if err != nil {
		return nil, err
	}
	return failed, actionErr
}

func responseError(response *http.Response) string {
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		return ""
	}
	return "remote response: " + response.Status
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
