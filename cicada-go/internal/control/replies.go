package control

import (
	"bytes"
	"context"
	"crypto/hmac"
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

const maxReplyText = 64 * 1024

// ExternalReplyInput is the only Control-side input needed to request a
// provider reply. The target URL is an operator-owned connector callback; it
// must be approved before any network request is made.
type ExternalReplyInput struct {
	GoalID      string `json:"goal_id"`
	WorkerID    string `json:"worker_id"`
	Connector   string `json:"connector"`
	EventID     string `json:"event_id"`
	CallbackURL string `json:"callback_url"`
	Text        string `json:"text"`
}

func (c *Control) RequestExternalReply(input ExternalReplyInput) (*store.ExternalAction, error) {
	connector := strings.ToLower(strings.TrimSpace(input.Connector))
	if connector == "" {
		return nil, errors.New("connector is required")
	}
	switch connector {
	case "email", "calendar", "telegram", "x", "wechat", "qq", "slack", "discord":
	default:
		return nil, fmt.Errorf("unsupported reply connector: %s", connector)
	}
	event, err := c.store.GetExternalEvent(strings.TrimSpace(input.EventID))
	if err != nil {
		return nil, err
	}
	if event == nil {
		return nil, errors.New("external event not found")
	}
	if event.Connector != connector {
		return nil, errors.New("reply connector does not match external event")
	}
	text := strings.TrimSpace(input.Text)
	if text == "" || len(text) > maxReplyText {
		return nil, errors.New("reply text must be 1-65536 bytes")
	}
	if _, err := validateExternalURL(input.CallbackURL); err != nil {
		return nil, fmt.Errorf("validate reply callback: %w", err)
	}
	goalID := strings.TrimSpace(input.GoalID)
	if goalID == "" {
		goalID = event.GoalID
	}
	payload, err := json.Marshal(map[string]string{
		"connector": connector, "event_id": event.ID, "text": text,
	})
	if err != nil {
		return nil, err
	}
	return c.RequestExternalAction(ExternalActionInput{
		GoalID: goalID, WorkerID: strings.TrimSpace(input.WorkerID), Kind: "reply",
		Method: http.MethodPost, URL: input.CallbackURL, Payload: payload,
	})
}

// ExecuteExternalReply sends an approved reply to the operator-owned
// connector callback. The callback receives only normalized JSON and a
// connector-specific HMAC; provider credentials stay outside Control.
func (c *Control) ExecuteExternalReply(ctx context.Context, id string) (*store.ExternalAction, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	action, err := c.store.GetExternalAction(strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	if action == nil {
		return nil, errors.New("external reply not found")
	}
	if action.Kind != "reply" {
		return action, errors.New("external action is not a reply")
	}
	if action.Status != "queued" {
		return action, fmt.Errorf("external reply is %s", action.Status)
	}
	target, err := validateExternalURL(action.URL)
	if err != nil {
		return action, err
	}
	if err := validateResolvedHost(ctx, target); err != nil {
		return action, err
	}
	var envelope struct {
		Connector string `json:"connector"`
		EventID   string `json:"event_id"`
		Text      string `json:"text"`
	}
	if err := json.Unmarshal(action.Payload, &envelope); err != nil || envelope.Connector == "" || envelope.EventID == "" || envelope.Text == "" {
		return action, errors.New("reply payload is invalid")
	}
	secret := c.webhookSecret(envelope.Connector)
	if strings.TrimSpace(secret) == "" {
		return action, errors.New("reply connector secret is not configured")
	}
	claimed, err := c.ClaimExternalAction(action.ID)
	if err != nil {
		return action, err
	}
	if claimed == nil || claimed.Status != "running" {
		return claimed, errors.New("external reply could not be claimed")
	}
	requestContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, target.String(), bytes.NewReader(action.Payload))
	if err != nil {
		return c.failExternalAction(action.ID, err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.1")
	request.Header.Set("User-Agent", "cicada-control/0.3")
	request.Header.Set("X-Cicada-Reply-Event-ID", envelope.EventID)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(action.Payload)
	request.Header.Set("X-Cicada-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response, err := safeExternalHTTPClient().Do(request)
	if err != nil {
		return c.failExternalAction(action.ID, err)
	}
	defer response.Body.Close()
	resultBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxExternalResponse+1))
	if readErr != nil {
		return c.failExternalAction(action.ID, readErr)
	}
	truncated := len(resultBody) > maxExternalResponse
	if truncated {
		resultBody = resultBody[:maxExternalResponse]
	}
	result, marshalErr := json.Marshal(map[string]any{
		"status_code": response.StatusCode, "body_base64": base64.RawStdEncoding.EncodeToString(resultBody),
		"truncated": truncated,
	})
	if marshalErr != nil {
		return c.failExternalAction(action.ID, marshalErr)
	}
	completed, completeErr := c.CompleteExternalAction(action.ID, result, responseError(response))
	if completeErr != nil {
		return nil, completeErr
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return completed, fmt.Errorf("reply callback returned %s", response.Status)
	}
	return completed, nil
}
