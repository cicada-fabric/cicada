// Package social normalizes inbound X, WeChat, and QQ message webhooks before
// they enter Control. Provider envelopes, credentials, and unknown fields are
// intentionally discarded at this boundary.
package social

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const MaxMessageBytes = 1 << 20

var supportedProviders = map[string]bool{"x": true, "wechat": true, "qq": true}

// Normalize returns an idempotency key, a normalized event type, and a small
// provider-neutral payload. It accepts either a direct event object or a
// provider wrapper with a data/message/event object.
func Normalize(provider string, raw []byte) (externalID, eventType string, payload []byte, err error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if !supportedProviders[provider] {
		return "", "", nil, fmt.Errorf("unsupported social connector: %s", provider)
	}
	if len(raw) == 0 || len(raw) > MaxMessageBytes || !json.Valid(raw) {
		return "", "", nil, errors.New("social event must be valid JSON and at most 1 MiB")
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		return "", "", nil, err
	}
	input = unwrap(input)
	externalID = firstString(input, "id", "message_id", "event_id", "update_id", "tweet_id")
	if externalID == "" || len(externalID) > 512 {
		return "", "", nil, errors.New("social event requires an id under 512 bytes")
	}
	eventType = normalizeEventType(firstString(input, "event_type", "type", "kind"))
	if eventType == "" {
		eventType = "message.created"
	}
	if eventType != "message.created" && eventType != "message.updated" && eventType != "message.deleted" {
		return "", "", nil, fmt.Errorf("unsupported social event type: %s", eventType)
	}
	value := map[string]any{
		"provider":        provider,
		"external_id":     externalID,
		"event_type":      eventType,
		"sender":          bounded(firstString(input, "sender", "from", "author", "author_id", "user_id"), 1024),
		"recipient":       bounded(firstString(input, "recipient", "to", "page_id", "bot_id"), 1024),
		"conversation_id": bounded(firstString(input, "conversation_id", "conversation", "thread_id", "chat_id"), 512),
		"text":            bounded(firstString(input, "text", "message", "body", "content", "full_text"), 64*1024),
		"timestamp":       bounded(firstString(input, "timestamp", "created_at", "updated_at", "date"), 128),
		"reply_to":        bounded(firstString(input, "reply_to", "in_reply_to", "in_reply_to_id"), 512),
	}
	payload, err = json.Marshal(value)
	return externalID, eventType, payload, err
}

// Signature returns the HMAC header accepted by the Control connector API.
func Signature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func unwrap(input map[string]json.RawMessage) map[string]json.RawMessage {
	for _, key := range []string{"data", "message", "event", "payload"} {
		raw, ok := input[key]
		if !ok {
			continue
		}
		var nested map[string]json.RawMessage
		if json.Unmarshal(raw, &nested) != nil {
			continue
		}
		for field, value := range nested {
			if _, exists := input[field]; !exists {
				input[field] = value
			}
		}
	}
	return input
}

func normalizeEventType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "message.created", "message_create", "message", "tweet.created", "tweet_create", "created":
		return "message.created"
	case "message.updated", "message_update", "tweet.updated", "tweet_update", "updated":
		return "message.updated"
	case "message.deleted", "message_delete", "tweet.deleted", "tweet_delete", "deleted":
		return "message.deleted"
	default:
		return strings.TrimSpace(value)
	}
}

func firstString(fields map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		raw, ok := fields[name]
		if !ok {
			continue
		}
		var text string
		if json.Unmarshal(raw, &text) == nil && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
		var number json.Number
		if json.Unmarshal(raw, &number) == nil && strings.TrimSpace(number.String()) != "" {
			return number.String()
		}
		var object struct {
			ID   json.RawMessage `json:"id"`
			Name string          `json:"name"`
			User string          `json:"username"`
		}
		if json.Unmarshal(raw, &object) == nil {
			if id := firstString(map[string]json.RawMessage{"id": object.ID}); id != "" {
				return id
			}
			if strings.TrimSpace(object.Name) != "" {
				return strings.TrimSpace(object.Name)
			}
			if strings.TrimSpace(object.User) != "" {
				return strings.TrimSpace(object.User)
			}
		}
	}
	return ""
}

func bounded(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return value[:max]
	}
	return value
}
