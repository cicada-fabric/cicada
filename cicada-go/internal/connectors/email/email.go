// Package email normalizes provider-neutral email webhook payloads before
// they enter Control. Provider credentials and arbitrary headers never cross
// this boundary.
package email

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

// Normalize accepts a small provider-neutral JSON object. It deliberately
// copies only fields useful to triage and drops provider-specific envelopes.
func Normalize(raw []byte) (externalID, eventType string, payload []byte, err error) {
	if len(raw) == 0 || len(raw) > MaxMessageBytes || !json.Valid(raw) {
		return "", "", nil, errors.New("email event must be valid JSON and at most 1 MiB")
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		return "", "", nil, err
	}
	externalID = firstString(input, "message_id", "id")
	if externalID == "" || len(externalID) > 512 {
		return "", "", nil, errors.New("email event requires message_id or id under 512 bytes")
	}
	eventType = firstString(input, "event_type", "type")
	if eventType == "" {
		eventType = "message.created"
	}
	if eventType != "message.created" && eventType != "message.updated" && eventType != "message.deleted" {
		return "", "", nil, fmt.Errorf("unsupported email event type: %s", eventType)
	}
	value := map[string]any{
		"provider": "email", "external_id": externalID,
		"thread_id":   bounded(firstString(input, "thread_id", "conversation_id"), 512),
		"from":        bounded(firstString(input, "from", "sender"), 1024),
		"to":          bounded(firstString(input, "to", "recipients"), 4096),
		"cc":          bounded(firstString(input, "cc"), 4096),
		"subject":     bounded(firstString(input, "subject"), 4096),
		"text":        bounded(firstString(input, "text", "body", "snippet"), 64*1024),
		"timestamp":   bounded(firstString(input, "timestamp", "date", "created_at"), 128),
		"in_reply_to": bounded(firstString(input, "in_reply_to", "in_reply_to_id"), 512),
	}
	payload, err = json.Marshal(value)
	if err != nil {
		return "", "", nil, err
	}
	return externalID, eventType, payload, nil
}

// Signature returns the HMAC header accepted by the Control connector API.
func Signature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func firstString(fields map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		value, ok := fields[name]
		if !ok {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) == nil && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
		var list []string
		if json.Unmarshal(value, &list) == nil {
			parts := make([]string, 0, len(list))
			for _, item := range list {
				if item = strings.TrimSpace(item); item != "" {
					parts = append(parts, item)
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, ", ")
			}
		}
		var object struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if json.Unmarshal(value, &object) == nil {
			if strings.TrimSpace(object.Email) != "" {
				if strings.TrimSpace(object.Name) != "" {
					return strings.TrimSpace(object.Name) + " <" + strings.TrimSpace(object.Email) + ">"
				}
				return strings.TrimSpace(object.Email)
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
