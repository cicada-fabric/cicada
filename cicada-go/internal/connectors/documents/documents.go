// Package documents normalizes signed document events before they enter
// Control. Provider credentials, cookies, and arbitrary document metadata are
// deliberately discarded at this boundary.
package documents

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const MaxDocumentBytes = 4 << 20

// Normalize accepts a provider-neutral document webhook. A data/document/file
// wrapper is flattened once, and only fields useful for search and triage are
// retained in the normalized payload.
func Normalize(raw []byte) (externalID, eventType string, payload []byte, err error) {
	if len(raw) == 0 || len(raw) > MaxDocumentBytes || !json.Valid(raw) {
		return "", "", nil, errors.New("document event must be valid JSON and at most 4 MiB")
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		return "", "", nil, err
	}
	input = unwrap(input)
	externalID = firstString(input, "document_id", "file_id", "id")
	if externalID == "" || len(externalID) > 512 {
		return "", "", nil, errors.New("document event requires document_id, file_id, or id under 512 bytes")
	}
	eventType = normalizeEventType(firstString(input, "event_type", "type", "kind"))
	if eventType == "" {
		eventType = "document.updated"
	}
	if eventType != "document.created" && eventType != "document.updated" && eventType != "document.deleted" {
		return "", "", nil, fmt.Errorf("unsupported document event type: %s", eventType)
	}
	value := map[string]any{
		"provider":    "documents",
		"external_id": externalID,
		"event_type":  eventType,
		"title":       bounded(firstString(input, "title", "name", "filename"), 4096),
		"text":        bounded(firstString(input, "text", "content", "body", "snippet"), 256*1024),
		"url":         bounded(firstString(input, "url", "web_url", "permalink"), 4096),
		"mime_type":   bounded(firstString(input, "mime_type", "content_type", "type"), 256),
		"owner":       bounded(firstString(input, "owner", "author", "created_by"), 1024),
		"timestamp":   bounded(firstString(input, "timestamp", "updated_at", "created_at"), 128),
	}
	payload, err = json.Marshal(value)
	return externalID, eventType, payload, err
}

func Signature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func unwrap(input map[string]json.RawMessage) map[string]json.RawMessage {
	for _, key := range []string{"data", "document", "file", "payload"} {
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
	case "", "created", "document.created", "file.created", "document_create":
		return "document.created"
	case "updated", "document.updated", "file.updated", "document_update":
		return "document.updated"
	case "deleted", "document.deleted", "file.deleted", "document_delete":
		return "document.deleted"
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
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &object) == nil {
			if strings.TrimSpace(object.ID) != "" {
				return strings.TrimSpace(object.ID)
			}
			if strings.TrimSpace(object.Name) != "" {
				return strings.TrimSpace(object.Name)
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
