// Package calendar normalizes webhook JSON or bounded iCalendar events for
// Control triage. It never accepts credentials or arbitrary provider data.
package calendar

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const MaxEventBytes = 1 << 20

func Normalize(raw []byte) (externalID, eventType string, payload []byte, err error) {
	if len(raw) == 0 || len(raw) > MaxEventBytes {
		return "", "", nil, errors.New("calendar event must be at most 1 MiB")
	}
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "BEGIN:VCALENDAR") {
		return normalizeICS(string(raw))
	}
	if !json.Valid(raw) {
		return "", "", nil, errors.New("calendar event must be valid JSON or iCalendar")
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		return "", "", nil, err
	}
	externalID = firstString(input, "id", "uid", "event_id")
	if externalID == "" || len(externalID) > 512 {
		return "", "", nil, errors.New("calendar event requires id or uid under 512 bytes")
	}
	eventType = firstString(input, "event_type", "type")
	if eventType == "" {
		eventType = "event.created"
	}
	if eventType != "event.created" && eventType != "event.updated" && eventType != "event.cancelled" {
		return "", "", nil, fmt.Errorf("unsupported calendar event type: %s", eventType)
	}
	value := normalizedValue(externalID, eventType, input)
	payload, err = json.Marshal(value)
	return externalID, eventType, payload, err
}

func normalizeICS(raw string) (string, string, []byte, error) {
	fields := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "BEGIN:") || strings.HasPrefix(line, "END:") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToUpper(strings.TrimSpace(strings.SplitN(key, ";", 2)[0]))
		if _, exists := fields[key]; !exists {
			fields[key] = strings.TrimSpace(value)
		}
	}
	id := bounded(fields["UID"], 512)
	if id == "" {
		return "", "", nil, errors.New("iCalendar event requires UID")
	}
	kind := "event.created"
	switch strings.ToUpper(fields["STATUS"]) {
	case "CANCELLED":
		kind = "event.cancelled"
	case "CONFIRMED", "TENTATIVE":
		kind = "event.updated"
	}
	value := map[string]any{
		"provider": "calendar", "external_id": id, "event_type": kind,
		"summary": bounded(fields["SUMMARY"], 4096), "description": bounded(fields["DESCRIPTION"], 64*1024),
		"start": bounded(fields["DTSTART"], 128), "end": bounded(fields["DTEND"], 128),
		"location": bounded(fields["LOCATION"], 4096), "organizer": bounded(fields["ORGANIZER"], 4096),
		"status": bounded(fields["STATUS"], 64),
	}
	payload, err := json.Marshal(value)
	return id, kind, payload, err
}

func normalizedValue(id, kind string, input map[string]json.RawMessage) map[string]any {
	return map[string]any{
		"provider": "calendar", "external_id": id, "event_type": kind,
		"summary":     bounded(firstString(input, "summary", "title"), 4096),
		"description": bounded(firstString(input, "description", "details"), 64*1024),
		"start":       bounded(firstString(input, "start", "starts_at"), 128),
		"end":         bounded(firstString(input, "end", "ends_at"), 128),
		"location":    bounded(firstString(input, "location"), 4096),
		"organizer":   bounded(firstString(input, "organizer"), 4096),
		"status":      bounded(firstString(input, "status"), 64),
	}
}

func Signature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func firstString(fields map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		var value string
		if raw, ok := fields[name]; ok && json.Unmarshal(raw, &value) == nil && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
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
