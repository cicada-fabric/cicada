package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	groupSpaceMessagePayloadType = "cicada.group-space-message"
	groupSpaceMessagePayloadV1   = 1
	groupSpaceMessageRefLimit    = 8
)

func groupSpaceMessageRefsSchema() map[string]any {
	return map[string]any{"type": "array", "maxItems": groupSpaceMessageRefLimit,
		"items": map[string]any{"type": "object", "properties": map[string]any{
			"record_id": map[string]any{"type": "string", "description": "Exact record ID from the current selected Group"},
			"kind":      map[string]any{"type": "string", "enum": []string{"JOURNAL", "TOPIC", "REPLY", "TOPIC_STATUS"}},
		}, "required": []string{"record_id", "kind"}, "additionalProperties": false}}
}

type groupSpaceMessageReference struct {
	GroupID  string `json:"group_id"`
	RecordID string `json:"record_id"`
	Sequence int64  `json:"sequence"`
	Kind     string `json:"kind"`
	TopicID  string `json:"topic_id,omitempty"`
}

type groupSpaceMessagePayload struct {
	Type       string                       `json:"type"`
	Version    int                          `json:"version"`
	Body       string                       `json:"body"`
	RecordRefs []groupSpaceMessageReference `json:"record_refs,omitempty"`
}

type selectedGroupSpaceMessageReference struct {
	RecordID string
	Kind     string
}

func parseGroupSpaceReferenceRequest(raw any) ([]selectedGroupSpaceMessageReference, error) {
	if raw == nil {
		return nil, nil
	}
	items, ok := raw.([]any)
	if !ok || len(items) == 0 || len(items) > groupSpaceMessageRefLimit {
		return nil, errors.New("record_refs must contain 1 to 8 exact readable Journal or topic records")
	}
	refs := make([]selectedGroupSpaceMessageReference, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok || len(object) != 2 {
			return nil, fmt.Errorf("record_refs[%d] must contain only record_id and kind", index)
		}
		recordID, _ := object["record_id"].(string)
		kind, _ := object["kind"].(string)
		if recordID == "" || len(recordID) > 256 || strings.TrimSpace(recordID) != recordID ||
			!validGroupSpaceReferenceKind(kind) {
			return nil, fmt.Errorf("record_refs[%d] is not an exact readable GroupSpace record locator", index)
		}
		if _, duplicate := seen[recordID]; duplicate {
			return nil, errors.New("record_refs contains a duplicate record_id")
		}
		seen[recordID] = struct{}{}
		refs = append(refs, selectedGroupSpaceMessageReference{RecordID: recordID, Kind: kind})
	}
	return refs, nil
}

// encodeSelectedGroupSpaceReferences resolves each supplied ID through the
// current Node GroupSpace read path. Only the exact visible record coordinate
// is sealed with the message; no GroupSpace body or Hub-readable metadata is
// added to the relay request.
func (m *mcpServer) encodeSelectedGroupSpaceReferences(body string, raw any) (string, error) {
	requested, err := parseGroupSpaceReferenceRequest(raw)
	if err != nil {
		return "", err
	}
	if len(requested) == 0 {
		return body, nil
	}
	if strings.TrimSpace(body) == "" {
		return "", errors.New("record_refs must contain 1 to 8 exact readable Journal or topic records and a message body")
	}
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return "", err
	}
	refs := make([]groupSpaceMessageReference, 0, len(requested))
	for index, requestedRef := range requested {
		recordID, kind := requestedRef.RecordID, requestedRef.Kind
		tool := "cicada_journal_get"
		if kind != "JOURNAL" {
			tool = "cicada_discussion_get"
		}
		result, err := m.readGroupSpaceMCP(tool, map[string]any{"record_id": recordID})
		if err != nil {
			return "", fmt.Errorf("record_refs[%d] is not currently readable in the selected Group: %w", index, err)
		}
		local, ok := result.(*groupSpaceLocalResult)
		if !ok || local.Record == nil || local.Record.GroupID != scope.GroupID ||
			local.Record.RecordID != recordID || local.Record.Sequence <= 0 || local.Record.Kind != kind {
			return "", fmt.Errorf("record_refs[%d] did not resolve to the requested current GroupSpace record", index)
		}
		ref := groupSpaceMessageReference{GroupID: local.Record.GroupID,
			RecordID: local.Record.RecordID, Sequence: local.Record.Sequence, Kind: local.Record.Kind}
		if kind != "JOURNAL" {
			if local.Record.TopicID == "" || (kind == "TOPIC" && local.Record.TopicID != recordID) {
				return "", fmt.Errorf("record_refs[%d] Discussion topic identity changed", index)
			}
			ref.TopicID = local.Record.TopicID
		}
		refs = append(refs, ref)
	}
	encoded, err := json.Marshal(groupSpaceMessagePayload{Type: groupSpaceMessagePayloadType,
		Version: groupSpaceMessagePayloadV1, Body: body, RecordRefs: refs})
	if err != nil || len(encoded) > 64*1024 {
		return "", errors.New("sealed message with GroupSpace references exceeds 64 KiB")
	}
	return string(encoded), nil
}

// groupSpaceMessageIntentMatches compares an immutable outbox envelope with a
// retried caller request without re-reading records or changing their saved
// sequence coordinates. That matters after an uncertain response or later
// ACL/history changes: recovery must replay the exact sealed operation.
func groupSpaceMessageIntentMatches(saved, requestedBody string, requested []selectedGroupSpaceMessageReference) bool {
	body, refs, err := decodeGroupSpaceMessagePayload([]byte(saved))
	if err != nil || body != requestedBody || len(refs) != len(requested) {
		return false
	}
	for index, ref := range refs {
		if ref.RecordID != requested[index].RecordID || ref.Kind != requested[index].Kind {
			return false
		}
	}
	return true
}

func decodeGroupSpaceMessagePayload(plaintext []byte) (string, []groupSpaceMessageReference, error) {
	if len(plaintext) == 0 || len(plaintext) > 64*1024 {
		return "", nil, errors.New("sealed message body is outside the 64 KiB limit")
	}
	if !hasGroupSpaceMessageMarker(plaintext) {
		return string(plaintext), nil, nil
	}
	var payload groupSpaceMessagePayload
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return "", nil, errors.New("sealed GroupSpace reference envelope is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) ||
		payload.Type != groupSpaceMessagePayloadType || payload.Version != groupSpaceMessagePayloadV1 ||
		strings.TrimSpace(payload.Body) == "" || len([]byte(payload.Body)) > 64*1024 ||
		len(payload.RecordRefs) == 0 || len(payload.RecordRefs) > groupSpaceMessageRefLimit {
		return "", nil, errors.New("sealed GroupSpace reference envelope has invalid fields")
	}
	seen := make(map[string]struct{}, len(payload.RecordRefs))
	for _, ref := range payload.RecordRefs {
		if ref.GroupID == "" || len(ref.GroupID) > 256 || strings.TrimSpace(ref.GroupID) != ref.GroupID ||
			ref.RecordID == "" || len(ref.RecordID) > 256 || strings.TrimSpace(ref.RecordID) != ref.RecordID ||
			ref.Sequence <= 0 || !validGroupSpaceReferenceKind(ref.Kind) ||
			(ref.Kind == "TOPIC" && ref.TopicID != ref.RecordID) ||
			(ref.Kind != "JOURNAL" && ref.TopicID == "") ||
			(ref.Kind == "JOURNAL" && ref.TopicID != "") {
			return "", nil, errors.New("sealed GroupSpace reference coordinate is invalid")
		}
		if _, duplicate := seen[ref.GroupID+"\x00"+ref.RecordID]; duplicate {
			return "", nil, errors.New("sealed GroupSpace reference is duplicated")
		}
		seen[ref.GroupID+"\x00"+ref.RecordID] = struct{}{}
	}
	return payload.Body, payload.RecordRefs, nil
}

func validGroupSpaceReferenceKind(kind string) bool {
	switch kind {
	case "JOURNAL", "TOPIC", "REPLY", "TOPIC_STATUS":
		return true
	default:
		return false
	}
}

// Read the discriminator token-by-token so truncated or otherwise malformed
// reserved envelopes fail closed instead of falling back to legacy plain peer
// text. The fallback byte check only reserves this exact marker inside a JSON
// object when token parsing itself failed.
func hasGroupSpaceMessageMarker(plaintext []byte) bool {
	trimmed := bytes.TrimSpace(plaintext)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return bytes.Contains(trimmed, []byte(`"`+groupSpaceMessagePayloadType+`"`))
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return bytes.Contains(trimmed, []byte(`"`+groupSpaceMessagePayloadType+`"`))
		}
		if key == "type" {
			var marker string
			if err := decoder.Decode(&marker); err != nil {
				return bytes.Contains(trimmed, []byte(`"`+groupSpaceMessagePayloadType+`"`))
			}
			return marker == groupSpaceMessagePayloadType
		}
		var discard json.RawMessage
		if err := decoder.Decode(&discard); err != nil {
			return bytes.Contains(trimmed, []byte(`"`+groupSpaceMessagePayloadType+`"`))
		}
	}
	return false
}
