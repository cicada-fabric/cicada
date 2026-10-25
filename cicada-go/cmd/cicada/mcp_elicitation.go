package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
)

var (
	errMCPFormUnsupported = errors.New("MCP_FORM_UNSUPPORTED: this Host has not negotiated form elicitation; no peer was selected")
	errMCPFormDeclined    = errors.New("MCP_FORM_DECLINED: peer selection was declined; nothing was sent")
	errMCPFormCancelled   = errors.New("MCP_FORM_CANCELLED: peer selection was cancelled; nothing was sent")
	errMCPFormTimeout     = errors.New("MCP_FORM_TIMEOUT: peer selection expired; nothing was sent")
	errMCPFormInvalid     = errors.New("MCP_FORM_INVALID: the Host did not return an exact offered peer choice; nothing was sent")
	errMCPFormUnavailable = errors.New("MCP_FORM_UNAVAILABLE: peer selection requires its original active MCP tool call")
)

// Only opaque values and already-authorized display labels cross this seam.
// Neither this transport nor a Host response supplies a Cicada Actor or grant.
type mcpPeerFormOption struct{ ID, Label string }

type mcpElicitationReply struct {
	result  json.RawMessage
	invalid bool
}

// A missing or malformed capability never enables forms. Initialization is
// connection-scoped and cannot later upgrade an incompatible Host implicitly.
func (t *mcpStdioTransport) negotiate(params json.RawMessage) {
	if t == nil {
		return
	}
	var initialize struct {
		Capabilities struct {
			Elicitation map[string]json.RawMessage `json:"elicitation"`
		} `json:"capabilities"`
	}
	valid := json.Unmarshal(params, &initialize) == nil
	var form map[string]json.RawMessage
	valid = valid && json.Unmarshal(initialize.Capabilities.Elicitation["form"], &form) == nil && form != nil
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.negotiated {
		t.negotiated, t.formSupported = true, valid
	}
}

func (t *mcpStdioTransport) supportsPeerForm() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.negotiated && t.formSupported && t.ctx.Err() == nil
}

// elicitPeer returns one exact opaque option ID. It does not resolve a target,
// persist permission, send a peer message, or extend the original tool proof.
// Business code must revalidate its original Actor and snapshot after the wait.
func (t *mcpStdioTransport) elicitPeer(message string, options []mcpPeerFormOption) (string, error) {
	if t == nil {
		return "", errMCPFormUnsupported
	}
	choices := make(map[string]bool, len(options))
	items := make([]map[string]string, 0, len(options))
	if !mcpFormText(message, 4096) || len(options) == 0 || len(options) > 64 {
		return "", errMCPFormInvalid
	}
	for _, option := range options {
		if !mcpFormText(option.ID, 512) || !mcpFormText(option.Label, 2048) || choices[option.ID] {
			return "", errMCPFormInvalid
		}
		choices[option.ID] = true
		items = append(items, map[string]string{"const": option.ID, "title": option.Label})
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	id := "cicada-form-" + hex.EncodeToString(nonce[:])
	key := "s:" + id
	replies := make(chan mcpElicitationReply, 1)
	t.mu.Lock()
	if !t.negotiated || !t.formSupported {
		t.mu.Unlock()
		return "", errMCPFormUnsupported
	}
	call := t.active
	if call == nil || call.request.Method != "tools/call" || call.ctx.Err() != nil || len(t.pending) != 0 {
		t.mu.Unlock()
		return "", errMCPFormUnavailable
	}
	ctx, cancel := context.WithTimeout(call.ctx, t.formTimeout)
	call.form = true
	t.pending[key] = replies
	t.mu.Unlock()
	defer cancel()
	defer func() { t.mu.Lock(); delete(t.pending, key); t.mu.Unlock() }()
	if ctx.Err() != nil {
		return "", errMCPFormCancelled
	}
	request := map[string]any{"jsonrpc": "2.0", "id": id, "method": "elicitation/create", "params": map[string]any{
		"mode": "form", "message": message, "requestedSchema": map[string]any{
			"type": "object", "properties": map[string]any{"peer": map[string]any{"type": "string", "title": "Peer", "oneOf": items}},
			"required": []string{"peer"}, "additionalProperties": false,
		},
	}}
	if err := t.writeContext(ctx, request); err != nil {
		t.shutdown(err)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", errMCPFormTimeout
		}
		if call.ctx.Err() != nil {
			return "", errMCPFormCancelled
		}
		return "", errMCPStdioClosed
	}
	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", errMCPFormTimeout
		}
		return "", errMCPFormCancelled
	case reply := <-replies:
		if ctx.Err() != nil {
			return "", errMCPFormCancelled
		}
		if reply.invalid {
			return "", errMCPFormInvalid
		}
		var result struct {
			Action  string                     `json:"action"`
			Content map[string]json.RawMessage `json:"content,omitempty"`
		}
		decoder := json.NewDecoder(bytes.NewReader(reply.result))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil {
			return "", errMCPFormInvalid
		}
		switch result.Action {
		case "decline":
			return "", errMCPFormDeclined
		case "cancel":
			return "", errMCPFormCancelled
		case "accept":
			var selected string
			if len(result.Content) != 1 || json.Unmarshal(result.Content["peer"], &selected) != nil || !choices[selected] {
				return "", errMCPFormInvalid
			}
			return selected, nil
		default:
			return "", errMCPFormInvalid
		}
	}
}

func mcpFormText(value string, max int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= max && strings.IndexFunc(value, unicode.IsControl) < 0
}

func (t *mcpStdioTransport) receiveReply(fields map[string]json.RawMessage) {
	key, ok := mcpStdioIDKey(fields["id"])
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if reply := t.pending[key]; reply != nil {
		// The first matching response consumes the pending slot, even if it is
		// malformed. A duplicate cannot replace a refusal or repair bad input.
		t.pending[key] = nil
		invalid := fields["error"] != nil || fields["result"] == nil
		for field := range fields {
			if field != "jsonrpc" && field != "id" && field != "result" && field != "error" {
				invalid = true
			}
		}
		reply <- mcpElicitationReply{result: fields["result"], invalid: invalid}
	}
}
