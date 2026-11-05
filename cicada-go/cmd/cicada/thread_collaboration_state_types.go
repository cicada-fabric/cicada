package main

import (
	"encoding/json"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Private original evidence shares the existing bounded Node state file. No
// identity/key is regenerated and unresolved packets are never silently dropped.
type machineThreadCollaborationOriginal struct {
	Operation            string                           `json:"operation"`
	EndpointID           string                           `json:"endpoint_id"`
	Original             wire.ThreadCollaborationOriginal `json:"original"`
	Scope                wire.GroupLockScope              `json:"scope"`
	Caller               wire.GroupLockHolder             `json:"caller"`
	Harness              string                           `json:"harness"`
	NativeSessionID      string                           `json:"native_session_id"`
	Workspace            string                           `json:"workspace"`
	RegistrationDigest   string                           `json:"registration_digest"`
	RegistrationRevision uint64                           `json:"registration_revision"`
	Body                 json.RawMessage                  `json:"body"`
	RequestPacket        []byte                           `json:"request_packet"`
	ResponsePacket       []byte                           `json:"response_packet,omitempty"`
	NodeBindingID        string                           `json:"node_binding_id"`
	NodeKeyEpoch         uint64                           `json:"node_key_epoch"`
	Sequence             uint64                           `json:"sequence"`
	State                string                           `json:"state"`
	Outcome              string                           `json:"outcome,omitempty"`
	ErrorCode            string                           `json:"error_code,omitempty"`
	CreatedAt            string                           `json:"created_at"`
	UpdatedAt            string                           `json:"updated_at"`
}

func cloneMachineThreadCollaborationOriginals(in map[string]machineThreadCollaborationOriginal) map[string]machineThreadCollaborationOriginal {
	if in == nil {
		return nil
	}
	out := make(map[string]machineThreadCollaborationOriginal, len(in))
	for key, v := range in {
		v.Body = append(json.RawMessage(nil), v.Body...)
		v.RequestPacket = append([]byte(nil), v.RequestPacket...)
		v.ResponsePacket = append([]byte(nil), v.ResponsePacket...)
		out[key] = v
	}
	return out
}

func threadCollaborationNodeOperation(op string) bool {
	for _, known := range wire.ThreadCollaborationNativeOperations() {
		if op == known {
			return true
		}
	}
	return false
}
