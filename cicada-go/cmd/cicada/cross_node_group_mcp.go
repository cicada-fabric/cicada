package main

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/harness"
)

const crossNodeGroupProtocolVersion = 1

// crossNodeGroupRequest crosses the owner-only Node socket. Caller identity is
// repeated only so the Node can compare it with the live Session binding; the
// Hub derives the actual route from its Node credential and current records.
type crossNodeGroupRequest struct {
	Version            int    `json:"version"`
	Operation          string `json:"operation"`
	Harness            string `json:"harness"`
	NativeSessionID    string `json:"native_session_id"`
	NodeID             string `json:"node_id"`
	Workspace          string `json:"workspace"`
	SessionToken       string `json:"session_token"`
	EndpointID         string `json:"endpoint_id"`
	PrincipalID        string `json:"principal_id"`
	OwnerID            string `json:"owner_id"`
	GroupID            string `json:"group_id"`
	BindingID          string `json:"binding_id"`
	BindingEpoch       uint64 `json:"binding_epoch"`
	TargetEndpointID   string `json:"target_endpoint_id,omitempty"`
	OperationID        string `json:"operation_id,omitempty"`
	OperationCreatedAt string `json:"operation_created_at,omitempty"`
	IdempotencyKey     string `json:"idempotency_key,omitempty"`
	RequestID          string `json:"request_id,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Body               string `json:"body,omitempty"`
}

type crossNodeGroupResult struct {
	MessageID        string `json:"message_id,omitempty"`
	RequestID        string `json:"request_id,omitempty"`
	TargetEndpointID string `json:"target_endpoint_id,omitempty"`
	State            string `json:"state"`
	Delivery         string `json:"delivery,omitempty"`
	PayloadMode      string `json:"payload_mode,omitempty"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	ReplyMessageID   string `json:"reply_message_id,omitempty"`
	LateMessageID    string `json:"late_message_id,omitempty"`
	Sequence         uint64 `json:"endpoint_sequence,omitempty"`
	CiphertextReused bool   `json:"ciphertext_reused,omitempty"`
}

func requestMachineAgentCrossNodeGroup(socketPath string, request crossNodeGroupRequest) (*crossNodeGroupResult, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, errLocalJoinBridgeUnavailable
	}
	connection, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	request.Version = crossNodeGroupProtocolVersion
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, &localSealedSendError{message: "could not submit sealed Group request to the local Node", retryable: true}
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 64*1024))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, &localSealedSendError{message: "local Node returned an invalid sealed Group response", retryable: true}
	}
	if response.Error != "" {
		return nil, &localSealedSendError{message: response.Error, retryable: response.Retryable}
	}
	if response.CrossNodeGroup == nil || response.CrossNodeGroup.State == "" {
		return nil, &localSealedSendError{message: "local Node returned an incomplete sealed Group result", retryable: true}
	}
	if request.OperationID != "" {
		messageID, requestID, idErr := localSealedRPCIDs(request.OperationID)
		if idErr != nil || response.CrossNodeGroup.MessageID != messageID ||
			(request.Operation == "cross_node_group_ask" && response.CrossNodeGroup.RequestID != requestID) {
			return nil, &localSealedSendError{message: "local Node returned an uncorrelated sealed Group result", retryable: true}
		}
	}
	if request.RequestID != "" && response.CrossNodeGroup.RequestID != request.RequestID {
		return nil, &localSealedSendError{message: "local Node returned an uncorrelated sealed Group request", retryable: true}
	}
	return response.CrossNodeGroup, nil
}

func validateCrossNodeGroupRequest(request crossNodeGroupRequest, nodeID string) error {
	if request.Version != crossNodeGroupProtocolVersion || harness.Canonical(request.Harness) != "codex" ||
		strings.TrimSpace(request.NativeSessionID) == "" || len(request.NativeSessionID) > 512 ||
		request.NodeID != nodeID || strings.TrimSpace(request.Workspace) == "" ||
		strings.TrimSpace(request.SessionToken) == "" || request.EndpointID == "" ||
		request.PrincipalID == "" || request.OwnerID == "" || request.GroupID == "" ||
		request.BindingID == "" || request.BindingEpoch == 0 {
		return errors.New("invalid trusted same-Group Node context")
	}
	for _, value := range []string{request.EndpointID, request.PrincipalID, request.OwnerID,
		request.GroupID, request.BindingID, request.TargetEndpointID, request.OperationID,
		request.IdempotencyKey, request.RequestID} {
		if len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("invalid trusted same-Group Node context")
		}
	}
	if len([]byte(request.Body)) > 64*1024 || len(request.Reason) > 512 {
		return errors.New("invalid trusted same-Group message")
	}
	switch request.Operation {
	case "cross_node_group_send":
		if request.TargetEndpointID == "" || request.OperationID == "" || request.IdempotencyKey == "" ||
			request.Body == "" || request.RequestID != "" || request.OperationCreatedAt != "" || request.Reason != "" {
			return errors.New("invalid same-Group SEND")
		}
		_, _, err := localSealedRPCIDs(request.OperationID)
		return err
	case "cross_node_group_ask":
		if request.TargetEndpointID == "" || request.OperationID == "" || request.IdempotencyKey == "" ||
			request.Body == "" || request.RequestID != "" || request.Reason != "" {
			return errors.New("invalid same-Group ASK")
		}
		if _, _, err := localSealedRPCIDs(request.OperationID); err != nil {
			return err
		}
		createdAt, err := time.Parse(time.RFC3339Nano, request.OperationCreatedAt)
		if err != nil || createdAt.After(time.Now().UTC().Add(time.Minute)) {
			return errors.New("same-Group ASK requires a valid durable creation time")
		}
	case "cross_node_group_reply":
		if request.TargetEndpointID != "" || request.OperationID == "" || request.IdempotencyKey == "" ||
			request.RequestID == "" || request.Body == "" || request.OperationCreatedAt != "" || request.Reason != "" {
			return errors.New("invalid same-Group REPLY")
		}
		_, _, err := localSealedRPCIDs(request.OperationID)
		return err
	case "cross_node_group_status", "cross_node_group_cancel":
		if request.RequestID == "" || request.TargetEndpointID != "" || request.OperationID != "" ||
			request.IdempotencyKey != "" || request.Body != "" || request.OperationCreatedAt != "" ||
			request.Reason != "" {
			return errors.New("invalid same-Group request control")
		}
	default:
		return errors.New("unsupported same-Group Node operation")
	}
	return nil
}

func (m *mcpServer) dispatchCrossNodeGroupMCPOutbox(outbox *mcpOutboxStore,
	scope mcpOutboxScope, operation mcpOutboxOperation, input mcpOutboxInput) (any, error) {
	if input.LinkID != "" || len([]byte(input.Body)) > 64*1024 || len([]byte(input.Question)) > 64*1024 {
		return m.recordSealedRPCError(outbox, scope, operation, errors.New("invalid same-Group sealed message"))
	}
	contextInput := input
	if operation.Kind == "ask" {
		contextInput.Body = input.Question
	}
	trusted, err := m.currentLocalSealedSendRequest(operation, contextInput)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	request := crossNodeGroupRequest{
		Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID,
		NodeID: trusted.NodeID, Workspace: trusted.Workspace, SessionToken: trusted.SessionToken,
		EndpointID: trusted.EndpointID, PrincipalID: trusted.PrincipalID, OwnerID: trusted.OwnerID,
		GroupID: trusted.GroupID, BindingID: trusted.BindingID, BindingEpoch: trusted.BindingEpoch,
		OperationID: operation.OperationID, OperationCreatedAt: operation.CreatedAt,
		IdempotencyKey: operation.IdempotencyKey, RequestID: input.RequestID, Body: contextInput.Body,
	}
	switch operation.Kind {
	case "send", "ask":
		card, resolveErr := m.resolveMCPOutboxTarget(operation, input.Target)
		if resolveErr != nil {
			return m.recordSealedRPCError(outbox, scope, operation, resolveErr)
		}
		if card.GroupID != trusted.GroupID || card.EndpointID == trusted.EndpointID || card.NodeID == trusted.NodeID {
			return m.recordSealedRPCError(outbox, scope, operation,
				errors.New("target is not a remote same-Group Endpoint"))
		}
		request.TargetEndpointID = card.EndpointID
		if operation.Kind == "send" {
			request.Operation = "cross_node_group_send"
			request.OperationCreatedAt = ""
		} else {
			request.Operation = "cross_node_group_ask"
		}
	case "reply":
		request.Operation = "cross_node_group_reply"
		request.OperationCreatedAt = ""
	default:
		return m.recordSealedRPCError(outbox, scope, operation, errors.New("unsupported same-Group sealed operation"))
	}
	result, err := requestMachineAgentCrossNodeGroup(defaultMCPJoinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	if result.PayloadMode != "SEALED_V1" || result.MessageID == "" || result.Delivery == "" ||
		(operation.Kind == "ask" && result.RequestID == "") ||
		(operation.Kind == "reply" && result.RequestID != input.RequestID) {
		return m.recordSealedRPCError(outbox, scope, operation,
			&localSealedSendError{message: "local Node returned an incomplete sealed same-Group receipt", retryable: true})
	}
	resultJSON, err := mcpOutboxResultJSON(result, request.SessionToken)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	sent, err := outbox.markResult(scope, operation.OperationID, mcpOutboxStatusSent, "", resultJSON)
	if err != nil {
		operation.Status = mcpOutboxStatusUnknown
		operation.LastError = "local outbox result persistence failed"
		return mcpOutboxPublicResult(operation), nil
	}
	return mcpOutboxPublicResult(sent), nil
}
