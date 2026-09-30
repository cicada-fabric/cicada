package main

import (
	"encoding/json"
	"errors"

	"github.com/cicada-ai/cicada/internal/harness"
)

// A sealed RPC is submitted through the same durable MCP outbox as the
// plaintext operations. Only the owner-local Node receives the body; it
// authenticates the current native binding again before sealing anything.
func (m *mcpServer) dispatchSealedRPCMCPOutbox(outbox *mcpOutboxStore,
	scope mcpOutboxScope, operation mcpOutboxOperation, input mcpOutboxInput) (any, error) {
	if input.LinkID == "" || input.Body == "" && operation.Kind == "reply" ||
		input.Question == "" && operation.Kind == "ask" ||
		len([]byte(input.Body)) > 64*1024 || len([]byte(input.Question)) > 64*1024 ||
		(operation.Kind == "ask" && input.DataScope == "") ||
		(operation.Kind == "reply" && input.RequestID == "") {
		failed, err := outbox.markError(scope, operation.OperationID, mcpOutboxStatusFailed,
			errors.New("sealed RPC requires a Link and a bounded question or correlated reply"))
		if err != nil {
			return nil, err
		}
		return mcpOutboxPublicResult(failed), nil
	}
	contextInput := input
	if operation.Kind == "ask" {
		contextInput.Body = input.Question
	}
	trusted, err := m.currentLocalSealedSendRequest(operation, contextInput)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	request := localSealedRPCRequest{
		Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID,
		NodeID: trusted.NodeID, Workspace: trusted.Workspace,
		SessionToken: trusted.SessionToken, EndpointID: trusted.EndpointID,
		PrincipalID: trusted.PrincipalID, OwnerID: trusted.OwnerID,
		GroupID: trusted.GroupID, BindingID: trusted.BindingID,
		BindingEpoch: trusted.BindingEpoch, OperationID: operation.OperationID,
		IdempotencyKey: operation.IdempotencyKey, LinkID: input.LinkID,
		DataScope: input.DataScope, ExpiresAt: input.ExpiresAt,
		RequestID: input.RequestID, Body: contextInput.Body,
	}
	if operation.Kind == "ask" {
		request.Operation = "sealed_ask"
		request.OperationCreatedAt = operation.CreatedAt
	} else {
		request.Operation = "sealed_reply"
	}
	result, err := requestMachineAgentSealedRPC(m.joinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	if result == nil || result.RequestID == "" || result.MessageID == "" ||
		result.PayloadMode != "SEALED_V1" ||
		(operation.Kind == "reply" && result.RequestID != input.RequestID) {
		unknown, err := outbox.markError(scope, operation.OperationID, mcpOutboxStatusUnknown,
			errors.New("trusted local Node returned an incomplete sealed RPC receipt"))
		if err != nil {
			return nil, err
		}
		return mcpOutboxPublicResult(unknown), nil
	}
	resultJSON, err := mcpOutboxResultJSON(result, request.SessionToken)
	if err != nil {
		unknown, persistErr := outbox.markError(scope, operation.OperationID, mcpOutboxStatusUnknown, err)
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(unknown), nil
	}
	sent, err := outbox.markResult(scope, operation.OperationID, mcpOutboxStatusSent, "", resultJSON)
	if err != nil {
		operation.Status = mcpOutboxStatusUnknown
		operation.LastError = "local outbox result persistence failed"
		return mcpOutboxPublicResult(operation), nil
	}
	return mcpOutboxPublicResult(sent), nil
}

func (m *mcpServer) recordSealedRPCError(outbox *mcpOutboxStore, scope mcpOutboxScope,
	operation mcpOutboxOperation, requestErr error) (any, error) {
	status := mcpOutboxStatusFailed
	if sealedSendErrorRetryable(requestErr) {
		status = mcpOutboxStatusUnknown
	}
	failed, err := outbox.markError(scope, operation.OperationID, status,
		errors.New(m.safeMCPError(requestErr)))
	if err != nil {
		return nil, err
	}
	return mcpOutboxPublicResult(failed), nil
}

// currentSealedRPCControlRequest uses the same fresh native-session and
// CicadaSession checks as the sealed send path, without persisting a message.
func (m *mcpServer) currentSealedRPCControlRequest(operation, requestID, linkID, reason string) (localSealedRPCRequest, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return localSealedRPCRequest{}, err
	}
	trusted, err := m.currentLocalSealedSendRequest(mcpOutboxOperation{
		APIOrigin: scope.APIOrigin, Scope: scope.Scope, Harness: scope.Harness,
		NativeSessionID: scope.NativeSessionID, NodeID: scope.NodeID,
		Workspace: scope.Workspace, EndpointID: scope.EndpointID,
		GroupID: scope.GroupID,
	}, mcpOutboxInput{})
	if err != nil {
		return localSealedRPCRequest{}, err
	}
	return localSealedRPCRequest{
		Operation: operation, Harness: trusted.Harness,
		NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID,
		Workspace: trusted.Workspace, SessionToken: trusted.SessionToken,
		EndpointID: trusted.EndpointID, PrincipalID: trusted.PrincipalID,
		OwnerID: trusted.OwnerID, GroupID: trusted.GroupID,
		BindingID: trusted.BindingID, BindingEpoch: trusted.BindingEpoch,
		RequestID: requestID, LinkID: linkID, Reason: reason,
	}, nil
}

func (m *mcpServer) sealedRPCControl(operation, requestID, linkID, reason string) (any, error) {
	request, err := m.currentSealedRPCControlRequest(operation, requestID, linkID, reason)
	if err != nil {
		return nil, err
	}
	result, err := requestMachineAgentSealedRPC(m.joinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return nil, err
	}
	// Return metadata only. The Hub does not expose peer plaintext through the
	// request lifecycle API.
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	var public map[string]any
	if err := json.Unmarshal(encoded, &public); err != nil {
		return nil, err
	}
	return public, nil
}
