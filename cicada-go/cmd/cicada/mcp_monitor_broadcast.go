package main

import (
	"encoding/json"
	"errors"
)

func (m *mcpServer) currentMonitorBroadcastRequest(operation mcpOutboxOperation, approvalID string) (monitorBroadcastRequest, error) {
	trusted, err := m.currentLocalSealedSendRequest(operation, mcpOutboxInput{})
	if err != nil {
		return monitorBroadcastRequest{}, err
	}
	if !trusted.LocalPeerDeliveryPresent || trusted.LocalPeerDelivery != "sealed_v1" {
		return monitorBroadcastRequest{}, errors.New("Monitor broadcast requires sealed native Endpoint delivery")
	}
	return monitorBroadcastRequest{Operation: "monitor_broadcast_info", Harness: trusted.Harness,
		NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID, Workspace: trusted.Workspace,
		SessionToken: trusted.SessionToken, EndpointID: trusted.EndpointID, PrincipalID: trusted.PrincipalID,
		OwnerID: trusted.OwnerID, GroupID: trusted.GroupID, BindingID: trusted.BindingID,
		BindingEpoch: trusted.BindingEpoch, PreviewID: approvalID}, nil
}

func (m *mcpServer) submitMonitorBroadcast(approvalID string) (any, error) {
	if !validMonitorApprovalID(approvalID) {
		return nil, errors.New("a current Monitor approval_id is required")
	}
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	request, err := m.currentMonitorBroadcastRequest(mcpOutboxOperation{
		APIOrigin: scope.APIOrigin, Scope: scope.Scope, Harness: scope.Harness,
		NativeSessionID: scope.NativeSessionID, NodeID: scope.NodeID, Workspace: scope.Workspace,
		EndpointID: scope.EndpointID, GroupID: scope.GroupID}, approvalID)
	if err != nil {
		return nil, err
	}
	info, err := requestMachineAgentMonitorBroadcast(request)
	if err != nil {
		return nil, err
	}
	outbox, err := m.ensureMCPOutbox()
	if err != nil {
		return nil, err
	}
	op, created, err := outbox.prepareMonitorBroadcast(scope, approvalID, info.OperationID)
	if err != nil {
		return nil, err
	}
	if !created {
		return mcpOutboxPublicResult(op), nil
	}
	return m.dispatchMCPOutbox(outbox, scope, op)
}

// previewMonitorBroadcast performs only authenticated reads and Node-local
// verification. The result is intentionally confined to this original MCP
// session; it does not create an outbox operation or authorize dispatch.
func (m *mcpServer) previewMonitorBroadcast(approvalID string) (any, error) {
	if !validMonitorApprovalID(approvalID) {
		return nil, errors.New("a current Monitor approval_id is required")
	}
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	request, err := m.currentMonitorBroadcastRequest(mcpOutboxOperation{
		APIOrigin: scope.APIOrigin, Scope: scope.Scope, Harness: scope.Harness,
		NativeSessionID: scope.NativeSessionID, NodeID: scope.NodeID, Workspace: scope.Workspace,
		EndpointID: scope.EndpointID, GroupID: scope.GroupID}, approvalID)
	if err != nil {
		return nil, err
	}
	request.Operation = "monitor_broadcast_preview"
	result, err := requestMachineAgentMonitorBroadcast(request)
	if err != nil {
		return nil, err
	}
	if result.Review == nil {
		return nil, errors.New("Monitor preview has no verified review result")
	}
	return result.Review, nil
}

// The model supplies neither broadcast text nor a user-approved flag. The Node
// decrypts the fixed Client payload only after independently verifying Owner
// evidence. The MCP outbox stores an approval ID and progress, never that body.
func (m *mcpServer) dispatchMonitorBroadcastMCPOutbox(outbox *mcpOutboxStore,
	scope mcpOutboxScope, operation mcpOutboxOperation) (any, error) {
	var input mcpOutboxInput
	if err := json.Unmarshal([]byte(operation.InputJSON), &input); err != nil ||
		!validMonitorApprovalID(input.ApprovalID) || input != (mcpOutboxInput{ApprovalID: input.ApprovalID}) {
		return m.recordBroadcastError(outbox, scope, operation, errors.New("Monitor broadcast has invalid immutable input"))
	}
	broadcastID, err := mcpBroadcastID(operation.OperationID)
	if err != nil {
		return m.recordBroadcastError(outbox, scope, operation, err)
	}
	progress := mcpBroadcastProgress{BroadcastID: broadcastID, GroupID: operation.GroupID}
	if operation.ResultJSON != "" {
		if json.Unmarshal([]byte(operation.ResultJSON), &progress) != nil || progress.BroadcastID != broadcastID ||
			progress.GroupID != operation.GroupID || progress.RecipientCount < 0 ||
			progress.RecipientCount > mcpBroadcastMaxRecipients || progress.NextOffset < 0 || progress.NextOffset > progress.RecipientCount {
			return m.recordBroadcastError(outbox, scope, operation, errors.New("invalid durable Monitor broadcast progress"))
		}
	}
	request, err := m.currentMonitorBroadcastRequest(operation, input.ApprovalID)
	if err != nil {
		return m.recordBroadcastError(outbox, scope, operation, err)
	}
	request.Operation = "monitor_broadcast_execute"
	request.Offset = progress.NextOffset
	if progress.Complete {
		request.Offset = 0
	}
	result, err := requestMachineAgentMonitorBroadcast(request)
	if err != nil {
		return m.recordBroadcastError(outbox, scope, operation, err)
	}
	if result.OperationID != operation.OperationID || result.Progress == nil {
		return m.recordBroadcastError(outbox, scope, operation, errors.New("Monitor broadcast operation identity changed"))
	}
	if err := progress.apply(*result.Progress, request.Offset); err != nil {
		return m.recordBroadcastError(outbox, scope, operation, err)
	}
	encoded, err := json.Marshal(progress)
	if err != nil {
		return m.recordBroadcastError(outbox, scope, operation, err)
	}
	status := mcpOutboxStatusUnknown
	if progress.Complete && progress.allAccepted() {
		status = mcpOutboxStatusSent
	}
	updated, err := outbox.markResult(scope, operation.OperationID, status, "", string(encoded))
	if err != nil {
		return nil, err
	}
	return mcpOutboxPublicResult(updated), nil
}
