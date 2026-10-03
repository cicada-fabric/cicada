package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
)

func localPeerDeliveryCapability(capabilities map[string]any) (string, bool) {
	raw, present := capabilities["local_peer_delivery"]
	if !present {
		return "", false
	}
	value, ok := raw.(string)
	if !ok {
		return "", true
	}
	return strings.TrimSpace(value), true
}

func (m *mcpServer) resolveMCPOutboxTarget(op mcpOutboxOperation, target string) (fabric.NetworkCard, error) {
	result, err := m.apiForGroup(http.MethodPost, "/v2/fabric/resolve",
		fabric.ResolveInput{Query: target}, op.GroupID)
	if err != nil {
		return fabric.NetworkCard{}, err
	}
	card, err := networkCardFromResult(result)
	if err != nil || card.EndpointID == "" || card.GroupID != op.GroupID || card.NodeID == "" {
		return fabric.NetworkCard{}, errors.New("Directory returned an invalid same-Group target")
	}
	return card, nil
}

func (m *mcpServer) dispatchLocalGroupMCPOutbox(outbox *mcpOutboxStore,
	scope mcpOutboxScope, operation mcpOutboxOperation, input mcpOutboxInput) (any, error) {
	if operation.Kind != "send" && operation.Kind != "ask" && operation.Kind != "reply" {
		return nil, errors.New("unsupported local Group operation")
	}
	if input.LinkID != "" || len([]byte(input.Body)) > 64*1024 ||
		len([]byte(input.Question)) > 64*1024 {
		return m.recordSealedRPCError(outbox, scope, operation, errors.New("invalid local Group message"))
	}
	contextInput := input
	if operation.Kind == "ask" {
		contextInput.Body = input.Question
	}
	trusted, err := m.currentLocalSealedSendRequest(operation, contextInput)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	if !trusted.LocalPeerDeliveryPresent || trusted.LocalPeerDelivery != "sealed_v1" {
		return m.recordSealedRPCError(outbox, scope, operation,
			errors.New("source is missing the required sealed_v1 peer-delivery capability"))
	}
	if operation.Kind == "reply" {
		// The Node derives the return route from the durable request and rejects
		// replies that do not belong to this current native binding.
		return m.dispatchCrossNodeGroupMCPOutbox(outbox, scope, operation, input)
	}
	card, err := m.resolveMCPOutboxTarget(operation, input.Target)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	targetCapability, targetHasCapability := localPeerDeliveryCapability(card.Capabilities)
	if !targetHasCapability || targetCapability != "sealed_v1" {
		return m.recordSealedRPCError(outbox, scope, operation,
			errors.New("target is missing the required sealed_v1 peer-delivery capability"))
	}
	// Generic native direct has no authenticated account/physical-host/API
	// eligibility evidence. Equal Node labels are only route metadata.
	// The Node retains exact legacy local-operation recovery independently.
	return m.dispatchCrossNodeGroupMCPOutbox(outbox, scope, operation, input)
}

func (m *mcpServer) localGroupRequestControl(operation, requestID, reason string) (any, bool, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, false, err
	}
	trustedContext, err := normalizeMCPTrustedContext(harness.SessionContext{
		Harness: scope.Harness, NativeSessionID: scope.NativeSessionID,
		MachineID: scope.NodeID, Workspace: scope.Workspace,
	})
	if err != nil {
		return nil, false, err
	}
	operationScope := mcpOutboxOperation{
		APIOrigin: scope.APIOrigin, Scope: scope.Scope, Harness: scope.Harness,
		NativeSessionID: scope.NativeSessionID, NodeID: scope.NodeID,
		Workspace: scope.Workspace, EndpointID: scope.EndpointID, GroupID: scope.GroupID,
	}
	trusted, err := m.currentMCPDeliveryRequest(operationScope, mcpOutboxInput{}, trustedContext)
	if err != nil {
		return nil, false, err
	}
	if !trusted.LocalPeerDeliveryPresent {
		return nil, false, nil
	}
	if trusted.LocalPeerDelivery != "sealed_v1" {
		return nil, false, errors.New("source has an unsupported peer-delivery capability; no Hub status or cancellation fallback")
	}
	// The Node validates the current native binding and requester ownership.
	// A missing local request returns an error; it never falls back to Hub.
	request := crossNodeGroupRequest{
		Operation: operation, Harness: trusted.Harness,
		NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID,
		Workspace: trusted.Workspace, SessionToken: trusted.SessionToken,
		EndpointID: trusted.EndpointID, PrincipalID: trusted.PrincipalID,
		OwnerID: trusted.OwnerID, GroupID: trusted.GroupID,
		BindingID: trusted.BindingID, BindingEpoch: trusted.BindingEpoch,
		RequestID: requestID, Reason: reason,
	}
	if request.Operation == "local_status" {
		request.Operation = "cross_node_group_status"
	} else if request.Operation == "local_cancel" {
		request.Operation = "cross_node_group_cancel"
	} else {
		return nil, false, errors.New("unsupported same-Group request control")
	}
	result, err := requestMachineAgentCrossNodeGroup(m.joinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return nil, true, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, true, err
	}
	var public map[string]any
	if err := json.Unmarshal(encoded, &public); err != nil {
		return nil, true, err
	}
	return public, true, nil
}
