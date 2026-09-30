package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

const mcpGroupSpaceMaxBody = 16 * 1024

func (m *mcpServer) groupSpaceMCPTool(name string, arguments map[string]any) (any, error) {
	allowed := map[string]bool{}
	switch name {
	case "cicada_space_history_manifest":
		allowed = map[string]bool{"record_id": true, "recipient_endpoint_id": true, "owner_key_id": true}
	case "cicada_space_history_share":
		allowed = map[string]bool{"owner_proof": true}
	case "cicada_journal_append":
		allowed = map[string]bool{"body": true, "corrects_id": true, "idempotency_key": true}
	case "cicada_discussion_topic_create":
		allowed = map[string]bool{"body": true, "idempotency_key": true}
	case "cicada_discussion_reply":
		allowed = map[string]bool{"topic_id": true, "body": true, "idempotency_key": true}
	case "cicada_discussion_resolve", "cicada_discussion_reopen":
		allowed = map[string]bool{"topic_id": true, "expected_topic_version": true, "idempotency_key": true}
	case "cicada_journal_list":
		allowed = map[string]bool{"cursor": true, "limit": true}
	case "cicada_space_sync":
		allowed = map[string]bool{"after_seq": true, "limit": true}
	case "cicada_space_read_state":
		allowed = map[string]bool{}
	case "cicada_space_mark_read":
		allowed = map[string]bool{"through_seq": true}
	case "cicada_regroup_propose":
		allowed = map[string]bool{"network_id": true, "target_group_id": true, "action": true,
			"new_group_name": true, "expected_source_version": true, "expected_target_version": true, "idempotency_key": true}
	case "cicada_regroup_apply":
		allowed = map[string]bool{"proposal_id": true, "delegation_id": true}
	case "cicada_discussion_list":
		allowed = map[string]bool{"topic_id": true, "cursor": true, "limit": true}
	case "cicada_journal_get", "cicada_discussion_get":
		allowed = map[string]bool{"record_id": true}
	default:
		return nil, errors.New("unsupported Group Space tool")
	}
	for key := range arguments {
		if !allowed[key] {
			return nil, fmt.Errorf("%s does not accept %q", name, key)
		}
	}
	if name == "cicada_space_history_manifest" || name == "cicada_space_history_share" {
		return m.historyGroupSpaceMCP(name, arguments)
	}
	if name == "cicada_space_sync" || name == "cicada_space_read_state" || name == "cicada_space_mark_read" {
		return m.syncGroupSpaceMCP(name, arguments)
	}
	if name == "cicada_regroup_propose" || name == "cicada_regroup_apply" {
		return m.regroupMCP(name, arguments)
	}
	if strings.HasSuffix(name, "_list") || strings.HasSuffix(name, "_get") {
		return m.readGroupSpaceMCP(name, arguments)
	}
	body := stringArgument(arguments, "body")
	if name == "cicada_discussion_resolve" || name == "cicada_discussion_reopen" {
		if intArgument(arguments, "expected_topic_version") <= 0 {
			return nil, errors.New("expected_topic_version must be positive")
		}
	} else if body == "" || len([]byte(body)) > mcpGroupSpaceMaxBody {
		return nil, errors.New("Group Space body must be non-empty and at most 16 KiB")
	}
	if strings.HasPrefix(name, "cicada_discussion_") && name != "cicada_discussion_topic_create" &&
		strings.TrimSpace(stringArgument(arguments, "topic_id")) == "" {
		return nil, errors.New("topic_id is required")
	}
	input := mcpOutboxInput{Body: body, TopicID: stringArgument(arguments, "topic_id"),
		CorrectsID:   stringArgument(arguments, "corrects_id"),
		TopicVersion: int64(intArgument(arguments, "expected_topic_version"))}
	if name == "cicada_discussion_resolve" {
		input.SpaceStatus = "RESOLVED"
	}
	if name == "cicada_discussion_reopen" {
		input.SpaceStatus = "OPEN"
	}
	return m.submitMCPOutbox("space_"+strings.TrimPrefix(name, "cicada_"), input,
		stringArgument(arguments, "idempotency_key"))
}

func (m *mcpServer) regroupMCP(name string, arguments map[string]any) (any, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	operation := mcpOutboxOperation{APIOrigin: scope.APIOrigin, Scope: scope.Scope,
		Harness: scope.Harness, NativeSessionID: scope.NativeSessionID, NodeID: scope.NodeID,
		Workspace: scope.Workspace, EndpointID: scope.EndpointID, GroupID: scope.GroupID}
	request, err := m.groupSpaceTrustedRequest(operation, mcpOutboxInput{})
	if err != nil {
		return nil, err
	}
	if name == "cicada_regroup_propose" {
		request.Operation = "space_regroup_propose"
		request.RegroupInput = &store.RegroupProposalInput{
			OperationID:           stringArgument(arguments, "idempotency_key"),
			NetworkID:             stringArgument(arguments, "network_id"),
			SourceGroupID:         scope.GroupID,
			TargetGroupID:         stringArgument(arguments, "target_group_id"),
			Action:                stringArgument(arguments, "action"),
			NewGroupName:          stringArgument(arguments, "new_group_name"),
			ExpectedSourceVersion: int64(intArgument(arguments, "expected_source_version")),
			ExpectedTargetVersion: int64(intArgument(arguments, "expected_target_version")),
		}
		if request.RegroupInput.OperationID == "" || request.RegroupInput.NetworkID == "" ||
			request.RegroupInput.TargetGroupID == "" || request.RegroupInput.ExpectedSourceVersion <= 0 ||
			request.RegroupInput.ExpectedTargetVersion <= 0 ||
			(request.RegroupInput.Action != store.RegroupSetParent && request.RegroupInput.Action != store.RegroupCreateChild) {
			return nil, errors.New("regroup proposal requires exact current scope and expected versions")
		}
	} else {
		request.Operation = "space_regroup_apply"
		request.ProposalID = stringArgument(arguments, "proposal_id")
		request.DelegationID = stringArgument(arguments, "delegation_id")
		if request.ProposalID == "" || request.DelegationID == "" {
			return nil, errors.New("regroup apply requires exact proposal and delegation")
		}
	}
	result, err := requestMachineAgentGroupSpace(m.joinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return nil, err
	}
	if name == "cicada_regroup_propose" {
		if result.RegroupProposal == nil || result.RegroupProposal.Input.SourceGroupID != scope.GroupID {
			return nil, errors.New("local Node returned mismatched regroup proposal")
		}
	} else if result.RegroupApply == nil || result.RegroupApply.ProposalID != request.ProposalID {
		return nil, errors.New("local Node returned mismatched regroup result")
	}
	return result, nil
}

func (m *mcpServer) syncGroupSpaceMCP(name string, arguments map[string]any) (any, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	operation := mcpOutboxOperation{APIOrigin: scope.APIOrigin, Scope: scope.Scope,
		Harness: scope.Harness, NativeSessionID: scope.NativeSessionID, NodeID: scope.NodeID,
		Workspace: scope.Workspace, EndpointID: scope.EndpointID, GroupID: scope.GroupID}
	request, err := m.groupSpaceTrustedRequest(operation, mcpOutboxInput{})
	if err != nil {
		return nil, err
	}
	request.Operation = "space_" + strings.TrimPrefix(name, "cicada_space_")
	request.AfterSeq = int64(intArgument(arguments, "after_seq"))
	request.ThroughSeq = int64(intArgument(arguments, "through_seq"))
	request.Limit = intArgument(arguments, "limit")
	if request.AfterSeq < 0 || request.Limit < 0 || request.Limit > 16 ||
		(name == "cicada_space_mark_read" && request.ThroughSeq < 0) {
		return nil, errors.New("invalid Group Space sequence or page limit")
	}
	result, err := requestMachineAgentGroupSpace(m.joinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return nil, err
	}
	if name == "cicada_space_sync" {
		if result.Sync == nil || result.Sync.GroupID != scope.GroupID {
			return nil, errors.New("local Node returned mismatched Group Space sync")
		}
	} else if result.ReadState == nil || result.ReadState.GroupID != scope.GroupID {
		return nil, errors.New("local Node returned mismatched Group Space read state")
	}
	return result, nil
}

func (m *mcpServer) historyGroupSpaceMCP(name string, arguments map[string]any) (any, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	operation := mcpOutboxOperation{APIOrigin: scope.APIOrigin, Scope: scope.Scope,
		Harness: scope.Harness, NativeSessionID: scope.NativeSessionID, NodeID: scope.NodeID,
		Workspace: scope.Workspace, EndpointID: scope.EndpointID, GroupID: scope.GroupID}
	request, err := m.groupSpaceTrustedRequest(operation, mcpOutboxInput{})
	if err != nil {
		return nil, err
	}
	request.Operation = "space_history_" + strings.TrimPrefix(name, "cicada_space_history_")
	request.RecordID = stringArgument(arguments, "record_id")
	request.RecipientEndpointID = stringArgument(arguments, "recipient_endpoint_id")
	request.OwnerKeyID = stringArgument(arguments, "owner_key_id")
	request.OwnerProof = stringArgument(arguments, "owner_proof")
	if name == "cicada_space_history_manifest" {
		if request.RecordID == "" || request.RecipientEndpointID == "" || request.OwnerKeyID == "" {
			return nil, errors.New("history manifest requires record_id, recipient_endpoint_id and owner_key_id")
		}
	} else if request.OwnerProof == "" || len(request.OwnerProof) > 24000 {
		return nil, errors.New("history share requires a bounded Owner proof")
	}
	result, err := requestMachineAgentGroupSpace(m.joinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return nil, err
	}
	if name == "cicada_space_history_manifest" {
		if result.HistoryGrant == nil || result.HistoryGrant.GroupID != scope.GroupID ||
			result.HistoryGrant.RecordID != request.RecordID ||
			result.HistoryGrant.RecipientEndpointID != request.RecipientEndpointID ||
			result.HistoryGrant.OwnerKeyID != request.OwnerKeyID {
			return nil, errors.New("local Node returned mismatched history manifest")
		}
	} else if result.Record == nil || result.Record.GroupID != scope.GroupID {
		return nil, errors.New("local Node returned mismatched history share")
	}
	return result, nil
}

func (m *mcpServer) groupSpaceTrustedRequest(operation mcpOutboxOperation, input mcpOutboxInput) (groupSpaceLocalRequest, error) {
	base, err := m.currentLocalSealedSendRequest(operation, input)
	if err != nil {
		return groupSpaceLocalRequest{}, err
	}
	return groupSpaceLocalRequest{localSealedSendRequest: base,
		OperationID: operation.OperationID, TopicID: input.TopicID,
		CorrectsID: input.CorrectsID, ExpectedTopicVersion: input.TopicVersion,
		Status: input.SpaceStatus}, nil
}

func (m *mcpServer) dispatchGroupSpaceMCPOutbox(outbox *mcpOutboxStore,
	scope mcpOutboxScope, operation mcpOutboxOperation) (any, error) {
	var input mcpOutboxInput
	if err := json.Unmarshal([]byte(operation.InputJSON), &input); err != nil {
		return m.recordGroupSpaceMCPError(outbox, scope, operation,
			errors.New("Group Space operation has invalid immutable input"))
	}
	request, err := m.groupSpaceTrustedRequest(operation, input)
	if err != nil {
		return m.recordGroupSpaceMCPError(outbox, scope, operation, err)
	}
	request.Operation = operation.Kind
	result, err := requestMachineAgentGroupSpace(m.joinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return m.recordGroupSpaceMCPError(outbox, scope, operation, err)
	}
	if result.Record == nil || result.Record.GroupID != scope.GroupID ||
		result.Record.RecordID == "" || result.Record.Body == "" {
		return m.recordGroupSpaceMCPError(outbox, scope, operation,
			errors.New("local Node returned an incomplete Group Space write"))
	}
	encoded, err := mcpOutboxResultJSON(result, request.SessionToken)
	if err != nil {
		return m.recordGroupSpaceMCPError(outbox, scope, operation, err)
	}
	updated, err := outbox.markResult(scope, operation.OperationID, mcpOutboxStatusSent, "", encoded)
	if err != nil {
		operation.Status = mcpOutboxStatusUnknown
		operation.LastError = "Group Space outbox result persistence failed"
		return mcpOutboxPublicResult(operation), nil
	}
	return mcpOutboxPublicResult(updated), nil
}

func (m *mcpServer) recordGroupSpaceMCPError(outbox *mcpOutboxStore,
	scope mcpOutboxScope, operation mcpOutboxOperation, cause error) (any, error) {
	status := mcpOutboxStatusFailed
	if localSealedSendRetryable(cause) {
		status = mcpOutboxStatusUnknown
	}
	updated, err := outbox.markResult(scope, operation.OperationID,
		status, m.safeMCPError(cause), operation.ResultJSON)
	if err != nil {
		return nil, err
	}
	return mcpOutboxPublicResult(updated), nil
}

func (m *mcpServer) readGroupSpaceMCP(name string, arguments map[string]any) (any, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	operation := mcpOutboxOperation{APIOrigin: scope.APIOrigin, Scope: scope.Scope,
		Harness: scope.Harness, NativeSessionID: scope.NativeSessionID, NodeID: scope.NodeID,
		Workspace: scope.Workspace, EndpointID: scope.EndpointID, GroupID: scope.GroupID}
	request, err := m.groupSpaceTrustedRequest(operation, mcpOutboxInput{})
	if err != nil {
		return nil, err
	}
	request.Operation = "space_" + strings.TrimPrefix(name, "cicada_")
	request.RecordID = stringArgument(arguments, "record_id")
	request.TopicID = stringArgument(arguments, "topic_id")
	request.Cursor = stringArgument(arguments, "cursor")
	request.Limit = intArgument(arguments, "limit")
	if strings.HasSuffix(name, "_get") && request.RecordID == "" {
		return nil, errors.New("record_id is required")
	}
	if request.Limit < 0 || request.Limit > 16 {
		return nil, errors.New("Group Space page limit must be at most 16")
	}
	result, err := requestMachineAgentGroupSpace(m.joinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(name, "_get") {
		if result.Record == nil || result.Record.GroupID != scope.GroupID ||
			result.Record.RecordID != request.RecordID {
			return nil, errors.New("local Node returned a mismatched Group Space record")
		}
	} else {
		if len(result.Records) > 16 {
			return nil, errors.New("local Node returned oversized Group Space page")
		}
		for _, record := range result.Records {
			if record.GroupID != scope.GroupID || record.RecordID == "" {
				return nil, errors.New("local Node returned a cross-scope Group Space page")
			}
		}
	}
	return result, nil
}
