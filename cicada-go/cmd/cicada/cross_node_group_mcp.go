package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

const crossNodeGroupProtocolVersion = 1

// crossNodeGroupRequest crosses the owner-only Node socket. Caller identity is
// repeated only so the Node can compare it with the live Session binding; the
// Hub derives the actual route from its Node credential and current records.
type crossNodeGroupRequest struct {
	Version              int                                  `json:"version"`
	Operation            string                               `json:"operation"`
	Harness              string                               `json:"harness"`
	NativeSessionID      string                               `json:"native_session_id"`
	NodeID               string                               `json:"node_id"`
	Workspace            string                               `json:"workspace"`
	SessionToken         string                               `json:"session_token"`
	EndpointID           string                               `json:"endpoint_id"`
	PrincipalID          string                               `json:"principal_id"`
	OwnerID              string                               `json:"owner_id"`
	GroupID              string                               `json:"group_id"`
	BindingID            string                               `json:"binding_id"`
	BindingEpoch         uint64                               `json:"binding_epoch"`
	TargetEndpointID     string                               `json:"target_endpoint_id,omitempty"`
	OperationID          string                               `json:"operation_id,omitempty"`
	OperationCreatedAt   string                               `json:"operation_created_at,omitempty"`
	IdempotencyKey       string                               `json:"idempotency_key,omitempty"`
	RequestID            string                               `json:"request_id,omitempty"`
	ParentRequestID      string                               `json:"parent_request_id,omitempty"`
	Reason               string                               `json:"reason,omitempty"`
	Body                 string                               `json:"body,omitempty"`
	TaskHandoffID        string                               `json:"task_handoff_id,omitempty"`
	TaskID               string                               `json:"task_id,omitempty"`
	ExpectedRevision     int64                                `json:"expected_revision,omitempty"`
	OwnerEpoch           int64                                `json:"owner_epoch,omitempty"`
	HandoffMessageID     string                               `json:"handoff_message_id,omitempty"`
	ExpiresAt            string                               `json:"expires_at,omitempty"`
	RequiredArtifactRefs []store.SealedTaskHandoffArtifactRef `json:"required_artifact_refs,omitempty"`
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
	Digest           string `json:"message_digest,omitempty"`
	SharedMemoryRisk bool   `json:"shared_memory_risk,omitempty"`
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
	if request.Operation == "cross_node_task_handoff" {
		if request.OperationID != "" || response.CrossNodeGroup.MessageID != request.HandoffMessageID ||
			response.CrossNodeGroup.Digest == "" {
			return nil, &localSealedSendError{message: "local Node returned an uncorrelated sealed Task handoff receipt", retryable: true}
		}
	} else if request.OperationID != "" {
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
		request.IdempotencyKey, request.RequestID, request.ParentRequestID} {
		if len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("invalid trusted same-Group Node context")
		}
	}
	if len([]byte(request.Body)) > 60*1024 || len(request.Reason) > 512 {
		return errors.New("invalid trusted same-Group message")
	}
	switch request.Operation {
	case "cross_node_group_send":
		if request.TargetEndpointID == "" || request.OperationID == "" || request.IdempotencyKey == "" ||
			request.Body == "" || request.RequestID != "" || request.ParentRequestID != "" ||
			request.OperationCreatedAt != "" || request.Reason != "" {
			return errors.New("invalid same-Group SEND")
		}
		_, _, err := localSealedRPCIDs(request.OperationID)
		return err
	case "cross_node_group_ask":
		if request.TargetEndpointID == "" || request.OperationID == "" || request.IdempotencyKey == "" ||
			request.Body == "" || request.RequestID != "" || request.Reason != "" {
			return errors.New("invalid same-Group ASK")
		}
		if len(request.ParentRequestID) > 256 || request.ParentRequestID != strings.TrimSpace(request.ParentRequestID) ||
			strings.ContainsAny(request.ParentRequestID, "\r\n\x00") {
			return errors.New("same-Group ASK parent request ID is invalid")
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
			request.RequestID == "" || request.ParentRequestID != "" || request.Body == "" ||
			request.OperationCreatedAt != "" || request.Reason != "" {
			return errors.New("invalid same-Group REPLY")
		}
		_, _, err := localSealedRPCIDs(request.OperationID)
		return err
	case "cross_node_group_status", "cross_node_group_cancel":
		if request.RequestID == "" || request.TargetEndpointID != "" || request.OperationID != "" ||
			request.IdempotencyKey != "" || request.ParentRequestID != "" || request.Body != "" || request.OperationCreatedAt != "" ||
			request.Reason != "" {
			return errors.New("invalid same-Group request control")
		}
	case "cross_node_task_handoff":
		if request.TargetEndpointID == "" || request.OperationID != "" || request.IdempotencyKey == "" ||
			request.TaskHandoffID == "" || request.TaskID == "" || request.ExpectedRevision <= 0 ||
			request.OwnerEpoch <= 0 || request.HandoffMessageID == "" || request.ExpiresAt == "" ||
			request.Body == "" || request.RequestID != "" || request.ParentRequestID != "" || request.OperationCreatedAt != "" ||
			request.Reason != "" || len(request.RequiredArtifactRefs) > 32 {
			return errors.New("invalid sealed Task handoff SEND")
		}
		handoffID, deadline, ok := parseTaskHandoffMessageID(request.HandoffMessageID)
		parsed, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
		if !ok || handoffID != request.TaskHandoffID || !validTaskHandoffToken(request.TaskID) ||
			!validTaskHandoffToken(request.TaskHandoffID) || err != nil ||
			deadline.UnixMilli() != parsed.UnixMilli() || parsed.Nanosecond()%1_000_000 != 0 ||
			!parsed.After(time.Now().UTC()) || parsed.Sub(time.Now().UTC()) > 24*time.Hour {
			return errors.New("sealed Task handoff message ID does not match its deadline")
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
	if operation.Kind == "sealed_task_handoff" {
		return m.dispatchSealedTaskHandoffOutbox(outbox, scope, operation, input)
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
		ParentRequestID: input.ParentRequestID,
	}
	switch operation.Kind {
	case "send", "ask":
		card, resolveErr := m.resolveMCPOutboxTarget(operation, input.Target)
		if resolveErr != nil {
			return m.recordSealedRPCError(outbox, scope, operation, resolveErr)
		}
		if card.GroupID != trusted.GroupID || card.EndpointID == trusted.EndpointID {
			return m.recordSealedRPCError(outbox, scope, operation,
				errors.New("target is not a distinct same-Group Endpoint"))
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

func (m *mcpServer) dispatchSealedTaskHandoffOutbox(outbox *mcpOutboxStore,
	scope mcpOutboxScope, operation mcpOutboxOperation, input mcpOutboxInput) (any, error) {
	refs, err := parseOutboxTaskHandoffRefs(input.RequiredArtifactRefsJSON)
	if err != nil || operation.OperationID == "" || input.TaskID == "" || input.Target == "" ||
		input.ExpectedRevision <= 0 || input.OwnerEpoch <= 0 || input.Body == "" || input.ExpiresAt == "" {
		if err == nil {
			err = errors.New("durable sealed Task handoff input is incomplete")
		}
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	trusted, err := m.currentLocalSealedSendRequest(operation, input)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	if !trusted.LocalPeerDeliveryPresent || trusted.LocalPeerDelivery != "sealed_v1" {
		return m.recordSealedRPCError(outbox, scope, operation,
			errors.New("same-Group Task handoff requires current sealed_v1 peer delivery"))
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, input.ExpiresAt)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, errors.New("durable handoff expiry is invalid"))
	}
	expiresAt = time.UnixMilli(expiresAt.UnixMilli()).UTC()
	if !expiresAt.After(time.Now().UTC()) || expiresAt.Sub(time.Now().UTC()) > 24*time.Hour {
		return m.recordSealedRPCError(outbox, scope, operation, errors.New("durable handoff expiry is outside the supported window"))
	}
	handoffID := operation.OperationID
	messageID := "shared-task-handoff.v1:" + strconv.FormatInt(expiresAt.UnixMilli(), 10) + ":" + handoffID
	request := crossNodeGroupRequest{
		Operation: "cross_node_task_handoff", Harness: trusted.Harness,
		NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID, Workspace: trusted.Workspace,
		SessionToken: trusted.SessionToken, EndpointID: trusted.EndpointID, PrincipalID: trusted.PrincipalID,
		OwnerID: trusted.OwnerID, GroupID: trusted.GroupID, BindingID: trusted.BindingID,
		BindingEpoch: trusted.BindingEpoch, TargetEndpointID: input.Target,
		IdempotencyKey: operation.IdempotencyKey, Body: input.Body, TaskHandoffID: handoffID,
		TaskID: input.TaskID, ExpectedRevision: input.ExpectedRevision, OwnerEpoch: input.OwnerEpoch,
		HandoffMessageID: messageID, ExpiresAt: expiresAt.Format(time.RFC3339Nano),
		RequiredArtifactRefs: refs,
	}
	card, resolveErr := m.resolveMCPOutboxTarget(operation, input.RequestedTarget)
	if resolveErr != nil || card.EndpointID != input.Target || card.GroupID != scope.GroupID {
		if resolveErr == nil {
			resolveErr = errors.New("Task handoff target no longer resolves to its durable Endpoint")
		}
		return m.recordSealedRPCError(outbox, scope, operation, resolveErr)
	}
	if card.NodeID == trusted.NodeID {
		localRequest := localGroupRequest{
			Operation: "local_task_handoff", Harness: trusted.Harness,
			NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID, Workspace: trusted.Workspace,
			SessionToken: trusted.SessionToken, EndpointID: trusted.EndpointID, PrincipalID: trusted.PrincipalID,
			OwnerID: trusted.OwnerID, GroupID: trusted.GroupID, BindingID: trusted.BindingID,
			BindingEpoch: trusted.BindingEpoch, OperationID: operation.OperationID,
			OperationCreatedAt: operation.CreatedAt, IdempotencyKey: operation.IdempotencyKey,
			Target: input.Target, Body: input.Body, TaskHandoffID: handoffID, TaskID: input.TaskID,
			ExpectedRevision: input.ExpectedRevision, OwnerEpoch: input.OwnerEpoch,
			HandoffMessageID: messageID, ExpiresAt: expiresAt.Format(time.RFC3339Nano),
			RequiredArtifactRefs: refs,
		}
		localResult, localErr := requestMachineAgentLocalGroup(defaultMCPJoinSocketPath(harness.SessionContext{
			Harness: localRequest.Harness, NativeSessionID: localRequest.NativeSessionID,
			MachineID: localRequest.NodeID, Workspace: localRequest.Workspace,
		}), localRequest)
		if localErr != nil {
			return m.recordSealedRPCError(outbox, scope, operation, localErr)
		}
		if localResult == nil || localResult.MessageID != messageID || localResult.TargetEndpointID != input.Target ||
			localResult.Delivery != "LOCAL_PERSISTED" || localResult.PayloadMode != "SEALED_V1" ||
			!validSHA256Hex(localResult.MessageDigest) || len(localResult.SenderProof) == 0 {
			return m.recordSealedRPCError(outbox, scope, operation,
				&localSealedSendError{message: "local Node returned an incomplete sealed Task handoff receipt", retryable: true})
		}
		delivery := &crossNodeGroupResult{MessageID: localResult.MessageID,
			TargetEndpointID: localResult.TargetEndpointID, State: localResult.State,
			Delivery: localResult.Delivery, PayloadMode: localResult.PayloadMode, Digest: localResult.MessageDigest,
			SharedMemoryRisk: localResult.SharedMemoryRisk}
		return m.dispatchLocalSealedTaskHandoffProposal(outbox, scope, operation, input, refs,
			expiresAt, messageID, localResult.SenderProof, delivery, localRequest)
	}
	result, err := requestMachineAgentCrossNodeGroup(defaultMCPJoinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	if result == nil || result.PayloadMode != store.RelayPayloadModeSealedV1 ||
		result.MessageID != messageID || result.TargetEndpointID != input.Target ||
		result.Delivery != "RELAY_PERSISTED" || len(result.Digest) != 64 {
		return m.recordSealedRPCError(outbox, scope, operation,
			&localSealedSendError{message: "local Node returned an incomplete sealed Task handoff receipt", retryable: true})
	}
	// The local Node's durable crypto outbox reuses the exact sealed packet for
	// this operation ID. Recover the Hub proposal before issuing another POST:
	// the first response may have been lost and the receiver may already have
	// accepted the proposal by the time this retry runs.
	existing, found, err := m.getSealedTaskHandoff(scope, handoffID)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	if found {
		if !sealedTaskHandoffMatches(existing, operation, scope, input, refs, expiresAt, messageID, result.Digest) {
			return m.recordSealedRPCError(outbox, scope, operation,
				errors.New("Hub handoff metadata conflicts with the exact durable sealed operation"))
		}
		return m.markSealedTaskHandoffSent(outbox, scope, operation, request.SessionToken, *existing, result)
	}
	proposal := fabricpkg.SealedTaskHandoffProposeInput{
		HandoffID: handoffID, TaskID: input.TaskID, Target: input.Target,
		ExpectedRevision: input.ExpectedRevision, OwnerEpoch: input.OwnerEpoch,
		MessageID: result.MessageID, MessageDigest: result.Digest, ExpiresAt: expiresAt.Format(time.RFC3339Nano),
		RequiredArtifactRefs: refs,
	}
	proposed, err := m.apiForGroup(http.MethodPost, "/v2/fabric/tasks/sealed-handoffs", proposal, scope.GroupID)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	var handoff store.SealedSharedTaskHandoff
	encodedProposal, marshalErr := json.Marshal(proposed)
	if marshalErr != nil || json.Unmarshal(encodedProposal, &handoff) != nil || handoff.ID != handoffID ||
		!sealedTaskHandoffMatches(&handoff, operation, scope, input, refs, expiresAt, messageID, result.Digest) {
		return m.recordSealedRPCError(outbox, scope, operation,
			&localSealedSendError{message: "Hub returned an uncorrelated sealed Task handoff proposal", retryable: true})
	}
	return m.markSealedTaskHandoffSent(outbox, scope, operation, request.SessionToken, handoff, result)
}

func (m *mcpServer) dispatchLocalSealedTaskHandoffProposal(outbox *mcpOutboxStore,
	scope mcpOutboxScope, operation mcpOutboxOperation, input mcpOutboxInput,
	refs []store.SealedTaskHandoffArtifactRef, expiresAt time.Time, messageID string,
	senderProof []byte, delivery *crossNodeGroupResult, localRequest localGroupRequest) (any, error) {
	handoffID := operation.OperationID
	existing, found, err := m.getSealedTaskHandoff(scope, handoffID)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	if found {
		if !sealedTaskHandoffMatches(existing, operation, scope, input, refs, expiresAt, messageID, delivery.Digest) {
			return m.recordSealedRPCError(outbox, scope, operation,
				errors.New("Hub handoff metadata conflicts with the exact durable local sealed operation"))
		}
		if existing.Status == store.SealedTaskHandoffProposed {
			if _, err := m.wakeLocalSealedTaskHandoff(localRequest); err != nil {
				return m.recordSealedRPCError(outbox, scope, operation, err)
			}
		}
		return m.markSealedTaskHandoffSent(outbox, scope, operation, localRequest.SessionToken, *existing, delivery)
	}
	proposal := fabricpkg.LocalSealedTaskHandoffProposeInput{
		HandoffID: handoffID, TaskID: input.TaskID, Target: input.Target,
		ExpectedRevision: input.ExpectedRevision, OwnerEpoch: input.OwnerEpoch,
		MessageID: messageID, MessageDigest: delivery.Digest,
		ExpiresAt: expiresAt.Format(time.RFC3339Nano), RequiredArtifactRefs: refs,
		SenderProof: senderProof,
	}
	result, err := m.apiForGroup(http.MethodPost, "/v2/fabric/tasks/sealed-handoffs/local", proposal, scope.GroupID)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	encoded, marshalErr := json.Marshal(result)
	var handoff store.SealedSharedTaskHandoff
	if marshalErr != nil || json.Unmarshal(encoded, &handoff) != nil || handoff.ID != handoffID ||
		!sealedTaskHandoffMatches(&handoff, operation, scope, input, refs, expiresAt, messageID, delivery.Digest) {
		return m.recordSealedRPCError(outbox, scope, operation,
			&localSealedSendError{message: "Hub returned an uncorrelated local sealed Task handoff proposal", retryable: true})
	}
	if handoff.Status == store.SealedTaskHandoffProposed {
		if _, err := m.wakeLocalSealedTaskHandoff(localRequest); err != nil {
			return m.recordSealedRPCError(outbox, scope, operation, err)
		}
	}
	return m.markSealedTaskHandoffSent(outbox, scope, operation, localRequest.SessionToken, handoff, delivery)
}

func (m *mcpServer) wakeLocalSealedTaskHandoff(request localGroupRequest) (*localGroupResult, error) {
	request.Operation = "local_task_handoff_notify"
	request.OperationID, request.OperationCreatedAt, request.IdempotencyKey = "", "", ""
	request.Target, request.Body, request.RequestID = "", "", ""
	request.TaskID, request.HandoffMessageID, request.ExpiresAt = "", "", ""
	request.ExpectedRevision, request.OwnerEpoch = 0, 0
	request.RequiredArtifactRefs = nil
	result, err := requestMachineAgentLocalGroup(defaultMCPJoinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return nil, err
	}
	if result == nil || result.Delivery != "LOCAL_WAKE" || result.State != "READY" {
		return nil, &localSealedSendError{message: "local Node did not confirm the Task handoff wake", retryable: true}
	}
	return result, nil
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, b := range []byte(value) {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return false
		}
	}
	return true
}

func (m *mcpServer) getSealedTaskHandoff(scope mcpOutboxScope, handoffID string) (*store.SealedSharedTaskHandoff, bool, error) {
	result, err := m.apiForGroup(http.MethodGet, "/v2/fabric/tasks/sealed-handoffs/"+url.PathEscape(handoffID), nil, scope.GroupID)
	if err != nil {
		var responseErr *mcpHTTPError
		if errors.As(err, &responseErr) && responseErr.statusCode == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, false, err
	}
	var handoff store.SealedSharedTaskHandoff
	if err := json.Unmarshal(encoded, &handoff); err != nil || handoff.ID != handoffID {
		return nil, false, errors.New("Hub returned invalid sealed Task handoff recovery metadata")
	}
	return &handoff, true, nil
}

func sealedTaskHandoffMatches(handoff *store.SealedSharedTaskHandoff, operation mcpOutboxOperation,
	scope mcpOutboxScope, input mcpOutboxInput, refs []store.SealedTaskHandoffArtifactRef,
	expiresAt time.Time, messageID, digest string) bool {
	if handoff == nil || handoff.ID != operation.OperationID || handoff.TaskID != input.TaskID ||
		handoff.GroupID != scope.GroupID || handoff.FromEndpointID != scope.EndpointID ||
		handoff.ToEndpointID != input.Target || handoff.TaskRevision != input.ExpectedRevision ||
		handoff.FromOwnerEpoch != input.OwnerEpoch || handoff.MessageID != messageID ||
		handoff.MessageDigest != digest || handoff.ExpiresAt != expiresAt.Format(time.RFC3339Nano) ||
		handoff.Version <= 0 || (handoff.Status != store.SealedTaskHandoffProposed &&
		handoff.Status != store.SealedTaskHandoffTransferred) || len(handoff.RequiredArtifactRefs) != len(refs) {
		return false
	}
	for i := range refs {
		if handoff.RequiredArtifactRefs[i] != refs[i] {
			return false
		}
	}
	return true
}

func (m *mcpServer) markSealedTaskHandoffSent(outbox *mcpOutboxStore, scope mcpOutboxScope,
	operation mcpOutboxOperation, sessionToken string, handoff store.SealedSharedTaskHandoff,
	delivery *crossNodeGroupResult) (any, error) {
	public := map[string]any{"handoff": handoff, "delivery": delivery}
	resultJSON, err := mcpOutboxResultJSON(public, sessionToken)
	if err != nil {
		return m.recordSealedRPCError(outbox, scope, operation, err)
	}
	sent, err := outbox.markResult(scope, operation.OperationID, mcpOutboxStatusSent, "", resultJSON)
	if err != nil {
		operation.Status = mcpOutboxStatusUnknown
		operation.LastError = "local outbox handoff result persistence failed"
		return mcpOutboxPublicResult(operation), nil
	}
	return mcpOutboxPublicResult(sent), nil
}
