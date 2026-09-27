package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cicada-ai/cicada/internal/harness"
)

const mcpBroadcastMaxRecipients = 32

// mcpBroadcastProgress is safe to expose to a model: it contains route and
// delivery state only. The immutable body remains in the native-session MCP
// outbox, while the recipient snapshot lives in the Hub Store.
type mcpBroadcastProgress struct {
	BroadcastID    string                          `json:"broadcast_id"`
	GroupID        string                          `json:"group_id"`
	SnapshotDigest string                          `json:"snapshot_digest"`
	RecipientCount int                             `json:"recipient_count"`
	NextOffset     int                             `json:"next_offset"`
	Complete       bool                            `json:"complete"`
	Recipients     []groupBroadcastRecipientResult `json:"recipients"`
}

func mcpBroadcastID(operationID string) (string, error) {
	if !strings.HasPrefix(operationID, "op_") || len(operationID) <= 3 {
		return "", errors.New("invalid durable broadcast operation ID")
	}
	return "bc_" + strings.TrimPrefix(operationID, "op_"), nil
}

func (m *mcpServer) dispatchBroadcastMCPOutbox(outbox *mcpOutboxStore,
	scope mcpOutboxScope, operation mcpOutboxOperation) (any, error) {
	var input mcpOutboxInput
	if err := json.Unmarshal([]byte(operation.InputJSON), &input); err != nil ||
		input.Body == "" || len([]byte(input.Body)) > 64*1024 || input.LinkID != "" ||
		input.Target != "" || input.DataScope != "" || input.Question != "" || input.RequestID != "" {
		failed, persistErr := outbox.markError(scope, operation.OperationID, mcpOutboxStatusFailed,
			errors.New("broadcast has invalid immutable input"))
		if persistErr != nil {
			return nil, persistErr
		}
		return mcpOutboxPublicResult(failed), nil
	}
	broadcastID, err := mcpBroadcastID(operation.OperationID)
	if err != nil {
		return m.recordBroadcastError(outbox, scope, operation, err)
	}
	progress := mcpBroadcastProgress{BroadcastID: broadcastID, GroupID: operation.GroupID}
	if operation.ResultJSON != "" {
		if err := json.Unmarshal([]byte(operation.ResultJSON), &progress); err != nil ||
			progress.BroadcastID != broadcastID || progress.GroupID != operation.GroupID ||
			progress.RecipientCount < 0 || progress.RecipientCount > mcpBroadcastMaxRecipients ||
			progress.NextOffset < 0 || progress.NextOffset > progress.RecipientCount {
			return m.recordBroadcastError(outbox, scope, operation,
				errors.New("durable broadcast progress is invalid"))
		}
	}
	trusted, err := m.currentLocalSealedSendRequest(operation, input)
	if err != nil {
		return m.recordBroadcastError(outbox, scope, operation, err)
	}
	if !trusted.LocalPeerDeliveryPresent || trusted.LocalPeerDelivery != "sealed_v1" {
		return m.recordBroadcastError(outbox, scope, operation,
			errors.New("broadcast requires sealed native Endpoint delivery"))
	}
	offset := progress.NextOffset
	if progress.Complete {
		// An explicit retry after a partial result replays the same fixed
		// snapshot and stable per-recipient IDs. Accepted children deduplicate.
		offset = 0
	}
	request := groupBroadcastRequest{
		Operation: "group_broadcast", Harness: trusted.Harness,
		NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID,
		Workspace: trusted.Workspace, SessionToken: trusted.SessionToken,
		EndpointID: trusted.EndpointID, PrincipalID: trusted.PrincipalID,
		OwnerID: trusted.OwnerID, GroupID: trusted.GroupID,
		BindingID: trusted.BindingID, BindingEpoch: trusted.BindingEpoch,
		OperationID: operation.OperationID, BroadcastID: broadcastID,
		Body: input.Body, Offset: offset,
	}
	result, err := requestMachineAgentGroupBroadcast(defaultMCPJoinSocketPath(harness.SessionContext{
		Harness: request.Harness, NativeSessionID: request.NativeSessionID,
		MachineID: request.NodeID, Workspace: request.Workspace,
	}), request)
	if err != nil {
		return m.recordBroadcastError(outbox, scope, operation, err)
	}
	if err := progress.apply(*result, request.Offset); err != nil {
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
		operation.Status = mcpOutboxStatusUnknown
		operation.LastError = "broadcast progress persistence failed"
		return mcpOutboxPublicResult(operation), nil
	}
	return mcpOutboxPublicResult(updated), nil
}

func (m *mcpServer) recordBroadcastError(outbox *mcpOutboxStore,
	scope mcpOutboxScope, operation mcpOutboxOperation, cause error) (any, error) {
	updated, err := outbox.markResult(scope, operation.OperationID,
		mcpOutboxStatusUnknown, m.safeMCPError(cause), operation.ResultJSON)
	if err != nil {
		return nil, err
	}
	return mcpOutboxPublicResult(updated), nil
}

func (progress *mcpBroadcastProgress) apply(result groupBroadcastResult, offset int) error {
	if result.BroadcastID != progress.BroadcastID || result.GroupID != progress.GroupID ||
		result.SnapshotDigest == "" || result.Offset != offset ||
		result.RecipientCount < 0 || result.RecipientCount > mcpBroadcastMaxRecipients ||
		offset < 0 || result.NextOffset < offset || result.NextOffset > result.RecipientCount ||
		len(result.Recipients) != result.NextOffset-result.Offset ||
		result.Complete != (result.NextOffset == result.RecipientCount) ||
		(!result.Complete && result.NextOffset == offset) ||
		(progress.SnapshotDigest != "" && progress.SnapshotDigest != result.SnapshotDigest) ||
		(progress.SnapshotDigest != "" && progress.RecipientCount != result.RecipientCount) {
		return errors.New("local Node returned inconsistent broadcast progress")
	}
	byEndpoint := make(map[string]groupBroadcastRecipientResult, len(progress.Recipients)+len(result.Recipients))
	for _, recipient := range progress.Recipients {
		if !validBroadcastRecipientResult(recipient) {
			return errors.New("durable broadcast recipient is invalid")
		}
		if _, duplicate := byEndpoint[recipient.EndpointID]; duplicate {
			return errors.New("durable broadcast recipient is duplicated")
		}
		byEndpoint[recipient.EndpointID] = recipient
	}
	seenInBatch := make(map[string]struct{}, len(result.Recipients))
	for _, recipient := range result.Recipients {
		if !validBroadcastRecipientResult(recipient) {
			return errors.New("local Node returned invalid broadcast recipient state")
		}
		if _, duplicate := seenInBatch[recipient.EndpointID]; duplicate {
			return errors.New("local Node returned a duplicate broadcast recipient")
		}
		seenInBatch[recipient.EndpointID] = struct{}{}
		previous := byEndpoint[recipient.EndpointID]
		if previous.NodeID != "" && previous.NodeID != recipient.NodeID {
			return errors.New("local Node changed a broadcast recipient Node")
		}
		if previous.MessageID != "" && recipient.MessageID != "" && previous.MessageID != recipient.MessageID {
			return errors.New("local Node changed a broadcast recipient message ID")
		}
		// A later failure cannot disprove a prior transport acceptance, and a
		// definite rejection of this attempt cannot resolve an older uncertain
		// attempt. Only positive evidence for the stable child ID advances it.
		if previous.State == "ACCEPTED" || (previous.State == "UNKNOWN" && recipient.State == "FAILED") {
			continue
		}
		byEndpoint[recipient.EndpointID] = recipient
	}
	if len(byEndpoint) > mcpBroadcastMaxRecipients || len(byEndpoint) > result.RecipientCount {
		return fmt.Errorf("broadcast recipient result exceeds immutable snapshot")
	}
	// Commit only after the entire batch validates. A malformed result must
	// not change the durable retry cursor or any previously accepted child.
	progress.SnapshotDigest = result.SnapshotDigest
	progress.RecipientCount = result.RecipientCount
	progress.NextOffset = result.NextOffset
	progress.Complete = result.Complete
	progress.Recipients = progress.Recipients[:0]
	for _, recipient := range byEndpoint {
		progress.Recipients = append(progress.Recipients, recipient)
	}
	sort.Slice(progress.Recipients, func(i, j int) bool {
		return progress.Recipients[i].EndpointID < progress.Recipients[j].EndpointID
	})
	return nil
}

func validBroadcastRecipientResult(result groupBroadcastRecipientResult) bool {
	if result.EndpointID == "" || result.NodeID == "" {
		return false
	}
	switch result.State {
	case "ACCEPTED":
		return result.MessageID != "" && result.FailureCode == ""
	case "FAILED":
		return result.MessageID == "" && result.FailureCode == "DELIVERY_REJECTED"
	case "UNKNOWN":
		return result.MessageID == "" && result.FailureCode == "DELIVERY_OUTCOME_UNKNOWN"
	default:
		return false
	}
}

func (progress mcpBroadcastProgress) allAccepted() bool {
	if len(progress.Recipients) != progress.RecipientCount {
		return false
	}
	for _, recipient := range progress.Recipients {
		if recipient.State != "ACCEPTED" || recipient.MessageID == "" {
			return false
		}
	}
	return true
}
