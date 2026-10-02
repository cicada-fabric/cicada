package main

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

type monitorBroadcastOutcomeResponse struct {
	HubID          string                                         `json:"hub_id"`
	PreviewID      string                                         `json:"preview_id"`
	BroadcastID    string                                         `json:"broadcast_id"`
	OperationID    string                                         `json:"operation_id"`
	SnapshotDigest string                                         `json:"snapshot_digest"`
	Results        []store.UserMonitorBroadcastV2RecipientOutcome `json:"results"`
}

// Report the verified dispatch transport only. The Hub verifies Relay persistence
// on either Node route; authenticated historical local replay remains Node-reported.
// An uncertain report reply cannot turn an accepted child into a new message.
func (b *machineAgentJoinBridge) reportMonitorBroadcastOutcomes(request monitorBroadcastRequest,
	snapshot *store.SameGroupBroadcastV2Snapshot, progress *groupBroadcastResult) error {
	if snapshot == nil || progress == nil || progress.BroadcastID != snapshot.BroadcastID ||
		progress.SnapshotDigest != snapshot.SnapshotDigest || progress.Offset != request.Offset ||
		progress.NextOffset > len(snapshot.Recipients) || progress.NextOffset < progress.Offset ||
		progress.Offset < 0 || len(progress.Recipients) != progress.NextOffset-progress.Offset ||
		len(progress.Recipients) > groupBroadcastBatchSize {
		return errors.New("Monitor outcome batch does not match its immutable snapshot")
	}
	if len(progress.Recipients) == 0 {
		return nil
	}
	input := store.UserMonitorBroadcastV2OutcomeReportInput{BroadcastID: snapshot.BroadcastID,
		OperationID: "op_" + strings.TrimPrefix(snapshot.BroadcastID, "bc_"), SnapshotDigest: snapshot.SnapshotDigest,
		Results: make([]store.UserMonitorBroadcastV2RecipientReport, 0, len(progress.Recipients))}
	for i, child := range progress.Recipients {
		ordinal := progress.Offset + i
		expected := snapshot.Recipients[ordinal]
		childID, messageID, err := store.UserMonitorBroadcastV2ChildIDs(snapshot.BroadcastID, expected.EndpointID)
		if err != nil || child.EndpointID != expected.EndpointID || child.NodeID != expected.NodeID ||
			!validBroadcastRecipientResult(child) || (child.State == "ACCEPTED" && child.MessageID != messageID) {
			return errors.New("Monitor child outcome identity is inconsistent")
		}
		report := store.UserMonitorBroadcastV2RecipientReport{Ordinal: ordinal, EndpointID: child.EndpointID,
			ChildOperationID: childID, MessageID: messageID, State: child.State, FailureCode: child.FailureCode}
		if child.State == "ACCEPTED" {
			switch child.transportEvidence {
			case "RELAY_PERSISTED":
				report.Evidence = store.UserMonitorBroadcastV2EvidenceRelay
			case "LOCAL_PERSISTED":
				if child.NodeID != b.nodeID {
					return errors.New("historical local child belongs to another Node")
				}
				report.Evidence = store.UserMonitorBroadcastV2EvidenceNode
			default:
				return errors.New("Monitor child lacks verified transport evidence")
			}
		}
		input.Results = append(input.Results, report)
	}
	// Use the Node-only wire DTO: the path supplies preview_id, and credentials
	// live exclusively in headers. Store's internal input is not a wire schema.
	wire := struct {
		BroadcastID    string                                        `json:"broadcast_id"`
		OperationID    string                                        `json:"operation_id"`
		SnapshotDigest string                                        `json:"snapshot_digest"`
		Results        []store.UserMonitorBroadcastV2RecipientReport `json:"results"`
	}{input.BroadcastID, input.OperationID, input.SnapshotDigest, input.Results}
	var response monitorBroadcastOutcomeResponse
	if err := b.monitorBroadcastHub(http.MethodPost, "/"+url.PathEscape(request.PreviewID)+"/outcomes",
		request.SessionToken, wire, &response); err != nil {
		return &localSealedSendError{message: "Monitor outcome report is unconfirmed; reconcile the same operation", retryable: true}
	}
	if !monitorBroadcastHubMatchesFor(b.ctx, response.HubID) || response.PreviewID != request.PreviewID ||
		response.BroadcastID != input.BroadcastID || response.OperationID != input.OperationID ||
		response.SnapshotDigest != input.SnapshotDigest || len(response.Results) != len(snapshot.Recipients) {
		return errors.New("Monitor outcome receipt is uncorrelated")
	}
	for _, reported := range input.Results {
		stored := response.Results[reported.Ordinal]
		if stored.Ordinal != reported.Ordinal || stored.EndpointID != reported.EndpointID ||
			!monitorOutcomeAcknowledges(stored, reported) {
			return errors.New("Monitor outcome receipt lost existing transport evidence")
		}
	}
	return nil
}

func monitorOutcomeAcknowledges(stored store.UserMonitorBroadcastV2RecipientOutcome,
	reported store.UserMonitorBroadcastV2RecipientReport) bool {
	if stored.State == store.UserMonitorBroadcastV2OutcomeAccepted {
		if stored.MessageID != reported.MessageID || stored.FailureCode != "" ||
			(stored.Evidence != store.UserMonitorBroadcastV2EvidenceNode && stored.Evidence != store.UserMonitorBroadcastV2EvidenceRelay) {
			return false
		}
		if reported.State == store.UserMonitorBroadcastV2OutcomeAccepted {
			return reported.FailureCode == "" && stored.Evidence == reported.Evidence
		}
		// A retry can report a lower, uncertain attempt after the Hub already
		// persisted this exact Relay child. Acknowledge that durable fact without
		// changing the current attempt's UNKNOWN/FAILED progress or consumption.
		if stored.Evidence != store.UserMonitorBroadcastV2EvidenceRelay || reported.Evidence != "" {
			return false
		}
		switch reported.State {
		case store.UserMonitorBroadcastV2OutcomeUnknown:
			return reported.FailureCode == "DELIVERY_OUTCOME_UNKNOWN"
		case store.UserMonitorBroadcastV2OutcomeFailed:
			return reported.FailureCode == "DELIVERY_REJECTED"
		default:
			return false
		}
	}
	if stored.Evidence != "" || stored.MessageID != "" {
		return false
	}
	switch stored.State {
	case store.UserMonitorBroadcastV2OutcomeUnknown:
		return reported.State != store.UserMonitorBroadcastV2OutcomeAccepted && stored.FailureCode == "DELIVERY_OUTCOME_UNKNOWN"
	case store.UserMonitorBroadcastV2OutcomeFailed:
		return reported.State == store.UserMonitorBroadcastV2OutcomeFailed && stored.FailureCode == "DELIVERY_REJECTED"
	default:
		return false
	}
}
