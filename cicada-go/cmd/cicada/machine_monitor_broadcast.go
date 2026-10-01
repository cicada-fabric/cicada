package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/store"
)

func machineMonitorBroadcastInboxPath(stateDir, nodeID string) string {
	return filepath.Join(machineNodeStateDir(stateDir, nodeID), "monitor-broadcast-inbox.sqlite")
}

func openExistingMachineMonitorBroadcastInbox(path string) (*nodeinbox.Inbox, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect Monitor management inbox: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Monitor management inbox path is not a regular file")
	}
	return nodeinbox.Open(path)
}

// Notice receipt state is mutable; it is not part of the original delivery
// identity persisted in the Node inbox. No readable broadcast body is queued.
func monitorNotificationBytes(n store.UserMonitorBroadcastV2Notification) ([]byte, string, error) {
	n.ReceiptState = ""
	payload, err := json.Marshal(n)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(payload)
	return payload, hex.EncodeToString(digest[:]), nil
}

func (b *machineAgentJoinBridge) reportMonitorNotification(n store.UserMonitorBroadcastV2Notification,
	state nodeinbox.State) error {
	receipt := "NODE_ACCEPTED"
	switch state {
	case nodeinbox.CONSUMPTION_UNCONFIRMED, nodeinbox.RUNTIME_INJECTED:
		receipt = "QUEUE_ACCEPTED"
	case nodeinbox.INJECTION_UNCERTAIN:
		receipt = "INJECTION_UNCERTAIN"
	case nodeinbox.FAILED:
		receipt = "FAILED"
	case nodeinbox.NODE_RECEIVED, nodeinbox.INJECTING:
	default:
		return errors.New("unknown Monitor notification receipt state")
	}
	input := map[string]any{"broadcast_id": n.BroadcastID, "snapshot_digest": n.SnapshotDigest,
		"binding_id": n.BindingID, "binding_epoch": n.BindingEpoch, "state": receipt}
	var response monitorBroadcastNotificationResponse
	if err := b.monitorBroadcastHub(http.MethodPost, "/"+url.PathEscape(n.PreviewID)+"/receipt", "", input, &response); err != nil {
		return err
	}
	hubMatches := monitorBroadcastHubMatchesFor(b.ctx, response.HubID)
	notificationPresent := response.Notification != nil
	receiptMatches := notificationPresent && response.Notification.ReceiptState == receipt
	metadataMatches := notificationPresent && sameMonitorBroadcastNotification(*response.Notification, n)
	if !hubMatches || !notificationPresent || !receiptMatches || !metadataMatches {
		metadataFields := "missing_notification"
		if notificationPresent {
			metadataFields = strings.Join(monitorNotificationMismatchFields(*response.Notification, n), ",")
		}
		return fmt.Errorf("Monitor notification receipt is uncorrelated (hub=%t notification=%t receipt=%t metadata_fields=%s)",
			hubMatches, notificationPresent, receiptMatches, metadataFields)
	}
	// This acknowledges an already persisted fact. It must match the original
	// notice exactly, but crossing its deadline during injection does not erase
	// that fact. Fresh notice reads still enforce expiry before any injection.
	return nil
}

func sameMonitorBroadcastNotification(a, b store.UserMonitorBroadcastV2Notification) bool {
	return len(monitorNotificationMismatchFields(a, b)) == 0
}

func monitorNotificationMismatchFields(a, b store.UserMonitorBroadcastV2Notification) []string {
	var mismatches []string
	if a.HubID != b.HubID {
		mismatches = append(mismatches, "hub_id")
	}
	if a.PreviewID != b.PreviewID {
		mismatches = append(mismatches, "preview_id")
	}
	if a.BroadcastID != b.BroadcastID {
		mismatches = append(mismatches, "broadcast_id")
	}
	if a.GroupID != b.GroupID {
		mismatches = append(mismatches, "group_id")
	}
	if (a.NativeContextScope == nil) != (b.NativeContextScope == nil) {
		mismatches = append(mismatches, "native_context_scope")
	} else if a.NativeContextScope != nil && *a.NativeContextScope != *b.NativeContextScope {
		if a.NativeContextScope.HubID != b.NativeContextScope.HubID {
			mismatches = append(mismatches, "scope.hub_id")
		}
		if a.NativeContextScope.NetworkID != b.NativeContextScope.NetworkID {
			mismatches = append(mismatches, "scope.network_id")
		}
		if a.NativeContextScope.GroupID != b.NativeContextScope.GroupID {
			mismatches = append(mismatches, "scope.group_id")
		}
		if a.NativeContextScope.GroupContextPolicy != b.NativeContextScope.GroupContextPolicy {
			mismatches = append(mismatches, "scope.group_policy")
		}
		if a.NativeContextScope.NetworkContextPolicy != b.NativeContextScope.NetworkContextPolicy {
			mismatches = append(mismatches, "scope.network_policy")
		}
	}
	if a.MonitorEndpointID != b.MonitorEndpointID {
		mismatches = append(mismatches, "monitor_endpoint_id")
	}
	if a.NodeID != b.NodeID {
		mismatches = append(mismatches, "node_id")
	}
	if a.NativeSessionID != b.NativeSessionID {
		mismatches = append(mismatches, "native_session_id")
	}
	if a.BindingID != b.BindingID {
		mismatches = append(mismatches, "binding_id")
	}
	if a.BindingEpoch != b.BindingEpoch {
		mismatches = append(mismatches, "binding_epoch")
	}
	if a.BodyDigest != b.BodyDigest {
		mismatches = append(mismatches, "body_digest")
	}
	if a.SnapshotDigest != b.SnapshotDigest {
		mismatches = append(mismatches, "snapshot_digest")
	}
	if a.ExpiresAt != b.ExpiresAt {
		mismatches = append(mismatches, "expires_at")
	}
	return mismatches
}

// Management notices have their own durable inbox. The peer inbox cannot
// accidentally consume them as a SEND or claim that the broadcast succeeded.
func processMachineMonitorBroadcastNotifications(ctx context.Context, bridge *machineAgentJoinBridge,
	inbox **nodeinbox.Inbox, inboxPath string) error {
	if bridge == nil || inbox == nil || strings.TrimSpace(inboxPath) == "" {
		return errors.New("Monitor notifications need an authenticated Node and inbox path")
	}
	var response monitorBroadcastNotificationsResponse
	if err := bridge.monitorBroadcastHub(http.MethodGet, "", "", nil, &response); err != nil {
		return err
	}
	if !monitorBroadcastHubMatchesFor(ctx, response.HubID) || len(response.Notifications) > 16 {
		return errors.New("Monitor notice list does not match the configured Hub")
	}
	for _, listed := range response.Notifications {
		if validateMonitorBroadcastNotificationFor(ctx, listed, listed.PreviewID, bridge.nodeID, false) != nil {
			return errors.New("Monitor notice list contains an invalid Node or Hub hint")
		}
	}
	if *inbox == nil {
		existing, err := openExistingMachineMonitorBroadcastInbox(inboxPath)
		if err != nil {
			return fmt.Errorf("open Monitor management inbox: %w", err)
		}
		*inbox = existing
		if *inbox == nil && len(response.Notifications) != 0 {
			created, err := nodeinbox.Open(inboxPath)
			if err != nil {
				return fmt.Errorf("open Monitor management inbox: %w", err)
			}
			*inbox = created
		}
	}
	if *inbox == nil {
		return nil
	}
	for _, listed := range response.Notifications {
		// The list is an authenticated, bounded wake hint. The fresh detail read
		// in drainMachineMonitorBroadcastNotification remains the final Guard
		// check immediately before native injection.
		payload, digest, err := monitorNotificationBytes(listed)
		if err != nil {
			return err
		}
		delivery, _, err := (*inbox).Save(ctx, nodeinbox.Message{MessageID: listed.PreviewID, Digest: digest,
			EndpointID: listed.MonitorEndpointID, SessionID: listed.NativeSessionID, BindingEpoch: listed.BindingEpoch,
			GroupID: listed.GroupID, Payload: payload})
		if err != nil {
			return err
		}
		if err := bridge.reportMonitorNotification(listed, delivery.State); err != nil {
			return err
		}
	}
	for drained := 0; drained < 16; drained++ {
		claim, err := (*inbox).Claim(ctx, "monitor-notice:"+bridge.nodeID)
		if errors.Is(err, nodeinbox.ErrNoDelivery) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := drainMachineMonitorBroadcastNotification(ctx, bridge, *inbox, *claim); err != nil {
			return err
		}
	}
	// Process jobs and Relay work after at most one bounded Monitor batch.
	return nil
}

func drainMachineMonitorBroadcastNotification(ctx context.Context, bridge *machineAgentJoinBridge,
	inbox *nodeinbox.Inbox, claim nodeinbox.Claim) error {
	var original store.UserMonitorBroadcastV2Notification
	if json.Unmarshal(claim.Payload, &original) != nil || original.PreviewID != claim.MessageID {
		return inbox.RejectBeforeInjection(ctx, claim, "Monitor notice metadata is invalid")
	}
	current, err := bridge.monitorBroadcastNotification(original.PreviewID)
	if err != nil {
		if localSealedSendRetryable(err) {
			_ = inbox.AbandonClaim(ctx, claim.AttemptID)
			return err
		}
		return inbox.RejectBeforeInjection(ctx, claim, "Monitor authorization no longer permits notification")
	}
	_, digest, err := monitorNotificationBytes(*current)
	if err != nil || digest != claim.Digest || current.MonitorEndpointID != claim.EndpointID ||
		current.NativeSessionID != claim.SessionID || current.BindingEpoch != claim.BindingEpoch {
		return inbox.RejectBeforeInjection(ctx, claim, "Monitor notice target changed")
	}
	var nativeScope nodeinbox.NativeContextScopeInput
	decision := &nodeinbox.NativeContextScopeDecision{Accepted: true,
		NativeHistoryCoverage: nodeinbox.NativeContextHistoryCoverageNotChecked}
	if _, managed := machineHubFrom(ctx); managed && current.NativeContextScope != nil {
		nativeScope, err = machineNativeContextScopeFromMetadata(ctx, "codex",
			current.NativeSessionID, current.MonitorEndpointID, current.BindingID,
			current.BindingEpoch, *current.NativeContextScope)
		if err != nil {
			return inbox.RejectBeforeInjection(ctx, claim, "Monitor native context scope is unavailable")
		}
		decision, err = checkMachineNativeContext(ctx, nativeScope)
		if err != nil {
			return inbox.RejectBeforeInjection(ctx, claim, "Monitor native context scope was not accepted")
		}
	} else if hub, managed := machineHubFrom(ctx); managed {
		if hub.RequireNativeContext {
			return inbox.RejectBeforeInjection(ctx, claim, "Monitor authorization has no authoritative native context scope")
		}
	}
	if _, err := inbox.BeginInjection(ctx, claim.AttemptID); err != nil {
		return err
	}
	prompt := fmt.Sprintf("Cicada management notice: a pending Monitor broadcast is available for Group %s. "+
		"This notice is not approval evidence. In this original joined Group context, call "+
		"cicada_monitor_broadcast with approval_id %s to validate current user authority and send the exact sealed content. "+
		"Do not substitute text or create a new broadcast. Transport acceptance does not prove recipient consumption.",
		current.GroupID, current.PreviewID)
	if decision.SharedMemoryRisk {
		prompt = "CICADA_CONTEXT_SCOPE_SHARED_MEMORY_RISK: this native Codex Thread is known to have been used in more than one Cicada Group or Network scope. Treat earlier content as potentially visible and do not assume Cicada can erase or isolate Runtime history.\n" + prompt
	}
	receipt := localGroupReceipt(claim)
	operation, err := machineNativeOperation(ctx, claim, current.BindingID)
	if err != nil {
		return err
	}
	var queueErr error
	if nativeScope.NativeSessionID != "" {
		queueErr = executeMachineNativeCodex(ctx, claim.SessionID, prompt, operation, nativeScope)
	} else {
		queueErr = executeMachineNativeCodex(ctx, claim.SessionID, prompt, operation)
	}
	var recorded *nodeinbox.Delivery
	if queueErr == nil {
		if err = requireMachineNativeQueueOutcome(ctx, claim.SessionID, operation); err == nil {
			recorded, err = inbox.RecordCodexQueueAccepted(ctx, receipt)
		}
	} else {
		var uncertain *nativeInjectionUncertainError
		if errors.As(queueErr, &uncertain) {
			receipt.State = nodeinbox.INJECTION_UNCERTAIN
			receipt.Error = "native notice injection outcome is uncertain"
			recorded, err = inbox.Acknowledge(ctx, receipt)
		} else {
			recorded, err = inbox.RecordFailed(ctx, receipt, "native notice queue did not start")
		}
	}
	if err != nil {
		// INJECTING remains durable. Opening this inbox after a crash marks it
		// uncertain; a missing receipt must never trigger blind reinjection.
		return err
	}
	return bridge.reportMonitorNotification(*current, recorded.State)
}
