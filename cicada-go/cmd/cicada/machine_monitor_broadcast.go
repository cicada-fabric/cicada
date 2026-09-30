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
	if !monitorBroadcastHubMatchesFor(b.ctx, response.HubID) || response.Notification == nil ||
		response.Notification.ReceiptState != receipt || !sameMonitorBroadcastNotification(*response.Notification, n) {
		return errors.New("Monitor notification receipt is uncorrelated")
	}
	// This acknowledges an already persisted fact. It must match the original
	// notice exactly, but crossing its deadline during injection does not erase
	// that fact. Fresh notice reads still enforce expiry before any injection.
	return nil
}

func sameMonitorBroadcastNotification(a, b store.UserMonitorBroadcastV2Notification) bool {
	a.ReceiptState = ""
	b.ReceiptState = ""
	return a == b
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
	if _, err := inbox.BeginInjection(ctx, claim.AttemptID); err != nil {
		return err
	}
	prompt := fmt.Sprintf("Cicada management notice: a pending Monitor broadcast is available for Group %s. "+
		"This notice is not approval evidence. In this original joined Group context, call "+
		"cicada_monitor_broadcast with approval_id %s to validate current user authority and send the exact sealed content. "+
		"Do not substitute text or create a new broadcast. Transport acceptance does not prove recipient consumption.",
		current.GroupID, current.PreviewID)
	receipt := localGroupReceipt(claim)
	operation, err := machineNativeOperation(ctx, claim, current.BindingID)
	if err != nil {
		return err
	}
	queueErr := executeMachineNativeCodex(ctx, claim.SessionID, prompt, operation)
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
