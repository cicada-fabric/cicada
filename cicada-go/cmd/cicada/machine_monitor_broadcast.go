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
	"github.com/cicada-ai/cicada/internal/nodelock"
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
	bridge = machineMonitorNotificationBridge(ctx, bridge)
	var pendingErrors []error
	if *inbox == nil {
		existing, err := openExistingMachineMonitorBroadcastInbox(inboxPath)
		if err != nil {
			return fmt.Errorf("open Monitor management inbox: %w", err)
		}
		*inbox = existing
	}
	if *inbox != nil {
		// Recovery reads original rows independently of the current wake list.
		// A revoked Client or an expired approval can hide a genuine old queue
		// acceptance; neither permits a new injection nor erases that observation.
		batch, err := (*inbox).NextNativeRecoveryBatch(ctx, 16)
		if err != nil {
			pendingErrors = append(pendingErrors, err)
		} else {
			for _, delivery := range batch {
				if err := reconcileMachineMonitorNotification(ctx, bridge, *inbox, delivery); err != nil {
					pendingErrors = append(pendingErrors, err)
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(append(pendingErrors, err)...)
	}
	var response monitorBroadcastNotificationsResponse
	if err := bridge.monitorBroadcastHub(http.MethodGet, "", "", nil, &response); err != nil {
		return errors.Join(append(pendingErrors, err)...)
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
		if len(response.Notifications) != 0 {
			created, err := nodeinbox.Open(inboxPath)
			if err != nil {
				return fmt.Errorf("open Monitor management inbox: %w", err)
			}
			*inbox = created
		}
	}
	if *inbox == nil {
		return errors.Join(pendingErrors...)
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
			pendingErrors = append(pendingErrors, err)
			continue
		}
		switch delivery.State {
		case nodeinbox.INJECTING, nodeinbox.INJECTION_UNCERTAIN, nodeinbox.CONSUMPTION_UNCONFIRMED:
			// Do not make uncertainty terminal before checking the exact durable
			// native outcome, including a row outside this call's recovery page.
			err = reconcileMachineMonitorNotification(ctx, bridge, *inbox, *delivery)
		default:
			err = bridge.reportMonitorNotification(listed, delivery.State)
		}
		if err != nil {
			pendingErrors = append(pendingErrors, err)
		}
	}
	for drained := 0; drained < 16; drained++ {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(pendingErrors, err)...)
		}
		claim, err := (*inbox).Claim(ctx, "monitor-notice:"+bridge.nodeID)
		if errors.Is(err, nodeinbox.ErrNoDelivery) {
			return errors.Join(pendingErrors...)
		}
		if err != nil {
			return errors.Join(append(pendingErrors, err)...)
		}
		if err := drainMachineMonitorBroadcastNotification(ctx, bridge, *inbox, *claim); err != nil {
			return errors.Join(append(pendingErrors, err)...)
		}
	}
	// Process jobs and Relay work after at most one bounded Monitor batch.
	return errors.Join(pendingErrors...)
}

// The real bridge owns synchronization and a listener. A request bridge copies
// only immutable request fields, never its locks or its mutable shared context.
func machineMonitorNotificationBridge(ctx context.Context, bridge *machineAgentJoinBridge) *machineAgentJoinBridge {
	return &machineAgentJoinBridge{ctx: ctx, baseURL: bridge.baseURL, stateDir: bridge.stateDir,
		nodeID: bridge.nodeID, nodeToken: bridge.nodeToken}
}

func machineMonitorPersistedNotification(ctx context.Context, bridge *machineAgentJoinBridge,
	delivery nodeinbox.Delivery) (store.UserMonitorBroadcastV2Notification, nodelock.NativeOperation, error) {
	var original store.UserMonitorBroadcastV2Notification
	var operation nodelock.NativeOperation
	if err := decodeStrictBridgeJSON(delivery.Payload, &original); err != nil {
		return original, operation, errors.New("Monitor notice metadata is invalid")
	}
	_, digest, err := monitorNotificationBytes(original)
	if err != nil || digest != delivery.Digest || !monitorBroadcastHubMatchesFor(ctx, original.HubID) ||
		original.NodeID != bridge.nodeID || !validMonitorApprovalID(original.PreviewID) ||
		original.PreviewID != delivery.MessageID || original.MonitorEndpointID != delivery.EndpointID ||
		original.NativeSessionID != delivery.SessionID || original.BindingEpoch != delivery.BindingEpoch ||
		!validMonitorNotificationToken(original.BindingID) || delivery.AttemptID == "" {
		return original, operation, errors.New("Monitor notice does not match its original native attempt")
	}
	operation, err = machineNativeOperation(ctx, nodeinbox.Claim{Delivery: delivery}, original.BindingID)
	return original, operation, err
}

func reconcileMachineMonitorNotification(ctx context.Context, bridge *machineAgentJoinBridge,
	inbox *nodeinbox.Inbox, delivery nodeinbox.Delivery) error {
	original, operation, err := machineMonitorPersistedNotification(ctx, bridge, delivery)
	if err != nil {
		return err
	}
	// This helper acquires and releases the physical writer. Never invoke it
	// from a held-writer callback, or replace the exact witness with a Boolean.
	state, err := machineNativeQueueOutcome(ctx, delivery.SessionID, operation)
	if err != nil {
		return fmt.Errorf("read original Monitor native outcome: %w", err)
	}
	receipt := localGroupReceipt(nodeinbox.Claim{Delivery: delivery})
	if state == nodelock.NativeQueueAccepted {
		deliveryPtr, err := inbox.RecordCodexQueueAccepted(ctx, receipt)
		if err != nil {
			return err
		}
		delivery = *deliveryPtr
	} else {
		if delivery.State == nodeinbox.CONSUMPTION_UNCONFIRMED {
			return errors.New("Monitor accepted inbox row has no exact durable queue witness")
		}
		if delivery.State != nodeinbox.INJECTING && delivery.State != nodeinbox.INJECTION_UNCERTAIN {
			return errors.New("Monitor recovery row is not an interrupted native attempt")
		}
		receipt.State = nodeinbox.INJECTION_UNCERTAIN
		receipt.Error = "native notice injection outcome is uncertain; do not reinject"
		deliveryPtr, err := inbox.Acknowledge(ctx, receipt)
		if err != nil {
			return err
		}
		delivery = *deliveryPtr
	}
	// Historical receipt authority fences the original Node/binding/epoch. It
	// does not re-authorize consent or queue after expiry or Client revocation.
	return machineMonitorNotificationBridge(ctx, bridge).reportMonitorNotification(original, delivery.State)
}

func drainMachineMonitorBroadcastNotification(ctx context.Context, bridge *machineAgentJoinBridge,
	inbox *nodeinbox.Inbox, claim nodeinbox.Claim) (result error) {
	injectionBegan, disposed := false, false
	defer func() {
		if !injectionBegan && !disposed {
			result = errors.Join(result, abandonMachineNativeClaim(ctx, inbox, claim))
		}
	}()
	original, operation, err := machineMonitorPersistedNotification(ctx, bridge, claim.Delivery)
	if err != nil {
		err = inbox.RejectBeforeInjection(ctx, claim, "Monitor notice metadata is invalid")
		disposed = err == nil
		return err
	}
	reject := func() error {
		if err := inbox.RejectBeforeInjection(ctx, claim, "Monitor authorization no longer permits notification"); err != nil {
			return err
		}
		disposed = true
		return machineMonitorNotificationBridge(ctx, bridge).reportMonitorNotification(original, nodeinbox.FAILED)
	}
	queueErr := runMachineNativeDelivery(ctx, claim.SessionID, operation,
		func(queueCtx context.Context) (string, []nodeinbox.NativeContextScopeInput, error) {
			requestBridge := machineMonitorNotificationBridge(queueCtx, bridge)
			current, err := requestBridge.monitorBroadcastNotification(original.PreviewID)
			if err != nil {
				if !localSealedSendRetryable(err) && queueCtx.Err() == nil {
					return "", nil, &machineNativeDeliveryDeniedError{cause: err}
				}
				return "", nil, err
			}
			if validateMonitorBroadcastNotificationFor(queueCtx, *current, original.PreviewID, bridge.nodeID, false) != nil ||
				!sameMonitorBroadcastNotification(original, *current) {
				return "", nil, &machineNativeDeliveryDeniedError{cause: errors.New("Monitor notice authority changed after writer wait")}
			}
			var scopes []nodeinbox.NativeContextScopeInput
			decision := &nodeinbox.NativeContextScopeDecision{Accepted: true,
				NativeHistoryCoverage: nodeinbox.NativeContextHistoryCoverageNotChecked}
			if current.NativeContextScope != nil {
				scope, err := machineNativeContextScopeFromMetadata(queueCtx, "codex", current.NativeSessionID,
					current.MonitorEndpointID, current.BindingID, current.BindingEpoch, *current.NativeContextScope)
				if err != nil {
					return "", nil, &machineNativeDeliveryDeniedError{cause: err}
				}
				decision, err = checkMachineNativeContext(queueCtx, scope)
				if err != nil {
					if definitiveMachineNativeContextFailure(err) {
						return "", nil, &machineNativeDeliveryDeniedError{cause: err}
					}
					return "", nil, err
				}
				scopes = append(scopes, scope)
			} else if hub, ok := machineHubFrom(queueCtx); ok && hub.RequireNativeContext {
				return "", nil, &machineNativeDeliveryDeniedError{cause: errors.New("Monitor authorization has no authoritative native context scope")}
			}
			prompt := fmt.Sprintf("Cicada management notice: a pending Monitor broadcast is available for Group %s. "+
				"This notice is not approval evidence. In this original joined Group context, call "+
				"cicada_monitor_broadcast with approval_id %s to validate current user authority and send the exact sealed content. "+
				"Do not substitute text or create a new broadcast. Transport acceptance does not prove recipient consumption.",
				current.GroupID, current.PreviewID)
			if decision.SharedMemoryRisk {
				prompt = "CICADA_CONTEXT_SCOPE_SHARED_MEMORY_RISK: this native Codex Thread is known to have been used in more than one Cicada Group or Network scope. Treat earlier content as potentially visible and do not assume Cicada can erase or isolate Runtime history.\n" + prompt
			}
			return prompt, scopes, nil
		}, func(queueCtx context.Context) error {
			_, err := inbox.BeginInjection(queueCtx, claim.AttemptID)
			injectionBegan = err == nil
			return err
		})
	// The runner released the writer before any outcome-reader or receipt work.
	if queueErr != nil {
		var denied *machineNativeDeliveryDeniedError
		if !injectionBegan {
			if (errors.As(queueErr, &denied) || machineNativeDeliveryIdentityConflict(queueErr)) && ctx.Err() == nil {
				return reject()
			}
			return queueErr
		}
		var uncertain *nativeInjectionUncertainError
		if !errors.As(queueErr, &uncertain) && !errors.Is(queueErr, nodeinbox.ErrInjectionUncertain) {
			recorded, err := inbox.RecordFailed(ctx, localGroupReceipt(claim), "native notice queue did not start")
			if err != nil {
				return errors.Join(queueErr, err)
			}
			return machineMonitorNotificationBridge(ctx, bridge).reportMonitorNotification(original, recorded.State)
		}
	}
	delivery, err := inbox.Get(ctx, claim.MessageID)
	if err != nil {
		return errors.Join(queueErr, err)
	}
	return reconcileMachineMonitorNotification(ctx, bridge, inbox, *delivery)
}
