package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

func machineNativeOperation(ctx context.Context, claim nodeinbox.Claim, bindingID string) (nodelock.NativeOperation, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok || hub.HubID == "" || hub.NodeID == "" || bindingID == "" {
		return nodelock.NativeOperation{}, errors.New("native operation lacks a pinned Hub or binding")
	}
	return nodelock.NativeOperation{HubID: hub.HubID, NodeID: hub.NodeID,
		EndpointID: claim.EndpointID, BindingID: bindingID, BindingEpoch: claim.BindingEpoch,
		MessageID: claim.MessageID, Digest: claim.Digest, AttemptID: claim.AttemptID}, nil
}

func machineRelayNativeOperation(ctx context.Context, claim nodeinbox.Claim, entry machineRelayJournalEntry) (nodelock.NativeOperation, error) {
	if claim.MessageID != entry.MessageID || claim.Digest != entry.Digest || claim.EndpointID != entry.EndpointID ||
		claim.SessionID != entry.SessionID || claim.BindingEpoch != entry.BindingEpoch {
		return nodelock.NativeOperation{}, errors.New("relay claim and native operation differ")
	}
	op, err := machineNativeOperation(ctx, claim, entry.BindingID)
	if err != nil {
		return op, err
	}
	// The local inbox claim and the Hub Relay claim have different attempt IDs.
	// Only the Hub attempt is evidence for the current remote receipt.
	op.AttemptID = entry.AttemptID
	return op, nil
}

func requireMachineRelayQueueOutcome(ctx context.Context, claim nodeinbox.Claim, entry machineRelayJournalEntry) error {
	op, err := machineRelayNativeOperation(ctx, claim, entry)
	if err != nil {
		return err
	}
	return requireMachineNativeQueueOutcome(ctx, claim.SessionID, op)
}

func requireMachineNativeQueueOutcome(ctx context.Context, nativeSessionID string, op nodelock.NativeOperation) error {
	state, err := machineNativeQueueOutcome(ctx, nativeSessionID, op)
	if err != nil {
		return err
	}
	if state != nodelock.NativeQueueAccepted {
		return fmt.Errorf("native queue has no durable accepted outcome: %s", state)
	}
	return nil
}

func machineNativeQueueOutcome(ctx context.Context, nativeSessionID string, op nodelock.NativeOperation) (nodelock.NativeOutcomeState, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok || hub.HubID == "" || hub.HubID != op.HubID || hub.NodeID != op.NodeID {
		return "", errors.New("native queue outcome does not match pinned Hub")
	}
	lockCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	writer, err := nodelock.AcquireNativeWriter(lockCtx, hub.WriterRoot, hub.WriterScope, "codex", nativeSessionID)
	if err != nil {
		return "", err
	}
	defer writer.Close()
	state, err := writer.NativeOperationOutcome(op)
	if err != nil {
		return "", err
	}
	return state, nil
}
