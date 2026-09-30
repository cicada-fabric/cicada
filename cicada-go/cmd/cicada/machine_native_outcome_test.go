package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

// Direct-call fixtures bypass the Agent, so give them the same explicit
// writer scope an Agent would carry. Production paths never synthesize a Hub.
func pinnedNativeTestContext(ctx context.Context, nodeID, stateDir, origin string) context.Context {
	if _, ok := machineHubFrom(ctx); ok {
		return ctx
	}
	hubID := strings.TrimSpace(os.Getenv("CICADA_HUB_ID"))
	if hubID == "" {
		hubID = "hub_synthetic_direct_call_fixture"
	}
	return withMachineHubContext(ctx, machineHubContext{HubID: hubID, Origin: origin, NodeID: nodeID, Token: machineNodeToken(),
		StateDir: stateDir, WriterRoot: stateDir, WriterScope: machineNativeWriterScope()})
}

func processPinnedTestMachineFabricDeliveries(ctx context.Context, base, nodeID string, inbox *nodeinbox.Inbox, stateDir string) error {
	return processMachineFabricDeliveriesV2(pinnedNativeTestContext(ctx, nodeID, stateDir, base), base, nodeID, inbox, stateDir)
}

func drainPinnedTestMachineRelayInbox(ctx context.Context, base, nodeID, stateDir string, inbox *nodeinbox.Inbox, journal *machineRelayJournal) error {
	return drainMachineRelayInbox(pinnedNativeTestContext(ctx, nodeID, stateDir, base), base, nodeID, stateDir, inbox, journal)
}

func processPinnedTestMachineLocalGroupDeliveries(ctx context.Context, bridge *machineAgentJoinBridge, inbox *nodeinbox.Inbox) error {
	return processMachineLocalGroupDeliveries(pinnedNativeTestContext(ctx, bridge.nodeID, bridge.stateDir, bridge.baseURL), bridge, inbox)
}

func processPinnedTestMachineMonitorBroadcastNotifications(ctx context.Context, bridge *machineAgentJoinBridge, inbox **nodeinbox.Inbox, path string) error {
	return processMachineMonitorBroadcastNotifications(pinnedNativeTestContext(ctx, bridge.nodeID, bridge.stateDir, bridge.baseURL), bridge, inbox, path)
}

func TestMachineNativeQueueOutcomeSurvivesAttemptAndBlocksUncertainRetry(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "queue-count")
	queue := filepath.Join(root, "fake-codex")
	if err := os.WriteFile(queue, []byte("#!/bin/sh\nprintf x >> '"+marker+"'\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_CODEX_BIN", queue)
	ctx := withMachineHubContext(context.Background(), machineHubContext{HubID: "hub-a", NodeID: "node-a", WriterRoot: root, WriterScope: "uid:1000"})
	op := nodelock.NativeOperation{HubID: "hub-a", NodeID: "node-a", EndpointID: "ep-a", BindingID: "bind-a",
		BindingEpoch: 1, MessageID: "msg-a", Digest: "digest-a", AttemptID: "attempt-one"}
	if err := executeMachineNativeCodex(ctx, "native-a", "synthetic prompt", op); err != nil {
		t.Fatal(err)
	}
	if err := requireMachineNativeQueueOutcome(ctx, "native-a", op); err != nil {
		t.Fatal(err)
	}
	op.AttemptID = "attempt-two"
	if err := executeMachineNativeCodex(ctx, "native-a", "synthetic prompt", op); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "x" {
		t.Fatalf("queue must run exactly once: %q %v", data, err)
	}
	missing := op
	missing.MessageID = "msg-other"
	if err := requireMachineNativeQueueOutcome(ctx, "native-a", missing); err == nil {
		t.Fatal("unrecorded queue accepted")
	}
	otherHub := withMachineHubContext(context.Background(), machineHubContext{HubID: "hub-b", NodeID: "node-a", WriterRoot: root, WriterScope: "uid:1000"})
	if err := requireMachineNativeQueueOutcome(otherHub, "native-a", op); err == nil {
		t.Fatal("cross-Hub result transplant")
	}

	if err := os.WriteFile(queue, []byte("#!/bin/sh\nprintf x >> '"+marker+"'\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	uncertain := op
	uncertain.MessageID = "msg-uncertain"
	uncertain.AttemptID = "attempt-one"
	var injectionErr *nativeInjectionUncertainError
	if err := executeMachineNativeCodex(ctx, "native-a", "synthetic prompt", uncertain); !errors.As(err, &injectionErr) {
		t.Fatalf("nonzero queue exit: %v", err)
	}
	uncertain.AttemptID = "attempt-two"
	if err := executeMachineNativeCodex(ctx, "native-a", "synthetic prompt", uncertain); !errors.As(err, &injectionErr) {
		t.Fatalf("uncertain replay: %v", err)
	}
	data, err = os.ReadFile(marker)
	if err != nil || string(data) != "xx" {
		t.Fatalf("uncertain queue retried: %q %v", data, err)
	}
}

func TestMachineNativeQueueRequiresPinnedHub(t *testing.T) {
	op := nodelock.NativeOperation{HubID: "hub-a", NodeID: "node-a", EndpointID: "ep-a", BindingID: "bind-a",
		BindingEpoch: 1, MessageID: "msg-a", Digest: "digest-a", AttemptID: "attempt-one"}
	if err := executeMachineNativeCodex(context.Background(), "native-a", "synthetic prompt", op); err == nil {
		t.Fatal("unscoped queue accepted")
	}
	ctx := withMachineHubContext(context.Background(), machineHubContext{NodeID: "node-a", WriterRoot: t.TempDir(), WriterScope: "uid:1000"})
	if err := executeMachineNativeCodex(ctx, "native-a", "synthetic prompt", op); err == nil {
		t.Fatal("single-Hub without Hub ID accepted")
	}
}

func TestMachineRelayQueueReceiptRequiresDurableWriterOutcome(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	root := t.TempDir()
	ctx := withMachineHubContext(context.Background(), machineHubContext{HubID: "hub-a", NodeID: "node-a",
		Origin: server.URL, WriterRoot: root, WriterScope: "uid:1000"})
	claim := nodeinbox.Claim{Delivery: nodeinbox.Delivery{MessageID: "msg-a", Digest: "digest-a", EndpointID: "ep-a",
		SessionID: "native-a", BindingEpoch: 3, AttemptID: "local-attempt"}}
	entry := machineRelayJournalEntry{MessageID: "msg-a", Digest: "digest-a", EndpointID: "ep-a", BindingID: "bind-a",
		BindingEpoch: 3, SessionID: "native-a", AttemptID: "hub-attempt", Harness: "codex", QueueAccepted: true}
	if err := completeMachineRelayCodexQueue(ctx, server.URL, "node-a", nil, nil, claim, entry); err == nil {
		t.Fatal("journal flag without durable writer result was accepted")
	}
	if requests != 0 {
		t.Fatalf("receipt sent without durable writer outcome: %d", requests)
	}
}
