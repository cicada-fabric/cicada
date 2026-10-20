package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func syntheticLocalEndpointRequest(operation string) localEndpointRequest {
	now := time.Now().UTC()
	id, err := newLocalEndpointRequestID(now)
	if err != nil {
		panic(err)
	}
	return localEndpointRequest{Version: 1, Operation: operation, RequestID: id, IssuedAt: now.Format(time.RFC3339Nano), APIOrigin: "http://127.0.0.1:9", Harness: "codex", NativeSessionID: "synthetic-thread", Workspace: "/synthetic/work", Name: "Synthetic endpoint"}
}

func TestLocalEndpointLeaveExactRecoveryDoesNotRefreshDigest(t *testing.T) {
	var hub *e2ee.Identity
	var binding nodewire.Binding
	var mu sync.Mutex
	var leavePackets [][]byte
	selfReads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := ioReadAllBounded(r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		opened, err := nodewire.OpenRequest(hub, binding.NodeKey, binding, raw)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		var result any
		switch opened.Route.Operation {
		case nodewire.EndpointDirectoryOperation:
			selfReads++
			result = nodewire.EndpointDirectoryResult{NodeID: binding.NodeID, Freshness: "SNAPSHOT_ONLY", Endpoints: []nodewire.EndpointDirectoryCard{{EndpointID: "synthetic-endpoint", Harness: "codex", NativeSessionID: "synthetic-thread", Workspace: "/synthetic/work", StateDigest: strings.Repeat("b", 64)}}}
		case nodewire.EndpointLeaveOperation:
			var q nodewire.EndpointLeave
			if json.Unmarshal(opened.Plaintext, &q) != nil || q.StateDigest != strings.Repeat("b", 64) {
				t.Error("Leave changed the original CAS state")
			}
			leavePackets = append(leavePackets, bytes.Clone(raw))
			if len(leavePackets) == 1 {
				w.WriteHeader(503)
				return
			}
			result = nodewire.EndpointRegistrationResult{EndpointID: "synthetic-endpoint", Presence: "left", StateDigest: strings.Repeat("c", 64)}
		default:
			t.Error("unexpected endpoint operation")
			w.WriteHeader(400)
			return
		}
		sealed, err := nodewire.SealResponse(hub, binding.NodeKey, binding, nodeControlTestResponseRoute(opened.Route), nodeControlTestEnvelope(t, opened.Route, true, result, ""))
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(sealed)
	}))
	defer server.Close()
	client, ctx, hub, binding := newMachineNodeControlRecoveryFixture(t, server.URL)
	q := syntheticLocalEndpointRequest("endpoint_leave")
	q.APIOrigin = server.URL
	q.Name = ""
	digest, err := client.retainLocalEndpointIntent(q, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	b := &machineAgentJoinBridge{ctx: ctx, nodeToken: "synthetic-node-token"}
	if err := b.localEndpointLeave(client, q, digest, &localEndpointResult{}); err == nil {
		t.Fatal("lost response reported completion")
	}
	before := cloneMachineNodeControlState(client.state)
	data, err := os.ReadFile(client.statePath)
	if err != nil {
		t.Fatal(err)
	}
	var disk machineNodeControlState
	if json.Unmarshal(data, &disk) != nil || !bytes.Equal(disk.PendingPacket, before.PendingPacket) || disk.PendingLocalEndpointIntentID != q.RequestID {
		t.Fatal("original intent/outbox not durable")
	}
	machineNodeControlClients.Delete(client.statePath)
	restarted, err := openMachineNodeControlClientMode(client.stateDir, server.URL, client.nodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.recoverPending(ctx, "synthetic-node-token"); err != nil {
		t.Fatal(err)
	}
	if len(restarted.state.PendingPacket) != 0 {
		t.Fatal("completed original remained pending")
	}
	data, err = os.ReadFile(client.statePath)
	if err != nil {
		t.Fatal(err)
	}
	disk = machineNodeControlState{}
	if json.Unmarshal(data, &disk) != nil {
		t.Fatal("invalid persisted completion")
	}
	stepID := localEndpointStepID(q.RequestID, digest, "leave")
	if len(disk.PendingPacket) != 0 || !disk.LocalEndpointIntents[q.RequestID].Steps[stepID].Settled || len(disk.LocalEndpointIntents[q.RequestID].Steps[stepID].ResponsePacket) == 0 {
		t.Fatal("outbox clear did not atomically retain original receipt")
	}
	r := &localEndpointResult{}
	if err := b.localEndpointLeave(restarted, q, digest, r); err != nil || r.Registration == nil || r.Registration.Presence != "left" {
		t.Fatalf("retained original result unavailable: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if selfReads != 1 || len(leavePackets) != 2 || !bytes.Equal(leavePackets[0], leavePackets[1]) {
		t.Fatal("recovery refreshed self state or regenerated Leave packet")
	}
	changed := q
	changed.Workspace = "/synthetic/other"
	if _, err := restarted.retainLocalEndpointIntent(changed, time.Now().UTC()); !errors.Is(err, errLocalEndpointIntentConflict) {
		t.Fatal("same ID changed intent")
	}
}

func TestLocalEndpointBoundedHistoryAndExpiredReadCannotRedispatch(t *testing.T) {
	client, _, _, _ := newMachineNodeControlRecoveryFixture(t, "http://127.0.0.1:9")
	now := time.Now().UTC()
	old := syntheticLocalEndpointRequest("endpoint_directory")
	old.Harness = ""
	old.NativeSessionID = ""
	old.Workspace = ""
	old.Name = ""
	oldTime := now.Add(-3 * time.Minute)
	old.IssuedAt = oldTime.Format(time.RFC3339Nano)
	old.RequestID, _ = newLocalEndpointRequestID(oldTime)
	client.state.LocalEndpointIntents = map[string]machineLocalEndpointIntent{old.RequestID: {Digest: "synthetic-old", Operation: old.Operation, IssuedAt: old.IssuedAt, Steps: map[string]machineLocalEndpointStep{"settled": {Settled: true}}}}
	q := old
	q.RequestID, _ = newLocalEndpointRequestID(now)
	q.IssuedAt = now.Format(time.RFC3339Nano)
	if _, err := client.retainLocalEndpointIntent(q, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := client.state.LocalEndpointIntents[old.RequestID]; ok {
		t.Fatal("expired settled read became a lifetime quota")
	}
	if _, err := client.retainLocalEndpointIntent(old, now); err == nil {
		t.Fatal("evicted old read was redispatched as fresh")
	}
	for i := 0; i < maxLocalEndpointMutationIntents; i++ {
		client.state.LocalEndpointIntents[fmt.Sprintf("synthetic-%d", i)] = machineLocalEndpointIntent{Digest: "retained-in-window", Mutation: true, IssuedAt: now.Format(time.RFC3339Nano)}
	}
	mutation := syntheticLocalEndpointRequest("endpoint_register")
	if _, err := client.retainLocalEndpointIntent(mutation, now); !errors.Is(err, errLocalEndpointHistoryFull) {
		t.Fatal("full mutation history did not apply backpressure")
	}
	if client.state.Sequence != 0 || len(client.state.PendingPacket) != 0 {
		t.Fatal("history capacity failure dispatched new effect")
	}
	if _, ok := client.state.LocalEndpointIntents["synthetic-0"]; !ok {
		t.Fatal("history capacity evicted an original tombstone")
	}
}

func TestLocalEndpointAuthenticatedPairFenceIsRetained(t *testing.T) {
	var hub *e2ee.Identity
	var binding nodewire.Binding
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		raw, err := ioReadAllBounded(r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		opened, err := nodewire.OpenRequest(hub, binding.NodeKey, binding, raw)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		sealed, err := nodewire.SealResponse(hub, binding.NodeKey, binding, nodeControlTestResponseRoute(opened.Route), nodeControlTestEnvelope(t, opened.Route, false, nil, wire.NativePairNodeJoinFenceCode))
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(sealed)
	}))
	defer server.Close()
	client, ctx, hub, binding := newMachineNodeControlRecoveryFixture(t, server.URL)
	q := syntheticLocalEndpointRequest("native_pair_join_named")
	q.Name = ""
	q.PairLabel = "Synthetic pair"
	q.Slot = "A"
	q.APIOrigin = server.URL
	digest, err := client.retainLocalEndpointIntent(q, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	body := wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision, PairID: strings.Repeat("a", 32), Slot: "A", ExpectedGeneration: 1, BootstrapProofDigest: strings.Repeat("b", 64), Runtime: "codex", NativeSessionID: q.NativeSessionID, Workspace: q.Workspace}
	for i := 0; i < 2; i++ {
		if err := client.callLocalEndpoint(ctx, "synthetic-node-token", q.RequestID, digest, "join", wire.OperationNativePairNodeJoin, body, nil); !errors.Is(err, errNativePairNodeRejected) {
			t.Fatalf("authenticated fence became unknown on attempt %d: %v", i, err)
		}
	}
	if posts != 1 || len(client.state.PendingPacket) != 0 {
		t.Fatal("exact retained refusal redispatched Join")
	}
}

func TestLocalEndpointExpiredUnstartedLeaveAndMonotonicFloor(t *testing.T) {
	client, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, "http://127.0.0.1:9")
	now := time.Now().UTC()
	oldTime := now.Add(-3 * time.Minute)
	q := syntheticLocalEndpointRequest("endpoint_leave")
	q.Name = ""
	q.IssuedAt = oldTime.Format(time.RFC3339Nano)
	q.RequestID, _ = newLocalEndpointRequestID(oldTime)
	digest, err := client.retainLocalEndpointIntent(q, oldTime)
	if err != nil {
		t.Fatal(err)
	}
	b := &machineAgentJoinBridge{ctx: ctx, nodeToken: "synthetic-node-token"}
	if err := b.localEndpointLeave(client, q, digest, &localEndpointResult{}); !errors.Is(err, errLocalEndpointReceiptExpired) {
		t.Fatalf("expired unstarted Leave attempted self lookup: %v", err)
	}
	if client.state.Sequence != 0 || len(client.state.PendingPacket) != 0 || len(client.state.LocalEndpointIntents[q.RequestID].Steps) != 0 {
		t.Fatal("expired Leave prepared a new self/CAS step")
	}
	changed := q
	changed.IssuedAt = now.Format(time.RFC3339Nano)
	if _, err := client.retainLocalEndpointIntent(changed, now); err == nil {
		t.Fatal("old time ID accepted a changed issue time")
	}
	// Keep an unrelated unknown even as completed/unstarted old entries expire.
	unknownID, _ := newLocalEndpointRequestID(oldTime)
	client.state.LocalEndpointIntents[unknownID] = machineLocalEndpointIntent{Digest: "synthetic-unknown", Mutation: true, IssuedAt: q.IssuedAt, Steps: map[string]machineLocalEndpointStep{"unknown": {RequestPacket: []byte("synthetic-pending-packet"), Settled: false}}}
	fresh := syntheticLocalEndpointRequest("endpoint_register")
	if _, err := client.retainLocalEndpointIntent(fresh, now); err != nil {
		t.Fatal(err)
	}
	if client.state.LocalEndpointAdmissionFloorMS != oldTime.UnixMilli() {
		t.Fatal("GC did not advance durable time floor")
	}
	if _, ok := client.state.LocalEndpointIntents[q.RequestID]; ok {
		t.Fatal("unstarted expired intent remained a lifetime quota")
	}
	if _, ok := client.state.LocalEndpointIntents[unknownID]; !ok {
		t.Fatal("unknown operation was evicted")
	}
	data, err := os.ReadFile(client.statePath)
	if err != nil {
		t.Fatal(err)
	}
	var disk machineNodeControlState
	if json.Unmarshal(data, &disk) != nil || disk.LocalEndpointAdmissionFloorMS != oldTime.UnixMilli() {
		t.Fatal("GC and floor were not persisted together")
	}
	rolledBack := q
	rolledBack.RequestID, _ = newLocalEndpointRequestID(oldTime)
	if _, err := client.retainLocalEndpointIntent(rolledBack, oldTime.Add(time.Second)); err == nil {
		t.Fatal("clock rollback resurrected an old time coordinate")
	}
	if client.state.LocalEndpointAdmissionFloorMS != oldTime.UnixMilli() || client.state.Sequence != 0 {
		t.Fatal("rejected rollback changed floor or counter")
	}
}

func TestLocalEndpointCompletedMutationHistoryIsNotLifetimeQuota(t *testing.T) {
	client, _, _, _ := newMachineNodeControlRecoveryFixture(t, "http://127.0.0.1:9")
	now := time.Now().UTC()
	old := now.Add(-3 * time.Minute)
	client.state.LocalEndpointIntents = make(map[string]machineLocalEndpointIntent)
	for i := 0; i < maxLocalEndpointMutationIntents; i++ {
		id, err := newLocalEndpointRequestID(old)
		if err != nil {
			t.Fatal(err)
		}
		client.state.LocalEndpointIntents[id] = machineLocalEndpointIntent{Digest: "synthetic-completed", Mutation: true, IssuedAt: old.Format(time.RFC3339Nano), Steps: map[string]machineLocalEndpointStep{"selection": {Operation: "local.selection"}, "completed": {Settled: true}}}
	}
	q := syntheticLocalEndpointRequest("endpoint_register")
	if _, err := client.retainLocalEndpointIntent(q, now); err != nil {
		t.Fatal("completed history imposed a lifetime quota", err)
	}
	if len(client.state.LocalEndpointIntents) != 1 || client.state.LocalEndpointAdmissionFloorMS != old.UnixMilli() {
		t.Fatal("completed/local-only history did not safely compact")
	}
}

func TestLocalEndpointOperatorRealTCPRegisterLeaveAndNamedPair(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	transcript := filepath.Join(os.Getenv("CODEX_HOME"), "sessions", "2026", "09", "23", "rollout-2026-09-23T00-00-00-"+f.native[0]+".jsonl")
	meta, _ := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": f.native[0], "cwd": f.workspace, "source": "exec", "originator": "codex_exec"}})
	if err := os.WriteFile(transcript, append(meta, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	issue := syntheticCodexContextIssue()
	issue.APIOrigin = f.server.URL
	issue.NativeSessionID = f.native[0]
	issue.Workspace = f.workspace
	issue.TranscriptPath = transcript
	ticket, err := requestMachineAgentCodexContextIssue(f.bridge.path, issue)
	if err != nil {
		t.Fatalf("actual private IPC context issue: %v", err)
	}
	context, err := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(issue, ticket.Ticket))
	if err != nil || context.Context.NativeSessionID != f.native[0] || context.Context.Workspace != f.workspace {
		t.Fatalf("actual private IPC context consume: %v", err)
	}
	if _, err := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(issue, ticket.Ticket)); err == nil {
		t.Fatal("IPC replay consumed context twice")
	}
	q := syntheticLocalEndpointRequest("endpoint_register")
	q.APIOrigin = f.server.URL
	q.NativeSessionID = f.native[0]
	q.Workspace = f.workspace
	registered, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || registered == nil || registered.Registration == nil || registered.Registration.Presence != "offline" {
		t.Fatalf("private IPC registration: %v", err)
	}
	repeated, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || repeated.Registration.EndpointID != registered.Registration.EndpointID {
		t.Fatal("exact local registration did not retain its original result")
	}
	q.Operation = "endpoint_directory"
	q.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	requestTime, _ := time.Parse(time.RFC3339Nano, q.IssuedAt)
	q.RequestID, _ = newLocalEndpointRequestID(requestTime)
	q.Harness = ""
	q.NativeSessionID = ""
	q.Workspace = ""
	q.Name = ""
	directory, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || directory.Directory == nil || len(directory.Directory.Endpoints) != 1 || directory.Directory.Endpoints[0].EndpointID != registered.Registration.EndpointID {
		t.Fatalf("Node own directory: %v", err)
	}
	q.Operation = "endpoint_leave"
	q.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	requestTime, _ = time.Parse(time.RFC3339Nano, q.IssuedAt)
	q.RequestID, _ = newLocalEndpointRequestID(requestTime)
	q.Harness = "codex"
	q.NativeSessionID = f.native[1]
	q.Workspace = f.workspace
	if result, err := requestMachineAgentEndpoint(f.bridge.path, q); !errors.Is(err, nodewire.ErrEndpointUnavailable) && (err == nil || result == nil || result.State != "REFUSED") {
		t.Fatalf("absent self Leave must not register: %v", err)
	}
	q.Operation = "native_pair_join_named"
	q.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	requestTime, _ = time.Parse(time.RFC3339Nano, q.IssuedAt)
	q.RequestID, _ = newLocalEndpointRequestID(requestTime)
	q.NativeSessionID = f.native[0]
	q.PairLabel = "Synthetic consumer pair"
	q.Slot = "A"
	f.mu.Lock()
	f.dropJoin = 1
	f.mu.Unlock()
	lost, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err == nil || lost == nil || lost.State != "UNKNOWN" {
		t.Fatal("actual Hub Join ACK loss discarded original intent")
	}
	joined, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || joined.Join == nil || joined.Join.Endpoint.ID != registered.Registration.EndpointID {
		t.Fatalf("named Pair reused private Endpoint and original Owner proof: %v", err)
	}
	f.mu.Lock()
	packets := f.nodePackets[wire.OperationNativePairNodeJoin]
	f.mu.Unlock()
	if len(packets) != 2 || !bytes.Equal(packets[0], packets[1]) {
		t.Fatal("named Join ACK recovery changed original packet/generation")
	}
	// This test never admits keys, consents, sends a model message or runs a Runtime.
	status := f.status(t)
	if status.State != wire.NativePairWaitingJoin {
		t.Fatal("one named Join silently admitted the Pair")
	}
}
