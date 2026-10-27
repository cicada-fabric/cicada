package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Actual Owner HTTP, Node crypto/receipts and protected persistence. This case
// isolates retention synchronization from the four-Thread Unix performance
// workload; it neither changes nor claims to repair that earlier race failure.
func TestEndpointGroupsChallengeRetentionProtectedSnapshots(t *testing.T) {
	f, r := endpointGroupsOriginalFixture(t)
	f.bridge.endpointGroupsMu.Lock()
	defer f.bridge.endpointGroupsMu.Unlock()
	ownerHTTP := func(operation string, body any) ([]byte, wire.OwnerEndpointGroupsResult) {
		t.Helper()
		packet, err := wire.SealClientRequest(f.device, f.hub, body)
		if err != nil {
			t.Fatal(err)
		}
		raw := f.http(t, http.MethodPost, wire.OwnerEndpointGroupsHTTPPath(operation), "", "", packet, http.StatusOK)
		var result wire.OwnerEndpointGroupsResult
		if wire.OpenOwnerEndpointGroupsResponse(f.device, f.hub, packet, raw, &result) != nil || wire.VerifyOwnerEndpointGroupsResult(body, packet, result, f.hub) != nil {
			t.Fatal("real Owner envelope verification failed")
		}
		return packet, result
	}
	apply := func(body wire.OwnerEndpointGroupsPrepareBody) wire.OwnerEndpointGroupsResult {
		t.Helper()
		body.NodeID, body.NetworkID = f.nodeID, r.Anchor.NetworkID
		q, err := wire.NewOwnerEndpointGroupsPrepare(f.session, f.scope.Actor, body, f.owner, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		packet, prepared := ownerHTTP(wire.OperationOwnerEndpointGroupsPrepare, q)
		if prepared.Review == nil || wire.ValidateOwnerEndpointGroupsReview(q, packet, *prepared.Review, f.hub, time.Now().UTC()) != nil {
			t.Fatal("real approved review unavailable")
		}
		q2, err := wire.NewOwnerEndpointGroupsApply(f.session, f.scope.Actor, q, packet, *prepared.Review, f.owner, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		appliedPacket, result := ownerHTTP(wire.OperationOwnerEndpointGroupsApply, q2)
		if result.State != "COMPLETED" || result.Operation == nil || wire.VerifyOwnerEndpointGroupsOperation(*prepared.Review, appliedPacket, *result.Operation, nil) != nil {
			t.Fatal("real Owner operation failed")
		}
		return result
	}
	created := apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, Name: "Synthetic single registration retention race"})
	group := created.Operation.Target.GroupID
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: group, EndpointID: r.Anchor.Registration.EndpointID, Duration: "until_revoked"})
	var description wire.EndpointGroupsNodeDescribeResult
	var err error
	r, description, err = f.bridge.describeEndpointGroups(f.ctx, f.client, r, "", 64)
	if err != nil {
		t.Fatal("actual Node Describe", err)
	}
	var card wire.OwnerEndpointGroupsRelationCard
	var source wire.OwnerEndpointGroupsContributionCard
	for _, candidate := range description.Relations {
		if candidate.GroupID != group {
			continue
		}
		card = candidate
		for _, contribution := range candidate.Contributions {
			if contribution.Source == "OWNER_EXPLICIT" {
				source = contribution
			}
		}
	}
	if source.State != "PENDING_KEY" {
		t.Fatal("real pending manual contribution unavailable")
	}
	originalAnchor := r.Anchor
	originalKey, err := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), r.Anchor.Registration.EndpointID)
	if err != nil {
		t.Fatal(err)
	}

	var transportMu sync.Mutex
	var packets [][]byte
	var committedResponse []byte
	drop := true
	f.mu.Lock()
	actual := f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/node/control/rpc" {
			actual.ServeHTTP(w, request)
			return
		}
		raw, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(raw))
		packet, decodeErr := wire.DecodeEndpointGroupsNodePacket(raw)
		transportMu.Lock()
		packets = append(packets, bytes.Clone(raw))
		lose := decodeErr == nil && packet.Route.Operation == wire.OperationEndpointGroupsNodeKeyComplete && drop
		if lose {
			drop = false
		}
		transportMu.Unlock()
		if lose {
			recorder := httptest.NewRecorder()
			actual.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Error("real Complete did not commit before response loss")
			}
			transportMu.Lock()
			committedResponse = bytes.Clone(recorder.Body.Bytes())
			transportMu.Unlock()
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		actual.ServeHTTP(w, request)
	})
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.handler = actual; f.mu.Unlock() }()
	count := func() int { transportMu.Lock(); defer transportMu.Unlock(); return len(packets) }
	capture := func() ([]byte, []byte) {
		t.Helper()
		f.client.mu.Lock()
		raw, marshalErr := json.Marshal(f.client.state)
		f.client.mu.Unlock()
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		disk, readErr := os.ReadFile(f.client.statePath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		return raw, disk
	}
	if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); !machineAPIHasStatus(err, http.StatusServiceUnavailable) {
		t.Fatal("real committed Complete response loss not observed", err)
	}
	f.client.mu.Lock()
	pending := cloneMachineNodeControlState(f.client.state)
	f.client.mu.Unlock()
	if pending.PendingOperation != wire.OperationEndpointGroupsNodeKeyComplete || len(pending.PendingPacket) == 0 || len(pending.PendingResponsePacket) != 0 {
		t.Fatal("actual unknown original write unavailable")
	}
	pendingRaw, pendingDisk := capture()
	beforeCalls := count()
	if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
		t.Fatal(err)
	}
	issuer := context.WithValue(f.ctx, endpointGroupsIssueReadKey{}, &endpointGroupsIssueReadScope{Request: wire.EndpointGroupsNodeDescribe{EndpointID: r.Anchor.Registration.EndpointID, NetworkID: r.Anchor.NetworkID, Limit: 64}})
	if err := f.client.recoverNodeControlPending(issuer, f.token); err == nil {
		t.Fatal("issuer recovered an unknown write")
	}
	afterPending, afterPendingDisk := capture()
	if count() != beforeCalls || !bytes.Equal(pendingRaw, afterPending) || !bytes.Equal(pendingDisk, afterPendingDisk) {
		t.Fatal("retention or issuer changed/dispatched a real unknown write")
	}
	if err := f.client.recoverNodeControlPending(f.ctx, f.token); err != nil {
		t.Fatal("explicit original write recovery", err)
	}
	transportMu.Lock()
	var completions [][]byte
	for _, raw := range packets {
		packet, _ := wire.DecodeEndpointGroupsNodePacket(raw)
		if packet.Route.Operation == wire.OperationEndpointGroupsNodeKeyComplete {
			completions = append(completions, bytes.Clone(raw))
		}
	}
	successfulResponse := bytes.Clone(committedResponse)
	transportMu.Unlock()
	if len(completions) != 2 || !bytes.Equal(completions[0], pending.PendingPacket) || !bytes.Equal(completions[0], completions[1]) {
		t.Fatal("explicit recovery replaced the original write")
	}
	// Settling the sealed write alone does not install a grant. Re-enter the
	// actual verifier with its original card/source and exact cached receipts.
	cachedCalls := count()
	if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); err != nil {
		t.Fatal("original grant verification after recovery", err)
	}
	if count() != cachedCalls {
		t.Fatal("grant restoration issued a new action")
	}

	f.client.mu.Lock()
	before := cloneMachineNodeControlState(f.client.state)
	intent := before.LocalEndpointIntents[r.IntentID]
	var readID, writeID string
	var readRequest wire.EndpointGroupsNodeKeyPrepare
	var writeRequest wire.EndpointGroupsNodeKeyComplete
	for id, step := range intent.Steps {
		if step.Operation == wire.OperationEndpointGroupsNodeKeyPrepare {
			readID = id
			if decodeStrictBridgeJSON(step.Body, &readRequest) != nil {
				t.Fatal("original read unavailable")
			}
		}
		if step.Operation == wire.OperationEndpointGroupsNodeKeyComplete {
			writeID = id
			if decodeStrictBridgeJSON(step.Body, &writeRequest) != nil {
				t.Fatal("original write unavailable")
			}
		}
	}
	write := intent.Steps[writeID]
	envelope, openErr := f.client.openEndpointGroupsEnvelopeLocked(write.RequestPacket, write.ResponsePacket)
	var granted wire.EndpointGroupsNodeKeyResult
	grantErr := decodeStrictBridgeJSON(envelope.Result, &granted)
	f.client.mu.Unlock()
	if readID == "" || writeID == "" || openErr != nil || !envelope.OK || grantErr != nil || granted.Grant == nil || !bytes.Equal(write.ResponsePacket, successfulResponse) {
		t.Fatal("authenticated exact successful Complete receipt unavailable")
	}
	pendingFields := []struct {
		name string
		set  func(*machineNodeControlState)
	}{
		{"operation", func(x *machineNodeControlState) { x.PendingOperation = wire.OperationEndpointGroupsNodeRenew }},
		{"operation_id", func(x *machineNodeControlState) { x.PendingOperationID = writeID }},
		{"sequence", func(x *machineNodeControlState) { x.PendingSequence = before.Sequence + 1 }},
		{"plaintext_digest", func(x *machineNodeControlState) { x.PendingPlaintextDigest = strings.Repeat("a", 64) }},
		{"packet", func(x *machineNodeControlState) { x.PendingPacket = bytes.Clone(write.RequestPacket) }},
		{"response", func(x *machineNodeControlState) { x.PendingResponsePacket = bytes.Clone(write.ResponsePacket) }},
		{"local_intent", func(x *machineNodeControlState) { x.PendingLocalEndpointIntentID = r.IntentID }},
		{"native_pair_body", func(x *machineNodeControlState) {
			x.PendingNativePairBody = []byte("synthetic retained native operation")
		}},
		{"worker_id", func(x *machineNodeControlState) { x.PendingWorkerID = "synthetic-retained-worker" }},
		{"worker_attempt", func(x *machineNodeControlState) { x.PendingWorkerAttempt = 1 }},
		{"snapshot_path", func(x *machineNodeControlState) { x.PendingSnapshotPath = "synthetic-retained-snapshot" }},
		{"snapshot_manifest", func(x *machineNodeControlState) { x.PendingSnapshotManifest = &nodewire.SnapshotManifest{} }},
		{"claim", func(x *machineNodeControlState) {
			x.ClaimTicket = &machineNodeControlClaimTicket{Version: 1, Phase: "EXECUTING"}
		}},
	}
	for _, field := range pendingFields {
		f.client.mu.Lock()
		f.client.state = cloneMachineNodeControlState(before)
		field.set(&f.client.state)
		fenced, _ := json.Marshal(f.client.state)
		f.client.mu.Unlock()
		if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
			t.Fatal(field.name, err)
		}
		f.client.mu.Lock()
		observed, _ := json.Marshal(f.client.state)
		f.client.state = cloneMachineNodeControlState(before)
		f.client.mu.Unlock()
		if !bytes.Equal(fenced, observed) {
			t.Fatal("pending coordinate lost its fence", field.name)
		}
	}
	if count() != cachedCalls {
		t.Fatal("pending fences dispatched Node traffic")
	}

	expected := cloneMachineNodeControlState(before)
	expectedIntent := expected.LocalEndpointIntents[r.IntentID]
	retired := expectedIntent.Steps[readID]
	retired.ResponsePacket = nil
	expectedIntent.Steps[readID] = retired
	expected.LocalEndpointIntents[r.IntentID] = expectedIntent
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(expected)
	type snapshotResult struct {
		Before, After, WhileActive int
		MaxLockWaitNS              int64
		Err                        error
	}
	snapshots := make(chan snapshotResult, 1)
	ready := make(chan struct{})
	begin := make(chan struct{})
	done := make(chan struct{})
	var active atomic.Bool
	go func() {
		var result snapshotResult
		observe := func() {
			started := time.Now()
			inFlight := active.Load()
			f.client.mu.Lock()
			wait := time.Since(started).Nanoseconds()
			raw, err := json.Marshal(f.client.state)
			f.client.mu.Unlock()
			if wait > result.MaxLockWaitNS {
				result.MaxLockWaitNS = wait
			}
			if inFlight {
				result.WhileActive++
			}
			if err != nil {
				result.Err = err
				return
			}
			if bytes.Equal(raw, beforeJSON) {
				result.Before++
			} else if bytes.Equal(raw, afterJSON) {
				result.After++
			} else {
				result.Err = errors.New("protected snapshot observed a partial retirement")
			}
		}
		observe()
		close(ready)
		<-begin
		for sample := 0; sample < 64; sample++ {
			observe()
			time.Sleep(2 * time.Millisecond)
		}
		<-done
		observe()
		snapshots <- result
	}()
	<-ready
	active.Store(true)
	close(begin)
	retireErr := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub)
	active.Store(false)
	close(done)
	observed := <-snapshots
	if retireErr != nil || observed.Err != nil || observed.Before == 0 || observed.After == 0 || observed.WhileActive == 0 {
		t.Fatal("retirement/snapshot synchronization failed", retireErr, observed.Err)
	}
	afterGC, diskAfterGC := capture()
	if !bytes.Equal(afterGC, afterJSON) || !bytes.Equal(bytes.TrimSpace(diskAfterGC), afterJSON) {
		t.Fatal("retirement changed more than one confirmed Challenge response or was not durable")
	}
	if count() != cachedCalls {
		t.Fatal("retention dispatched Node traffic")
	}
	readScope := localEndpointCallScope{IntentID: r.IntentID, Digest: r.IntentDigest, StepID: readID}
	var replay wire.EndpointGroupsNodeKeyResult
	if err := f.client.call(context.WithValue(f.ctx, localEndpointCallKey{}, readScope), f.token, wire.OperationEndpointGroupsNodeKeyPrepare, readRequest, &replay); !errors.Is(err, errLocalEndpointReceiptExpired) {
		t.Fatal("retired original read redispatched", err)
	}
	readRequest.ExpectedRelationRevision++
	if err := f.client.call(context.WithValue(f.ctx, localEndpointCallKey{}, readScope), f.token, wire.OperationEndpointGroupsNodeKeyPrepare, readRequest, &replay); !errors.Is(err, errLocalEndpointIntentConflict) {
		t.Fatal("same read ID accepted changed body", err)
	}
	writeScope := localEndpointCallScope{IntentID: r.IntentID, Digest: r.IntentDigest, StepID: writeID}
	if err := f.client.call(context.WithValue(f.ctx, localEndpointCallKey{}, writeScope), f.token, wire.OperationEndpointGroupsNodeKeyComplete, writeRequest, &replay); err != nil || replay.OwnerControl != granted.OwnerControl || replay.Grant == nil {
		t.Fatal("original successful write/head was not retained", err)
	}
	if count() != cachedCalls {
		t.Fatal("old exact/changed read or exact write replay issued new traffic")
	}
	current, desc, err := f.bridge.describeEndpointGroups(f.ctx, f.client, r, "", 64)
	key, keyErr := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), r.Anchor.Registration.EndpointID)
	if err != nil || keyErr != nil || !sameEndpointGroupsAnchor(current.Anchor, originalAnchor) || !machineSamePublicIdentity(key.Public(), originalKey.Public()) {
		t.Fatal("retirement changed original identity/key/binding", err, keyErr)
	}
	found := false
	for _, relation := range desc.Relations {
		if relation.GroupID == group && relation.OwnerControl == granted.OwnerControl && relation.State == "ACTIVE" {
			found = true
		}
	}
	if !found {
		t.Fatal("fresh real authority lost its original active Owner head")
	}
	crypto, err := nodekeys.OpenExistingCryptoState(f.ctx, machineNodeStateDir(f.nodeRoot, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Close()
	required, err := crypto.EndpointGroupsRequired(f.ctx, current.Anchor.Registration.EndpointID, group)
	if err != nil || !required {
		t.Fatal("retirement removed the original managed marker", err)
	}
	t.Logf("CLOSED_RETENTION_SYNCHRONIZATION pending_fields=13 real_committed_loss=RETAINED issuer_write_dispatch=0 generic_exact_write_requests=2 response_bytes_equal=true snapshots_before=%d snapshots_after=%d snapshots_started_during_retire=%d max_mutex_wait_ns=%d old_read=EXPIRED changed_body=CONFLICT cached_replay_dispatch=0 identity_head_marker=RETAINED", observed.Before, observed.After, observed.WhileActive, observed.MaxLockWaitNS)
}
