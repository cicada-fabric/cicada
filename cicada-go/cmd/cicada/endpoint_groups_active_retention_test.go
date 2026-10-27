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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func TestEndpointGroupsSupersededActiveRetention(t *testing.T) {
	for _, branch := range []string{"replacement", "terminal"} {
		t.Run(branch, func(t *testing.T) {
			f, r := endpointGroupsOriginalFixture(t)
			f.bridge.endpointGroupsMu.Lock()
			locked := true
			defer func() {
				if locked {
					f.bridge.endpointGroupsMu.Unlock()
				}
			}()
			apply := func(body wire.OwnerEndpointGroupsPrepareBody, head *e2ee.EndpointGroupOwnerControl) wire.OwnerEndpointGroupsResult {
				t.Helper()
				body.NodeID, body.NetworkID = f.nodeID, r.Anchor.NetworkID
				call := func(op string, q any) ([]byte, wire.OwnerEndpointGroupsResult) {
					packet, err := wire.SealClientRequest(f.device, f.hub, q)
					if err != nil {
						t.Fatal(err)
					}
					raw := f.http(t, http.MethodPost, wire.OwnerEndpointGroupsHTTPPath(op), "", "", packet, http.StatusOK)
					var result wire.OwnerEndpointGroupsResult
					if wire.OpenOwnerEndpointGroupsResponse(f.device, f.hub, packet, raw, &result) != nil || wire.VerifyOwnerEndpointGroupsResult(q, packet, result, f.hub) != nil {
						t.Fatal("real Owner response verification failed")
					}
					return packet, result
				}
				q, err := wire.NewOwnerEndpointGroupsPrepare(f.session, f.scope.Actor, body, f.owner, time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				packet, prepared := call(wire.OperationOwnerEndpointGroupsPrepare, q)
				if prepared.Review == nil || wire.ValidateOwnerEndpointGroupsReview(q, packet, *prepared.Review, f.hub, time.Now().UTC()) != nil {
					t.Fatal("real Owner review unavailable")
				}
				q2, err := wire.NewOwnerEndpointGroupsApply(f.session, f.scope.Actor, q, packet, *prepared.Review, f.owner, time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				applied, result := call(wire.OperationOwnerEndpointGroupsApply, q2)
				if result.State != "COMPLETED" || result.Operation == nil || wire.VerifyOwnerEndpointGroupsOperation(*prepared.Review, applied, *result.Operation, head) != nil {
					t.Fatal("real Owner operation failed")
				}
				return result
			}
			group := apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, Name: "Synthetic original active retention"}, nil).Operation.Target.GroupID
			manual := func() (wire.OwnerEndpointGroupsRelationCard, wire.OwnerEndpointGroupsContributionCard) {
				t.Helper()
				var d wire.EndpointGroupsNodeDescribeResult
				var err error
				r, d, err = f.bridge.describeEndpointGroups(f.ctx, f.client, r, "", 64)
				if err != nil {
					t.Fatal("real Node Describe", err)
				}
				for _, card := range d.Relations {
					if card.GroupID == group {
						for _, source := range card.Contributions {
							if source.Source == "OWNER_EXPLICIT" {
								return card, source
							}
						}
					}
				}
				t.Fatal("actual manual source unavailable")
				return wire.OwnerEndpointGroupsRelationCard{}, wire.OwnerEndpointGroupsContributionCard{}
			}
			var transportMu sync.Mutex
			rpcCount := 0
			dropNext := false
			var lostOriginal []byte
			f.mu.Lock()
			actual := f.handler
			f.handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path != "/v2/node/control/rpc" {
					actual.ServeHTTP(w, req)
					return
				}
				raw, err := io.ReadAll(req.Body)
				if err != nil {
					w.WriteHeader(400)
					return
				}
				req.Body = io.NopCloser(bytes.NewReader(raw))
				packet, _ := wire.DecodeEndpointGroupsNodePacket(raw)
				transportMu.Lock()
				rpcCount++
				drop := dropNext && packet.Route.Operation == wire.OperationEndpointGroupsNodeKeyComplete
				if drop {
					dropNext = false
					lostOriginal = bytes.Clone(raw)
				}
				transportMu.Unlock()
				if drop {
					recorder := httptest.NewRecorder()
					actual.ServeHTTP(recorder, req)
					if recorder.Code != 200 {
						t.Error("actual replacement Complete did not commit")
					}
					w.WriteHeader(503)
					return
				}
				actual.ServeHTTP(w, req)
			})
			f.mu.Unlock()
			defer func() { f.mu.Lock(); f.handler = actual; f.mu.Unlock() }()
			count := func() int { transportMu.Lock(); defer transportMu.Unlock(); return rpcCount }
			apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: group, EndpointID: r.Anchor.Registration.EndpointID, Duration: "until_revoked"}, nil)
			card, source := manual()
			if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); err != nil {
				t.Fatal(err)
			}
			card, source = manual()
			if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); err != nil {
				t.Fatal("actual ACTIVE read", err)
			}
			originalAnchor := r.Anchor
			originalKey, keyErr := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), r.Anchor.Registration.EndpointID)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			capture := func() machineNodeControlState {
				f.client.mu.Lock()
				defer f.client.mu.Unlock()
				return cloneMachineNodeControlState(f.client.state)
			}
			findRead := func(policy string) (string, machineLocalEndpointStep) {
				t.Helper()
				state := capture()
				for id, step := range state.LocalEndpointIntents[r.IntentID].Steps {
					var q wire.EndpointGroupsNodeKeyPrepare
					if step.Operation != wire.OperationEndpointGroupsNodeKeyPrepare || decodeStrictBridgeJSON(step.Body, &q) != nil || q.PolicyID != policy || len(step.ResponsePacket) == 0 {
						continue
					}
					f.client.mu.Lock()
					env, err := f.client.openEndpointGroupsEnvelopeLocked(step.RequestPacket, step.ResponsePacket)
					f.client.mu.Unlock()
					var result wire.EndpointGroupsNodeKeyResult
					if err == nil && env.OK && decodeStrictBridgeJSON(env.Result, &result) == nil && result.Grant != nil {
						return id, step
					}
				}
				t.Fatal("real retained ACTIVE read missing")
				return "", machineLocalEndpointStep{}
			}
			oldHead := card.OwnerControl
			oldID, oldRead := findRead(oldHead.PolicyID)
			oldWrites := map[string]machineLocalEndpointStep{}
			for id, step := range capture().LocalEndpointIntents[r.IntentID].Steps {
				if step.Operation == wire.OperationEndpointGroupsNodeKeyComplete {
					oldWrites[id] = step
				}
			}
			// Equal current head is permanently ineligible, even with an exact Complete.
			cachedBefore := count()
			if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(capture().LocalEndpointIntents[r.IntentID].Steps[oldID].ResponsePacket, oldRead.ResponsePacket) || count() != cachedBefore {
				t.Fatal("current ACTIVE cache was retired or dispatched")
			}
			apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: group, EndpointID: r.Anchor.Registration.EndpointID}, &oldHead)
			if branch == "replacement" {
				apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: group, EndpointID: r.Anchor.Registration.EndpointID, Duration: "until_revoked"}, nil)
				// An App-side pending policy does not install or advance the Node head.
				if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(capture().LocalEndpointIntents[r.IntentID].Steps[oldID].ResponsePacket, oldRead.ResponsePacket) {
					t.Fatal("pending policy alone retired ACTIVE read")
				}
				card, source = manual()
				transportMu.Lock()
				dropNext = true
				transportMu.Unlock()
				if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); !machineAPIHasStatus(err, 503) {
					t.Fatal("real replacement Complete response loss unavailable", err)
				}
				pending := capture()
				pendingRaw, _ := json.Marshal(pending)
				calls := count()
				if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
					t.Fatal(err)
				}
				issuer := context.WithValue(f.ctx, endpointGroupsIssueReadKey{}, &endpointGroupsIssueReadScope{Request: wire.EndpointGroupsNodeDescribe{EndpointID: r.Anchor.Registration.EndpointID, NetworkID: r.Anchor.NetworkID, Limit: 64}})
				if err := f.client.recoverNodeControlPending(issuer, f.token); err == nil {
					t.Fatal("issuer dispatched unknown replacement write")
				}
				after, _ := json.Marshal(capture())
				if !bytes.Equal(pendingRaw, after) || count() != calls {
					t.Fatal("unknown write changed or dispatched during retention")
				}
				transportMu.Lock()
				original := bytes.Clone(lostOriginal)
				transportMu.Unlock()
				if !bytes.Equal(original, pending.PendingPacket) {
					t.Fatal("wrong original replacement write retained")
				}
				if err := f.client.recoverNodeControlPending(f.ctx, f.token); err != nil {
					t.Fatal(err)
				}
				if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); err != nil {
					t.Fatal("actual replacement grant restoration", err)
				}
				// Invalid old/new write evidence cannot retire the target ACTIVE read.
				for _, variant := range []string{"bad_old_receipt", "bad_new_receipt", "new_wrong_group", "missing_old_complete"} {
					f.client.mu.Lock()
					intent := f.client.state.LocalEndpointIntents[r.IntentID]
					var target string
					var saved machineLocalEndpointStep
					for id, step := range intent.Steps {
						var q wire.EndpointGroupsNodeKeyComplete
						if step.Operation != wire.OperationEndpointGroupsNodeKeyComplete || decodeStrictBridgeJSON(step.Body, &q) != nil {
							continue
						}
						isOld := q.PolicyID == oldHead.PolicyID
						if (variant == "bad_old_receipt" || variant == "missing_old_complete") == isOld {
							target = id
							saved = step
							break
						}
					}
					if target == "" {
						f.client.mu.Unlock()
						t.Fatal("negative write target missing")
					}
					changed := saved
					changed.ResponsePacket = bytes.Clone(saved.ResponsePacket)
					switch variant {
					case "bad_old_receipt", "bad_new_receipt":
						changed.ResponsePacket[len(changed.ResponsePacket)/2] ^= 1
					case "new_wrong_group":
						var q wire.EndpointGroupsNodeKeyComplete
						_ = decodeStrictBridgeJSON(changed.Body, &q)
						q.GroupID = "synthetic-different-group"
						changed.Body, _ = json.Marshal(q)
					case "missing_old_complete":
						delete(intent.Steps, target)
					}
					if variant != "missing_old_complete" {
						intent.Steps[target] = changed
					}
					f.client.state.LocalEndpointIntents[r.IntentID] = intent
					f.client.mu.Unlock()
					calls := count()
					if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
						t.Fatal(variant, err)
					}
					state := capture()
					if !bytes.Equal(state.LocalEndpointIntents[r.IntentID].Steps[oldID].ResponsePacket, oldRead.ResponsePacket) || count() != calls {
						t.Fatal("invalid evidence retired target read", variant)
					}
					f.client.mu.Lock()
					intent = f.client.state.LocalEndpointIntents[r.IntentID]
					intent.Steps[target] = saved
					f.client.state.LocalEndpointIntents[r.IntentID] = intent
					err := f.client.persistLocked()
					f.client.mu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				}
			} else {
				card, _ = manual()
				if card.OwnerControl.DenyReason != "REMOVED" || card.OwnerControl.PolicyEpoch != oldHead.PolicyEpoch || card.OwnerControl.PolicyID != oldHead.PolicyID || card.OwnerControl.Revision <= oldHead.Revision {
					t.Fatal("real same-epoch terminal head missing")
				}
				for _, authority := range r.Authorities {
					if authority.Relation.GroupID == group {
						t.Fatal("terminal Group incorrectly retained a current authority")
					}
				}
			}
			// Every pending coordinate fences this real old ACTIVE candidate.
			before := capture()
			fields := []func(*machineNodeControlState){func(x *machineNodeControlState) { x.PendingOperation = "node.endpoint_groups.renew" }, func(x *machineNodeControlState) { x.PendingOperationID = oldID }, func(x *machineNodeControlState) { x.PendingSequence = before.Sequence + 1 }, func(x *machineNodeControlState) { x.PendingPlaintextDigest = strings.Repeat("a", 64) }, func(x *machineNodeControlState) { x.PendingPacket = bytes.Clone(oldRead.RequestPacket) }, func(x *machineNodeControlState) { x.PendingResponsePacket = bytes.Clone(oldRead.ResponsePacket) }, func(x *machineNodeControlState) { x.PendingLocalEndpointIntentID = r.IntentID }, func(x *machineNodeControlState) { x.PendingNativePairBody = []byte("synthetic pending native") }, func(x *machineNodeControlState) { x.PendingWorkerID = "synthetic-worker" }, func(x *machineNodeControlState) { x.PendingWorkerAttempt = 1 }, func(x *machineNodeControlState) { x.PendingSnapshotPath = "synthetic-snapshot" }, func(x *machineNodeControlState) { x.PendingSnapshotManifest = &nodewire.SnapshotManifest{} }, func(x *machineNodeControlState) {
				x.ClaimTicket = &machineNodeControlClaimTicket{Version: 1, Phase: "EXECUTING"}
			}}
			for i, set := range fields {
				f.client.mu.Lock()
				f.client.state = cloneMachineNodeControlState(before)
				set(&f.client.state)
				raw, _ := json.Marshal(f.client.state)
				f.client.mu.Unlock()
				calls := count()
				if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
					t.Fatal(i, err)
				}
				after, _ := json.Marshal(capture())
				if !bytes.Equal(raw, after) || count() != calls {
					t.Fatal("pending fence lost", i)
				}
				f.client.mu.Lock()
				f.client.state = cloneMachineNodeControlState(before)
				f.client.mu.Unlock()
			}
			before = capture()
			expected := cloneMachineNodeControlState(before)
			intent := expected.LocalEndpointIntents[r.IntentID]
			step := intent.Steps[oldID]
			step.ResponsePacket = nil
			intent.Steps[oldID] = step
			expected.LocalEndpointIntents[r.IntentID] = intent
			beforeJSON, _ := json.Marshal(before)
			afterJSON, _ := json.Marshal(expected)
			ready := make(chan struct{})
			begin := make(chan struct{})
			done := make(chan struct{})
			observations := make(chan error, 1)
			var active atomic.Bool
			var during int
			go func() {
				var problem error
				observe := func() {
					inFlight := active.Load()
					f.client.mu.Lock()
					raw, _ := json.Marshal(f.client.state)
					f.client.mu.Unlock()
					if inFlight {
						during++
					}
					if !bytes.Equal(raw, beforeJSON) && !bytes.Equal(raw, afterJSON) {
						problem = errors.New("partial protected ACTIVE retirement")
					}
				}
				observe()
				close(ready)
				<-begin
				for i := 0; i < 64; i++ {
					observe()
					time.Sleep(2 * time.Millisecond)
				}
				<-done
				observe()
				observations <- problem
			}()
			<-ready
			calls := count()
			active.Store(true)
			close(begin)
			retireErr := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub)
			active.Store(false)
			close(done)
			if err := <-observations; err != nil || retireErr != nil || during == 0 {
				t.Fatal("concurrent retention failed", err, retireErr)
			}
			after, _ := json.Marshal(capture())
			disk, err := os.ReadFile(f.client.statePath)
			if err != nil || !bytes.Equal(after, afterJSON) || !bytes.Equal(bytes.TrimSpace(disk), afterJSON) || count() != calls {
				t.Fatal("retirement changed more than target response or dispatched")
			}
			var oldQ wire.EndpointGroupsNodeKeyPrepare
			_ = decodeStrictBridgeJSON(oldRead.Body, &oldQ)
			scope := localEndpointCallScope{IntentID: r.IntentID, Digest: r.IntentDigest, StepID: oldID}
			var result wire.EndpointGroupsNodeKeyResult
			if err := f.client.call(context.WithValue(f.ctx, localEndpointCallKey{}, scope), f.token, wire.OperationEndpointGroupsNodeKeyPrepare, oldQ, &result); !errors.Is(err, errLocalEndpointReceiptExpired) {
				t.Fatal("old ACTIVE exact read did not expire", err)
			}
			oldQ.ExpectedRelationRevision++
			if err := f.client.call(context.WithValue(f.ctx, localEndpointCallKey{}, scope), f.token, wire.OperationEndpointGroupsNodeKeyPrepare, oldQ, &result); !errors.Is(err, errLocalEndpointIntentConflict) {
				t.Fatal("old ACTIVE ID accepted changed body", err)
			}
			for id, old := range oldWrites {
				current := capture().LocalEndpointIntents[r.IntentID].Steps[id]
				if !reflect.DeepEqual(current, old) {
					t.Fatal("original successful write changed")
				}
			}
			if count() != calls {
				t.Fatal("expired/conflicting old ACTIVE issued traffic")
			}
			// Keep the valid replacement ACTIVE cache and recover it from disk.
			if branch == "replacement" {
				card, source = manual()
				if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); err != nil {
					t.Fatal(err)
				}
				currentID, currentRead := findRead(card.OwnerControl.PolicyID)
				calls = count()
				if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(capture().LocalEndpointIntents[r.IntentID].Steps[currentID].ResponsePacket, currentRead.ResponsePacket) || count() != calls {
					t.Fatal("current ACTIVE response lost")
				}
				if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); err != nil || count() != calls {
					t.Fatal("current ACTIVE no longer replays exactly", err)
				}
			}
			headStore, err := nodekeys.OpenExistingCryptoState(f.ctx, machineNodeStateDir(f.nodeRoot, f.nodeID))
			if err != nil {
				t.Fatal(err)
			}
			known, err := headStore.ReadEndpointGroupStoredOwnerHead(f.ctx, f.hub, r.Anchor, group)
			_ = headStore.Close()
			if err != nil {
				t.Fatal(err)
			}
			f.bridge.endpointGroupsMu.Unlock()
			locked = false
			if err := f.bridge.Close(); err != nil {
				t.Fatal(err)
			}
			machineNodeControlClients.Delete(f.client.statePath)
			f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
			if err != nil {
				t.Fatal(err)
			}
			restored, _, err := f.client.endpointGroupsRegistrationCandidate(r.Anchor.Registration.NativeSessionID, r.Anchor.Registration.Workspace)
			key, keyErr := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), r.Anchor.Registration.EndpointID)
			if err != nil || keyErr != nil || !sameEndpointGroupsAnchor(restored.Anchor, originalAnchor) || !machineSamePublicIdentity(key.Public(), originalKey.Public()) || len(capture().LocalEndpointIntents[r.IntentID].Steps[oldID].ResponsePacket) != 0 {
				t.Fatal("cold recovery changed original identity/tombstone", err, keyErr)
			}
			headStore, err = nodekeys.OpenExistingCryptoState(f.ctx, machineNodeStateDir(f.nodeRoot, f.nodeID))
			if err != nil {
				t.Fatal(err)
			}
			reopenedHead, err := headStore.ReadEndpointGroupStoredOwnerHead(f.ctx, f.hub, restored.Anchor, group)
			_ = headStore.Close()
			if err != nil || reopenedHead != known {
				t.Fatal("durable Owner head/deny changed on reopen", err)
			}
			if branch == "replacement" {
				calls := count()
				if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, restored, card, source); err != nil || count() != calls {
					t.Fatal("cold current ACTIVE cache did not restore through original verifier", err)
				}
			}
			for id, old := range oldWrites {
				if !reflect.DeepEqual(capture().LocalEndpointIntents[r.IntentID].Steps[id], old) {
					t.Fatal("cold recovery changed original write")
				}
			}
			t.Logf("CLOSED_ACTIVE_RETENTION branch=%s retired_response_bytes=%d current_equal_head_preserved=true pending_fences=13 concurrent_snapshots=66 old_read=EXPIRED changed_body=CONFLICT redispatch=0 original_writes_keys_anchor_head=RETAINED cold_reopen=true", branch, len(oldRead.ResponsePacket))
		})
	}
}
