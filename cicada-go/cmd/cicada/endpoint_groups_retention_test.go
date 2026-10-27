package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// A finite M1-M6 identity/authorization and retention sequence, not a Runtime reproduction.
// Every retained byte comes from real enrollment, Owner review or Node RPC;
// no fabricated history, capacity padding, state limit or TTL changes are used.
func TestEndpointGroupsCompletedChallengeRetirementPreservesFourOriginalThreads(t *testing.T) {
	f := newNativePeerTCPConsumerFixture(t, false)
	domain := activateLocalDomainConsumer(t, f)
	natives := [4]string{f.native[0], f.native[1], "synthetic-tcp-consumer-original-c", "synthetic-tcp-consumer-original-d"}
	issueFor := func(i int, tool string) localCodexContextIssue {
		t.Helper()
		sid := natives[i]
		path := filepath.Join(os.Getenv("CODEX_HOME"), "sessions", "2026", "09", "23", "rollout-2026-09-23T00-00-00-"+sid+".jsonl")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		metadata, err := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": sid, "session_id": sid, "cwd": f.workspace, "source": "vscode", "originator": "codex-tui"}})
		if err != nil || os.WriteFile(path, append(metadata, '\n'), 0o600) != nil {
			t.Fatal("synthetic original native record unavailable", err)
		}
		q := syntheticCodexContextIssue()
		q.APIOrigin, q.NativeSessionID, q.Workspace, q.TranscriptPath = f.server.URL, sid, f.workspace, path
		q.ToolName = tool
		if tool == "codex.operator.endpoint_register" {
			q.TurnID, q.ToolUseID = "", ""
		}
		return q
	}
	checkpoint := func(label string) {
		t.Helper()
		// The durable atomic file can be observed while an original HTTP call
		// holds client.mu; taking that mutex at the transport barrier would wait.
		raw, err := os.ReadFile(f.client.statePath)
		if err != nil {
			t.Fatal(err)
		}
		var state machineNodeControlState
		if json.Unmarshal(raw, &state) != nil {
			t.Fatal("protected state checkpoint unavailable")
		}
		serialized, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		type operationBytes struct {
			Steps, Settled, BodyBytes, OriginalBytes, ResponseBytes, DiagnosticBytes int
		}
		operations := map[string]operationBytes{}
		for _, intent := range state.LocalEndpointIntents {
			for _, step := range intent.Steps {
				x := operations[step.Operation]
				x.Steps++
				if step.Settled {
					x.Settled++
				}
				x.BodyBytes += len(step.Body)
				x.OriginalBytes += len(step.RequestPacket)
				x.ResponseBytes += len(step.ResponsePacket)
				x.DiagnosticBytes += len(step.DiagnosticPacket) + len(step.DiagnosticResponse)
				operations[step.Operation] = x
			}
		}
		reserve := managedPairStateReserve(state)
		pendingHash := sha256.Sum256([]byte(state.PendingOperationID))
		row := map[string]any{"phase": label, "disk_bytes": len(raw), "serialized_bytes": len(serialized), "managed_reserve_bytes": reserve, "rpc_reserve_bytes": 2 << 20, "limit_bytes": maxMachineNodeControlStateBytes, "pre_pending_rpc_headroom_bytes": maxMachineNodeControlStateBytes - len(serialized) - (2 << 20) - reserve, "intents": len(state.LocalEndpointIntents), "registrations": len(state.EndpointGroupsRegistrations), "native_receipts": len(state.NativePairReceipts), "pending_operation": state.PendingOperation, "pending_sequence": state.PendingSequence, "pending_operation_sha256": fmt.Sprintf("%x", pendingHash), "pending_original_bytes": len(state.PendingPacket), "pending_response_bytes": len(state.PendingResponsePacket), "operations": operations}
		closed, _ := json.Marshal(row)
		t.Logf("CLOSED_FOUR_THREAD_CHECKPOINT %s", closed)
	}
	for i := range natives {
		q := issueFor(i, "codex.operator.endpoint_register")
		ticket, err := requestMachineAgentCodexContextIssue(f.bridge.path, q)
		if err != nil {
			t.Fatal("original registration issue", err)
		}
		consumed, err := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(q, ticket.Ticket))
		if err != nil {
			t.Fatal("original registration consume", err)
		}
		now := time.Now().UTC()
		id, err := newLocalEndpointRequestID(now)
		if err != nil {
			t.Fatal(err)
		}
		request := localEndpointRequest{Version: localJoinProtocolVersion, Operation: "endpoint_register", RequestID: id, IssuedAt: now.Format(time.RFC3339Nano), APIOrigin: f.server.URL, Harness: "codex", NativeSessionID: natives[i], Workspace: f.workspace, Name: "Synthetic original Thread", LocalDomainVersion: consumed.Context.LocalDomainVersion, LocalDomain: consumed.Context.LocalDomain}
		if _, err := requestMachineAgentEndpoint(f.bridge.path, request); err != nil {
			t.Fatal("original registration/key readiness", err)
		}
	}
	locked := false
	lock := func() { f.bridge.endpointGroupsMu.Lock(); locked = true }
	unlock := func() { f.bridge.endpointGroupsMu.Unlock(); locked = false }
	defer func() {
		if locked {
			f.bridge.endpointGroupsMu.Unlock()
		}
	}()
	lock()
	var originals [4]machineEndpointGroupsRegistration
	var originalKeys [4]e2ee.PublicIdentity
	for i := range originals {
		r, _, err := f.client.endpointGroupsRegistrationCandidate(natives[i], f.workspace)
		if err != nil {
			t.Fatal(err)
		}
		r, _, err = f.bridge.describeEndpointGroups(f.ctx, f.client, r, "", 64)
		if err != nil {
			t.Fatal(err)
		}
		originals[i] = r
		key, err := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), r.Anchor.Registration.EndpointID)
		if err != nil {
			t.Fatal(err)
		}
		originalKeys[i] = key.Public()
	}
	checkpoint("four_originals_ready")
	ownerHTTP := func(operation string, body any) ([]byte, wire.OwnerEndpointGroupsResult) {
		t.Helper()
		packet, err := wire.SealClientRequest(f.device, f.hub, body)
		if err != nil {
			t.Fatal(err)
		}
		raw := f.http(t, http.MethodPost, wire.OwnerEndpointGroupsHTTPPath(operation), "", "", packet, http.StatusOK)
		var result wire.OwnerEndpointGroupsResult
		if wire.OpenOwnerEndpointGroupsResponse(f.device, f.hub, packet, raw, &result) != nil || wire.VerifyOwnerEndpointGroupsResult(body, packet, result, f.hub) != nil {
			t.Fatal("original Owner response verification failed")
		}
		return packet, result
	}
	apply := func(body wire.OwnerEndpointGroupsPrepareBody, head *e2ee.EndpointGroupOwnerControl) wire.OwnerEndpointGroupsResult {
		t.Helper()
		body.NodeID, body.NetworkID = f.nodeID, domain.Policy.NetworkID
		q, err := wire.NewOwnerEndpointGroupsPrepare(f.session, f.scope.Actor, body, f.owner, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		original, prepared := ownerHTTP(wire.OperationOwnerEndpointGroupsPrepare, q)
		if prepared.Review == nil || wire.ValidateOwnerEndpointGroupsReview(q, original, *prepared.Review, f.hub, time.Now().UTC()) != nil {
			t.Fatal("real reviewed operation unavailable", prepared.ErrorCode)
		}
		q2, err := wire.NewOwnerEndpointGroupsApply(f.session, f.scope.Actor, q, original, *prepared.Review, f.owner, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		packet, result := ownerHTTP(wire.OperationOwnerEndpointGroupsApply, q2)
		if result.State != "COMPLETED" || result.Operation == nil || wire.VerifyOwnerEndpointGroupsOperation(*prepared.Review, packet, *result.Operation, head) != nil {
			t.Fatal("real approved operation failed", result.ErrorCode)
		}
		return result
	}
	manual := func(i int, group string) (machineEndpointGroupsRegistration, wire.OwnerEndpointGroupsRelationCard, wire.OwnerEndpointGroupsContributionCard) {
		t.Helper()
		r, _, err := f.client.endpointGroupsRegistrationCandidate(natives[i], f.workspace)
		if err != nil {
			t.Fatal(err)
		}
		r, d, err := f.bridge.describeEndpointGroups(f.ctx, f.client, r, "", 64)
		if err != nil {
			t.Fatal(err)
		}
		for _, card := range d.Relations {
			if card.GroupID == group {
				for _, source := range card.Contributions {
					if source.Source == "OWNER_EXPLICIT" {
						return r, card, source
					}
				}
			}
		}
		t.Fatal("manual contribution absent")
		return r, wire.OwnerEndpointGroupsRelationCard{}, wire.OwnerEndpointGroupsContributionCard{}
	}
	retirementChecked := false
	activate := func(i int, group string) e2ee.EndpointGroupOwnerControl {
		t.Helper()
		apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: group, EndpointID: originals[i].Anchor.Registration.EndpointID, Duration: "until_revoked"}, nil)
		r, card, source := manual(i, group)
		if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); err != nil {
			t.Fatal("actual manual key completion", err)
		}
		if !retirementChecked {
			assertEndpointGroupsCompletedChallengeRetirement(t, f, r)
			retirementChecked = true
		}
		measureOrigin := func() (int, int) {
			f.client.mu.Lock()
			defer f.client.mu.Unlock()
			intent := f.client.state.LocalEndpointIntents[r.IntentID]
			raw := 0
			for _, step := range intent.Steps {
				raw += len(step.ResponsePacket)
			}
			encoded, _ := json.Marshal(intent)
			return raw, len(encoded)
		}
		beforeRaw, beforeJSON := measureOrigin()
		_, active, _ := manual(i, group)
		afterRaw, afterJSON := measureOrigin()
		t.Logf("CLOSED_CALLER_ORIGIN_RETIREMENT actor_index=%d raw_reclaimed_bytes=%d serialized_reclaimed_bytes=%d", i, beforeRaw-afterRaw, beforeJSON-afterJSON)
		return active.OwnerControl
	}
	created := apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, Name: "Synthetic finite four Thread Group"}, nil)
	g1, g2 := domain.Policy.GroupID, created.Operation.Target.GroupID
	dHead := activate(3, g2)
	checkpoint("m1_d_g2_first_complete")
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: g2, EndpointID: originals[3].Anchor.Registration.EndpointID}, &dHead)
	manual(3, g2) // Persist the real terminal deny before a separate Owner re-add.
	activate(3, g2)
	checkpoint("m1_d_g2_readd_complete")
	for i := 0; i < 3; i++ {
		activate(i, g2)
		checkpoint(fmt.Sprintf("m2_actor_%d_g2_complete", i))
	}
	defaultHead := e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: g1, EndpointID: originals[3].Anchor.Registration.EndpointID}, &defaultHead)
	manual(3, g2)
	checkpoint("m3_d_g1_removed")
	nodePublic := f.client.publicIdentity()
	unlock()
	if err := f.bridge.Close(); err != nil {
		t.Fatal(err)
	}
	machineNodeControlClients.Delete(f.client.statePath)
	var err error
	f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
	if err != nil {
		t.Fatal("reopen original protected state", err)
	}
	f.bridge, err = startMachineAgentJoinBridge(f.ctx, f.nodeRoot, f.server.URL, f.nodeID, f.token)
	if err != nil {
		t.Fatal(err)
	}
	lock()
	if !machineSamePublicIdentity(nodePublic, f.client.publicIdentity()) {
		t.Fatal("restart changed the original Node key")
	}
	for i, original := range originals {
		r, enrolled, err := f.client.endpointGroupsRegistrationCandidate(natives[i], f.workspace)
		key, keyErr := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), original.Anchor.Registration.EndpointID)
		if err != nil || !enrolled || !sameEndpointGroupsAnchor(r.Anchor, original.Anchor) || keyErr != nil || !machineSamePublicIdentity(key.Public(), originalKeys[i]) {
			t.Fatal("restart changed an original native, key, binding or epoch")
		}
	}
	checkpoint("m4_reopened_same_four_originals")
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: g1, EndpointID: originals[3].Anchor.Registration.EndpointID, Duration: "until_revoked"}, nil)
	r, card, source := manual(3, g1)
	entered, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	f.mu.Lock()
	actualHandler := f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/node/control/rpc" {
			raw, err := io.ReadAll(request.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			request.Body = io.NopCloser(bytes.NewReader(raw))
			if packet, err := wire.DecodeEndpointGroupsNodePacket(raw); err == nil && packet.Route.Operation == wire.OperationEndpointGroupsNodeKeyComplete {
				once.Do(func() { close(entered) })
				select {
				case <-release:
				case <-request.Context().Done():
					return
				}
			}
		}
		actualHandler.ServeHTTP(w, request)
	})
	f.mu.Unlock()
	completed := make(chan error, 1)
	go func() { completed <- f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source) }()
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("actual original completion did not reach barrier")
	}
	checkpoint("m4_original_complete_held_before_forward")
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: g1, EndpointID: originals[3].Anchor.Registration.EndpointID}, &card.OwnerControl)
	unblock()
	select {
	case err := <-completed:
		var refusal *endpointGroupsNodeError
		if !errors.As(err, &refusal) || refusal.code != "TARGET_NOT_AUTHORIZED" {
			t.Fatal("original completion lacked authenticated terminal refusal", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("original completion did not settle")
	}
	f.mu.Lock()
	f.handler = actualHandler
	f.mu.Unlock()
	f.client.mu.Lock()
	rejectedBefore, _ := json.Marshal(f.client.state)
	f.client.mu.Unlock()
	if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
		t.Fatal(err)
	}
	f.client.mu.Lock()
	rejectedAfter, _ := json.Marshal(f.client.state)
	f.client.mu.Unlock()
	if !bytes.Equal(rejectedBefore, rejectedAfter) {
		t.Fatal("rejected Complete retired an original Challenge")
	}
	checkpoint("m4_old_complete_rejected")
	unlock()
	q := issueFor(2, "cicada_reply")
	q.ArgumentsDigest, err = codexArgumentsDigest(map[string]any{"request_id": "synthetic-original-g2-request", "body": "synthetic original C reply"})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	issued, issueErr := requestMachineAgentCodexContextIssue(f.bridge.path, q)
	class := "NONE"
	if issueErr != nil {
		class = "OTHER_PRIVATE_ISSUE_ERROR"
		if strings.HasPrefix(issueErr.Error(), "ENDPOINT_LOCAL_HISTORY_FULL:") {
			class = "ENDPOINT_LOCAL_HISTORY_FULL"
		} else if strings.HasPrefix(issueErr.Error(), "CODEX_CONTEXT_BUSY:") {
			class = "CODEX_CONTEXT_BUSY"
		}
	}
	t.Logf("CLOSED_FOUR_THREAD_REPLY_ISSUE elapsed_ms=%d error_class=%s", time.Since(started).Milliseconds(), class)
	checkpoint("m4_c_reply_issue_finished")
	if issueErr != nil || issued == nil || issued.Ticket == "" {
		t.Fatal("four original Thread C Reply issue failed; closed class", class)
	}
	consumed, err := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(q, issued.Ticket))
	if err != nil || consumed.Context.VerificationProfile != LocalCodexContextProfileEndpointGroups || consumed.Context.NativeSessionID != natives[2] || consumed.Context.RegistrationDigest != originals[2].Anchor.RegistrationDigest {
		t.Fatal("four original Thread C Reply ticket changed its registered invocation", err)
	}
	// Bounded continuation of the existing QA M4/M6 Owner/Node sequence.
	// No 24-hour clock simulation, extra Owner loops or synthetic history.
	lock()
	// A single real ACTIVE read (normally already cached by the restarted
	// worker) verifies the skip path without adding Owner operations or a loop.
	activeR, activeCard, activeSource := manual(2, g2)
	if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, activeR, activeCard, activeSource); err != nil {
		t.Fatal("actual retained ACTIVE read", err)
	}
	f.client.mu.Lock()
	activeIntent := f.client.state.LocalEndpointIntents[activeR.IntentID]
	activeBefore, _ := json.Marshal(f.client.state)
	activeCount := 0
	for _, step := range activeIntent.Steps {
		if step.Operation != wire.OperationEndpointGroupsNodeKeyPrepare || len(step.ResponsePacket) == 0 {
			continue
		}
		envelope, openErr := f.client.openEndpointGroupsEnvelopeLocked(step.RequestPacket, step.ResponsePacket)
		var result wire.EndpointGroupsNodeKeyResult
		if openErr != nil || !envelope.OK || decodeStrictBridgeJSON(envelope.Result, &result) != nil {
			t.Fatal("retained read authentication unavailable")
		}
		if result.Grant != nil {
			activeCount++
			if endpointGroupsRetirementMetadata(activeIntent, step) {
				t.Fatal("ACTIVE revision was treated as completed Challenge metadata")
			}
		}
	}
	f.client.mu.Unlock()
	if activeCount == 0 {
		t.Fatal("actual ACTIVE response missing from skip-path test")
	}
	canceled, cancel := context.WithCancel(f.ctx)
	cancel()
	if err := f.bridge.retireEndpointGroupsChallenges(canceled, f.client, activeR, f.hub); err != nil {
		t.Fatal("ACTIVE-only origin did not preserve its read under a canceled context", err)
	}
	f.client.mu.Lock()
	activeAfter, _ := json.Marshal(f.client.state)
	f.client.mu.Unlock()
	if !bytes.Equal(activeBefore, activeAfter) {
		t.Fatal("ACTIVE prefilter changed protected state")
	}
	t.Logf("CLOSED_ACTIVE_RETENTION_SKIP active_reads=%d unchanged=true canceled_context=NO_RECEIPT_VALIDATION", activeCount)
	restart := func(label string) {
		t.Helper()
		unlock()
		if err := f.bridge.Close(); err != nil {
			t.Fatal(err)
		}
		machineNodeControlClients.Delete(f.client.statePath)
		retainedBefore, _ := json.Marshal(f.client.state.EndpointGroupsRegistrations)
		retainedIntents, _ := json.Marshal(f.client.state.LocalEndpointIntents)
		f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
		if err != nil {
			t.Fatal(err)
		}
		retainedAfter, _ := json.Marshal(f.client.state.EndpointGroupsRegistrations)
		intentsAfter, _ := json.Marshal(f.client.state.LocalEndpointIntents)
		if !bytes.Equal(retainedBefore, retainedAfter) || !bytes.Equal(retainedIntents, intentsAfter) {
			t.Fatal("reopen changed retained registration authority heads or access state")
		}
		f.bridge, err = startMachineAgentJoinBridge(f.ctx, f.nodeRoot, f.server.URL, f.nodeID, f.token)
		if err != nil {
			t.Fatal(err)
		}
		lock()
		for i, before := range originals {
			r, enrolled, err := f.client.endpointGroupsRegistrationCandidate(natives[i], f.workspace)
			key, keyErr := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), before.Anchor.Registration.EndpointID)
			if err != nil || !enrolled || !sameEndpointGroupsAnchor(r.Anchor, before.Anchor) || keyErr != nil || !machineSamePublicIdentity(key.Public(), originalKeys[i]) {
				t.Fatal("tail restart changed original identity/key/binding/epoch")
			}
		}
		checkpoint(label)
	}
	checkCIssue := func(label string) {
		t.Helper()
		checkpoint(label + "_before_issue")
		unlock()
		call := issueFor(2, "cicada_reply")
		call.ArgumentsDigest, err = codexArgumentsDigest(map[string]any{"request_id": "synthetic-original-tail-request", "body": "synthetic C reply"})
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		issued, callErr := requestMachineAgentCodexContextIssue(f.bridge.path, call)
		class := "NONE"
		if callErr != nil {
			class = "OTHER_PRIVATE_ISSUE_ERROR"
			if strings.HasPrefix(callErr.Error(), "ENDPOINT_LOCAL_HISTORY_FULL:") {
				class = "ENDPOINT_LOCAL_HISTORY_FULL"
			}
		}
		t.Logf("CLOSED_TAIL_C_ISSUE stage=%s elapsed_ms=%d error_class=%s", label, time.Since(started).Milliseconds(), class)
		checkpoint(label + "_after_issue")
		lock()
		if callErr != nil || issued == nil || issued.Ticket == "" {
			t.Fatal("finite original Owner sequence denied C Reply issue; closed class", class)
		}
		consumed, err := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(call, issued.Ticket))
		if err != nil || consumed.Context.RegistrationDigest != originals[2].Anchor.RegistrationDigest {
			t.Fatal("tail C issue lost its original registered context", err)
		}
	}
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: g1, EndpointID: originals[3].Anchor.Registration.EndpointID, Duration: "until_revoked"}, nil)
	r, card, source = manual(3, g1)
	f.mu.Lock()
	actualHandler = f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/node/control/rpc" {
			raw, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			request.Body = io.NopCloser(bytes.NewReader(raw))
			if packet, decodeErr := wire.DecodeEndpointGroupsNodePacket(raw); decodeErr == nil && packet.Route.Operation == wire.OperationEndpointGroupsNodeKeyComplete {
				committed := httptest.NewRecorder()
				actualHandler.ServeHTTP(committed, request)
				if committed.Code != http.StatusOK {
					t.Error("actual tail completion failed before response loss")
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		actualHandler.ServeHTTP(w, request)
	})
	f.mu.Unlock()
	if lostErr := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); !machineAPIHasStatus(lostErr, http.StatusServiceUnavailable) {
		t.Fatal("tail did not retain a real committed completion with lost response")
	}
	f.mu.Lock()
	f.handler = actualHandler
	f.mu.Unlock()
	f.client.mu.Lock()
	pendingBefore := cloneMachineNodeControlState(f.client.state)
	f.client.mu.Unlock()
	if pendingBefore.PendingOperation != wire.OperationEndpointGroupsNodeKeyComplete || len(pendingBefore.PendingPacket) == 0 {
		t.Fatal("retention pending-write negative lacks its actual committed original")
	}
	if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
		t.Fatal(err)
	}
	f.client.mu.Lock()
	pendingJSONBefore, _ := json.Marshal(pendingBefore)
	pendingJSONAfter, _ := json.Marshal(f.client.state)
	unchangedPending := bytes.Equal(pendingJSONBefore, pendingJSONAfter)
	f.client.mu.Unlock()
	if !unchangedPending {
		t.Fatal("retention changed a real unresolved original write or its dependencies")
	}
	checkpoint("tail_m4_d_g1_commit_response_lost")
	restart("tail_m4_d_g1_commit_reopened")
	if err := f.client.recoverNodeControlPending(f.ctx, f.token); err != nil {
		t.Fatal("tail explicit original completion recovery", err)
	}
	r, card, source = manual(3, g1)
	if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); err != nil {
		t.Fatal("tail original ACTIVE grant observation", err)
	}
	checkCIssue("tail_m4_d_g1_readd_recovered")
	_, activeD, _ := manual(3, g1)
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: g1, EndpointID: originals[3].Anchor.Registration.EndpointID}, &activeD.OwnerControl)
	manual(3, g2)
	checkCIssue("tail_m4_d_g1_removed_again")
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: g1, EndpointID: originals[0].Anchor.Registration.EndpointID, Duration: "1d"}, nil)
	r, card, source = manual(0, g1)
	if card.OwnerControl.Mode != "DEFAULT" || card.State != "ACTIVE" || source.State != "PENDING_KEY" || source.ExpiresAt == "" {
		t.Fatal("finite A takeover changed default authority before completion")
	}
	originalExpiry := source.ExpiresAt
	checkpoint("tail_m4_finite_a_pending_default_preserved")
	if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); err != nil {
		t.Fatal("tail finite A completion", err)
	}
	_, finite, finiteSource := manual(0, g1)
	if finite.OwnerControl.Mode != "OWNER" || finiteSource.ExpiresAt != originalExpiry {
		t.Fatal("finite A completion moved its reviewed deadline")
	}
	checkCIssue("tail_m4_finite_a_completed")
	restart("tail_m4_finite_a_reopened")
	_, finite, finiteSource = manual(0, g1)
	if finite.OwnerControl.Mode != "OWNER" || finiteSource.ExpiresAt != originalExpiry {
		t.Fatal("finite A restart moved its original policy deadline")
	}
	checkCIssue("tail_m4_finite_a_same_expiry_after_restart")
	_, dG2, _ := manual(3, g2)
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: g2, EndpointID: originals[3].Anchor.Registration.EndpointID}, &dG2.OwnerControl)
	r, _, _ = manual(3, g2)
	if len(r.Authorities) != 0 {
		t.Fatal("last Group removal left a current business source")
	}
	checkCIssue("tail_m6_d_last_group_removed")
	unlock()
	joinIssue := issueFor(3, "codex.operator.endpoint_register")
	name := "Synthetic original registration ready without Group"
	joinIssue.ArgumentsDigest, _ = codexArgumentsDigest(map[string]any{"operation": "endpoint_register", "name": name, "pair_label": "", "slot": ""})
	joinTicket, joinErr := requestMachineAgentCodexContextIssue(f.bridge.path, joinIssue)
	if joinErr != nil {
		t.Fatal("zero-Group original registration issue", joinErr)
	}
	joinContext, joinErr := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(joinIssue, joinTicket.Ticket))
	if joinErr != nil {
		t.Fatal(joinErr)
	}
	binding, joinErr := codexContextBinding(joinContext.Context)
	if joinErr != nil {
		t.Fatal(joinErr)
	}
	now := time.Now().UTC()
	id, _ := newLocalEndpointRequestID(now)
	joined, joinErr := requestMachineAgentEndpoint(f.bridge.path, localEndpointRequest{Version: localJoinProtocolVersion, Operation: "endpoint_register", RequestID: id, IssuedAt: now.Format(time.RFC3339Nano), APIOrigin: f.server.URL, Harness: "codex", NativeSessionID: natives[3], Workspace: f.workspace, Name: name, codexEndpointGroupsBinding: binding.codexEndpointGroupsBinding, endpointGroupsOperatorContextProof: endpointGroupsOperatorContextProof{ContextTicketID: strings.Split(joinTicket.Ticket, ".")[0], ContextConnectionNonce: joinIssue.ConnectionNonce}})
	lock()
	if joinErr != nil || joined.Join != nil || joined.Registration.EndpointID != originals[3].Anchor.Registration.EndpointID {
		t.Fatal("zero-Group Join changed original identity or claimed admission", joinErr)
	}
	r, _, _ = manual(3, g2)
	if len(r.Authorities) != 0 {
		t.Fatal("zero-Group Join restored a removed Group")
	}
	checkCIssue("tail_m6_original_join_zero_groups")
	activate(3, g2)
	checkCIssue("tail_m6_exact_owner_readd_completed")
	t.Log("CLOSED_TAIL_RESULT finite_sequence=PASS Runtime=NOT_RUN one_day_clock_expiry=NOT_RUN")
}

// Exercise the real authenticated read/write cache produced immediately above.
// No synthesized receipt can make a response eligible for retirement.
func assertEndpointGroupsCompletedChallengeRetirement(t *testing.T, f *nativePairTCPConsumerFixture, r machineEndpointGroupsRegistration) {
	t.Helper()
	f.client.mu.Lock()
	before := cloneMachineNodeControlState(f.client.state)
	intent := before.LocalEndpointIntents[r.IntentID]
	var readID, writeID string
	var read machineLocalEndpointStep
	var request wire.EndpointGroupsNodeKeyPrepare
	var completeRequest wire.EndpointGroupsNodeKeyComplete
	for id, step := range intent.Steps {
		if step.Operation == wire.OperationEndpointGroupsNodeKeyPrepare {
			readID, read = id, step
			if decodeStrictBridgeJSON(step.Body, &request) != nil {
				t.Fatal("read body unavailable")
			}
		}
		if step.Operation == wire.OperationEndpointGroupsNodeKeyComplete {
			writeID = id
			if decodeStrictBridgeJSON(step.Body, &completeRequest) != nil {
				t.Fatal("write body unavailable")
			}
		}
	}
	f.client.mu.Unlock()
	if readID == "" || writeID == "" || len(read.ResponsePacket) == 0 || !intent.Steps[writeID].Settled {
		t.Fatal("real completed Challenge receipts unavailable")
	}
	var rpcMu sync.Mutex
	rpcCalls := 0
	f.mu.Lock()
	actual := f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/v2/node/control/rpc" {
			rpcMu.Lock()
			rpcCalls++
			rpcMu.Unlock()
		}
		actual.ServeHTTP(w, req)
	})
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.handler = actual; f.mu.Unlock() }()
	// Any single retained pending coordinate fences collection, including crash
	// windows with metadata but no packet. None may dispatch or erase a receipt.
	pendingFields := []struct {
		name string
		set  func(*machineNodeControlState)
	}{
		{"operation", func(x *machineNodeControlState) { x.PendingOperation = wire.OperationEndpointGroupsNodeRenew }},
		{"operation_id", func(x *machineNodeControlState) { x.PendingOperationID = writeID }},
		{"sequence", func(x *machineNodeControlState) { x.PendingSequence = before.Sequence + 1 }},
		{"plaintext_digest", func(x *machineNodeControlState) { x.PendingPlaintextDigest = strings.Repeat("a", 64) }},
		{"packet", func(x *machineNodeControlState) { x.PendingPacket = bytes.Clone(intent.Steps[writeID].RequestPacket) }},
		{"response", func(x *machineNodeControlState) {
			x.PendingResponsePacket = bytes.Clone(intent.Steps[writeID].ResponsePacket)
		}},
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
	for fieldIndex, field := range pendingFields {
		f.client.mu.Lock()
		f.client.state = cloneMachineNodeControlState(before)
		field.set(&f.client.state)
		issuerFenceUnchanged := fieldIndex < 7 || endpointGroupsNodePendingEmpty(f.client.state)
		fencedBefore, _ := json.Marshal(f.client.state)
		f.client.mu.Unlock()
		if !issuerFenceUnchanged {
			t.Fatal("retention-only legacy state changed the issuer read fence", field.name)
		}
		if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
			t.Fatal(field.name, err)
		}
		f.client.mu.Lock()
		fencedAfter, _ := json.Marshal(f.client.state)
		f.client.state = cloneMachineNodeControlState(before)
		f.client.mu.Unlock()
		if !bytes.Equal(fencedBefore, fencedAfter) {
			t.Fatal("incomplete pending state lost its read/write fence", field.name)
		}
	}
	// A corrupt authenticated receipt and a changed Challenge cannot supersede
	// the original read. These negative copies are never persisted or dispatched.
	for _, variant := range []string{"corrupt_receipt", "different_challenge", "unsettled_complete"} {
		f.client.mu.Lock()
		f.client.state = cloneMachineNodeControlState(before)
		negative := f.client.state.LocalEndpointIntents[r.IntentID]
		write := negative.Steps[writeID]
		switch variant {
		case "corrupt_receipt":
			write.ResponsePacket[len(write.ResponsePacket)/2] ^= 1
		case "different_challenge":
			changed := completeRequest
			changed.ChallengeID += "-different"
			write.Body, _ = json.Marshal(changed)
		case "unsettled_complete":
			write.Settled = false
		}
		negative.Steps[writeID] = write
		f.client.state.LocalEndpointIntents[r.IntentID] = negative
		negativeBefore := cloneMachineNodeControlState(f.client.state)
		f.client.mu.Unlock()
		if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
			t.Fatal(variant, err)
		}
		f.client.mu.Lock()
		unchanged := reflect.DeepEqual(negativeBefore, f.client.state)
		f.client.state = cloneMachineNodeControlState(before)
		f.client.mu.Unlock()
		if !unchanged {
			t.Fatal("unverified or unresolved Complete retired a Challenge", variant)
		}
	}
	if err := f.bridge.retireEndpointGroupsChallenges(f.ctx, f.client, r, f.hub); err != nil {
		t.Fatal(err)
	}
	f.client.mu.Lock()
	after := cloneMachineNodeControlState(f.client.state)
	f.client.mu.Unlock()
	expected := cloneMachineNodeControlState(before)
	old := expected.LocalEndpointIntents[r.IntentID]
	tombstone := old.Steps[readID]
	tombstone.ResponsePacket = nil
	old.Steps[readID] = tombstone
	expected.LocalEndpointIntents[r.IntentID] = old
	if !reflect.DeepEqual(after, expected) {
		t.Fatal("retirement changed more than the confirmed Challenge response")
	}
	scope := localEndpointCallScope{IntentID: r.IntentID, Digest: r.IntentDigest, StepID: readID}
	ctx := context.WithValue(f.ctx, localEndpointCallKey{}, scope)
	var result wire.EndpointGroupsNodeKeyResult
	if err := f.client.call(ctx, f.token, wire.OperationEndpointGroupsNodeKeyPrepare, request, &result); !errors.Is(err, errLocalEndpointReceiptExpired) {
		t.Fatal("old exact read was not durably expired", err)
	}
	request.ExpectedRelationRevision++
	if err := f.client.call(ctx, f.token, wire.OperationEndpointGroupsNodeKeyPrepare, request, &result); !errors.Is(err, errLocalEndpointIntentConflict) {
		t.Fatal("same read ID accepted a changed body", err)
	}
	writeScope := localEndpointCallScope{IntentID: r.IntentID, Digest: r.IntentDigest, StepID: writeID}
	if err := f.client.call(context.WithValue(f.ctx, localEndpointCallKey{}, writeScope), f.token, wire.OperationEndpointGroupsNodeKeyComplete, completeRequest, &result); err != nil || result.Grant == nil {
		t.Fatal("retirement lost the successful original write receipt", err)
	}
	rpcMu.Lock()
	calls := rpcCalls
	rpcMu.Unlock()
	f.client.mu.Lock()
	sequenceUnchanged := f.client.state.Sequence == before.Sequence
	f.client.mu.Unlock()
	if calls != 0 || !sequenceUnchanged {
		t.Fatal("retired read or retained write replay dispatched new traffic")
	}
	beforeRaw, _ := json.Marshal(before)
	afterRaw, _ := json.Marshal(after)
	t.Logf("CLOSED_CHALLENGE_RETIREMENT raw_response_bytes=%d serialized_reclaimed_bytes=%d exact_read=EXPIRED changed_body=CONFLICT pending_fields=13 rpc_calls=%d original_complete=RETAINED", len(read.ResponsePacket), len(beforeRaw)-len(afterRaw), calls)
}
