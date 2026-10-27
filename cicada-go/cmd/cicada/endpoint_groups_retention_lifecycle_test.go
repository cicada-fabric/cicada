package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

// Derived finite M4 prefix, real D Leave/Join, three bounded production batches,
// and exactly one real Owner P0 revoke and one
// synthetic original-D groups issue/consume. Not the actual Runtime footprint;
// no App/Host process, additional Owner loops, padding or identity changes.
// Every retained byte comes from real enrollment, Owner review or Node RPC;
// no fabricated history, capacity padding, state limit or TTL changes are used.
func TestEndpointGroupsRetirementSurvivesP0RevokeAndReadd(t *testing.T) {
	testStarted := time.Now()
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

	// Count each original registration by its actual retained origin intent.
	// Cached receipts are authenticated only for closed result classification;
	// neither their metadata nor these snapshots grants current authority.
	footprint := func(label string) {
		t.Helper()
		f.client.mu.Lock()
		state := cloneMachineNodeControlState(f.client.state)
		var cached []map[string]any
		for id, intent := range state.LocalEndpointIntents {
			for stepID, step := range intent.Steps {
				if step.Operation != wire.OperationEndpointGroupsNodeKeyPrepare && step.Operation != wire.OperationEndpointGroupsNodeKeyComplete {
					continue
				}
				if len(step.ResponsePacket) == 0 {
					continue
				}
				envelope, err := f.client.openEndpointGroupsEnvelopeLocked(step.RequestPacket, step.ResponsePacket)
				kind, code := "UNVERIFIED", ""
				if err == nil {
					if !envelope.OK {
						kind = "AUTHENTICATED_REFUSAL"
						code = envelope.ErrorCode
					} else {
						var result wire.EndpointGroupsNodeKeyResult
						if decodeStrictBridgeJSON(envelope.Result, &result) == nil {
							if result.Grant != nil && result.Challenge == nil {
								kind = "ACTIVE_GRANT"
							} else if result.Challenge != nil && result.Grant == nil {
								kind = "CHALLENGE"
							}
						}
					}
				}
				h := sha256.Sum256([]byte(id))
				stepHash := sha256.Sum256([]byte(stepID))
				cached = append(cached, map[string]any{"origin_intent_sha256": fmt.Sprintf("%x", h), "step_sha256": fmt.Sprintf("%x", stepHash), "operation": step.Operation, "settled": step.Settled, "response_bytes": len(step.ResponsePacket), "authenticated_result_kind": kind, "error_code": code})
			}
		}
		f.client.mu.Unlock()
		serialized, _ := json.Marshal(state)
		flags := map[string]bool{"operation": state.PendingOperation != "", "operation_id": state.PendingOperationID != "", "sequence": state.PendingSequence != 0, "plaintext_digest": state.PendingPlaintextDigest != "", "packet": len(state.PendingPacket) > 0, "response": len(state.PendingResponsePacket) > 0, "local_intent": state.PendingLocalEndpointIntentID != "", "native_pair_body": len(state.PendingNativePairBody) > 0, "worker_id": state.PendingWorkerID != "", "worker_attempt": state.PendingWorkerAttempt != 0, "snapshot_path": state.PendingSnapshotPath != "", "snapshot_manifest": state.PendingSnapshotManifest != nil, "claim_ticket": state.ClaimTicket != nil, "endpoint_groups_diagnostic": state.EndpointGroupsDiagnostic != nil, "native_pair_diagnostic": state.NativePairDiagnostic != nil}
		var actors []map[string]any
		for i, sid := range natives {
			for _, reg := range state.EndpointGroupsRegistrations {
				if reg.Anchor.Registration.NativeSessionID != sid {
					continue
				}
				ops := map[string]int{}
				for _, step := range state.LocalEndpointIntents[reg.IntentID].Steps {
					ops[step.Operation]++
				}
				h := sha256.Sum256([]byte(reg.IntentID))
				actors = append(actors, map[string]any{"actor_index": i, "origin_intent_sha256": fmt.Sprintf("%x", h), "origin_operations": ops, "locally_offline": reg.LocallyOffline})
			}
		}
		ops := map[string]int{}
		steps := 0
		for _, intent := range state.LocalEndpointIntents {
			for _, step := range intent.Steps {
				ops[step.Operation]++
				steps++
			}
		}
		row := map[string]any{"phase": label, "serialized_bytes": len(serialized), "rpc_reserve_bytes": 2 << 20, "managed_reserve_bytes": managedPairStateReserve(state), "pre_pending_rpc_headroom_bytes": maxMachineNodeControlStateBytes - len(serialized) - (2 << 20) - managedPairStateReserve(state), "pending_flags_15": flags, "pending_operation": state.PendingOperation, "pending_sequence": state.PendingSequence, "intents": len(state.LocalEndpointIntents), "steps": steps, "operations": ops, "actor_origins": actors, "cached_node_receipt_classification": cached, "batch_entrypoint_has_no_error_return": true}
		raw, _ := json.Marshal(row)
		t.Logf("CLOSED_SIX_INTENT_PHASE %s", raw)
	}

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

	// Exactly one actual maintenance read while this first manual source is
	// still ACTIVE. It cannot be reconstructed after its later Owner removal.
	footprint("m1_first_d_g2_active_before_production_batch")
	f.client.mu.Lock()
	priorReadSteps := map[string]bool{}
	for id := range f.client.state.LocalEndpointIntents[originals[3].IntentID].Steps {
		priorReadSteps[id] = true
	}
	f.client.mu.Unlock()
	unlock()
	f.bridge.renewEndpointGroupsRegistrationBatch(f.ctx)
	lock()
	footprint("m1_first_d_g2_active_after_production_batch")
	f.client.mu.Lock()
	var firstActiveRows []map[string]any
	for id, step := range f.client.state.LocalEndpointIntents[originals[3].IntentID].Steps {
		if priorReadSteps[id] || step.Operation != wire.OperationEndpointGroupsNodeKeyPrepare || !step.Settled || len(step.ResponsePacket) == 0 {
			continue
		}
		var q wire.EndpointGroupsNodeKeyPrepare
		if decodeStrictBridgeJSON(step.Body, &q) != nil || q.PolicyID != dHead.PolicyID || q.PolicyEpoch != dHead.PolicyEpoch || q.GroupID != g2 || q.EndpointID != originals[3].Anchor.Registration.EndpointID {
			continue
		}
		envelope, err := f.client.openEndpointGroupsEnvelopeLocked(step.RequestPacket, step.ResponsePacket)
		var result wire.EndpointGroupsNodeKeyResult
		if err != nil || !envelope.OK || decodeStrictBridgeJSON(envelope.Result, &result) != nil || result.Grant == nil || result.Challenge != nil || result.OwnerControl != dHead {
			continue
		}
		hash := func(v any) string { raw, _ := json.Marshal(v); h := sha256.Sum256(raw); return fmt.Sprintf("%x", h) }
		firstActiveRows = append(firstActiveRows, map[string]any{"authenticated_result_kind": "ACTIVE_GRANT", "policy_id_sha256": hash(q.PolicyID), "policy_epoch": q.PolicyEpoch, "group_id_sha256": hash(q.GroupID), "endpoint_id_sha256": hash(q.EndpointID), "owner_head_sha256": hash(result.OwnerControl), "step_id_sha256": hash(id), "expected_relation_revision": q.ExpectedRelationRevision, "original_request_bytes": len(step.RequestPacket), "response_bytes": len(step.ResponsePacket), "same_original_owner_head": true})
	}
	f.client.mu.Unlock()
	firstActiveClosed, _ := json.Marshal(firstActiveRows)
	t.Logf("CLOSED_FIRST_D_G2_ACTIVE_RECEIPT %s", firstActiveClosed)
	if len(firstActiveRows) == 0 {
		t.Fatal("required real early ACTIVE read was not produced")
	}
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

	footprint("m3_before_real_d_leave_join")
	dOriginal, _, err := f.client.endpointGroupsRegistrationCandidate(natives[3], f.workspace)
	if err != nil {
		t.Fatal(err)
	}
	_, dJoined, _, err := f.client.endpointGroupsOriginal(dOriginal)
	if err != nil {
		t.Fatal(err)
	}
	_, dBeforeOps, _ := manual(3, g2)
	for _, operation := range []string{"endpoint_leave", "endpoint_register"} {
		name := ""
		if operation == "endpoint_register" {
			name = dJoined.Endpoint.Name
		}
		unlock()
		issue := issueFor(3, codexOperatorContextTool(operation))
		issue.TurnID, issue.ToolUseID = "", ""
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		issue.ConnectionNonce = hex.EncodeToString(nonce)
		issue.ArgumentsDigest, err = codexArgumentsDigest(map[string]any{"operation": operation, "name": name, "pair_label": "", "slot": ""})
		if err != nil {
			t.Fatal(err)
		}
		ticket, issueErr := diagnoseEndpointGroupsRetentionLifecycleUnixIssueOnce(t, f.bridge.path, issue, testStarted)
		if issueErr != nil || ticket == nil || ticket.Ticket == "" {
			t.Fatal("CONTROL_RED actual D operator context issue failed", operation)
		}
		contextResult, consumeErr := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(issue, ticket.Ticket))
		if consumeErr != nil {
			t.Fatal("actual D operator consume", consumeErr)
		}
		binding, bindingErr := codexContextBinding(contextResult.Context)
		if bindingErr != nil || binding.EndpointGroupsVersion != 1 {
			t.Fatal("actual D original profile absent", bindingErr)
		}
		now := time.Now().UTC()
		id, idErr := newLocalEndpointRequestID(now)
		if idErr != nil {
			t.Fatal(idErr)
		}
		request := localEndpointRequest{Version: localJoinProtocolVersion, Operation: operation, RequestID: id, IssuedAt: now.Format(time.RFC3339Nano), APIOrigin: f.server.URL, Harness: "codex", NativeSessionID: natives[3], Workspace: f.workspace, Name: name, codexEndpointGroupsBinding: binding.codexEndpointGroupsBinding, endpointGroupsOperatorContextProof: endpointGroupsOperatorContextProof{ContextTicketID: strings.Split(ticket.Ticket, ".")[0], ContextConnectionNonce: issue.ConnectionNonce}}
		result, requestErr := requestMachineAgentEndpoint(f.bridge.path, request)
		class, digest := "NONE", ""
		if requestErr != nil {
			class = endpointGroupsRetentionLifecycleRemoteClass(requestErr.Error())
			h := sha256.Sum256([]byte(requestErr.Error()))
			digest = fmt.Sprintf("%x", h)
		}
		t.Logf("CLOSED_SIX_INTENT_OPERATOR operation=%s error_class=%s error_sha256=%s", operation, class, digest)
		lock()
		if requestErr != nil || result == nil || result.State != "COMPLETED" {
			t.Fatal("CONTROL_RED real D operator request failed", operation)
		}
		current, _, currentErr := f.client.endpointGroupsRegistrationCandidate(natives[3], f.workspace)
		key, keyErr := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), originals[3].Anchor.Registration.EndpointID)
		if currentErr != nil || keyErr != nil || !sameEndpointGroupsAnchor(current.Anchor, dOriginal.Anchor) || current.IntentID != dOriginal.IntentID || current.LeaseID != dOriginal.LeaseID || !machineSamePublicIdentity(key.Public(), originalKeys[3]) || current.LocallyOffline != (operation == "endpoint_leave") {
			t.Fatal("operator changed original identity or local access semantics")
		}
		if operation == "endpoint_register" && (result.Registration == nil || result.Registration.Name != dJoined.Endpoint.Name || result.Join != nil) {
			t.Fatal("D Join changed original name or allocated a new domain Join")
		}
		footprint("m3_after_real_d_" + operation)
	}
	dAfterRecord, dAfterOps, _ := manual(3, g2)
	if dAfterOps.OwnerControl != dBeforeOps.OwnerControl || dAfterOps.State != "ACTIVE" {
		t.Fatal("local Leave/Join changed D manual G2")
	}
	currentD, dAfterDesc, descErr := f.bridge.describeEndpointGroups(f.ctx, f.client, dAfterRecord, "", 64)
	if descErr != nil || !sameEndpointGroupsAnchor(currentD.Anchor, dOriginal.Anchor) {
		t.Fatal("D original anchor after local operator flow", descErr)
	}
	denySeen := false
	for _, relation := range dAfterDesc.Relations {
		if relation.GroupID == g1 && relation.OwnerControl.Mode == "OWNER" && relation.OwnerControl.DenyReason == "REMOVED" {
			denySeen = true
		}
	}
	if !denySeen {
		t.Fatal("local Join erased original G1 Owner deny")
	}
	nodePublic := f.client.publicIdentity()
	unlock()
	if err := f.bridge.Close(); err != nil {
		t.Fatal(err)
	}
	machineNodeControlClients.Delete(f.client.statePath)
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

	footprint("m4_recovered_before_production_batch")
	unlock()
	f.bridge.renewEndpointGroupsRegistrationBatch(f.ctx)
	lock()
	footprint("m4_recovered_after_production_batch")
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

	// Capture the original manual source before P0 revocation. No Node Describe
	// or App/session operation is inserted between the revoke and D's issue.
	_, dBefore, _ := manual(3, g2)
	if dBefore.State != "ACTIVE" || dBefore.OwnerControl.Mode != "OWNER" {
		t.Fatal("original D manual Group was not active before P0 revoke")
	}
	status, err := wire.NewLocalDomainStatus(f.session, f.scope.Actor, domain.Policy.PolicyID, f.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := wire.SealClientRequest(f.device, f.hub, status)
	if err != nil {
		t.Fatal(err)
	}
	raw := f.http(t, http.MethodPost, wire.LocalDomainHTTPPath(wire.OperationLocalDomainStatus), "", "", packet, http.StatusOK)
	var currentP0 wire.LocalDomainResult
	if wire.OpenLocalDomainResponse(f.device, f.hub, packet, raw, &currentP0) != nil || wire.ValidateLocalDomainResultTarget(status, packet, currentP0, f.hub) != nil || currentP0.Description == nil || currentP0.Description.State != wire.LocalDomainActive {
		t.Fatal("real fresh P0 Owner status unavailable")
	}
	revoke, err := wire.NewLocalDomainRevoke(f.session, f.scope.Actor, *currentP0.Description, f.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet, err = wire.SealClientRequest(f.device, f.hub, revoke)
	if err != nil {
		t.Fatal(err)
	}
	raw = f.http(t, http.MethodPost, wire.LocalDomainHTTPPath(wire.OperationLocalDomainRevoke), "", "", packet, http.StatusOK)
	var revoked wire.LocalDomainResult
	if wire.OpenLocalDomainResponse(f.device, f.hub, packet, raw, &revoked) != nil || wire.ValidateLocalDomainResultTarget(revoke, packet, revoked, f.hub) != nil || revoked.Description == nil || revoked.Description.State != wire.LocalDomainRevoked {
		t.Fatal("real Owner P0 revoke did not authenticate REVOKED")
	}

	footprint("p0_revoked_before_production_batch")
	unlock()
	f.bridge.renewEndpointGroupsRegistrationBatch(f.ctx)
	lock()
	footprint("p0_revoked_after_production_batch")
	// App authorization is used no further. History probes are local reads, not
	// current authorization evidence. The following is the sole new D issue.
	p0Snapshot := func(label string) {
		t.Helper()
		raw, err := os.ReadFile(f.client.statePath)
		if err != nil {
			t.Fatal(err)
		}
		var state machineNodeControlState
		if json.Unmarshal(raw, &state) != nil {
			t.Fatal("protected control state unavailable")
		}
		serialized, _ := json.Marshal(state)
		hash := func(v any) string { b, _ := json.Marshal(v); h := sha256.Sum256(b); return fmt.Sprintf("%x", h) }
		flags := map[string]bool{"operation": state.PendingOperation != "", "operation_id": state.PendingOperationID != "", "sequence": state.PendingSequence != 0, "plaintext_digest": state.PendingPlaintextDigest != "", "packet": len(state.PendingPacket) > 0, "response": len(state.PendingResponsePacket) > 0, "local_intent": state.PendingLocalEndpointIntentID != "", "native_pair_body": len(state.PendingNativePairBody) > 0, "worker_id": state.PendingWorkerID != "", "worker_attempt": state.PendingWorkerAttempt != 0, "snapshot_path": state.PendingSnapshotPath != "", "snapshot_manifest": state.PendingSnapshotManifest != nil, "claim_ticket": state.ClaimTicket != nil, "endpoint_groups_diagnostic": state.EndpointGroupsDiagnostic != nil, "native_pair_diagnostic": state.NativePairDiagnostic != nil}
		var registrations []map[string]any
		for i, sid := range natives {
			for _, reg := range state.EndpointGroupsRegistrations {
				if reg.Anchor.Registration.NativeSessionID != sid {
					continue
				}
				immutable := reg.Anchor
				immutable.State = ""
				immutable.LeaseExpiresAt = ""
				registrations = append(registrations, map[string]any{"actor_index": i, "registration_sha256": hash(reg.Anchor), "immutable_anchor_sha256": hash(immutable), "registration_digest_sha256": hash(reg.Anchor.RegistrationDigest), "authorities_sha256": hash(reg.Authorities), "authority_count": len(reg.Authorities), "locally_offline": reg.LocallyOffline, "anchor_state": reg.Anchor.State, "lease_live": time.Now().Before(parseMachineNativePairTime(reg.Anchor.LeaseExpiresAt))})
			}
		}
		var steps int
		ops := map[string]int{}
		for _, intent := range state.LocalEndpointIntents {
			for _, step := range intent.Steps {
				steps++
				ops[step.Operation]++
			}
		}
		row := map[string]any{"phase": label, "disk_bytes": len(raw), "serialized_bytes": len(serialized), "managed_reserve_bytes": managedPairStateReserve(state), "rpc_reserve_bytes": 2 << 20, "limit_bytes": maxMachineNodeControlStateBytes, "pre_pending_rpc_headroom_bytes": maxMachineNodeControlStateBytes - len(serialized) - (2 << 20) - managedPairStateReserve(state), "pending_flags_15": flags, "pending_operation": state.PendingOperation, "pending_sequence": state.PendingSequence, "pending_operation_id_sha256": hash(state.PendingOperationID), "pending_packet_bytes": len(state.PendingPacket), "pending_response_bytes": len(state.PendingResponsePacket), "retained_read_fence": state.EndpointGroupsLastReadFence != nil, "pending_pairing": state.PendingPairing != nil, "intents": len(state.LocalEndpointIntents), "steps": steps, "operations": ops, "registrations": registrations, "original_d_g2_head_sha256": hash(dBefore.OwnerControl), "original_d_g2_mode": dBefore.OwnerControl.Mode, "original_d_g2_state": dBefore.State, "original_d_g2_is_pre_revoke_snapshot": true}
		closed, _ := json.Marshal(row)
		t.Logf("CLOSED_SIX_INTENT_P0_CONTROL_STATE %s", closed)
	}
	p0History := func(label string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
		defer cancel()
		crypto, openErr := nodekeys.OpenExistingCryptoState(ctx, machineNodeStateDir(f.nodeRoot, f.nodeID))
		class := "NONE"
		var digest string
		if openErr == nil {
			_, openErr = crypto.LocalDomainPolicyForGroup(ctx, domain.Policy.GroupID)
			_ = crypto.Close()
		}
		if openErr != nil {
			class = endpointGroupsRetentionLifecycleErrorEnum(openErr)
			h := sha256.Sum256([]byte(openErr.Error()))
			digest = fmt.Sprintf("%x", h)
		}
		t.Logf("CLOSED_SIX_INTENT_P0_HISTORY_GETTER phase=%s success=%t error_enum=%s error_sha256=%s current_authority=false", label, openErr == nil, class, digest)
	}
	p0Snapshot("p0_revoked_before_d_issue")
	p0History("before_d_issue")
	unlock()
	groupsIssue := issueFor(3, "cicada_groups")
	groupsIssue.TurnID, groupsIssue.ToolUseID = "synthetic-p0-revoke-groups-turn", "synthetic-p0-revoke-groups-tool"
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	groupsIssue.ConnectionNonce = hex.EncodeToString(nonce)
	groupsIssue.ArgumentsDigest, err = codexArgumentsDigest(map[string]any{"network_id": domain.Policy.NetworkID})
	if err != nil {
		t.Fatal(err)
	}
	groupsTicket, groupsErr := diagnoseEndpointGroupsRetentionLifecycleUnixIssueOnce(t, f.bridge.path, groupsIssue, testStarted)
	p0Snapshot("p0_revoked_after_d_issue")
	p0History("after_d_issue")
	if groupsErr != nil || groupsTicket == nil || groupsTicket.Ticket == "" {
		t.Fatal("CONTROL_RED original D groups issue failed after authenticated P0 revoke")
	}
	groupsContext, consumeErr := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(groupsIssue, groupsTicket.Ticket))
	if consumeErr != nil || groupsContext.Context.VerificationProfile != LocalCodexContextProfileEndpointGroups || groupsContext.Context.NativeSessionID != natives[3] || groupsContext.Context.RegistrationDigest != originals[3].Anchor.RegistrationDigest {
		t.Fatal("CONTROL_RED original D context consume failed or changed original coordinates", consumeErr)
	}
	lock()
	_, dG2, _ := manual(3, g2)
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: g2, EndpointID: originals[3].Anchor.Registration.EndpointID}, &dG2.OwnerControl)
	r, _, _ = manual(3, g2)
	if len(r.Authorities) != 0 {
		t.Fatal("last Group removal left a current business source")
	}
	checkCIssue("tail_m6_d_last_group_removed")
	unlock()
	joinIssue := issueFor(3, "codex.operator.endpoint_register")
	name := dJoined.Endpoint.Name
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
	t.Log("CLOSED_RETENTION_LIFECYCLE P0_REVOKED_M6_REMOVE_JOIN_READD_PASSED Runtime=NOT_RUN")
}

func endpointGroupsRetentionLifecycleErrorEnum(err error) string {
	if err == nil {
		return "NONE"
	}
	switch {
	case errors.Is(err, io.EOF):
		return "EOF"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "UNEXPECTED_EOF"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "DEADLINE_EXCEEDED"
	case errors.Is(err, context.Canceled):
		return "CONTEXT_CANCELED"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "NETWORK_TIMEOUT"
	}
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		return "JSON_SYNTAX"
	}
	var field *json.UnmarshalTypeError
	if errors.As(err, &field) {
		return "JSON_FIELD_TYPE"
	}
	return "OTHER"
}

func endpointGroupsRetentionLifecycleRemoteClass(raw string) string {
	if raw == "" {
		return "NONE"
	}
	if raw == context.DeadlineExceeded.Error() {
		return "CONTEXT_DEADLINE_EXCEEDED"
	}
	if raw == context.Canceled.Error() {
		return "CONTEXT_CANCELED"
	}
	for _, known := range []string{"ENDPOINT_LOCAL_HISTORY_FULL", "ENDPOINT_LOCAL_INTENT_CONFLICT", "ENDPOINT_LOCAL_RECEIPT_EXPIRED", "OWNER_ENDPOINT_GROUPS_REJECTED", "ENDPOINT_LOCAL_OFFLINE", "UNSUPPORTED_PROFILE", "CODEX_CONTEXT_BUSY", "CODEX_CONTEXT_INVALID"} {
		if strings.HasPrefix(raw, known+":") {
			return known
		}
	}
	return "REMOTE_OTHER"
}

// Identical owner/socket checks, Dial2, client35, newline JSON and CloseWrite.
// The only difference is retaining safe classifications before the production
// client coalesces Decode errors. This issues exactly one original request.
func diagnoseEndpointGroupsRetentionLifecycleUnixIssueOnce(t *testing.T, socketPath string, q localCodexContextIssue, testStarted time.Time) (issued *localCodexContextIssueResult, resultErr error) {
	t.Helper()
	started := time.Now()
	row := map[string]any{"wall_start_utc": started.UTC().Format(time.RFC3339Nano), "decode_error_enum": "NOT_REACHED", "remote_error_class": "NOT_REACHED", "stage": "VALIDATE_SOCKET", "tool_call_count": 1}
	defer func() {
		row["wall_end_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
		row["issue_monotonic_elapsed_ms"] = time.Since(started).Milliseconds()
		row["test_monotonic_elapsed_ms"] = time.Since(testStarted).Milliseconds()
		row["result_error_enum"] = endpointGroupsRetentionLifecycleErrorEnum(resultErr)
		row["ticket_returned"] = issued != nil && issued.Ticket != ""
		raw, _ := json.Marshal(row)
		t.Logf("CLOSED_SIX_INTENT_P0_UNIX_DECODE_DIAGNOSTIC %s", raw)
	}()
	if err := validateMachineAgentJoinSocketForDial(socketPath); err != nil {
		return nil, errors.New("DIAGNOSTIC_SOCKET_VALIDATION_REJECTED")
	}
	row["stage"] = "DIAL"
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(35 * time.Second))
	row["dial_complete_ms"] = time.Since(started).Milliseconds()
	row["stage"] = "ENCODE"
	if err := json.NewEncoder(conn).Encode(q); err != nil {
		return nil, err
	}
	if unix, ok := conn.(*net.UnixConn); ok {
		if err := unix.CloseWrite(); err != nil {
			return nil, err
		}
	}
	row["write_complete_ms"] = time.Since(started).Milliseconds()
	row["stage"] = "DECODE_RESPONSE"
	decoder := json.NewDecoder(io.LimitReader(conn, 2<<20))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil {
		row["decode_error_enum"] = endpointGroupsRetentionLifecycleErrorEnum(err)
		return nil, err
	}
	row["decode_error_enum"] = "NONE"
	row["response_complete_ms"] = time.Since(started).Milliseconds()
	if response.Version != localJoinProtocolVersion {
		return nil, errors.New("DIAGNOSTIC_RESPONSE_VERSION_REJECTED")
	}
	row["stage"] = "DECODE_FRAMING"
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		row["framing_error_enum"] = endpointGroupsRetentionLifecycleErrorEnum(err)
		return nil, errors.New("DIAGNOSTIC_RESPONSE_FRAMING_REJECTED")
	}
	row["framing_error_enum"] = "EOF_EXPECTED"
	row["stage"] = "REMOTE_RESULT"
	row["remote_error_class"] = endpointGroupsRetentionLifecycleRemoteClass(response.Error)
	if response.Error != "" {
		digest := sha256.Sum256([]byte(response.Error))
		row["remote_error_sha256"] = fmt.Sprintf("%x", digest)
		return nil, errors.New("DIAGNOSTIC_" + endpointGroupsRetentionLifecycleRemoteClass(response.Error))
	}
	if response.CodexContextIssue == nil {
		return nil, errors.New("DIAGNOSTIC_MISSING_CONTEXT_RESULT")
	}
	row["stage"] = "COMPLETE"
	return response.CodexContextIssue, nil
}
