package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Narrow two-original C/D control, not the old full Runtime footprint. All
// authority, history and IPC come from existing production paths. No padding,
// discarded state, changed identities, fake grants or verification budgets.
func TestEndpointGroupsCSelectAfterDLastGroupReaddControl(t *testing.T) {
	runEndpointGroupsM6SelectionControl(t, false)
}
func TestEndpointGroupsCSelectWithFourOriginalHistories(t *testing.T) {
	runEndpointGroupsM6SelectionControl(t, true)
}
func TestEndpointGroupsCapacityFourOriginalLifecycle(t *testing.T) {
	runEndpointGroupsM6SelectionControl(t, true, true)
}
func runEndpointGroupsM6SelectionControl(t *testing.T, withHistory bool, continueLifecycle ...bool) {
	f := newNativePeerTCPConsumerFixture(t, false)
	domain := activateLocalDomainConsumer(t, f)
	natives := []string{f.native[0], f.native[1]}
	if withHistory {
		natives = append(natives, "synthetic-m6-original-a", "synthetic-m6-original-b")
	}
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
	checkpoint := func(label string) { t.Helper(); t.Logf("CLOSED_HEAD_CHECKPOINT phase=%s", label) }
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
	originals := make([]machineEndpointGroupsRegistration, len(natives))
	originalKeys := make([]e2ee.PublicIdentity, len(natives))
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

	group := apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, Name: "Synthetic C retained and D last Group"}, nil).Operation.Target.GroupID
	snapshot := func(stage string) {
		t.Helper()
		raw, err := os.ReadFile(f.client.statePath)
		if err != nil {
			t.Fatal(err)
		}
		var state machineNodeControlState
		if json.Unmarshal(raw, &state) != nil {
			t.Fatal("closed control state unavailable")
		}
		encoded, _ := json.Marshal(state)
		steps := 0
		operations := map[string]int{}
		for _, intent := range state.LocalEndpointIntents {
			steps += len(intent.Steps)
			for _, step := range intent.Steps {
				operations[step.Operation]++
			}
		}
		flags := map[string]bool{"operation": state.PendingOperation != "", "operation_id": state.PendingOperationID != "", "sequence": state.PendingSequence != 0, "plaintext_digest": state.PendingPlaintextDigest != "", "packet": len(state.PendingPacket) > 0, "response": len(state.PendingResponsePacket) > 0, "local_intent": state.PendingLocalEndpointIntentID != "", "native_pair_body": len(state.PendingNativePairBody) > 0, "worker_id": state.PendingWorkerID != "", "worker_attempt": state.PendingWorkerAttempt != 0, "snapshot_path": state.PendingSnapshotPath != "", "snapshot_manifest": state.PendingSnapshotManifest != nil, "claim_ticket": state.ClaimTicket != nil, "endpoint_groups_diagnostic": state.EndpointGroupsDiagnostic != nil, "native_pair_diagnostic": state.NativePairDiagnostic != nil}
		actors := []map[string]any{}
		for i, sid := range natives {
			for _, reg := range state.EndpointGroupsRegistrations {
				if reg.Anchor.Registration.NativeSessionID == sid {
					actors = append(actors, map[string]any{"role_index": i, "present": true, "offline": reg.LocallyOffline, "lease_live": time.Now().Before(parseMachineNativePairTime(reg.Anchor.LeaseExpiresAt)), "authority_count": len(reg.Authorities), "registration_digest_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(reg.Anchor.RegistrationDigest)))})
				}
			}
		}
		row := map[string]any{"stage": stage, "bytes": len(encoded), "disk_bytes": len(raw), "headroom_bytes": maxMachineNodeControlStateBytes - len(encoded) - (2 << 20) - managedPairStateReserve(state), "steps": steps, "operations": operations, "intents": len(state.LocalEndpointIntents), "pending_flags_15": flags, "actors": actors}
		closed, _ := json.Marshal(row)
		t.Logf("CLOSED_M6_SELECTION_STATE %s", closed)
	}

	activateFor := func(i int, g, duration string) e2ee.EndpointGroupOwnerControl {
		apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: g, EndpointID: originals[i].Anchor.Registration.EndpointID, Duration: duration}, nil)
		reg, card, source := manual(i, g)
		if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, reg, card, source); err != nil {
			snapshot("complete_refused")
			t.Fatal("real Owner completion", err)
		}
		_, card, _ = manual(i, g)
		return card.OwnerControl
	}
	activate := func(i int) e2ee.EndpointGroupOwnerControl { return activateFor(i, group, "until_revoked") }
	observeActive := func(i int, g string) {
		reg, card, source := manual(i, g)
		if source.State != "ACTIVE" {
			t.Fatal("actual ACTIVE observation unavailable")
		}
		if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, reg, card, source); err != nil {
			snapshot("active_read_refused")
			t.Fatal("real ACTIVE observation", err)
		}
	}
	var dHead e2ee.EndpointGroupOwnerControl
	if !withHistory {
		activate(0)
		dHead = activate(1)
	} else {
		// Finite original M1-M4 history only. These real actions are not a
		// repeated fill loop; each corresponds to an adopted Runtime prefix.
		dHead = activate(1)
		observeActive(1, group)
		apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: group, EndpointID: originals[1].Anchor.Registration.EndpointID}, &dHead)
		manual(1, group)
		dHead = activate(1)
		observeActive(1, group)
		for _, i := range []int{0, 2, 3} {
			activate(i)
			observeActive(i, group)
		}
		defaultHead := e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
		apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: domain.Policy.GroupID, EndpointID: originals[1].Anchor.Registration.EndpointID}, &defaultHead)
		manual(1, group)
		apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: domain.Policy.GroupID, EndpointID: originals[1].Anchor.Registration.EndpointID, Duration: "until_revoked"}, nil)
		reg, card, source := manual(1, domain.Policy.GroupID)
		key := fmt.Sprintf("%s.%d.%d", source.AuthorityID, source.AuthorityEpoch, card.RelationRevision)
		prepareStep := fmt.Sprintf("groups.prepare.%s.%d", key, reg.KeyPrepareGenerations[key])
		var prepared wire.EndpointGroupsNodeKeyResult
		request := wire.EndpointGroupsNodeKeyPrepare{PolicyID: source.AuthorityID, PolicyEpoch: source.AuthorityEpoch, EndpointID: reg.Anchor.Registration.EndpointID, GroupID: card.GroupID, ExpectedRelationRevision: card.RelationRevision}
		if err := f.client.callLocalEndpoint(f.ctx, f.token, reg.IntentID, reg.IntentDigest, prepareStep, wire.OperationEndpointGroupsNodeKeyPrepare, request, &prepared); err != nil {
			snapshot("original_prepare_refused")
			t.Fatal(err)
		}
		apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: domain.Policy.GroupID, EndpointID: originals[1].Anchor.Registration.EndpointID}, &card.OwnerControl)
		rejected := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, reg, card, source)
		var refusal *endpointGroupsNodeError
		if !errors.As(rejected, &refusal) || refusal.code != "TARGET_NOT_AUTHORIZED" {
			snapshot("original_rejection_unexpected")
			t.Fatal("original removed Complete did not retain exact refusal", rejected)
		}
		apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: domain.Policy.GroupID, EndpointID: originals[1].Anchor.Registration.EndpointID, Duration: "until_revoked"}, nil)
		reg, card, source = manual(1, domain.Policy.GroupID)
		f.mu.Lock()
		actual := f.handler
		var dropMu sync.Mutex
		dropNext := true
		f.handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/v2/node/control/rpc" {
				raw, err := io.ReadAll(req.Body)
				if err != nil {
					w.WriteHeader(400)
					return
				}
				req.Body = io.NopCloser(bytes.NewReader(raw))
				packet, _ := wire.DecodeEndpointGroupsNodePacket(raw)
				dropMu.Lock()
				drop := dropNext && packet.Route.Operation == wire.OperationEndpointGroupsNodeKeyComplete
				if drop {
					dropNext = false
				}
				dropMu.Unlock()
				if drop {
					recorder := httptest.NewRecorder()
					actual.ServeHTTP(recorder, req)
					if recorder.Code != 200 {
						t.Error("real original Complete failed before response loss")
					}
					w.WriteHeader(503)
					return
				}
			}
			actual.ServeHTTP(w, req)
		})
		f.mu.Unlock()
		lost := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, reg, card, source)
		f.mu.Lock()
		f.handler = actual
		f.mu.Unlock()
		if !machineAPIHasStatus(lost, http.StatusServiceUnavailable) {
			snapshot("real_lost_complete_unexpected")
			t.Fatal("real response loss absent", lost)
		}
		if err := f.client.recoverNodeControlPending(f.ctx, f.token); err != nil {
			snapshot("real_complete_recovery_refused")
			t.Fatal(err)
		}
		_, activeD, _ := manual(1, domain.Policy.GroupID)
		observeActive(1, domain.Policy.GroupID)
		apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: domain.Policy.GroupID, EndpointID: originals[1].Anchor.Registration.EndpointID}, &activeD.OwnerControl)
		manual(1, group)
		activateFor(2, domain.Policy.GroupID, "1d")
		observeActive(2, domain.Policy.GroupID)
		snapshot("FOUR_ORIGINAL_M1_M4_HISTORY_READY")
	}
	// Revoke P0 through the actual Owner API, leaving both independent G2
	// grants active. D's later G2 removal therefore removes its final Group.
	status, err := wire.NewLocalDomainStatus(f.session, f.scope.Actor, domain.Policy.PolicyID, f.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := wire.SealClientRequest(f.device, f.hub, status)
	if err != nil {
		t.Fatal(err)
	}
	raw := f.http(t, http.MethodPost, wire.LocalDomainHTTPPath(wire.OperationLocalDomainStatus), "", "", packet, http.StatusOK)
	var p0 wire.LocalDomainResult
	if wire.OpenLocalDomainResponse(f.device, f.hub, packet, raw, &p0) != nil || wire.ValidateLocalDomainResultTarget(status, packet, p0, f.hub) != nil || p0.Description == nil {
		t.Fatal("fresh original P0 status")
	}
	revoke, err := wire.NewLocalDomainRevoke(f.session, f.scope.Actor, *p0.Description, f.owner, time.Now().UTC())
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
		t.Fatal("real P0 revoke")
	}

	if withHistory {
		// Actual signed Renew creates the same receipt kind as M5, without
		// pretending to have observed its real 301-second cold interval.
		for i := range natives {
			reg, _, err := f.client.endpointGroupsRegistrationCandidate(natives[i], f.workspace)
			if err != nil {
				t.Fatal(err)
			}
			old := sha256.Sum256([]byte(reg.Anchor.LeaseExpiresAt))
			step := fmt.Sprintf("groups.renew.%x", old)
			q := wire.EndpointGroupsNodeRenew{EndpointID: reg.Anchor.Registration.EndpointID, RegistrationDigest: reg.Anchor.RegistrationDigest, ExpectedBindingID: reg.Anchor.BindingID, ExpectedBindingEpoch: reg.Anchor.BindingEpoch}
			var renewed wire.EndpointGroupsNodeRenewResult
			if err := f.client.callLocalEndpoint(f.ctx, f.token, reg.IntentID, reg.IntentDigest, step, wire.OperationEndpointGroupsNodeRenew, q, &renewed); err != nil {
				snapshot("proactive_real_renew_refused")
				t.Fatal("first actual renewal failure", err)
			}
			if _, _, err := f.bridge.describeEndpointGroups(f.ctx, f.client, reg, "", 64); err != nil {
				snapshot("renewed_describe_refused")
				t.Fatal(err)
			}
		}
		unlock()
		f.bridge.renewEndpointGroupsRegistrationBatch(f.ctx)
		lock()
		snapshot("FOUR_ORIGINAL_POST_P0_HISTORY_READY_NO_COLD_CLAIM")
	}
	invocation := 0
	issue := func(i int, tool string, args map[string]any) (localCodexContextIssue, *localCodexContextIssueResult) {
		t.Helper()
		invocation++
		q := localDomainConsumerIssue(t, f, i)
		q.ToolName = tool
		if !strings.HasPrefix(tool, "codex.operator.") {
			q.TurnID = fmt.Sprintf("synthetic-m6-turn-%d", invocation)
			q.ToolUseID = fmt.Sprintf("synthetic-m6-tool-%d", invocation)
		}
		q.ArgumentsDigest, err = codexArgumentsDigest(args)
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		ticket, issueErr := requestMachineAgentCodexContextIssue(f.bridge.path, q)
		class := endpointGroupsRetentionLifecycleErrorEnum(issueErr)
		digest := ""
		if issueErr != nil {
			digest = fmt.Sprintf("%x", sha256.Sum256([]byte(issueErr.Error())))
		}
		t.Logf("CLOSED_M6_PRIVATE_ISSUE role_index=%d invocation=%d tool=%s elapsed_ms=%d error_enum=%s error_type=%T error_sha256=%s", i, invocation, tool, time.Since(started).Milliseconds(), class, issueErr, digest)
		snapshot(fmt.Sprintf("issuer_return_%d", invocation))
		if issueErr != nil || ticket == nil || ticket.Ticket == "" {
			t.Fatal("first private issuer failure", class, digest)
		}
		return q, ticket
	}
	selectGroup := func(i int, stage string) {
		t.Helper()
		snapshot(stage + "_before")
		unlock()
		args := map[string]any{"group_id": group}
		q, ticket := issue(i, "cicada_use_group", args)
		consumed, err := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(q, ticket.Ticket))
		if err != nil {
			t.Fatal("actual one-use consumption", err)
		}
		binding, err := codexContextBinding(consumed.Context)
		if err != nil {
			t.Fatal(err)
		}
		arguments, _ := json.Marshal(args)
		result, err := requestMachineAgentEndpointGroups(context.Background(), f.bridge.path, localEndpointGroupsRequest{Version: localJoinProtocolVersion, Operation: "endpoint_groups_select", APIOrigin: f.server.URL, Harness: "codex", NativeSessionID: natives[i], Workspace: f.workspace, ContextTicketID: strings.Split(ticket.Ticket, ".")[0], ConnectionNonce: q.ConnectionNonce, ToolName: q.ToolName, ArgumentsDigest: q.ArgumentsDigest, Arguments: arguments, GroupID: group, codexEndpointGroupsBinding: binding.codexEndpointGroupsBinding})
		lock()
		snapshot(stage + "_after")
		if err != nil || result == nil || result.Authority.Relation.GroupID != group || result.Authority.Relation.EndpointID != originals[i].Anchor.Registration.EndpointID || result.Card == nil || result.Card.GroupID != group {
			t.Fatal("fresh guarded Group selection failed", err)
		}
	}
	operator := func(operation string) {
		t.Helper()
		unlock()
		args := map[string]any{"operation": operation, "name": "", "pair_label": "", "slot": ""}
		if operation == "endpoint_register" {
			args["name"] = "Synthetic original D retained"
		}
		q, ticket := issue(1, codexOperatorContextTool(operation), args)
		consumed, err := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(q, ticket.Ticket))
		if err != nil {
			t.Fatal(err)
		}
		binding, err := codexContextBinding(consumed.Context)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		id, err := newLocalEndpointRequestID(now)
		if err != nil {
			t.Fatal(err)
		}
		result, err := requestMachineAgentEndpoint(f.bridge.path, localEndpointRequest{Version: localJoinProtocolVersion, Operation: operation, RequestID: id, IssuedAt: now.Format(time.RFC3339Nano), APIOrigin: f.server.URL, Harness: "codex", NativeSessionID: natives[1], Workspace: f.workspace, Name: args["name"].(string), codexEndpointGroupsBinding: binding.codexEndpointGroupsBinding, endpointGroupsOperatorContextProof: endpointGroupsOperatorContextProof{ContextTicketID: strings.Split(ticket.Ticket, ".")[0], ContextConnectionNonce: q.ConnectionNonce}})
		lock()
		if err != nil || result == nil {
			t.Fatal("original D local operator", err)
		}
		if operation == "endpoint_register" && (result.Join != nil || result.Registration.EndpointID != originals[1].Anchor.Registration.EndpointID) {
			t.Fatal("D Join created substitute admission")
		}
	}
	selectGroup(0, "C_BASELINE_G2")
	selectGroup(1, "D_BASELINE_G2")
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: group, EndpointID: originals[1].Anchor.Registration.EndpointID}, &dHead)
	dReg, _, _ := manual(1, group)
	if len(dReg.Authorities) != 0 {
		t.Fatal("D removal did not leave zero Groups")
	}
	selectGroup(0, "C_AFTER_D_LAST_GROUP_REMOVED")
	operator("endpoint_register")
	dReg, _, _ = manual(1, group)
	if len(dReg.Authorities) != 0 {
		t.Fatal("D original Join restored business authority")
	}
	selectGroup(0, "C_AFTER_D_JOIN_ZERO_GROUPS")
	activate(1)
	selectGroup(1, "D_READDED_G2_SELECT")
	if withHistory {
		// One normal ACTIVE observation between the successful D selection and
		// C's next issuer. The old Runtime has a final Prepare in this interval,
		// but its original native mapping was not retained; no attribution to D.
		observeActive(1, group)
		snapshot("ONE_REAL_ACTIVE_OBSERVATION_AFTER_D_SELECT")
	}
	selectGroup(0, "C_AFTER_D_READDED_G2_SELECT")
	if len(continueLifecycle) > 0 && continueLifecycle[0] {
		// Continue past the frozen 04 RED/GREEN boundary through an actual
		// signed Renew and a new exact Owner remove/readd + Prepare/Complete.
		// No elapsed cold lease or full Runtime acceptance is inferred.
		reg, _, err := f.client.endpointGroupsRegistrationCandidate(natives[0], f.workspace)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256([]byte(reg.Anchor.LeaseExpiresAt))
		step := fmt.Sprintf("groups.renew.%x", hash)
		_, existed, err := f.client.localEndpointStep(reg.IntentID, reg.IntentDigest, step)
		if err != nil || existed {
			t.Fatal("continuation Renew must be a fresh original", err)
		}
		request := wire.EndpointGroupsNodeRenew{EndpointID: reg.Anchor.Registration.EndpointID, RegistrationDigest: reg.Anchor.RegistrationDigest, ExpectedBindingID: reg.Anchor.BindingID, ExpectedBindingEpoch: reg.Anchor.BindingEpoch}
		var renewed wire.EndpointGroupsNodeRenewResult
		if err := f.client.callLocalEndpoint(f.ctx, f.token, reg.IntentID, reg.IntentDigest, step, wire.OperationEndpointGroupsNodeRenew, request, &renewed); err != nil || !sameEndpointGroupsAnchor(reg.Anchor, renewed.Registration) {
			snapshot("continuation_renew_refused")
			t.Fatal("post-boundary actual Renew failed", err)
		}
		reg.Anchor = renewed.Registration
		if err := f.client.saveEndpointGroupsRegistration(reg); err != nil {
			t.Fatal(err)
		}
		snapshot("POST_BOUNDARY_ACTUAL_RENEW")
		_, currentD, _ := manual(1, group)
		apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: group, EndpointID: originals[1].Anchor.Registration.EndpointID}, &currentD.OwnerControl)
		removed, _, _ := manual(1, group)
		if len(removed.Authorities) != 0 {
			t.Fatal("post-boundary exact removal kept Group authority")
		}
		activate(1)
		snapshot("POST_BOUNDARY_OWNER_READD_PREPARE_COMPLETE")
		selectGroup(0, "C_AFTER_CONTINUATION_RENEW_AND_D_READD")
	}
	for i, original := range originals {
		reg, _, err := f.client.endpointGroupsRegistrationCandidate(natives[i], f.workspace)
		key, keyErr := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), original.Anchor.Registration.EndpointID)
		if err != nil || keyErr != nil || !sameEndpointGroupsAnchor(reg.Anchor, original.Anchor) || !machineSamePublicIdentity(key.Public(), originalKeys[i]) {
			t.Fatal("original native/key/binding/epoch changed")
		}
	}
	t.Log("CLOSED_M6_SELECTION_CONTROL outcome=NO_REPRO original_C_keeps_G2=true D_last_Group_remove_join_readd_select=true extra_local_leave=false C_following_select=true original_Runtime_cause=NOT_PROVEN Runtime=NOT_RUN capacity_padding=false")
}
