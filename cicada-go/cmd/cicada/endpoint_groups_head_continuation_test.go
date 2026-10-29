package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// One controlled cancellation through real synthetic-native transport. This is
// a production-path diagnostic, not a reproduction of the Runtime's 68 seconds.
func TestEndpointGroupsCanceledCompleteInstallsRecoveredHead(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		name := "before_commit"
		if afterCommit {
			name = "after_commit_response_lost"
		}
		t.Run(name, func(t *testing.T) { testEndpointGroupsRecoveredHead(t, afterCommit) })
	}
}
func testEndpointGroupsRecoveredHead(t *testing.T, afterCommit bool) {
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

	g1 := domain.Policy.GroupID
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: g1, EndpointID: originals[0].Anchor.Registration.EndpointID, Duration: "1d"}, nil)
	r, card, source := manual(0, g1)
	if card.OwnerControl.Mode != "DEFAULT" || source.State != "PENDING_KEY" {
		t.Fatal("finite takeover must retain DEFAULT until Complete")
	}
	// The ordinary background worker remains excluded while phases are driven.
	// All phases still use their production functions, clock and 5s budget.
	started := time.Now()
	observedCtx := f.ctx
	dbURL := url.URL{Scheme: "file", Path: filepath.Join(machineNodeStateDir(f.nodeRoot, f.nodeID), "node-crypto-state.sqlite")}
	db, err := sql.Open("sqlite", dbURL.String()+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	readHead := func(ctx context.Context) (e2ee.EndpointGroupOwnerControl, error) {
		var raw []byte
		var h e2ee.EndpointGroupOwnerControl
		err := db.QueryRowContext(ctx, `SELECT head_json FROM node_endpoint_group_heads_v1 WHERE hub_id=? AND network_id=? AND group_id=? AND endpoint_id=?`, f.hub.HubID, r.Anchor.NetworkID, g1, r.Anchor.Registration.EndpointID).Scan(&raw)
		if err == nil {
			err = json.Unmarshal(raw, &h)
		}
		return h, err
	}
	sampleCtx, stopSampling := context.WithCancel(f.ctx)
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		queries := 0
		var longest time.Duration
		for {
			select {
			case <-sampleCtx.Done():
				t.Logf("CLOSED_HEAD_SAMPLING queries=%d longest_query_ms=%d", queries, longest.Milliseconds())
				return
			default:
			}
			queryCtx, cancel := context.WithTimeout(sampleCtx, 100*time.Millisecond)
			qstart := time.Now()
			head, readErr := readHead(queryCtx)
			cancel()
			elapsed := time.Since(qstart)
			queries++
			if elapsed > longest {
				longest = elapsed
			}
			if readErr == nil && head.Mode == "OWNER" && head.DenyReason == "NONE" {
				t.Logf("CLOSED_HEAD_FIRST_OWNER since_ms=%d query_ms=%d revision=%d epoch=%d", time.Since(started).Milliseconds(), elapsed.Milliseconds(), head.Revision, head.PolicyEpoch)
				return
			}
			select {
			case <-sampleCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { stopSampling(); <-sampled }()
	var transportMu sync.Mutex
	var original, committedResponse []byte
	var attempts, forwarded int
	released := false
	entered := make(chan struct{})
	var once sync.Once
	f.mu.Lock()
	actualHandler := f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/node/control/rpc" {
			raw, err := io.ReadAll(request.Body)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			request.Body = io.NopCloser(bytes.NewReader(raw))
			if packet, err := wire.DecodeEndpointGroupsNodePacket(raw); err == nil && packet.Route.Operation == wire.OperationEndpointGroupsNodeKeyComplete {
				transportMu.Lock()
				attempts++
				if original == nil {
					original = bytes.Clone(raw)
				}
				same := bytes.Equal(original, raw)
				allow := released
				if allow {
					forwarded++
				}
				transportMu.Unlock()
				if !same {
					t.Error("Complete retry replaced original ciphertext")
				}
				once.Do(func() { close(entered) })
				if !allow {
					if afterCommit {
						recorded := httptest.NewRecorder()
						actualHandler.ServeHTTP(recorded, request)
						transportMu.Lock()
						committedResponse = bytes.Clone(recorded.Body.Bytes())
						forwarded++
						transportMu.Unlock()
					}
					<-request.Context().Done()
					return
				}
			}
		}
		actualHandler.ServeHTTP(w, request)
	})
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.handler = actualHandler; f.mu.Unlock() }()
	bounded, cancel := context.WithTimeout(observedCtx, 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- f.bridge.completeEndpointGroupPolicy(bounded, f.client, r, card, source) }()
	select {
	case <-entered:
	case <-bounded.Done():
		t.Fatal("Complete never reached original transport barrier")
	}
	err = <-done
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("original Complete did not exhaust its real budget", err)
	}
	checkpoint("finite_original_canceled")
	transportMu.Lock()
	released = true
	packetHash := sha256.Sum256(original)
	transportMu.Unlock()
	f.client.mu.Lock()
	pendingOriginal := cloneMachineNodeControlState(f.client.state)
	f.client.mu.Unlock()
	reopen := func() {
		machineNodeControlClients.Delete(f.client.statePath)
		var openErr error
		f.client, openErr = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
		if openErr != nil {
			t.Fatal("reopen original protected state", openErr)
		}
	}
	reopen() // response is still lost and the exact original remains pending.
	// Recover the original as one bounded operation; a fresh Describe is separate.
	phaseStart := time.Now()
	bounded, cancel = context.WithTimeout(observedCtx, 5*time.Second)
	err = f.client.recoverNodeControlPending(bounded, f.token)
	cancel()
	if err != nil {
		t.Fatal("original recovery primitive", err)
	}
	t.Logf("CLOSED_HEAD_RECOVER elapsed_ms=%d original_sha256=%x", time.Since(phaseStart).Milliseconds(), packetHash)
	f.client.mu.Lock()
	pending := len(f.client.state.PendingPacket) > 0
	settled := false
	var settledStep machineLocalEndpointStep
	for _, step := range f.client.state.LocalEndpointIntents[r.IntentID].Steps {
		if bytes.Equal(step.RequestPacket, original) {
			settled = step.Settled
			settledStep = step
		}
	}
	f.client.mu.Unlock()
	if pending || !settled {
		t.Fatal("ordinary recovery failed to settle original")
	}
	bounded, cancel = context.WithTimeout(f.ctx, time.Second)
	head, readErr := readHead(bounded)
	cancel()
	missingHead := errors.Is(readErr, sql.ErrNoRows) || readErr == nil && head.Mode == "DEFAULT"
	t.Logf("CLOSED_HEAD_AFTER_GENERIC settled=%t pending=%t owner_head_installed=%t since_ms=%d", settled, pending, !missingHead, time.Since(started).Milliseconds())
	if missingHead {
		t.Fatal("generic recovery returned before installing the original Owner head")
	}
	if readErr != nil && !errors.Is(readErr, sql.ErrNoRows) {
		t.Fatal("head read failed", readErr)
	}
	// A subsequent read has its own unchanged operation budget. This does not
	// extend the completed recovery invocation or its expired context.
	bounded, cancel = context.WithTimeout(f.ctx, 5*time.Second)
	_, _, err = f.bridge.describeEndpointGroups(bounded, f.client, originals[1], "", 64)
	cancel()
	if err != nil {
		t.Fatal("separate other-native read after completed recovery", err)
	}
	if afterCommit && !bytes.Equal(committedResponse, settledStep.ResponsePacket) {
		t.Fatal("committed response was replaced during exact recovery")
	}
	reopen() // installation and outbox cleanup both survive a fresh state handle.
	// Re-enter a real cached response as at a crash before control-state cleanup.
	// Negative cases must not dispatch another RPC or alter the installed head.
	cached := cloneMachineNodeControlState(pendingOriginal)
	cached.PendingResponsePacket = bytes.Clone(settledStep.ResponsePacket)
	restore := func(state machineNodeControlState) {
		f.client.mu.Lock()
		// Restoring the old pending coordinates models cached-response reentry,
		// never a rollback of the writer's already used sequence floor.
		if state.Sequence < f.client.state.Sequence {
			state.Sequence = f.client.state.Sequence
		}
		f.client.state = cloneMachineNodeControlState(state)
		err := f.client.persistLocked()
		f.client.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	f.client.mu.Lock()
	healthy := cloneMachineNodeControlState(f.client.state)
	f.client.mu.Unlock()
	for _, kind := range []string{"unknown_origin", "mixed_origin", "wrong_digest", "wrong_epoch", "missing_challenge", "canceled_context", "expired_grant", "late_canceled_context"} {
		t.Run(kind, func(t *testing.T) {
			broken := cloneMachineNodeControlState(cached)
			switch kind {
			case "unknown_origin":
				broken.PendingLocalEndpointIntentID = "synthetic-unknown-origin"
			case "mixed_origin":
				broken.PendingLocalEndpointIntentID = originals[1].IntentID
			case "wrong_digest":
				reg := broken.EndpointGroupsRegistrations[r.Anchor.RegistrationDigest]
				reg.IntentDigest = "synthetic-wrong-digest"
				broken.EndpointGroupsRegistrations[r.Anchor.RegistrationDigest] = reg
			case "wrong_epoch":
				broken.NodeKeyEpoch++
			case "missing_challenge":
				intent := broken.LocalEndpointIntents[r.IntentID]
				for id, step := range intent.Steps {
					if step.Operation == wire.OperationEndpointGroupsNodeKeyPrepare {
						delete(intent.Steps, id)
					}
				}
				broken.LocalEndpointIntents[r.IntentID] = intent
			}
			restore(broken)
			transportMu.Lock()
			beforeAttempts := attempts
			transportMu.Unlock()
			ctx := f.ctx
			if kind == "canceled_context" {
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			}
			var retryErr error
			if kind == "expired_grant" || kind == "late_canceled_context" {
				// Synthetic verification time only; production always supplies real now.
				f.client.mu.Lock()
				_ = f.client.rememberLocalEndpointReceiptLocked(cached.PendingResponsePacket)
				clock := func() time.Time { return parseMachineNativePairTime(source.ExpiresAt).Add(time.Second) }
				var lateCancel context.CancelFunc
				if kind == "late_canceled_context" {
					ctx, lateCancel = context.WithCancel(ctx)
					defer lateCancel()
					clock = func() time.Time { lateCancel(); return time.Now() }
				}
				retryErr = f.client.installRecoveredEndpointGroupGrantLocked(ctx, clock)
				f.client.mu.Unlock()
				var obsolete *endpointGroupsRecoveredGrantObsolete
				if kind == "late_canceled_context" {
					if !errors.Is(retryErr, context.Canceled) {
						t.Fatal("late cancellation was swallowed", retryErr)
					}
				} else if !errors.As(retryErr, &obsolete) || obsolete.reason != "POLICY_EXPIRED" {
					t.Fatal("expired grant lacked explicit terminal classification", retryErr)
				}
			} else {
				retryErr = f.client.recoverPending(ctx, f.token)
			}
			if retryErr == nil {
				t.Fatal("unsafe cached recovery succeeded")
			}
			f.client.mu.Lock()
			stillPending := bytes.Equal(f.client.state.PendingPacket, cached.PendingPacket)
			f.client.mu.Unlock()
			transportMu.Lock()
			unchangedAttempts := beforeAttempts == attempts
			transportMu.Unlock()
			if !stillPending || !unchangedAttempts {
				t.Fatal("failed local validation lost original or dispatched RPC")
			}
			restore(healthy)
		})
	}
	oldGeneration := cloneMachineNodeControlState(cached)
	oldIntent := oldGeneration.LocalEndpointIntents[r.IntentID]
	for id, step := range oldIntent.Steps {
		if step.Operation == wire.OperationEndpointGroupsNodeKeyPrepare {
			old := step
			old.ResponsePacket = nil
			oldIntent.Steps[id+"_synthetic_retired_generation"] = old
			break
		}
	}
	oldGeneration.LocalEndpointIntents[r.IntentID] = oldIntent
	restore(oldGeneration)
	reopen()
	if err := f.client.recoverNodeControlPending(f.ctx, f.token); err != nil {
		t.Fatal("retired same-request generation blocked exact original", err)
	}
	restore(cached)
	reopen()
	if err := f.client.recoverNodeControlPending(f.ctx, f.token); err != nil {
		t.Fatal("cached response reentry did not install idempotently", err)
	}
	reopen()
	// Do not manually call Remember or completePolicy to fill the gap.
	phaseStart = time.Now()
	unlock()
	f.bridge.renewEndpointGroupsRegistrationBatch(observedCtx)
	lock()
	bounded, cancel = context.WithTimeout(f.ctx, time.Second)
	head, readErr = readHead(bounded)
	cancel()
	t.Logf("CLOSED_HEAD_AFTER_MAINTENANCE elapsed_ms=%d owner_head_installed=%t revision=%d epoch=%d", time.Since(phaseStart).Milliseconds(), readErr == nil && head.Mode == "OWNER", head.Revision, head.PolicyEpoch)
	if readErr != nil || head.Mode != "OWNER" || head.DenyReason != "NONE" {
		t.Fatal("ordinary maintenance failed to persist finite head", readErr)
	}
	transportMu.Lock()
	actualAttempts, actualForwarded := attempts, forwarded
	transportMu.Unlock()
	expectedForwarded := 1
	if afterCommit {
		expectedForwarded = 2
	}
	if actualAttempts != 2 || actualForwarded != expectedForwarded {
		t.Fatal("original was not replayed exactly once", actualAttempts, actualForwarded)
	}
	for i, original := range originals {
		reg, _, err := f.client.endpointGroupsRegistrationCandidate(natives[i], f.workspace)
		key, keyErr := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), original.Anchor.Registration.EndpointID)
		if err != nil || keyErr != nil || !sameEndpointGroupsAnchor(reg.Anchor, original.Anchor) || !machineSamePublicIdentity(key.Public(), originalKeys[i]) {
			t.Fatal("control changed original identity")
		}
	}
	// An independently observed newer deny supersedes this historical success.
	apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: g1, EndpointID: r.Anchor.Registration.EndpointID}, &head)
	_, denied, _ := manual(0, g1)
	if denied.OwnerControl.DenyReason != "REMOVED" {
		t.Fatal("real Owner removal did not advance deny")
	}
	restore(cached)
	reopen()
	err = f.client.recoverNodeControlPending(f.ctx, f.token)
	var obsolete *endpointGroupsRecoveredGrantObsolete
	if !errors.As(err, &obsolete) || obsolete.reason != "SUPERSEDED_HEAD" {
		t.Fatal("newer deny did not explicitly settle obsolete grant", err)
	}
	f.client.mu.Lock()
	pending = len(f.client.state.PendingPacket) > 0
	f.client.mu.Unlock()
	finalHead, err := readHead(f.ctx)
	if err != nil || pending || finalHead != denied.OwnerControl {
		t.Fatal("obsolete recovery stalled outbox or replaced deny", err)
	}
	if _, _, err := f.bridge.describeEndpointGroups(f.ctx, f.client, originals[1], "", 64); err != nil {
		t.Fatal("terminal old grant blocked another original native", err)
	}
	crypto, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.nodeRoot, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	trust, err := crypto.GetNodeOwnerKeyTrustLocal(r.Anchor.Registration.OwnerID, f.owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = crypto.RevokeNodeOwnerKeyTrustLocal(r.Anchor.Registration.OwnerID, f.owner.Public().ID, trust.Version)
	crypto.Close()
	if err != nil {
		t.Fatal(err)
	}
	restore(cached)
	reopen()
	err = f.client.recoverNodeControlPending(f.ctx, f.token)
	if !errors.As(err, &obsolete) || obsolete.reason != "OWNER_PIN_REVOKED" {
		t.Fatal("revoked pin did not explicitly settle obsolete grant", err)
	}
	f.client.mu.Lock()
	pending = len(f.client.state.PendingPacket) > 0
	f.client.mu.Unlock()
	finalHead, err = readHead(f.ctx)
	if err != nil || pending || finalHead != denied.OwnerControl {
		t.Fatal("revoked-pin recovery stalled outbox or replaced deny", err)
	}
	t.Log("CLOSED_HEAD_REGRESSION result=PASS generic_head_before_return=true cached_reentry=true response_loss_restart=true negative_scope=true expired_verification_time=SYNTHETIC revoked_pin_and_newer_deny_preserved=true no_new_rpc=true")
}
