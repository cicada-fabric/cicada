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
	"sync"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type endpointGroupsIssueRecoveryExchange struct {
	original, response []byte
	operation          string
	forwarded          bool
}

type endpointGroupsIssueRecoveryTrace struct {
	mu         sync.Mutex
	exchanges  []endpointGroupsIssueRecoveryExchange
	allowWrite bool
}

func TestEndpointGroupsRegistrationPreservesConfirmedContextCauses(t *testing.T) {
	f, original, _, trace := endpointGroupsIssueRecoveryFixture(t, "none", 0)
	f.client.mu.Lock()
	before, _ := json.Marshal(f.client.state)
	f.client.mu.Unlock()
	for _, kind := range []string{"canceled", "deadline", "shape_with_canceled_context", "shape_with_deadline_context", "coordinates"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			anchor := original.Anchor
			var want error
			switch kind {
			case "canceled":
				cancel()
				want = context.Canceled
			case "deadline":
				ctx, cancel = context.WithDeadline(f.ctx, time.Now().Add(-time.Second))
				defer cancel()
				want = context.DeadlineExceeded
			case "shape_with_canceled_context":
				cancel()
				anchor.Profile = "SYNTHETIC-invalid-profile"
				want = errEndpointGroupsRegistration
			case "shape_with_deadline_context":
				ctx, cancel = context.WithDeadline(f.ctx, time.Now().Add(-time.Second))
				defer cancel()
				anchor.Profile = "SYNTHETIC-invalid-profile"
				want = errEndpointGroupsRegistration
			case "coordinates":
				anchor.NetworkMembershipRevision++
				want = errEndpointGroupsRegistration
			}
			err := f.bridge.validateEndpointGroupsRegistration(ctx, f.client, original, anchor, f.hub)
			if !errors.Is(err, want) || want == errEndpointGroupsRegistration && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				t.Fatal("actual registration verifier lost cause or promoted a permanent Guard refusal", kind)
			}
			started := time.Now()
			d := f.bridge.codexIssueFailureDiagnostic("VERIFICATION", err, started, started.Add(30*time.Second))
			if d.Substage == "" || d.Substage == "UNKNOWN" || d.CauseDeadline == nil || *d.CauseDeadline != (want == context.DeadlineExceeded) {
				t.Fatal("actual verifier did not retain its private failure substage", kind)
			}
		})
	}
	f.client.mu.Lock()
	after, _ := json.Marshal(f.client.state)
	f.client.mu.Unlock()
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if !bytes.Equal(before, after) || len(trace.exchanges) != 0 {
		t.Fatal("registration refusal changed original state or dispatched an RPC")
	}
}

// This fixture uses the actual TCP Hub and owner-only Unix issuer. The worker's
// existing entry lock attributes the controlled fault to this issue, not to an
// unrelated periodic read. No public protocol, native event or timer is changed.
func endpointGroupsIssueRecoveryFixture(t *testing.T, mode string, losses int) (*nativePairTCPConsumerFixture, machineEndpointGroupsRegistration, localCodexContextIssue, *endpointGroupsIssueRecoveryTrace) {
	t.Helper()
	f, original := endpointGroupsOriginalFixture(t)
	q := localDomainConsumerIssue(t, f, 0)
	q.ToolName, q.TurnID, q.ToolUseID = "cicada_reply", "synthetic-original-reply-turn", "synthetic-original-reply-tool"
	var err error
	q.ArgumentsDigest, err = codexArgumentsDigest(map[string]any{"request_id": "synthetic-original-request", "body": "synthetic original reply"})
	if err != nil {
		t.Fatal(err)
	}
	f.bridge.managedLeaseMu.Lock()
	t.Cleanup(func() { f.bridge.managedLeaseMu.Unlock() })
	f.bridge.endpointGroupsMu.Lock()
	trace := &endpointGroupsIssueRecoveryTrace{}
	f.mu.Lock()
	actual := f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/node/control/rpc" {
			actual.ServeHTTP(w, request)
			return
		}
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(raw))
		packet, err := wire.DecodeEndpointGroupsNodePacket(raw)
		if err != nil {
			actual.ServeHTTP(w, request)
			return
		}
		trace.mu.Lock()
		drop := mode == "pending_write" && packet.Route.Operation == wire.OperationEndpointGroupsNodeRenew && !trace.allowWrite
		fault := false
		if packet.Route.Operation == wire.OperationEndpointGroupsNodeDescribe && losses > 0 {
			losses--
			fault = true
		}
		trace.mu.Unlock()
		recorded := httptest.NewRecorder()
		forwarded := !drop && !(fault && mode == "forbidden")
		if forwarded {
			actual.ServeHTTP(recorded, request)
		} else {
			recorded.WriteHeader(http.StatusForbidden)
		}
		response := bytes.Clone(recorded.Body.Bytes())
		if fault && mode == "bad_response" && len(response) > 0 {
			response[len(response)-1] ^= 1
		}
		if fault && mode == "native_changed" {
			// An actual local identity mismatch after the real Hub reply, before
			// final native verification, must not be retried or mint a ticket.
			if err := os.WriteFile(q.TranscriptPath, []byte("{\"type\":\"session_meta\",\"payload\":{\"id\":\"different-synthetic-native\"}}\n"), 0o600); err != nil {
				t.Error("could not create negative native-record fixture")
			}
		}
		trace.mu.Lock()
		trace.exchanges = append(trace.exchanges, endpointGroupsIssueRecoveryExchange{bytes.Clone(raw), response, packet.Route.Operation, forwarded})
		trace.mu.Unlock()
		if drop || fault && mode == "timeout" {
			<-request.Context().Done()
			return
		}
		for key, values := range recorded.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(recorded.Code)
		_, _ = w.Write(response)
	})
	f.mu.Unlock()
	f.bridge.endpointGroupsMu.Unlock()
	return f, original, q, trace
}

func TestEndpointGroupsUnixReplyIssueRecoversWithinOriginalInvocation(t *testing.T) {
	f, original, q, trace := endpointGroupsIssueRecoveryFixture(t, "timeout", 1)
	started := time.Now()
	issued, err := requestMachineAgentCodexContextIssue(f.bridge.path, q)
	if err != nil || issued == nil || issued.Ticket == "" {
		t.Fatal("one recoverable lost Describe response prevented the original Unix issue")
	}
	elapsed := time.Since(started)
	consumed, err := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(q, issued.Ticket))
	if err != nil || consumed.Context.NativeSessionID != q.NativeSessionID || consumed.Context.RegistrationDigest != original.Anchor.RegistrationDigest || consumed.Context.BindingID != original.Anchor.BindingID || consumed.Context.BindingEpoch != original.Anchor.BindingEpoch {
		t.Fatal("single-issue recovery changed original invocation coordinates")
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if len(trace.exchanges) != 3 {
		t.Fatal("single-issue recovery exceeded original/replay/fresh read exchanges")
	}
	a, replay, fresh := trace.exchanges[0], trace.exchanges[1], trace.exchanges[2]
	if !bytes.Equal(a.original, replay.original) || !bytes.Equal(a.response, replay.response) || bytes.Equal(a.original, fresh.original) {
		t.Fatal("single issue changed original bytes or borrowed its historical read as current")
	}
	f.client.mu.Lock()
	historical, historicalErr := f.client.openEndpointGroupsEnvelopeLocked(a.original, a.response)
	current, currentErr := f.client.openEndpointGroupsEnvelopeLocked(fresh.original, fresh.response)
	stillPending := len(f.client.state.PendingPacket) != 0
	f.client.mu.Unlock()
	var d wire.EndpointGroupsNodeDescribeResult
	if historicalErr != nil || currentErr != nil || !historical.OK || !current.OK || json.Unmarshal(current.Result, &d) != nil || wire.ValidateEndpointGroupsNodeDescribeResult(d, f.hub, time.Now().UTC()) != nil || stillPending {
		t.Fatal("single issue did not authenticate the original and independently fresh registration")
	}
	t.Logf("CLOSED_SINGLE_ISSUE_RECOVERY elapsed_ms=%d original_digest=%s exact_request_replay=true exact_response_replay=true independent_fresh_read=true native_reverified=true ticket_consumed=true", elapsed.Milliseconds(), nodewire.RecoveryDigest(a.original))
}

func TestEndpointGroupsUnixIssueDoesNotRetryRefusalsOrChangedIdentity(t *testing.T) {
	for _, mode := range []string{"forbidden", "bad_response", "native_changed"} {
		t.Run(mode, func(t *testing.T) {
			f, _, q, trace := endpointGroupsIssueRecoveryFixture(t, mode, 1)
			if issued, err := requestMachineAgentCodexContextIssue(f.bridge.path, q); err == nil || issued != nil {
				t.Fatal("refused or changed native evidence minted an invocation ticket")
			}
			trace.mu.Lock()
			defer trace.mu.Unlock()
			if len(trace.exchanges) != 1 || trace.exchanges[0].operation != wire.OperationEndpointGroupsNodeDescribe {
				t.Fatal("issuer retried a denial, bad proof or changed identity")
			}
			f.bridge.codexContexts.mu.Lock()
			defer f.bridge.codexContexts.mu.Unlock()
			if len(f.bridge.codexContexts.live) != 0 {
				t.Fatal("failed verification left a live ticket")
			}
		})
	}
}

func TestEndpointGroupsUnixIssueRepeatedReadTimeoutIsBounded(t *testing.T) {
	f, _, q, trace := endpointGroupsIssueRecoveryFixture(t, "timeout", 2)
	started := time.Now()
	if issued, err := requestMachineAgentCodexContextIssue(f.bridge.path, q); err == nil || issued != nil {
		t.Fatal("two lost read responses falsely minted a ticket")
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if len(trace.exchanges) != 2 || !bytes.Equal(trace.exchanges[0].original, trace.exchanges[1].original) {
		t.Fatal("bounded recovery replaced the original or dispatched a third read")
	}
	f.client.mu.Lock()
	defer f.client.mu.Unlock()
	if !bytes.Equal(f.client.state.PendingPacket, trace.exchanges[0].original) || f.client.state.PendingOperation != wire.OperationEndpointGroupsNodeDescribe {
		t.Fatal("bounded failure lost its exact unresolved original")
	}
	t.Logf("CLOSED_BOUNDED_ISSUE_FAILURE attempts=2 elapsed_ms=%d original_retained=true", time.Since(started).Milliseconds())
}

func TestEndpointGroupsUnixIssueDoesNotRecoverPendingWrite(t *testing.T) {
	f, original, q, trace := endpointGroupsIssueRecoveryFixture(t, "pending_write", 0)
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	a := original.Anchor
	request := wire.EndpointGroupsNodeRenew{EndpointID: a.Registration.EndpointID, RegistrationDigest: a.RegistrationDigest, ExpectedBindingID: a.BindingID, ExpectedBindingEpoch: a.BindingEpoch}
	var result wire.EndpointGroupsNodeRenewResult
	if err := f.client.callLocalEndpoint(ctx, f.token, original.IntentID, original.IntentDigest, "synthetic.actual.pending.renew", wire.OperationEndpointGroupsNodeRenew, request, &result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("actual pending-write fixture did not lose its transport response")
	}
	f.client.mu.Lock()
	pending := bytes.Clone(f.client.state.PendingPacket)
	op, seq := f.client.state.PendingOperationID, f.client.state.PendingSequence
	f.client.mu.Unlock()
	if issued, err := requestMachineAgentCodexContextIssue(f.bridge.path, q); err == nil || issued != nil {
		t.Fatal("issuer minted a ticket across another intent's pending write")
	}
	trace.mu.Lock()
	if len(trace.exchanges) != 1 || trace.exchanges[0].operation != wire.OperationEndpointGroupsNodeRenew || trace.exchanges[0].forwarded {
		trace.mu.Unlock()
		t.Fatal("issue dispatched or reconciled the pending write")
	}
	trace.mu.Unlock()
	f.client.mu.Lock()
	if !bytes.Equal(f.client.state.PendingPacket, pending) || f.client.state.PendingOperationID != op || f.client.state.PendingSequence != seq || f.client.state.PendingOperation != wire.OperationEndpointGroupsNodeRenew || f.client.state.EndpointGroupsDiagnostic != nil {
		f.client.mu.Unlock()
		t.Fatal("issue altered the exact pending write or created a detached recovery")
	}
	f.client.mu.Unlock()
	t.Log("CLOSED_PENDING_WRITE_FENCE write_dispatches=1 forwarded_effects=0 issuer_write_replays=0 original_packet_unchanged=true")
	// An explicit existing management recovery retains its original behavior;
	// only issuer verification is prohibited from dispatching this write.
	trace.mu.Lock()
	trace.allowWrite = true
	trace.mu.Unlock()
	if err := f.client.recoverNodeControlPending(f.ctx, f.token); err != nil {
		t.Fatal("explicit original write recovery was changed by the issuer fence", err)
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if len(trace.exchanges) != 2 || !trace.exchanges[1].forwarded || !bytes.Equal(trace.exchanges[1].original, pending) {
		t.Fatal("explicit write recovery replaced the original or repeated its effect")
	}
}

func TestEndpointGroupsIssueExpiredBudgetDoesNotMint(t *testing.T) {
	f, _, q, trace := endpointGroupsIssueRecoveryFixture(t, "none", 0)
	q.verifyDeadline = time.Now().Add(-time.Second)
	if issued, err := f.bridge.codexContextIssue(q); !errors.Is(err, context.DeadlineExceeded) || issued != nil {
		t.Fatal("expired original verification budget minted a ticket")
	}
	encoded, err := json.Marshal(q)
	if err != nil || bytes.Contains(encoded, []byte("verifyDeadline")) {
		t.Fatal("private accepted deadline entered the request protocol")
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if len(trace.exchanges) != 0 {
		t.Fatal("expired original budget dispatched a read")
	}
}

func TestEndpointGroupsIssueMutexWaitConsumesOriginalBudget(t *testing.T) {
	f, _, q, trace := endpointGroupsIssueRecoveryFixture(t, "none", 0)
	f.bridge.endpointGroupsMu.Lock()
	q.verifyDeadline = time.Now().Add(100 * time.Millisecond)
	result := make(chan error, 1)
	go func() {
		issued, err := f.bridge.codexContextIssue(q)
		if issued != nil {
			result <- errors.New("ticket minted after the accepted verification budget")
			return
		}
		result <- err
	}()
	<-time.After(time.Until(q.verifyDeadline) + 10*time.Millisecond)
	f.bridge.endpointGroupsMu.Unlock()
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("mutex wait reset the original verification budget")
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if len(trace.exchanges) != 0 {
		t.Fatal("expired mutex waiter dispatched a read")
	}
}
