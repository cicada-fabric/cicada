package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// A real proactive signed Renew followed by normal production recovery,
// Describe and warm heartbeat. This is not an elapsed cold-lease or Runtime
// reproduction; no clock, SQL lease, identity or authority is manufactured.
func TestEndpointGroupsRenewRecoveryAllowsLaterHeartbeatLease(t *testing.T) {
	f, r := endpointGroupsOriginalFixture(t)
	f.bridge.endpointGroupsMu.Lock()
	defer f.bridge.endpointGroupsMu.Unlock()
	bounded := func() (context.Context, context.CancelFunc) { return context.WithTimeout(f.ctx, 5*time.Second) }
	ctx, cancel := bounded()
	var err error
	r, _, err = f.bridge.describeEndpointGroups(ctx, f.client, r, "", 64)
	cancel()
	if err != nil {
		t.Fatal("real original registration Describe", err)
	}
	before := r.Anchor
	nodeBefore := f.client.publicIdentity()
	immutable := func(a wire.EndpointGroupsRegistrationAnchor) wire.EndpointGroupsRegistrationAnchor {
		a.LeaseExpiresAt = ""
		return a
	}
	hash := func(v any) string { raw, _ := json.Marshal(v); h := sha256.Sum256(raw); return fmt.Sprintf("%x", h) }
	logAnchor := func(phase string, a wire.EndpointGroupsRegistrationAnchor) {
		t.Helper()
		t.Logf("CLOSED_RENEW_PROGRESS phase=%s lease_expires_at=%s immutable_sha256=%s immutable_equal=%t state=%s", phase, a.LeaseExpiresAt, hash(immutable(a)), reflect.DeepEqual(immutable(before), immutable(a)), a.State)
	}
	logAnchor("BEFORE_ACTIVE_RENEW", before)
	var transportMu sync.Mutex
	var original, committedResponse []byte
	renewAttempts := 0
	dropNext := true
	f.mu.Lock()
	actualHandler := f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/node/control/rpc" {
			actualHandler.ServeHTTP(w, request)
			return
		}
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(raw))
		packet, packetErr := wire.DecodeEndpointGroupsNodePacket(raw)
		if packetErr == nil && packet.Route.Operation == wire.OperationEndpointGroupsNodeRenew {
			transportMu.Lock()
			renewAttempts++
			drop := dropNext
			dropNext = false
			if original == nil {
				original = bytes.Clone(raw)
			}
			same := bytes.Equal(original, raw)
			transportMu.Unlock()
			if !same {
				t.Error("recovery replaced the signed Renew original")
			}
			if drop {
				recorder := httptest.NewRecorder()
				actualHandler.ServeHTTP(recorder, request)
				if recorder.Code != http.StatusOK {
					t.Error("proactive real Renew did not commit", recorder.Code)
				}
				transportMu.Lock()
				committedResponse = bytes.Clone(recorder.Body.Bytes())
				transportMu.Unlock()
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		actualHandler.ServeHTTP(w, request)
	})
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.handler = actualHandler; f.mu.Unlock() }()
	stepHash := sha256.Sum256([]byte(before.LeaseExpiresAt))
	stepName := fmt.Sprintf("groups.renew.%x", stepHash)
	q := wire.EndpointGroupsNodeRenew{EndpointID: before.Registration.EndpointID, RegistrationDigest: before.RegistrationDigest, ExpectedBindingID: before.BindingID, ExpectedBindingEpoch: before.BindingEpoch}
	ctx, cancel = bounded()
	var lost wire.EndpointGroupsNodeRenewResult
	err = f.client.callLocalEndpoint(ctx, f.token, r.IntentID, r.IntentDigest, stepName, wire.OperationEndpointGroupsNodeRenew, q, &lost)
	cancel()
	if !machineAPIHasStatus(err, http.StatusServiceUnavailable) {
		t.Fatal("response loss did not retain the real original", err)
	}
	transportMu.Lock()
	packet, response := bytes.Clone(original), bytes.Clone(committedResponse)
	transportMu.Unlock()
	f.client.mu.Lock()
	envelope, openErr := f.client.openEndpointGroupsEnvelopeLocked(packet, response)
	pendingBefore := bytes.Equal(f.client.state.PendingPacket, packet)
	f.client.mu.Unlock()
	var renewed wire.EndpointGroupsNodeRenewResult
	if openErr != nil || !envelope.OK || decodeStrictBridgeJSON(envelope.Result, &renewed) != nil || renewed.ContractRevision != wire.OwnerEndpointGroupsContractRevision || !reflect.DeepEqual(immutable(before), immutable(renewed.Registration)) {
		t.Fatal("actual lost Renew response did not authenticate for the original")
	}
	if !pendingBefore || !parseMachineNativePairTime(renewed.Registration.LeaseExpiresAt).After(parseMachineNativePairTime(before.LeaseExpiresAt)) {
		t.Fatal("proactive original failed to extend its real lease")
	}
	ctx, cancel = bounded()
	err = f.bridge.validateEndpointGroupsRegistration(ctx, f.client, r, renewed.Registration, f.hub)
	cancel()
	if err != nil {
		t.Fatal("renewed original registration validation", err)
	}
	logAnchor("AUTHENTICATED_ORIGINAL_RESPONSE", renewed.Registration)
	ctx, cancel = bounded()
	err = f.client.recoverNodeControlPending(ctx, f.token)
	cancel()
	if err != nil {
		t.Fatal("generic original Renew recovery", err)
	}
	settled, ok, err := f.client.localEndpointStep(r.IntentID, r.IntentDigest, stepName)
	f.client.mu.Lock()
	empty := endpointGroupsRetentionIdle(f.client.state)
	f.client.mu.Unlock()
	if err != nil || !ok || !settled.Settled || !empty || !bytes.Equal(settled.RequestPacket, packet) || !bytes.Equal(settled.ResponsePacket, response) {
		t.Fatal("generic recovery lost the original exact receipt or kept pending")
	}
	current, _, err := f.client.endpointGroupsRegistrationCandidate(before.Registration.NativeSessionID, before.Registration.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	logAnchor("LOCAL_AFTER_GENERIC_RECOVERY", current.Anchor)
	ctx, cancel = bounded()
	r, _, err = f.bridge.describeEndpointGroups(ctx, f.client, current, "", 64)
	cancel()
	if err != nil {
		t.Fatal("normal Describe after recovered Renew", err)
	}
	saved, _, err := f.client.endpointGroupsRegistrationCandidate(before.Registration.NativeSessionID, before.Registration.Workspace)
	if err != nil || !reflect.DeepEqual(saved.Anchor, r.Anchor) || parseMachineNativePairTime(saved.Anchor.LeaseExpiresAt).Before(parseMachineNativePairTime(renewed.Registration.LeaseExpiresAt)) {
		t.Fatal("normal Describe failed to save the already renewed original anchor", err)
	}
	logAnchor("LOCAL_AFTER_NORMAL_DESCRIBE", saved.Anchor)
	ctx, cancel = bounded()
	r, err = f.bridge.renewEndpointGroupsRegistration(ctx, f.client, saved)
	cancel()
	if err != nil {
		t.Fatal("normal warm registration heartbeat", err)
	}
	final, _, err := f.client.endpointGroupsRegistrationCandidate(before.Registration.NativeSessionID, before.Registration.Workspace)
	if err != nil || !reflect.DeepEqual(final.Anchor, r.Anchor) || !reflect.DeepEqual(immutable(before), immutable(final.Anchor)) || !machineSamePublicIdentity(nodeBefore, f.client.publicIdentity()) {
		t.Fatal("normal heartbeat changed original identity or failed to save", err)
	}
	logAnchor("LOCAL_AFTER_NORMAL_HEARTBEAT", final.Anchor)
	if !parseMachineNativePairTime(final.Anchor.LeaseExpiresAt).After(parseMachineNativePairTime(renewed.Registration.LeaseExpiresAt)) {
		t.Fatal("normal heartbeat did not advance beyond the original Renew result")
	}
	transportMu.Lock()
	attempts := renewAttempts
	transportMu.Unlock()
	if attempts != 2 {
		t.Fatal("control dispatched a replacement Renew", attempts)
	}
	requestHash, responseHash := sha256.Sum256(packet), sha256.Sum256(response)
	t.Logf("CLOSED_RENEW_PROGRESS_RESULT original_request_sha256=%x original_response_sha256=%x exact_original_attempts=%d settled=true pending_empty=true old_exact_expiry_equal=false immutable_equal=true later_local_lease=true proactive_live_renew=true elapsed_cold_lease=NOT_RUN Runtime_hXlWlN_cause=NOT_PROVEN", requestHash, responseHash, attempts)
}
