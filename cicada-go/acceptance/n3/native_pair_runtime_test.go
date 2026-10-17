package n3_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// The new pair protocol is exercised by an independent PQ caller. Only the
// preceding N2/N3 setup uses the production App Controller. These tests neither
// accept the production App's pair UI nor create real Codex Threads/model turns.
type nativePairActor struct {
	*authorityWireActor
	scope e2ee.OwnerNativePairScope
}

func newNativePairActor(t *testing.T) *nativePairActor {
	t.Helper()
	f := newNodeHubFixture(t)
	marker := filepath.Join(f.dir, "pair-original-app.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	node := startNodeProcess(t, f, "synthetic-n3-native-pair")
	pending := node.awaitState(t, f, false)
	node.kill(t)
	preview := commandApp(t, f, app, 1, appActorCommand{Action: &appcore.Action{
		Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode}})
	if preview.ActionFailed || preview.Current.Node.Candidate == nil {
		t.Fatal("production App could not preview the owned original Node")
	}
	approved := commandApp(t, f, app, 2, appActorCommand{Action: &appcore.Action{
		Kind: appcore.ActionApproveNode, NodeReviewID: preview.Current.Node.Candidate.ReviewID,
		ConfirmNodeIdentity: true, ConfirmNodeAccess: true}})
	if approved.ActionFailed || approved.Current.Node.Binding == nil || !approved.Current.Node.Access.Confirmed {
		t.Fatal("production App could not approve the original exact Node")
	}
	app.kill(t)
	account := ownedAccountSession(t, f)
	a := &nativePairActor{authorityWireActor: &authorityWireActor{f: f,
		device: ownedAppIdentity(t, f, appvault.PurposeAppDevice), owner: ownedAppIdentity(t, f, appvault.PurposeOwnerSigner)}}
	a.session = wire.AppNodeSession{Hub: f.cfg.Hub, Origin: f.cfg.Origin, AccountID: account.AccountID,
		OwnerID: account.OwnerID, DeviceID: account.DeviceID, AccountEpoch: account.AccountEpoch,
		DeviceEpoch: account.DeviceEpoch, Token: account.SessionToken}
	q := must(wire.NewAppNodeStatus(a.session, "", time.Now().UTC()))
	_, current := a.authorityWireActor.call(t, wire.OperationAppNodeStatus, q)
	if current.Result == nil || current.Result.Authority.RootState != wire.RootActiveState || current.Result.Authority.LoginRequired {
		t.Fatal("pair fixture lacks actual current ACTIVE Owner/account provenance")
	}
	a.scope.Actor = current.Result.Authority.Scope
	a.scope.Actor.HeadVersion = 0 // Separate authority domain; never borrow N3 head.
	vault := ownedAppVault(t, f)
	raw, _, found, err := vault.LoadState("appcore.node-confirmation.v1")
	if vault.Close() != nil || err != nil || !found {
		t.Fatal("original App lacks its durable Node confirmation")
	}
	defer clear(raw)
	var record struct {
		Binding   e2ee.OwnerAppNodeBinding `json:"binding"`
		Operation struct {
			Request  []byte                        `json:"request"`
			Response []byte                        `json:"response"`
			Expected uint64                        `json:"expected_response_sequence"`
			Claims   *e2ee.OwnerAppNodeGrantClaims `json:"grant_claims"`
		} `json:"operation"`
	}
	if json.Unmarshal(raw, &record) != nil || record.Operation.Claims == nil {
		t.Fatal("original App confirmation record is invalid")
	}
	confirmed := must(wire.OpenAppNodeConfirmationResponse(a.device, f.cfg.Hub, *record.Operation.Claims,
		record.Operation.Request, record.Operation.Response, record.Operation.Expected))
	if !confirmed.OK || confirmed.Binding == nil || !reflect.DeepEqual(*confirmed.Binding, record.Binding) {
		t.Fatal("original Node binding is not the pinned authenticated actual confirmation")
	}
	a.scope.Node = record.Binding
	if wire.ValidateNativePairBootstrapPreviewScope(a.scope, f.cfg.Hub) != nil {
		t.Fatal("actual N2/N3 tuple cannot form the frozen bootstrap preview scope")
	}
	node = startNodeProcess(t, f, node.id)
	bound := node.awaitState(t, f, true)
	if bound.NodeID != a.scope.Node.NodeID || bound.NodeFingerprint != a.scope.Node.NodeKeyFingerprint {
		t.Fatal("actual Node restart replaced the approved original identity")
	}
	t.Log("NATIVE_PAIR_PRECONDITION production_App_N2_N3=true ACTIVE_Owner=true single_Node=true DB_grant_injection=false Control_inference=false")
	a.requireDiscovery(t)
	return a
}

func (a *nativePairActor) requireDiscovery(t *testing.T) {
	t.Helper()
	before := len(a.f.proxy.snapshot())
	response := must(a.f.proxy.client.Get(a.f.proxy.server.URL + wire.NativePairCapabilitiesPath))
	raw := must(io.ReadAll(io.LimitReader(response.Body, 16*1024+1)))
	response.Body.Close()
	defer clear(raw)
	var caps wire.NativePairCapabilities
	if response.StatusCode != 200 || len(raw) > 16*1024 || json.Unmarshal(raw, &caps) != nil ||
		!caps.Available || caps.ContractRevision != wire.NativePairContractRevision ||
		caps.PeerTransport != "SEALED_RELAY" || caps.Policy != e2ee.NativePairFixedPeerPolicy() {
		// Discovery is public availability only. Never bypass an unavailable or
		// unknown profile by sending a new secret request to its guessed route.
		for _, ex := range a.f.proxy.snapshot()[before:] {
			if ex.Path != wire.NativePairCapabilitiesPath {
				t.Fatal("unsupported discovery caused a secret POST")
			}
		}
		t.Fatalf("NATIVE_PAIR_UNAVAILABLE HTTP=%d new_pair_secret_posts=0 (failure, not acceptance)", response.StatusCode)
	}
}

func pairContext(scope e2ee.OwnerNativePairScope) wire.NativePairRequestContext {
	a := scope.Actor
	return wire.NativePairRequestContext{Origin: a.Origin, HubID: a.HubID, AccountID: a.AccountID,
		OwnerID: a.OwnerID, DeviceID: a.DeviceID, AccountSessionID: a.AccountSessionID,
		AccountEpoch: a.AccountEpoch, DeviceEpoch: a.DeviceEpoch, ClientSessionEpoch: a.ClientSessionEpoch,
		RequestID: must(wire.NewRequestID()), ClientNonce: must(wire.NewNonce()), IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
}

func pairClaims(scope e2ee.OwnerNativePairScope, purpose string) (wire.NativePairRequestContext, e2ee.OwnerNativePairClaims) {
	c := pairContext(scope)
	issued := must(time.Parse(time.RFC3339Nano, c.IssuedAt))
	end := issued.Add(time.Minute)
	sessionEnd := must(time.Parse(time.RFC3339Nano, scope.Actor.AccountSessionExpiresAt))
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	return c, e2ee.OwnerNativePairClaims{Version: 1, Purpose: purpose, Scope: scope, RequestID: c.RequestID,
		Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt, ExpiresAt: end.Format(time.RFC3339Nano)}
}

func (a *nativePairActor) preview(t *testing.T, scope e2ee.OwnerNativePairScope) wire.NativePairBootstrapPrepare {
	t.Helper()
	ctx, claims := pairClaims(scope, e2ee.OwnerNativePairBootstrapPreview)
	claims.Bootstrap = &e2ee.NativePairBootstrapClaims{GroupLabel: "Synthetic QA pair ONLY", Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy()}
	return wire.NativePairBootstrapPrepare{Format: wire.NativePairFormat, Context: ctx,
		SessionToken: a.session.Token, OwnerProof: must(e2ee.SignOwnerNativePair(a.owner, claims))}
}

func (a *nativePairActor) seal(t *testing.T, body any) []byte {
	t.Helper()
	packet := must(wire.SealClientRequest(a.device, a.f.cfg.Hub, body))
	p := must(wire.DecodeNativePairPacket(packet))
	atomicPrivate(t, filepath.Join(a.f.dir, "pair-original-"+p.Packet.Route.OperationID+".packet"), packet)
	return packet
}

// Exactly one HTTP attempt: fault/recovery tests must observe transport loss,
// not hide it behind a retry helper. Metrics include actual envelope bytes.
func (a *nativePairActor) send(t *testing.T, operation string, packet []byte) (int, []byte, error) {
	t.Helper()
	request := must(http.NewRequest(http.MethodPost, a.f.proxy.server.URL+wire.NativePairHTTPPath(operation), bytes.NewReader(packet)))
	request.Header.Set("Origin", a.f.cfg.Origin)
	request.Header.Set("Content-Type", "application/json")
	start := time.Now()
	response, err := a.f.proxy.client.Do(request)
	status, raw := 0, []byte(nil)
	if err == nil {
		status = response.StatusCode
		raw, err = io.ReadAll(io.LimitReader(response.Body, wire.MaxNativePairReconcilePacketBytes+1))
		response.Body.Close()
		if len(raw) > wire.MaxNativePairReconcilePacketBytes {
			t.Fatal("pair response exceeds frozen maximum")
		}
	}
	t.Logf("NATIVE_PAIR_HTTP operation=%s request_bytes=%d response_bytes=%d elapsed_us=%d status=%d transport_error=%t request_sha256=%s response_sha256=%s",
		operation, len(packet), len(raw), time.Since(start).Microseconds(), status, err != nil, hash(packet), hash(raw))
	return status, raw, err
}

func (a *nativePairActor) call(t *testing.T, op string, packet []byte, out any) []byte {
	t.Helper()
	status, raw, err := a.send(t, op, packet)
	if err != nil || status != 200 {
		t.Fatalf("actual pair operation failed: operation=%s HTTP=%d transport_error=%t", op, status, err != nil)
	}
	if wire.OpenClientResponse(a.device, a.f.cfg.Hub, packet, raw, out) != nil {
		t.Fatal("pair response failed pinned PQ/original-route authentication")
	}
	p := must(wire.DecodeNativePairPacket(packet))
	atomicPrivate(t, filepath.Join(a.f.dir, "pair-response-"+p.Packet.Route.OperationID+".packet"), raw)
	return raw
}

func (a *nativePairActor) prepare(t *testing.T) (wire.NativePairBootstrapPrepare, []byte, wire.NativePairBootstrapChallenge, []byte) {
	t.Helper()
	q := a.preview(t, a.scope)
	packet := a.seal(t, q)
	var challenge wire.NativePairBootstrapChallenge
	response := a.call(t, wire.OperationNativePairBootstrapPrepare, packet, &challenge)
	if wire.ValidateNativePairBootstrapTarget(q, packet, challenge, a.f.cfg.Hub, time.Now().UTC()) != nil {
		t.Fatal("Hub prepare changed the signed actual Owner/App/Node bootstrap target")
	}
	return q, packet, challenge, response
}

func (a *nativePairActor) completion(t *testing.T, ch wire.NativePairBootstrapChallenge) []byte {
	t.Helper()
	ctx, claims := pairClaims(ch.Scope, e2ee.OwnerNativePairBootstrapCommit)
	claims.Bootstrap = &ch.Bootstrap
	return a.seal(t, wire.NativePairBootstrapComplete{Format: wire.NativePairFormat, Context: ctx,
		SessionToken: a.session.Token, OwnerProof: must(e2ee.SignOwnerNativePair(a.owner, claims))})
}

func assertEmptyPair(t *testing.T, r wire.NativePairResult, pairID string) {
	t.Helper()
	if r.PairID != pairID || r.Outcome != "COMPLETED" || r.State != wire.NativePairWaitingJoin ||
		r.ControlRevision == 0 || r.SlotA != nil || r.SlotB != nil || r.SlotAState != wire.NativePairSlotReserved ||
		r.SlotBState != wire.NativePairSlotReserved || r.Budget != (wire.NativePairBudgetObservation{}) {
		t.Fatal("empty-slot bootstrap fabricated SID/peer permission, consumed budget, or changed target")
	}
}

func (a *nativePairActor) reconcile(t *testing.T, pairID string, original []byte) wire.NativePairReconciled {
	t.Helper()
	q := wire.NativePairReconcileRequest{Format: wire.NativePairFormat, Context: pairContext(a.scope), PairID: pairID, OriginalPacket: original}
	packet := a.seal(t, q)
	var result wire.NativePairReconciled
	a.call(t, wire.OperationNativePairReconcile, packet, &result)
	if wire.ValidateNativePairReconcileTarget(result, pairID, original) != nil {
		t.Fatal("reconcile substituted original packet/route/pair")
	}
	return result
}

func TestN3NativePairBootstrapAndExactReplay(t *testing.T) {
	a := newNativePairActor(t)
	_, prepare, ch, prepareResponse := a.prepare(t)
	complete := a.completion(t, ch)
	var result wire.NativePairResult
	response := a.call(t, wire.OperationNativePairBootstrapComplete, complete, &result)
	assertEmptyPair(t, result, ch.Bootstrap.PairID)
	a.f.hub.kill(t)
	a.f.start(t)
	var repeatedCh wire.NativePairBootstrapChallenge
	if got := a.call(t, wire.OperationNativePairBootstrapPrepare, prepare, &repeatedCh); !bytes.Equal(got, prepareResponse) {
		t.Fatal("prepare exact receipt changed across actual Hub restart")
	}
	var repeated wire.NativePairResult
	if got := a.call(t, wire.OperationNativePairBootstrapComplete, complete, &repeated); !bytes.Equal(got, response) || !reflect.DeepEqual(result, repeated) {
		t.Fatal("bootstrap exact receipt changed across actual Hub restart")
	}
	t.Log("NATIVE_PAIR_SCOPE bootstrap_exact_replay_only=true zero_slots=true real_native_Join_NOT_RUN=true dual_consent_NOT_RUN=true real_Codex_NOT_RUN=true")
}

func TestN3NativePairWrongNodeScopeIsFenced(t *testing.T) {
	a := newNativePairActor(t)
	wrong := a.scope
	wrong.Node.NodeID = "synthetic-n3-other-node"
	q := a.preview(t, wrong) // Genuine original Owner signature, valid wire shape.
	packet := a.seal(t, q)
	var fence wire.NativePairBootstrapFence
	response := a.call(t, wire.OperationNativePairBootstrapPrepare, packet, &fence)
	if !fence.NoEffect || fence.State != "REJECTED_FENCED" || fence.RequestPacketDigest != wire.NativePairPacketDigest(packet) {
		t.Fatal("wrong current Node tuple was admitted or lacked permanent no-effect fence")
	}
	a.f.hub.kill(t)
	a.f.start(t)
	var repeated wire.NativePairBootstrapFence
	if got := a.call(t, wire.OperationNativePairBootstrapPrepare, packet, &repeated); !bytes.Equal(response, got) {
		t.Fatal("wrong-scope fence was not durable")
	}
	// A valid original must still be able to bootstrap: no hidden reservation
	// from the rejected request may block its one-nonterminal-pair guard.
	_, _, ch, _ := a.prepare(t)
	var result wire.NativePairResult
	a.call(t, wire.OperationNativePairBootstrapComplete, a.completion(t, ch), &result)
	assertEmptyPair(t, result, ch.Bootstrap.PairID)
}

func TestN3NativePairPrepareLossBeforeForward(t *testing.T) {
	a := newNativePairActor(t)
	q := a.preview(t, a.scope)
	packet := a.seal(t, q)
	a.f.proxy.arm(wire.NativePairHTTPPath(wire.OperationNativePairBootstrapPrepare), "before-forward", 1)
	_, raw, err := a.send(t, wire.OperationNativePairBootstrapPrepare, packet)
	clear(raw)
	if err == nil {
		t.Fatal("before-forward fault did not lose actual TCP response")
	}
	a.f.hub.kill(t)
	a.f.start(t)
	recovered := a.reconcile(t, "", packet) // No PairID was assigned/observed.
	var fence wire.NativePairBootstrapFence
	if recovered.State != "REJECTED_FENCED" || recovered.PairID != "" ||
		wire.OpenClientResponse(a.device, a.f.cfg.Hub, packet, recovered.ReceiptPacket, &fence) != nil ||
		!fence.NoEffect || fence.RequestPacketDigest != wire.NativePairPacketDigest(packet) {
		t.Fatal("unadmitted unknown-pair original was not durably no-effect fenced")
	}
	var late wire.NativePairBootstrapFence
	if response := a.call(t, wire.OperationNativePairBootstrapPrepare, packet, &late); !bytes.Equal(response, recovered.ReceiptPacket) {
		t.Fatal("late original executed after permanent reconciliation fence")
	}
}

func TestN3NativePairCompleteLossAfterCommit(t *testing.T) {
	a := newNativePairActor(t)
	_, _, ch, _ := a.prepare(t)
	packet := a.completion(t, ch)
	a.f.proxy.arm(wire.NativePairHTTPPath(wire.OperationNativePairBootstrapComplete), "drop-after-response", 1)
	_, raw, err := a.send(t, wire.OperationNativePairBootstrapComplete, packet)
	clear(raw)
	if err == nil {
		t.Fatal("after-response fault did not lose actual TCP response")
	}
	trace := a.f.proxy.snapshot()
	committed := trace[len(trace)-1]
	if !committed.Forwarded || committed.Status != 200 {
		t.Fatal("fault did not occur after a successful actual Hub response")
	}
	a.f.hub.kill(t)
	a.f.start(t)
	recovered := a.reconcile(t, ch.Bootstrap.PairID, packet)
	var result wire.NativePairResult
	if recovered.State != "COMPLETED" || !bytes.Equal(recovered.ReceiptPacket, committed.response) ||
		wire.OpenClientResponse(a.device, a.f.cfg.Hub, packet, recovered.ReceiptPacket, &result) != nil {
		t.Fatal("committed original receipt was not recovered exactly after Hub restart")
	}
	assertEmptyPair(t, result, ch.Bootstrap.PairID)
	var repeated wire.NativePairResult
	if got := a.call(t, wire.OperationNativePairBootstrapComplete, packet, &repeated); !bytes.Equal(got, recovered.ReceiptPacket) {
		t.Fatal("exact retry created a second effect after recovery")
	}
}

func TestN3NativePairMissingOwnerProofCannotBootstrap(t *testing.T) {
	a := newNativePairActor(t)
	q := a.preview(t, a.scope)
	q.OwnerProof = nil
	// Bypass only typed outgoing validation. The production Hub still receives
	// a real App-signed PQ envelope; local constructor refusal is insufficient.
	binding, route, err := wire.RequestRoute(a.f.cfg.Hub, q.Context.OwnerID, q.Context.DeviceID,
		q.Context.RequestID, wire.OperationNativePairBootstrapPrepare, wire.HandshakeEpoch, a.device.Public())
	if err != nil {
		t.Fatal("cannot form frozen adversarial pair route")
	}
	plain := must(json.Marshal(q))
	defer clear(plain)
	inner := must(clientwire.SealRequestWithLimits(a.device, a.f.cfg.Hub.Public, binding, route, plain,
		wire.MaxNativePairBodyBytes, wire.MaxNativePairInnerPacketBytes))
	defer clear(inner)
	var encrypted clientwire.Packet
	if json.Unmarshal(inner, &encrypted) != nil {
		t.Fatal("invalid adversarial PQ frame")
	}
	packet := must(json.Marshal(wire.Packet{Format: wire.PacketFormat, Version: wire.PacketVersion, SenderPublicIdentity: a.device.Public(), Packet: encrypted}))
	atomicPrivate(t, filepath.Join(a.f.dir, "pair-invalid-original.packet"), packet)
	status, raw, err := a.send(t, wire.OperationNativePairBootstrapPrepare, packet)
	defer clear(raw)
	if err != nil {
		t.Fatal("proof absence was hidden by transport failure")
	}
	if status == 200 {
		var fence wire.NativePairBootstrapFence
		if wire.OpenClientResponse(a.device, a.f.cfg.Hub, packet, raw, &fence) != nil || !fence.NoEffect || fence.State != "REJECTED_FENCED" {
			t.Fatal("missing proof was accepted without authenticated no-effect fence")
		}
	} else if status != 400 && status != 401 && status != 403 {
		t.Fatalf("missing-proof rejection unavailable: HTTP=%d", status)
	}
	_, _, ch, _ := a.prepare(t)
	var result wire.NativePairResult
	a.call(t, wire.OperationNativePairBootstrapComplete, a.completion(t, ch), &result)
	assertEmptyPair(t, result, ch.Bootstrap.PairID)
}
