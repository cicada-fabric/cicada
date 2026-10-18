package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

// These opt-in overlay cases are PREPARED, not accepted until a separately
// frozen A3 producer and Root-authorized gate execute them. They use actual
// API transitions; no SQL update creates ACTIVE or grants a permission.
func TestQANativePairA3FirstConsentZeroSecondUsesOriginalGrants(t *testing.T) {
	a := qaA3Setup(t)
	var first wire.NativePairResult
	packet, receipt := a.call(t, wire.OperationNativePairConsentComplete, a.consent(t, 0), &first)
	if first.State != wire.NativePairWaitingConsent || first.SlotAState != wire.NativePairSlotConsentRecorded ||
		first.SlotBState != wire.NativePairSlotCandidateReady || first.ControlRevision != a.plan.Plan.ExpectedRevision {
		t.Fatal("first consent changed the immutable plan revision or fabricated activation")
	}
	a.assertZero(t)
	replayed, err := a.sendPacket(t, a.f.http.URL, wire.OperationNativePairConsentComplete, packet)
	if err != nil || !bytes.Equal(replayed, receipt) {
		t.Fatal("first consent exact retry did not recover its original receipt")
	}
	a.assertZero(t)
	var active wire.NativePairResult
	a.call(t, wire.OperationNativePairConsentComplete, a.consent(t, 1), &active)
	a.assertActive(t, active)
	if active.ControlRevision != first.ControlRevision+1 || active.Budget != (wire.NativePairBudgetObservation{}) {
		t.Fatal("second consent activated more than once or charged message budget")
	}
	t.Log("QA_NATIVE_PAIR_A3 first_consent_zero=true second_consent_original_GroupKeyGrant_CURRENT=true exact_first_receipt=true no_SQL_activation=true Runtime_NOT_RUN=true")
}

func TestQANativePairA3SecondGrantFailureRollsBackBothMemberships(t *testing.T) {
	a := qaA3Setup(t)
	var first wire.NativePairResult
	a.call(t, wire.OperationNativePairConsentComplete, a.consent(t, 0), &first)
	a.assertZero(t)
	// Fault injection only: fail the second existing legacy key-grant insert.
	// An implementation using separate transactions would expose a partial
	// membership or first effective key grant, which the public Store reads test.
	db, err := sql.Open("sqlite", a.f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	endpoint := strings.ReplaceAll(a.joins[1].Endpoint.ID, "'", "''")
	_, err = db.Exec(`CREATE TRIGGER synthetic_qa_a3_grant_abort BEFORE INSERT ON group_endpoint_key_grants_v2
WHEN NEW.endpoint_id='` + endpoint + `' BEGIN SELECT RAISE(ABORT,'synthetic QA second grant failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DROP TRIGGER IF EXISTS synthetic_qa_a3_grant_abort`) })
	q := a.consent(t, 1)
	var fence wire.NativePairRejectionFence
	packet, receipt := a.call(t, wire.OperationNativePairConsentComplete, q, &fence)
	if wire.ValidateNativePairRejectionTarget(fence, q, packet) != nil || !fence.NoEffect {
		t.Fatal("failed activation did not commit its exact no-effect fence")
	}
	a.assertZero(t)
	status := a.status(t)
	if status.State != wire.NativePairWaitingConsent || status.ControlRevision != first.ControlRevision ||
		status.SlotAState != wire.NativePairSlotConsentRecorded {
		t.Fatal("second-grant failure damaged first consent or advanced activation")
	}
	if _, err = db.Exec(`DROP TRIGGER synthetic_qa_a3_grant_abort`); err != nil {
		t.Fatal(err)
	}
	retry, err := a.sendPacket(t, a.f.http.URL, wire.OperationNativePairConsentComplete, packet)
	if err != nil || !bytes.Equal(receipt, retry) {
		t.Fatal("removed fault revived the permanently fenced original")
	}
	a.assertZero(t)
	var active wire.NativePairResult
	a.call(t, wire.OperationNativePairConsentComplete, a.consent(t, 1), &active)
	a.assertActive(t, active)
	t.Log("QA_NATIVE_PAIR_A3 second_legacy_grant_abort=true both_memberships_and_grants_rolled_back=true original_fence_permanent=true fresh_explicit_consent_required=true Runtime_NOT_RUN=true")
}

type qaA3AckLoss struct {
	mu      sync.Mutex
	receipt []byte
	posts   int
}

func qaA3LostAckProxy(t *testing.T, a *qaA3Fixture) (*httptest.Server, *qaA3AckLoss) {
	t.Helper()
	state := &qaA3AckLoss{}
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != wire.NativePairHTTPPath(wire.OperationNativePairConsentComplete) {
			http.Error(w, "unexpected synthetic fault route", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxNativePairOriginalBytes+1))
		if err != nil || len(body) > wire.MaxNativePairOriginalBytes {
			http.Error(w, "invalid synthetic packet", http.StatusBadRequest)
			return
		}
		forward, err := http.NewRequestWithContext(r.Context(), http.MethodPost, a.f.http.URL+r.URL.Path, bytes.NewReader(body))
		if err != nil {
			http.Error(w, "synthetic forwarding failed", http.StatusBadGateway)
			return
		}
		forward.Header = r.Header.Clone()
		response, err := transport.RoundTrip(forward)
		if err != nil {
			http.Error(w, "synthetic upstream failed", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		receipt, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxNativePairReceiptBytes+1))
		if err != nil || response.StatusCode != http.StatusOK || len(receipt) > wire.MaxNativePairReceiptBytes {
			http.Error(w, "synthetic upstream did not complete", http.StatusBadGateway)
			return
		}
		state.mu.Lock()
		state.posts++
		state.receipt = append([]byte(nil), receipt...)
		state.mu.Unlock()
		// Upstream completed and the full sealed receipt exists. Close this
		// actual TCP connection before returning any acknowledgement bytes.
		connection, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = connection.Close()
		}
	}))
	t.Cleanup(proxy.Close)
	return proxy, state
}

func TestQANativePairA3LostActivationAckRecoversAcceptedHistory(t *testing.T) {
	a := qaA3Setup(t)
	var first wire.NativePairResult
	a.call(t, wire.OperationNativePairConsentComplete, a.consent(t, 0), &first)
	q := a.consent(t, 1)
	original := a.packet(t, q)
	proxy, loss := qaA3LostAckProxy(t, a)
	if raw, err := a.sendPacket(t, proxy.URL, wire.OperationNativePairConsentComplete, original); err == nil || len(raw) != 0 {
		t.Fatal("actual lost acknowledgement was hidden by a retry or fabricated response")
	}
	loss.mu.Lock()
	posts, committedReceipt := loss.posts, append([]byte(nil), loss.receipt...)
	loss.mu.Unlock()
	if posts != 1 || len(committedReceipt) == 0 {
		t.Fatal("fault proxy did not capture exactly one committed activation")
	}
	query := wire.NativePairReconcileRequest{Format: wire.NativePairFormat, Context: a.context(t),
		PairID: a.plan.Plan.PairID, OriginalPacket: original}
	var recovered wire.NativePairReconciled
	a.call(t, wire.OperationNativePairReconcile, query, &recovered)
	if wire.ValidateNativePairReconcileTarget(recovered, a.plan.Plan.PairID, original) != nil ||
		recovered.State != "COMPLETED" || !bytes.Equal(recovered.ReceiptPacket, committedReceipt) {
		t.Fatal("accepted-but-unacknowledged activation was guessed as no effect or replayed")
	}
	var active wire.NativePairResult
	if wire.OpenClientResponse(a.device, a.f.hub, original, recovered.ReceiptPacket, &active) != nil {
		t.Fatal("nested original activation receipt could not be authenticated")
	}
	a.assertActive(t, active)
	repeated, err := a.sendPacket(t, a.f.http.URL, wire.OperationNativePairConsentComplete, original)
	if err != nil || !bytes.Equal(repeated, committedReceipt) {
		t.Fatal("late exact original changed accepted history")
	}
	current := a.status(t)
	if current.ControlRevision != active.ControlRevision || current.Budget != active.Budget {
		t.Fatal("activation recovery advanced revision or reset budget")
	}
	t.Log("QA_NATIVE_PAIR_A3 real_TCP_lost_ACK=true committed_original_reconcile=true no_false_NO_EFFECT=true no_double_activation=true Runtime_NOT_RUN=true")
}

func TestQANativePairA3CurrentRequiredAndExactCoordinates(t *testing.T) {
	a := qaA3Setup(t)
	for i := 0; i != 2; i++ {
		var result wire.NativePairResult
		a.call(t, wire.OperationNativePairConsentComplete, a.consent(t, i), &result)
		if i == 1 {
			a.assertActive(t, result)
		}
	}
	query := url.Values{"group_id": {a.plan.Plan.GroupID}, "source_endpoint_id": {a.joins[0].Endpoint.ID}, "target_endpoint_id": {a.joins[1].Endpoint.ID}}
	code, raw := a.http(t, http.MethodGet, "/v2/relay/nodes/"+a.scope.Node.NodeID+"/group/sealed/peer-key?"+query.Encode(),
		"CicadaNode "+a.nodeToken, "", nil)
	var carrier store.SameGroupSealedV1PeerKey
	if code != http.StatusOK || json.Unmarshal(raw, &carrier) != nil || carrier.NativePairEvidence == nil || carrier.NativePairCurrent == nil {
		t.Fatal("actual active carrier lacks mandatory independent evidence/current coordinates")
	}
	verify := func(e *wire.NativePairPeerEvidence, c *wire.NativePairPeerCurrent) error {
		return wire.VerifyNativePairPeerAuthorization(true, e, c, a.f.hub, a.owner.Public(),
			a.plan.Plan.Scope.NodeTupleDigest, a.joins[0].Endpoint.ID, a.joins[1].Endpoint.ID, time.Now().UTC())
	}
	if verify(carrier.NativePairEvidence, carrier.NativePairCurrent) != nil || verify(nil, carrier.NativePairCurrent) == nil ||
		verify(carrier.NativePairEvidence, nil) == nil || verify(nil, nil) == nil {
		t.Fatal("Pair-required absence was accepted as a legacy fallback")
	}
	for name, edit := range map[string]func(*wire.NativePairPeerCurrent){
		"actual_sid":   func(c *wire.NativePairPeerCurrent) { c.Sender.NativeSessionID = "synthetic-other-original" },
		"access_id":    func(c *wire.NativePairPeerCurrent) { c.Receiver.NetworkAccessBindingID = "synthetic-other-access" },
		"access_epoch": func(c *wire.NativePairPeerCurrent) { c.Sender.NetworkAccessEpoch++ },
		"generation":   func(c *wire.NativePairPeerCurrent) { c.Receiver.Generation++ },
		"attempt": func(c *wire.NativePairPeerCurrent) {
			prefix := "0"
			if strings.HasPrefix(c.Sender.AttemptID, prefix) {
				prefix = "1"
			}
			c.Sender.AttemptID = prefix + c.Sender.AttemptID[1:]
		},
		"network_member":   func(c *wire.NativePairPeerCurrent) { c.Receiver.NetworkMembershipRevision++ },
		"endpoint_network": func(c *wire.NativePairPeerCurrent) { c.Sender.EndpointNetworkRevision++ },
		"lease_owner":      func(c *wire.NativePairPeerCurrent) { c.Receiver.LeaseOwner = "synthetic-other-lease" },
	} {
		changed := *carrier.NativePairCurrent
		edit(&changed)
		if verify(carrier.NativePairEvidence, &changed) == nil {
			t.Fatal("actual carrier accepted a substituted Current coordinate", name)
		}
	}
	t.Log("QA_NATIVE_PAIR_A3 actual_crypto_carrier=true required_Current_no_fallback=true substituted_coordinates_rejected=true helper_verification_only_no_Runtime_or_queue=true")
}
