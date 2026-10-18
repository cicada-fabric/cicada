package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

// This increment starts from actual dual-consent authority and obtains both
// complete carrier types through real TCP/Relay APIs. Only a private in-memory
// copy's unsigned grant ID is padded for rendering faults; no DB write creates
// ACTIVE, a grant or an imaginary route/attempt. No Runtime/queue is invoked.
func TestQANativePairA3HTTPExactBodyAndAtomicRejection(t *testing.T) {
	a := qaA3Setup(t)
	for i := 0; i < 2; i++ {
		var result wire.NativePairResult
		a.call(t, wire.OperationNativePairConsentComplete, a.consent(t, i), &result)
		if i == 1 {
			a.assertActive(t, result)
		}
	}
	base := "/v2/relay/nodes/" + a.scope.Node.NodeID + "/group/sealed/"
	query := url.Values{"group_id": {a.plan.Plan.GroupID}, "source_endpoint_id": {a.joins[0].Endpoint.ID}, "target_endpoint_id": {a.joins[1].Endpoint.ID}}
	code, raw := a.http(t, http.MethodGet, base+"peer-key?"+query.Encode(), "CicadaNode "+a.nodeToken, "", nil)
	var peer store.SameGroupSealedV1PeerKey
	if code != http.StatusOK || json.Unmarshal(raw, &peer) != nil {
		t.Fatal("actual peer-key HTTP route did not return a typed carrier")
	}
	qaA3ExactHTTPEncoding(t, raw, &peer)
	if wire.VerifyNativePairPeerAuthorization(true, peer.NativePairEvidence, peer.NativePairCurrent,
		a.f.hub, a.owner.Public(), a.plan.Plan.Scope.NodeTupleDigest, peer.Sender.EndpointID, peer.Receiver.EndpointID, time.Now().UTC()) != nil {
		t.Fatal("actual carrier lacks independently pinned valid evidence")
	}
	s, r := peer.Sender, peer.Receiver
	const msg, request = "synthetic-qa-a3-size-message", "synthetic-qa-a3-size-request"
	context := e2ee.EndpointMessageContext{MessageID: msg, Kind: "REQUEST", RequestID: request,
		SenderEndpointID: s.EndpointID, SenderPrincipalID: s.PrincipalID, SenderOwnerID: s.OwnerID,
		SenderGroupID: peer.GroupID, SenderMembershipRevision: s.MembershipRevision,
		SenderBindingEpoch: s.BindingEpoch, SenderKeyID: s.Candidate.KeyID,
		ReceiverEndpointID: r.EndpointID, ReceiverPrincipalID: r.PrincipalID, ReceiverOwnerID: r.OwnerID,
		ReceiverGroupID: peer.GroupID, ReceiverMembershipRevision: r.MembershipRevision,
		ReceiverBindingEpoch: r.BindingEpoch, ReceiverKeyID: r.Candidate.KeyID, TransportHubID: peer.HubID}
	cipher, err := e2ee.SealEndpointMessage(a.keys[0], a.keys[1].Public(), context, []byte("synthetic size-only opaque payload"), 1)
	if err != nil {
		t.Fatal(err)
	}
	code, _ = a.http(t, http.MethodPost, base+"ask", "CicadaNode "+a.nodeToken, "", fabric.NodeSameGroupSealedV1AskInput{
		GroupID: peer.GroupID, SourceEndpointID: s.EndpointID, TargetEndpointID: r.EndpointID,
		MessageID: msg, RequestID: request, IdempotencyKey: msg, DataScope: store.SameGroupSealedV1DataScope,
		ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), Ciphertext: cipher})
	if code != http.StatusAccepted {
		t.Fatal("actual synthetic sealed ASK was not admitted", code)
	}
	code, raw = a.http(t, http.MethodPost, base+"claim", "CicadaNode "+a.nodeToken, "", fabric.NodeClaimInput{ConsumerID: "synthetic-qa-size-only", Limit: 1})
	var claimed struct {
		Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &claimed) != nil || len(claimed.Deliveries) != 1 || claimed.Deliveries[0].AttemptID == "" {
		t.Fatal("actual synthetic claim did not allocate one genuine attempt")
	}
	path := base + "deliveries/" + msg + "/authorization?attempt_id=" + url.QueryEscape(claimed.Deliveries[0].AttemptID)
	code, raw = a.http(t, http.MethodGet, path, "CicadaNode "+a.nodeToken, "", nil)
	var delivery store.SameGroupSealedV1DeliveryAuthorization
	if code != http.StatusOK || json.Unmarshal(raw, &delivery) != nil || delivery.MessageID != msg ||
		delivery.AttemptID != claimed.Deliveries[0].AttemptID || delivery.NativeSessionID != a.plan.Plan.SlotB.NativeSessionID {
		t.Fatal("actual final authorization lost its original message/attempt/SID")
	}
	qaA3ExactHTTPEncoding(t, raw, &delivery)
	if wire.VerifyNativePairPeerAuthorization(true, delivery.NativePairEvidence, delivery.NativePairCurrent,
		a.f.hub, a.owner.Public(), a.plan.Plan.Scope.NodeTupleDigest, s.EndpointID, r.EndpointID, time.Now().UTC()) != nil {
		t.Fatal("actual final authorization did not verify against the independent Owner pin")
	}
	before := a.status(t)
	for _, actual := range []any{&peer, &delivery} {
		qaA3CarrierHTTPBoundary(t, actual)
	}
	after := a.status(t)
	if before.State != wire.NativePairActive || after.State != before.State || before.ControlRevision != after.ControlRevision || before.Budget != after.Budget {
		t.Fatal("rendering rejection changed live authority, control revision or message budget")
	}
	t.Log("QA_NATIVE_PAIR_A3_HTTP actual_PQ_TCP_dual_consent_and_Relay_carriers=true exact_327680_bytes=true plus_one_and_incomplete_404_no_partial_authorization=true legacy_Encoder_LF_preserved=true no_SQL_activation=true Runtime_NOT_RUN=true")
}

func qaA3ExactHTTPEncoding(t *testing.T, body []byte, carrier any) {
	t.Helper()
	encoded, err := json.Marshal(carrier)
	if err != nil || !bytes.Equal(body, encoded) {
		t.Fatal("actual Pair HTTP route differs from complete typed Marshal bytes", len(body), len(encoded))
	}
}

func qaA3CarrierHTTPBoundary(t *testing.T, actual any) {
	t.Helper()
	baseline, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	var clone any
	var grantID *string
	var evidence **wire.NativePairPeerEvidence
	var current **wire.NativePairPeerCurrent
	switch actual.(type) {
	case *store.SameGroupSealedV1PeerKey:
		v := new(store.SameGroupSealedV1PeerKey)
		if json.Unmarshal(baseline, v) != nil || v.Receiver.Grant == nil {
			t.Fatal("actual peer snapshot is incomplete")
		}
		clone, grantID, evidence, current = v, &v.Receiver.Grant.ID, &v.NativePairEvidence, &v.NativePairCurrent
	case *store.SameGroupSealedV1DeliveryAuthorization:
		v := new(store.SameGroupSealedV1DeliveryAuthorization)
		if json.Unmarshal(baseline, v) != nil || v.Receiver.Grant == nil {
			t.Fatal("actual delivery snapshot is incomplete")
		}
		clone, grantID, evidence, current = v, &v.Receiver.Grant.ID, &v.NativePairEvidence, &v.NativePairCurrent
	default:
		t.Fatal("unknown typed carrier")
	}
	remaining := wire.MaxNativePairCarrierBytes - len(baseline)
	if remaining <= 6 || *evidence == nil || *current == nil {
		t.Fatal("actual carrier cannot exercise the complete boundary")
	}
	// Include JSON expansion rather than assuming string length equals wire
	// bytes: '&' encodes to six bytes, then 's' fills the exact remainder.
	*grantID += "&" + strings.Repeat("s", remaining-6)
	exact, err := json.Marshal(clone)
	if err != nil || len(exact) != wire.MaxNativePairCarrierBytes {
		t.Fatal("independent complete encoded-byte oracle is invalid", len(exact))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSameGroupSealedV1Carrier(w, http.StatusOK, clone)
	}))
	defer server.Close()
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	call := func(status int, want []byte) {
		t.Helper()
		response, e := client.Get(server.URL)
		if e != nil {
			t.Fatal("owned boundary HTTP failed")
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, wire.MaxNativePairCarrierBytes+2))
		if e != nil || response.StatusCode != status {
			t.Fatal("wrong actual HTTP boundary status", response.StatusCode, status)
		}
		if status == http.StatusOK {
			if !bytes.Equal(body, want) {
				t.Fatal("actual HTTP body differs from independent complete encoding", len(body), len(want))
			}
		} else if len(body) > 2048 || !json.Valid(body) || bytes.Contains(body, []byte(`"native_pair_evidence"`)) || bytes.Contains(body, []byte(`"native_pair_current"`)) || bytes.HasPrefix(body, exact[:128]) {
			t.Fatal("rejection partially wrote a successful authorization body")
		}
	}
	call(http.StatusOK, exact)
	*grantID += "s"
	plusOne, _ := json.Marshal(clone)
	if len(plusOne) != wire.MaxNativePairCarrierBytes+1 {
		t.Fatal("independent limit+1 oracle is invalid")
	}
	call(http.StatusNotFound, nil)
	*grantID = (*grantID)[:len(*grantID)-1]
	// Removing either mandatory field must not fall back to the old writer.
	signed, observed := *evidence, *current
	*evidence = nil
	call(http.StatusNotFound, nil)
	*evidence, *current = signed, nil
	call(http.StatusNotFound, nil)
	*evidence, *current = nil, nil
	legacy, _ := json.Marshal(clone)
	call(http.StatusOK, append(legacy, '\n'))
	*evidence, *current = signed, observed
	call(http.StatusOK, exact)
}
