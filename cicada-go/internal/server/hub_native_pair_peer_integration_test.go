package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

func (a *nativePairTCPActor) pairHTTP(t *testing.T, method, path, authorization, group string, body any, want int) []byte {
	t.Helper()
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, a.f.http.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Cicada-Group-Scope", group)
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, wire.MaxNativePairCarrierBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != want {
		t.Fatal("synthetic bounded HTTP", method, path, "status", res.StatusCode, "expected", want)
	}
	return out
}

// Real N2/N3 + Owner/native-pair PQ + old Relay routes over disposable TCP.
// Two synthetic SIDs are never executed; this is not a Runtime/provider gate.
func TestNativePairPeerRealTCPConsentResolveAskClaimAndRevoke(t *testing.T) {
	a := nativePairTCP(t)
	ch := a.completePair(t)
	a.scope = ch.Scope
	description := a.describePair(t, ch, 1)
	var joins [2]fabric.JoinResult
	var keys [2]*e2ee.Identity
	for i, letter := range []string{"A", "B"} {
		q := wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision, PairID: ch.Bootstrap.PairID, Slot: letter, ExpectedGeneration: 1, BootstrapProofDigest: wire.NativePairProofDigest(description.BootstrapOwnerProof), Runtime: "codex", NativeSessionID: "synthetic-http-original-" + letter, Workspace: "/synthetic/http/" + letter, EndpointName: "Synthetic Peer " + letter}
		packet := a.nodeSeal(t, wire.OperationNativePairNodeJoin, uint64(i+2), q)
		reply := a.nodeOpen(t, packet, a.nodePost(t, packet, http.StatusOK))
		if !reply.OK || json.Unmarshal(reply.Result, &joins[i]) != nil {
			t.Fatal("synthetic HTTP zero Join refused")
		}
		var err error
		keys[i], err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		proof, err := keys[i].SignEndpointKeyAttestation(joins[i].Endpoint.ID, joins[i].Endpoint.PrincipalID, a.scope.Node.NodeID, joins[i].BindingID, joins[i].BindingEpoch)
		if err != nil {
			t.Fatal(err)
		}
		a.pairHTTP(t, http.MethodPost, "/v2/fabric/endpoint-keys", "CicadaSession "+joins[i].SessionToken, ch.Bootstrap.GroupID, map[string]any{"attestation": json.RawMessage(proof)}, http.StatusOK)
	}
	statusQ := wire.NativePairStatusRequest{Format: wire.NativePairFormat, Context: a.context(t), SessionToken: a.session.Token, PairID: ch.Bootstrap.PairID}
	packet := a.seal(t, statusQ)
	var status wire.NativePairResult
	if wire.OpenClientResponse(a.device, a.f.hub, packet, a.post(t, wire.OperationNativePairStatus, packet), &status) != nil || status.SlotA == nil || status.SlotB == nil {
		t.Fatal("HTTP candidates not observable")
	}
	c := a.context(t)
	at, _ := time.Parse(time.RFC3339Nano, c.IssuedAt)
	ad, _ := wire.NativePairSlotDigest(*status.SlotA)
	bd, _ := wire.NativePairSlotDigest(*status.SlotB)
	claims := e2ee.OwnerNativePairClaims{Version: 1, Purpose: e2ee.OwnerNativePairConsentPreview, Scope: a.scope, RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt, ExpiresAt: at.Add(time.Minute).Format(time.RFC3339Nano), Consent: &e2ee.NativePairConsentClaims{PairID: status.PairID, ExpectedRevision: status.ControlRevision, SlotADigest: ad, SlotBDigest: bd, PeerExpiresAt: status.PeerExpiresAt}}
	proof, err := e2ee.SignOwnerNativePair(a.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairConsentPrepare{Format: wire.NativePairFormat, Context: c, SessionToken: a.session.Token, OwnerProof: proof}
	packet = a.seal(t, q)
	var plan wire.NativePairPlanChallenge
	if wire.OpenClientResponse(a.device, a.f.hub, packet, a.post(t, wire.OperationNativePairConsentPrepare, packet), &plan) != nil || wire.ValidateNativePairPlanTarget(q, packet, plan, description.BootstrapOwnerProof, a.f.hub, time.Now().UTC()) != nil {
		t.Fatal("HTTP actual consent Plan refused")
	}
	for i, slot := range []wire.NativePairSlot{plan.Plan.SlotA, plan.Plan.SlotB} {
		other, m := plan.Plan.SlotB, plan.Plan.SlotAKeyManifest
		if i == 1 {
			other, m = plan.Plan.SlotA, plan.Plan.SlotBKeyManifest
		}
		c = a.context(t)
		at, _ = time.Parse(time.RFC3339Nano, c.IssuedAt)
		claims = e2ee.OwnerNativePairClaims{Version: 1, Purpose: e2ee.OwnerNativePairSlotConsent, Scope: a.scope, RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt, ExpiresAt: at.Add(time.Minute).Format(time.RFC3339Nano), Consent: &e2ee.NativePairConsentClaims{PairID: status.PairID, ExpectedRevision: plan.Plan.ExpectedRevision, PlanID: plan.Plan.PlanID, PlanDigest: plan.Plan.Digest, SlotADigest: ad, SlotBDigest: bd, Slot: slot.Slot, SlotGeneration: slot.Generation, SlotAttemptID: slot.AttemptID, NativeSessionID: slot.NativeSessionID, PeerNativeSessionID: other.NativeSessionID, ActivateWhenBoth: true, PlanExpiresAt: plan.Plan.ExpiresAt, PeerExpiresAt: plan.Plan.PeerExpiresAt}}
		proof, err = e2ee.SignOwnerNativePair(a.owner, claims)
		if err != nil {
			t.Fatal(err)
		}
		issued, _ := time.Parse(time.RFC3339Nano, m.IssuedAt)
		end, _ := time.Parse(time.RFC3339Nano, m.ExpiresAt)
		groupProof, e := a.owner.SignOwnerLinkKeyGrant(m.OwnerID, m.Operation, m.Digest, m.CandidateBindingDigest, uint64(m.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issued, end)
		if e != nil {
			t.Fatal(e)
		}
		complete := wire.NativePairConsentComplete{Format: wire.NativePairFormat, Context: c, SessionToken: a.session.Token, OwnerProof: proof, GroupKeyProof: groupProof}
		packet = a.seal(t, complete)
		response := a.post(t, wire.OperationNativePairConsentComplete, packet)
		if wire.OpenClientResponse(a.device, a.f.hub, packet, response, &status) != nil || (i == 0 && status.State != wire.NativePairWaitingConsent) || (i == 1 && status.State != wire.NativePairActive) {
			t.Fatal("HTTP dual Consent did not activate once")
		}
		if retry := a.post(t, wire.OperationNativePairConsentComplete, packet); !bytes.Equal(response, retry) {
			t.Fatal("HTTP exact consent receipt changed")
		}
	}
	resolve := a.pairHTTP(t, http.MethodPost, "/v2/fabric/resolve", "CicadaSession "+joins[0].SessionToken, ch.Bootstrap.GroupID, fabric.ResolveInput{Query: joins[1].Endpoint.ID}, http.StatusOK)
	var card fabric.NetworkCard
	if json.Unmarshal(resolve, &card) != nil || card.EndpointID != joins[1].Endpoint.ID {
		t.Fatal("bounded resolve lost actual peer")
	}
	base := "/v2/relay/nodes/" + a.scope.Node.NodeID + "/group/sealed/"
	query := url.Values{"group_id": {ch.Bootstrap.GroupID}, "source_endpoint_id": {joins[0].Endpoint.ID}, "target_endpoint_id": {joins[1].Endpoint.ID}}
	data := a.pairHTTP(t, http.MethodGet, base+"peer-key?"+query.Encode(), "CicadaNode "+a.nodeToken, "", nil, http.StatusOK)
	var peer store.SameGroupSealedV1PeerKey
	if json.Unmarshal(data, &peer) != nil || peer.NativePairEvidence == nil || peer.NativePairCurrent == nil || wire.VerifyNativePairPeerAuthorization(true, peer.NativePairEvidence, peer.NativePairCurrent, a.f.hub, a.owner.Public(), plan.Plan.Scope.NodeTupleDigest, joins[0].Endpoint.ID, joins[1].Endpoint.ID, time.Now().UTC()) != nil {
		t.Fatal("HTTP carrier lacks independent Owner/Current evidence")
	}
	assertNativePairCarrierHTTPBoundary(t, "peer_key", &peer)

	msg, request := "synthetic-http-pair-ask", "synthetic-http-pair-request"
	s, r := peer.Sender, peer.Receiver
	context := e2ee.EndpointMessageContext{MessageID: msg, Kind: "REQUEST", RequestID: request, SenderEndpointID: s.EndpointID, SenderPrincipalID: s.PrincipalID, SenderOwnerID: s.OwnerID, SenderGroupID: peer.GroupID, SenderMembershipRevision: s.MembershipRevision, SenderBindingEpoch: s.BindingEpoch, SenderKeyID: s.Candidate.KeyID, ReceiverEndpointID: r.EndpointID, ReceiverPrincipalID: r.PrincipalID, ReceiverOwnerID: r.OwnerID, ReceiverGroupID: peer.GroupID, ReceiverMembershipRevision: r.MembershipRevision, ReceiverBindingEpoch: r.BindingEpoch, ReceiverKeyID: r.Candidate.KeyID, TransportHubID: peer.HubID}
	cipher, err := e2ee.SealEndpointMessage(keys[0], keys[1].Public(), context, []byte("synthetic opaque HTTP exchange"), 1)
	if err != nil {
		t.Fatal(err)
	}
	a.pairHTTP(t, http.MethodPost, base+"ask", "CicadaNode "+a.nodeToken, "", fabric.NodeSameGroupSealedV1AskInput{GroupID: peer.GroupID, SourceEndpointID: s.EndpointID, TargetEndpointID: r.EndpointID, MessageID: msg, RequestID: request, IdempotencyKey: msg, DataScope: store.SameGroupSealedV1DataScope, ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), Ciphertext: cipher}, http.StatusAccepted)
	data = a.pairHTTP(t, http.MethodPost, base+"claim", "CicadaNode "+a.nodeToken, "", fabric.NodeClaimInput{ConsumerID: "synthetic-pair-http", Limit: 1}, http.StatusOK)
	var claimed struct {
		Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
	}
	if json.Unmarshal(data, &claimed) != nil || len(claimed.Deliveries) != 1 {
		t.Fatal("bounded HTTP claim lost message")
	}
	delivery := base + "deliveries/" + msg + "/authorization?attempt_id=" + url.QueryEscape(claimed.Deliveries[0].AttemptID)
	data = a.pairHTTP(t, http.MethodGet, delivery, "CicadaNode "+a.nodeToken, "", nil, http.StatusOK)
	var auth store.SameGroupSealedV1DeliveryAuthorization
	if json.Unmarshal(data, &auth) != nil || auth.NativePairCurrent == nil || auth.NativeSessionID != joins[1].Endpoint.NativeSessionID {
		t.Fatal("HTTP final authorization lost original SID")
	}
	assertNativePairCarrierHTTPBoundary(t, "delivery_authorization", &auth)

	c = a.context(t)
	at, _ = time.Parse(time.RFC3339Nano, c.IssuedAt)
	target, _ := wire.NativePairRevokeTargetDigest(a.scope, status.PairID, status.ControlRevision)
	claims = e2ee.OwnerNativePairClaims{Version: 1, Purpose: e2ee.OwnerNativePairRevoke, Scope: a.scope, RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt, ExpiresAt: at.Add(time.Minute).Format(time.RFC3339Nano), Revoke: &e2ee.NativePairRevokeClaims{PairID: status.PairID, ExpectedRevision: status.ControlRevision, PairTargetDigest: target}}
	proof, err = e2ee.SignOwnerNativePair(a.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	packet = a.seal(t, wire.NativePairRevoke{Format: wire.NativePairFormat, Context: c, SessionToken: a.session.Token, OwnerProof: proof})
	a.post(t, wire.OperationNativePairRevoke, packet)
	a.pairHTTP(t, http.MethodGet, delivery, "CicadaNode "+a.nodeToken, "", nil, http.StatusNotFound)
	a.pairHTTP(t, http.MethodGet, base+"peer-key?"+query.Encode(), "CicadaNode "+a.nodeToken, "", nil, http.StatusNotFound)
	for _, path := range []string{"/v2/fabric/node/join", base + "send", base + "deliveries/extra/authorization/extra"} {
		a.pairHTTP(t, http.MethodPost, path, "CicadaNode "+a.nodeToken, "", map[string]any{}, http.StatusNotFound)
	}
}
