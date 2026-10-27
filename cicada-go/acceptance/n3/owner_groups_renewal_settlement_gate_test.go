package n3_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Gate safety only: synthetic registration/state, real PQ packets and TCP.
// No product lease is renewed and no native Runtime observation is supplied.
func TestN3OwnerGroupsRenewalSettlementRequiresConsumedOriginalAnchor(t *testing.T) {
	node, hub, candidate := must(e2ee.NewIdentity()), must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
	publicHub := wire.HubIdentity{Contract: "android-hub-v1", HubID: "hub-synthetic", Public: hub.Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}
	binding := nodewire.Binding{HubID: publicHub.HubID, NodeID: "node-synthetic", BindingID: "binding-synthetic", BindingVersion: 1, NodeKeyEpoch: 1,
		HubKeyVersion: 1, NodeKeyVersion: 1, HubKey: hub.Public(), NodeKey: node.Public()}
	now := time.Now().UTC()
	anchor := wire.EndpointGroupsRegistrationAnchor{Profile: wire.EndpointGroupsNativeProfile, RegistrationSource: wire.EndpointGroupsRegistrationSource,
		Registration: e2ee.EndpointGroupRegistration{HubID: publicHub.HubID, OwnerID: "owner-synthetic", NodeID: binding.NodeID, Harness: "codex",
			NativeSessionID: "SYNTHETIC_ORIGINAL_A", Workspace: "/synthetic/renew/A", EndpointID: "endpoint-synthetic-a", PrincipalID: "principal-synthetic-a"},
		RegistrationRevision: 1, LocalUserScope: "uid:1000", NetworkID: "network-synthetic", BindingID: binding.BindingID, BindingEpoch: 1, NodeKeyEpoch: 1,
		LeaseOwner: "writer-synthetic", NetworkAccessBindingID: "access-synthetic", NetworkAccessEpoch: 1, NetworkMembershipRevision: 1, EndpointNetworkRevision: 1,
		CandidateVersion: 1, CandidateKeyID: candidate.Public().ID, CandidatePublic: candidate.Public(), CandidateFingerprint: must(nodekeys.PeerKeyFingerprint(candidate.Public())),
		CandidateProofDigest: strings.Repeat("a", 64), State: "REGISTERED", LeaseExpiresAt: now.Add(-time.Minute).Format(time.RFC3339Nano)}
	anchor.RegistrationDigest = must(e2ee.EndpointGroupRegistrationDigest(anchor.Registration))
	if wire.ValidateEndpointGroupsRegistrationAnchor(anchor, publicHub) != nil {
		t.Fatal("synthetic original renewal anchor is invalid")
	}
	before := ownerGroupsSettlementRegistration{Anchor: anchor, IntentID: "SYNTHETIC_ORIGIN_A"}
	q := wire.EndpointGroupsNodeRenew{EndpointID: anchor.Registration.EndpointID, RegistrationDigest: anchor.RegistrationDigest, ExpectedBindingID: anchor.BindingID, ExpectedBindingEpoch: anchor.BindingEpoch}
	body := must(wire.CanonicalEndpointGroupsNodeRequest(wire.OperationEndpointGroupsNodeRenew, q))
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: binding.HubID, NodeID: binding.NodeID,
		BindingID: binding.BindingID, BindingVersion: binding.BindingVersion, NodeKeyEpoch: binding.NodeKeyEpoch, OperationID: "op-synthetic-renew-a", Sequence: 77,
		Operation: wire.OperationEndpointGroupsNodeRenew, SenderKeyID: node.Public().ID, SenderKeyVersion: 1, ReceiverKeyID: hub.Public().ID, ReceiverKeyVersion: 1}
	request := must(nodewire.SealRequest(node, hub.Public(), binding, route, body))
	reverse := route
	reverse.Direction = nodewire.DirectionResponse
	reverse.SenderKeyID, reverse.ReceiverKeyID = reverse.ReceiverKeyID, reverse.SenderKeyID
	reverse.SenderKeyVersion, reverse.ReceiverKeyVersion = reverse.ReceiverKeyVersion, reverse.SenderKeyVersion
	consumed := anchor
	consumed.LeaseExpiresAt = now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	result := wire.EndpointGroupsNodeRenewResult{ContractRevision: wire.OwnerEndpointGroupsContractRevision, Registration: consumed, ObservedAt: now.Format(time.RFC3339Nano)}
	seal := func(r nodewire.Route, result wire.EndpointGroupsNodeRenewResult, ok bool) []byte {
		plain := map[string]any{"operation_id": r.OperationID, "sequence": r.Sequence, "ok": ok}
		if ok {
			plain["result"] = result
		} else {
			plain["error_code"] = "TARGET_NOT_AUTHORIZED"
		}
		return must(nodewire.SealResponse(hub, node.Public(), binding, r, must(json.Marshal(plain))))
	}
	response := seal(reverse, result, true)
	var posts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		raw, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(raw, request) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		opened, err := nodewire.OpenRequest(hub, node.Public(), binding, raw)
		if err != nil || opened.Route != route || !bytes.Equal(opened.Plaintext, body) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		clear(opened.Plaintext)
		_, _ = w.Write(response)
	}))
	defer server.Close()
	loopback(t, server.URL)
	r := must(http.Post(server.URL, "application/json", bytes.NewReader(request)))
	actual := must(io.ReadAll(r.Body))
	r.Body.Close()
	if r.StatusCode != http.StatusOK || !bytes.Equal(actual, response) {
		t.Fatal("synthetic real TCP original renewal exchange failed")
	}
	ref := ownerGroupsSettlementReference{request: request, response: actual, bodyDigest: hash(body), route: route,
		renewal: &ownerGroupsRenewalReference{before: before, request: q, hub: publicHub}}
	makeState := func() ownerGroupsSettlementState {
		return ownerGroupsSettlementState{Intents: map[string]ownerGroupsSettlementIntent{before.IntentID: {Steps: map[string]ownerGroupsSettlementStep{
			route.OperationID: {Operation: route.Operation, Body: body, RequestPacket: request, ResponsePacket: actual, Settled: true, CompletedAt: now.Format(time.RFC3339Nano)},
		}}}, Registrations: map[string]ownerGroupsSettlementRegistration{anchor.RegistrationDigest: {Anchor: consumed, IntentID: before.IntentID}}}
	}
	path := filepath.Join(t.TempDir(), "node-control-state.json")
	check := func(t *testing.T, state ownerGroupsSettlementState, reference ownerGroupsSettlementReference, ready, failed bool) {
		t.Helper()
		writeJSON(t, path, state)
		beforeBytes := must(os.ReadFile(path))
		raw := readNodeControlState(t, path)
		var observed ownerGroupsSettlementState
		if json.Unmarshal(raw, &observed) != nil {
			t.Fatal("synthetic renewal snapshot invalid")
		}
		clear(raw)
		got, diagnostic, err := ownerGroupsSettlementReady(observed, reference, node, binding)
		if got != ready || (err != nil) != failed {
			t.Fatalf("renewal gate ready=%t error_present=%t code=%v", got, err != nil, err)
		}
		if !bytes.Equal(beforeBytes, must(os.ReadFile(path))) || posts.Load() != 1 {
			t.Fatal("renewal matcher wrote state or dispatched traffic")
		}
		closed := must(json.Marshal(diagnostic))
		for _, private := range [][]byte{body, []byte(route.OperationID), []byte(before.IntentID), []byte(anchor.Registration.NativeSessionID)} {
			if bytes.Contains(closed, private) {
				t.Fatal("renewal matcher exported private coordinates")
			}
		}
	}
	t.Run("hub_receipt_is_not_local_settlement", func(t *testing.T) {
		s := makeState()
		step := s.Intents[before.IntentID].Steps[route.OperationID]
		step.Settled, step.ResponsePacket, step.CompletedAt = false, nil, ""
		s.Intents[before.IntentID].Steps[route.OperationID] = step
		s.PendingOperation, s.PendingOperationID, s.PendingSequence, s.PendingPacket = route.Operation, route.OperationID, route.Sequence, request
		check(t, s, ref, false, false)
	})
	t.Run("settled_original_waits_for_consumed_anchor", func(t *testing.T) {
		s := makeState()
		s.Registrations[anchor.RegistrationDigest] = before
		check(t, s, ref, false, false)
		delete(s.Registrations, anchor.RegistrationDigest)
		check(t, s, ref, false, false)
	})
	t.Run("original_A_consumed_positive", func(t *testing.T) { check(t, makeState(), ref, true, false) })
	t.Run("pending_execution_still_blocks", func(t *testing.T) { s := makeState(); s.PendingWorkerAttempt = 1; check(t, s, ref, false, false) })
	t.Run("unique_original_intent_required", func(t *testing.T) {
		s := makeState()
		s.Intents["SYNTHETIC_OTHER"] = s.Intents[before.IntentID]
		check(t, s, ref, false, true)
		delete(s.Intents, before.IntentID)
		check(t, s, ref, false, true)
	})
	t.Run("changed_local_key_binding_or_lease_owner", func(t *testing.T) {
		for _, mutate := range []func(*wire.EndpointGroupsRegistrationAnchor){
			func(a *wire.EndpointGroupsRegistrationAnchor) { a.CandidateKeyID = "changed" },
			func(a *wire.EndpointGroupsRegistrationAnchor) { a.BindingEpoch++ },
			func(a *wire.EndpointGroupsRegistrationAnchor) { a.LeaseOwner = "changed" },
		} {
			s := makeState()
			local := s.Registrations[anchor.RegistrationDigest]
			mutate(&local.Anchor)
			s.Registrations[anchor.RegistrationDigest] = local
			check(t, s, ref, false, true)
		}
	})
	t.Run("authenticated_changed_renewal_result_rejected", func(t *testing.T) {
		for _, mutate := range []func(*wire.EndpointGroupsNodeRenewResult){
			func(r *wire.EndpointGroupsNodeRenewResult) { r.Registration.BindingEpoch++ },
			func(r *wire.EndpointGroupsNodeRenewResult) { r.Registration.LeaseExpiresAt = anchor.LeaseExpiresAt },
			func(r *wire.EndpointGroupsNodeRenewResult) {
				r.Registration.Registration.NativeSessionID = "SYNTHETIC_OTHER"
			},
		} {
			changed := result
			mutate(&changed)
			signed := seal(reverse, changed, true)
			s := makeState()
			step := s.Intents[before.IntentID].Steps[route.OperationID]
			step.ResponsePacket = signed
			s.Intents[before.IntentID].Steps[route.OperationID] = step
			changedRef := ref
			changedRef.response = signed
			check(t, s, changedRef, false, true)
		}
	})
	t.Run("authenticated_negative_or_other_sequence_rejected", func(t *testing.T) {
		other := reverse
		other.Sequence++
		for _, signed := range [][]byte{seal(reverse, result, false), seal(other, result, true)} {
			s := makeState()
			step := s.Intents[before.IntentID].Steps[route.OperationID]
			step.ResponsePacket = signed
			s.Intents[before.IntentID].Steps[route.OperationID] = step
			changedRef := ref
			changedRef.response = signed
			check(t, s, changedRef, false, true)
		}
	})
	t.Run("changed_original_body_packet_or_completion_time", func(t *testing.T) {
		for _, mutate := range []func(*ownerGroupsSettlementStep){
			func(s *ownerGroupsSettlementStep) { s.Body = []byte(`{"synthetic":"other"}`) },
			func(s *ownerGroupsSettlementStep) { s.RequestPacket = append(bytes.Clone(request), 'x') },
			func(s *ownerGroupsSettlementStep) { s.CompletedAt = "invalid" },
		} {
			s := makeState()
			step := s.Intents[before.IntentID].Steps[route.OperationID]
			mutate(&step)
			s.Intents[before.IntentID].Steps[route.OperationID] = step
			check(t, s, ref, false, true)
		}
	})
}
