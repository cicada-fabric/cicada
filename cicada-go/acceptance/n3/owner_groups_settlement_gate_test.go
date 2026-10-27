package n3_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Gate safety test only: synthetic protected snapshots, real PQ receipts and a
// loopback TCP exchange. It cannot supply a Runtime fact or product grant.
func TestN3OwnerGroupsSettlementRequiresLocalOriginalReceipt(t *testing.T) {
	node, hub := must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
	b := nodewire.Binding{HubID: "hub-synthetic", NodeID: "node-synthetic", BindingID: "binding-synthetic",
		BindingVersion: 2, NodeKeyEpoch: 3, HubKeyVersion: 1, NodeKeyVersion: 1, NodeKey: node.Public(), HubKey: hub.Public()}
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID,
		NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch,
		Sequence: 434, OperationID: "op-synthetic-original", Operation: wire.OperationEndpointGroupsNodeKeyComplete,
		SenderKeyID: node.Public().ID, SenderKeyVersion: 1, ReceiverKeyID: hub.Public().ID, ReceiverKeyVersion: 1}
	body := []byte(`{"synthetic":"receipt-gate-only"}`)
	request := must(nodewire.SealRequest(node, hub.Public(), b, route, body))
	reverse := route
	reverse.Direction = nodewire.DirectionResponse
	reverse.SenderKeyID, reverse.ReceiverKeyID = reverse.ReceiverKeyID, reverse.SenderKeyID
	reverse.SenderKeyVersion, reverse.ReceiverKeyVersion = reverse.ReceiverKeyVersion, reverse.SenderKeyVersion
	plain := must(json.Marshal(map[string]any{"operation_id": route.OperationID, "sequence": route.Sequence, "ok": false, "error_code": "TARGET_NOT_AUTHORIZED"}))
	response := must(nodewire.SealResponse(hub, node.Public(), b, reverse, plain))
	var posts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		raw, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(raw, request) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		opened, err := nodewire.OpenRequest(hub, node.Public(), b, raw)
		if err != nil || opened.Route != route || !bytes.Equal(opened.Plaintext, body) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		clear(opened.Plaintext)
		_, _ = w.Write(response)
	}))
	defer server.Close()
	loopback(t, server.URL)
	reply := must(http.Post(server.URL, "application/json", bytes.NewReader(request)))
	actual := must(io.ReadAll(reply.Body))
	reply.Body.Close()
	if reply.StatusCode != http.StatusOK || !bytes.Equal(actual, response) {
		t.Fatal("real synthetic receipt exchange failed")
	}
	ref := ownerGroupsSettlementReference{request: request, response: actual, bodyDigest: hash(body), route: route}
	step := ownerGroupsSettlementStep{Operation: route.Operation, Body: body, RequestPacket: request,
		ResponsePacket: actual, Settled: true, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	makeState := func() ownerGroupsSettlementState {
		return ownerGroupsSettlementState{Intents: map[string]ownerGroupsSettlementIntent{
			"SYNTHETIC_ORIGINAL_INTENT": {Steps: map[string]ownerGroupsSettlementStep{route.OperationID: step}},
		}}
	}
	path := filepath.Join(t.TempDir(), "node-control-state.json")
	check := func(t *testing.T, state ownerGroupsSettlementState, wantReady, wantError bool) {
		t.Helper()
		writeJSON(t, path, state) // Only this synthetic test producer writes.
		before := must(os.ReadFile(path))
		raw := readNodeControlState(t, path)
		var observed ownerGroupsSettlementState
		if json.Unmarshal(raw, &observed) != nil {
			t.Fatal("synthetic atomic state invalid")
		}
		clear(raw)
		ready, diagnostics, err := ownerGroupsSettlementReady(observed, ref, node, b)
		if ready != wantReady || (err != nil) != wantError {
			t.Fatalf("gate result ready=%t error_present=%t", ready, err != nil)
		}
		if !bytes.Equal(before, must(os.ReadFile(path))) || posts.Load() != 1 {
			t.Fatal("readonly settlement dispatched traffic or changed protected state")
		}
		closed := must(json.Marshal(diagnostics))
		for _, sentinel := range [][]byte{body, []byte(route.OperationID), []byte("SYNTHETIC_ORIGINAL_INTENT")} {
			if bytes.Contains(closed, sentinel) {
				t.Fatal("settlement observation exported private contents")
			}
		}
	}
	t.Run("hub_receipt_is_not_local_settlement", func(t *testing.T) {
		s := makeState()
		x := s.Intents["SYNTHETIC_ORIGINAL_INTENT"].Steps[route.OperationID]
		x.Settled, x.ResponsePacket, x.CompletedAt = false, nil, ""
		s.Intents["SYNTHETIC_ORIGINAL_INTENT"].Steps[route.OperationID] = x
		s.PendingOperation, s.PendingOperationID, s.PendingSequence = route.Operation, route.OperationID, route.Sequence
		s.PendingPacket, s.PendingPlaintextDigest, s.PendingLocalEndpointIntentID = request, hash(body), "SYNTHETIC_ORIGINAL_INTENT"
		check(t, s, false, false)
	})
	t.Run("authenticated_original_local_receipt", func(t *testing.T) { check(t, makeState(), true, false) })
	t.Run("unsettled_or_changed_original", func(t *testing.T) {
		for _, mutation := range []func(*ownerGroupsSettlementStep){
			func(s *ownerGroupsSettlementStep) { s.Settled = false },
			func(s *ownerGroupsSettlementStep) { s.Body = []byte(`{"synthetic":"different"}`) },
			func(s *ownerGroupsSettlementStep) { s.RequestPacket = append(bytes.Clone(request), 'x') },
			func(s *ownerGroupsSettlementStep) { s.ResponsePacket = append(bytes.Clone(actual), 'x') },
			func(s *ownerGroupsSettlementStep) { s.CompletedAt = "invalid" },
		} {
			s := makeState()
			x := step
			mutation(&x)
			s.Intents["SYNTHETIC_ORIGINAL_INTENT"].Steps[route.OperationID] = x
			check(t, s, false, x.Settled)
		}
	})
	t.Run("pending_and_retained_execution_fence", func(t *testing.T) {
		for _, set := range []func(*ownerGroupsSettlementState){
			func(s *ownerGroupsSettlementState) { s.PendingOperation = route.Operation },
			func(s *ownerGroupsSettlementState) { s.PendingOperationID = route.OperationID },
			func(s *ownerGroupsSettlementState) { s.PendingSequence = route.Sequence },
			func(s *ownerGroupsSettlementState) { s.PendingPlaintextDigest = hash(body) },
			func(s *ownerGroupsSettlementState) { s.PendingPacket = request },
			func(s *ownerGroupsSettlementState) { s.PendingResponsePacket = actual },
			func(s *ownerGroupsSettlementState) { s.PendingLocalEndpointIntentID = "SYNTHETIC_ORIGINAL_INTENT" },
			func(s *ownerGroupsSettlementState) { s.PendingNativePairBody = []byte("synthetic") },
			func(s *ownerGroupsSettlementState) { s.PendingWorkerID = "synthetic" },
			func(s *ownerGroupsSettlementState) { s.PendingWorkerAttempt = 1 },
			func(s *ownerGroupsSettlementState) { s.PendingSnapshotPath = "synthetic" },
			func(s *ownerGroupsSettlementState) { s.PendingSnapshotManifest = json.RawMessage(`{}`) },
			func(s *ownerGroupsSettlementState) { s.ClaimTicket = json.RawMessage(`{}`) },
			func(s *ownerGroupsSettlementState) { s.NativePairDiagnostic = json.RawMessage(`{}`) },
			func(s *ownerGroupsSettlementState) { s.EndpointGroupsDiagnostic = json.RawMessage(`{}`) },
		} {
			s := makeState()
			set(&s)
			check(t, s, false, false)
		}
	})
	t.Run("valid_signature_wrong_sequence", func(t *testing.T) {
		otherRoute := reverse
		otherRoute.Sequence++
		wrong := must(nodewire.SealResponse(hub, node.Public(), b, otherRoute, plain))
		other := ref
		other.response = wrong
		s := makeState()
		x := step
		x.ResponsePacket = wrong
		s.Intents["SYNTHETIC_ORIGINAL_INTENT"].Steps[route.OperationID] = x
		ready, _, err := ownerGroupsSettlementReady(s, other, node, b)
		if ready || err == nil {
			t.Fatal("authenticated different response sequence satisfied original settlement")
		}
	})
}
