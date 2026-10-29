package n3_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type ownerGroupsSettlementStep struct {
	Operation      string          `json:"operation"`
	Body           json.RawMessage `json:"body"`
	RequestPacket  []byte          `json:"request_packet"`
	ResponsePacket []byte          `json:"response_packet"`
	Settled        bool            `json:"settled"`
	CompletedAt    string          `json:"completed_at"`
}

type ownerGroupsSettlementIntent struct {
	Steps map[string]ownerGroupsSettlementStep `json:"steps"`
}

type ownerGroupsSettlementState struct {
	PendingOperation             string                                       `json:"pending_operation"`
	PendingOperationID           string                                       `json:"pending_operation_id"`
	PendingSequence              uint64                                       `json:"pending_sequence"`
	PendingPlaintextDigest       string                                       `json:"pending_plaintext_digest"`
	PendingPacket                []byte                                       `json:"pending_packet"`
	PendingResponsePacket        []byte                                       `json:"pending_response_packet"`
	PendingLocalEndpointIntentID string                                       `json:"pending_local_endpoint_intent_id"`
	PendingNativePairBody        []byte                                       `json:"pending_native_pair_body"`
	PendingWorkerID              string                                       `json:"pending_worker_id"`
	PendingWorkerAttempt         int                                          `json:"pending_worker_attempt"`
	PendingSnapshotPath          string                                       `json:"pending_snapshot_path"`
	PendingSnapshotManifest      json.RawMessage                              `json:"pending_snapshot_manifest"`
	ClaimTicket                  json.RawMessage                              `json:"claim_ticket"`
	NativePairDiagnostic         json.RawMessage                              `json:"native_pair_diagnostic"`
	EndpointGroupsDiagnostic     json.RawMessage                              `json:"endpoint_groups_diagnostic"`
	Intents                      map[string]ownerGroupsSettlementIntent       `json:"local_endpoint_intents"`
	Registrations                map[string]ownerGroupsSettlementRegistration `json:"endpoint_groups_registrations"`
}

func (s ownerGroupsSettlementState) remaining() map[string]bool {
	present := func(raw json.RawMessage) bool {
		return len(bytes.TrimSpace(raw)) != 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
	}
	return map[string]bool{
		"operation": s.PendingOperation != "", "operation_id": s.PendingOperationID != "", "sequence": s.PendingSequence != 0,
		"plaintext_digest": s.PendingPlaintextDigest != "", "packet": len(s.PendingPacket) != 0, "response": len(s.PendingResponsePacket) != 0,
		"local_intent": s.PendingLocalEndpointIntentID != "", "native_pair_body": len(s.PendingNativePairBody) != 0,
		"worker_id": s.PendingWorkerID != "", "worker_attempt": s.PendingWorkerAttempt != 0, "snapshot_path": s.PendingSnapshotPath != "",
		"snapshot_manifest": present(s.PendingSnapshotManifest), "claim": present(s.ClaimTicket),
		"native_pair_diagnostic": present(s.NativePairDiagnostic), "endpoint_groups_diagnostic": present(s.EndpointGroupsDiagnostic),
	}
}

type ownerGroupsSettlementReference struct {
	request, response []byte
	bodyDigest        string
	route             nodewire.Route
	renewal           *ownerGroupsRenewalReference
}

// This authenticates retained bytes only. It never submits an RPC or writes
// Node state, and a Hub receipt alone cannot satisfy the local-consumption gate.
func ownerGroupsSettlementReady(s ownerGroupsSettlementState, original ownerGroupsSettlementReference, key *e2ee.Identity, binding nodewire.Binding) (bool, map[string]any, error) {
	remaining := s.remaining()
	diagnostic := map[string]any{"remaining": remaining, "pending_sequence": s.PendingSequence,
		"pending_operation_sha256": hash([]byte(s.PendingOperation)), "step_present": false, "step_settled": false}
	var found *ownerGroupsSettlementStep
	var foundIntent string
	for intentID, intent := range s.Intents {
		if step, ok := intent.Steps[original.route.OperationID]; ok {
			if found != nil {
				return false, diagnostic, errors.New("DUPLICATE_ORIGINAL_STEP")
			}
			copy := step
			found = &copy
			foundIntent = intentID
		}
	}
	if found == nil {
		return false, diagnostic, nil
	}
	diagnostic["step_present"], diagnostic["step_settled"] = true, found.Settled
	if found.Operation != original.route.Operation || hash(found.Body) != original.bodyDigest ||
		len(found.RequestPacket) != 0 && !bytes.Equal(found.RequestPacket, original.request) {
		return false, diagnostic, errors.New("ORIGINAL_STEP_CHANGED")
	}
	if !found.Settled {
		return false, diagnostic, nil
	}
	if !bytes.Equal(found.RequestPacket, original.request) || !bytes.Equal(found.ResponsePacket, original.response) {
		return false, diagnostic, errors.New("ORIGINAL_RECEIPT_CHANGED")
	}
	if _, err := time.Parse(time.RFC3339Nano, found.CompletedAt); err != nil {
		return false, diagnostic, errors.New("MISSING_COMPLETION_TIME")
	}
	for _, active := range remaining {
		if active {
			return false, diagnostic, nil
		}
	}
	opened, err := nodewire.OpenResponse(key, binding.HubKey, binding, found.ResponsePacket)
	if err != nil {
		return false, diagnostic, errors.New("LOCAL_RECEIPT_NOT_AUTHENTICATED")
	}
	defer clear(opened.Plaintext)
	want := original.route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = want.ReceiverKeyID, want.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = want.ReceiverKeyVersion, want.SenderKeyVersion
	var reply appPairNodeReply
	if opened.Route != want || json.Unmarshal(opened.Plaintext, &reply) != nil || reply.OperationID != original.route.OperationID || reply.Sequence != original.route.Sequence ||
		reply.OK && (reply.ErrorCode != "" || len(reply.Result) == 0) || !reply.OK && (reply.ErrorCode != "TARGET_NOT_AUTHORIZED" || len(reply.Result) != 0) {
		return false, diagnostic, errors.New("LOCAL_RECEIPT_RESULT_CHANGED")
	}
	diagnostic["response_authenticated"], diagnostic["ok"] = true, reply.OK
	if original.route.Operation == wire.OperationEndpointGroupsNodeRenew {
		ready, renewalDiagnostic, err := ownerGroupsRenewalReady(s, foundIntent, original, reply, key, binding)
		for name, value := range renewalDiagnostic {
			diagnostic[name] = value
		}
		diagnostic["original_registration_converged"] = ready
		return ready, diagnostic, err
	}
	return true, diagnostic, nil
}

func awaitOwnerGroupsNodeSettlement(t *testing.T, v *codexProductFixture, label string, original exchange) {
	t.Helper()
	awaitOwnerGroupsNodeSettlementSince(t, v, label, original, time.Now())
}

func awaitOwnerGroupsNodeSettlementSince(t *testing.T, v *codexProductFixture, label string, original exchange, started time.Time) {
	t.Helper()
	awaitOwnerGroupsSettlementSince(t, v, label, original, started, nil)
}

func awaitOwnerGroupsSettlementSince(t *testing.T, v *codexProductFixture, label string, original exchange, started time.Time, renewal *ownerGroupsRenewalReference) {
	t.Helper()
	key, binding := ownerGroupsNodeAuditIdentity(t, v)
	packet := must(wire.DecodeEndpointGroupsNodePacket(original.request))
	if (packet.Route.Operation != wire.OperationEndpointGroupsNodeKeyComplete && packet.Route.Operation != wire.OperationEndpointGroupsNodeRenew) ||
		(packet.Route.Operation == wire.OperationEndpointGroupsNodeRenew) != (renewal != nil) || original.RequestSHA256 != hash(original.request) {
		t.Fatal("Node settlement lost its captured original completion")
	}
	// Existing request/response audits use only the original independently
	// pinned identities. No current authority is inferred from this receipt.
	body := openOwnerGroupsNodeRequest(t, v, original.request)
	canonical := must(wire.CanonicalEndpointGroupsNodeRequest(packet.Route.Operation, body))
	defer clear(canonical)
	reply := openOwnerGroupsNodeExchange(t, v, original)
	if !reply.OK && (packet.Route.Operation == wire.OperationEndpointGroupsNodeRenew || reply.ErrorCode != "TARGET_NOT_AUTHORIZED") {
		t.Fatal("Node settlement lacks its authenticated expected terminal result")
	}
	reference := ownerGroupsSettlementReference{request: original.request, response: original.response, bodyDigest: hash(canonical), route: packet.Route, renewal: renewal}
	var last map[string]any
	nextLog := started
	for time.Since(started) < 75*time.Second {
		raw := readNodeControlState(t, v.actualNode.statePath())
		var state ownerGroupsSettlementState
		err := json.Unmarshal(raw, &state)
		size := len(raw)
		clear(raw)
		if err != nil {
			t.Fatal("Node settlement atomic snapshot is invalid")
		}
		ready, observed, err := ownerGroupsSettlementReady(state, reference, key, binding)
		last = observed
		last["state_bytes"], last["elapsed_ms"], last["observed_at"] = size, time.Since(started).Milliseconds(), time.Now().UTC().Format(time.RFC3339Nano)
		last["node_running"], last["hub_running"] = v.actualNode.running(), v.f.hub.running()
		if err != nil {
			t.Fatalf("original Node settlement failed closed: label=%s code=%s metadata=%s", label, err, must(json.Marshal(last)))
		}
		if ready && time.Since(started) < 75*time.Second {
			t.Logf("OWNER_GROUPS_NODE_SETTLED label=%s original_sequence=%d operation_sha256=%s request_sha256=%s response_sha256=%s metadata=%s", label, packet.Route.Sequence, hash([]byte(packet.Route.OperationID)), hash(original.request), hash(original.response), must(json.Marshal(last)))
			return
		}
		if !time.Now().Before(nextLog) {
			t.Logf("OWNER_GROUPS_NODE_SETTLEMENT_WAIT label=%s original_sequence=%d metadata=%s", label, packet.Route.Sequence, must(json.Marshal(last)))
			nextLog = time.Now().Add(5 * time.Second)
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("real Node did not settle its exact original completion within 75s: label=%s metadata=%s", label, must(json.Marshal(last)))
}

// Used only before positive MCP expectations while the original Node identity
// remains valid. Post-revocation M7 deliberately permits a denied pending write.
func awaitOwnerGroupsPositiveCompletion(t *testing.T, v *codexProductFixture, from int, label string, identity ownerGroupsIdentity, group string) {
	t.Helper()
	started := time.Now()
	deadline := started.Add(75 * time.Second)
	checked := map[string]bool{}
	for time.Now().Before(deadline) {
		for _, ex := range v.f.proxy.snapshot()[from:] {
			if ex.Path != "/v2/node/control/rpc" || ex.Method != http.MethodPost || !ex.Forwarded || ex.Status != http.StatusOK {
				continue
			}
			packet, err := nodewire.DecodePacket(ex.request)
			if err != nil || packet.Route.Operation != wire.OperationEndpointGroupsNodeKeyComplete || checked[ex.RequestSHA256] {
				continue
			}
			body, ok := openOwnerGroupsNodeRequest(t, v, ex.request).(wire.EndpointGroupsNodeKeyComplete)
			if !ok || body.EndpointID != identity.Endpoint || body.GroupID != group {
				checked[ex.RequestSHA256] = true
				continue
			}
			if !openOwnerGroupsNodeExchange(t, v, ex).OK {
				t.Fatal("pre-revocation positive completion was refused")
			}
			awaitOwnerGroupsNodeSettlementSince(t, v, label, ex, started)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("actual positive original completion was not observed within 75s: label=%s", label)
}
