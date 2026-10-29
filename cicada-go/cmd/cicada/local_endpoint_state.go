package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

const localEndpointIntentTTL = 2 * time.Minute
const maxLocalEndpointMutationIntents = 256
const maxLocalEndpointReadIntents = 64
const localEndpointResponseReserve = 1 << 20

var errLocalEndpointHistoryFull = errors.New("ENDPOINT_LOCAL_HISTORY_FULL: original intents retained; no new operation issued")
var errLocalEndpointIntentConflict = errors.New("ENDPOINT_LOCAL_INTENT_CONFLICT: request ID belongs to another original intent")
var errLocalEndpointReceiptExpired = errors.New("ENDPOINT_LOCAL_RECEIPT_EXPIRED: original action remains fenced; no redispatch")

// Settled intents may expire behind a durable, monotonic admission floor.
// Unknown packets remain retained; an evicted old intent cannot become fresh.
type machineLocalEndpointIntent struct {
	Digest           string                              `json:"digest"`
	Operation        string                              `json:"operation"`
	IssuedAt         string                              `json:"issued_at"`
	Mutation         bool                                `json:"mutation"`
	LocalJoinRefused bool                                `json:"local_join_refused,omitempty"`
	Steps            map[string]machineLocalEndpointStep `json:"steps,omitempty"`
}

type machineLocalEndpointStep struct {
	Operation          string          `json:"operation"`
	Body               json.RawMessage `json:"body"`
	RequestPacket      []byte          `json:"request_packet,omitempty"`
	ResponsePacket     []byte          `json:"response_packet,omitempty"`
	Settled            bool            `json:"settled,omitempty"`
	CompletedAt        string          `json:"completed_at,omitempty"`
	DiagnosticPacket   []byte          `json:"diagnostic_packet,omitempty"`
	DiagnosticResponse []byte          `json:"diagnostic_response,omitempty"`
}

type localEndpointCallKey struct{}
type localEndpointCallScope struct{ IntentID, Digest, StepID string }

func newLocalEndpointRequestID(now time.Time) (string, error) {
	ms := now.UnixMilli()
	if ms <= 0 || ms >= 1<<48 {
		return "", nodewire.ErrEndpointContext
	}
	var random [10]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%012x", ms) + hex.EncodeToString(random[:]), nil
}

func localEndpointIssuedAt(q localEndpointRequest) (time.Time, error) {
	issued, err := time.Parse(time.RFC3339Nano, q.IssuedAt)
	if err != nil || issued.Location() != time.UTC || !localContextHex(q.RequestID, 32) {
		return time.Time{}, nodewire.ErrEndpointContext
	}
	ms, err := strconv.ParseUint(q.RequestID[:12], 16, 48)
	if err != nil || issued.UnixMilli() <= 0 || uint64(issued.UnixMilli()) != ms {
		return time.Time{}, nodewire.ErrEndpointContext
	}
	return issued, nil
}

func localEndpointStepID(id, digest, step string) string {
	sum := sha256.Sum256([]byte("cicada/local-endpoint-step/v1\x00" + id + "\x00" + digest + "\x00" + step))
	return "ncrpc_" + hex.EncodeToString(sum[:16])
}

func cloneMachineLocalEndpointState(state machineNodeControlState) machineNodeControlState {
	if state.LocalEndpointIntents == nil {
		return state
	}
	original := state.LocalEndpointIntents
	state.LocalEndpointIntents = make(map[string]machineLocalEndpointIntent, len(original))
	for id, intent := range original {
		steps := intent.Steps
		intent.Steps = make(map[string]machineLocalEndpointStep, len(steps))
		for k, s := range steps {
			s.Body = bytes.Clone(s.Body)
			s.RequestPacket = bytes.Clone(s.RequestPacket)
			s.ResponsePacket = bytes.Clone(s.ResponsePacket)
			s.DiagnosticPacket = bytes.Clone(s.DiagnosticPacket)
			s.DiagnosticResponse = bytes.Clone(s.DiagnosticResponse)
			intent.Steps[k] = s
		}
		state.LocalEndpointIntents[id] = intent
	}
	return state
}

func localEndpointMutation(operation string) bool {
	return operation == "endpoint_register" || operation == "endpoint_leave" || operation == "native_pair_join_named"
}

func endpointNodeBusinessOperation(operation string) bool {
	return operation == nodewire.EndpointRegisterOperation || operation == nodewire.EndpointLeaveOperation || operation == nodewire.EndpointDirectoryOperation || operation == nodewire.NativePairAvailableOperation
}

func (client *machineNodeControlClient) retainLocalEndpointIntent(q localEndpointRequest, now time.Time) (string, error) {
	return client.retainLocalEndpointIntentAuthenticated(q, now, false)
}

// Only an independently consumed, current invocation bound to this exact
// original may admit an aged, never-admitted local operator intent. Permanent
// request floors and the original timestamp/ID/digest remain unchanged.
func (client *machineNodeControlClient) retainLocalEndpointIntentAuthenticated(q localEndpointRequest, now time.Time, freshOriginal bool) (string, error) {
	if freshOriginal && (q.EndpointGroupsVersion != 1 || q.Operation != "endpoint_register" && q.Operation != "endpoint_leave") {
		return "", errLocalEndpointIntentConflict
	}
	q.InvocationProof = nil
	issued, err := localEndpointIssuedAt(q)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(q)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	client.mu.Lock()
	defer client.mu.Unlock()
	if original, ok := client.state.LocalEndpointIntents[q.RequestID]; ok {
		if original.Digest != digest {
			return "", errLocalEndpointIntentConflict
		}
		return digest, nil
	}
	if issued.UnixMilli() <= client.state.LocalEndpointAdmissionFloorMS || issued.After(now.Add(30*time.Second)) || !now.Before(issued.Add(localEndpointIntentTTL)) && !freshOriginal {
		return "", errors.New("ENDPOINT_LOCAL_INTENT_EXPIRED: no new operation issued")
	}
	previous := cloneMachineNodeControlState(client.state)
	mutations, reads := 0, 0
	for id, intent := range client.state.LocalEndpointIntents {
		t, _ := time.Parse(time.RFC3339Nano, intent.IssuedAt)
		// A prepared step with no packet and no corresponding shared outbox
		// never reached the network. Otherwise only settled steps are safe.
		settled := true
		for _, s := range intent.Steps {
			if !s.Settled && len(s.RequestPacket) > 0 {
				settled = false
			}
		}
		if settled && !now.Before(t.Add(localEndpointIntentTTL)) && client.state.PendingLocalEndpointIntentID != id && !client.localDomainIntentRetainedLocked(id) {
			if t.UnixMilli() > client.state.LocalEndpointAdmissionFloorMS {
				client.state.LocalEndpointAdmissionFloorMS = t.UnixMilli()
			}
			delete(client.state.LocalEndpointIntents, id)
			continue
		}
		if intent.Mutation {
			mutations++
		} else {
			reads++
		}
	}
	if issued.UnixMilli() <= client.state.LocalEndpointAdmissionFloorMS {
		client.state = previous
		return "", errLocalEndpointReceiptExpired
	}
	if localEndpointMutation(q.Operation) && mutations >= maxLocalEndpointMutationIntents || !localEndpointMutation(q.Operation) && reads >= maxLocalEndpointReadIntents {
		client.state = previous
		return "", errLocalEndpointHistoryFull
	}
	if client.state.LocalEndpointIntents == nil {
		client.state.LocalEndpointIntents = make(map[string]machineLocalEndpointIntent)
	}
	client.state.LocalEndpointIntents[q.RequestID] = machineLocalEndpointIntent{Digest: digest, Operation: q.Operation, IssuedAt: q.IssuedAt, Mutation: localEndpointMutation(q.Operation), Steps: make(map[string]machineLocalEndpointStep)}
	if err := client.localEndpointCapacityLocked(); err != nil {
		client.state = previous
		return "", err
	}
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return "", err
	}
	return digest, nil
}

func (client *machineNodeControlClient) localEndpointCapacityLocked() error {
	if endpointGroupsOriginalOperation(client.state.PendingOperation) && len(client.state.PendingPacket) > 0 {
		return client.endpointGroupsPendingCapacityLocked()
	}
	data, err := json.Marshal(client.state)
	if err != nil {
		return err
	}
	if len(data)+localEndpointResponseReserve >= maxMachineNodeControlStateBytes {
		return errLocalEndpointHistoryFull
	}
	return nil
}

// Preparing a step is durable and immutable. In particular a Leave's CAS body
// is saved once, before sending; a lost response can never refresh its digest.
func (client *machineNodeControlClient) prepareLocalEndpointStep(id, digest, step, operation string, body any) (localEndpointCallScope, error) {
	scope := localEndpointCallScope{id, digest, localEndpointStepID(id, digest, step)}
	plain, err := json.Marshal(body)
	if err != nil {
		return scope, err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	intent, ok := client.state.LocalEndpointIntents[id]
	if !ok || intent.Digest != digest {
		return scope, errLocalEndpointIntentConflict
	}
	if intent.LocalJoinRefused && operation == wire.OperationNativePairNodeJoin {
		return scope, errNativePairNodeRejected
	}
	if old, ok := intent.Steps[scope.StepID]; ok {
		if old.Operation != operation || !bytes.Equal(old.Body, plain) {
			return scope, errLocalEndpointIntentConflict
		}
		return scope, nil
	}
	issued, err := time.Parse(time.RFC3339Nano, intent.IssuedAt)
	if err != nil || !time.Now().UTC().Before(issued.Add(localEndpointIntentTTL)) && !(endpointGroupsNodeBusinessOperation(operation) && client.endpointGroupsIntentRetainedLocked(id)) && !(operation == "local.endpoint_groups.operator_result" && client.endpointGroupsLocalOperatorRetainedLocked(id)) {
		return scope, errLocalEndpointReceiptExpired
	}
	previous := cloneMachineNodeControlState(client.state)
	intent.Steps[scope.StepID] = machineLocalEndpointStep{Operation: operation, Body: plain}
	client.state.LocalEndpointIntents[id] = intent
	if err := client.localEndpointCapacityLocked(); err != nil {
		client.state = previous
		return scope, err
	}
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return scope, err
	}
	return scope, nil
}

func (client *machineNodeControlClient) localEndpointStep(id, digest, step string) (machineLocalEndpointStep, bool, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	intent, ok := client.state.LocalEndpointIntents[id]
	if !ok || intent.Digest != digest {
		return machineLocalEndpointStep{}, false, errLocalEndpointIntentConflict
	}
	s, ok := intent.Steps[localEndpointStepID(id, digest, step)]
	s.Body = bytes.Clone(s.Body)
	return s, ok, nil
}

func (client *machineNodeControlClient) callLocalEndpoint(ctx context.Context, token, id, digest, step, operation string, body, target any) error {
	scope, err := client.prepareLocalEndpointStep(id, digest, step, operation, body)
	if err != nil {
		return err
	}
	return client.call(context.WithValue(ctx, localEndpointCallKey{}, scope), token, operation, body, target)
}

func (client *machineNodeControlClient) replayLocalEndpointLocked(scope localEndpointCallScope, operation string, plain []byte, target any) (bool, error) {
	intent, ok := client.state.LocalEndpointIntents[scope.IntentID]
	if !ok || intent.Digest != scope.Digest {
		return true, errLocalEndpointIntentConflict
	}
	if intent.LocalJoinRefused && operation == wire.OperationNativePairNodeJoin {
		return true, errNativePairNodeRejected
	}
	s, ok := intent.Steps[scope.StepID]
	if !ok || s.Operation != operation || !bytes.Equal(s.Body, plain) {
		return true, errLocalEndpointIntentConflict
	}
	if !s.Settled {
		if len(client.state.PendingPacket) == 0 {
			issued, err := time.Parse(time.RFC3339Nano, intent.IssuedAt)
			if err != nil || !time.Now().UTC().Before(issued.Add(localEndpointIntentTTL)) && !(endpointGroupsNodeBusinessOperation(operation) && client.endpointGroupsIntentRetainedLocked(scope.IntentID)) {
				return true, errLocalEndpointReceiptExpired
			}
		}
		return false, nil
	}
	if len(s.ResponsePacket) == 0 {
		return true, errLocalEndpointReceiptExpired
	}
	binding := machineNodeControlBindingFromState(client)
	request, err := nodewire.DecodePacket(s.RequestPacket)
	if err != nil {
		return true, errLocalEndpointIntentConflict
	}
	opened, err := nodewire.OpenResponse(client.identity, binding.HubKey, binding, s.ResponsePacket)
	if err != nil || opened.Route.Operation != operation || opened.Route.OperationID != scope.StepID || opened.Route.Sequence != request.Route.Sequence || request.Route.OperationID != scope.StepID || request.Route.Operation != operation {
		return true, errLocalEndpointIntentConflict
	}
	var env struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		ErrorCode   string          `json:"error_code,omitempty"`
		OperationID string          `json:"operation_id"`
		Sequence    uint64          `json:"sequence"`
	}
	if decodeMachineNodeControlJSON(opened.Plaintext, &env) != nil || env.OperationID != scope.StepID || env.Sequence != request.Route.Sequence {
		return true, errLocalEndpointIntentConflict
	}
	if !env.OK {
		if endpointGroupsNodeBusinessOperation(operation) {
			return true, endpointGroupsNodeRefusal(env.ErrorCode)
		}
		return true, localEndpointTerminalError(env.ErrorCode)
	}
	if target != nil {
		return true, decodeMachineNodeControlJSON(env.Result, target)
	}
	return true, nil
}

func localEndpointTerminalError(code string) error {
	switch code {
	case wire.NativePairNodeJoinFenceCode:
		return errNativePairNodeRejected
	case "RESULT_EXPIRED":
		return errLocalEndpointReceiptExpired
	case "READ_EXPIRED":
		return errLocalEndpointReceiptExpired
	case "LOCAL_DOMAIN_REJECTED", "REJECTED_UNADMITTED":
		return errLocalDomainNodeRejected
	case nodewire.ErrEndpointContext.Error():
		return nodewire.ErrEndpointContext
	case nodewire.ErrEndpointConflict.Error():
		return nodewire.ErrEndpointConflict
	case nodewire.ErrEndpointUnavailable.Error():
		return nodewire.ErrEndpointUnavailable
	default:
		return errors.New("ENDPOINT_LOCAL_AUTHENTICATED_REFUSAL: original operation remains fenced")
	}
}

func (client *machineNodeControlClient) rememberLocalEndpointReceiptLocked(response []byte) error {
	id := client.state.PendingLocalEndpointIntentID
	if id == "" {
		return nil
	}
	intent, ok := client.state.LocalEndpointIntents[id]
	s, exists := intent.Steps[client.state.PendingOperationID]
	if !ok || !exists || s.Operation != client.state.PendingOperation {
		return errLocalEndpointIntentConflict
	}
	sum := sha256.Sum256(s.Body)
	if hex.EncodeToString(sum[:]) != client.state.PendingPlaintextDigest || len(response) > 256<<10 {
		return errLocalEndpointIntentConflict
	}
	s.RequestPacket = bytes.Clone(client.state.PendingPacket)
	s.ResponsePacket = bytes.Clone(response)
	s.Settled = true
	s.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	intent.Steps[client.state.PendingOperationID] = s
	client.state.LocalEndpointIntents[id] = intent
	return nil
}
