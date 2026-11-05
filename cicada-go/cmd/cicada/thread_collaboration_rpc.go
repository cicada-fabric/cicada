package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type machineThreadCollaborationEnvelope struct {
	OK               bool                                  `json:"ok"`
	Result           json.RawMessage                       `json:"result"`
	ErrorCode        string                                `json:"error_code,omitempty"`
	OperationID      string                                `json:"operation_id"`
	Sequence         uint64                                `json:"sequence"`
	OriginalEvidence *wire.ThreadCollaborationNodeEvidence `json:"original_evidence,omitempty"`
}

func threadCollaborationOriginalKey(r machineThreadCollaborationOriginal) string {
	raw, _ := json.Marshal(struct {
		Operation string
		Scope     wire.GroupLockScope
		Caller    wire.GroupLockHolder
		ID, Key   string
	}{r.Operation, r.Scope, r.Caller, r.Original.OperationID, r.Original.IdempotencyKey})
	return threadCollaborationPacketDigest(append([]byte("cicada/node-thread-original/v1\x00"), raw...))
}

// The common timestamped inner IDs make retirement safe: after the same
// 24-hour window the Hub refuses executing that old original under any fresh
// carrier. Unknown and currently pending originals are never garbage-collected.
func (c *machineNodeControlClient) gcThreadCollaborationOriginalsLocked(now time.Time) {
	for key, r := range c.state.ThreadCollaborationOriginals {
		if r.State != localThreadCollaborationApplied && r.State != localThreadCollaborationRejectedFenced {
			continue
		}
		if len(c.state.PendingPacket) > 0 && bytes.Equal(c.state.PendingPacket, r.RequestPacket) {
			continue
		}
		created, err := wire.GroupLockOriginalTime(r.Original.OperationID)
		if err == nil && !now.Before(created.Add(wire.GroupLockOriginalRecoverySeconds*time.Second)) {
			delete(c.state.ThreadCollaborationOriginals, key)
		}
	}
}

// Within the Hub's semantic recovery window, a settled local journal entry may
// be evicted under pressure. Its timestamped inner IDs still select the Hub's
// immutable semantic receipt under a fresh carrier; no new business is inferred.
func (c *machineNodeControlClient) evictThreadCollaborationTerminalLocked() bool {
	var selected string
	var oldest time.Time
	for key, r := range c.state.ThreadCollaborationOriginals {
		if r.State != localThreadCollaborationApplied && r.State != localThreadCollaborationRejectedFenced {
			continue
		}
		if len(c.state.PendingPacket) > 0 && bytes.Equal(c.state.PendingPacket, r.RequestPacket) {
			continue
		}
		created, err := wire.GroupLockOriginalTime(r.Original.OperationID)
		if err != nil {
			continue
		}
		if selected == "" || created.Before(oldest) || created.Equal(oldest) && key < selected {
			selected, oldest = key, created
		}
	}
	if selected == "" {
		return false
	}
	delete(c.state.ThreadCollaborationOriginals, selected)
	return true
}

func (c *machineNodeControlClient) makeThreadCollaborationOriginalRoomLocked(now time.Time) bool {
	c.gcThreadCollaborationOriginalsLocked(now)
	for len(c.state.ThreadCollaborationOriginals) >= machineThreadCollaborationOriginalLimit {
		if !c.evictThreadCollaborationTerminalLocked() {
			return false
		}
	}
	return true
}

func threadCollaborationRejectionCode(code string) bool {
	switch code {
	case wire.ThreadCollaborationErrorUnsupported, wire.ThreadCollaborationErrorAuthorizationRequired, wire.ThreadCollaborationErrorSlotInvalid, wire.ThreadCollaborationErrorNetworkConflict, wire.ThreadCollaborationErrorNetworkUnresolved, wire.ThreadCollaborationErrorClassificationRequired, wire.ThreadCollaborationErrorWorkerGroupLimit, wire.ThreadCollaborationErrorPolicyRequired, wire.ThreadCollaborationErrorSlotBusy, wire.ThreadCollaborationErrorVersionConflict, wire.ThreadCollaborationErrorHolderMismatch, wire.ThreadCollaborationErrorGenerationStale, wire.ThreadCollaborationErrorLeaseExpired, wire.ThreadCollaborationErrorOriginalConflict, wire.ThreadCollaborationErrorAtLimit:
		return true
	}
	return false
}

type threadCollaborationOriginalRejection struct{ code string }

func (e *threadCollaborationOriginalRejection) Error() string {
	return e.code + ": exact original Thread collaboration operation was rejected"
}

func (c *machineNodeControlClient) threadCollaborationOriginalLocked(operation string, body any) (string, machineThreadCollaborationOriginal, error) {
	original, endpoint, request, err := threadCollaborationBodyOriginal(body)
	if err != nil {
		return "", machineThreadCollaborationOriginal{}, err
	}
	for key, r := range c.state.ThreadCollaborationOriginals {
		if r.Operation == operation && r.Caller.EndpointID == endpoint && r.Original.OperationID == original.OperationID && r.Original.IdempotencyKey == original.IdempotencyKey {
			plain, e := json.Marshal(body)
			if e != nil || !bytes.Equal(plain, r.Body) || r.Original != original || wire.VerifyGroupLockRequestDigest(operation, r.Caller, request) != nil {
				return "", r, errThreadCollaborationInvalid
			}
			return key, r, nil
		}
	}
	return "", machineThreadCollaborationOriginal{}, errThreadCollaborationInvalid
}

func validateThreadCollaborationRead(operation string, body any, raw json.RawMessage, node, hub string) error {
	switch q := body.(type) {
	case wire.ThreadScopeNodeRead:
		var v wire.ThreadScopeView
		if decodeMachineNodeControlJSON(raw, &v) != nil || wire.ValidateThreadScopeView(v) != nil || v.NodeID != node {
			return errThreadCollaborationInvalid
		}
		if v.State != "NETWORK_CONFLICT" && (v.HubID != hub || v.NetworkID != q.NetworkID || v.EndpointID != q.EndpointID) {
			return errThreadCollaborationInvalid
		}
	case wire.GroupLocksNodeRead:
		var v wire.GroupSlotView
		if decodeMachineNodeControlJSON(raw, &v) != nil || wire.ValidateGroupSlotView(v) != nil || v.Scope != q.Scope {
			return errThreadCollaborationInvalid
		}
	default:
		return errThreadCollaborationInvalid
	}
	return nil
}

func validateThreadCollaborationOriginalEnvelope(r machineThreadCollaborationOriginal, envelope machineThreadCollaborationEnvelope) error {
	e := envelope.OriginalEvidence
	if e == nil || e.Operation != r.Operation || e.Original != r.Original || e.RequestPacketDigest != threadCollaborationPacketDigest(r.RequestPacket) || e.ErrorCode != envelope.ErrorCode {
		return errThreadCollaborationUnknown
	}
	if envelope.OK {
		var receipt wire.GroupLockReceipt
		if e.Outcome != localThreadCollaborationApplied || decodeMachineNodeControlJSON(envelope.Result, &receipt) != nil || validateThreadCollaborationReceipt(r, receipt) != nil {
			return errThreadCollaborationInvalid
		}
	} else if e.Outcome != localThreadCollaborationRejectedFenced || !threadCollaborationRejectionCode(e.ErrorCode) {
		return errThreadCollaborationUnknown
	}
	return nil
}

// Every send, including an exact original replay, uses the existing serialized
// counter and durable pending slot. Unknown HTTP/current-Guard outcomes never
// clear it. A successful reply is validated before either local settlement.
func (c *machineNodeControlClient) callThreadCollaboration(ctx context.Context, token, operation string, body, target any) error {
	if !threadCollaborationNodeOperation(operation) || wire.ValidateThreadCollaborationNodeBody(operation, body) != nil {
		return errThreadCollaborationInvalid
	}
	plain, err := json.Marshal(body)
	if err != nil || len(plain) > wire.MaxThreadCollaborationNodeBodyBytes {
		return errThreadCollaborationInvalid
	}
	digest := threadCollaborationPacketDigest(plain)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.BindingID == "" || c.state.NodeKeyEpoch == 0 || c.state.NodeID != c.nodeID || c.state.NodeKeyID != c.identity.Public().ID || c.state.PendingLocalEndpointIntentID != "" {
		return errThreadCollaborationUnknown
	}
	mutation := threadCollaborationMutation(operation)
	var key string
	var record machineThreadCollaborationOriginal
	if mutation {
		key, record, err = c.threadCollaborationOriginalLocked(operation, body)
		if err != nil {
			return err
		}
	}
	if len(c.state.PendingPacket) > 0 {
		if c.state.PendingOperation != operation || c.state.PendingPlaintextDigest != digest || mutation && len(record.RequestPacket) > 0 && !bytes.Equal(c.state.PendingPacket, record.RequestPacket) {
			return errThreadCollaborationUnknown
		}
	} else {
		previous := cloneMachineNodeControlState(c.state)
		var packet []byte
		var sequence uint64
		var id string
		if mutation && len(record.RequestPacket) > 0 {
			p, e := wire.DecodeThreadCollaborationNodePacket(record.RequestPacket)
			if e != nil || record.NodeBindingID != c.state.BindingID || record.NodeKeyEpoch != c.state.NodeKeyEpoch || p.Route.Sequence != record.Sequence {
				return errThreadCollaborationUnknown
			}
			packet, sequence, id = bytes.Clone(record.RequestPacket), record.Sequence, p.Route.OperationID
		} else {
			if c.state.Sequence >= uint64(1<<63-1) {
				return errLocalEndpointHistoryFull
			}
			sequence = c.state.Sequence + 1
			id, err = newMachineNodeControlOperationID()
			if err != nil {
				return err
			}
			binding := machineNodeControlBindingFromState(c)
			route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: binding.HubID, NodeID: binding.NodeID, BindingID: binding.BindingID, BindingVersion: binding.BindingVersion, NodeKeyEpoch: binding.NodeKeyEpoch, Sequence: sequence, OperationID: id, Operation: operation, SenderKeyID: binding.NodeKey.ID, SenderKeyVersion: binding.NodeKeyVersion, ReceiverKeyID: binding.HubKey.ID, ReceiverKeyVersion: binding.HubKeyVersion}
			packet, err = nodewire.SealRequest(c.identity, binding.HubKey, binding, route, plain)
			if err != nil {
				return err
			}
			if _, err = wire.DecodeThreadCollaborationNodePacket(packet); err != nil {
				return err
			}
			if mutation {
				record.RequestPacket = bytes.Clone(packet)
				record.Sequence = sequence
				record.NodeBindingID = c.state.BindingID
				record.NodeKeyEpoch = c.state.NodeKeyEpoch
				record.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
				c.state.ThreadCollaborationOriginals[key] = record
			}
		}
		if sequence > c.state.Sequence {
			c.state.Sequence = sequence
		}
		c.state.PendingOperation, c.state.PendingOperationID, c.state.PendingSequence = operation, id, sequence
		c.state.PendingPacket, c.state.PendingPlaintextDigest, c.state.PendingResponsePacket = packet, digest, nil
		if err = c.persistLocked(); err != nil {
			c.state = previous
			return err
		}
	}
	response := bytes.Clone(c.state.PendingResponsePacket)
	if len(response) == 0 {
		response, err = c.postPacket(ctx, token, c.state.PendingPacket)
		if err != nil {
			return errors.Join(errThreadCollaborationUnknown, err)
		}
	}
	envelope, err := c.openThreadCollaborationEnvelopeLocked(c.state.PendingPacket, response)
	if err != nil {
		return err
	}
	if mutation {
		if err = validateThreadCollaborationOriginalEnvelope(record, envelope); err != nil {
			return err
		}
	} else if envelope.OK {
		if err = validateThreadCollaborationRead(operation, body, envelope.Result, c.nodeID, c.state.HubID); err != nil {
			return err
		}
	} else if !threadCollaborationRejectionCode(envelope.ErrorCode) {
		return errThreadCollaborationUnknown
	}
	if envelope.OK && target != nil {
		if err = decodeMachineNodeControlJSON(envelope.Result, target); err != nil {
			return fmt.Errorf("invalid typed Thread collaboration response: %w", err)
		}
	}
	previous := cloneMachineNodeControlState(c.state)
	c.state.PendingResponsePacket = bytes.Clone(response)
	if mutation {
		record.ResponsePacket = bytes.Clone(response)
		record.State = envelope.OriginalEvidence.Outcome
		record.Outcome = envelope.OriginalEvidence.Outcome
		record.ErrorCode = envelope.ErrorCode
		record.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		c.state.ThreadCollaborationOriginals[key] = record
	}
	if err = c.persistLocked(); err != nil {
		c.state = previous
		return err
	}
	previous = cloneMachineNodeControlState(c.state)
	c.clearPendingLocked()
	if err = c.persistLocked(); err != nil {
		c.state = previous
		return err
	}
	if !envelope.OK {
		return &threadCollaborationOriginalRejection{envelope.ErrorCode}
	}
	return nil
}

const (
	localThreadCollaborationApplied         = "APPLIED"
	localThreadCollaborationRejectedFenced  = "REJECTED_FENCED"
	localThreadCollaborationUnknown         = "UNKNOWN"
	machineThreadCollaborationOriginalLimit = 128
)

var errThreadCollaborationInvalid = errors.New("THREAD_COLLABORATION_INVALID: exact registered native source and original receipt required")
var errThreadCollaborationUnknown = errors.New("ORIGINAL_OUTCOME_UNCERTAIN: retain the exact Thread collaboration original")

type localThreadCollaborationOriginalEvidence struct {
	Operation            string                           `json:"operation"`
	Original             wire.ThreadCollaborationOriginal `json:"original"`
	RequestPacketDigest  string                           `json:"request_packet_digest"`
	ResponsePacketDigest string                           `json:"response_packet_digest"`
	Outcome              string                           `json:"outcome"`
	ErrorCode            string                           `json:"error_code,omitempty"`
}

func threadCollaborationMutation(operation string) bool {
	return operation == wire.OperationGroupLocksAcquire || operation == wire.OperationGroupLocksRenew || operation == wire.OperationGroupLocksRelease
}

func threadCollaborationBodyOriginal(body any) (wire.ThreadCollaborationOriginal, string, any, error) {
	switch q := body.(type) {
	case wire.GroupLocksNodeAcquire:
		return q.Request.Original, q.EndpointID, q.Request, nil
	case wire.GroupLocksNodeRenew:
		return q.Request.Original, q.EndpointID, q.Request, nil
	case wire.GroupLocksNodeRelease:
		return q.Request.Original, q.EndpointID, q.Request, nil
	}
	return wire.ThreadCollaborationOriginal{}, "", nil, errThreadCollaborationInvalid
}

func threadCollaborationPacketDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func threadCollaborationScopeMatches(view wire.ThreadScopeView, anchor wire.EndpointGroupsRegistrationAnchor) error {
	if wire.ValidateThreadScopeView(view) != nil {
		return errThreadCollaborationInvalid
	}
	if view.State == "NETWORK_CONFLICT" {
		return errors.New(wire.ThreadCollaborationErrorNetworkConflict)
	}
	if view.HubID != anchor.Registration.HubID || view.NetworkID != anchor.NetworkID || view.NodeID != anchor.Registration.NodeID || view.EndpointID != anchor.Registration.EndpointID || view.RegistrationDigest != anchor.RegistrationDigest {
		return errThreadCollaborationInvalid
	}
	return nil
}

// The native caller is supplied by the independently verified registration and
// authenticated scope read. Request JSON never establishes a holder/source.
func threadCollaborationCaller(view wire.ThreadScopeView, anchor wire.EndpointGroupsRegistrationAnchor) (wire.GroupLockHolder, error) {
	if err := threadCollaborationScopeMatches(view, anchor); err != nil {
		return wire.GroupLockHolder{}, err
	}
	if view.State == "CLASSIFICATION_REQUIRED" {
		return wire.GroupLockHolder{}, errors.New(wire.ThreadCollaborationErrorClassificationRequired)
	}
	if view.State != "CURRENT" {
		return wire.GroupLockHolder{}, errors.New(wire.ThreadCollaborationErrorWorkerGroupLimit)
	}
	return wire.GroupLockHolder{NodeID: anchor.Registration.NodeID, EndpointID: anchor.Registration.EndpointID, PrincipalID: anchor.Registration.PrincipalID, Source: view.Source}, nil
}

func validateThreadCollaborationReceipt(record machineThreadCollaborationOriginal, receipt wire.GroupLockReceipt) error {
	body, err := wire.DecodeThreadCollaborationNodeBody(record.Operation, record.Body)
	if err != nil {
		return errThreadCollaborationInvalid
	}
	original, endpoint, request, err := threadCollaborationBodyOriginal(body)
	if err != nil || endpoint != record.Caller.EndpointID || original != record.Original || wire.VerifyGroupLockRequestDigest(record.Operation, record.Caller, request) != nil || wire.ValidateGroupLockReceipt(receipt) != nil {
		return errThreadCollaborationInvalid
	}
	var scope wire.GroupLockScope
	var slot uint8
	var version, generation uint64
	var outcome string
	var ttl *uint32
	switch q := request.(type) {
	case wire.GroupLockAcquireRequest:
		scope, slot, version, outcome, ttl = q.Scope, q.Slot, q.ExpectedVersion, "ACQUIRED", q.TTLSeconds
	case wire.GroupLockRenewRequest:
		scope, slot, version, generation, outcome, ttl = q.Scope, q.Slot, q.ExpectedVersion, q.Generation, "RENEWED", q.TTLSeconds
	case wire.GroupLockReleaseRequest:
		scope, slot, version, generation, outcome = q.Scope, q.Slot, q.ExpectedVersion, q.Generation, "RELEASED"
	}
	if receipt.Scope != scope || receipt.OperationID != original.OperationID || receipt.RequestDigest != original.RequestDigest || receipt.Slot != slot || receipt.Outcome != outcome || receipt.AppliedVersion != version+1 || (generation != 0 && receipt.Generation != generation) {
		return errThreadCollaborationInvalid
	}
	if outcome != "RELEASED" {
		observed, e := time.Parse(time.RFC3339Nano, receipt.ObservedAt)
		if e != nil {
			return errThreadCollaborationInvalid
		}
		expiry, e := wire.GroupLockLeaseExpiry(ttl, observed)
		if e != nil || expiry != receipt.ExpiresAt {
			return errThreadCollaborationInvalid
		}
	}
	return nil
}

// Verify every route coordinate, including binding and both key versions.
func (c *machineNodeControlClient) openThreadCollaborationEnvelopeLocked(original, response []byte) (machineThreadCollaborationEnvelope, error) {
	request, err := wire.DecodeThreadCollaborationNodePacket(original)
	if err != nil {
		return machineThreadCollaborationEnvelope{}, errThreadCollaborationInvalid
	}
	if _, err = wire.DecodeThreadCollaborationNodePacket(response); err != nil {
		return machineThreadCollaborationEnvelope{}, errThreadCollaborationInvalid
	}
	binding := machineNodeControlBindingFromState(c)
	opened, err := nodewire.OpenResponse(c.identity, binding.HubKey, binding, response)
	wanted := request.Route
	wanted.Direction = nodewire.DirectionResponse
	wanted.SenderKeyID, wanted.ReceiverKeyID = wanted.ReceiverKeyID, wanted.SenderKeyID
	wanted.SenderKeyVersion, wanted.ReceiverKeyVersion = wanted.ReceiverKeyVersion, wanted.SenderKeyVersion
	if err != nil || !reflect.DeepEqual(opened.Route, wanted) {
		return machineThreadCollaborationEnvelope{}, errThreadCollaborationInvalid
	}
	var envelope machineThreadCollaborationEnvelope
	if decodeMachineNodeControlJSON(opened.Plaintext, &envelope) != nil || envelope.OperationID != request.Route.OperationID || envelope.Sequence != request.Route.Sequence || envelope.OK && (envelope.ErrorCode != "" || len(envelope.Result) == 0) || !envelope.OK && len(envelope.Result) != 0 {
		return envelope, errThreadCollaborationInvalid
	}
	return envelope, nil
}

// Used by state validation after the existing identity/key binding is loaded.
func validateMachineThreadCollaborationState(s machineNodeControlState, identity *e2ee.Identity) error {
	if len(s.ThreadCollaborationOriginals) > machineThreadCollaborationOriginalLimit {
		return errLocalEndpointHistoryFull
	}
	for id, r := range s.ThreadCollaborationOriginals {
		body, err := wire.DecodeThreadCollaborationNodeBody(r.Operation, r.Body)
		if err != nil {
			return errThreadCollaborationInvalid
		}
		original, endpoint, request, err := threadCollaborationBodyOriginal(body)
		if err != nil || id != threadCollaborationOriginalKey(r) || r.Original != original || endpoint != r.Caller.EndpointID || r.Caller.NodeID != s.NodeID || !localContextHex(r.RegistrationDigest, 64) || wire.VerifyGroupLockRequestDigest(r.Operation, r.Caller, request) != nil {
			return errThreadCollaborationInvalid
		}
		if r.State != localThreadCollaborationUnknown && r.State != localThreadCollaborationApplied && r.State != localThreadCollaborationRejectedFenced {
			return errThreadCollaborationInvalid
		}
		if r.State != localThreadCollaborationUnknown && (len(r.RequestPacket) == 0 || len(r.ResponsePacket) == 0) {
			return errThreadCollaborationInvalid
		}
		if len(r.RequestPacket) > 0 {
			p, e := wire.DecodeThreadCollaborationNodePacket(r.RequestPacket)
			if e != nil || p.Route.Direction != nodewire.DirectionRequest || p.Route.Operation != r.Operation || p.Route.NodeID != s.NodeID || p.Route.BindingID != r.NodeBindingID || p.Route.NodeKeyEpoch != r.NodeKeyEpoch || p.Route.Sequence != r.Sequence || r.Sequence > s.Sequence {
				return errThreadCollaborationInvalid
			}
		}
		if len(r.ResponsePacket) > 0 {
			c := &machineNodeControlClient{identity: identity, state: s}
			envelope, e := c.openThreadCollaborationEnvelopeLocked(r.RequestPacket, r.ResponsePacket)
			if e != nil || validateThreadCollaborationOriginalEnvelope(r, envelope) != nil || envelope.OriginalEvidence.Outcome != r.State {
				return errThreadCollaborationInvalid
			}
		}
	}
	return nil
}
