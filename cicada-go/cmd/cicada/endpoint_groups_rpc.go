package main

import (
	"bytes"
	"context"
	"errors"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func endpointGroupsNodeBusinessOperation(operation string) bool {
	switch operation {
	case wire.OperationEndpointGroupsNodeDescribe, wire.OperationEndpointGroupsNodeKeyPrepare, wire.OperationEndpointGroupsNodeKeyComplete, wire.OperationEndpointGroupsNodeRenew, wire.OperationEndpointGroupsNodeReconcile:
		return true
	}
	return false
}

func endpointGroupsNodeCode(code string) bool {
	switch code {
	case "UNSUPPORTED_PROFILE", "OWNER_AUTHORITY_REQUIRED", "TARGET_NOT_AUTHORIZED", "REVIEW_EXPIRED", "CAS_CONFLICT", "KEY_NOT_READY", "OWNER_READD_REQUIRED", "ORIGINAL_PACKET_CONFLICT", "OUTCOME_UNCERTAIN", "GROUP_RELATION_LIMIT", "SHARED_MEMBERSHIP_CONFLICT", "CURSOR_STALE", "MANUAL_SOURCE_ALREADY_ACTIVE", "RELATION_PENDING", "READ_EXPIRED":
		return true
	}
	return false
}

type endpointGroupsNodeError struct{ code string }

func (e *endpointGroupsNodeError) Error() string {
	return e.code + ": original registered-Thread Group operation was refused"
}
func (e *endpointGroupsNodeError) Unwrap() error {
	switch e.code {
	case "UNSUPPORTED_PROFILE":
		return errEndpointGroupsUnsupported
	case "OUTCOME_UNCERTAIN":
		return errMachineNodeControlOutcomeUncertain
	case "READ_EXPIRED":
		return errLocalEndpointReceiptExpired
	}
	return errEndpointGroupsRegistration
}

func endpointGroupsNodeRefusal(code string) error {
	if !endpointGroupsNodeCode(code) {
		return errors.New("OWNER_ENDPOINT_GROUPS_REJECTED: original operation has no recognized terminal receipt")
	}
	return &endpointGroupsNodeError{code: code}
}

type machineEndpointGroupsDiagnostic struct {
	OriginalDigest string `json:"original_digest"`
	OriginalPacket []byte `json:"original_packet,omitempty"`
	Packet         []byte `json:"packet"`
	ResponsePacket []byte `json:"response_packet,omitempty"`
}

func (c *machineNodeControlClient) openEndpointGroupsEnvelopeLocked(original, response []byte) (machineNativePairEnvelope, error) {
	request, err := wire.DecodeEndpointGroupsNodePacket(original)
	if err != nil {
		return machineNativePairEnvelope{}, err
	}
	if _, err := wire.DecodeEndpointGroupsNodePacket(response); err != nil {
		return machineNativePairEnvelope{}, err
	}
	binding := machineNodeControlBindingFromState(c)
	opened, err := nodewire.OpenResponse(c.identity, binding.HubKey, binding, response)
	wanted := request.Route
	wanted.Direction = nodewire.DirectionResponse
	wanted.SenderKeyID, wanted.ReceiverKeyID = wanted.ReceiverKeyID, wanted.SenderKeyID
	wanted.SenderKeyVersion, wanted.ReceiverKeyVersion = wanted.ReceiverKeyVersion, wanted.SenderKeyVersion
	if err != nil || opened.Route != wanted {
		return machineNativePairEnvelope{}, errEndpointGroupsRegistration
	}
	var envelope machineNativePairEnvelope
	if decodeMachineNodeControlJSON(opened.Plaintext, &envelope) != nil || envelope.OperationID != request.Route.OperationID || envelope.Sequence != request.Route.Sequence ||
		(envelope.OK && (envelope.ErrorCode != "" || len(envelope.Result) == 0)) || (!envelope.OK && (len(envelope.Result) != 0 || !machineNodeControlResponseCodeAllowedFor(request.Route.Operation, envelope.ErrorCode))) {
		return machineNativePairEnvelope{}, errEndpointGroupsRegistration
	}
	return envelope, nil
}

// Recover the sealed original first. A detached, exact-scope query can settle
// only that packet; neither a read failure nor uncertainty creates a new action.
func (c *machineNodeControlClient) recoverEndpointGroupsOriginal(ctx context.Context, token string) error {
	originalError := c.recoverPending(ctx, token)
	if originalError == nil {
		return nil
	}
	c.mu.Lock()
	if !endpointGroupsNodeBusinessOperation(c.state.PendingOperation) || c.state.PendingOperation == wire.OperationEndpointGroupsNodeReconcile || len(c.state.PendingPacket) == 0 {
		c.mu.Unlock()
		return originalError
	}
	err := c.reconcileEndpointGroupsLocked(ctx, token)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return c.recoverPending(ctx, token)
}

func (c *machineNodeControlClient) reconcileEndpointGroupsLocked(ctx context.Context, token string) error {
	original := c.state.PendingPacket
	packet, err := wire.DecodeEndpointGroupsNodePacket(original)
	if err != nil || packet.Route.Operation != c.state.PendingOperation || packet.Route.OperationID != c.state.PendingOperationID || packet.Route.Sequence != c.state.PendingSequence {
		return errEndpointGroupsRegistration
	}
	digest := nodewire.RecoveryDigest(original)
	diagnostic := c.state.EndpointGroupsDiagnostic
	if diagnostic != nil && diagnostic.OriginalDigest != digest {
		return errEndpointGroupsRegistration
	}
	if diagnostic == nil {
		body, err := wire.CanonicalEndpointGroupsNodeRequest(wire.OperationEndpointGroupsNodeReconcile, wire.EndpointGroupsNodeReconcile{OriginalPacket: bytes.Clone(original)})
		if err != nil {
			return err
		}
		route := packet.Route
		route.Operation = wire.OperationEndpointGroupsNodeReconcile
		route.OperationID, err = newMachineNodeControlOperationID()
		if err != nil {
			return err
		}
		binding := machineNodeControlBindingFromState(c)
		sealed, err := nodewire.SealRequest(c.identity, binding.HubKey, binding, route, body)
		if err != nil {
			return err
		}
		if _, err := wire.DecodeEndpointGroupsNodePacket(sealed); err != nil {
			return err
		}
		previous := cloneMachineNodeControlState(c.state)
		diagnostic = &machineEndpointGroupsDiagnostic{OriginalDigest: digest, OriginalPacket: bytes.Clone(original), Packet: sealed}
		c.state.EndpointGroupsDiagnostic = diagnostic
		if err := c.persistLocked(); err != nil {
			c.state = previous
			return err
		}
	}
	response := diagnostic.ResponsePacket
	if len(response) == 0 {
		response, err = c.postPacket(ctx, token, diagnostic.Packet)
		if err != nil {
			return err
		}
	}
	envelope, err := c.openEndpointGroupsEnvelopeLocked(diagnostic.Packet, response)
	if err != nil || !envelope.OK {
		return errMachineNodeControlOutcomeUncertain
	}
	var reconciled wire.EndpointGroupsNodeReconciled
	if decodeMachineNodeControlJSON(envelope.Result, &reconciled) != nil || wire.ValidateEndpointGroupsNodeReconcileTarget(reconciled, original) != nil {
		return errMachineNodeControlOutcomeUncertain
	}
	nested, err := c.openEndpointGroupsEnvelopeLocked(original, reconciled.ReceiptPacket)
	if err != nil || reconciled.State == "COMPLETED" && !nested.OK || reconciled.State == "REJECTED_FENCED" && nested.OK || reconciled.State == "READ_EXPIRED" && (nested.OK || nested.ErrorCode != "READ_EXPIRED" || (reconciled.OriginalOperation != wire.OperationEndpointGroupsNodeDescribe && reconciled.OriginalOperation != wire.OperationEndpointGroupsNodeKeyPrepare)) {
		return errMachineNodeControlOutcomeUncertain
	}
	previous := cloneMachineNodeControlState(c.state)
	diagnostic.ResponsePacket = bytes.Clone(response)
	if err := c.persistLocked(); err != nil {
		c.state = previous
		return err
	}
	previous = cloneMachineNodeControlState(c.state)
	if reconciled.State == "READ_EXPIRED" {
		fence := *diagnostic
		c.state.EndpointGroupsLastReadFence = &fence
		if id := c.state.PendingLocalEndpointIntentID; id != "" {
			intent, ok := c.state.LocalEndpointIntents[id]
			step, exists := intent.Steps[c.state.PendingOperationID]
			if !ok || !exists {
				return errLocalEndpointIntentConflict
			}
			step.Settled = true
			step.RequestPacket = bytes.Clone(original)
			step.ResponsePacket = nil
			step.DiagnosticPacket = bytes.Clone(diagnostic.Packet)
			step.DiagnosticResponse = bytes.Clone(response)
			intent.Steps[c.state.PendingOperationID] = step
			c.state.LocalEndpointIntents[id] = intent
		}
		c.clearPendingLocked()
	} else {
		c.state.PendingResponsePacket = bytes.Clone(reconciled.ReceiptPacket)
	}
	if err := c.persistLocked(); err != nil {
		c.state = previous
		return err
	}
	return nil
}
