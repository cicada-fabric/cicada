package main

import (
	"bytes"
	"encoding/json"
	"strings"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func endpointGroupsOriginalOperation(operation string) bool {
	switch operation {
	case wire.OperationEndpointGroupsNodeDescribe, wire.OperationEndpointGroupsNodeKeyPrepare,
		wire.OperationEndpointGroupsNodeKeyComplete, wire.OperationEndpointGroupsNodeRenew:
		return true
	}
	return false
}

// The page supplies Anchor, Authorities, RelationsRevision, ObservedAt and
// cursor unchanged; its omitted contract/relation-card fields exceed the saved
// cursor tag's extra bytes. Existing pages remain in S. For a first enrollment,
// local receipt coordinates and transcript path are absent from the page, so
// include the largest actual retained lease's metadata, a new registration map
// entry, and one maximum-width preparation-generation entry as well.
func endpointGroupsRegistrationGrowth(s machineNodeControlState) (int, error) {
	const maximum = uint64(1<<63 - 1)
	key := strings.Repeat("f", 32) + ".9223372036854775807.9223372036854775807"
	metadata := func(id string, m machineManagedLocalDomainLease) (int, error) {
		r := machineEndpointGroupsRegistration{LeaseID: id, IntentID: m.IntentID, IntentDigest: m.IntentDigest,
			TranscriptPath: m.TranscriptPath, LocalAccessRevision: maximum, LocallyOffline: true,
			KeyPrepareGenerations: map[string]uint64{key: maximum}}
		raw, err := json.Marshal(map[string]machineEndpointGroupsRegistration{strings.Repeat("0", 64): r})
		return len(raw) + len(`,"endpoint_groups_registrations":`), err
	}
	most, err := metadata("", machineManagedLocalDomainLease{})
	if err != nil {
		return 0, err
	}
	for id, m := range s.ManagedLocalDomainLeases {
		n, err := metadata(id, m)
		if err != nil {
			return 0, err
		}
		if n > most {
			most = n
		}
	}
	return wire.MaxOwnerEndpointGroupsPageBytes + most, nil
}

// Project the actual durable branches before dispatch, including their JSON
// fields and base64 expansion. Packet limits bound authenticated envelopes, not
// just their plaintext: even READ_EXPIRED may carry envelope whitespace up to
// the full reconcile transport limit. Nothing is collected to make room here.
// The caller holds c.mu; this function never changes the live state.
func (c *machineNodeControlClient) endpointGroupsPendingPeakLocked() (int, error) {
	original := c.state.PendingPacket
	packet, err := wire.DecodeEndpointGroupsNodePacket(original)
	if err != nil || !endpointGroupsOriginalOperation(packet.Route.Operation) ||
		packet.Route.Operation != c.state.PendingOperation || packet.Route.OperationID != c.state.PendingOperationID || packet.Route.Sequence != c.state.PendingSequence {
		return 0, errLocalEndpointIntentConflict
	}
	body, err := wire.CanonicalEndpointGroupsNodeRequest(wire.OperationEndpointGroupsNodeReconcile, wire.EndpointGroupsNodeReconcile{OriginalPacket: original})
	if err != nil {
		return 0, err
	}
	route := packet.Route
	route.Operation = wire.OperationEndpointGroupsNodeReconcile
	// The real reconcile ID always has this fixed codec length, independently
	// of whether the original ID came from a local step or the generic RPC.
	route.OperationID = "ncrpc_00000000000000000000000000000000"
	binding := machineNodeControlBindingFromState(c)
	query, err := nodewire.SealRequest(c.identity, binding.HubKey, binding, route, body)
	if err != nil {
		return 0, err
	}
	if _, err := wire.DecodeEndpointGroupsNodePacket(query); err != nil {
		return 0, err
	}
	if d := c.state.EndpointGroupsDiagnostic; d != nil && len(d.Packet) > len(query) {
		// A retained original diagnostic must keep its exact bytes, including
		// any accepted noncanonical whitespace, across a cold reopen.
		query = d.Packet
	}
	receipt := make([]byte, wire.MaxEndpointGroupsNodeReceiptBytes)
	diagnostic := &machineEndpointGroupsDiagnostic{OriginalDigest: nodewire.RecoveryDigest(original),
		OriginalPacket: original, Packet: query, ResponsePacket: make([]byte, wire.MaxEndpointGroupsNodeReconcilePacketBytes)}
	peak := 0
	measure := func(s machineNodeControlState, growth int) error {
		raw, err := json.Marshal(s)
		if err != nil {
			return err
		}
		n := len(raw) + 1 + managedPairStateReserve(s) + growth
		if n > peak {
			peak = n
		}
		return nil
	}
	// Normal response cache, then the completed reconcile cache containing
	// original p, actual sealed query q, outer t and nested receipt r together.
	s := cloneMachineNodeControlState(c.state)
	s.PendingResponsePacket = receipt
	if err := measure(s, 0); err != nil {
		return 0, err
	}
	s.EndpointGroupsDiagnostic = diagnostic
	if err := measure(s, 0); err != nil {
		return 0, err
	}
	settled := machineNodeControlClient{state: cloneMachineNodeControlState(c.state)}
	if id := s.PendingLocalEndpointIntentID; id != "" {
		intent, ok := settled.state.LocalEndpointIntents[id]
		step, exists := intent.Steps[s.PendingOperationID]
		if !ok || !exists || step.Operation != s.PendingOperation {
			return 0, errLocalEndpointIntentConflict
		}
		step.RequestPacket, step.ResponsePacket, step.Settled = original, receipt, true
		step.CompletedAt = "2000-01-01T00:00:00.000000001Z" // maximum UTC RFC3339Nano width
		intent.Steps[s.PendingOperationID] = step
		settled.state.LocalEndpointIntents[id] = intent
	}
	settled.clearPendingLocked()
	growth, err := endpointGroupsRegistrationGrowth(c.state)
	if err != nil {
		return 0, err
	}
	if err := measure(settled.state, growth); err != nil {
		return 0, err
	}
	if s.PendingOperation == wire.OperationEndpointGroupsNodeDescribe || s.PendingOperation == wire.OperationEndpointGroupsNodeKeyPrepare {
		expired := machineNodeControlClient{state: cloneMachineNodeControlState(c.state)}
		expired.state.EndpointGroupsLastReadFence = diagnostic
		if id := s.PendingLocalEndpointIntentID; id != "" {
			intent := expired.state.LocalEndpointIntents[id]
			step := intent.Steps[s.PendingOperationID]
			step.Settled, step.RequestPacket, step.ResponsePacket = true, bytes.Clone(original), nil
			step.DiagnosticPacket, step.DiagnosticResponse = query, diagnostic.ResponsePacket
			intent.Steps[s.PendingOperationID] = step
			expired.state.LocalEndpointIntents[id] = intent
		}
		expired.clearPendingLocked()
		if err := measure(expired.state, 0); err != nil {
			return 0, err
		}
	}
	return peak, nil
}

func (c *machineNodeControlClient) endpointGroupsPendingCapacityLocked() error {
	peak, err := c.endpointGroupsPendingPeakLocked()
	if err != nil {
		return err
	}
	if peak > maxMachineNodeControlStateBytes {
		return errLocalEndpointHistoryFull
	}
	return nil
}
