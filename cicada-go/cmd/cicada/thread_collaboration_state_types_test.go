package main

import (
	"context"
	"errors"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"reflect"
	"testing"
)

func TestThreadCollaborationGenericRecoveryRetainsOriginal(t *testing.T) {
	for _, op := range wire.ThreadCollaborationNativeOperations() {
		t.Run(op, func(t *testing.T) {
			c := &machineNodeControlClient{state: machineNodeControlState{Sequence: 7, PendingOperation: op, PendingOperationID: "synthetic-original", PendingSequence: 7, PendingPacket: []byte("SYNTHETIC retained exact original")}}
			before := cloneMachineNodeControlState(c.state)
			if err := c.recoverPending(context.Background(), "synthetic-no-transport"); !errors.Is(err, errMachineNodeControlOutcomeUncertain) {
				t.Fatal("generic recovery treated a scoped original as a terminal result", err)
			}
			if !reflect.DeepEqual(c.state, before) {
				t.Fatal("generic recovery changed pending identity, sequence or packet")
			}
			if err := c.call(context.Background(), "synthetic-no-transport", "node.binding.status", map[string]string{}, nil); !errors.Is(err, errMachineNodeControlOutcomeUncertain) {
				t.Fatal("ordinary call touched a scoped pending original", err)
			}
			if !reflect.DeepEqual(c.state, before) {
				t.Fatal("ordinary call changed the scoped pending original")
			}
		})
	}
}
func TestThreadCollaborationRollbackCloneRetainsPacketBytes(t *testing.T) {
	state := machineNodeControlState{ThreadCollaborationOriginals: map[string]machineThreadCollaborationOriginal{"synthetic-key": {Operation: wire.OperationGroupLocksAcquire, State: "UNKNOWN", Body: []byte(`{"synthetic":true}`), RequestPacket: []byte("SYNTHETIC original request"), ResponsePacket: []byte("SYNTHETIC original response")}}}
	rollback := cloneMachineNodeControlState(state)
	changed := state.ThreadCollaborationOriginals["synthetic-key"]
	changed.Body[0] = 'x'
	changed.RequestPacket[0] = 'x'
	changed.ResponsePacket[0] = 'x'
	state.ThreadCollaborationOriginals["synthetic-key"] = changed
	old := rollback.ThreadCollaborationOriginals["synthetic-key"]
	if old.Body[0] != '{' || old.RequestPacket[0] != 'S' || old.ResponsePacket[0] != 'S' {
		t.Fatal("uncommitted state changes overwrote rollback original evidence")
	}
}
