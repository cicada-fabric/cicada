package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

var errMachineNodePairPending = errors.New("Owner approval or original pairing response is pending; resume the same Node state")

func machineNodePairTypedBody(op string, raw []byte) (any, error) {
	out := wire.NewNodePairTrustRequestBody(op)
	if out == nil || machineNodePairStrictJSON(raw, out) != nil {
		return nil, errMachineNodePairState
	}
	return reflect.ValueOf(out).Elem().Interface(), nil
}
func machineNodePairIssued(body any) string {
	switch b := body.(type) {
	case wire.NodePairTrustStart:
		return b.IssuedAt
	case wire.NodePairTrustExistingStart:
		return b.IssuedAt
	case wire.NodePairTrustCommit:
		return b.IssuedAt
	case wire.NodePairTrustACK:
		return b.IssuedAt
	}
	return ""
}
func newMachineNodePairRequest(stateDir string, node *e2ee.Identity, s *machineNodePairState, hub wire.HubIdentity, op string, body any) error {
	if s.PendingOperation != "" || len(s.PendingPacket) != 0 {
		return errMachineNodePairState
	}
	id, e := wire.NewRequestID()
	if e != nil {
		return e
	}
	packet, e := wire.SealNodePairTrustRequest(node, hub, wire.NodePairTrustPacket{Operation: op, RequestID: id, AttemptID: s.AttemptID}, body, time.Now().UTC())
	if e != nil {
		return errMachineNodePairState
	}
	raw, e := json.Marshal(body)
	if e != nil {
		return errMachineNodePairState
	}
	s.PendingOperation, s.PendingPacket, s.PendingBody = op, packet, raw
	s.ReconcilePacket = nil
	s.ReconcileBody = nil
	return saveMachineNodePairState(stateDir, node, s)
}
func machineNodePairPOST(ctx context.Context, client *http.Client, origin, op string, raw []byte) ([]byte, error) {
	path := wire.NodePairTrustHTTPPath(op)
	if path == "" {
		return nil, errMachineNodePairState
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	response, e := client.Do(req)
	if e != nil {
		return nil, errMachineNodePairPending
	}
	defer response.Body.Close()
	limit := wire.MaxNodePairTrustResponsePacketBytes
	if op == wire.OperationNodePairTrustReconcile {
		limit = wire.MaxNodePairTrustReconcileResponsePacketBytes
	}
	packet, e := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if e != nil || len(packet) > limit {
		return nil, errMachineNodePairPending
	}
	if response.StatusCode != http.StatusOK {
		return nil, errMachineNodePairPending
	}
	return packet, nil
}

// Aged requests never become fresh dispatch. Only an exact original receipt or
// a no-effect original fence can release this local pending packet. A fence is
// not an attempt terminal state; callers then observe current status.
func sendMachineNodePairPending(ctx context.Context, stateDir string, node *e2ee.Identity, s *machineNodePairState, d hubtransport.Descriptor, client *http.Client) (wire.NodePairTrustResult, []byte, error) {
	return sendOrObserveMachineNodePairPending(ctx, stateDir, node, s, d, client, false)
}
func sendOrObserveMachineNodePairPending(ctx context.Context, stateDir string, node *e2ee.Identity, s *machineNodePairState, d hubtransport.Descriptor, client *http.Client, observeOnly bool) (wire.NodePairTrustResult, []byte, error) {
	body, e := machineNodePairTypedBody(s.PendingOperation, s.PendingBody)
	if e != nil {
		return wire.NodePairTrustResult{}, nil, e
	}
	now := time.Now().UTC()
	at, e := time.Parse(time.RFC3339Nano, machineNodePairIssued(body))
	if e != nil {
		return wire.NodePairTrustResult{}, nil, errMachineNodePairState
	}
	if !observeOnly && !now.After(at.Add(50*time.Second)) {
		raw, e := machineNodePairPOST(ctx, client, d.Claims.Origin, s.PendingOperation, s.PendingPacket)
		if e != nil {
			return wire.NodePairTrustResult{}, nil, e
		}
		r, e := wire.OpenNodePairTrustResponse(node, d.Claims.Hub, s.PendingPacket, raw, body)
		if e != nil {
			return wire.NodePairTrustResult{}, nil, errMachineNodePairState
		}
		return r, raw, nil
	}
	if s.ReconcileBody == nil || func() bool {
		at, e := time.Parse(time.RFC3339Nano, s.ReconcileBody.IssuedAt)
		return e != nil || now.After(at.Add(50*time.Second))
	}() {
		b := wire.NodePairTrustReconcile{Format: wire.NodePairTrustFormat, OriginalPacket: append([]byte(nil), s.PendingPacket...), OriginalPacketDigest: wire.NodePairTrustPacketDigest(s.PendingPacket), IssuedAt: now.Format(time.RFC3339Nano)}
		id, e := wire.NewRequestID()
		if e != nil {
			return wire.NodePairTrustResult{}, nil, e
		}
		raw, e := wire.SealNodePairTrustRequest(node, d.Claims.Hub, wire.NodePairTrustPacket{Operation: wire.OperationNodePairTrustReconcile, RequestID: id, AttemptID: s.AttemptID}, b, now)
		if e != nil {
			return wire.NodePairTrustResult{}, nil, errMachineNodePairState
		}
		s.ReconcileBody = &b
		s.ReconcilePacket = raw
		if e = saveMachineNodePairState(stateDir, node, s); e != nil {
			return wire.NodePairTrustResult{}, nil, e
		}
	}
	raw, e := machineNodePairPOST(ctx, client, d.Claims.Origin, wire.OperationNodePairTrustReconcile, s.ReconcilePacket)
	if e != nil {
		return wire.NodePairTrustResult{}, nil, e
	}
	r, e := wire.OpenNodePairTrustResponse(node, d.Claims.Hub, s.ReconcilePacket, raw, *s.ReconcileBody)
	if e != nil {
		return wire.NodePairTrustResult{}, nil, errMachineNodePairState
	}
	if r.State == wire.NodePairTrustFenced && r.ErrorCode == "FENCED" {
		return r, raw, nil
	}
	r, receipt, e := wire.OpenNodePairTrustRecoveredResponse(node, d.Claims.Hub, s.ReconcilePacket, raw, *s.ReconcileBody, body)
	if e != nil {
		return wire.NodePairTrustResult{}, nil, errMachineNodePairState
	}
	return r, receipt, nil
}
func clearMachineNodePairPending(s *machineNodePairState) {
	s.PendingOperation = ""
	s.PendingPacket = nil
	clear(s.PendingBody)
	s.PendingBody = nil
	s.ReconcilePacket = nil
	s.ReconcileBody = nil
}
