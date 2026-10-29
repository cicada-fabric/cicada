package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

func machineNodePairScopedTypedBody(op string, raw []byte) (any, error) {
	out := wire.NewNodePairTrustScopedRequestBody(op)
	if out == nil || machineNodePairStrictJSON(raw, out) != nil {
		return nil, errMachineNodePairState
	}
	return reflect.ValueOf(out).Elem().Interface(), nil
}
func machineNodePairScopedIssued(body any) string {
	switch b := body.(type) {
	case wire.NodePairTrustScopedStart:
		return b.IssuedAt
	case wire.NodePairTrustScopedExistingStart:
		return b.IssuedAt
	case wire.NodePairTrustScopedCommit:
		return b.IssuedAt
	case wire.NodePairTrustScopedACK:
		return b.IssuedAt
	}
	return ""
}
func newMachineNodePairScopedRequest(stateDir string, node *e2ee.Identity, s *machineNodePairScopedState, hub wire.HubIdentity, op string, body any) error {
	if s.PendingOperation != "" || len(s.PendingPacket) != 0 {
		return errMachineNodePairState
	}
	id, e := wire.NewRequestID()
	if e != nil {
		return e
	}
	packet, e := wire.SealNodePairTrustScopedRequest(node, hub, wire.NodePairTrustScopedPacket{Operation: op, RequestID: id, AttemptID: s.AttemptID}, body, time.Now().UTC())
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
	return saveMachineNodePairScopedState(stateDir, node, s)
}
func machineNodePairScopedPOST(ctx context.Context, client *http.Client, origin, op string, raw []byte) ([]byte, error) {
	if err := machineNodePairScopedAvailable(ctx, client, origin); err != nil {
		return nil, err
	}
	path := wire.NodePairTrustScopedHTTPPath(op)
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
	limit := wire.MaxNodePairTrustScopedResponsePacketBytes
	if op == wire.OperationNodePairTrustScopedReconcile {
		limit = wire.MaxNodePairTrustScopedReconcileResponsePacketBytes
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
func sendMachineNodePairScopedPending(ctx context.Context, stateDir string, node *e2ee.Identity, s *machineNodePairScopedState, d hubtransport.Descriptor, client *http.Client) (wire.NodePairTrustScopedResult, []byte, error) {
	return sendOrObserveMachineNodePairScopedPending(ctx, stateDir, node, s, d, client, false)
}
func sendOrObserveMachineNodePairScopedPending(ctx context.Context, stateDir string, node *e2ee.Identity, s *machineNodePairScopedState, d hubtransport.Descriptor, client *http.Client, observeOnly bool) (wire.NodePairTrustScopedResult, []byte, error) {
	body, e := machineNodePairScopedTypedBody(s.PendingOperation, s.PendingBody)
	if e != nil {
		return wire.NodePairTrustScopedResult{}, nil, e
	}
	now := time.Now().UTC()
	at, e := time.Parse(time.RFC3339Nano, machineNodePairScopedIssued(body))
	if e != nil {
		return wire.NodePairTrustScopedResult{}, nil, errMachineNodePairState
	}
	if !observeOnly && !now.After(at.Add(50*time.Second)) {
		raw, e := machineNodePairScopedPOST(ctx, client, d.Claims.Origin, s.PendingOperation, s.PendingPacket)
		if e != nil {
			return wire.NodePairTrustScopedResult{}, nil, e
		}
		r, e := wire.OpenNodePairTrustScopedResponse(node, d.Claims.Hub, s.PendingPacket, raw, body)
		if e != nil {
			return wire.NodePairTrustScopedResult{}, nil, errMachineNodePairState
		}
		return r, raw, nil
	}
	if s.ReconcileBody == nil || func() bool {
		at, e := time.Parse(time.RFC3339Nano, s.ReconcileBody.IssuedAt)
		return e != nil || now.After(at.Add(50*time.Second))
	}() {
		b := wire.NodePairTrustScopedReconcile{Format: wire.NodePairTrustScopedFormat, OriginalPacket: append([]byte(nil), s.PendingPacket...), OriginalPacketDigest: wire.NodePairTrustScopedPacketDigest(s.PendingPacket), IssuedAt: now.Format(time.RFC3339Nano)}
		id, e := wire.NewRequestID()
		if e != nil {
			return wire.NodePairTrustScopedResult{}, nil, e
		}
		raw, e := wire.SealNodePairTrustScopedRequest(node, d.Claims.Hub, wire.NodePairTrustScopedPacket{Operation: wire.OperationNodePairTrustScopedReconcile, RequestID: id, AttemptID: s.AttemptID}, b, now)
		if e != nil {
			return wire.NodePairTrustScopedResult{}, nil, errMachineNodePairState
		}
		s.ReconcileBody = &b
		s.ReconcilePacket = raw
		if e = saveMachineNodePairScopedState(stateDir, node, s); e != nil {
			return wire.NodePairTrustScopedResult{}, nil, e
		}
	}
	raw, e := machineNodePairScopedPOST(ctx, client, d.Claims.Origin, wire.OperationNodePairTrustScopedReconcile, s.ReconcilePacket)
	if e != nil {
		return wire.NodePairTrustScopedResult{}, nil, e
	}
	r, e := wire.OpenNodePairTrustScopedResponse(node, d.Claims.Hub, s.ReconcilePacket, raw, *s.ReconcileBody)
	if e != nil {
		return wire.NodePairTrustScopedResult{}, nil, errMachineNodePairState
	}
	if r.State == wire.NodePairTrustScopedFenced && r.ErrorCode == "FENCED" {
		return r, raw, nil
	}
	r, receipt, e := wire.OpenNodePairTrustScopedRecoveredResponse(node, d.Claims.Hub, s.ReconcilePacket, raw, *s.ReconcileBody, body)
	if e != nil {
		return wire.NodePairTrustScopedResult{}, nil, errMachineNodePairState
	}
	return r, receipt, nil
}
func clearMachineNodePairScopedPending(s *machineNodePairScopedState) {
	s.PendingOperation = ""
	s.PendingPacket = nil
	clear(s.PendingBody)
	s.PendingBody = nil
	s.ReconcilePacket = nil
	s.ReconcileBody = nil
}
