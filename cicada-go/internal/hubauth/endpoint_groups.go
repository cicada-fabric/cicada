package hubauth

import (
	"context"
	"errors"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
	"reflect"
	"time"
)

var ErrEndpointGroupsPacketConflict = errors.New("ORIGINAL_PACKET_CONFLICT")
var ErrEndpointGroupsOutcomeUncertain = errors.New("OUTCOME_UNCERTAIN")

func (s *Service) OwnerEndpointGroupsCapabilities() (wire.OwnerEndpointGroupsCapabilities, error) {
	if s == nil || !s.appNodeAuthority {
		return wire.OwnerEndpointGroupsCapabilities{}, ErrAuthentication
	}
	hub, err := s.HubIdentity()
	if err != nil {
		return wire.OwnerEndpointGroupsCapabilities{}, err
	}
	caps, err := wire.NewOwnerEndpointGroupsCapabilities(hub)
	if err != nil {
		return wire.OwnerEndpointGroupsCapabilities{}, err
	}
	caps.Available = true
	caps.NativeSelfGroups = true
	return caps, nil
}

func (s *Service) openEndpointGroups(raw []byte, operation string, hub wire.HubIdentity, trusted e2ee.PublicIdentity) (store.HubEndpointGroupsInput, store.HubEndpointGroupsSeal, error) {
	p, err := wire.PreflightRequest(raw, operation)
	if err != nil {
		return store.HubEndpointGroupsInput{}, nil, ErrAuthentication
	}
	r := p.Packet.Route
	binding, expected, err := wire.RequestRoute(hub, r.OwnerID, r.DeviceID, r.OperationID, operation, wire.HandshakeEpoch, trusted)
	if err != nil || r != expected || !reflect.DeepEqual(p.SenderPublicIdentity, trusted) {
		return store.HubEndpointGroupsInput{}, nil, ErrAuthentication
	}
	var out any
	switch operation {
	case wire.OperationOwnerEndpointGroupsPrepare:
		out = &wire.OwnerEndpointGroupsPrepareRequest{}
	case wire.OperationOwnerEndpointGroupsApply:
		out = &wire.OwnerEndpointGroupsApplyRequest{}
	case wire.OperationOwnerEndpointGroupsStatus:
		out = &wire.OwnerEndpointGroupsStatusRequest{}
	case wire.OperationOwnerEndpointGroupsRead:
		out = &wire.OwnerEndpointGroupsReadRequest{}
	case wire.OperationOwnerEndpointGroupsReconcile:
		out = &wire.OwnerEndpointGroupsReconcileRequest{}
	default:
		return store.HubEndpointGroupsInput{}, nil, ErrAuthentication
	}
	if wire.OpenRequestAt(s.ids.ClientControl, &trusted, binding, r, raw, out, time.Time{}) != nil {
		return store.HubEndpointGroupsInput{}, nil, ErrAuthentication
	}
	in := store.HubEndpointGroupsInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), Device: trusted, Packet: raw, Body: reflect.ValueOf(out).Elem().Interface(), Now: s.requestTime}
	return in, func(body any) ([]byte, error) { return wire.SealResponse(s.ids.ClientControl, trusted, r, body) }, nil
}

func clearEndpointGroupsBody(body any) {
	switch q := body.(type) {
	case wire.OwnerEndpointGroupsPrepareRequest:
		clear(q.SessionToken)
		clear(q.OwnerProof)
	case wire.OwnerEndpointGroupsApplyRequest:
		clear(q.SessionToken)
		clear(q.OwnerProof)
		clear(q.Body.PolicyProof)
	case wire.OwnerEndpointGroupsStatusRequest:
		clear(q.SessionToken)
		clear(q.OwnerProof)
	case wire.OwnerEndpointGroupsReadRequest:
		clear(q.SessionToken)
		clear(q.OwnerProof)
	case wire.OwnerEndpointGroupsReconcileRequest:
		clear(q.Body.OriginalPacket)
		clear(q.SessionToken)
		clear(q.OwnerProof)
	}
}

func (s *Service) handleEndpointGroups(ctx context.Context, operation string, raw []byte) ([]byte, error) {
	if !s.appNodeAuthority {
		return nil, ErrAuthentication
	}
	p, err := wire.PreflightRequest(raw, operation)
	if err != nil {
		return nil, ErrAuthentication
	}
	device, err := s.db.GetClientDevice(p.Packet.Route.OwnerID, p.Packet.Route.DeviceID)
	if err != nil || !reflect.DeepEqual(device.Public, p.SenderPublicIdentity) {
		return nil, ErrAuthentication
	}
	hub, err := s.HubIdentity()
	if err != nil {
		return nil, ErrAuthentication
	}
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	in, seal, err := s.openEndpointGroups(raw, operation, hub, device.Public)
	if err != nil {
		return nil, err
	}
	defer clearEndpointGroupsBody(in.Body)
	if q, ok := in.Body.(wire.OwnerEndpointGroupsReconcileRequest); ok {
		original, err := wire.DecodeOwnerEndpointGroupsPacket(q.Body.OriginalPacket)
		if err != nil || original.Packet.Route.Operation == wire.OperationOwnerEndpointGroupsReconcile {
			return nil, ErrAuthentication
		}
		o, os, err := s.openEndpointGroups(q.Body.OriginalPacket, original.Packet.Route.Operation, hub, device.Public)
		if err != nil {
			return nil, err
		}
		defer clearEndpointGroupsBody(o.Body)
		in.Original = &o
		in.OriginalSeal = os
	}
	reply, err := s.db.ProcessHubEndpointGroups(in, seal)
	if errors.Is(err, store.ErrHubEndpointGroupsPacketConflict) {
		return nil, ErrEndpointGroupsPacketConflict
	}
	if errors.Is(err, store.ErrHubEndpointGroupsOutcomeUncertain) {
		return nil, ErrEndpointGroupsOutcomeUncertain
	}
	return reply, appNodeServiceError(err)
}
