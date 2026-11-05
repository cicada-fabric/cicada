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

func (s *Service) ThreadCollaborationCapabilities(serveMode string) (wire.ThreadCollaborationCapabilities, error) {
	if s == nil || !s.appNodeAuthority {
		return wire.ThreadCollaborationCapabilities{}, ErrAuthentication
	}
	hub, err := s.HubIdentity()
	if err != nil {
		return wire.ThreadCollaborationCapabilities{}, err
	}
	caps, err := wire.NewThreadCollaborationCapabilities(hub, serveMode)
	if err == nil && serveMode == "--hub-nodes-only" {
		caps.ThreadScopeRoleAvailable = true
		caps.GroupLocksAvailable = true
	}
	return caps, err
}

func (s *Service) openThreadCollaboration(raw []byte, operation string, hub wire.HubIdentity, trusted e2ee.PublicIdentity) (store.HubThreadCollaborationInput, store.HubThreadCollaborationSeal, error) {
	p, err := wire.PreflightRequest(raw, operation)
	if err != nil {
		return store.HubThreadCollaborationInput{}, nil, ErrAuthentication
	}
	r := p.Packet.Route
	binding, expected, err := wire.RequestRoute(hub, r.OwnerID, r.DeviceID, r.OperationID, operation, wire.HandshakeEpoch, trusted)
	if err != nil || r != expected || !reflect.DeepEqual(p.SenderPublicIdentity, trusted) {
		return store.HubThreadCollaborationInput{}, nil, ErrAuthentication
	}
	var out any
	switch operation {
	case wire.OperationThreadCollaborationOwnerPrepare:
		out = &wire.ThreadCollaborationOwnerPrepareRequest{}
	case wire.OperationThreadCollaborationOwnerApply:
		out = &wire.ThreadCollaborationOwnerApplyRequest{}
	case wire.OperationThreadCollaborationOwnerStatus:
		out = &wire.ThreadCollaborationOwnerStatusRequest{}
	case wire.OperationThreadCollaborationOwnerRead:
		out = &wire.ThreadCollaborationOwnerReadRequest{}
	case wire.OperationThreadCollaborationOwnerReconcile:
		out = &wire.ThreadCollaborationOwnerReconcileRequest{}
	default:
		return store.HubThreadCollaborationInput{}, nil, ErrAuthentication
	}
	if wire.OpenRequestAt(s.ids.ClientControl, &trusted, binding, r, raw, out, time.Time{}) != nil {
		return store.HubThreadCollaborationInput{}, nil, ErrAuthentication
	}
	in := store.HubThreadCollaborationInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), Device: trusted, Packet: raw, Body: reflect.ValueOf(out).Elem().Interface(), Now: s.requestTime}
	return in, func(body any) ([]byte, error) { return wire.SealResponse(s.ids.ClientControl, trusted, r, body) }, nil
}

func clearThreadCollaborationBody(body any) {
	switch q := body.(type) {
	case wire.ThreadCollaborationOwnerPrepareRequest:
		clear(q.SessionToken)
		clear(q.OwnerProof)
	case wire.ThreadCollaborationOwnerApplyRequest:
		clear(q.SessionToken)
		clear(q.OwnerProof)
	case wire.ThreadCollaborationOwnerStatusRequest:
		clear(q.SessionToken)
		clear(q.OwnerProof)
	case wire.ThreadCollaborationOwnerReadRequest:
		clear(q.SessionToken)
		clear(q.OwnerProof)
	case wire.ThreadCollaborationOwnerReconcileRequest:
		clear(q.Body.OriginalPacket)
		clear(q.SessionToken)
		clear(q.OwnerProof)
	}
}

func (s *Service) handleThreadCollaboration(ctx context.Context, operation string, raw []byte) ([]byte, error) {
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
	in, seal, err := s.openThreadCollaboration(raw, operation, hub, device.Public)
	if err != nil {
		return nil, err
	}
	defer clearThreadCollaborationBody(in.Body)
	if q, ok := in.Body.(wire.ThreadCollaborationOwnerReconcileRequest); ok {
		original, err := wire.DecodeThreadCollaborationOwnerPacket(q.Body.OriginalPacket)
		if err != nil || original.Packet.Route.Operation == wire.OperationThreadCollaborationOwnerReconcile {
			return nil, ErrAuthentication
		}
		o, os, err := s.openThreadCollaboration(q.Body.OriginalPacket, original.Packet.Route.Operation, hub, device.Public)
		if err != nil {
			return nil, err
		}
		defer clearThreadCollaborationBody(o.Body)
		in.Original = &o
		in.OriginalSeal = os
	}
	reply, err := s.db.ProcessHubThreadCollaboration(in, seal)
	if errors.Is(err, store.ErrHubEndpointGroupsPacketConflict) {
		return nil, ErrEndpointGroupsPacketConflict
	}
	if errors.Is(err, store.ErrHubEndpointGroupsOutcomeUncertain) {
		return nil, ErrEndpointGroupsOutcomeUncertain
	}
	return reply, appNodeServiceError(err)
}
