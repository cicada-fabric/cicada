package hubauth

import (
	"context"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

func (s *Service) LocalDomainCapabilities() (wire.LocalDomainCapabilities, error) {
	if s == nil || !s.appNodeAuthority {
		return wire.LocalDomainCapabilities{}, ErrAuthentication
	}
	setup, err := s.db.GetHubOwnerSetup()
	if err != nil || setup == nil {
		return wire.LocalDomainCapabilities{}, ErrAuthentication
	}
	policy := wire.AppNodeTransportHTTPS
	if setup.AllowLoopbackHTTP {
		policy = wire.AppNodeTransportLoopbackTest
	}
	return wire.LocalDomainCapabilities{Format: wire.LocalDomainFormat, ContractRevision: wire.LocalDomainContractRevision, Available: true, ServeMode: "--hub-nodes-only", TransportPolicy: policy, HTTPOperations: wire.LocalDomainHTTPOperations(), NodeOperations: wire.LocalDomainNodeOperations(), Rights: e2ee.LocalDomainRights(), MaxActivePoliciesPerNodeUser: 1, OptionalPolicyExpiry: true}, nil
}

func (s *Service) openLocalDomain(raw []byte, operation string, hub wire.HubIdentity, trusted e2ee.PublicIdentity) (store.HubLocalDomainInput, store.HubLocalDomainSeal, error) {
	p, err := wire.PreflightRequest(raw, operation)
	if err != nil {
		return store.HubLocalDomainInput{}, nil, ErrAuthentication
	}
	r := p.Packet.Route
	binding, expected, err := wire.RequestRoute(hub, r.OwnerID, r.DeviceID, r.OperationID, operation, wire.HandshakeEpoch, trusted)
	if err != nil || r != expected || !reflect.DeepEqual(p.SenderPublicIdentity, trusted) {
		return store.HubLocalDomainInput{}, nil, ErrAuthentication
	}
	var out any
	switch operation {
	case wire.OperationLocalDomainPrepare:
		out = &wire.LocalDomainPrepare{}
	case wire.OperationLocalDomainActivate:
		out = &wire.LocalDomainActivate{}
	case wire.OperationLocalDomainStatus:
		out = &wire.LocalDomainStatusRequest{}
	case wire.OperationLocalDomainRevoke:
		out = &wire.LocalDomainRevoke{}
	case wire.OperationLocalDomainReconcile:
		out = &wire.LocalDomainReconcileRequest{}
	default:
		return store.HubLocalDomainInput{}, nil, ErrAuthentication
	}
	if wire.OpenRequestAt(s.ids.ClientControl, &trusted, binding, r, raw, out, time.Time{}) != nil {
		return store.HubLocalDomainInput{}, nil, ErrAuthentication
	}
	in := store.HubLocalDomainInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), Device: trusted, Packet: raw, Body: reflect.ValueOf(out).Elem().Interface(), Now: s.requestTime}
	return in, func(body any) ([]byte, error) { return wire.SealResponse(s.ids.ClientControl, trusted, r, body) }, nil
}

func clearLocalDomainBody(body any) {
	switch q := body.(type) {
	case wire.LocalDomainPrepare:
		clear(q.SessionToken)
		clear(q.OwnerProof)
	case wire.LocalDomainActivate:
		clear(q.SessionToken)
		clear(q.OwnerProof)
		clear(q.PolicyProof)
	case wire.LocalDomainStatusRequest:
		clear(q.SessionToken)
		clear(q.OwnerProof)
	case wire.LocalDomainRevoke:
		clear(q.SessionToken)
		clear(q.OwnerProof)
	case wire.LocalDomainReconcileRequest:
		clear(q.OriginalPacket)
	}
}

func (s *Service) handleLocalDomain(ctx context.Context, operation string, raw []byte) ([]byte, error) {
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
	in, seal, err := s.openLocalDomain(raw, operation, hub, device.Public)
	if err != nil {
		return nil, err
	}
	defer clearLocalDomainBody(in.Body)
	if q, ok := in.Body.(wire.LocalDomainReconcileRequest); ok {
		original, err := wire.DecodeLocalDomainPacket(q.OriginalPacket)
		if err != nil || original.Packet.Route.Operation == wire.OperationLocalDomainReconcile {
			return nil, ErrAuthentication
		}
		o, os, err := s.openLocalDomain(q.OriginalPacket, original.Packet.Route.Operation, hub, device.Public)
		if err != nil {
			return nil, err
		}
		defer clearLocalDomainBody(o.Body)
		in.Original = &o
		in.OriginalSeal = os
	}
	reply, err := s.db.ProcessHubLocalDomain(in, seal)
	return reply, appNodeServiceError(err)
}
