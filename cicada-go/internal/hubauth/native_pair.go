package hubauth

import (
	"context"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

// The integrated candidate advertises the fixed Hub Nodes pair profile.
// Public discovery does not bypass purpose-specific Owner authorization,
// both consents or the current data-plane Guards.
func (s *Service) NativePairCapabilities() (wire.NativePairCapabilities, error) {
	if s == nil || !s.appNodeAuthority {
		return wire.NativePairCapabilities{}, ErrAuthentication
	}
	setup, err := s.db.GetHubOwnerSetup()
	if err != nil || setup == nil {
		return wire.NativePairCapabilities{}, ErrAuthentication
	}
	policy := wire.AppNodeTransportHTTPS
	if setup.AllowLoopbackHTTP {
		policy = wire.AppNodeTransportLoopbackTest
	}
	return wire.NativePairCapabilities{Format: wire.NativePairFormat, ContractRevision: wire.NativePairContractRevision, Available: true, ServeMode: "--hub-nodes-only", TransportPolicy: policy, HTTPOperations: wire.NativePairHTTPOperations(), NodeOperations: wire.NativePairNodeOperations(), PeerTransport: "SEALED_RELAY", Policy: e2ee.NativePairFixedPeerPolicy()}, nil
}

func (s *Service) openNativePair(raw []byte, operation string, hub wire.HubIdentity, trusted e2ee.PublicIdentity) (store.HubNativePairInput, store.HubNativePairSeal, error) {
	p, err := wire.PreflightRequest(raw, operation)
	if err != nil {
		return store.HubNativePairInput{}, nil, ErrAuthentication
	}
	r := p.Packet.Route
	binding, expected, err := wire.RequestRoute(hub, r.OwnerID, r.DeviceID, r.OperationID, operation, wire.HandshakeEpoch, trusted)
	if err != nil || r != expected || !reflect.DeepEqual(p.SenderPublicIdentity, trusted) {
		return store.HubNativePairInput{}, nil, ErrAuthentication
	}
	var out any
	switch operation {
	case wire.OperationNativePairBootstrapPrepare:
		out = &wire.NativePairBootstrapPrepare{}
	case wire.OperationNativePairBootstrapComplete:
		out = &wire.NativePairBootstrapComplete{}
	case wire.OperationNativePairSlotReject:
		out = &wire.NativePairSlotReject{}
	case wire.OperationNativePairConsentPrepare:
		out = &wire.NativePairConsentPrepare{}
	case wire.OperationNativePairConsentComplete:
		out = &wire.NativePairConsentComplete{}
	case wire.OperationNativePairStatus:
		out = &wire.NativePairStatusRequest{}
	case wire.OperationNativePairRevoke:
		out = &wire.NativePairRevoke{}
	case wire.OperationNativePairReconcile:
		out = &wire.NativePairReconcileRequest{}
	default:
		return store.HubNativePairInput{}, nil, ErrAuthentication
	}
	// Retained originals authenticate structurally here. Transaction time and
	// current authority belong to Store; old proofs are never freshly admitted
	// just because their exact historical packet can still be decrypted.
	if wire.OpenRequestAt(s.ids.ClientControl, &trusted, binding, r, raw, out, time.Time{}) != nil {
		return store.HubNativePairInput{}, nil, ErrAuthentication
	}
	in := store.HubNativePairInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), Device: trusted, Packet: raw, Body: reflect.ValueOf(out).Elem().Interface(), Now: s.requestTime}
	return in, func(body any) ([]byte, error) { return wire.SealResponse(s.ids.ClientControl, trusted, r, body) }, nil
}

func clearNativePairBody(body any) {
	var q wire.NativePairBootstrapPrepare
	switch v := body.(type) {
	case wire.NativePairBootstrapPrepare:
		q = v
	case wire.NativePairBootstrapComplete:
		q = wire.NativePairBootstrapPrepare(v)
	case wire.NativePairSlotReject:
		q = wire.NativePairBootstrapPrepare(v)
	case wire.NativePairConsentPrepare:
		q = wire.NativePairBootstrapPrepare(v)
	case wire.NativePairRevoke:
		q = wire.NativePairBootstrapPrepare(v)
	case wire.NativePairConsentComplete:
		q = wire.NativePairBootstrapPrepare{SessionToken: v.SessionToken, OwnerProof: v.OwnerProof}
		clear(v.GroupKeyProof)
	case wire.NativePairStatusRequest:
		clear(v.SessionToken)
	case wire.NativePairReconcileRequest:
		clear(v.OriginalPacket)
	}
	clear(q.SessionToken)
	clear(q.OwnerProof)
}

func (s *Service) handleNativePair(ctx context.Context, operation string, raw []byte) ([]byte, error) {
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
	in, seal, err := s.openNativePair(raw, operation, hub, device.Public)
	if err != nil {
		return nil, err
	}
	defer clearNativePairBody(in.Body)
	if q, ok := in.Body.(wire.NativePairReconcileRequest); ok {
		original, err := wire.DecodeNativePairPacket(q.OriginalPacket)
		if err != nil || original.Packet.Route.Operation == wire.OperationNativePairReconcile {
			return nil, ErrAuthentication
		}
		o, os, err := s.openNativePair(q.OriginalPacket, original.Packet.Route.Operation, hub, device.Public)
		if err != nil {
			return nil, err
		}
		defer clearNativePairBody(o.Body)
		in.Original = &o
		in.OriginalSeal = os
	}
	reply, err := s.db.ProcessHubNativePair(in, seal)
	return reply, appNodeServiceError(err)
}
