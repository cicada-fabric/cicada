package hubauth

import (
	"context"
	"reflect"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func (s *Service) OwnerEndpointReadCapabilities() (wire.OwnerEndpointReadCapabilities, error) {
	if s == nil {
		return wire.OwnerEndpointReadCapabilities{}, ErrAuthentication
	}
	hub, err := s.HubIdentity()
	if err != nil {
		return wire.OwnerEndpointReadCapabilities{}, err
	}
	fp, err := wire.HubFingerprint(hub)
	if err != nil {
		return wire.OwnerEndpointReadCapabilities{}, err
	}
	return wire.OwnerEndpointReadCapabilities{Format: wire.OwnerEndpointReadCapabilitiesFormat, ContractRevision: wire.OwnerEndpointReadContractRevision,
		Available: s.appNodeAuthority, HubID: hub.HubID, HubFingerprint: fp, MaxPageRows: 64, MaxPageBytes: wire.MaxOwnerEndpointPageBytes, MaxProofSeconds: 60}, nil
}

func (s *Service) handleOwnerEndpointRead(ctx context.Context, raw []byte) ([]byte, error) {
	p, err := wire.PreflightRequest(raw, wire.OperationOwnerEndpointRead)
	if err != nil {
		return nil, ErrAuthentication
	}
	d, err := s.db.GetClientDevice(p.Packet.Route.OwnerID, p.Packet.Route.DeviceID)
	if err != nil || !reflect.DeepEqual(d.Public, p.SenderPublicIdentity) {
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
	r := p.Packet.Route
	binding, expected, err := wire.RequestRoute(hub, r.OwnerID, r.DeviceID, r.OperationID, wire.OperationOwnerEndpointRead, wire.HandshakeEpoch, d.Public)
	if err != nil || r != expected {
		return nil, ErrAuthentication
	}
	var q wire.OwnerEndpointReadRequest
	// Historical request syntax/signature is opened first. Store distinguishes
	// exact retained receipts from fresh, current Owner-signed read authority.
	if wire.OpenRequestAt(s.ids.ClientControl, &d.Public, binding, r, raw, &q, time.Time{}) != nil {
		return nil, ErrAuthentication
	}
	defer clear(q.SessionToken)
	defer clear(q.OwnerProof)
	response, err := s.db.ReadOwnerEndpoints(store.OwnerEndpointReadInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), Device: d.Public, Packet: raw, Request: q, At: s.requestTime(), Now: s.requestTime}, func(body any) ([]byte, error) { return wire.SealResponse(s.ids.ClientControl, d.Public, r, body) })
	return response, appNodeServiceError(err)
}

func (s *Service) NodeOperatorCapabilities() (nodewire.NodeOperatorCapabilities, error) {
	if s == nil {
		return nodewire.NodeOperatorCapabilities{}, ErrAuthentication
	}
	hub, err := s.HubIdentity()
	if err != nil {
		return nodewire.NodeOperatorCapabilities{}, err
	}
	return nodewire.NodeOperatorCapabilities{Format: nodewire.NodeOperatorCapabilitiesFormat, ContractRevision: nodewire.NodeOperatorContractRevision,
		Available: s.appNodeAuthority, HubID: hub.HubID, NodeControlFingerprint: nodewire.IdentityFingerprint(s.ids.NodeControl.Public()), Operations: nodewire.NodeOperatorOperations(), MaxPageRows: 64, MaxPageBytes: nodewire.MaxEndpointDirectoryBytes}, nil
}
