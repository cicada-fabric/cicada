package hubauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/store"
)

// This constructor is used only by explicit --hub-nodes-only composition.
// Ordinary Hub/account and Control modes never enable new N3 admissions.
func (s *Service) openAppNodeScoped(raw []byte, operation string, hub wire.HubIdentity, trusted e2ee.PublicIdentity) (store.HubAppNodeScopedAuthorityInput, store.HubAppNodeScopedSeal, error) {
	p, err := wire.PreflightRequest(raw, operation)
	if err != nil {
		return store.HubAppNodeScopedAuthorityInput{}, nil, ErrAuthentication
	}
	r := p.Packet.Route
	binding, expected, err := wire.RequestRoute(hub, r.OwnerID, r.DeviceID, r.OperationID, operation, wire.HandshakeEpoch, trusted)
	if err != nil || r != expected || !reflect.DeepEqual(p.SenderPublicIdentity, trusted) {
		return store.HubAppNodeScopedAuthorityInput{}, nil, ErrAuthentication
	}
	var out any
	switch operation {
	case wire.OperationAppNodeScopedPrepare:
		out = &wire.AppNodeScopedPrepare{}
	case wire.OperationAppNodeScopedComplete:
		out = &wire.AppNodeScopedComplete{}
	case wire.OperationAppNodeScopedStatus:
		out = &wire.AppNodeScopedStatus{}
	case wire.OperationAppNodeScopedCancel:
		out = &wire.AppNodeScopedCancel{}
	case wire.OperationAppNodeScopedReconcile:
		out = &wire.AppNodeScopedReconcile{}
	default:
		return store.HubAppNodeScopedAuthorityInput{}, nil, ErrAuthentication
	}
	// Authenticate retained packets without current-time admission here. Store
	// owns freshness/current authority atomically, including aged read settlement
	// and original mutation rejection fencing after response loss.
	if err = wire.OpenRequestAt(s.ids.ClientControl, &trusted, binding, r, raw, out, time.Time{}); err != nil {
		return store.HubAppNodeScopedAuthorityInput{}, nil, ErrAuthentication
	}
	in := store.HubAppNodeScopedAuthorityInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), Device: trusted, Packet: raw, Body: reflect.ValueOf(out).Elem().Interface(), Now: s.requestTime}
	seal := func(body any) ([]byte, error) { return wire.SealResponse(s.ids.ClientControl, trusted, r, body) }
	return in, seal, nil
}

func clearAppNodeScopedBody(body any) {
	switch r := body.(type) {
	case wire.AppNodeScopedPrepare:
		clear(r.SessionToken)
		clear(r.OwnerIntent)
	case wire.AppNodeScopedComplete:
		clear(r.SessionToken)
		clear(r.OwnerGrant)
	case wire.AppNodeScopedCancel:
		clear(r.SessionToken)
	case wire.AppNodeScopedStatus:
		clear(r.SessionToken)
	}
}

func (s *Service) handleAppNodeScoped(ctx context.Context, operation string, raw []byte) ([]byte, error) {
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
	in, seal, err := s.openAppNodeScoped(raw, operation, hub, device.Public)
	if err != nil {
		return nil, err
	}
	defer clearAppNodeScopedBody(in.Body)
	if req, ok := in.Body.(wire.AppNodeScopedReconcile); ok {
		switch req.OriginalKind {
		case wire.AppNodeScopedOriginalAuthority:
			original, err := wire.DecodePacket(req.OriginalPacket)
			if err != nil || !wire.AppNodeScopedReconcileOriginalAllowed(req.OriginalKind, original.Packet.Route.Operation) {
				return nil, ErrAuthentication
			}
			o, originalSeal, err := s.openAppNodeScoped(req.OriginalPacket, original.Packet.Route.Operation, hub, device.Public)
			if err != nil {
				return nil, err
			}
			defer clearAppNodeScopedBody(o.Body)
			in.Original, in.OriginalSeal = &o, originalSeal
		case wire.AppNodeScopedOriginalClient:
			o, err := s.openAppNodeScopedClient(req.OriginalPacket, hub, device.Public)
			if err != nil {
				return nil, err
			}
			in.OriginalClient = &o
		default:
			return nil, ErrAuthentication
		}
	}
	packet, err := s.db.ProcessHubAppNodeScopedAuthority(in, seal)
	return packet, appNodeServiceError(err)
}

func (s *Service) openAppNodeScopedClient(raw []byte, hub wire.HubIdentity, trusted e2ee.PublicIdentity) (store.HubAppNodeClientInput, error) {
	if len(raw) == 0 || len(raw) > wire.MaxAppNodeScopedOriginalBytes {
		return store.HubAppNodeClientInput{}, ErrAuthentication
	}
	var p clientwire.Packet
	if json.Unmarshal(raw, &p) != nil || p.Route.Operation != "nodes.confirm" {
		return store.HubAppNodeClientInput{}, ErrAuthentication
	}
	if _, _, err := wire.ParseAppNodeScopedBusinessOperationID(p.Route.OperationID); err != nil {
		return store.HubAppNodeClientInput{}, ErrAuthentication
	}
	r := p.Route
	binding := clientwire.Binding{HubID: hub.HubID, OwnerID: r.OwnerID, DeviceID: r.DeviceID, SessionEpoch: r.SessionEpoch, HubKeyVersion: hub.KeyVersion, DeviceKeyVersion: wire.DeviceKeyVersion}
	opened, err := clientwire.OpenRequest(s.ids.ClientControl, trusted, binding, raw)
	if err != nil {
		return store.HubAppNodeClientInput{}, ErrAuthentication
	}
	var body struct {
		Code    string `json:"user_code"`
		Digest  string `json:"candidate_digest"`
		Version uint64 `json:"candidate_version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(opened.Plaintext))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil {
		return store.HubAppNodeClientInput{}, ErrAuthentication
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return store.HubAppNodeClientInput{}, ErrAuthentication
	}
	in := store.HubAppNodeClientInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), Device: trusted, Packet: raw, Route: opened.Route, Code: body.Code, CandidateDigest: body.Digest, CandidateVersion: body.Version, Now: s.requestTime}
	in.Seal = func(sequence uint64, id string, result *store.NodeControlKeyBinding, code string) ([]byte, error) {
		wrapper := struct {
			Error       string `json:"error,omitempty"`
			OK          bool   `json:"ok"`
			OperationID string `json:"operation_id"`
			RequestID   string `json:"request_id"`
			Result      any    `json:"result,omitempty"`
		}{Error: code, OK: code == "", OperationID: r.OperationID, RequestID: id}
		if result != nil {
			wrapper.Result = result
		}
		plain, err := json.Marshal(wrapper)
		if err != nil {
			return nil, err
		}
		reply := r
		reply.Direction = clientwire.DirectionResponse
		reply.Sequence = sequence
		reply.SenderKeyID, reply.ReceiverKeyID = r.ReceiverKeyID, r.SenderKeyID
		reply.SenderKeyVersion, reply.ReceiverKeyVersion = r.ReceiverKeyVersion, r.SenderKeyVersion
		return clientwire.SealResponse(s.ids.ClientControl, trusted, binding, reply, plain)
	}
	return in, nil
}

func (s *Service) HandleAppNodeScopedClient(ctx context.Context, raw []byte) ([]byte, error) {
	if !s.ScopedNodeAuthorityEnabled() || len(raw) == 0 || len(raw) > wire.MaxAppNodeScopedOriginalBytes {
		return nil, ErrAuthentication
	}
	var p clientwire.Packet
	if json.Unmarshal(raw, &p) != nil {
		return nil, ErrAuthentication
	}
	device, err := s.db.GetClientDevice(p.Route.OwnerID, p.Route.DeviceID)
	if err != nil {
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
	in, err := s.openAppNodeScopedClient(raw, hub, device.Public)
	if err != nil {
		return nil, err
	}
	packet, err := s.db.ProcessHubAppNodeScopedClient(in)
	return packet, appNodeServiceError(err)
}

// NewServiceWithScopedNodeAuthority is an explicit composition opt-in used by
// isolated carrier qualification. The normal Hub Nodes constructor and CLI
// retain the default availability constant until the combined consumers qualify.
func NewServiceWithScopedNodeAuthority(db *store.Store, ids hubidentity.Set) (*Service, error) {
	s, err := NewServiceWithNodeAuthority(db, ids)
	if err != nil {
		return nil, err
	}
	s.appNodeScopedAuthority = true
	return s, nil
}
func (s *Service) ScopedNodeAuthorityEnabled() bool {
	return s != nil && s.appNodeAuthority && s.appNodeScopedAuthority
}
func (s *Service) AppNodeScopedCapabilities() (wire.AppNodeScopedCapabilities, error) {
	base, err := s.AppNodeCapabilities()
	if err != nil {
		return wire.AppNodeScopedCapabilities{}, err
	}
	caps := wire.AppNodeScopedContractCapabilities(base.TransportPolicy)
	caps.Available = s.ScopedNodeAuthorityEnabled()
	return caps, nil
}
