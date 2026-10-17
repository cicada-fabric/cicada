package hubauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/store"
)

var ErrAppNodeCounterConflict = errors.New("COUNTER_CONFLICT")

// This constructor is used only by explicit --hub-nodes-only composition.
// Ordinary Hub/account and Control modes never enable new N3 admissions.
func NewServiceWithNodeAuthority(db *store.Store, ids hubidentity.Set) (*Service, error) {
	s, err := NewService(db, ids)
	if err != nil {
		return nil, err
	}
	s.appNodeAuthority = true
	return s, nil
}

func (s *Service) AppNodeCapabilities() (wire.AppNodeCapabilities, error) {
	if s == nil || !s.appNodeAuthority {
		return wire.AppNodeCapabilities{}, ErrAuthentication
	}
	setup, err := s.db.GetHubOwnerSetup()
	if err != nil || setup == nil {
		return wire.AppNodeCapabilities{}, ErrAuthentication
	}
	policy := wire.AppNodeTransportHTTPS
	if setup.AllowLoopbackHTTP {
		policy = wire.AppNodeTransportLoopbackTest
	}
	return wire.AppNodeCapabilities{Format: wire.AppNodeCapabilitiesFormat, ContractRevision: wire.AppNodeContractRevision, ServeMode: "--hub-nodes-only", Available: true, HTTPOperations: []string{wire.OperationAppNodePrepare, wire.OperationAppNodeComplete, wire.OperationAppNodeStatus, wire.OperationAppNodeCancel, wire.OperationAppNodeReconcile}, Profiles: []string{wire.AppNodeProfileInitial, wire.AppNodeProfileStatus}, RuntimeLeaseSeconds: uint64(wire.AppNodeLeaseLifetime / time.Second), MaxOriginalBytes: wire.MaxAppNodeOriginalBytes, TransportPolicy: policy}, nil
}

func (s *Service) openAppNode(raw []byte, operation string, hub wire.HubIdentity, trusted e2ee.PublicIdentity) (store.HubAppNodeAuthorityInput, store.HubAppNodeSeal, error) {
	p, err := wire.PreflightRequest(raw, operation)
	if err != nil {
		return store.HubAppNodeAuthorityInput{}, nil, ErrAuthentication
	}
	r := p.Packet.Route
	binding, expected, err := wire.RequestRoute(hub, r.OwnerID, r.DeviceID, r.OperationID, operation, wire.HandshakeEpoch, trusted)
	if err != nil || r != expected || !reflect.DeepEqual(p.SenderPublicIdentity, trusted) {
		return store.HubAppNodeAuthorityInput{}, nil, ErrAuthentication
	}
	var out any
	switch operation {
	case wire.OperationAppNodePrepare:
		out = &wire.AppNodePrepare{}
	case wire.OperationAppNodeComplete:
		out = &wire.AppNodeComplete{}
	case wire.OperationAppNodeStatus:
		out = &wire.AppNodeStatusRequest{}
	case wire.OperationAppNodeCancel:
		out = &wire.AppNodeCancel{}
	case wire.OperationAppNodeReconcile:
		out = &wire.AppNodeReconcileRequest{}
	default:
		return store.HubAppNodeAuthorityInput{}, nil, ErrAuthentication
	}
	// Authenticate retained packets without current-time admission here. Store
	// owns freshness/current authority atomically, including aged read settlement
	// and original mutation rejection fencing after response loss.
	if err = wire.OpenRequestAt(s.ids.ClientControl, &trusted, binding, r, raw, out, time.Time{}); err != nil {
		return store.HubAppNodeAuthorityInput{}, nil, ErrAuthentication
	}
	in := store.HubAppNodeAuthorityInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), Device: trusted, Packet: raw, Body: reflect.ValueOf(out).Elem().Interface(), Now: s.requestTime}
	seal := func(body any) ([]byte, error) { return wire.SealResponse(s.ids.ClientControl, trusted, r, body) }
	return in, seal, nil
}

func clearAppNodeBody(body any) {
	switch r := body.(type) {
	case wire.AppNodePrepare:
		clear(r.SessionToken)
		clear(r.OwnerIntent)
	case wire.AppNodeComplete:
		clear(r.SessionToken)
		clear(r.OwnerGrant)
	case wire.AppNodeCancel:
		clear(r.SessionToken)
	case wire.AppNodeStatusRequest:
		clear(r.SessionToken)
	}
}

func appNodeServiceError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, store.ErrHubOwnerDiagnosticsFull) {
		return ErrBusy
	}
	if errors.Is(err, store.ErrClientRequestSequence) || errors.Is(err, store.ErrClientRequestStateConflict) || errors.Is(err, store.ErrClientRequestConflict) {
		return ErrAppNodeCounterConflict
	}
	return ErrAuthentication
}

func (s *Service) handleAppNode(ctx context.Context, operation string, raw []byte) ([]byte, error) {
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
	in, seal, err := s.openAppNode(raw, operation, hub, device.Public)
	if err != nil {
		return nil, err
	}
	defer clearAppNodeBody(in.Body)
	if req, ok := in.Body.(wire.AppNodeReconcileRequest); ok {
		switch req.OriginalKind {
		case wire.AppNodeOriginalAuthority:
			original, err := wire.DecodePacket(req.OriginalPacket)
			if err != nil || !wire.AppNodeReconcileOriginalAllowed(req.OriginalKind, original.Packet.Route.Operation) {
				return nil, ErrAuthentication
			}
			o, originalSeal, err := s.openAppNode(req.OriginalPacket, original.Packet.Route.Operation, hub, device.Public)
			if err != nil {
				return nil, err
			}
			defer clearAppNodeBody(o.Body)
			in.Original, in.OriginalSeal = &o, originalSeal
		case wire.AppNodeOriginalClient:
			o, err := s.openAppNodeClient(req.OriginalPacket, hub, device.Public)
			if err != nil {
				return nil, err
			}
			in.OriginalClient = &o
		default:
			return nil, ErrAuthentication
		}
	}
	packet, err := s.db.ProcessHubAppNodeAuthority(in, seal)
	return packet, appNodeServiceError(err)
}

func (s *Service) openAppNodeClient(raw []byte, hub wire.HubIdentity, trusted e2ee.PublicIdentity) (store.HubAppNodeClientInput, error) {
	if len(raw) == 0 || len(raw) > wire.MaxAppNodeOriginalBytes {
		return store.HubAppNodeClientInput{}, ErrAuthentication
	}
	var p clientwire.Packet
	if json.Unmarshal(raw, &p) != nil || p.Route.Operation != "nodes.confirm" {
		return store.HubAppNodeClientInput{}, ErrAuthentication
	}
	if _, _, err := wire.ParseAppNodeBusinessOperationID(p.Route.OperationID); err != nil {
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

func (s *Service) HandleAppNodeClient(ctx context.Context, raw []byte) ([]byte, error) {
	if s == nil || !s.appNodeAuthority || len(raw) == 0 || len(raw) > wire.MaxAppNodeOriginalBytes {
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
	in, err := s.openAppNodeClient(raw, hub, device.Public)
	if err != nil {
		return nil, err
	}
	packet, err := s.db.ProcessHubAppNodeClient(in)
	return packet, appNodeServiceError(err)
}
