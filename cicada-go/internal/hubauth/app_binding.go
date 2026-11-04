package hubauth

import (
	"context"
	"errors"
	"reflect"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/store"
)

func (s *Service) AppBindingCapabilities() (wire.AppBindingCapabilities, error) {
	if s == nil || s.db == nil {
		return wire.AppBindingCapabilities{}, ErrAuthentication
	}
	if _, _, err := s.db.HubAccountSetup(); err != nil {
		return wire.AppBindingCapabilities{}, ErrAuthentication
	}
	return wire.AppBindingContractCapabilities(), nil
}

func (s *Service) handleAppBinding(ctx context.Context, operation string, raw []byte) ([]byte, error) {
	p, err := wire.PreflightRequest(raw, operation)
	if err != nil {
		return nil, ErrAuthentication
	}
	hub, err := s.HubIdentity()
	if err != nil {
		return nil, ErrAuthentication
	}
	setup, _, err := s.db.HubAccountSetup()
	if err != nil {
		return nil, ErrAuthentication
	}
	r := p.Packet.Route
	device := p.SenderPublicIdentity
	if r.HubID != setup.HubID || r.OwnerID != setup.OwnerID {
		return nil, ErrAuthentication
	}
	for _, key := range []string{s.ids.Peer.Public().ID, s.ids.ClientControl.Public().ID, s.ids.NodeControl.Public().ID} {
		if device.ID == key {
			return nil, ErrAuthentication
		}
	}
	binding, route, err := wire.RequestRoute(hub, setup.OwnerID, r.DeviceID, r.OperationID, operation, wire.HandshakeEpoch, device)
	if err != nil || route != r {
		return nil, ErrAuthentication
	}
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	var body any
	switch operation {
	case wire.OperationAppUnbindPrepare:
		body = &wire.AppUnbindPrepare{}
	case wire.OperationAppRebindPrepare:
		body = &wire.AppRebindPrepare{}
	case wire.OperationAppUnbindComplete, wire.OperationAppRebindComplete:
		body = &wire.AppBindingComplete{}
	default:
		return nil, ErrAuthentication
	}
	// Historical opening allows exact receipts and authenticated refusal after
	// expiry. Store repeats live scope and writer-time checks before effects.
	if wire.OpenRequestAt(s.ids.ClientControl, &device, binding, r, raw, body, time.Time{}) != nil {
		return nil, ErrAuthentication
	}
	value := reflect.ValueOf(body).Elem().Interface()
	in := store.HubAppBindingInput{Hub: hub, DevicePublic: device, Operation: operation, Body: value, Packet: raw, Now: s.requestTime,
		Seal: func(v any) ([]byte, error) { return wire.SealResponse(s.ids.ClientControl, device, r, v) },
		VerifyProof: func(p ownerbootstrap.PairingFile, proof []byte, at time.Time) (string, error) {
			return ownerbootstrap.VerifyProof(s.ids.ClientControl, p, proof, at)
		},
		Challenge: func(b wire.AppBinding, clientNonce []byte, at time.Time) (wire.AppBindingChallenge, string, error) {
			pair := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: b.Origin, AllowLoopbackHTTP: setup.AllowLoopbackHTTP, Hub: hub, Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: b.AccountID, OwnerID: b.OwnerID, HubID: b.HubID, AuthorityID: b.PrepareRequestID, OperationID: b.Digest(), CandidatePublic: b.OwnerPublic, CandidateFingerprint: ownerbootstrap.Fingerprint(b.OwnerPublic), ExpiresAt: b.ExpiresAt}}
			pair, ownerNonce, err := ownerbootstrap.CreateChallenge(s.ids.ClientControl, pair, at)
			if err != nil {
				return wire.AppBindingChallenge{}, "", err
			}
			nonce, err := wire.NewNonce()
			if err != nil {
				return wire.AppBindingChallenge{}, "", err
			}
			return wire.AppBindingChallenge{Format: wire.AppBindingChallengeFormat, Operation: operation, RequestID: b.PrepareRequestID, RequestPacketDigest: b.PreparePacketDigest, Binding: b, ClientNonce: clientNonce, ServerNonce: nonce, Proof: pair}, ownerNonce, nil
		},
	}
	packet, err := s.db.ProcessHubAppBinding(in)
	if errors.Is(err, store.ErrHubOwnerDiagnosticsFull) {
		return nil, ErrBusy
	}
	if err != nil {
		return nil, ErrAuthentication
	}
	return packet, nil
}
