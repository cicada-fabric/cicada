package hubnodes

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func (s *Service) nativePairHubIdentity() (wire.HubIdentity, error) {
	id, err := s.db.GetClientHubID()
	if err != nil {
		return wire.HubIdentity{}, err
	}
	return wire.HubIdentity{Contract: "android-hub-v1", HubID: id, Public: s.ids.ClientControl.Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}, nil
}

func (s *Service) openNativePairNode(credential string, raw []byte) (store.HubNativePairNodeInput, store.HubNativePairNodeSeal, error) {
	p, err := wire.DecodeNativePairNodePacket(raw)
	if err != nil || p.Route.Direction != nodewire.DirectionRequest {
		return store.HubNativePairNodeInput{}, nil, ErrUnavailable
	}
	hub, err := s.nativePairHubIdentity()
	if err != nil {
		return store.HubNativePairNodeInput{}, nil, err
	}
	b, err := s.db.HubNativePairNodeKey(credential, p.Route, hub, s.ids.NodeControl.Public())
	if err != nil {
		return store.HubNativePairNodeInput{}, nil, ErrUnavailable
	}
	opened, err := nodewire.OpenRequest(s.ids.NodeControl, b.NodePublicIdentity, nodeBinding(b), raw)
	if err != nil {
		return store.HubNativePairNodeInput{}, nil, ErrUnavailable
	}
	defer clear(opened.Plaintext)
	body, err := wire.DecodeNativePairNodeRequest(opened.Route.Operation, opened.Plaintext)
	if err != nil {
		return store.HubNativePairNodeInput{}, nil, ErrUnavailable
	}
	in := store.HubNativePairNodeInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), CredentialDigest: credential, Packet: raw, Body: body, Now: time.Now}
	seal := func(out store.HubNativePairNodeOutput) ([]byte, error) {
		response := map[string]any{"ok": out.ErrorCode == "", "operation_id": opened.Route.OperationID, "sequence": opened.Route.Sequence}
		switch {
		case out.ErrorCode != "":
			response["error_code"] = out.ErrorCode
		case out.Description != nil:
			response["result"] = out.Description
		case out.Join != nil:
			response["result"] = s.fabric.NativePairZeroJoinResult(*out.Join)
		case out.Reconciled != nil:
			response["result"] = out.Reconciled
		default:
			return nil, ErrUnavailable
		}
		plaintext, err := json.Marshal(response)
		if err != nil {
			return nil, err
		}
		defer clear(plaintext)
		limit := wire.MaxNativePairNodeReceiptBytes
		if opened.Route.Operation == wire.OperationNativePairNodeReconcile {
			limit = wire.MaxNativePairNodeReconcileBodyBytes
		}
		if len(plaintext) > limit {
			return nil, ErrUnavailable
		}
		r := opened.Route
		r.Direction = nodewire.DirectionResponse
		r.SenderKeyID, r.ReceiverKeyID = r.ReceiverKeyID, r.SenderKeyID
		r.SenderKeyVersion, r.ReceiverKeyVersion = r.ReceiverKeyVersion, r.SenderKeyVersion
		packet, err := nodewire.SealResponse(s.ids.NodeControl, b.NodePublicIdentity, nodeBinding(b), r, plaintext)
		if err != nil {
			return nil, err
		}
		if _, err = wire.DecodeNativePairNodePacket(packet); err != nil {
			return nil, err
		}
		return packet, nil
	}
	return in, seal, nil
}

func (s *Service) nativePairRPC(ctx context.Context, token string, raw []byte) ([]byte, error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	in, seal, err := s.openNativePairNode(fabric.HashSessionCredential(token), raw)
	if err != nil {
		return nil, err
	}
	if q, ok := in.Body.(wire.NativePairNodeReconcile); ok {
		original, originalSeal, e := s.openNativePairNode(in.CredentialDigest, q.OriginalPacket)
		if e != nil {
			return nil, e
		}
		in.Original = &original
		in.OriginalSeal = originalSeal
	}
	if _, ok := in.Body.(wire.NativePairNodeJoin); ok {
		in.SessionToken, _, err = fabric.NewSessionCredential()
		if err != nil {
			return nil, err
		}
	}
	packet, err := s.db.ProcessHubNativePairNode(in, seal)
	if err != nil {
		return nil, ErrUnavailable
	}
	return packet, nil
}
