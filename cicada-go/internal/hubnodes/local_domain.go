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

func (s *Service) openLocalDomainNode(credential string, raw []byte) (store.HubLocalDomainNodeInput, store.HubLocalDomainNodeSeal, error) {
	p, err := wire.DecodeLocalDomainNodePacket(raw)
	if err != nil {
		return store.HubLocalDomainNodeInput{}, nil, ErrUnavailable
	}
	hub, err := s.nativePairHubIdentity()
	if err != nil {
		return store.HubLocalDomainNodeInput{}, nil, ErrUnavailable
	}
	b, err := s.db.HubLocalDomainNodeKey(credential, p.Route, hub, s.ids.NodeControl.Public())
	if err != nil {
		return store.HubLocalDomainNodeInput{}, nil, ErrUnavailable
	}
	opened, err := nodewire.OpenRequest(s.ids.NodeControl, b.NodePublicIdentity, nodeBinding(b), raw)
	if err != nil {
		return store.HubLocalDomainNodeInput{}, nil, ErrUnavailable
	}
	defer clear(opened.Plaintext)
	body, err := wire.DecodeLocalDomainNodeRequest(opened.Route.Operation, opened.Plaintext)
	if err != nil {
		return store.HubLocalDomainNodeInput{}, nil, ErrUnavailable
	}
	in := store.HubLocalDomainNodeInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), CredentialDigest: credential, Packet: raw, Body: body, Now: time.Now}
	seal := func(out store.HubLocalDomainNodeOutput) ([]byte, error) {
		response := map[string]any{"ok": out.ErrorCode == "", "operation_id": opened.Route.OperationID, "sequence": opened.Route.Sequence}
		if out.ErrorCode != "" {
			response["error_code"] = out.ErrorCode
		} else if out.Result != nil {
			response["result"] = out.Result
		} else {
			return nil, ErrUnavailable
		}
		plaintext, err := json.Marshal(response)
		if err != nil {
			return nil, err
		}
		defer clear(plaintext)
		limit := wire.MaxLocalDomainNodeReceiptBytes
		if opened.Route.Operation == wire.OperationLocalDomainNodeReconcile {
			limit = wire.MaxLocalDomainNodeReconcilePacketBytes
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
		if _, err = wire.DecodeLocalDomainNodePacket(packet); err != nil {
			return nil, err
		}
		return packet, nil
	}
	return in, seal, nil
}

func (s *Service) localDomainRPC(ctx context.Context, token string, raw []byte) ([]byte, error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	in, seal, err := s.openLocalDomainNode(fabric.HashSessionCredential(token), raw)
	if err != nil {
		return nil, err
	}
	if q, ok := in.Body.(wire.LocalDomainNodeReconcile); ok {
		original, os, err := s.openLocalDomainNode(in.CredentialDigest, q.OriginalPacket)
		if err != nil {
			return nil, err
		}
		in.Original = &original
		in.OriginalSeal = os
	}
	if _, ok := in.Body.(wire.LocalDomainNodeJoin); ok {
		in.SessionToken, _, err = fabric.NewSessionCredential()
		if err != nil {
			return nil, err
		}
	}
	packet, err := s.db.ProcessHubLocalDomainNode(in, seal)
	if err != nil {
		return nil, ErrUnavailable
	}
	return packet, nil
}
