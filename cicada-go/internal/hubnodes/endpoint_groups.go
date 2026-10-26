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

func (s *Service) openEndpointGroupsNode(credential string, raw []byte) (store.HubEndpointGroupsNodeInput, store.HubEndpointGroupsNodeSeal, error) {
	p, err := wire.DecodeEndpointGroupsNodePacket(raw)
	if err != nil {
		return store.HubEndpointGroupsNodeInput{}, nil, ErrUnavailable
	}
	hub, err := s.nativePairHubIdentity()
	if err != nil {
		return store.HubEndpointGroupsNodeInput{}, nil, ErrUnavailable
	}
	b, err := s.db.HubLocalDomainNodeKey(credential, p.Route, hub, s.ids.NodeControl.Public())
	if err != nil {
		return store.HubEndpointGroupsNodeInput{}, nil, ErrUnavailable
	}
	opened, err := nodewire.OpenRequest(s.ids.NodeControl, b.NodePublicIdentity, nodeBinding(b), raw)
	if err != nil {
		return store.HubEndpointGroupsNodeInput{}, nil, ErrUnavailable
	}
	defer clear(opened.Plaintext)
	body, err := wire.DecodeEndpointGroupsNodeRequest(opened.Route.Operation, opened.Plaintext)
	if err != nil {
		return store.HubEndpointGroupsNodeInput{}, nil, ErrUnavailable
	}
	in := store.HubEndpointGroupsNodeInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), CredentialDigest: credential, Packet: raw, Body: body, Now: time.Now}
	seal := func(out store.HubEndpointGroupsNodeOutput) ([]byte, error) {
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
		limit := wire.MaxEndpointGroupsNodeReceiptBytes
		if opened.Route.Operation == wire.OperationEndpointGroupsNodeReconcile {
			limit = wire.MaxEndpointGroupsNodeReconcilePacketBytes
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
		if _, err = wire.DecodeEndpointGroupsNodePacket(packet); err != nil {
			return nil, err
		}
		return packet, nil
	}
	return in, seal, nil
}

func (s *Service) endpointGroupsRPC(ctx context.Context, token string, raw []byte) ([]byte, error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	in, seal, err := s.openEndpointGroupsNode(fabric.HashSessionCredential(token), raw)
	if err != nil {
		return nil, err
	}
	if q, ok := in.Body.(wire.EndpointGroupsNodeReconcile); ok {
		original, os, err := s.openEndpointGroupsNode(in.CredentialDigest, q.OriginalPacket)
		if err != nil {
			return nil, err
		}
		in.Original = &original
		in.OriginalSeal = os
	}
	packet, err := s.db.ProcessHubEndpointGroupsNode(in, seal)
	if err != nil {
		return nil, ErrUnavailable
	}
	return packet, nil
}
