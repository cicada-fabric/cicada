package hubnodes

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

var ErrOriginalOutcomeUncertain = errors.New("original Node outcome unavailable; retain original packet")

func (s *Service) openThreadCollaborationNode(credential string, raw []byte) (store.HubThreadCollaborationNodeInput, store.HubThreadCollaborationNodeSeal, error) {
	p, err := wire.DecodeThreadCollaborationNodePacket(raw)
	if err != nil {
		return store.HubThreadCollaborationNodeInput{}, nil, ErrUnavailable
	}
	hub, err := s.nativePairHubIdentity()
	if err != nil {
		return store.HubThreadCollaborationNodeInput{}, nil, ErrUnavailable
	}
	b, err := s.db.HubLocalDomainNodeKey(credential, p.Route, hub, s.ids.NodeControl.Public())
	if err != nil {
		return store.HubThreadCollaborationNodeInput{}, nil, ErrUnavailable
	}
	opened, err := nodewire.OpenRequest(s.ids.NodeControl, b.NodePublicIdentity, nodeBinding(b), raw)
	if err != nil {
		return store.HubThreadCollaborationNodeInput{}, nil, ErrUnavailable
	}
	defer clear(opened.Plaintext)
	body, err := wire.DecodeThreadCollaborationNodeBody(opened.Route.Operation, opened.Plaintext)
	if err != nil {
		return store.HubThreadCollaborationNodeInput{}, nil, ErrUnavailable
	}
	in := store.HubThreadCollaborationNodeInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), CredentialDigest: credential, Packet: raw, Body: body, Now: time.Now}
	seal := func(out store.HubThreadCollaborationNodeOutput) ([]byte, error) {
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
		limit := nodewire.MaxPlaintextBytes

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
		if _, err = wire.DecodeThreadCollaborationNodePacket(packet); err != nil {
			return nil, err
		}
		return packet, nil
	}
	return in, seal, nil
}

func (s *Service) threadCollaborationRPC(ctx context.Context, token string, raw []byte) ([]byte, error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	in, seal, err := s.openThreadCollaborationNode(fabric.HashSessionCredential(token), raw)
	if err != nil {
		return nil, err
	}
	packet, err := s.db.ProcessHubThreadCollaborationNode(in, seal)
	if errors.Is(err, store.ErrHubEndpointGroupsOutcomeUncertain) {
		return nil, ErrOriginalOutcomeUncertain
	}
	return packet, err
}
