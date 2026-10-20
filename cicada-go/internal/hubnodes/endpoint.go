package hubnodes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func (s *Service) endpointRPC(ctx context.Context, token string, raw []byte, packet nodewire.Packet) ([]byte, error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	digest := fabric.HashSessionCredential(token)
	b, err := s.db.NodeControlKeyForCredential(digest, packet.Route.NodeID)
	if err != nil {
		return nil, ErrUnavailable
	}
	opened, err := nodewire.OpenRequest(s.ids.NodeControl, b.NodePublicIdentity, nodeBinding(b), raw)
	if err != nil {
		return nil, ErrUnavailable
	}
	hash := sha256.Sum256(raw)
	in := store.NodeControlRPCInput{CredentialDigest: digest, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyID: b.NodeKeyID, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: opened.Route.Sequence, OperationID: opened.Route.OperationID, Operation: opened.Route.Operation, RequestDigest: hex.EncodeToString(hash[:])}
	record, retry, err := s.db.BeginNodeControlRPC(in)
	if err != nil {
		return nil, ErrUnavailable
	}
	if retry && record.State == store.NodeControlRPCComplete && len(record.ResponsePacket) > 0 {
		return record.ResponsePacket, nil
	}
	code := ""
	var result any
	if retry {
		code = "IN_PROGRESS"
		if record.State == store.NodeControlRPCComplete {
			code = "RESULT_EXPIRED"
		}
		if record.State == store.NodeControlRPCUncertain {
			code = "OUTCOME_UNCERTAIN"
		}
	} else {
		decode := func(v any) error {
			d := json.NewDecoder(bytes.NewReader(opened.Plaintext))
			d.DisallowUnknownFields()
			if d.Decode(v) != nil {
				return nodewire.ErrEndpointContext
			}
			var extra any
			if d.Decode(&extra) != io.EOF {
				return nodewire.ErrEndpointContext
			}
			return nil
		}
		switch in.Operation {
		case nodewire.EndpointDirectoryOperation:
			var q *nodewire.EndpointDirectoryRequest
			if err = decode(&q); err == nil {
				if q == nil {
					err = nodewire.ErrEndpointContext
				} else {
					result, err = s.fabric.ListNodeEndpoints(in, *q)
				}
			}
		case nodewire.EndpointRegisterOperation:
			var q nodewire.EndpointRegistration
			if err = decode(&q); err == nil {
				result, err = s.fabric.RegisterNodeEndpoint(in, q)
			}
		case nodewire.EndpointLeaveOperation:
			var q nodewire.EndpointLeave
			if err = decode(&q); err == nil {
				result, err = s.fabric.LeaveNodeEndpoint(in, q)
			}
		case nodewire.NativePairAvailableOperation:
			var q struct{}
			if err = decode(&q); err == nil {
				result, err = s.fabric.AvailableNodeNativePairs(in, b.HubPublicIdentity)
			}
		}
		if err != nil {
			for _, known := range []error{nodewire.ErrEndpointContext, nodewire.ErrEndpointConflict, nodewire.ErrEndpointUnavailable} {
				if errors.Is(err, known) {
					code = known.Error()
				}
			}
			if code == "" {
				_ = s.db.MarkNodeControlRPCUncertain(in)
				code = "OUTCOME_UNCERTAIN"
			}
		}
	}
	body := map[string]any{"ok": code == "", "operation_id": in.OperationID, "sequence": in.Sequence}
	if code == "" {
		body["result"] = result
	} else {
		body["error_code"] = code
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		_ = s.db.MarkNodeControlRPCUncertain(in)
		return nil, ErrUnavailable
	}
	r := opened.Route
	r.Direction = nodewire.DirectionResponse
	r.SenderKeyID, r.ReceiverKeyID = r.ReceiverKeyID, r.SenderKeyID
	r.SenderKeyVersion, r.ReceiverKeyVersion = r.ReceiverKeyVersion, r.SenderKeyVersion
	sealed, err := nodewire.SealResponse(s.ids.NodeControl, b.NodePublicIdentity, nodeBinding(b), r, encoded)
	if err != nil {
		_ = s.db.MarkNodeControlRPCUncertain(in)
		return nil, ErrUnavailable
	}
	if !retry && code != "OUTCOME_UNCERTAIN" {
		if err = s.db.CompleteNodeControlRPC(store.NodeControlRPCCompletion{NodeControlRPCInput: in, ResponsePacket: sealed}); err != nil {
			_ = s.db.MarkNodeControlRPCUncertain(in)
			return nil, ErrUnavailable
		}
	}
	return sealed, nil
}
