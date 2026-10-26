// Package hubnodes composes existing Node proof/binding/Fabric services without
// Control business, planner, scheduler, local machines or Runtime startup.
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
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/nodebinding"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

var ErrUnavailable = errors.New("Hub Node request unavailable")
var ErrBusy = errors.New("Hub Node request capacity is busy")

type Service struct {
	db      *store.Store
	ids     hubidentity.Set
	pairing *nodebinding.Service
	fabric  *fabric.Service
	workers chan struct{}
}

func NewService(db *store.Store, ids hubidentity.Set) (*Service, error) {
	if db == nil || ids.Peer == nil || ids.ClientControl == nil || ids.NodeControl == nil {
		return nil, ErrUnavailable
	}
	setup, err := db.GetHubOwnerSetup()
	if err != nil || setup == nil {
		return nil, ErrUnavailable
	}
	pairing, err := nodebinding.NewService(db, ids.NodeControl)
	if err != nil {
		return nil, err
	}
	f, err := fabric.NewService(db, setup.OwnerID, setup.OwnerID)
	if err != nil {
		return nil, err
	}
	return &Service{db: db, ids: ids, pairing: pairing, fabric: f, workers: make(chan struct{}, 2)}, nil
}
func (s *Service) Fabric() *fabric.Service                    { return s.fabric }
func (s *Service) Identity() (nodebinding.HubIdentity, error) { return s.pairing.PublicIdentity() }
func (s *Service) acquire(ctx context.Context) (func(), error) {
	select {
	case <-ctx.Done():
		return nil, ErrUnavailable
	case s.workers <- struct{}{}:
		return func() { <-s.workers }, nil
	default:
		return nil, ErrBusy
	}
}
func (s *Service) Start(ctx context.Context, input nodebinding.Input) (*nodebinding.DeviceCode, error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.pairing.Start(input, store.NodeControlPairingInitial)
}
func (s *Service) PairingStatus(token, nodeID, id string) (*store.NodeControlKeyCandidate, error) {
	if _, err := fabric.NodeCredentialFromAuthorization("CicadaNode " + token); err != nil {
		return nil, ErrUnavailable
	}
	return s.db.NodeControlPairingStatus(fabric.HashSessionCredential(token), nodeID, id)
}

func nodeBinding(b *store.NodeControlKeyBinding) nodewire.Binding {
	return nodewire.Binding{HubID: b.HubID, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, HubKeyVersion: b.HubKeyVersion, NodeKeyVersion: b.NodeKeyVersion, NodeKey: b.NodePublicIdentity, HubKey: b.HubPublicIdentity}
}

// RPC keeps the existing status operation and separately dispatches the closed
// native-pair methods to their own atomic, retained-Node-authenticated service.
// A read interrupted before durable response completion may be recomputed from
// its exact authenticated original; no business effect is redispatched.
func (s *Service) RPC(ctx context.Context, token string, raw []byte) ([]byte, error) {
	if _, err := fabric.NodeCredentialFromAuthorization("CicadaNode " + token); err != nil {
		return nil, ErrUnavailable
	}
	packet, err := nodewire.DecodePacket(raw)
	if err != nil || packet.Route.Direction != nodewire.DirectionRequest {
		return nil, ErrUnavailable
	}
	switch packet.Route.Operation {
	case wire.OperationEndpointGroupsNodeDescribe, wire.OperationEndpointGroupsNodeKeyPrepare, wire.OperationEndpointGroupsNodeKeyComplete, wire.OperationEndpointGroupsNodeRenew, wire.OperationEndpointGroupsNodeReconcile:
		return s.endpointGroupsRPC(ctx, token, raw)
	case wire.OperationLocalDomainNodeAvailable, wire.OperationLocalDomainNodeJoin, wire.OperationLocalDomainNodeKeyPrepare, wire.OperationLocalDomainNodeKeyComplete, wire.OperationLocalDomainNodeDescribe, wire.OperationLocalDomainNodeReconcile:
		return s.localDomainRPC(ctx, token, raw)
	case nodewire.EndpointRegisterOperation, nodewire.EndpointLeaveOperation, nodewire.NativePairAvailableOperation, nodewire.EndpointDirectoryOperation:
		return s.endpointRPC(ctx, token, raw, packet)
	case wire.OperationNativePairNodeDescribe, wire.OperationNativePairNodeJoin, wire.OperationNativePairNodeReconcile:
		return s.nativePairRPC(ctx, token, raw)
	}
	if packet.Route.Operation != "node.binding.status" {
		return nil, ErrUnavailable
	}
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
	var empty struct{}
	decoder := json.NewDecoder(bytes.NewReader(opened.Plaintext))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&empty) != nil {
		return nil, ErrUnavailable
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrUnavailable
	}
	hash := sha256.Sum256(raw)
	in := store.NodeControlRPCInput{CredentialDigest: digest, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyID: b.NodeKeyID, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: opened.Route.Sequence, OperationID: opened.Route.OperationID, Operation: opened.Route.Operation, RequestDigest: hex.EncodeToString(hash[:])}
	record, retry, err := s.db.BeginNodeControlRPC(in)
	if err != nil {
		return nil, ErrUnavailable
	}
	if retry && len(record.ResponsePacket) > 0 && record.State == store.NodeControlRPCComplete {
		return record.ResponsePacket, nil
	}
	var body []byte
	if retry && record.State == store.NodeControlRPCComplete {
		body, err = json.Marshal(map[string]any{"ok": false, "operation_id": in.OperationID, "sequence": in.Sequence, "error_code": "RESULT_EXPIRED"})
	} else {
		body, err = json.Marshal(map[string]any{"ok": true, "operation_id": in.OperationID, "sequence": in.Sequence, "result": map[string]any{"request_id": b.ApprovedRequestID, "candidate_version": b.ApprovedRequestVersion, "candidate_digest": b.ApprovedCandidateDigest, "node_id": b.NodeID, "hub_id": b.HubID, "binding_id": b.OwnerBindingID, "binding_version": b.BindingVersion, "node_key_id": b.NodeKeyID, "node_key_fingerprint": b.NodeKeyFingerprint, "node_key_epoch": b.NodeKeyEpoch, "hub_key_id": b.HubKeyID, "hub_key_version": b.HubKeyVersion, "hub_key_fingerprint": b.HubKeyFingerprint}})
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	r := opened.Route
	r.Direction = nodewire.DirectionResponse
	r.SenderKeyID, r.ReceiverKeyID = r.ReceiverKeyID, r.SenderKeyID
	r.SenderKeyVersion, r.ReceiverKeyVersion = r.ReceiverKeyVersion, r.SenderKeyVersion
	sealed, err := nodewire.SealResponse(s.ids.NodeControl, b.NodePublicIdentity, nodeBinding(b), r, body)
	if err != nil {
		return nil, ErrUnavailable
	}
	if retry && record.State == store.NodeControlRPCComplete {
		return sealed, nil
	}
	if err = s.db.CompleteNodeControlRPC(store.NodeControlRPCCompletion{NodeControlRPCInput: in, ResponsePacket: sealed}); err != nil {
		return nil, ErrUnavailable
	}
	return sealed, nil
}
