package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type HubNativePairNodeInput struct {
	Hub               wire.HubIdentity
	NodeControlPublic e2ee.PublicIdentity
	CredentialDigest  string
	Packet            []byte
	Body              any
	At                time.Time
	Now               func() time.Time
	SessionToken      string
	Original          *HubNativePairNodeInput
	OriginalSeal      HubNativePairNodeSeal
}
type HubNativePairZeroJoin struct {
	Endpoint           Endpoint
	Binding            SessionBinding
	SessionToken       string
	NativeContextScope NativeContextScopeMetadata
}
type HubNativePairNodeOutput struct {
	Description *wire.NativePairNodeDescription
	Join        *HubNativePairZeroJoin
	Reconciled  *wire.NativePairNodeReconciled
	ErrorCode   string
}
type HubNativePairNodeSeal func(HubNativePairNodeOutput) ([]byte, error)

func nativePairNodeInput(in HubNativePairNodeInput) (NodeControlRPCInput, string, error) {
	p, err := wire.DecodeNativePairNodePacket(in.Packet)
	if err != nil || p.Route.Direction != nodewire.DirectionRequest || in.At.IsZero() {
		return NodeControlRPCInput{}, "", ErrHubAccountRejected
	}
	var op, pair string
	switch q := in.Body.(type) {
	case wire.NativePairNodeDescribe:
		op, pair = wire.OperationNativePairNodeDescribe, q.PairID
	case wire.NativePairNodeJoin:
		op, pair = wire.OperationNativePairNodeJoin, q.PairID
	case wire.NativePairNodeReconcile:
		op, pair = wire.OperationNativePairNodeReconcile, q.PairID
	default:
		return NodeControlRPCInput{}, "", ErrHubAccountRejected
	}
	raw, err := json.Marshal(in.Body)
	if err != nil {
		return NodeControlRPCInput{}, "", err
	}
	if _, err = wire.DecodeNativePairNodeRequest(op, raw); err != nil || op != p.Route.Operation || p.Route.HubID != in.Hub.HubID {
		return NodeControlRPCInput{}, "", ErrHubAccountRejected
	}
	r := p.Route
	return NodeControlRPCInput{CredentialDigest: in.CredentialDigest, NodeID: r.NodeID, BindingID: r.BindingID, BindingVersion: r.BindingVersion, NodeKeyID: r.SenderKeyID, NodeKeyEpoch: r.NodeKeyEpoch, Sequence: r.Sequence, OperationID: r.OperationID, Operation: r.Operation, RequestDigest: wire.NativePairNodePacketDigest(in.Packet)}, pair, nil
}

// This is retained authentication only. The committed Owner bootstrap pins the
// original Node route/key/credential even after its live binding is revoked.
// It does not authorize a fresh Join or provide new session credentials.
func nativePairRetainedNodeKeyTx(tx *sql.Tx, credential string, r nodewire.Route, hub wire.HubIdentity, control e2ee.PublicIdentity) (*NodeControlKeyBinding, error) {
	digest, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != credential || r.Direction != nodewire.DirectionRequest || r.HubID != hub.HubID {
		return nil, ErrNodeControlKeyUnauthorized
	}
	var pair, scopeJSON string
	var proof []byte
	err = tx.QueryRow(`SELECT pair_id,scope_json,bootstrap_owner_proof FROM hub_native_pairs_v1 WHERE hub_id=? AND node_id=? AND bootstrap_owner_proof IS NOT NULL AND json_extract(scope_json,'$.credential_commitment')=? AND json_extract(scope_json,'$.node.owner_binding_id')=? AND json_extract(scope_json,'$.node.binding_version')=? AND json_extract(scope_json,'$.node.node_key_epoch')=? AND json_extract(scope_json,'$.node.node_public_identity.id')=? LIMIT 1`, r.HubID, r.NodeID, hex.EncodeToString(digest), r.BindingID, r.BindingVersion, r.NodeKeyEpoch, r.SenderKeyID).Scan(&pair, &scopeJSON, &proof)
	var scope e2ee.OwnerNativePairScope
	if err != nil || json.Unmarshal([]byte(scopeJSON), &scope) != nil || wire.ValidateNativePairScope(scope, hub) != nil {
		return nil, ErrNodeControlKeyUnauthorized
	}
	c, err := e2ee.VerifyOwnerNativePair(scope.Actor.OwnerPublic, proof, e2ee.OwnerNativePairBootstrapCommit, time.Time{})
	if err != nil || c.Bootstrap.PairID != pair || !reflect.DeepEqual(c.Scope, scope) {
		return nil, ErrNodeControlKeyUnauthorized
	}
	n := scope.Node
	if !reflect.DeepEqual(n.HubNodeControlPublic, control) || r.ReceiverKeyID != control.ID || r.ReceiverKeyVersion != n.HubNodeControlKeyVersion || r.SenderKeyVersion != n.NodeKeyVersion {
		return nil, ErrNodeControlKeyUnauthorized
	}
	return &NodeControlKeyBinding{OwnerBindingID: n.OwnerBindingID, OwnerID: n.OwnerID, HubID: n.HubID, NodeID: n.NodeID, NodeName: n.NodeName, ClientDeviceID: n.ClientDeviceID, OwnerKeyID: n.OwnerKeyID, NodeCredentialVersion: n.CredentialVersion, BindingVersion: n.BindingVersion, NodeKeyID: n.NodePublic.ID, NodePublicIdentity: n.NodePublic, NodeKeyFingerprint: n.NodeKeyFingerprint, NodeKeyVersion: n.NodeKeyVersion, NodeKeyEpoch: n.NodeKeyEpoch, HubKeyID: n.HubNodeControlPublic.ID, HubPublicIdentity: n.HubNodeControlPublic, HubKeyFingerprint: n.HubNodeControlFingerprint, HubKeyVersion: n.HubNodeControlKeyVersion, ApprovedRequestID: n.ApprovedRequestID, ApprovedRequestVersion: int64(n.ApprovedRequestVersion), ApprovedCandidateDigest: n.ApprovedCandidateDigest, ApprovedOwnerDeviceID: n.ClientDeviceID, ApprovedOwnerKeyID: n.OwnerKeyID, ApprovedAt: n.ApprovedAt, State: n.State, Version: scope.NodeControlBindingVersion, CredentialDigest: credential}, nil
}

func (s *Store) HubNativePairNodeKey(credential string, route nodewire.Route, hub wire.HubIdentity, control e2ee.PublicIdentity) (*NodeControlKeyBinding, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return nativePairRetainedNodeKeyTx(tx, credential, route, hub, control)
}

func nativePairNodeCurrentTx(tx *sql.Tx, p *hubNativePair, in HubNativePairNodeInput, route NodeControlRPCInput) error {
	a, err := appNodeActor(tx, in.Hub, p.device, p.scope.Actor.DevicePublic, nil, in.At)
	if err != nil || !a.source || !appNodeSameSecurity(a.scope, p.scope.Actor) {
		return ErrHubAccountRejected
	}
	b, err := nativePairProvenNode(tx, a, p.scope.Node, in.NodeControlPublic)
	if err != nil || b.OwnerBindingID != route.BindingID || b.BindingVersion != route.BindingVersion || b.NodeKeyID != route.NodeKeyID || b.NodeKeyEpoch != route.NodeKeyEpoch || b.CredentialDigest != route.CredentialDigest || b.Version != p.scope.NodeControlBindingVersion {
		return ErrHubAccountRejected
	}
	digest, err := base64.RawURLEncoding.DecodeString(b.CredentialDigest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != p.scope.CredentialCommitment {
		return ErrHubAccountRejected
	}
	return nil
}

func nativePairNodeHistoryTx(tx *sql.Tx, in NodeControlRPCInput, pair string) (nativePairReceipt, error) {
	var old NodeControlRPCInput
	var savedPair, state string
	var packet []byte
	err := tx.QueryRow(`SELECT operation_id,operation,pair_id,request_digest,outcome,response_packet FROM hub_native_pair_node_operations_v1 WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=?`, in.BindingID, in.NodeKeyEpoch, in.Sequence).Scan(&old.OperationID, &old.Operation, &savedPair, &old.RequestDigest, &state, &packet)
	if errors.Is(err, sql.ErrNoRows) {
		return nativePairReceipt{}, nil
	}
	if err != nil {
		return nativePairReceipt{}, err
	}
	if old.OperationID != in.OperationID || old.Operation != in.Operation || savedPair != pair || old.RequestDigest != in.RequestDigest {
		return nativePairReceipt{}, ErrNodeControlRPCConflict
	}
	return nativePairReceipt{packet: packet, pair: savedPair, state: state}, nil
}
