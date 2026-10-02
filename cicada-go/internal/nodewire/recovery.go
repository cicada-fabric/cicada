package nodewire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"reflect"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const RecoveryOperation = "node.recovery.status"
const MaxRecoveryPacketBytes = 64 << 10
const MaxRecoveryOperations = 16
const recoveryAADDomain = "cicada/node-control/recovery-status/v1\x00"

type RecoveryOperationQuery struct {
	OperationID   string `json:"operation_id"`
	Sequence      uint64 `json:"sequence"`
	RequestDigest string `json:"request_digest"`
}
type RecoveryRequest struct {
	Nonce            []byte                   `json:"nonce"`
	Origin           string                   `json:"origin"`
	CredentialDigest string                   `json:"credential_digest"`
	RestoreDigest    string                   `json:"restore_digest"`
	PlanDigest       string                   `json:"plan_digest"`
	Operations       []RecoveryOperationQuery `json:"operations"`
}
type RecoveryOperationStatus struct {
	RecoveryOperationQuery
	State string `json:"state"`
}
type RecoveryStatus struct {
	HubID             string                    `json:"hub_id"`
	NodeID            string                    `json:"node_id"`
	BindingID         string                    `json:"binding_id"`
	BindingVersion    uint64                    `json:"binding_version"`
	NodeKeyID         string                    `json:"node_key_id"`
	NodeKeyVersion    uint64                    `json:"node_key_version"`
	NodeKeyEpoch      uint64                    `json:"node_key_epoch"`
	HubKeyID          string                    `json:"hub_key_id"`
	HubKeyVersion     uint64                    `json:"hub_key_version"`
	CredentialVersion uint64                    `json:"credential_version"`
	AcceptedHighwater uint64                    `json:"accepted_highwater"`
	Operations        []RecoveryOperationStatus `json:"operations"`
}
type recoveryReply struct {
	Request             RecoveryRequest `json:"request"`
	RequestPacketDigest string          `json:"request_packet_digest"`
	Status              RecoveryStatus  `json:"status"`
}

func RecoveryDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func ValidRecoveryDigest(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && value == strings.ToLower(value)
}
func ValidateRecoveryRequest(q RecoveryRequest) error {
	u, err := url.Parse(q.Origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != q.Origin || len(q.Origin) > 2048 ||
		len(q.Nonce) != 32 || len(q.CredentialDigest) == 0 || len(q.CredentialDigest) > 128 || !ValidRecoveryDigest(q.RestoreDigest) || !ValidRecoveryDigest(q.PlanDigest) || len(q.Operations) > MaxRecoveryOperations {
		return ErrInvalidPacket
	}
	seen := map[string]bool{}
	for _, op := range q.Operations {
		if !validToken(op.OperationID) || op.Sequence == 0 || op.Sequence > uint64(^uint64(0)>>1) || !ValidRecoveryDigest(op.RequestDigest) || seen[op.OperationID] {
			return ErrInvalidPacket
		}
		seen[op.OperationID] = true
	}
	return nil
}
func recoveryRoute(b Binding, q RecoveryRequest, direction string) Route {
	r := Route{Version: Version, Direction: direction, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: 1, OperationID: hex.EncodeToString(q.Nonce), Operation: RecoveryOperation, SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	if direction == DirectionResponse {
		r.SenderKeyID, r.ReceiverKeyID = r.ReceiverKeyID, r.SenderKeyID
		r.SenderKeyVersion, r.ReceiverKeyVersion = r.ReceiverKeyVersion, r.SenderKeyVersion
	}
	return r
}
func recoverySeal(sender *e2ee.Identity, receiver e2ee.PublicIdentity, b Binding, r Route, body any) ([]byte, error) {
	if sender == nil || validateRoute(r, b, r.Direction) != nil || r.Operation != RecoveryOperation || r.Sequence != 1 || sender.Public().ID != r.SenderKeyID || receiver.ID != r.ReceiverKeyID {
		return nil, ErrInvalidPacket
	}
	plain, err := json.Marshal(body)
	if err != nil || len(plain) > MaxRecoveryPacketBytes/4 {
		return nil, ErrInvalidPacket
	}
	aad, _ := json.Marshal(r)
	env, err := e2ee.Seal(sender, receiver, plain, append([]byte(recoveryAADDomain), aad...), 1)
	if err != nil {
		return nil, err
	}
	packet, err := json.Marshal(Packet{Route: r, Envelope: env})
	if err != nil || len(packet) > MaxRecoveryPacketBytes {
		return nil, ErrInvalidPacket
	}
	return packet, nil
}
func recoveryOpen(recipient *e2ee.Identity, sender e2ee.PublicIdentity, b Binding, data []byte, direction string, target any) (Route, error) {
	if len(data) > MaxRecoveryPacketBytes || recipient == nil {
		return Route{}, ErrInvalidPacket
	}
	p, err := DecodePacket(data)
	if err != nil || validateRoute(p.Route, b, direction) != nil || p.Route.Operation != RecoveryOperation || p.Route.Sequence != 1 || recipient.Public().ID != p.Route.ReceiverKeyID || sender.ID != p.Route.SenderKeyID {
		return Route{}, ErrInvalidPacket
	}
	aad, _ := json.Marshal(p.Route)
	plain, seq, err := e2ee.Open(recipient, sender, p.Envelope, append([]byte(recoveryAADDomain), aad...))
	if err != nil || seq != 1 || len(plain) > MaxRecoveryPacketBytes/4 {
		return Route{}, ErrInvalidPacket
	}
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if dec.Decode(target) != nil || !errors.Is(dec.Decode(new(any)), io.EOF) {
		return Route{}, ErrInvalidPacket
	}
	return p.Route, nil
}
func SealRecoveryRequest(node *e2ee.Identity, b Binding, q RecoveryRequest) ([]byte, error) {
	if ValidateRecoveryRequest(q) != nil {
		return nil, ErrInvalidPacket
	}
	return recoverySeal(node, b.HubKey, b, recoveryRoute(b, q, DirectionRequest), q)
}
func OpenRecoveryRequest(hub *e2ee.Identity, b Binding, data []byte) (RecoveryRequest, error) {
	var q RecoveryRequest
	r, err := recoveryOpen(hub, b.NodeKey, b, data, DirectionRequest, &q)
	if err != nil || ValidateRecoveryRequest(q) != nil || r.OperationID != hex.EncodeToString(q.Nonce) {
		return q, ErrInvalidPacket
	}
	return q, nil
}
func SealRecoveryResponse(hub *e2ee.Identity, b Binding, q RecoveryRequest, requestPacket []byte, status RecoveryStatus) ([]byte, error) {
	return recoverySeal(hub, b.NodeKey, b, recoveryRoute(b, q, DirectionResponse), recoveryReply{Request: q, RequestPacketDigest: RecoveryDigest(requestPacket), Status: status})
}
func OpenRecoveryResponse(node *e2ee.Identity, b Binding, q RecoveryRequest, requestPacket, response []byte) (RecoveryStatus, error) {
	var reply recoveryReply
	r, err := recoveryOpen(node, b.HubKey, b, response, DirectionResponse, &reply)
	if err != nil || r.OperationID != hex.EncodeToString(q.Nonce) || !reflect.DeepEqual(reply.Request, q) || reply.RequestPacketDigest != RecoveryDigest(requestPacket) {
		return RecoveryStatus{}, ErrInvalidPacket
	}
	s := reply.Status
	if s.HubID != b.HubID || s.NodeID != b.NodeID || s.BindingID != b.BindingID || s.BindingVersion != b.BindingVersion || s.NodeKeyID != b.NodeKey.ID || s.NodeKeyVersion != b.NodeKeyVersion || s.NodeKeyEpoch != b.NodeKeyEpoch || s.HubKeyID != b.HubKey.ID || s.HubKeyVersion != b.HubKeyVersion || s.CredentialVersion == 0 || s.AcceptedHighwater > uint64(^uint64(0)>>1) || len(s.Operations) != len(q.Operations) {
		return RecoveryStatus{}, ErrInvalidPacket
	}
	for i, op := range s.Operations {
		if op.RecoveryOperationQuery != q.Operations[i] || (op.State != "NOT_RECORDED" && op.State != "PROCESSING" && op.State != "COMPLETE" && op.State != "UNCERTAIN") {
			return RecoveryStatus{}, ErrInvalidPacket
		}
	}
	return s, nil
}
