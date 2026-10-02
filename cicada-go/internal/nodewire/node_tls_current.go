package nodewire

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const TLSCurrentOperation = "node.binding.status"
const TLSCurrentOperationPrefix = "tls-current-"
const MaxTLSCurrentPacketBytes = 512 << 10
const MaxTLSCurrentPlaintextBytes = 256 << 10
const TLSCurrentLifetime = 30 * time.Second
const tlsCurrentAAD = "cicada/node-control/tls-current-status/v1\x00"

// TLSCurrentRequest starts a new read-only conversation. Sequence one belongs
// only to this random 256-bit nonce and separate domain, never the RPC outbox.
type TLSCurrentRequest struct {
	Nonce            []byte `json:"nonce"`
	Origin           string `json:"origin"`
	CredentialDigest string `json:"credential_digest"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
}

// TLSCurrentAuthority is public committed material. Keeping this wire mirror
// independent of Store avoids making nodewire depend on database internals.
type TLSCurrentAuthority struct {
	State              string                       `json:"state"`
	RowVersion         uint64                       `json:"row_version"`
	ReservationVersion uint64                       `json:"reservation_version"`
	Claims             e2ee.OwnerTLSLeafGrantClaims `json:"claims"`
	Grant              []byte                       `json:"grant"`
	CSRPEM             []byte                       `json:"csr_pem"`
	IssuerChainPEM     []byte                       `json:"issuer_chain_pem"`
	TrustAnchorPEM     []byte                       `json:"trust_anchor_pem"`
	LeafCertificatePEM []byte                       `json:"leaf_certificate_pem"`
	LeafDERHash        string                       `json:"leaf_der_hash"`
	InstallAck         []byte                       `json:"install_ack"`
	Activation         []byte                       `json:"activation"`
}
type TLSCurrentStatus struct {
	CurrentBinding      json.RawMessage     `json:"current_binding"`
	OwnerKeyVersion     uint64              `json:"owner_key_version"`
	ClientDeviceVersion uint64              `json:"client_device_version"`
	CurrentAuthority    TLSCurrentAuthority `json:"current_authority"`
	ReadAt              string              `json:"read_at"`
	ExpiresAt           string              `json:"expires_at"`
}
type tlsCurrentReply struct {
	Request             TLSCurrentRequest `json:"request"`
	RequestPacketDigest string            `json:"request_packet_digest"`
	Status              TLSCurrentStatus  `json:"status"`
}

func tlsCurrentTime(issued, expires string, at time.Time) bool {
	a, err := time.Parse(time.RFC3339, issued)
	if err != nil {
		return false
	}
	b, err := time.Parse(time.RFC3339, expires)
	return err == nil && a.UTC().Format(time.RFC3339) == issued && b.UTC().Format(time.RFC3339) == expires && b.Equal(a.Add(TLSCurrentLifetime)) && !at.Before(a) && at.Before(b)
}
func ValidateTLSCurrentRequest(q TLSCurrentRequest, at time.Time) error {
	u, err := url.Parse(q.Origin)
	digest, digestErr := base64.RawURLEncoding.DecodeString(q.CredentialDigest)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != q.Origin || len(q.Origin) > 2048 || len(q.Nonce) != 32 || digestErr != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != q.CredentialDigest || !tlsCurrentTime(q.IssuedAt, q.ExpiresAt, at) {
		return ErrInvalidPacket
	}
	return nil
}
func IsTLSCurrentRoute(r Route) bool {
	return r.Operation == TLSCurrentOperation && strings.HasPrefix(r.OperationID, TLSCurrentOperationPrefix)
}
func tlsCurrentRoute(b Binding, q TLSCurrentRequest, direction string) Route {
	r := Route{Version: Version, Direction: direction, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: 1, OperationID: TLSCurrentOperationPrefix + hex.EncodeToString(q.Nonce), Operation: TLSCurrentOperation, SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	if direction == DirectionResponse {
		r.SenderKeyID, r.ReceiverKeyID = r.ReceiverKeyID, r.SenderKeyID
		r.SenderKeyVersion, r.ReceiverKeyVersion = r.ReceiverKeyVersion, r.SenderKeyVersion
	}
	return r
}
func tlsCurrentSeal(sender *e2ee.Identity, receiver e2ee.PublicIdentity, b Binding, r Route, body any) ([]byte, error) {
	if sender == nil || validateRoute(r, b, r.Direction) != nil || !IsTLSCurrentRoute(r) || r.Sequence != 1 || sender.Public().ID != r.SenderKeyID || receiver.ID != r.ReceiverKeyID {
		return nil, ErrInvalidPacket
	}
	plain, err := json.Marshal(body)
	if err != nil || len(plain) > MaxTLSCurrentPlaintextBytes {
		return nil, ErrInvalidPacket
	}
	aad, _ := json.Marshal(r)
	env, err := e2ee.Seal(sender, receiver, plain, append([]byte(tlsCurrentAAD), aad...), 1)
	if err != nil {
		return nil, err
	}
	packet, err := json.Marshal(Packet{Route: r, Envelope: env})
	if err != nil || len(packet) > MaxTLSCurrentPacketBytes {
		return nil, ErrInvalidPacket
	}
	return packet, nil
}
func tlsCurrentOpen(recipient *e2ee.Identity, sender e2ee.PublicIdentity, b Binding, data []byte, direction string, target any) (Route, error) {
	if len(data) > MaxTLSCurrentPacketBytes || recipient == nil {
		return Route{}, ErrInvalidPacket
	}
	p, err := DecodePacket(data)
	if err != nil || validateRoute(p.Route, b, direction) != nil || !IsTLSCurrentRoute(p.Route) || p.Route.Sequence != 1 || recipient.Public().ID != p.Route.ReceiverKeyID || sender.ID != p.Route.SenderKeyID {
		return Route{}, ErrInvalidPacket
	}
	aad, _ := json.Marshal(p.Route)
	plain, seq, err := e2ee.Open(recipient, sender, p.Envelope, append([]byte(tlsCurrentAAD), aad...))
	if err != nil || seq != 1 || len(plain) > MaxTLSCurrentPlaintextBytes {
		return Route{}, ErrInvalidPacket
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return Route{}, ErrInvalidPacket
	}
	return p.Route, nil
}
func SealTLSCurrentRequest(node *e2ee.Identity, b Binding, q TLSCurrentRequest, at time.Time) ([]byte, error) {
	if ValidateTLSCurrentRequest(q, at) != nil {
		return nil, ErrInvalidPacket
	}
	return tlsCurrentSeal(node, b.HubKey, b, tlsCurrentRoute(b, q, DirectionRequest), q)
}
func OpenTLSCurrentRequest(hub *e2ee.Identity, b Binding, data []byte, at time.Time) (TLSCurrentRequest, error) {
	var q TLSCurrentRequest
	r, err := tlsCurrentOpen(hub, b.NodeKey, b, data, DirectionRequest, &q)
	if err != nil || ValidateTLSCurrentRequest(q, at) != nil || r.OperationID != TLSCurrentOperationPrefix+hex.EncodeToString(q.Nonce) {
		return q, ErrInvalidPacket
	}
	return q, nil
}
func SealTLSCurrentResponse(hub *e2ee.Identity, b Binding, q TLSCurrentRequest, requestPacket []byte, status TLSCurrentStatus, at time.Time) ([]byte, error) {
	if ValidateTLSCurrentRequest(q, at) != nil || !validTLSCurrentStatus(b, q, status, at) {
		return nil, ErrInvalidPacket
	}
	return tlsCurrentSeal(hub, b.NodeKey, b, tlsCurrentRoute(b, q, DirectionResponse), tlsCurrentReply{Request: q, RequestPacketDigest: RecoveryDigest(requestPacket), Status: status})
}
func OpenTLSCurrentResponse(node *e2ee.Identity, b Binding, q TLSCurrentRequest, requestPacket, response []byte, at time.Time) (TLSCurrentStatus, error) {
	var reply tlsCurrentReply
	r, err := tlsCurrentOpen(node, b.HubKey, b, response, DirectionResponse, &reply)
	if err != nil || ValidateTLSCurrentRequest(q, at) != nil || r.OperationID != TLSCurrentOperationPrefix+hex.EncodeToString(q.Nonce) || !reflect.DeepEqual(reply.Request, q) || reply.RequestPacketDigest != RecoveryDigest(requestPacket) || !validTLSCurrentStatus(b, q, reply.Status, at) {
		return TLSCurrentStatus{}, ErrInvalidPacket
	}
	return reply.Status, nil
}
func validTLSCurrentStatus(b Binding, q TLSCurrentRequest, s TLSCurrentStatus, at time.Time) bool {
	a := s.CurrentAuthority
	c := a.Claims
	if !tlsCurrentTime(s.ReadAt, s.ExpiresAt, at) || s.ReadAt < q.IssuedAt || s.OwnerKeyVersion == 0 || s.ClientDeviceVersion == 0 || len(s.CurrentBinding) == 0 || !json.Valid(s.CurrentBinding) || a.State != "ACTIVE" || a.RowVersion == 0 || a.ReservationVersion != 1 || e2ee.ValidateOwnerTLSLeafGrantClaims(c) != nil {
		return false
	}
	return c.HubID == b.HubID && c.NodeID == b.NodeID && c.OwnerBindingID == b.BindingID && c.OwnerBindingVersion == b.BindingVersion && c.NodeControlKeyID == b.NodeKey.ID && c.NodeControlKeyVersion == b.NodeKeyVersion && c.NodeControlKeyEpoch == b.NodeKeyEpoch && c.HubControlKeyID == b.HubKey.ID && c.HubControlKeyVersion == b.HubKeyVersion && c.OwnerKeyVersion == s.OwnerKeyVersion && c.ClientDeviceVersion == s.ClientDeviceVersion && c.ApplicationOrigin == q.Origin && c.CredentialDigest == q.CredentialDigest && len(a.Grant) > 0 && len(a.InstallAck) > 0 && len(a.Activation) > 0 && len(a.CSRPEM) > 0 && len(a.IssuerChainPEM) > 0 && len(a.TrustAnchorPEM) > 0 && len(a.LeafCertificatePEM) > 0 && ValidRecoveryDigest(a.LeafDERHash)
}
