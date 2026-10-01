// Package nodewire frames the application-layer encrypted Node-to-Control
// management channel. It is deliberately independent of clientwire and of
// the peer Endpoint message formats.
package nodewire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	Version           = 1
	DirectionRequest  = "REQUEST"
	DirectionResponse = "RESPONSE"
	Algorithm         = e2ee.Algorithm
	// Requests retain the existing 64KiB management-body ceiling. Responses
	// may carry bounded Worker prompts/results and use the old 2MiB body limit.
	MaxRequestPacketBytes    = 256 << 10
	MaxPacketBytes           = 5 << 20
	MaxRequestPlaintextBytes = 64 << 10
	MaxPlaintextBytes        = 2 << 20 // maximum response plaintext
	aadDomain                = "cicada/node-control/packet/v1\x00"
)

var ErrInvalidPacket = errors.New("invalid Node-Control packet")

type PairingProofContext struct {
	HubID              string
	NodeID             string
	RequestNonce       []byte
	CredentialDigest   string
	NodePublicIdentity e2ee.PublicIdentity
	HubPublicIdentity  e2ee.PublicIdentity
	HubKeyVersion      uint64
}

type pairingProofTranscript struct {
	Version            int                 `json:"version"`
	HubID              string              `json:"hub_id"`
	NodeID             string              `json:"node_id"`
	RequestNonce       []byte              `json:"request_nonce"`
	CredentialDigest   string              `json:"credential_digest"`
	NodePublicIdentity e2ee.PublicIdentity `json:"node_public_identity"`
	NodeFingerprint    string              `json:"node_fingerprint"`
	HubPublicIdentity  e2ee.PublicIdentity `json:"hub_public_identity"`
	HubFingerprint     string              `json:"hub_fingerprint"`
	HubKeyVersion      uint64              `json:"hub_key_version"`
}

func IdentityFingerprint(identity e2ee.PublicIdentity) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cicada/node-control/key-fingerprint/v1\x00"))
	_, _ = hash.Write(identity.KEMPublic)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(identity.SigningPublic)
	return hex.EncodeToString(hash.Sum(nil))
}

func PairingProofAAD() []byte {
	return []byte("cicada/node-control/pairing-proof/v1\x00")
}

func PairingProofTranscript(input PairingProofContext) ([]byte, error) {
	if !validToken(input.HubID) || !validToken(input.NodeID) || len(input.RequestNonce) < 16 || len(input.RequestNonce) > 64 ||
		input.CredentialDigest == "" || len(input.CredentialDigest) > 64 || input.HubKeyVersion == 0 ||
		e2ee.ValidatePublicIdentity(input.NodePublicIdentity) != nil || e2ee.ValidatePublicIdentity(input.HubPublicIdentity) != nil {
		return nil, ErrInvalidPacket
	}
	return json.Marshal(pairingProofTranscript{Version: Version, HubID: input.HubID, NodeID: input.NodeID,
		RequestNonce: append([]byte(nil), input.RequestNonce...), CredentialDigest: input.CredentialDigest,
		NodePublicIdentity: input.NodePublicIdentity, NodeFingerprint: IdentityFingerprint(input.NodePublicIdentity),
		HubPublicIdentity: input.HubPublicIdentity, HubFingerprint: IdentityFingerprint(input.HubPublicIdentity),
		HubKeyVersion: input.HubKeyVersion})
}

// Binding is loaded only from Hub-persisted Owner-approved Node key state.
// None of these values may be inferred from an untrusted packet header.
type Binding struct {
	HubID          string
	NodeID         string
	BindingID      string
	BindingVersion uint64
	NodeKeyEpoch   uint64
	HubKeyVersion  uint64
	NodeKeyVersion uint64
	NodeKey        e2ee.PublicIdentity
	HubKey         e2ee.PublicIdentity
}

// Route is authenticated metadata. Authorization and actor identity still
// come from the bearer and the current durable binding in the Store.
type Route struct {
	Version            int    `json:"version"`
	Direction          string `json:"direction"`
	HubID              string `json:"hub_id"`
	NodeID             string `json:"node_id"`
	BindingID          string `json:"binding_id"`
	BindingVersion     uint64 `json:"binding_version"`
	NodeKeyEpoch       uint64 `json:"node_key_epoch"`
	Sequence           uint64 `json:"sequence"`
	OperationID        string `json:"operation_id"`
	Operation          string `json:"operation"`
	SenderKeyID        string `json:"sender_key_id"`
	SenderKeyVersion   uint64 `json:"sender_key_version"`
	ReceiverKeyID      string `json:"receiver_key_id"`
	ReceiverKeyVersion uint64 `json:"receiver_key_version"`
}

type Packet struct {
	Route    Route  `json:"route"`
	Envelope []byte `json:"envelope"`
}

type Opened struct {
	Route     Route
	Plaintext []byte
}

func DecodePacket(data []byte) (Packet, error) {
	if len(data) == 0 || len(data) > MaxPacketBytes {
		return Packet{}, ErrInvalidPacket
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var packet Packet
	if err := decoder.Decode(&packet); err != nil {
		return Packet{}, fmt.Errorf("decode Node-Control packet: %w", err)
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || len(packet.Envelope) == 0 {
		return Packet{}, ErrInvalidPacket
	}
	return packet, nil
}

func validToken(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "/\\") {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validateRoute(route Route, binding Binding, direction string) error {
	if route.Version != Version || route.Direction != direction ||
		!validToken(route.HubID) || !validToken(route.NodeID) ||
		!validToken(route.BindingID) || !validToken(route.OperationID) ||
		!validToken(route.Operation) || route.HubID != binding.HubID ||
		route.NodeID != binding.NodeID || route.BindingID != binding.BindingID ||
		route.BindingVersion == 0 || route.BindingVersion != binding.BindingVersion ||
		route.NodeKeyEpoch == 0 || route.NodeKeyEpoch != binding.NodeKeyEpoch ||
		binding.HubKeyVersion == 0 || binding.NodeKeyVersion == 0 ||
		route.SenderKeyVersion == 0 || route.ReceiverKeyVersion == 0 ||
		route.Sequence == 0 {
		return ErrInvalidPacket
	}
	if direction == DirectionRequest {
		if route.SenderKeyID != binding.NodeKey.ID || route.ReceiverKeyID != binding.HubKey.ID ||
			route.SenderKeyVersion != binding.NodeKeyVersion || route.ReceiverKeyVersion != binding.HubKeyVersion {
			return ErrInvalidPacket
		}
	} else if route.SenderKeyID != binding.HubKey.ID || route.ReceiverKeyID != binding.NodeKey.ID ||
		route.SenderKeyVersion != binding.HubKeyVersion || route.ReceiverKeyVersion != binding.NodeKeyVersion {
		return ErrInvalidPacket
	}
	return nil
}

func associatedData(route Route) ([]byte, error) {
	encoded, err := json.Marshal(route)
	if err != nil {
		return nil, err
	}
	return append([]byte(aadDomain), encoded...), nil
}

func seal(sender *e2ee.Identity, receiver e2ee.PublicIdentity, binding Binding,
	route Route, direction string, plaintext []byte) ([]byte, error) {
	maxPlaintext := MaxPlaintextBytes
	maxPacket := MaxPacketBytes
	if direction == DirectionRequest {
		maxPlaintext = MaxRequestPlaintextBytes
		maxPacket = MaxRequestPacketBytes
	}
	if sender == nil || len(plaintext) == 0 || len(plaintext) > maxPlaintext {
		return nil, ErrInvalidPacket
	}
	if err := validateRoute(route, binding, direction); err != nil {
		return nil, err
	}
	if err := e2ee.ValidatePublicIdentity(receiver); err != nil {
		return nil, ErrInvalidPacket
	}
	if sender.Public().ID != route.SenderKeyID || receiver.ID != route.ReceiverKeyID {
		return nil, ErrInvalidPacket
	}
	aad, err := associatedData(route)
	if err != nil {
		return nil, err
	}
	envelope, err := e2ee.Seal(sender, receiver, plaintext, aad, route.Sequence)
	if err != nil {
		return nil, err
	}
	packet, err := json.Marshal(Packet{Route: route, Envelope: envelope})
	if err != nil {
		return nil, err
	}
	if len(packet) > maxPacket {
		return nil, ErrInvalidPacket
	}
	return packet, nil
}

func open(recipient *e2ee.Identity, sender e2ee.PublicIdentity, binding Binding,
	data []byte, direction string) (Opened, error) {
	if recipient == nil {
		return Opened{}, ErrInvalidPacket
	}
	packet, err := DecodePacket(data)
	if err != nil {
		return Opened{}, err
	}
	if err := validateRoute(packet.Route, binding, direction); err != nil {
		return Opened{}, err
	}
	if recipient.Public().ID != packet.Route.ReceiverKeyID || sender.ID != packet.Route.SenderKeyID {
		return Opened{}, ErrInvalidPacket
	}
	aad, err := associatedData(packet.Route)
	if err != nil {
		return Opened{}, err
	}
	plaintext, sequence, err := e2ee.Open(recipient, sender, packet.Envelope, aad)
	if err != nil {
		return Opened{}, err
	}
	maxPlaintext := MaxPlaintextBytes
	if direction == DirectionRequest {
		maxPlaintext = MaxRequestPlaintextBytes
	}
	if sequence != packet.Route.Sequence || len(plaintext) == 0 || len(plaintext) > maxPlaintext {
		return Opened{}, ErrInvalidPacket
	}
	return Opened{Route: packet.Route, Plaintext: plaintext}, nil
}

func SealRequest(node *e2ee.Identity, hub e2ee.PublicIdentity, binding Binding,
	route Route, plaintext []byte) ([]byte, error) {
	return seal(node, hub, binding, route, DirectionRequest, plaintext)
}

func OpenRequest(hub *e2ee.Identity, node e2ee.PublicIdentity, binding Binding,
	packet []byte) (Opened, error) {
	return open(hub, node, binding, packet, DirectionRequest)
}

func SealResponse(hub *e2ee.Identity, node e2ee.PublicIdentity, binding Binding,
	route Route, plaintext []byte) ([]byte, error) {
	return seal(hub, node, binding, route, DirectionResponse, plaintext)
}

func OpenResponse(node *e2ee.Identity, hub e2ee.PublicIdentity, binding Binding,
	packet []byte) (Opened, error) {
	return open(node, hub, binding, packet, DirectionResponse)
}
