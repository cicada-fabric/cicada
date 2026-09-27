// Package clientwire defines the application-layer encrypted packet exchanged
// between an external Client and the Hub's Control ingress. It owns framing,
// not device enrollment, authorization, or durable replay state.
package clientwire

import (
	"bytes"
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
	maxPacketBytes    = 256 * 1024
	maxPlaintextBytes = 64 * 1024
	aadDomain         = "cicada/client-control/packet/v1\x00"
)

var ErrInvalidPacket = errors.New("invalid Client-Control packet")

// Binding must come from a verified Hub-side device/session registry. Client
// packet headers cannot establish owner, device, key, or session identity.
type Binding struct {
	HubID            string
	OwnerID          string
	DeviceID         string
	SessionEpoch     uint64
	HubKeyVersion    uint64
	DeviceKeyVersion uint64
}

// Route is public authenticated metadata. The operation body stays encrypted.
// Sequence must be reserved durably by the sender and accepted atomically by
// the receiver before dispatch; OpenRequest alone cannot prove freshness.
type Route struct {
	Version            int    `json:"version"`
	Direction          string `json:"direction"`
	HubID              string `json:"hub_id"`
	OwnerID            string `json:"owner_id"`
	DeviceID           string `json:"device_id"`
	SessionEpoch       uint64 `json:"session_epoch"`
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

func validToken(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/\\") {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validateRoute(route Route, binding Binding, sender, receiver e2ee.PublicIdentity, direction string) error {
	if route.Version != Version || route.Direction != direction ||
		!validToken(route.HubID) || !validToken(route.OwnerID) || !validToken(route.DeviceID) ||
		!validToken(route.OperationID) || !validToken(route.Operation) ||
		route.HubID != binding.HubID || route.OwnerID != binding.OwnerID || route.DeviceID != binding.DeviceID ||
		route.SessionEpoch == 0 || route.SessionEpoch != binding.SessionEpoch || route.Sequence == 0 ||
		route.SenderKeyID != sender.ID || route.ReceiverKeyID != receiver.ID ||
		route.SenderKeyVersion == 0 || route.ReceiverKeyVersion == 0 {
		return ErrInvalidPacket
	}
	if direction == DirectionRequest {
		if route.SenderKeyVersion != binding.DeviceKeyVersion || route.ReceiverKeyVersion != binding.HubKeyVersion {
			return ErrInvalidPacket
		}
	} else if route.SenderKeyVersion != binding.HubKeyVersion || route.ReceiverKeyVersion != binding.DeviceKeyVersion {
		return ErrInvalidPacket
	}
	return nil
}

func aad(route Route) ([]byte, error) {
	encoded, err := json.Marshal(route)
	if err != nil {
		return nil, err
	}
	return append([]byte(aadDomain), encoded...), nil
}

func seal(sender *e2ee.Identity, receiver e2ee.PublicIdentity, binding Binding, route Route, direction string, plaintext []byte) ([]byte, error) {
	if sender == nil || len(plaintext) == 0 || len(plaintext) > maxPlaintextBytes {
		return nil, ErrInvalidPacket
	}
	if err := validateRoute(route, binding, sender.Public(), receiver, direction); err != nil {
		return nil, err
	}
	associated, err := aad(route)
	if err != nil {
		return nil, err
	}
	envelope, err := e2ee.Seal(sender, receiver, plaintext, associated, route.Sequence)
	if err != nil {
		return nil, err
	}
	packet, err := json.Marshal(Packet{Route: route, Envelope: envelope})
	if err != nil {
		return nil, err
	}
	if len(packet) > maxPacketBytes {
		return nil, ErrInvalidPacket
	}
	return packet, nil
}

func open(recipient *e2ee.Identity, sender e2ee.PublicIdentity, binding Binding, data []byte, direction string) (Opened, error) {
	if recipient == nil || len(data) == 0 || len(data) > maxPacketBytes {
		return Opened{}, ErrInvalidPacket
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var packet Packet
	if err := decoder.Decode(&packet); err != nil {
		return Opened{}, fmt.Errorf("decode Client-Control packet: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Opened{}, ErrInvalidPacket
	}
	if err := validateRoute(packet.Route, binding, sender, recipient.Public(), direction); err != nil {
		return Opened{}, err
	}
	associated, err := aad(packet.Route)
	if err != nil {
		return Opened{}, err
	}
	plaintext, sequence, err := e2ee.Open(recipient, sender, packet.Envelope, associated)
	if err != nil {
		return Opened{}, err
	}
	if sequence != packet.Route.Sequence || len(plaintext) == 0 || len(plaintext) > maxPlaintextBytes {
		return Opened{}, ErrInvalidPacket
	}
	return Opened{Route: packet.Route, Plaintext: plaintext}, nil
}

// SealRequest is also used by the Go test-vector producer. Android implements
// the same wire contract in its own repository and never imports this package.
func SealRequest(device *e2ee.Identity, hub e2ee.PublicIdentity, binding Binding, route Route, plaintext []byte) ([]byte, error) {
	return seal(device, hub, binding, route, DirectionRequest, plaintext)
}

// OpenRequest authenticates and decrypts one packet. The caller must look up
// the trusted Binding and device key independently, then atomically register
// Route.Sequence/OperationID and check authorization before invoking Control.
func OpenRequest(hub *e2ee.Identity, device e2ee.PublicIdentity, binding Binding, data []byte) (Opened, error) {
	return open(hub, device, binding, data, DirectionRequest)
}

func SealResponse(hub *e2ee.Identity, device e2ee.PublicIdentity, binding Binding, route Route, plaintext []byte) ([]byte, error) {
	return seal(hub, device, binding, route, DirectionResponse, plaintext)
}

func OpenResponse(device *e2ee.Identity, hub e2ee.PublicIdentity, binding Binding, data []byte) (Opened, error) {
	return open(device, hub, binding, data, DirectionResponse)
}
