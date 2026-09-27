package clientwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func wireFixture(t *testing.T) (*e2ee.Identity, *e2ee.Identity, Binding, Route) {
	t.Helper()
	hub, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{HubID: "hub-one", OwnerID: "owner-one", DeviceID: "android-one",
		SessionEpoch: 7, HubKeyVersion: 3, DeviceKeyVersion: 2}
	route := Route{Version: Version, Direction: DirectionRequest, HubID: binding.HubID,
		OwnerID: binding.OwnerID, DeviceID: binding.DeviceID, SessionEpoch: binding.SessionEpoch,
		Sequence: 11, OperationID: "op-one", Operation: "status.snapshot",
		SenderKeyID: device.Public().ID, SenderKeyVersion: binding.DeviceKeyVersion,
		ReceiverKeyID: hub.Public().ID, ReceiverKeyVersion: binding.HubKeyVersion}
	return hub, device, binding, route
}

func TestClientWireRequestResponseRoundTrip(t *testing.T) {
	hub, device, binding, requestRoute := wireFixture(t)
	wire, err := SealRequest(device, hub.Public(), binding, requestRoute, []byte(`{"cursor":""}`))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(`"cursor"`)) {
		t.Fatal("request plaintext appeared in packet")
	}
	opened, err := OpenRequest(hub, device.Public(), binding, wire)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Route != requestRoute || string(opened.Plaintext) != `{"cursor":""}` {
		t.Fatalf("unexpected authenticated request: %#v", opened)
	}
	responseRoute := requestRoute
	responseRoute.Direction = DirectionResponse
	responseRoute.Sequence = 23
	responseRoute.SenderKeyID, responseRoute.ReceiverKeyID = hub.Public().ID, device.Public().ID
	responseRoute.SenderKeyVersion, responseRoute.ReceiverKeyVersion = binding.HubKeyVersion, binding.DeviceKeyVersion
	response, err := SealResponse(hub, device.Public(), binding, responseRoute, []byte(`{"nodes":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	result, err := OpenResponse(device, hub.Public(), binding, response)
	if err != nil || result.Route != responseRoute || string(result.Plaintext) != `{"nodes":[]}` {
		t.Fatalf("unexpected authenticated response: %#v, %v", result, err)
	}
}

func TestClientWireRejectsWrongTrustedBindingAndHeaderTamper(t *testing.T) {
	hub, device, binding, route := wireFixture(t)
	wire, err := SealRequest(device, hub.Public(), binding, route, []byte("sensitive intent"))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Binding){
		"hub":                func(v *Binding) { v.HubID = "wrong-hub" },
		"owner":              func(v *Binding) { v.OwnerID = "other-owner" },
		"device":             func(v *Binding) { v.DeviceID = "other-device" },
		"epoch":              func(v *Binding) { v.SessionEpoch++ },
		"hub-key-version":    func(v *Binding) { v.HubKeyVersion++ },
		"device-key-version": func(v *Binding) { v.DeviceKeyVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			change(&changed)
			if _, err := OpenRequest(hub, device.Public(), changed, wire); !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("wrong trusted binding accepted: %v", err)
			}
		})
	}
	other, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRequest(hub, other.Public(), binding, wire); err == nil {
		t.Fatal("unregistered sender accepted")
	}
	var packet Packet
	if err := json.Unmarshal(wire, &packet); err != nil {
		t.Fatal(err)
	}
	packet.Route.Operation = "approval.decide"
	tampered, err := json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRequest(hub, device.Public(), binding, tampered); err == nil {
		t.Fatal("tampered operation accepted")
	}
	packet.Route = route
	packet.Route.Direction = DirectionResponse
	tampered, err = json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRequest(hub, device.Public(), binding, tampered); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("wrong direction accepted: %v", err)
	}
}

func TestClientWireRejectsInvalidSizeAndMetadata(t *testing.T) {
	hub, device, binding, route := wireFixture(t)
	if _, err := SealRequest(device, hub.Public(), binding, route, []byte(strings.Repeat("x", maxPlaintextBytes+1))); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("oversize plaintext accepted: %v", err)
	}
	route.Sequence = 0
	if _, err := SealRequest(device, hub.Public(), binding, route, []byte("hello")); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("zero sequence accepted: %v", err)
	}
	route.Sequence = 1
	route.OperationID = " bad id "
	if _, err := SealRequest(device, hub.Public(), binding, route, []byte("hello")); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("noncanonical operation ID accepted: %v", err)
	}
	if _, err := OpenRequest(hub, device.Public(), binding, append([]byte(`{"route":{}}`), []byte(` {}`)...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
