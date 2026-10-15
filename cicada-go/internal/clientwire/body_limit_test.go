package clientwire

import (
	"bytes"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestExplicitLargerBodyDoesNotExpandFrozenClientDefaults(t *testing.T) {
	hub, _ := e2ee.NewIdentity()
	device, _ := e2ee.NewIdentity()
	b := Binding{HubID: "hub_synthetic", OwnerID: "owner_synthetic", DeviceID: "device_synthetic", SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	r := Route{Version: 1, Direction: DirectionRequest, HubID: b.HubID, OwnerID: b.OwnerID, DeviceID: b.DeviceID, SessionEpoch: 1, Sequence: 1, OperationID: "synthetic-larger-body", Operation: "owner.account.reconcile", SenderKeyID: device.Public().ID, ReceiverKeyID: hub.Public().ID, SenderKeyVersion: 1, ReceiverKeyVersion: 1}
	body := bytes.Repeat([]byte("S"), 100*1024)
	if _, err := SealRequest(device, hub.Public(), b, r, body); err == nil {
		t.Fatal("ordinary Client request default expanded beyond 64KiB")
	}
	packet, err := SealRequestWithBodyLimit(device, hub.Public(), b, r, body, 192*1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenRequest(hub, device.Public(), b, packet); err == nil {
		t.Fatal("ordinary Client ingress accepted larger additive body")
	}
	opened, err := OpenRequestWithBodyLimit(hub, device.Public(), b, packet, 192*1024)
	if err != nil || !bytes.Equal(opened.Plaintext, body) {
		t.Fatal("explicit bounded request failed")
	}
	r.Direction = DirectionResponse
	r.SenderKeyID = hub.Public().ID
	r.ReceiverKeyID = device.Public().ID
	if _, err = SealResponse(hub, device.Public(), b, r, body); err == nil {
		t.Fatal("ordinary Client response default expanded")
	}
	packet, err = SealResponseWithBodyLimit(hub, device.Public(), b, r, body, 192*1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenResponse(device, hub.Public(), b, packet); err == nil {
		t.Fatal("ordinary Client receiver accepted larger additive body")
	}
	opened, err = OpenResponseWithBodyLimit(device, hub.Public(), b, packet, 192*1024)
	if err != nil || !bytes.Equal(opened.Plaintext, body) {
		t.Fatal("explicit bounded response failed")
	}
	if _, err = OpenResponseWithBodyLimit(device, hub.Public(), b, packet, 193*1024); err == nil {
		t.Fatal("unbounded body limit accepted")
	}
}
