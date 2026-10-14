package clientwire

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type wirePrivateOperations struct {
	identity            *e2ee.Identity
	signs, decapsulates int
}

func (o *wirePrivateOperations) Sign(message []byte) ([]byte, error) {
	o.signs++
	return o.identity.Sign(message)
}
func (o *wirePrivateOperations) MLKEMDecapsulate(ciphertext []byte) ([]byte, error) {
	o.decapsulates++
	return o.identity.MLKEMDecapsulate(ciphertext)
}

func TestClientWirePrivateOperationsRequireExactRouteBeforePrivateUse(t *testing.T) {
	hub, device, binding, requestRoute := wireFixture(t)
	expected := requestRoute
	expected.Direction = DirectionResponse
	expected.SenderKeyID, expected.ReceiverKeyID = hub.Public().ID, device.Public().ID
	expected.SenderKeyVersion, expected.ReceiverKeyVersion = binding.HubKeyVersion, binding.DeviceKeyVersion
	packet, e := SealResponse(hub, device.Public(), binding, expected, []byte(`{"synthetic":"response"}`))
	if e != nil {
		t.Fatal(e)
	}
	ops := &wirePrivateOperations{identity: device}
	opened, e := OpenResponseWithPrivateOperations(device.Public(), ops, hub.Public(), binding, expected, packet)
	if e != nil || ops.decapsulates != 1 || ops.signs != 0 || !bytes.Equal(opened.Plaintext, []byte(`{"synthetic":"response"}`)) {
		t.Fatalf("external response open failed: %v", e)
	}
	for _, change := range []func(*Route){
		func(r *Route) { r.Version++ }, func(r *Route) { r.Direction = DirectionRequest },
		func(r *Route) { r.HubID = "synthetic-other" }, func(r *Route) { r.OwnerID = "synthetic-other" },
		func(r *Route) { r.DeviceID = "synthetic-other" }, func(r *Route) { r.SessionEpoch++ },
		func(r *Route) { r.Sequence++ }, func(r *Route) { r.OperationID = "synthetic-other" },
		func(r *Route) { r.Operation = "synthetic.other" }, func(r *Route) { r.SenderKeyID = "synthetic-other" },
		func(r *Route) { r.ReceiverKeyID = "synthetic-other" }, func(r *Route) { r.SenderKeyVersion++ },
		func(r *Route) { r.ReceiverKeyVersion++ },
	} {
		var p Packet
		if json.Unmarshal(packet, &p) != nil {
			t.Fatal("decode fixture")
		}
		change(&p.Route)
		raw, _ := json.Marshal(p)
		ops := &wirePrivateOperations{identity: device}
		if _, e = OpenResponseWithPrivateOperations(device.Public(), ops, hub.Public(), binding, expected, raw); e == nil || ops.decapsulates != 0 || ops.signs != 0 {
			t.Fatal("changed route invoked private callback")
		}
	}
	// Envelope sequence is part of the same route commitment. Even a valid
	// Hub signature cannot ask the provider to decapsulate a mismatched frame.
	associated, _ := aad(expected)
	wrongEnvelope, e := e2ee.Seal(hub, device.Public(), []byte(`{}`), associated, expected.Sequence+1)
	if e != nil {
		t.Fatal(e)
	}
	wrongSequencePacket, _ := json.Marshal(Packet{Route: expected, Envelope: wrongEnvelope})
	ops = &wirePrivateOperations{identity: device}
	if _, e = OpenResponseWithPrivateOperations(device.Public(), ops, hub.Public(), binding, expected, wrongSequencePacket); e == nil || ops.decapsulates != 0 {
		t.Fatal("signed envelope sequence mismatch invoked decapsulation")
	}
	// Even an authentic Hub signature does not turn a different operation into
	// permission to invoke the candidate's private key for this scoped opener.
	wrong := expected
	wrong.Operation = "synthetic.other"
	wrongPacket, e := SealResponse(hub, device.Public(), binding, wrong, []byte(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	ops = &wirePrivateOperations{identity: device}
	if _, e = OpenResponseWithPrivateOperations(device.Public(), ops, hub.Public(), binding, expected, wrongPacket); e == nil || ops.decapsulates != 0 {
		t.Fatal("authentic wrong-purpose packet invoked decapsulation")
	}
}

func TestClientWirePrivateOperationsRequestKeepsExistingFrames(t *testing.T) {
	hub, device, binding, route := wireFixture(t)
	ops := &wirePrivateOperations{identity: device}
	packet, e := SealRequestWithPrivateOperations(device.Public(), ops, hub.Public(), binding, route, []byte(`{"synthetic":"request"}`))
	if e != nil {
		t.Fatal(e)
	}
	opened, e := OpenRequest(hub, device.Public(), binding, packet)
	if e != nil || opened.Route != route || ops.signs != 1 || ops.decapsulates != 0 {
		t.Fatalf("external request incompatible with ordinary opener: %v", e)
	}
	wrong := route
	wrong.ReceiverKeyID = "synthetic-other"
	ops = &wirePrivateOperations{identity: device}
	if _, e = SealRequestWithPrivateOperations(device.Public(), ops, hub.Public(), binding, wrong, []byte(`{}`)); e == nil || ops.signs != 0 {
		t.Fatal("wrong receiver invoked external signer")
	}
}
