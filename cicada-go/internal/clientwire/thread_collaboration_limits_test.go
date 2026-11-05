package clientwire

import (
	"bytes"
	"testing"
)

func TestThreadCollaborationOwnerReconcileBoundsAndExactRoute(t *testing.T) {
	hub, device, binding, route := wireFixture(t)
	route.Operation = ThreadCollaborationOwnerReconcileOperation
	// Actual ML-KEM/ML-DSA envelope sized for a bounded original plus proof.
	// This carrier fixture is not a maximum legal product DTO measurement.
	body := bytes.Repeat([]byte("S"), 384<<10)
	packet, err := SealThreadCollaborationOwnerReconcileRequest(device, hub.Public(), binding, route, body)
	if err != nil || len(packet) > ThreadCollaborationOwnerReconcilePacketBytes {
		t.Fatal("bounded recovery carrier", err)
	}
	opened, err := OpenThreadCollaborationOwnerReconcileRequest(hub, device.Public(), binding, route, packet)
	if err != nil || !bytes.Equal(opened.Plaintext, body) {
		t.Fatal("exact recovery carrier", err)
	}
	if _, err := OpenRequestWithLimits(hub, device.Public(), binding, packet, ThreadCollaborationOwnerReconcileBodyBytes, ThreadCollaborationOwnerReconcilePacketBytes); err == nil {
		t.Fatal("generic opening borrowed a large budget without a trusted expected route")
	}
	for _, op := range []string{"status.snapshot", LocalDomainReconcileOperation, NativePairReconcileOperation, "owner.thread_collaboration.reconcile.extra"} {
		wrong := route
		wrong.Operation = op
		if _, err := SealThreadCollaborationOwnerReconcileRequest(device, hub.Public(), binding, wrong, body); err == nil {
			t.Fatal("unknown/legacy operation borrowed profile entry")
		}
		if _, err := OpenThreadCollaborationOwnerReconcileRequest(hub, device.Public(), binding, wrong, packet); err == nil {
			t.Fatal("wrong expected route opened recovery")
		}
	}
	if _, err := SealRequest(device, hub.Public(), binding, route, body); err == nil {
		t.Fatal("default body bound enlarged")
	}
	if _, err := SealThreadCollaborationOwnerReconcileRequest(device, hub.Public(), binding, route, make([]byte, ThreadCollaborationOwnerReconcileBodyBytes+1)); err == nil {
		t.Fatal("oversized plaintext accepted")
	}
	if _, err := OpenThreadCollaborationOwnerReconcileRequest(hub, device.Public(), binding, route, make([]byte, ThreadCollaborationOwnerReconcilePacketBytes+1)); err == nil {
		t.Fatal("oversized packet accepted")
	}
	response := route
	response.Direction = DirectionResponse
	response.SenderKeyID, response.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
	response.SenderKeyVersion, response.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
	sealed, err := SealThreadCollaborationOwnerReconcileResponse(hub, device.Public(), binding, response, body)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenThreadCollaborationOwnerReconcileResponse(device, hub.Public(), binding, response, sealed); err != nil || !bytes.Equal(got.Plaintext, body) {
		t.Fatal("recovery response", err)
	}
}
