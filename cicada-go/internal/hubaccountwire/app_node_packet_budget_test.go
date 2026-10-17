package hubaccountwire

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cicada-ai/cicada/internal/clientwire"
)

func TestAppNodeMaximumNestedReceiptTransportBudget(t *testing.T) {
	f := appNodeCrypto(t)
	status, err := NewAppNodeStatus(f.session, "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	original, err := SealClientRequest(f.device, f.hub, status)
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewAppNodeReconcile(f.session, AppNodeOriginalAuthority, "", original, f.now)
	if err != nil {
		t.Fatal(err)
	}
	request, err := SealClientRequest(f.device, f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err := NewClientRoute(f.hub, q, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	// Opaque bytes exercise the maximum carrier budget; they are not claimed
	// to be a valid nested business receipt or permission to settle an action.
	result := AppNodeReconcileResult{Format: AppNodeReconciledFormat, Origin: f.scope.Origin, HubID: f.hub.HubID, AccountID: f.scope.AccountID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, RequestID: q.Context.RequestID, RequestPacketDigest: AppNodePacketDigest(request),
		OriginalKind: AppNodeOriginalAuthority, OriginalOperation: OperationAppNodeStatus, OriginalRequestID: status.Context.RequestID, OriginalPacketDigest: AppNodePacketDigest(original), State: AppNodeCompleted, ReceiptPacket: make([]byte, MaxAppNodeReceiptBytes), AccountEpoch: 1, DeviceEpoch: 1, CurrentGrantState: AppNodeAbsent, ObservedAt: formatUTC(f.now)}
	reply, err := SealResponse(f.hubPrivate, f.device.Public(), r, result)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := json.Marshal(p.Packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(inner) <= MaxInnerPacketBytes || len(inner) > MaxAppNodeInnerPacketBytes || len(reply) > MaxPacketBytes {
		t.Fatal("maximum carrier did not exercise the N3-only inner bound")
	}
	var got AppNodeReconcileResult
	if err := OpenClientResponse(f.device, f.hub, request, reply, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.ReceiptPacket, result.ReceiptPacket) {
		t.Fatal("nested maximum carrier changed")
	}
	if _, err := clientwire.OpenResponseWithBodyLimit(f.device, f.hub.Public, b, inner, MaxAppNodeBodyBytes); err == nil {
		t.Fatal("default/N2 packet cap silently widened")
	}
	p.Packet.Route.Operation = OperationActivationStatus
	legacy, _ := json.Marshal(p)
	if _, err := DecodePacket(legacy); err == nil {
		t.Fatal("N2 accepted the enlarged N3 inner frame")
	}
	if _, err := DecodePacket(append(reply, bytes.Repeat([]byte{' '}, MaxPacketBytes-len(reply)+1)...)); err == nil {
		t.Fatal("outer cap widened")
	}
	result.ReceiptPacket = append(result.ReceiptPacket, 0)
	if _, err := SealResponse(f.hubPrivate, f.device.Public(), r, result); err == nil {
		t.Fatal("oversized nested carrier accepted")
	}
}
