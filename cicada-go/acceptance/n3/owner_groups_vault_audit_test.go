package n3_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Read the actual closed fixture App's protected record; never write a vault
// slot or manufacture a signed request. DTOs and ciphertext remain private.
type ownerGroupsStoredPacket struct {
	Format, DeviceKeyID, OwnerKeyID string
	NodeID, NetworkID               string
	Route                           clientwire.Route
	Digest, ParentDigest            string
	DTO                             json.RawMessage
	Applied                         bool
	Review                          *wire.OwnerEndpointGroupsReview
	ExpectedHead                    *e2ee.EndpointGroupOwnerControl
	packet                          []byte
}

func ownerGroupsStoredPacketAt(t *testing.T, v *codexProductFixture, namespace string) *ownerGroupsStoredPacket {
	t.Helper()
	if v.app.running() {
		t.Fatal("actual App must stop before inspecting its protected original")
	}
	vault := ownedAppVault(t, v.f)
	raw, _, found, err := vault.LoadState(namespace)
	if vault.Close() != nil || err != nil || !found || len(raw) < 9 || len(raw) > 1<<20 || string(raw[:4]) != "CEG1" {
		clear(raw)
		t.Fatal("actual App Group packet record is missing or malformed")
	}
	defer clear(raw)
	n := int(binary.BigEndian.Uint32(raw[4:8]))
	if n < 1 || n > 256<<10 || n >= len(raw)-8 {
		t.Fatal("actual App Group packet record exceeded its bounded framing")
	}
	var record ownerGroupsStoredPacket
	if json.Unmarshal(raw[8:8+n], &record) != nil {
		t.Fatal("actual App Group packet metadata is malformed")
	}
	record.packet = append([]byte(nil), raw[8+n:]...)
	t.Cleanup(func() { clear(record.packet); clear(record.DTO) })
	if record.DeviceKeyID == "" || record.OwnerKeyID != v.original.Account.LocalOwnerKeyID ||
		record.NodeID != v.actualNode.id || record.NetworkID == "" || wire.OwnerEndpointGroupsPacketDigest(record.packet) != record.Digest ||
		record.Route.HubID != v.f.cfg.Hub.HubID || record.Route.OwnerID != v.original.Account.OwnerID || record.Route.DeviceID != v.original.Account.DeviceID {
		t.Fatal("actual App Group record changed the original device, Owner, scope or ciphertext")
	}
	return &record
}

func ownerGroupsOriginalApply(t *testing.T, v *codexProductFixture, observed exchange) (*ownerGroupsStoredPacket, wire.OwnerEndpointGroupsApplyRequest) {
	t.Helper()
	record := ownerGroupsStoredPacketAt(t, v, "appcore.endpoint-groups-original.v1")
	device := ownedAppIdentity(t, v.f, appvault.PurposeAppDevice)
	packet, err := wire.DecodeOwnerEndpointGroupsPacket(record.packet)
	decoded, dtoErr := wire.DecodeOwnerEndpointGroupsRequest(wire.OperationOwnerEndpointGroupsApply, record.DTO, v.f.cfg.Hub, time.Time{})
	request, ok := decoded.(wire.OwnerEndpointGroupsApplyRequest)
	if record.DeviceKeyID != device.Public().ID || record.Format != "cicada.app-endpoint-groups.request.v1" || record.Route.Operation != wire.OperationOwnerEndpointGroupsApply || record.Applied ||
		err != nil || dtoErr != nil || !ok || !reflect.DeepEqual(packet.Packet.Route, record.Route) || request.Context.RequestID != record.Route.OperationID ||
		!bytes.Equal(record.packet, observed.request) || observed.RequestSHA256 != hash(record.packet) || record.Review == nil ||
		request.Body.ReviewID != record.Review.ReviewID || request.Body.ReviewDigest != record.Review.ReviewDigest {
		t.Fatal("actual closed App did not retain the exact unresolved original APPLY and reviewed intent")
	}
	return record, request
}

// Verify the nested ORIGINAL sealed receipt, bound to its exact original ID
// and ciphertext digest. Neither the recovery wrapper nor an empty SQL row can
// settle the unseen-original case. Historical receipt is not current authority.
func ownerGroupsOriginalReceipt(t *testing.T, v *codexProductFixture, original *ownerGroupsStoredPacket, request wire.OwnerEndpointGroupsApplyRequest, wrapper exchange, wantFence bool) wire.OwnerEndpointGroupsResult {
	t.Helper()
	if v.app.running() {
		t.Fatal("actual App must stop before auditing the accepted recovery receipt")
	}
	recovery := ownerGroupsStoredPacketAt(t, v, "appcore.endpoint-groups-recovery.v1")
	packet, packetErr := wire.DecodeOwnerEndpointGroupsPacket(recovery.packet)
	if recovery.DeviceKeyID != original.DeviceKeyID || recovery.Format != "cicada.app-endpoint-groups.request.v1" ||
		recovery.Route.Operation != wire.OperationOwnerEndpointGroupsReconcile || recovery.ParentDigest != original.Digest ||
		packetErr != nil || !reflect.DeepEqual(packet.Packet.Route, recovery.Route) || !bytes.Equal(recovery.packet, wrapper.request) ||
		wrapper.Method != http.MethodPost || wrapper.Path != wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsReconcile) ||
		!wrapper.Forwarded || wrapper.Status != http.StatusOK || wrapper.RequestSHA256 != hash(recovery.packet) || wrapper.ResponseSHA256 != hash(wrapper.response) {
		t.Fatal("actual App recovery replaced its original ciphertext/intent reference")
	}
	var recoveryRequest wire.OwnerEndpointGroupsReconcileRequest
	if json.Unmarshal(recovery.DTO, &recoveryRequest) != nil || len(recoveryRequest.Body.OriginalPacket) != 0 {
		t.Fatal("actual App recovery record changed its bounded original reference")
	}
	recoveryRequest.Body.OriginalPacket = original.packet
	if wire.ValidateOwnerEndpointGroupsRequest(recoveryRequest, v.f.cfg.Hub, time.Time{}) != nil {
		t.Fatal("actual App recovery proof does not bind the exact retained original")
	}
	device := ownedAppIdentity(t, v.f, appvault.PurposeAppDevice)
	// A settled query observation is retired after authenticating its nested
	// original receipt. Independently authenticate the actual TCP response;
	// upstream HTTP 200 alone never proves what the stopped App accepted.
	outer := openOwnerGroupsCapturedResponse(t, v, device, recoveryRequest, recovery.packet, wrapper.response)
	vault := ownedAppVault(t, v.f)
	retired, _, _, loadErr := vault.LoadState("appcore.endpoint-groups-recovery-response.v1")
	closeErr := vault.Close()
	defer clear(retired)
	if loadErr != nil || closeErr != nil || len(retired) != 0 {
		t.Fatal("actual App did not retire its authenticated settled query-response slot")
	}
	accepted := ownerGroupsStoredPacketAt(t, v, "appcore.endpoint-groups-response.v1")
	if accepted.DeviceKeyID != original.DeviceKeyID || len(outer.ReceiptPacket) == 0 || !bytes.Equal(accepted.packet, outer.ReceiptPacket) || accepted.ParentDigest != original.Digest ||
		!reflect.DeepEqual(accepted.Route, original.Route) {
		t.Fatal("actual App did not independently retain the original nested sealed receipt")
	}
	nested := openOwnerGroupsCapturedResponse(t, v, device, request, original.packet, accepted.packet)
	if wantFence {
		if wire.VerifyOwnerEndpointGroupsOriginalFence(request, original.packet, nested, v.f.cfg.Hub) != nil {
			t.Fatal("unseen original lacks its exact targetless permanent no-effect fence")
		}
	} else {
		requireOwnerGroupsCapturedOperation(t, *original.Review, original.packet, nested, original.ExpectedHead)
		if nested.Operation.State != "COMPLETED" || nested.Operation.ErrorCode != "" {
			t.Fatal("actual original mutation has no completed authenticated historical receipt")
		}
	}
	return nested
}
