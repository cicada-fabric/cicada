package clientwire

import "github.com/cicada-ai/cicada/internal/e2ee"

const (
	OwnerEndpointGroupsReconcileOperation   = "owner.endpoint_groups.reconcile"
	OwnerEndpointGroupsReconcileBodyBytes   = 640 << 10
	OwnerEndpointGroupsReconcilePacketBytes = 896 << 10
)

// Only this independent operation admits its exact recovery frame budget.
// Defaults, legacy identifiers and Pair-specific limits remain unchanged.
func SealOwnerEndpointGroupsReconcileRequest(device *e2ee.Identity, hub e2ee.PublicIdentity, b Binding, r Route, body []byte) ([]byte, error) {
	if device == nil || r.Operation != OwnerEndpointGroupsReconcileOperation {
		return nil, ErrInvalidPacket
	}
	return sealWithScopedLimits(device.Public(), device, hub, b, r, DirectionRequest, body, device, OwnerEndpointGroupsReconcileBodyBytes, OwnerEndpointGroupsReconcilePacketBytes, false)
}
func SealOwnerEndpointGroupsReconcileResponse(hub *e2ee.Identity, device e2ee.PublicIdentity, b Binding, r Route, body []byte) ([]byte, error) {
	if hub == nil || r.Operation != OwnerEndpointGroupsReconcileOperation {
		return nil, ErrInvalidPacket
	}
	return sealWithScopedLimits(hub.Public(), hub, device, b, r, DirectionResponse, body, hub, OwnerEndpointGroupsReconcileBodyBytes, OwnerEndpointGroupsReconcilePacketBytes, false)
}
func OpenOwnerEndpointGroupsReconcileRequest(hub *e2ee.Identity, device e2ee.PublicIdentity, b Binding, expected Route, packet []byte) (Opened, error) {
	if hub == nil || expected.Operation != OwnerEndpointGroupsReconcileOperation {
		return Opened{}, ErrInvalidPacket
	}
	return openWithScopedLimits(hub.Public(), hub, device, b, packet, DirectionRequest, &expected, hub, OwnerEndpointGroupsReconcileBodyBytes, OwnerEndpointGroupsReconcilePacketBytes, false)
}
func OpenOwnerEndpointGroupsReconcileResponse(device *e2ee.Identity, hub e2ee.PublicIdentity, b Binding, expected Route, packet []byte) (Opened, error) {
	if device == nil || expected.Operation != OwnerEndpointGroupsReconcileOperation {
		return Opened{}, ErrInvalidPacket
	}
	return openWithScopedLimits(device.Public(), device, hub, b, packet, DirectionResponse, &expected, device, OwnerEndpointGroupsReconcileBodyBytes, OwnerEndpointGroupsReconcilePacketBytes, false)
}
