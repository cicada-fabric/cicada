package clientwire

import "github.com/cicada-ai/cicada/internal/e2ee"

const (
	ThreadCollaborationOwnerReconcileOperation   = "owner.thread_collaboration.reconcile"
	ThreadCollaborationOwnerReconcileBodyBytes   = 640 << 10
	ThreadCollaborationOwnerReconcilePacketBytes = 896 << 10
)

// Only this independent operation admits its exact recovery frame budget.
// Defaults, legacy identifiers and Pair-specific limits remain unchanged.
func SealThreadCollaborationOwnerReconcileRequest(device *e2ee.Identity, hub e2ee.PublicIdentity, b Binding, r Route, body []byte) ([]byte, error) {
	if device == nil || r.Operation != ThreadCollaborationOwnerReconcileOperation {
		return nil, ErrInvalidPacket
	}
	return sealWithScopedLimits(device.Public(), device, hub, b, r, DirectionRequest, body, device, ThreadCollaborationOwnerReconcileBodyBytes, ThreadCollaborationOwnerReconcilePacketBytes, false)
}
func SealThreadCollaborationOwnerReconcileResponse(hub *e2ee.Identity, device e2ee.PublicIdentity, b Binding, r Route, body []byte) ([]byte, error) {
	if hub == nil || r.Operation != ThreadCollaborationOwnerReconcileOperation {
		return nil, ErrInvalidPacket
	}
	return sealWithScopedLimits(hub.Public(), hub, device, b, r, DirectionResponse, body, hub, ThreadCollaborationOwnerReconcileBodyBytes, ThreadCollaborationOwnerReconcilePacketBytes, false)
}
func OpenThreadCollaborationOwnerReconcileRequest(hub *e2ee.Identity, device e2ee.PublicIdentity, b Binding, expected Route, packet []byte) (Opened, error) {
	if hub == nil || expected.Operation != ThreadCollaborationOwnerReconcileOperation {
		return Opened{}, ErrInvalidPacket
	}
	return openWithScopedLimits(hub.Public(), hub, device, b, packet, DirectionRequest, &expected, hub, ThreadCollaborationOwnerReconcileBodyBytes, ThreadCollaborationOwnerReconcilePacketBytes, false)
}
func OpenThreadCollaborationOwnerReconcileResponse(device *e2ee.Identity, hub e2ee.PublicIdentity, b Binding, expected Route, packet []byte) (Opened, error) {
	if device == nil || expected.Operation != ThreadCollaborationOwnerReconcileOperation {
		return Opened{}, ErrInvalidPacket
	}
	return openWithScopedLimits(device.Public(), device, hub, b, packet, DirectionResponse, &expected, device, ThreadCollaborationOwnerReconcileBodyBytes, ThreadCollaborationOwnerReconcilePacketBytes, false)
}
