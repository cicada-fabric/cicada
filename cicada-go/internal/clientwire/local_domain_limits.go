package clientwire

import "github.com/cicada-ai/cicada/internal/e2ee"

const (
	LocalDomainReconcileOperation   = "owner.local_domain.reconcile"
	LocalDomainReconcileBodyBytes   = 640 << 10
	LocalDomainReconcilePacketBytes = 896 << 10
)

// Only this independent operation admits its exact recovery frame budget.
// Defaults, legacy identifiers and Pair-specific limits remain unchanged.
func SealLocalDomainReconcileRequest(device *e2ee.Identity, hub e2ee.PublicIdentity, b Binding, r Route, body []byte) ([]byte, error) {
	if device == nil || r.Operation != LocalDomainReconcileOperation {
		return nil, ErrInvalidPacket
	}
	return sealWithScopedLimits(device.Public(), device, hub, b, r, DirectionRequest, body, device, LocalDomainReconcileBodyBytes, LocalDomainReconcilePacketBytes, false)
}
func SealLocalDomainReconcileResponse(hub *e2ee.Identity, device e2ee.PublicIdentity, b Binding, r Route, body []byte) ([]byte, error) {
	if hub == nil || r.Operation != LocalDomainReconcileOperation {
		return nil, ErrInvalidPacket
	}
	return sealWithScopedLimits(hub.Public(), hub, device, b, r, DirectionResponse, body, hub, LocalDomainReconcileBodyBytes, LocalDomainReconcilePacketBytes, false)
}
func OpenLocalDomainReconcileRequest(hub *e2ee.Identity, device e2ee.PublicIdentity, b Binding, expected Route, packet []byte) (Opened, error) {
	if hub == nil || expected.Operation != LocalDomainReconcileOperation {
		return Opened{}, ErrInvalidPacket
	}
	return openWithScopedLimits(hub.Public(), hub, device, b, packet, DirectionRequest, &expected, hub, LocalDomainReconcileBodyBytes, LocalDomainReconcilePacketBytes, false)
}
func OpenLocalDomainReconcileResponse(device *e2ee.Identity, hub e2ee.PublicIdentity, b Binding, expected Route, packet []byte) (Opened, error) {
	if device == nil || expected.Operation != LocalDomainReconcileOperation {
		return Opened{}, ErrInvalidPacket
	}
	return openWithScopedLimits(device.Public(), device, hub, b, packet, DirectionResponse, &expected, device, LocalDomainReconcileBodyBytes, LocalDomainReconcilePacketBytes, false)
}
