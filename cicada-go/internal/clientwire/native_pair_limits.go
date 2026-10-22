package clientwire

import "github.com/cicada-ai/cicada/internal/e2ee"

const (
	NativePairReconcileOperation   = "owner.native_pair.reconcile"
	NativePairReconcileBodyBytes   = 352 * 1024
	NativePairReconcilePacketBytes = 640 * 1024
)

func validScopedPacketLimits(r Route, bodyLimit, packetLimit int, nativePair bool) bool {
	if nativePair {
		return r.Operation == NativePairReconcileOperation && (r.Direction == DirectionRequest || r.Direction == DirectionResponse) && bodyLimit == NativePairReconcileBodyBytes && packetLimit == NativePairReconcilePacketBytes
	}
	if r.Operation == LocalDomainReconcileOperation && bodyLimit == LocalDomainReconcileBodyBytes && packetLimit == LocalDomainReconcilePacketBytes {
		return r.Direction == DirectionRequest || r.Direction == DirectionResponse
	}
	return bodyLimit > 0 && bodyLimit <= 192*1024 && packetLimit > 0 && packetLimit <= 384*1024
}

// Explicit additive recovery entries require the trusted operation route.
// Generic WithLimits/default calls retain their original ceilings.
func SealNativePairReconcileRequest(device *e2ee.Identity, hub e2ee.PublicIdentity, b Binding, r Route, body []byte) ([]byte, error) {
	if device == nil {
		return nil, ErrInvalidPacket
	}
	return sealWithScopedLimits(device.Public(), device, hub, b, r, DirectionRequest, body, device, NativePairReconcileBodyBytes, NativePairReconcilePacketBytes, true)
}
func SealNativePairReconcileResponse(hub *e2ee.Identity, device e2ee.PublicIdentity, b Binding, r Route, body []byte) ([]byte, error) {
	if hub == nil {
		return nil, ErrInvalidPacket
	}
	return sealWithScopedLimits(hub.Public(), hub, device, b, r, DirectionResponse, body, hub, NativePairReconcileBodyBytes, NativePairReconcilePacketBytes, true)
}
func OpenNativePairReconcileRequest(hub *e2ee.Identity, device e2ee.PublicIdentity, b Binding, expected Route, packet []byte) (Opened, error) {
	if hub == nil {
		return Opened{}, ErrInvalidPacket
	}
	return openWithScopedLimits(hub.Public(), hub, device, b, packet, DirectionRequest, &expected, hub, NativePairReconcileBodyBytes, NativePairReconcilePacketBytes, true)
}
func OpenNativePairReconcileResponse(device *e2ee.Identity, hub e2ee.PublicIdentity, b Binding, expected Route, packet []byte) (Opened, error) {
	if device == nil {
		return Opened{}, ErrInvalidPacket
	}
	return openWithScopedLimits(device.Public(), device, hub, b, packet, DirectionResponse, &expected, device, NativePairReconcileBodyBytes, NativePairReconcilePacketBytes, true)
}
