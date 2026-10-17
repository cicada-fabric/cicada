package clientwire

import "github.com/cicada-ai/cicada/internal/e2ee"

// Explicit additive-protocol bounds. Ordinary APIs, including N2's body-limit
// variants, retain their 256 KiB inner packet cap. Only the five N3 account
// operations use 384 KiB. Fields, route, AAD, algorithms and version stay fixed.
func SealRequestWithLimits(device *e2ee.Identity, hub e2ee.PublicIdentity, binding Binding, route Route, body []byte, bodyLimit, packetLimit int) ([]byte, error) {
	if device == nil {
		return nil, ErrInvalidPacket
	}
	return sealWithLimits(device.Public(), device, hub, binding, route, DirectionRequest, body, device, bodyLimit, packetLimit)
}

func SealResponseWithLimits(hub *e2ee.Identity, device e2ee.PublicIdentity, binding Binding, route Route, body []byte, bodyLimit, packetLimit int) ([]byte, error) {
	if hub == nil {
		return nil, ErrInvalidPacket
	}
	return sealWithLimits(hub.Public(), hub, device, binding, route, DirectionResponse, body, hub, bodyLimit, packetLimit)
}

func OpenRequestWithLimits(hub *e2ee.Identity, device e2ee.PublicIdentity, binding Binding, packet []byte, bodyLimit, packetLimit int) (Opened, error) {
	if hub == nil {
		return Opened{}, ErrInvalidPacket
	}
	return openWithLimits(hub.Public(), hub, device, binding, packet, DirectionRequest, nil, hub, bodyLimit, packetLimit)
}

func OpenResponseWithLimits(device *e2ee.Identity, hub e2ee.PublicIdentity, binding Binding, packet []byte, bodyLimit, packetLimit int) (Opened, error) {
	if device == nil {
		return Opened{}, ErrInvalidPacket
	}
	return openWithLimits(device.Public(), device, hub, binding, packet, DirectionResponse, nil, device, bodyLimit, packetLimit)
}
