package hubaccountwire

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

// NewRequestID returns a 128-bit random lower-case hexadecimal request ID.
func NewRequestID() (string, error) { return randomHex(RequestIDBytes) }

// NewNonce returns a fresh 256-bit application challenge nonce.
func NewNonce() ([]byte, error) { return randomBytes(NonceBytes) }

// NewClientRoute returns the fixed one-packet account route for the supplied
// typed request. Handshake routes use epoch one; session routes use account epoch.
func NewClientRoute(hub HubIdentity, body any, device e2ee.PublicIdentity) (clientwire.Binding, clientwire.Route, error) {
	operation, requestID, ownerID, deviceID, epoch, err := requestRouteMetadata(body)
	if err != nil || validateHubIdentity(hub) != nil || e2ee.ValidatePublicIdentity(device) != nil {
		return clientwire.Binding{}, clientwire.Route{}, ErrInvalid
	}
	route := routeFor(hub, ownerID, deviceID, epoch, requestID, operation, device, hub.Public, clientwire.DirectionRequest)
	binding := clientwire.Binding{HubID: hub.HubID, OwnerID: ownerID, DeviceID: deviceID,
		SessionEpoch: epoch, HubKeyVersion: hub.KeyVersion, DeviceKeyVersion: DeviceKeyVersion}
	return binding, route, nil
}

// SealClientRequest creates one canonical account packet. Request IDs and
// purpose/route values must come from the typed constructors, not UI fields.
func SealClientRequest(device *e2ee.Identity, hub HubIdentity, body any) ([]byte, error) {
	if device == nil || validateHubIdentity(hub) != nil || validateRequestBody(body, hub, time.Time{}) != nil ||
		validateRequestMatchesDevice(body, device.Public()) != nil {
		return nil, ErrInvalid
	}
	binding, route, err := NewClientRoute(hub, body, device.Public())
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(body)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(plaintext)
	if len(plaintext) > maxBodyForOperation(route.Operation) {
		return nil, ErrInvalid
	}
	var inner []byte
	if route.Operation == OperationOwnerEndpointGroupsReconcile {
		inner, err = clientwire.SealOwnerEndpointGroupsReconcileRequest(device, hub.Public, binding, route, plaintext)
	} else if route.Operation == OperationNativePairReconcile {
		inner, err = clientwire.SealNativePairReconcileRequest(device, hub.Public, binding, route, plaintext)
	} else if route.Operation == OperationLocalDomainReconcile {
		inner, err = clientwire.SealLocalDomainReconcileRequest(device, hub.Public, binding, route, plaintext)
	} else if nativePairOperation(route.Operation) || localDomainOperation(route.Operation) || ownerEndpointGroupsOperation(route.Operation) {
		inner, err = clientwire.SealRequestWithLimits(device, hub.Public, binding, route, plaintext, maxBodyForOperation(route.Operation), innerLimitForOperation(route.Operation))
	} else if appNodeOperation(route.Operation) {
		inner, err = clientwire.SealRequestWithLimits(device, hub.Public, binding, route, plaintext, MaxAppNodeBodyBytes, MaxAppNodeInnerPacketBytes)
	} else if extensionOperation(route.Operation) {
		inner, err = clientwire.SealRequestWithBodyLimit(device, hub.Public, binding, route, plaintext, MaxActivationBodyBytes)
	} else {
		inner, err = clientwire.SealRequest(device, hub.Public, binding, route, plaintext)
	}
	if err != nil {
		return nil, err
	}
	var packet clientwire.Packet
	if err := decodeCanonical(inner, innerLimitForOperation(route.Operation), &packet); err != nil {
		return nil, ErrInvalid
	}
	return marshalPacket(Packet{Format: PacketFormat, Version: PacketVersion,
		SenderPublicIdentity: device.Public(), Packet: packet})
}

// PreflightRequest performs bounded canonical outer validation before any PQ
// decapsulation. It does not authorize the sender or decrypt protected fields.
func PreflightRequest(raw []byte, expectedOperation string) (Packet, error) {
	packet, err := decodePacketForOperation(raw, expectedOperation)
	if err != nil || packet.Packet.Route.Direction != clientwire.DirectionRequest ||
		packet.Packet.Route.Operation != expectedOperation || !knownOperation(expectedOperation) {
		return Packet{}, ErrInvalid
	}
	return packet, nil
}

// OpenRequest authenticates and decrypts a preflighted request. A nil trusted
// device is allowed only for initial claim.prepare, where the public identity
// is a candidate and the finite claim code remains the actual authority.
func OpenRequest(hub *e2ee.Identity, trustedDevice *e2ee.PublicIdentity, binding clientwire.Binding, expectedRoute clientwire.Route, raw []byte, out any) error {
	return OpenRequestAt(hub, trustedDevice, binding, expectedRoute, raw, out, time.Now().UTC())
}

func OpenRequestAt(hub *e2ee.Identity, trustedDevice *e2ee.PublicIdentity, binding clientwire.Binding, expectedRoute clientwire.Route, raw []byte, out any, now time.Time) error {
	packet, err := decodePacketForOperation(raw, expectedRoute.Operation)
	if err != nil || hub == nil || expectedRoute.Direction != clientwire.DirectionRequest ||
		packet.Packet.Route != expectedRoute || !validBinding(binding, expectedRoute) ||
		(expectedRoute.Operation != OperationClaimPrepare && expectedRoute.Operation != OperationActivationPrepare && trustedDevice == nil) {
		return ErrInvalid
	}
	if trustedDevice != nil && !reflect.DeepEqual(packet.SenderPublicIdentity, *trustedDevice) {
		return ErrInvalid
	}
	inner, err := json.Marshal(packet.Packet)
	if err != nil || len(inner) > innerLimitForOperation(expectedRoute.Operation) {
		return ErrInvalid
	}
	var opened clientwire.Opened
	if expectedRoute.Operation == OperationOwnerEndpointGroupsReconcile {
		opened, err = clientwire.OpenOwnerEndpointGroupsReconcileRequest(hub, packet.SenderPublicIdentity, binding, expectedRoute, inner)
	} else if expectedRoute.Operation == OperationNativePairReconcile {
		opened, err = clientwire.OpenNativePairReconcileRequest(hub, packet.SenderPublicIdentity, binding, expectedRoute, inner)
	} else if expectedRoute.Operation == OperationLocalDomainReconcile {
		opened, err = clientwire.OpenLocalDomainReconcileRequest(hub, packet.SenderPublicIdentity, binding, expectedRoute, inner)
	} else if nativePairOperation(expectedRoute.Operation) || localDomainOperation(expectedRoute.Operation) || ownerEndpointGroupsOperation(expectedRoute.Operation) {
		opened, err = clientwire.OpenRequestWithLimits(hub, packet.SenderPublicIdentity, binding, inner, maxBodyForOperation(expectedRoute.Operation), innerLimitForOperation(expectedRoute.Operation))
	} else if appNodeOperation(expectedRoute.Operation) {
		opened, err = clientwire.OpenRequestWithLimits(hub, packet.SenderPublicIdentity, binding, inner, MaxAppNodeBodyBytes, MaxAppNodeInnerPacketBytes)
	} else if extensionOperation(expectedRoute.Operation) {
		opened, err = clientwire.OpenRequestWithBodyLimit(hub, packet.SenderPublicIdentity, binding, inner, MaxActivationBodyBytes)
	} else {
		opened, err = clientwire.OpenRequest(hub, packet.SenderPublicIdentity, binding, inner)
	}
	if err != nil {
		return ErrInvalid
	}
	defer clear(opened.Plaintext)
	if opened.Route != expectedRoute || len(opened.Plaintext) > maxBodyForOperation(expectedRoute.Operation) {
		return ErrInvalid
	}
	if err := decodeCanonical(opened.Plaintext, maxBodyForOperation(expectedRoute.Operation), out); err != nil {
		return err
	}
	verifiedHub := HubIdentity{Contract: "android-hub-v1", HubID: binding.HubID, Public: hub.Public(),
		KeyVersion: binding.HubKeyVersion, Suite: ownerbootstrap.Suite}
	if expectedRoute.ReceiverKeyID != hub.Public().ID || expectedRoute.ReceiverKeyVersion != binding.HubKeyVersion ||
		validateRequestBody(out, verifiedHub, now) != nil || validateRequestMatchesDevice(out, packet.SenderPublicIdentity) != nil {
		return ErrInvalid
	}
	operation, requestID, ownerID, deviceID, epoch, err := requestRouteMetadata(out)
	if err != nil || operation != expectedRoute.Operation || requestID != expectedRoute.OperationID ||
		ownerID != expectedRoute.OwnerID || deviceID != expectedRoute.DeviceID || epoch != expectedRoute.SessionEpoch {
		return ErrInvalid
	}
	return nil
}

// SealResponse returns a Hub-signed and device-encrypted response with the
// exact operation ID/op mirrored from the request for durable exact retry.
func SealResponse(hub *e2ee.Identity, device e2ee.PublicIdentity, requestRoute clientwire.Route, body any) ([]byte, error) {
	if hub == nil || e2ee.ValidatePublicIdentity(device) != nil || requestRoute.Direction != clientwire.DirectionRequest ||
		!knownOperation(requestRoute.Operation) || requestRoute.Sequence != PacketSequence ||
		validateResponseForRoute(body, requestRoute) != nil {
		return nil, ErrInvalid
	}
	route := requestRoute
	route.Direction = clientwire.DirectionResponse
	route.SenderKeyID, route.ReceiverKeyID = requestRoute.ReceiverKeyID, requestRoute.SenderKeyID
	route.SenderKeyVersion, route.ReceiverKeyVersion = requestRoute.ReceiverKeyVersion, requestRoute.SenderKeyVersion
	plaintext, err := json.Marshal(body)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(plaintext)
	if len(plaintext) > maxBodyForOperation(route.Operation) {
		return nil, ErrInvalid
	}
	public := hub.Public()
	if public.ID != route.SenderKeyID || device.ID != route.ReceiverKeyID {
		return nil, ErrInvalid
	}
	binding := clientwire.Binding{HubID: route.HubID, OwnerID: route.OwnerID, DeviceID: route.DeviceID,
		SessionEpoch: route.SessionEpoch, HubKeyVersion: route.SenderKeyVersion, DeviceKeyVersion: route.ReceiverKeyVersion}
	var inner []byte
	if route.Operation == OperationOwnerEndpointGroupsReconcile {
		inner, err = clientwire.SealOwnerEndpointGroupsReconcileResponse(hub, device, binding, route, plaintext)
	} else if route.Operation == OperationNativePairReconcile {
		inner, err = clientwire.SealNativePairReconcileResponse(hub, device, binding, route, plaintext)
	} else if route.Operation == OperationLocalDomainReconcile {
		inner, err = clientwire.SealLocalDomainReconcileResponse(hub, device, binding, route, plaintext)
	} else if nativePairOperation(route.Operation) || localDomainOperation(route.Operation) || ownerEndpointGroupsOperation(route.Operation) {
		inner, err = clientwire.SealResponseWithLimits(hub, device, binding, route, plaintext, maxBodyForOperation(route.Operation), innerLimitForOperation(route.Operation))
	} else if appNodeOperation(route.Operation) {
		inner, err = clientwire.SealResponseWithLimits(hub, device, binding, route, plaintext, MaxAppNodeBodyBytes, MaxAppNodeInnerPacketBytes)
	} else if extensionOperation(route.Operation) {
		inner, err = clientwire.SealResponseWithBodyLimit(hub, device, binding, route, plaintext, MaxActivationBodyBytes)
	} else {
		inner, err = clientwire.SealResponse(hub, device, binding, route, plaintext)
	}
	if err != nil {
		return nil, err
	}
	var innerPacket clientwire.Packet
	if err := decodeCanonical(inner, innerLimitForOperation(route.Operation), &innerPacket); err != nil {
		return nil, ErrInvalid
	}
	return marshalPacket(Packet{Format: PacketFormat, Version: PacketVersion,
		SenderPublicIdentity: public, Packet: innerPacket})
}

// OpenClientResponse checks the full pinned Hub identity and exact response
// route derived from the original request before opening the envelope.
func OpenClientResponse(device *e2ee.Identity, hub HubIdentity, requestBytes, responseBytes []byte, out any) error {
	request, err := DecodePacket(requestBytes)
	if err != nil {
		return ErrInvalid
	}
	return openClientResponsePacket(device, hub, request, requestBytes, responseBytes, out)
}

// OpenLocalDomainResponse admits only this profile's explicitly bounded frames.
// The legacy OpenClientResponse/DecodePacket frame limit remains unchanged.
func OpenLocalDomainResponse(device *e2ee.Identity, hub HubIdentity, requestBytes, responseBytes []byte, out any) error {
	request, err := DecodeLocalDomainPacket(requestBytes)
	if err != nil {
		return ErrInvalid
	}
	return openClientResponsePacket(device, hub, request, requestBytes, responseBytes, out)
}

func openClientResponsePacket(device *e2ee.Identity, hub HubIdentity, request Packet, requestBytes, responseBytes []byte, out any) error {
	if device == nil || validateHubIdentity(hub) != nil ||
		request.Packet.Route.Direction != clientwire.DirectionRequest || request.Packet.Route.SenderKeyID != device.Public().ID ||
		request.Packet.Route.ReceiverKeyID != hub.Public.ID || request.Packet.Route.HubID != hub.HubID {
		return ErrInvalid
	}
	response, err := decodePacketForOperation(responseBytes, request.Packet.Route.Operation)
	if err != nil || response.Packet.Route != responseRoute(request.Packet.Route) ||
		!reflect.DeepEqual(response.SenderPublicIdentity, hub.Public) {
		return ErrInvalid
	}
	binding := clientwire.Binding{HubID: request.Packet.Route.HubID, OwnerID: request.Packet.Route.OwnerID,
		DeviceID: request.Packet.Route.DeviceID, SessionEpoch: request.Packet.Route.SessionEpoch,
		HubKeyVersion: hub.KeyVersion, DeviceKeyVersion: DeviceKeyVersion}
	inner, err := json.Marshal(response.Packet)
	if err != nil {
		return ErrInvalid
	}
	var opened clientwire.Opened
	if request.Packet.Route.Operation == OperationOwnerEndpointGroupsReconcile {
		opened, err = clientwire.OpenOwnerEndpointGroupsReconcileResponse(device, hub.Public, binding, responseRoute(request.Packet.Route), inner)
	} else if request.Packet.Route.Operation == OperationNativePairReconcile {
		opened, err = clientwire.OpenNativePairReconcileResponse(device, hub.Public, binding, responseRoute(request.Packet.Route), inner)
	} else if request.Packet.Route.Operation == OperationLocalDomainReconcile {
		opened, err = clientwire.OpenLocalDomainReconcileResponse(device, hub.Public, binding, responseRoute(request.Packet.Route), inner)
	} else if nativePairOperation(request.Packet.Route.Operation) || localDomainOperation(request.Packet.Route.Operation) || ownerEndpointGroupsOperation(request.Packet.Route.Operation) {
		opened, err = clientwire.OpenResponseWithLimits(device, hub.Public, binding, inner, maxBodyForOperation(request.Packet.Route.Operation), innerLimitForOperation(request.Packet.Route.Operation))
	} else if appNodeOperation(request.Packet.Route.Operation) {
		opened, err = clientwire.OpenResponseWithLimits(device, hub.Public, binding, inner, MaxAppNodeBodyBytes, MaxAppNodeInnerPacketBytes)
	} else if extensionOperation(request.Packet.Route.Operation) {
		opened, err = clientwire.OpenResponseWithBodyLimit(device, hub.Public, binding, inner, MaxActivationBodyBytes)
	} else {
		opened, err = clientwire.OpenResponse(device, hub.Public, binding, inner)
	}
	if err != nil {
		return ErrInvalid
	}
	defer clear(opened.Plaintext)
	if opened.Route != response.Packet.Route || len(opened.Plaintext) > maxBodyForOperation(opened.Route.Operation) {
		return ErrInvalid
	}
	if err := decodeCanonical(opened.Plaintext, maxBodyForOperation(opened.Route.Operation), out); err != nil {
		return err
	}
	if validateResponseForRoute(out, request.Packet.Route) != nil {
		return ErrInvalid
	}
	switch value := dereference(out).(type) {
	case OwnerEndpointGroupsResult:
		if value.RequestPacketDigest != OwnerEndpointGroupsPacketDigest(requestBytes) {
			return ErrInvalid
		}
	case LocalDomainChallenge:
		if value.RequestPacketDigest != LocalDomainPacketDigest(requestBytes) || ValidateLocalDomainPolicy(value.Policy, hub, time.Time{}) != nil {
			return ErrInvalid
		}
	case LocalDomainResult:
		if value.RequestPacketDigest != LocalDomainPacketDigest(requestBytes) {
			return ErrInvalid
		}
		if value.Description != nil && ValidateLocalDomainDescription(*value.Description, hub, time.Time{}) != nil {
			return ErrInvalid
		}
		for _, policy := range value.Policies {
			if ValidateLocalDomainDescription(policy, hub, time.Time{}) != nil {
				return ErrInvalid
			}
		}
	case LocalDomainReconciled:
		if value.RequestPacketDigest != LocalDomainPacketDigest(requestBytes) {
			return ErrInvalid
		}
	case NativePairBootstrapChallenge:
		if value.RequestPacketDigest != NativePairPacketDigest(requestBytes) || ValidateNativePairBootstrapChallenge(value, hub, time.Time{}) != nil {
			return ErrInvalid
		}
	case NativePairPlanChallenge:
		if value.RequestPacketDigest != NativePairPacketDigest(requestBytes) || ValidateNativePairPlan(value.Plan, hub) != nil {
			return ErrInvalid
		}
	case NativePairBootstrapFence:
		if value.RequestPacketDigest != NativePairPacketDigest(requestBytes) {
			return ErrInvalid
		}
	case NativePairRejectionFence:
		if value.RequestPacketDigest != NativePairPacketDigest(requestBytes) {
			return ErrInvalid
		}
	case NativePairResult:
		if value.RequestPacketDigest != NativePairPacketDigest(requestBytes) {
			return ErrInvalid
		}
	case NativePairReconciled:
		if value.RequestPacketDigest != NativePairPacketDigest(requestBytes) {
			return ErrInvalid
		}
	case ActivationChallenge:
		if value.Binding.PreparePacketDigest != ActivationPacketDigest(requestBytes) {
			return ErrInvalid
		}
	case ActivationResult:
		if value.RequestPacketDigest != ActivationPacketDigest(requestBytes) {
			return ErrInvalid
		}
	case AppNodeChallenge:
		if value.RequestPacketDigest != AppNodePacketDigest(requestBytes) || ValidateAppNodeGrantClaims(value.Claims, hub, time.Time{}) != nil {
			return ErrInvalid
		}
	case AppNodeResult:
		if value.RequestPacketDigest != AppNodePacketDigest(requestBytes) || validateOpenedAppNodeResult(value, hub) != nil {
			return ErrInvalid
		}
	case AppNodeReconcileResult:
		if value.RequestPacketDigest != AppNodePacketDigest(requestBytes) {
			return ErrInvalid
		}
	}
	return nil
}

// DecodePacket rejects unknown fields, duplicate/noncanonical JSON encodings,
// malformed public identities, unexpected operations, and oversized frames.
func DecodePacket(raw []byte) (Packet, error) { return decodePacketWithLimit(raw, MaxPacketBytes) }

func decodePacketWithLimit(raw []byte, limit int) (Packet, error) {
	var packet Packet
	if err := decodeCanonical(raw, limit, &packet); err != nil ||
		packet.Format != PacketFormat || packet.Version != PacketVersion ||
		e2ee.ValidatePublicIdentity(packet.SenderPublicIdentity) != nil || validateRouteHeader(packet.Packet.Route, packet.SenderPublicIdentity) != nil {
		return Packet{}, ErrInvalid
	}
	if len(raw) > outerLimitForRoute(packet.Packet.Route) {
		return Packet{}, ErrInvalid
	}
	inner, err := json.Marshal(packet.Packet)
	if err != nil || len(inner) > innerLimitForOperation(packet.Packet.Route.Operation) || len(packet.Packet.Envelope) == 0 {
		return Packet{}, ErrInvalid
	}
	return packet, nil
}

func RequestRoute(hub HubIdentity, ownerID, deviceID, operationID, operation string, epoch uint64, device e2ee.PublicIdentity) (clientwire.Binding, clientwire.Route, error) {
	if validateHubIdentity(hub) != nil || !validID(ownerID) || !validDeviceID(deviceID) || !isHex(operationID, RequestIDBytes) ||
		!knownOperation(operation) || epoch == 0 || e2ee.ValidatePublicIdentity(device) != nil {
		return clientwire.Binding{}, clientwire.Route{}, ErrInvalid
	}
	route := routeFor(hub, ownerID, deviceID, epoch, operationID, operation, device, hub.Public, clientwire.DirectionRequest)
	binding := clientwire.Binding{HubID: hub.HubID, OwnerID: ownerID, DeviceID: deviceID,
		SessionEpoch: epoch, HubKeyVersion: hub.KeyVersion, DeviceKeyVersion: DeviceKeyVersion}
	return binding, route, nil
}

func responseRoute(request clientwire.Route) clientwire.Route {
	response := request
	response.Direction = clientwire.DirectionResponse
	response.SenderKeyID, response.ReceiverKeyID = request.ReceiverKeyID, request.SenderKeyID
	response.SenderKeyVersion, response.ReceiverKeyVersion = request.ReceiverKeyVersion, request.SenderKeyVersion
	return response
}

func routeFor(hub HubIdentity, ownerID, deviceID string, epoch uint64, requestID, operation string, device, hubPublic e2ee.PublicIdentity, direction string) clientwire.Route {
	sender, receiver := device, hubPublic
	if direction == clientwire.DirectionResponse {
		sender, receiver = hubPublic, device
	}
	return clientwire.Route{Version: clientwire.Version, Direction: direction, HubID: hub.HubID,
		OwnerID: ownerID, DeviceID: deviceID, SessionEpoch: epoch, Sequence: PacketSequence,
		OperationID: requestID, Operation: operation, SenderKeyID: sender.ID, SenderKeyVersion: keyVersion(sender, hub, direction),
		ReceiverKeyID: receiver.ID, ReceiverKeyVersion: keyVersion(receiver, hub, oppositeDirection(direction))}
}

func keyVersion(identity e2ee.PublicIdentity, hub HubIdentity, direction string) uint64 {
	if identity.ID == hub.Public.ID {
		return hub.KeyVersion
	}
	return DeviceKeyVersion
}

func oppositeDirection(direction string) string {
	if direction == clientwire.DirectionRequest {
		return clientwire.DirectionResponse
	}
	return clientwire.DirectionRequest
}

func requestRouteMetadata(body any) (operation, requestID, ownerID, deviceID string, epoch uint64, err error) {
	switch value := body.(type) {
	case ClaimPrepare:
		return OperationClaimPrepare, value.RequestID, value.Claim.OwnerID, value.DeviceID, HandshakeEpoch, nil
	case *ClaimPrepare:
		if value != nil {
			return requestRouteMetadata(*value)
		}
	case ClaimComplete:
		return OperationClaimComplete, value.RequestID, value.OwnerID, value.DeviceID, HandshakeEpoch, nil
	case *ClaimComplete:
		if value != nil {
			return requestRouteMetadata(*value)
		}
	case LoginPrepare:
		return OperationLoginPrepare, value.RequestID, value.OwnerID, value.DeviceID, HandshakeEpoch, nil
	case *LoginPrepare:
		if value != nil {
			return requestRouteMetadata(*value)
		}
	case LoginComplete:
		return OperationLoginComplete, value.RequestID, value.OwnerID, value.DeviceID, HandshakeEpoch, nil
	case *LoginComplete:
		if value != nil {
			return requestRouteMetadata(*value)
		}
	case SessionInspectRequest:
		return OperationSessionInspect, value.RequestID, value.OwnerID, value.DeviceID, value.AccountEpoch, nil
	case *SessionInspectRequest:
		if value != nil {
			return requestRouteMetadata(*value)
		}
	case LogoutRequest:
		return OperationSessionLogout, value.RequestID, value.OwnerID, value.DeviceID, value.AccountEpoch, nil
	case *LogoutRequest:
		if value != nil {
			return requestRouteMetadata(*value)
		}
	}
	return extensionMetadata(body)
}
