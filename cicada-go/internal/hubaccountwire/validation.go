package hubaccountwire

import (
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

func validateRequestBody(body any, hub HubIdentity, now time.Time) error {
	_, requestID, ownerID, deviceID, epoch, err := requestRouteMetadata(body)
	if err != nil || !isHex(requestID, RequestIDBytes) || !validID(ownerID) || !validDeviceID(deviceID) || epoch == 0 {
		return ErrInvalid
	}
	switch value := dereference(body).(type) {
	case ClaimPrepare:
		if value.Format != ClaimPrepareFormat || value.Purpose != PurposeInitialClaim ||
			ValidateClaimCard(value.Claim, hub, now) != nil || value.Claim.OwnerID != ownerID ||
			!isHex(value.DeviceKeyFingerprint, 32) || len(value.ClientNonce) != NonceBytes ||
			validateRecent(value.IssuedAt, now, MaxSessionRequestLifetime) != nil {
			return ErrInvalid
		}
	case ClaimComplete:
		if value.Format != ClaimCompleteFormat || value.Purpose != PurposeInitialClaim || validateOrigin(value.Origin) != nil ||
			value.HubID != hub.HubID || !validID(value.AccountID) || !validID(value.ClaimID) || !isHex(value.AttemptID, 16) ||
			!isHex(value.PrepareRequestID, 16) || !isHex(value.DeviceKeyFingerprint, 32) ||
			len(value.PrepareClientNonce) != NonceBytes || len(value.ServerNonce) != NonceBytes || len(value.ClientNonce) != NonceBytes ||
			value.AccountEpoch == 0 || value.DeviceEpoch != 1 || !validUsername(value.Username) || !validPassword(value.Password) ||
			e2ee.ValidatePublicIdentity(value.OwnerPublicIdentity) != nil || validateRecent(value.IssuedAt, now, MaxSessionRequestLifetime) != nil {
			return ErrInvalid
		}
	case LoginPrepare:
		if value.Format != LoginPrepareFormat || value.Purpose != PurposeAccountLogin || validateOrigin(value.Origin) != nil ||
			value.HubID != hub.HubID || !validID(value.AccountID) || !validUsername(value.Username) ||
			!isHex(value.DeviceKeyFingerprint, 32) || !validID(value.DeviceKeyID) || len(value.ClientNonce) != NonceBytes ||
			validateRecent(value.IssuedAt, now, MaxSessionRequestLifetime) != nil {
			return ErrInvalid
		}
	case LoginComplete:
		if value.Format != LoginCompleteFormat || value.Purpose != PurposeAccountLogin || validateOrigin(value.Origin) != nil ||
			value.HubID != hub.HubID || !validID(value.AccountID) || !isHex(value.AttemptID, 16) ||
			!isHex(value.PrepareRequestID, 16) || !isHex(value.DeviceKeyFingerprint, 32) ||
			len(value.PrepareClientNonce) != NonceBytes || len(value.ServerNonce) != NonceBytes || len(value.ClientNonce) != NonceBytes ||
			value.AccountEpoch == 0 || value.DeviceEpoch == 0 || !validUsername(value.Username) || !validPassword(value.Password) ||
			validateRecent(value.IssuedAt, now, MaxSessionRequestLifetime) != nil {
			return ErrInvalid
		}
	case SessionInspectRequest:
		if validateSessionRequest(value.Format, value.Purpose, value.Origin, value.HubID, value.AccountID, value.OwnerID,
			value.DeviceID, value.DeviceKeyID, value.DeviceKeyFingerprint, value.SessionToken, value.AccountEpoch,
			value.DeviceEpoch, value.RequestID, value.ClientNonce, value.IssuedAt, value.ExpiresAt, hub, now) != nil {
			return ErrInvalid
		}
	case LogoutRequest:
		if validateSessionRequest(value.Format, value.Purpose, value.Origin, value.HubID, value.AccountID, value.OwnerID,
			value.DeviceID, value.DeviceKeyID, value.DeviceKeyFingerprint, value.SessionToken, value.AccountEpoch,
			value.DeviceEpoch, value.RequestID, value.ClientNonce, value.IssuedAt, value.ExpiresAt, hub, now) != nil {
			return ErrInvalid
		}
	default:
		return validateExtensionRequest(body, hub, now)
	}
	return nil
}

func validateResponseBody(body any) error {
	switch value := dereference(body).(type) {
	case ClaimChallenge:
		if value.Format != ClaimChallengeFormat || value.Purpose != PurposeInitialClaim || !validID(value.HubID) ||
			!validID(value.AccountID) || !validID(value.OwnerID) || !isHex(value.ClaimID, 16) || !isHex(value.AttemptID, 16) ||
			!validDeviceID(value.DeviceID) || !validID(value.DeviceKeyID) || !isHex(value.DeviceKeyFingerprint, 32) ||
			!isHex(value.PrepareRequestID, 16) || len(value.ClientNonce) != NonceBytes || len(value.ServerNonce) != NonceBytes ||
			value.AccountEpoch == 0 || value.DeviceEpoch != 1 || validateOrigin(value.Origin) != nil ||
			validateTimeWindow(value.IssuedAt, value.ExpiresAt, MaxClaimChallengeLifetime) != nil {
			return ErrInvalid
		}
	case ClaimReceipt:
		if value.Format != ClaimReceiptFormat || value.Purpose != PurposeInitialClaim || value.State != ClaimPendingState ||
			value.RootState != RootPendingState || value.RootActive || value.AccountEpoch == 0 || value.DeviceEpoch != 1 ||
			!validID(value.AccountID) || !validID(value.OwnerID) || !isHex(value.RequestID, RequestIDBytes) ||
			!isHex(value.OwnerFingerprint, 32) || !validID(value.OwnerKeyID) || !validDeviceID(value.DeviceID) ||
			validateOrigin(value.Origin) != nil || validateCanonicalTime(value.CompletedAt) != nil {
			return ErrInvalid
		}
	case LoginChallenge:
		if value.Format != LoginChallengeFormat || value.Purpose != PurposeAccountLogin || !validID(value.HubID) ||
			!validID(value.AccountID) || !validID(value.OwnerID) || !isHex(value.AttemptID, 16) || !validDeviceID(value.DeviceID) ||
			!validID(value.DeviceKeyID) || !isHex(value.DeviceKeyFingerprint, 32) || !isHex(value.PrepareRequestID, 16) ||
			len(value.ClientNonce) != NonceBytes || len(value.ServerNonce) != NonceBytes || value.AccountEpoch == 0 || value.DeviceEpoch == 0 ||
			validateTimeWindow(value.IssuedAt, value.ExpiresAt, MaxLoginChallengeLifetime) != nil {
			return ErrInvalid
		}
	case SessionReceipt:
		if value.Format != SessionReceiptFormat || value.Purpose != PurposeAccountSession || !validID(value.HubID) ||
			!validID(value.AccountID) || !validID(value.OwnerID) || !validDeviceID(value.DeviceID) || !validID(value.DeviceKeyID) ||
			!isHex(value.DeviceKeyFingerprint, 32) || len(value.SessionToken) != MaxSessionTokenBytes ||
			value.AccountEpoch == 0 || value.DeviceEpoch == 0 || !isHex(value.RequestID, RequestIDBytes) ||
			validateTimeWindow(value.IssuedAt, value.ExpiresAt, MaxSessionLifetime) != nil {
			return ErrInvalid
		}
	case SessionInspection:
		if value.Format != SessionInspectionFormat || value.Purpose != PurposeAccountSession || !validID(value.HubID) ||
			!validID(value.AccountID) || !validID(value.OwnerID) || !validUsername(value.Username) || !validDeviceID(value.ActorDeviceID) || value.ActorDeviceEpoch == 0 ||
			!isHex(value.RequestID, RequestIDBytes) || value.State != SessionActiveState || len(value.Devices) > 64 ||
			(value.RootState != RootPendingState && value.RootState != RootActiveState && value.RootState != RootUnavailableState) ||
			value.RootActive != (value.RootState == RootActiveState) || !validID(value.OwnerKeyID) || !isHex(value.OwnerFingerprint, 32) ||
			validateOrigin(value.Origin) != nil ||
			validateCanonicalTime(value.InspectedAt) != nil {
			return ErrInvalid
		}
		for _, device := range value.Devices {
			if !validDeviceID(device.DeviceID) || !validID(device.DeviceKeyID) || !isHex(device.DeviceKeyFingerprint, 32) ||
				device.State != DeviceActiveState || device.DeviceEpoch == 0 || validateCanonicalTime(device.CreatedAt) != nil ||
				(device.LastSeenAt != "" && validateCanonicalTime(device.LastSeenAt) != nil) {
				return ErrInvalid
			}
		}
	case LogoutReceipt:
		if value.Format != LogoutReceiptFormat || value.Purpose != PurposeAccountSession || !validID(value.HubID) ||
			!validID(value.AccountID) || !validID(value.OwnerID) || !validDeviceID(value.DeviceID) ||
			value.AccountEpoch == 0 || value.DeviceEpoch == 0 || !isHex(value.RequestID, RequestIDBytes) ||
			value.State != SessionRevokedState || validateCanonicalTime(value.LoggedOutAt) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validateSessionRequest(format, purpose, origin, hubID, accountID, ownerID, deviceID, keyID, fingerprint string,
	token []byte, accountEpoch, deviceEpoch uint64, requestID string, nonce []byte, issuedAt, expiresAt string,
	hub HubIdentity, now time.Time) error {
	if format != SessionInspectFormat && format != LogoutFormat || purpose != PurposeAccountSession || validateOrigin(origin) != nil ||
		hubID != hub.HubID || !validID(accountID) || !validID(ownerID) || !validDeviceID(deviceID) || !validID(keyID) ||
		!isHex(fingerprint, 32) || len(token) != MaxSessionTokenBytes || accountEpoch == 0 || deviceEpoch == 0 ||
		!isHex(requestID, RequestIDBytes) || len(nonce) != NonceBytes {
		return ErrInvalid
	}
	return validateTimeWindowNow(issuedAt, expiresAt, MaxSessionRequestLifetime, now)
}

func validateSessionContext(session SessionContext, now time.Time) error {
	if validateOrigin(session.Origin) != nil || !validID(session.HubID) || !validID(session.AccountID) || !validID(session.OwnerID) ||
		!validDeviceID(session.DeviceID) || !validID(session.DeviceKeyID) || !isHex(session.DeviceKeyFingerprint, 32) ||
		len(session.SessionToken) != MaxSessionTokenBytes || session.AccountEpoch == 0 || session.DeviceEpoch == 0 {
		return ErrInvalid
	}
	expires, err := parseCanonicalUTC(session.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return ErrInvalid
	}
	return nil
}

func validateHubIdentity(hub HubIdentity) error {
	if hub.Contract != "android-hub-v1" || !validID(hub.HubID) || hub.KeyVersion != 1 ||
		hub.Suite != ownerbootstrap.Suite || e2ee.ValidatePublicIdentity(hub.Public) != nil {
		return ErrInvalid
	}
	return nil
}

func validateRequestMatchesDevice(body any, device e2ee.PublicIdentity) error {
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(device)
	if err != nil {
		return ErrInvalid
	}
	switch value := dereference(body).(type) {
	case ClaimPrepare:
		if value.DeviceKeyFingerprint != fingerprint || value.DeviceID == "" {
			return ErrInvalid
		}
	case ClaimComplete:
		if value.DeviceKeyFingerprint != fingerprint || value.DeviceKeyID != device.ID || reflect.DeepEqual(value.OwnerPublicIdentity, device) {
			return ErrInvalid
		}
	case LoginPrepare:
		if value.DeviceKeyFingerprint != fingerprint || value.DeviceKeyID != device.ID {
			return ErrInvalid
		}
	case LoginComplete:
		if value.DeviceKeyFingerprint != fingerprint || value.DeviceKeyID != device.ID {
			return ErrInvalid
		}
	case SessionInspectRequest:
		if value.DeviceKeyFingerprint != fingerprint || value.DeviceKeyID != device.ID {
			return ErrInvalid
		}
	case LogoutRequest:
		if value.DeviceKeyFingerprint != fingerprint || value.DeviceKeyID != device.ID {
			return ErrInvalid
		}
	default:
		return validateExtensionDevice(body, device)
	}
	return nil
}

func validateResponseForRoute(body any, request clientwire.Route) error {
	var operationID, hubID, ownerID, deviceID string
	var expectedType string
	switch request.Operation {
	case OperationClaimPrepare:
		value, ok := dereference(body).(ClaimChallenge)
		if !ok {
			return ErrInvalid
		}
		operationID, hubID, ownerID, deviceID = value.PrepareRequestID, value.HubID, value.OwnerID, value.DeviceID
		expectedType = ClaimChallengeFormat
	case OperationClaimComplete:
		value, ok := dereference(body).(ClaimReceipt)
		if !ok {
			return ErrInvalid
		}
		operationID, hubID, ownerID, deviceID = value.RequestID, value.HubID, value.OwnerID, value.DeviceID
		expectedType = ClaimReceiptFormat
	case OperationLoginPrepare:
		value, ok := dereference(body).(LoginChallenge)
		if !ok {
			return ErrInvalid
		}
		operationID, hubID, ownerID, deviceID = value.PrepareRequestID, value.HubID, value.OwnerID, value.DeviceID
		expectedType = LoginChallengeFormat
	case OperationLoginComplete:
		value, ok := dereference(body).(SessionReceipt)
		if !ok {
			return ErrInvalid
		}
		operationID, hubID, ownerID, deviceID = value.RequestID, value.HubID, value.OwnerID, value.DeviceID
		expectedType = SessionReceiptFormat
	case OperationSessionInspect:
		value, ok := dereference(body).(SessionInspection)
		if !ok {
			return ErrInvalid
		}
		operationID, hubID, ownerID, deviceID = value.RequestID, value.HubID, value.OwnerID, value.ActorDeviceID
		expectedType = SessionInspectionFormat
	case OperationSessionLogout:
		value, ok := dereference(body).(LogoutReceipt)
		if !ok {
			return ErrInvalid
		}
		operationID, hubID, ownerID, deviceID = value.RequestID, value.HubID, value.OwnerID, value.DeviceID
		expectedType = LogoutReceiptFormat
	default:
		return validateExtensionResponse(body, request)
	}
	if validateResponseBody(body) != nil || operationID != request.OperationID || hubID != request.HubID ||
		ownerID != request.OwnerID || deviceID != request.DeviceID ||
		responseFormat(body) != expectedType {
		return ErrInvalid
	}
	return nil
}

func responseFormat(body any) string {
	switch value := dereference(body).(type) {
	case ClaimChallenge:
		return value.Format
	case ClaimReceipt:
		return value.Format
	case LoginChallenge:
		return value.Format
	case SessionReceipt:
		return value.Format
	case SessionInspection:
		return value.Format
	case LogoutReceipt:
		return value.Format
	default:
		return ""
	}
}

func validateOrigin(origin string) error {
	canonical, err := ownerbootstrap.CanonicalOrigin(origin, true)
	if err != nil || canonical != origin {
		return ErrInvalid
	}
	return nil
}

func validateRouteHeader(route clientwire.Route, sender e2ee.PublicIdentity) error {
	if route.Version != clientwire.Version || (route.Direction != clientwire.DirectionRequest && route.Direction != clientwire.DirectionResponse) ||
		!validID(route.HubID) || !validID(route.OwnerID) || !validDeviceID(route.DeviceID) || route.SessionEpoch == 0 ||
		route.Sequence != PacketSequence || !isHex(route.OperationID, RequestIDBytes) || !knownOperation(route.Operation) ||
		route.SenderKeyID != sender.ID || route.SenderKeyVersion == 0 || route.ReceiverKeyVersion == 0 {
		return ErrInvalid
	}
	if route.Direction == clientwire.DirectionRequest && route.SenderKeyVersion != DeviceKeyVersion {
		return ErrInvalid
	}
	if route.Direction == clientwire.DirectionResponse && route.ReceiverKeyVersion != DeviceKeyVersion {
		return ErrInvalid
	}
	return nil
}

func validBinding(binding clientwire.Binding, route clientwire.Route) bool {
	return binding.HubID == route.HubID && binding.OwnerID == route.OwnerID && binding.DeviceID == route.DeviceID &&
		binding.SessionEpoch == route.SessionEpoch && binding.HubKeyVersion != 0 && binding.DeviceKeyVersion == DeviceKeyVersion
}

func knownOperation(operation string) bool {
	switch operation {
	case OperationClaimPrepare, OperationClaimComplete, OperationLoginPrepare, OperationLoginComplete,
		OperationSessionInspect, OperationSessionLogout:
		return true
	default:
		return extensionOperation(operation)
	}
}

func maxBodyForOperation(operation string) int {
	if operation == OperationOwnerEndpointGroupsReconcile {
		return MaxOwnerEndpointGroupsReconcileBodyBytes
	}
	if ownerEndpointGroupsOperation(operation) {
		return MaxOwnerEndpointGroupsBodyBytes
	}
	if operation == OperationLocalDomainReconcile {
		return MaxLocalDomainReconcileBodyBytes
	}
	if localDomainOperation(operation) {
		return MaxLocalDomainBodyBytes
	}
	if operation == OperationNativePairReconcile {
		return MaxNativePairReconcileBodyBytes
	}
	if nativePairOperation(operation) {
		return MaxNativePairBodyBytes
	}
	if appNodeScopedOperation(operation) {
		return MaxAppNodeScopedBodyBytes
	}
	if appNodeOperation(operation) {
		return MaxAppNodeBodyBytes
	}
	if extensionOperation(operation) {
		return MaxActivationBodyBytes
	}
	if operation == OperationClaimComplete {
		return MaxClaimBodyBytes
	}
	return MaxBodyBytes
}
