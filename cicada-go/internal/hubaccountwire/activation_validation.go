package hubaccountwire

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

func extensionMetadata(body any) (operation, id, owner, device string, epoch uint64, err error) {
	if op, id, owner, device, epoch, err := localDomainMetadata(body); err == nil {
		return op, id, owner, device, epoch, nil
	}
	switch v := dereference(body).(type) {
	case OwnerEndpointReadRequest:
		return OperationOwnerEndpointRead, v.Context.RequestID, v.Context.OwnerID, v.Context.DeviceID, HandshakeEpoch, nil
	case ActivationPrepare:
		return OperationActivationPrepare, v.RequestID, v.Material.OwnerID, v.DeviceID, HandshakeEpoch, nil
	case ActivationComplete:
		return OperationActivationComplete, v.RequestID, v.Binding.OwnerID, v.Binding.DeviceID, HandshakeEpoch, nil
	case ActivationStatusRequest:
		return OperationActivationStatus, v.RequestID, v.OwnerID, v.DeviceID, HandshakeEpoch, nil
	case AccountReconcileRequest:
		return OperationAccountReconcile, v.RequestID, v.OwnerID, v.DeviceID, HandshakeEpoch, nil
	}
	if op, id, owner, device, epoch, err := nativePairMetadata(body); err == nil {
		return op, id, owner, device, epoch, nil
	}
	return appNodeMetadata(body)
}
func extensionOperation(op string) bool {
	return op == OperationOwnerEndpointRead || op == OperationActivationPrepare || op == OperationActivationComplete || op == OperationActivationStatus || op == OperationAccountReconcile || appNodeOperation(op) || nativePairOperation(op) || localDomainOperation(op)
}
func validateActivationBinding(b ActivationBinding) error {
	if b.Format != ActivationFormat || (b.Purpose != PurposeInitialActivation && b.Purpose != PurposeLegacyContinuation) || validateOrigin(b.Origin) != nil || !validID(b.HubID) || !validID(b.AccountID) || !validID(b.OwnerID) || !isHex(b.HubFingerprint, 32) || !isHex(b.ActivationID, 16) || b.SetupEpoch == 0 || b.AccountEpoch == 0 || b.DeviceEpoch == 0 || e2ee.ValidatePublicIdentity(b.OwnerPublic) != nil || e2ee.ValidatePublicIdentity(b.DevicePublic) != nil || b.OwnerPublic.ID == b.DevicePublic.ID || !validDeviceID(b.DeviceID) || !isHex(b.PrepareRequestID, 16) || !isHex(b.PreparePacketDigest, 32) || !isHex(b.GrantDigest, 32) || !reflect.DeepEqual(b.AllowedOperations, ActivationAllowedOperations()) || validateCanonicalTime(b.LeaseExpiresAt) != nil {
		return ErrInvalid
	}
	return nil
}
func validateExtensionRequest(body any, hub HubIdentity, now time.Time) error {
	if op, _, _, _, _, err := localDomainMetadata(body); err == nil && localDomainOperation(op) {
		return validateLocalDomainRequest(body, hub, now)
	}
	if q, ok := dereference(body).(OwnerEndpointReadRequest); ok {
		return validateOwnerEndpointReadRequest(q, hub, now)
	}
	if op, _, _, _, _, err := nativePairMetadata(body); err == nil && nativePairOperation(op) {
		return validateNativePairRequest(body, hub, now)
	}
	if op, _, _, _, _, err := appNodeMetadata(body); err == nil && appNodeOperation(op) {
		return validateAppNodeRequest(body, hub, now)
	}
	switch v := dereference(body).(type) {
	case ActivationPrepare:
		if v.Format != ActivationPrepareFormat || ValidateActivationHub(v.Material, hub, time.Time{}) != nil || e2ee.ValidatePublicIdentity(v.OwnerPublic) != nil || v.OwnerPublic.ID == hub.Public.ID || len(v.OwnerDeviceGrant) == 0 || len(v.OwnerDeviceGrant) > 16*1024 || len(v.ClientNonce) != NonceBytes || validateRecent(v.IssuedAt, now, MaxSessionRequestLifetime) != nil || (v.Material.ExpectedOwnerPublic != nil && !reflect.DeepEqual(*v.Material.ExpectedOwnerPublic, v.OwnerPublic)) {
			return ErrInvalid
		}
		var g e2ee.OwnerDeviceGrant
		if decodeCanonical(v.OwnerDeviceGrant, 16*1024, &g) != nil || validateTimeWindow(g.IssuedAt, g.ExpiresAt, MaxActivationProofLifetime) != nil {
			return ErrInvalid
		}
	case ActivationComplete:
		if v.Format != ActivationCompleteFormat || validateActivationBinding(v.Binding) != nil || v.Binding.HubID != hub.HubID || len(v.ServerNonce) != NonceBytes || len(v.OwnerProof) == 0 || len(v.OwnerProof) > 96*1024 || len(v.ClientNonce) != NonceBytes || validateRecent(v.IssuedAt, now, MaxSessionRequestLifetime) != nil {
			return ErrInvalid
		}
		if v.Binding.Purpose == PurposeInitialActivation {
			if !validUsername(v.Username) || !validPassword(v.Password) {
				return ErrInvalid
			}
		} else if v.Username != "" || v.Password != "" {
			return ErrInvalid
		}
	case ActivationStatusRequest:
		if v.Format != ActivationStatusFormat || validateOrigin(v.Origin) != nil || v.HubID != hub.HubID || !validID(v.AccountID) || !isHex(v.ActivationID, 16) || (v.TargetOperation != OperationActivationPrepare && v.TargetOperation != OperationActivationComplete) || !isHex(v.TargetRequestID, 16) || !isHex(v.TargetPacketDigest, 32) || len(v.ClientNonce) != NonceBytes || validateRecent(v.IssuedAt, now, MaxSessionRequestLifetime) != nil {
			return ErrInvalid
		}
	case AccountReconcileRequest:
		p, e := DecodePacket(v.OriginalPacket)
		if e != nil || v.Format != AccountReconcileFormat || validateOrigin(v.Origin) != nil || v.HubID != hub.HubID || !validID(v.AccountID) || len(v.OriginalPacket) > 96*1024 || !AccountReconcileOperationAllowed(p.Packet.Route.Operation) || p.Packet.Route.Direction != clientwire.DirectionRequest || p.Packet.Route.HubID != v.HubID || p.Packet.Route.OwnerID != v.OwnerID || p.Packet.Route.DeviceID != v.DeviceID || len(v.ClientNonce) != NonceBytes || validateRecent(v.IssuedAt, now, MaxSessionRequestLifetime) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func validateExtensionResponse(body any, r clientwire.Route) error {
	if localDomainOperation(r.Operation) {
		return validateLocalDomainResponse(body, r)
	}
	if r.Operation == OperationOwnerEndpointRead {
		return validateOwnerEndpointReadResponse(body, r)
	}
	if nativePairOperation(r.Operation) {
		return validateNativePairResponse(body, r)
	}
	if appNodeOperation(r.Operation) {
		return validateAppNodeResponse(body, r)
	}
	switch v := dereference(body).(type) {
	case ActivationChallenge:
		if r.Operation != OperationActivationPrepare || v.Format != ActivationChallengeFormat || validateActivationBinding(v.Binding) != nil || v.Binding.PrepareRequestID != r.OperationID || v.Binding.HubID != r.HubID || v.Binding.OwnerID != r.OwnerID || v.Binding.DeviceID != r.DeviceID || ValidateActivationChallenge(v, v.Proof.Hub, v.Binding.DevicePublic, time.Time{}) != nil {
			return ErrInvalid
		}
	case ActivationResult:
		if !extensionOperation(r.Operation) || r.Operation == OperationAccountReconcile || v.Format != ActivationResultFormat || v.Operation != r.Operation || v.RequestID != r.OperationID || v.HubID != r.HubID || v.OwnerID != r.OwnerID || v.DeviceID != r.DeviceID || validateOrigin(v.Origin) != nil || !validID(v.AccountID) || !isHex(v.ActivationID, 16) || !isHex(v.RequestPacketDigest, 32) || v.AccountEpoch == 0 || v.DeviceEpoch == 0 || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
		switch v.State {
		case ActivationCompleted, ActivationRejected, ActivationCancelled, ActivationPrepared, ActivationAbsent:
		default:
			return ErrInvalid
		}
		if len(v.ReceiptPacket) > MaxActivationReceiptBytes || len(v.AllowedOperations) > 2 {
			return ErrInvalid
		}
		if v.LeaseState != ActivationLeaseActive && v.LeaseState != ActivationLeaseExpired && v.LeaseState != ActivationLeaseRevoked && v.LeaseState != ActivationLeaseUnavailable {
			return ErrInvalid
		}
		if v.RootState != RootActiveState && v.RootState != RootPendingState && v.RootState != RootUnavailableState {
			return ErrInvalid
		}
		if v.LeaseExpiresAt != "" && validateCanonicalTime(v.LeaseExpiresAt) != nil {
			return ErrInvalid
		}
		if len(v.AllowedOperations) > 0 && !reflect.DeepEqual(v.AllowedOperations, ActivationAllowedOperations()) {
			return ErrInvalid
		}
		if r.Operation == OperationActivationStatus {
			if (v.TargetOperation != OperationActivationPrepare && v.TargetOperation != OperationActivationComplete) || !isHex(v.TargetRequestID, 16) || !isHex(v.TargetPacketDigest, 32) || (v.TargetState != ActivationAbsent && v.TargetState != ActivationCompleted && v.TargetState != ActivationRejected && v.TargetState != ActivationCancelled) {
				return ErrInvalid
			}
		}
	case AccountReconcileResult:
		if r.Operation != OperationAccountReconcile || v.Format != AccountReconciledFormat || v.RequestID != r.OperationID || v.HubID != r.HubID || v.OwnerID != r.OwnerID || v.DeviceID != r.DeviceID || validateOrigin(v.Origin) != nil || !validID(v.AccountID) || !AccountReconcileOperationAllowed(v.OriginalOperation) || !isHex(v.OriginalRequestID, 16) || !isHex(v.OriginalPacketDigest, 32) || (v.State != ActivationCompleted && v.State != ActivationRejected) || len(v.ReceiptPacket) > 96*1024 || v.AccountEpoch == 0 || v.DeviceEpoch == 0 || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
		if (v.State == ActivationCompleted) != (len(v.ReceiptPacket) > 0) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	raw, e := json.Marshal(body)
	if e != nil || len(raw) > MaxActivationBodyBytes {
		return ErrInvalid
	}
	return nil
}
