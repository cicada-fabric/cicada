package hubaccountwire

import (
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

func appBindingOperation(op string) bool { return AppBindingHTTPPath(op) != "" }
func appBindingMetadata(body any) (op, id, owner, device string, epoch uint64, err error) {
	switch q := dereference(body).(type) {
	case AppUnbindPrepare:
		return OperationAppUnbindPrepare, q.RequestID, q.OwnerID, q.DeviceID, HandshakeEpoch, nil
	case AppRebindPrepare:
		return OperationAppRebindPrepare, q.RequestID, q.OwnerID, q.DeviceID, HandshakeEpoch, nil
	case AppBindingComplete:
		op = OperationAppUnbindComplete
		if q.Binding.Purpose == AppBindingPurposeRebind {
			op = OperationAppRebindComplete
		}
		return op, q.RequestID, q.Binding.OwnerID, q.Binding.DeviceID, HandshakeEpoch, nil
	}
	return "", "", "", "", 0, ErrInvalid
}

func ValidateAppBinding(b AppBinding, now time.Time) error {
	if b.Format != AppBindingFormat || validateOrigin(b.Origin) != nil || !validID(b.HubID) || !isHex(b.HubFingerprint, 32) || !validID(b.AccountID) || !validID(b.OwnerID) || !validDeviceID(b.DeviceID) || e2ee.ValidatePublicIdentity(b.OwnerPublic) != nil || e2ee.ValidatePublicIdentity(b.DevicePublic) != nil || b.OwnerPublic.ID == b.DevicePublic.ID || b.OwnerKeyVersion == 0 || b.AccountEpoch == 0 || b.CredentialVersion == 0 || !isHex(b.PrepareRequestID, RequestIDBytes) || !isHex(b.PreparePacketDigest, 32) || validateTimeWindowNow(b.IssuedAt, b.ExpiresAt, MaxAppBindingChallengeLifetime, now) != nil {
		return ErrInvalid
	}
	for _, n := range []uint64{b.OwnerKeyVersion, b.AccountEpoch, b.CredentialVersion, b.DeviceEpoch, b.ClientDeviceVersion, b.ClientSessionEpoch} {
		if n == 0 || n >= 1<<63-1 {
			return ErrInvalid
		}
	}
	switch b.Purpose {
	case AppBindingPurposeUnbind:
		if !validID(b.SessionID) || b.PreviousDeviceID != "" || b.UnbindBindingDigest != "" {
			return ErrInvalid
		}
	case AppBindingPurposeRebind:
		if b.SessionID != "" || !validDeviceID(b.PreviousDeviceID) || b.PreviousDeviceID == b.DeviceID || !isHex(b.UnbindBindingDigest, 32) || b.DeviceEpoch != 1 || b.ClientDeviceVersion != 1 || b.ClientSessionEpoch != 1 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validateAppBindingRequest(body any, hub HubIdentity, now time.Time) error {
	var origin, hubID, account, owner, device, id, issued string
	var nonce []byte
	var public e2ee.PublicIdentity
	switch q := dereference(body).(type) {
	case AppUnbindPrepare:
		if q.Format != AppUnbindPrepareFormat || len(q.SessionToken) != MaxSessionTokenBytes || q.AccountEpoch == 0 || q.DeviceEpoch == 0 || q.AccountEpoch >= 1<<63-1 || q.DeviceEpoch >= 1<<63-1 {
			return ErrInvalid
		}
		origin, hubID, account, owner, device, id, nonce, issued, public = q.Origin, q.HubID, q.AccountID, q.OwnerID, q.DeviceID, q.RequestID, q.ClientNonce, q.IssuedAt, q.OwnerPublic
	case AppRebindPrepare:
		if q.Format != AppRebindPrepareFormat || !validDeviceID(q.PreviousDeviceID) || q.PreviousDeviceID == q.DeviceID || !isHex(q.UnbindBindingDigest, 32) {
			return ErrInvalid
		}
		origin, hubID, account, owner, device, id, nonce, issued, public = q.Origin, q.HubID, q.AccountID, q.OwnerID, q.DeviceID, q.RequestID, q.ClientNonce, q.IssuedAt, q.OwnerPublic
	case AppBindingComplete:
		if q.Format != AppBindingCompleteFormat || ValidateAppBinding(q.Binding, time.Time{}) != nil || len(q.PreparePacket) == 0 || len(q.PreparePacket) > MaxAppBindingOriginalBytes || len(q.OwnerProof) == 0 || len(q.OwnerProof) > MaxAppBindingProofBytes || len(q.ServerNonce) != NonceBytes || AppBindingPacketDigest(q.PreparePacket) != q.Binding.PreparePacketDigest {
			return ErrInvalid
		}
		b := q.Binding
		p, err := DecodePacket(q.PreparePacket)
		prepareOp := OperationAppUnbindPrepare
		if b.Purpose == AppBindingPurposeRebind {
			prepareOp = OperationAppRebindPrepare
		}
		if err != nil || p.Packet.Route.Operation != prepareOp || p.Packet.Route.OperationID != b.PrepareRequestID || p.Packet.Route.HubID != b.HubID || p.Packet.Route.OwnerID != b.OwnerID || p.Packet.Route.DeviceID != b.DeviceID || !reflect.DeepEqual(p.SenderPublicIdentity, b.DevicePublic) {
			return ErrInvalid
		}
		origin, hubID, account, owner, device, id, nonce, issued, public = b.Origin, b.HubID, b.AccountID, b.OwnerID, b.DeviceID, q.RequestID, q.ClientNonce, q.IssuedAt, b.OwnerPublic
	default:
		return ErrInvalid
	}
	if validateOrigin(origin) != nil || hubID != hub.HubID || !validID(account) || !validID(owner) || !validDeviceID(device) || e2ee.ValidatePublicIdentity(public) != nil || !isHex(id, RequestIDBytes) || len(nonce) != NonceBytes || validateRecent(issued, now, MaxSessionRequestLifetime) != nil {
		return ErrInvalid
	}
	return nil
}

func validateAppBindingDevice(body any, device e2ee.PublicIdentity) error {
	switch q := dereference(body).(type) {
	case AppUnbindPrepare:
		if q.OwnerPublic.ID == device.ID {
			return ErrInvalid
		}
	case AppRebindPrepare:
		if q.OwnerPublic.ID == device.ID {
			return ErrInvalid
		}
	case AppBindingComplete:
		if !reflect.DeepEqual(q.Binding.DevicePublic, device) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func ValidateAppBindingChallenge(ch AppBindingChallenge, hub HubIdentity, now time.Time) error {
	b, p := ch.Binding, ch.Proof
	fp, err := HubFingerprint(hub)
	op := OperationAppUnbindPrepare
	if b.Purpose == AppBindingPurposeRebind {
		op = OperationAppRebindPrepare
	}
	m := p.Manifest
	if err != nil || ch.Format != AppBindingChallengeFormat || ch.Operation != op || ch.RequestID != b.PrepareRequestID || ch.RequestPacketDigest != b.PreparePacketDigest || ValidateAppBinding(b, now) != nil || b.HubID != hub.HubID || b.HubFingerprint != fp || !reflect.DeepEqual(p.Hub, hub) || p.Origin != b.Origin || m.Version != 1 || m.Purpose != ownerbootstrap.Purpose || m.AccountID != b.AccountID || m.OwnerID != b.OwnerID || m.HubID != b.HubID || m.AuthorityID != b.PrepareRequestID || m.OperationID != b.Digest() || !reflect.DeepEqual(m.CandidatePublic, b.OwnerPublic) || m.CandidateFingerprint != ownerbootstrap.Fingerprint(b.OwnerPublic) || m.ExpiresAt != b.ExpiresAt || p.Validate(now) != nil || len(p.Challenge) == 0 || len(ch.ClientNonce) != NonceBytes || len(ch.ServerNonce) != NonceBytes {
		return ErrInvalid
	}
	return nil
}

func appBindingErrorCode(code string) bool {
	switch code {
	case "EXPIRED", "NOT_ADMITTED", "STALE_SCOPE", "OWNER_REVOKED", "DEVICE_INACTIVE", "ALREADY_REPLACED", "RESTORE_FENCED":
		return true
	}
	return false
}

func validateAppBindingResult(r AppBindingResult) error {
	if r.Format != AppBindingResultFormat || (r.Operation != OperationAppUnbindComplete && r.Operation != OperationAppRebindComplete) || !isHex(r.RequestID, RequestIDBytes) || !isHex(r.RequestPacketDigest, 32) || !isHex(r.BindingDigest, 32) || !validDeviceID(r.DeviceID) || validateCanonicalTime(r.ObservedAt) != nil {
		return ErrInvalid
	}
	switch r.State {
	case AppBindingUnbound:
		if r.Operation != OperationAppUnbindComplete || r.ErrorCode != "" || r.DeviceEpoch <= 1 || r.ClientDeviceVersion <= 1 || r.ClientSessionEpoch <= 1 {
			return ErrInvalid
		}
	case AppBindingBoundZero:
		if r.Operation != OperationAppRebindComplete || r.ErrorCode != "" || r.DeviceEpoch != 1 || r.ClientDeviceVersion != 1 || r.ClientSessionEpoch != 1 {
			return ErrInvalid
		}
	case AppBindingRejected:
		if !appBindingErrorCode(r.ErrorCode) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validateAppBindingResponse(body any, route clientwire.Route) error {
	switch r := dereference(body).(type) {
	case AppBindingChallenge:
		if r.Operation != route.Operation || r.RequestID != route.OperationID || r.Binding.OwnerID != route.OwnerID || r.Binding.DeviceID != route.DeviceID || r.Binding.HubID != route.HubID || ValidateAppBindingChallenge(r, r.Proof.Hub, time.Time{}) != nil {
			return ErrInvalid
		}
	case AppBindingResult:
		if r.Operation != route.Operation || r.RequestID != route.OperationID || r.DeviceID != route.DeviceID || validateAppBindingResult(r) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
