package hubaccountwire

import (
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	OperationAccountReconcile = "owner.account.reconcile"
	AccountReconcileFormat    = "cicada.owner-account-reconcile.v1"
	AccountReconciledFormat   = "cicada.owner-account-reconciled.v1"
)

// AccountReconcileRequest authenticates the original exact packet even when
// its password, challenge or session has expired. It grants no account access.
type AccountReconcileRequest struct {
	Format         string `json:"format"`
	Origin         string `json:"origin"`
	HubID          string `json:"hub_id"`
	AccountID      string `json:"account_id"`
	OwnerID        string `json:"owner_id"`
	DeviceID       string `json:"device_id"`
	OriginalPacket []byte `json:"original_packet"`
	RequestID      string `json:"request_id"`
	ClientNonce    []byte `json:"client_nonce"`
	IssuedAt       string `json:"issued_at"`
}
type AccountReconcileResult struct {
	Format               string `json:"format"`
	Origin               string `json:"origin"`
	HubID                string `json:"hub_id"`
	AccountID            string `json:"account_id"`
	OwnerID              string `json:"owner_id"`
	DeviceID             string `json:"device_id"`
	RequestID            string `json:"request_id"`
	OriginalOperation    string `json:"original_operation"`
	OriginalRequestID    string `json:"original_request_id"`
	OriginalPacketDigest string `json:"original_packet_digest"`
	State                string `json:"state"`
	ReceiptPacket        []byte `json:"receipt_packet"`
	AccountEpoch         uint64 `json:"account_epoch"`
	DeviceEpoch          uint64 `json:"device_epoch"`
	ObservedAt           string `json:"observed_at"`
}

func AccountReconcileOperationAllowed(op string) bool {
	return op == OperationLoginPrepare || op == OperationLoginComplete || op == OperationSessionInspect || op == OperationSessionLogout
}
func NewAccountReconcileRequest(hub HubIdentity, origin, account, owner, device string, original []byte, now time.Time) (AccountReconcileRequest, error) {
	p, err := DecodePacket(original)
	if err != nil || !AccountReconcileOperationAllowed(p.Packet.Route.Operation) || p.Packet.Route.HubID != hub.HubID || p.Packet.Route.OwnerID != owner || p.Packet.Route.DeviceID != device || validateOrigin(origin) != nil || !validID(account) || len(original) > 96*1024 {
		return AccountReconcileRequest{}, ErrInvalid
	}
	id, err := NewRequestID()
	if err != nil {
		return AccountReconcileRequest{}, err
	}
	nonce, err := NewNonce()
	if err != nil {
		return AccountReconcileRequest{}, err
	}
	return AccountReconcileRequest{Format: AccountReconcileFormat, Origin: origin, HubID: hub.HubID, AccountID: account, OwnerID: owner, DeviceID: device, OriginalPacket: append([]byte(nil), original...), RequestID: id, ClientNonce: nonce, IssuedAt: formatUTC(now)}, nil
}

func ValidateAccountReconcileTarget(result AccountReconcileResult, original []byte) error {
	p, err := DecodePacket(original)
	if err != nil {
		return ErrInvalid
	}
	r := p.Packet.Route
	if result.OriginalOperation != r.Operation || result.OriginalRequestID != r.OperationID || result.OriginalPacketDigest != ActivationPacketDigest(original) || result.HubID != r.HubID || result.OwnerID != r.OwnerID || result.DeviceID != r.DeviceID {
		return ErrInvalid
	}
	return nil
}

func validateExtensionDevice(body any, device e2ee.PublicIdentity) error {
	if op, _, _, _, _, err := localDomainMetadata(body); err == nil && localDomainOperation(op) {
		if q, ok := dereference(body).(LocalDomainReconcileRequest); ok {
			p, err := DecodeLocalDomainPacket(q.OriginalPacket)
			if err != nil || !reflect.DeepEqual(p.SenderPublicIdentity, device) {
				return ErrInvalid
			}
			return nil
		}
		_, _, _, _, raw := localDomainParts(body)
		var proof e2ee.OwnerLocalDomainRequestProof
		if decodeCanonical(raw, e2ee.MaxLocalDomainProofBytes, &proof) != nil || !reflect.DeepEqual(proof.Claims.Scope.DevicePublic, device) {
			return ErrInvalid
		}
		return nil
	}
	if q, ok := dereference(body).(OwnerEndpointReadRequest); ok {
		var proof e2ee.OwnerEndpointReadProof
		if decodeCanonical(q.OwnerProof, MaxAppNodeProofBytes, &proof) != nil || !reflect.DeepEqual(proof.Claims.Scope.DevicePublic, device) {
			return ErrInvalid
		}
		return nil
	}
	if op, _, _, _, _, err := nativePairMetadata(body); err == nil && nativePairOperation(op) {
		return validateNativePairDevice(body, device)
	}
	if op, _, _, _, _, err := appNodeMetadata(body); err == nil && appNodeOperation(op) {
		return validateAppNodeDevice(body, device)
	}
	switch v := dereference(body).(type) {
	case ActivationPrepare:
		if v.OwnerPublic.ID == device.ID || v.Material.HubID == "" {
			return ErrInvalid
		}
		var g e2ee.OwnerDeviceGrant
		if decodeCanonical(v.OwnerDeviceGrant, 16*1024, &g) != nil {
			return ErrInvalid
		}
		at, err := parseCanonicalUTC(g.IssuedAt)
		if err != nil {
			return ErrInvalid
		}
		if _, err = e2ee.VerifyOwnerDeviceGrant(v.OwnerDeviceGrant, v.OwnerPublic, device, v.Material.OwnerID, v.OwnerPublic.ID, v.DeviceID, v.Material.HubID, e2ee.OwnerDevicePurposeControl, at); err != nil {
			return ErrInvalid
		}
	case ActivationComplete:
		if v.Binding.DeviceID == "" || v.Binding.DevicePublic.ID != device.ID || activationDigest("device", v.Binding.DevicePublic) != activationDigest("device", device) {
			return ErrInvalid
		}
	case ActivationStatusRequest:
	case AccountReconcileRequest:
		p, e := DecodePacket(v.OriginalPacket)
		if e != nil || activationDigest("device", p.SenderPublicIdentity) != activationDigest("device", device) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
