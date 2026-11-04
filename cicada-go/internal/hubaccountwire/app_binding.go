package hubaccountwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

const (
	AppBindingContract             = "app-hub-binding-v1"
	AppBindingCapabilitiesPath     = "/v2/owner/app-binding/capabilities"
	AppUnbindPrepareFormat         = "cicada.app-unbind-prepare.v1"
	AppRebindPrepareFormat         = "cicada.app-rebind-prepare.v1"
	AppBindingFormat               = "cicada.app-hub-binding.v1"
	AppBindingChallengeFormat      = "cicada.app-hub-binding-challenge.v1"
	AppBindingCompleteFormat       = "cicada.app-hub-binding-complete.v1"
	AppBindingResultFormat         = "cicada.app-hub-binding-result.v1"
	OperationAppUnbindPrepare      = "owner.app.unbind.prepare"
	OperationAppUnbindComplete     = "owner.app.unbind.complete"
	OperationAppRebindPrepare      = "owner.app.rebind.prepare"
	OperationAppRebindComplete     = "owner.app.rebind.complete"
	AppBindingPurposeUnbind        = "VOLUNTARY_APP_UNBIND"
	AppBindingPurposeRebind        = "REPLACE_VOLUNTARILY_UNBOUND_APP"
	AppBindingUnbound              = "UNBOUND"
	AppBindingBoundZero            = "BOUND_ZERO"
	AppBindingRejected             = "REJECTED"
	MaxAppBindingChallengeLifetime = 2 * time.Minute
	MaxAppBindingOriginalBytes     = 96 << 10
	MaxAppBindingProofBytes        = 96 << 10
)

type AppBindingCapabilities struct {
	ContractRevision string   `json:"contract_revision"`
	Available        bool     `json:"available"`
	Operations       []string `json:"operations"`
	Recovery         string   `json:"recovery"`
}

func AppBindingContractCapabilities() AppBindingCapabilities {
	return AppBindingCapabilities{ContractRevision: AppBindingContract, Available: true, Operations: []string{OperationAppUnbindPrepare, OperationAppUnbindComplete, OperationAppRebindPrepare, OperationAppRebindComplete}, Recovery: "BYTE_IDENTICAL_ORIGINAL_ONLY"}
}

func AppBindingHTTPPath(operation string) string {
	switch operation {
	case OperationAppUnbindPrepare:
		return "/v2/owner/app-binding/unbind/prepare"
	case OperationAppUnbindComplete:
		return "/v2/owner/app-binding/unbind/complete"
	case OperationAppRebindPrepare:
		return "/v2/owner/app-binding/rebind/prepare"
	case OperationAppRebindComplete:
		return "/v2/owner/app-binding/rebind/complete"
	}
	return ""
}

// Only this current account device is a target. The session ID is resolved
// from its token by the Hub, never invented by a caller.
type AppUnbindPrepare struct {
	Format       string              `json:"format"`
	Origin       string              `json:"origin"`
	HubID        string              `json:"hub_id"`
	AccountID    string              `json:"account_id"`
	OwnerID      string              `json:"owner_id"`
	DeviceID     string              `json:"device_id"`
	SessionToken []byte              `json:"session_token"`
	AccountEpoch uint64              `json:"account_epoch"`
	DeviceEpoch  uint64              `json:"device_epoch"`
	OwnerPublic  e2ee.PublicIdentity `json:"owner_public_identity"`
	RequestID    string              `json:"request_id"`
	ClientNonce  []byte              `json:"client_nonce"`
	IssuedAt     string              `json:"issued_at"`
}

// Rebind is one replacement of one exact voluntary-unbind tombstone, not a
// general registration or a new initial Owner activation.
type AppRebindPrepare struct {
	Format              string              `json:"format"`
	Origin              string              `json:"origin"`
	HubID               string              `json:"hub_id"`
	AccountID           string              `json:"account_id"`
	OwnerID             string              `json:"owner_id"`
	PreviousDeviceID    string              `json:"previous_device_id"`
	UnbindBindingDigest string              `json:"unbind_binding_digest"`
	DeviceID            string              `json:"device_id"`
	OwnerPublic         e2ee.PublicIdentity `json:"owner_public_identity"`
	RequestID           string              `json:"request_id"`
	ClientNonce         []byte              `json:"client_nonce"`
	IssuedAt            string              `json:"issued_at"`
}

// Every field is covered by the Owner KEM/signing challenge's operation digest.
// Empty previous/session coordinates are mandatory only in their disjoint mode.
type AppBinding struct {
	Format              string              `json:"format"`
	Purpose             string              `json:"purpose"`
	Origin              string              `json:"origin"`
	HubID               string              `json:"hub_id"`
	HubFingerprint      string              `json:"hub_fingerprint"`
	AccountID           string              `json:"account_id"`
	OwnerID             string              `json:"owner_id"`
	OwnerPublic         e2ee.PublicIdentity `json:"owner_public_identity"`
	OwnerKeyVersion     uint64              `json:"owner_key_version"`
	AccountEpoch        uint64              `json:"account_epoch"`
	CredentialVersion   uint64              `json:"credential_version"`
	DeviceID            string              `json:"device_id"`
	DevicePublic        e2ee.PublicIdentity `json:"device_public_identity"`
	DeviceEpoch         uint64              `json:"device_epoch"`
	ClientDeviceVersion uint64              `json:"client_device_version"`
	ClientSessionEpoch  uint64              `json:"client_session_epoch"`
	SessionID           string              `json:"session_id"`
	PreviousDeviceID    string              `json:"previous_device_id"`
	UnbindBindingDigest string              `json:"unbind_binding_digest"`
	PrepareRequestID    string              `json:"prepare_request_id"`
	PreparePacketDigest string              `json:"prepare_packet_digest"`
	IssuedAt            string              `json:"issued_at"`
	ExpiresAt           string              `json:"expires_at"`
}

func (b AppBinding) Digest() string { return appBindingDigest("binding", b) }
func appBindingDigest(domain string, value any) string {
	raw, _ := json.Marshal(value)
	s := sha256.Sum256(append([]byte("cicada/app-hub-binding/"+domain+"/v1\x00"), raw...))
	return hex.EncodeToString(s[:])
}
func AppBindingPacketDigest(raw []byte) string {
	s := sha256.Sum256(append([]byte("cicada/app-hub-binding/packet/v1\x00"), raw...))
	return hex.EncodeToString(s[:])
}

type AppBindingChallenge struct {
	Format              string                     `json:"format"`
	Operation           string                     `json:"operation"`
	RequestID           string                     `json:"request_id"`
	RequestPacketDigest string                     `json:"request_packet_digest"`
	Binding             AppBinding                 `json:"binding"`
	ClientNonce         []byte                     `json:"client_nonce"`
	ServerNonce         []byte                     `json:"server_nonce"`
	Proof               ownerbootstrap.PairingFile `json:"proof"`
}

type AppBindingComplete struct {
	Format        string     `json:"format"`
	Binding       AppBinding `json:"binding"`
	PreparePacket []byte     `json:"prepare_packet"`
	ServerNonce   []byte     `json:"server_nonce"`
	OwnerProof    []byte     `json:"owner_proof"`
	RequestID     string     `json:"request_id"`
	ClientNonce   []byte     `json:"client_nonce"`
	IssuedAt      string     `json:"issued_at"`
}

// A terminal rejection names the exact original and its intended binding too.
// It settles only this original's no-effect fence, never a Hub/account deletion.
type AppBindingResult struct {
	Format              string `json:"format"`
	Operation           string `json:"operation"`
	RequestID           string `json:"request_id"`
	RequestPacketDigest string `json:"request_packet_digest"`
	State               string `json:"state"`
	ErrorCode           string `json:"error_code"`
	BindingDigest       string `json:"binding_digest"`
	DeviceID            string `json:"device_id"`
	DeviceEpoch         uint64 `json:"device_epoch"`
	ClientDeviceVersion uint64 `json:"client_device_version"`
	ClientSessionEpoch  uint64 `json:"client_session_epoch"`
	ObservedAt          string `json:"observed_at"`
}

func NewAppUnbindPrepare(session SessionContext, owner e2ee.PublicIdentity, now time.Time) (AppUnbindPrepare, error) {
	if validateSessionContext(session, now) != nil || e2ee.ValidatePublicIdentity(owner) != nil || owner.ID == session.DeviceKeyID {
		return AppUnbindPrepare{}, ErrInvalid
	}
	id, err := NewRequestID()
	if err != nil {
		return AppUnbindPrepare{}, err
	}
	nonce, err := NewNonce()
	if err != nil {
		return AppUnbindPrepare{}, err
	}
	return AppUnbindPrepare{Format: AppUnbindPrepareFormat, Origin: session.Origin, HubID: session.HubID, AccountID: session.AccountID, OwnerID: session.OwnerID, DeviceID: session.DeviceID, SessionToken: append([]byte(nil), session.SessionToken...), AccountEpoch: session.AccountEpoch, DeviceEpoch: session.DeviceEpoch, OwnerPublic: owner, RequestID: id, ClientNonce: nonce, IssuedAt: formatUTC(now)}, nil
}

func NewAppRebindPrepare(hub HubIdentity, origin, account, owner, previousDevice, unbindDigest, newDeviceID string, ownerPublic e2ee.PublicIdentity, now time.Time) (AppRebindPrepare, error) {
	id, err := NewRequestID()
	if err != nil {
		return AppRebindPrepare{}, err
	}
	nonce, err := NewNonce()
	if err != nil {
		return AppRebindPrepare{}, err
	}
	q := AppRebindPrepare{Format: AppRebindPrepareFormat, Origin: origin, HubID: hub.HubID, AccountID: account, OwnerID: owner, PreviousDeviceID: previousDevice, UnbindBindingDigest: unbindDigest, DeviceID: newDeviceID, OwnerPublic: ownerPublic, RequestID: id, ClientNonce: nonce, IssuedAt: formatUTC(now)}
	return q, validateAppBindingRequest(q, hub, now)
}

func NewAppBindingComplete(originalPrepare []byte, challenge AppBindingChallenge, ownerProof []byte, now time.Time) (AppBindingComplete, error) {
	if ValidateAppBindingChallenge(challenge, challenge.Proof.Hub, now) != nil || AppBindingPacketDigest(originalPrepare) != challenge.RequestPacketDigest || len(originalPrepare) > MaxAppBindingOriginalBytes || len(ownerProof) == 0 || len(ownerProof) > MaxAppBindingProofBytes {
		return AppBindingComplete{}, ErrInvalid
	}
	p, err := DecodePacket(originalPrepare)
	if err != nil || p.Packet.Route.Operation != challenge.Operation || p.Packet.Route.OperationID != challenge.RequestID || !reflect.DeepEqual(p.SenderPublicIdentity, challenge.Binding.DevicePublic) {
		return AppBindingComplete{}, ErrInvalid
	}
	id, err := NewRequestID()
	if err != nil {
		return AppBindingComplete{}, err
	}
	nonce, err := NewNonce()
	if err != nil {
		return AppBindingComplete{}, err
	}
	q := AppBindingComplete{Format: AppBindingCompleteFormat, Binding: challenge.Binding, PreparePacket: append([]byte(nil), originalPrepare...), ServerNonce: append([]byte(nil), challenge.ServerNonce...), OwnerProof: append([]byte(nil), ownerProof...), RequestID: id, ClientNonce: nonce, IssuedAt: formatUTC(now)}
	return q, validateAppBindingRequest(q, challenge.Proof.Hub, now)
}

func ValidateAppBindingPreparedResponse(prepare any, original []byte, challenge AppBindingChallenge, hub HubIdentity, now time.Time) error {
	if validateAppBindingRequest(prepare, hub, time.Time{}) != nil || ValidateAppBindingChallenge(challenge, hub, now) != nil || AppBindingPacketDigest(original) != challenge.RequestPacketDigest {
		return ErrInvalid
	}
	op, id, owner, device, _, err := appBindingMetadata(prepare)
	b := challenge.Binding
	if err != nil || op != challenge.Operation || id != challenge.RequestID || owner != b.OwnerID || device != b.DeviceID {
		return ErrInvalid
	}
	packet, err := PreflightRequest(original, op)
	if err != nil || packet.Packet.Route.OperationID != id || !reflect.DeepEqual(packet.SenderPublicIdentity, b.DevicePublic) {
		return ErrInvalid
	}
	switch q := dereference(prepare).(type) {
	case AppUnbindPrepare:
		if b.Purpose != AppBindingPurposeUnbind || q.Origin != b.Origin || q.AccountID != b.AccountID || q.AccountEpoch != b.AccountEpoch || q.DeviceEpoch != b.DeviceEpoch || !reflect.DeepEqual(q.OwnerPublic, b.OwnerPublic) || !reflect.DeepEqual(q.ClientNonce, challenge.ClientNonce) {
			return ErrInvalid
		}
	case AppRebindPrepare:
		if b.Purpose != AppBindingPurposeRebind || q.Origin != b.Origin || q.AccountID != b.AccountID || q.PreviousDeviceID != b.PreviousDeviceID || q.UnbindBindingDigest != b.UnbindBindingDigest || !reflect.DeepEqual(q.OwnerPublic, b.OwnerPublic) || !reflect.DeepEqual(q.ClientNonce, challenge.ClientNonce) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func ValidateAppBindingResultTarget(result AppBindingResult, original []byte, binding AppBinding) error {
	p, err := DecodePacket(original)
	if err != nil || ValidateAppBinding(binding, time.Time{}) != nil || !reflect.DeepEqual(p.SenderPublicIdentity, binding.DevicePublic) || result.RequestPacketDigest != AppBindingPacketDigest(original) || result.BindingDigest != binding.Digest() || result.DeviceID != binding.DeviceID || p.Packet.Route.DeviceID != binding.DeviceID || p.Packet.Route.HubID != binding.HubID || p.Packet.Route.OwnerID != binding.OwnerID || result.Operation != p.Packet.Route.Operation || result.RequestID != p.Packet.Route.OperationID || validateAppBindingResult(result) != nil {
		return ErrInvalid
	}
	op := OperationAppUnbindComplete
	if binding.Purpose == AppBindingPurposeRebind {
		op = OperationAppRebindComplete
	}
	if result.Operation != op {
		return ErrInvalid
	}
	if result.State == AppBindingUnbound && (binding.Purpose != AppBindingPurposeUnbind || result.DeviceEpoch != binding.DeviceEpoch+1 || result.ClientDeviceVersion != binding.ClientDeviceVersion+1 || result.ClientSessionEpoch != binding.ClientSessionEpoch+1) {
		return ErrInvalid
	}
	if result.State == AppBindingBoundZero && (binding.Purpose != AppBindingPurposeRebind || result.DeviceEpoch != 1 || result.ClientDeviceVersion != 1 || result.ClientSessionEpoch != 1) {
		return ErrInvalid
	}
	return nil
}

func (AppUnbindPrepare) String() string      { return "AppUnbindPrepare[redacted]" }
func (AppBindingComplete) String() string    { return "AppBindingComplete[redacted]" }
func (AppUnbindPrepare) GoString() string    { return "AppUnbindPrepare[redacted]" }
func (AppBindingComplete) GoString() string  { return "AppBindingComplete[redacted]" }
func (AppBindingChallenge) String() string   { return "AppBindingChallenge[redacted]" }
func (AppBindingChallenge) GoString() string { return "AppBindingChallenge[redacted]" }
