package hubaccountwire

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

// Activation is an additive protocol. None of the six account-v1 operations,
// owner-bootstrap-v1 bytes, or Client catalog identities are revised in place.
const (
	ActivationFormat            = "cicada.owner-activation.v1"
	ActivationCodePrefix        = "cicada-owner-activation-v1:"
	ActivationPrepareFormat     = "cicada.owner-activation-prepare.v1"
	ActivationChallengeFormat   = "cicada.owner-activation-challenge.v1"
	ActivationCompleteFormat    = "cicada.owner-activation-complete.v1"
	ActivationStatusFormat      = "cicada.owner-activation-status.v1"
	ActivationResultFormat      = "cicada.owner-activation-result.v1"
	PurposeInitialActivation    = "INITIAL_OWNER_ACTIVATION"
	PurposeLegacyContinuation   = "LEGACY_PENDING_CONTINUATION"
	OperationActivationPrepare  = "owner.activation.prepare"
	OperationActivationComplete = "owner.activation.complete"
	OperationActivationStatus   = "owner.activation.status"
	ActivationIssued            = "ISSUED"
	ActivationPrepared          = "PREPARED"
	ActivationCompleted         = "COMPLETED"
	ActivationRejected          = "REJECTED"
	ActivationCancelled         = "CANCELLED"
	ActivationAbsent            = "ABSENT"
	ActivationLeaseActive       = "ACTIVE"
	ActivationLeaseExpired      = "EXPIRED"
	ActivationLeaseRevoked      = "REVOKED"
	ActivationLeaseUnavailable  = "UNAVAILABLE"
	MaxActivationLifetime       = time.Hour
	MaxActivationProofLifetime  = 10 * time.Minute
	MaxAppLeaseLifetime         = 15 * time.Minute
	MaxActivationBodyBytes      = 192 * 1024
)

// ActivationMaterial is secret-bearing local installation material, never a
// URL. Legacy issuance includes the complete immutable pending Owner identity.
type ActivationMaterial struct {
	Format              string               `json:"format"`
	Version             int                  `json:"version"`
	Purpose             string               `json:"purpose"`
	Origin              string               `json:"origin"`
	AllowLoopbackHTTP   bool                 `json:"allow_loopback_http"`
	HubID               string               `json:"hub_id"`
	HubFingerprint      string               `json:"hub_fingerprint"`
	AccountID           string               `json:"account_id"`
	OwnerID             string               `json:"owner_id"`
	ActivationID        string               `json:"activation_id"`
	SetupEpoch          uint64               `json:"setup_epoch"`
	AccountEpoch        uint64               `json:"account_epoch"`
	ExpectedOwnerPublic *e2ee.PublicIdentity `json:"expected_owner_public_identity"`
	Code                string               `json:"code"`
	IssuedAt            string               `json:"issued_at"`
	ExpiresAt           string               `json:"expires_at"`
}

type ActivationPrepare struct {
	Format           string              `json:"format"`
	Material         ActivationMaterial  `json:"material"`
	OwnerPublic      e2ee.PublicIdentity `json:"owner_public_identity"`
	DeviceID         string              `json:"device_id"`
	OwnerDeviceGrant []byte              `json:"owner_device_grant"`
	RequestID        string              `json:"request_id"`
	ClientNonce      []byte              `json:"client_nonce"`
	IssuedAt         string              `json:"issued_at"`
}

// ActivationBinding is committed before either private-key challenge leaves
// the Hub. Owner proof signs its domain-separated digest through the unchanged
// bootstrap manifest's operation_id. This binds both identities and the lease.
type ActivationBinding struct {
	Format              string              `json:"format"`
	Purpose             string              `json:"purpose"`
	Origin              string              `json:"origin"`
	HubID               string              `json:"hub_id"`
	HubFingerprint      string              `json:"hub_fingerprint"`
	AccountID           string              `json:"account_id"`
	OwnerID             string              `json:"owner_id"`
	ActivationID        string              `json:"activation_id"`
	SetupEpoch          uint64              `json:"setup_epoch"`
	AccountEpoch        uint64              `json:"account_epoch"`
	DeviceEpoch         uint64              `json:"device_epoch"`
	OwnerPublic         e2ee.PublicIdentity `json:"owner_public_identity"`
	DeviceID            string              `json:"device_id"`
	DevicePublic        e2ee.PublicIdentity `json:"device_public_identity"`
	PrepareRequestID    string              `json:"prepare_request_id"`
	PreparePacketDigest string              `json:"prepare_packet_digest"`
	GrantDigest         string              `json:"grant_digest"`
	AllowedOperations   []string            `json:"allowed_operations"`
	LeaseExpiresAt      string              `json:"lease_expires_at"`
}

func (b ActivationBinding) Digest() string { return activationDigest("binding", b) }
func ActivationPacketDigest(raw []byte) string {
	s := sha256.Sum256(append([]byte("cicada/owner-activation/packet/v1\x00"), raw...))
	return hex.EncodeToString(s[:])
}
func activationDigest(domain string, value any) string {
	raw, _ := json.Marshal(value)
	s := sha256.Sum256(append([]byte("cicada/owner-activation/"+domain+"/v1\x00"), raw...))
	return hex.EncodeToString(s[:])
}
func ActivationGrantDigest(grant []byte) string {
	s := sha256.Sum256(grant)
	return hex.EncodeToString(s[:])
}
func ActivationAllowedOperations() []string { return []string{"nodes.list", "session.capabilities"} }

// ActivationHTTPPath owns the additive operation-to-endpoint mapping.
func ActivationHTTPPath(operation string) string {
	switch operation {
	case OperationActivationPrepare:
		return "/v2/owner/activation/prepare"
	case OperationActivationComplete:
		return "/v2/owner/activation/complete"
	case OperationActivationStatus:
		return "/v2/owner/activation/status"
	case OperationAccountReconcile:
		return "/v2/owner/account/reconcile"
	}
	return ""
}

type ActivationChallenge struct {
	Format      string                     `json:"format"`
	Binding     ActivationBinding          `json:"binding"`
	ClientNonce []byte                     `json:"client_nonce"`
	ServerNonce []byte                     `json:"server_nonce"`
	Proof       ownerbootstrap.PairingFile `json:"proof"`
	IssuedAt    string                     `json:"issued_at"`
	ExpiresAt   string                     `json:"expires_at"`
}

type ActivationComplete struct {
	Format      string            `json:"format"`
	Binding     ActivationBinding `json:"binding"`
	ServerNonce []byte            `json:"server_nonce"`
	OwnerProof  []byte            `json:"owner_proof"`
	Username    string            `json:"username"`
	Password    string            `json:"password"`
	RequestID   string            `json:"request_id"`
	ClientNonce []byte            `json:"client_nonce"`
	IssuedAt    string            `json:"issued_at"`
}

// Status never changes an absent operation into a settled failure. Callers
// retain an uncertain packet unless a durable terminal result names its digest.
type ActivationStatusRequest struct {
	Format             string `json:"format"`
	Origin             string `json:"origin"`
	HubID              string `json:"hub_id"`
	AccountID          string `json:"account_id"`
	OwnerID            string `json:"owner_id"`
	ActivationID       string `json:"activation_id"`
	DeviceID           string `json:"device_id"`
	TargetOperation    string `json:"target_operation"`
	TargetRequestID    string `json:"target_request_id"`
	TargetPacketDigest string `json:"target_packet_digest"`
	RequestID          string `json:"request_id"`
	ClientNonce        []byte `json:"client_nonce"`
	IssuedAt           string `json:"issued_at"`
}

// ActivationResult is used by all three new operations. ReceiptPacket contains
// the original authenticated response on reconciliation, never a new grant.
type ActivationResult struct {
	Format              string   `json:"format"`
	Operation           string   `json:"operation"`
	RequestID           string   `json:"request_id"`
	RequestPacketDigest string   `json:"request_packet_digest"`
	Origin              string   `json:"origin"`
	HubID               string   `json:"hub_id"`
	AccountID           string   `json:"account_id"`
	OwnerID             string   `json:"owner_id"`
	ActivationID        string   `json:"activation_id"`
	DeviceID            string   `json:"device_id"`
	AccountEpoch        uint64   `json:"account_epoch"`
	DeviceEpoch         uint64   `json:"device_epoch"`
	State               string   `json:"state"`
	RootState           string   `json:"root_state"`
	LeaseState          string   `json:"lease_state"`
	LeaseExpiresAt      string   `json:"lease_expires_at"`
	AllowedOperations   []string `json:"allowed_operations"`
	LoginRequired       bool     `json:"login_required"`
	TargetOperation     string   `json:"target_operation"`
	TargetRequestID     string   `json:"target_request_id"`
	TargetPacketDigest  string   `json:"target_packet_digest"`
	TargetState         string   `json:"target_state"`
	ReceiptPacket       []byte   `json:"receipt_packet"`
	ObservedAt          string   `json:"observed_at"`
}

func EncodeActivationCode(m ActivationMaterial) (string, error) {
	if ValidateActivationMaterial(m, time.Time{}) != nil {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", ErrInvalid
	}
	defer clear(raw)
	return ActivationCodePrefix + rawURL.EncodeToString(raw), nil
}
func DecodeActivationCode(code string) (ActivationMaterial, error) {
	var m ActivationMaterial
	if !strings.HasPrefix(code, ActivationCodePrefix) || len(code) > 32*1024 || strings.ContainsAny(code, " \t\r\n?#") {
		return m, ErrInvalid
	}
	raw, err := decodeRawURLBase64(strings.TrimPrefix(code, ActivationCodePrefix))
	defer clear(raw)
	if err != nil || decodeCanonical(raw, MaxClaimCardBytes, &m) != nil || ValidateActivationMaterial(m, time.Time{}) != nil {
		return ActivationMaterial{}, ErrInvalid
	}
	return m, nil
}
func ValidateActivationMaterial(m ActivationMaterial, now time.Time) error {
	if m.Format != ActivationFormat || m.Version != 1 || !validID(m.HubID) || !validID(m.AccountID) || !validID(m.OwnerID) || !isHex(m.ActivationID, 16) || !isHex(m.HubFingerprint, 32) || m.SetupEpoch == 0 || m.AccountEpoch == 0 || validateTimeWindowNow(m.IssuedAt, m.ExpiresAt, MaxActivationLifetime, now) != nil {
		return ErrInvalid
	}
	origin, err := ownerbootstrap.CanonicalOrigin(m.Origin, m.AllowLoopbackHTTP)
	if err != nil || origin != m.Origin {
		return ErrInvalid
	}
	secret, err := base64.RawURLEncoding.DecodeString(m.Code)
	defer clear(secret)
	if err != nil || len(secret) != CodeBytes || rawURL.EncodeToString(secret) != m.Code {
		return ErrInvalid
	}
	switch m.Purpose {
	case PurposeInitialActivation:
		if m.ExpectedOwnerPublic != nil {
			return ErrInvalid
		}
	case PurposeLegacyContinuation:
		if m.ExpectedOwnerPublic == nil || e2ee.ValidatePublicIdentity(*m.ExpectedOwnerPublic) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func ValidateActivationHub(m ActivationMaterial, hub HubIdentity, now time.Time) error {
	fp, err := HubFingerprint(hub)
	if err != nil || ValidateActivationMaterial(m, now) != nil || m.HubID != hub.HubID || m.HubFingerprint != fp {
		return ErrInvalid
	}
	return nil
}
func NewActivationPrepare(m ActivationMaterial, hub HubIdentity, device e2ee.PublicIdentity, owner e2ee.PublicIdentity, deviceID string, grant []byte, now time.Time) (ActivationPrepare, error) {
	if ValidateActivationHub(m, hub, now) != nil || e2ee.ValidatePublicIdentity(device) != nil || e2ee.ValidatePublicIdentity(owner) != nil || !validDeviceID(deviceID) || owner.ID == device.ID || owner.ID == hub.Public.ID || device.ID == hub.Public.ID || (m.ExpectedOwnerPublic != nil && !reflect.DeepEqual(*m.ExpectedOwnerPublic, owner)) {
		return ActivationPrepare{}, ErrInvalid
	}
	if _, err := e2ee.VerifyOwnerDeviceGrant(grant, owner, device, m.OwnerID, owner.ID, deviceID, m.HubID, e2ee.OwnerDevicePurposeControl, now); err != nil {
		return ActivationPrepare{}, ErrInvalid
	}
	var g e2ee.OwnerDeviceGrant
	if decodeCanonical(grant, 16*1024, &g) != nil || validateTimeWindow(g.IssuedAt, g.ExpiresAt, MaxActivationProofLifetime) != nil {
		return ActivationPrepare{}, ErrInvalid
	}
	id, err := NewRequestID()
	if err != nil {
		return ActivationPrepare{}, err
	}
	nonce, err := NewNonce()
	if err != nil {
		return ActivationPrepare{}, err
	}
	return ActivationPrepare{Format: ActivationPrepareFormat, Material: m, OwnerPublic: owner, DeviceID: deviceID, OwnerDeviceGrant: append([]byte(nil), grant...), RequestID: id, ClientNonce: nonce, IssuedAt: formatUTC(now)}, nil
}
func ValidateActivationChallenge(ch ActivationChallenge, hub HubIdentity, device e2ee.PublicIdentity, now time.Time) error {
	b := ch.Binding
	p := ch.Proof
	m := p.Manifest
	fp, err := HubFingerprint(hub)
	if err != nil || validateActivationBinding(b) != nil || ch.Format != ActivationChallengeFormat || b.Format != ActivationFormat || b.HubID != hub.HubID || b.HubFingerprint != fp || !reflect.DeepEqual(b.DevicePublic, device) || !reflect.DeepEqual(p.Hub, hub) || p.Origin != b.Origin || (strings.HasPrefix(b.Origin, "http:") && !p.AllowLoopbackHTTP) || m.AccountID != b.AccountID || m.OwnerID != b.OwnerID || m.AuthorityID != b.ActivationID || m.OperationID != b.Digest() || !reflect.DeepEqual(m.CandidatePublic, b.OwnerPublic) || m.ExpiresAt != ch.ExpiresAt || p.Validate(now) != nil || len(ch.ClientNonce) != NonceBytes || len(ch.ServerNonce) != NonceBytes || !reflect.DeepEqual(b.AllowedOperations, ActivationAllowedOperations()) || validateTimeWindowNow(ch.IssuedAt, ch.ExpiresAt, MaxActivationProofLifetime, now) != nil || validateTimeWindow(ch.IssuedAt, b.LeaseExpiresAt, MaxAppLeaseLifetime) != nil {
		return ErrInvalid
	}
	issued, _ := parseCanonicalUTC(ch.IssuedAt)
	if b.LeaseExpiresAt != formatUTC(issued.Add(MaxAppLeaseLifetime)) {
		return ErrInvalid
	}
	return nil
}

// ValidateActivationPreparedResponse also checks fields available while the
// caller still holds the typed prepare. Exact request bytes must be retained
// for response binding and crash-safe retry, never reconstructed and resealed.
func ValidateActivationPreparedResponse(ch ActivationChallenge, prepare ActivationPrepare, packet []byte, hub HubIdentity, device e2ee.PublicIdentity, now time.Time) error {
	b := ch.Binding
	m := prepare.Material
	if ValidateActivationChallenge(ch, hub, device, now) != nil || b.PreparePacketDigest != ActivationPacketDigest(packet) || b.PrepareRequestID != prepare.RequestID || !reflect.DeepEqual(ch.ClientNonce, prepare.ClientNonce) || b.GrantDigest != ActivationGrantDigest(prepare.OwnerDeviceGrant) || !reflect.DeepEqual(b.OwnerPublic, prepare.OwnerPublic) || b.DeviceID != prepare.DeviceID || b.ActivationID != m.ActivationID || b.Origin != m.Origin || b.Purpose != m.Purpose || b.AccountID != m.AccountID || b.OwnerID != m.OwnerID || b.SetupEpoch != m.SetupEpoch || b.AccountEpoch != m.AccountEpoch || ch.Proof.AllowLoopbackHTTP != m.AllowLoopbackHTTP {
		return ErrInvalid
	}
	return nil
}

func ValidateActivationStatusTarget(result ActivationResult, original []byte) error {
	p, err := DecodePacket(original)
	if err != nil {
		return ErrInvalid
	}
	r := p.Packet.Route
	if result.Operation != OperationActivationStatus || result.TargetOperation != r.Operation || result.TargetRequestID != r.OperationID || result.TargetPacketDigest != ActivationPacketDigest(original) || result.HubID != r.HubID || result.OwnerID != r.OwnerID || result.DeviceID != r.DeviceID {
		return ErrInvalid
	}
	return nil
}
func NewActivationComplete(ch ActivationChallenge, hub HubIdentity, device e2ee.PublicIdentity, owner *e2ee.Identity, username, password string, now time.Time) (ActivationComplete, error) {
	if owner == nil || ValidateActivationChallenge(ch, hub, device, now) != nil || !reflect.DeepEqual(ch.Binding.OwnerPublic, owner.Public()) {
		return ActivationComplete{}, ErrInvalid
	}
	if ch.Binding.Purpose == PurposeInitialActivation {
		if !validUsername(username) || !validPassword(password) {
			return ActivationComplete{}, ErrInvalid
		}
	} else if username != "" || password != "" {
		return ActivationComplete{}, ErrInvalid
	}
	proof, err := ownerbootstrap.CreateProof(owner, ch.Proof, now)
	if err != nil {
		return ActivationComplete{}, err
	}
	id, err := NewRequestID()
	if err != nil {
		return ActivationComplete{}, err
	}
	nonce, err := NewNonce()
	if err != nil {
		return ActivationComplete{}, err
	}
	return ActivationComplete{Format: ActivationCompleteFormat, Binding: ch.Binding, ServerNonce: append([]byte(nil), ch.ServerNonce...), OwnerProof: proof, Username: username, Password: password, RequestID: id, ClientNonce: nonce, IssuedAt: formatUTC(now)}, nil
}
func NewActivationStatusRequest(hub HubIdentity, origin, account, owner, activationID, deviceID, operation, requestID, digest string, now time.Time) (ActivationStatusRequest, error) {
	if validateHubIdentity(hub) != nil || validateOrigin(origin) != nil || !validID(account) || !validID(owner) || !isHex(activationID, 16) || !validDeviceID(deviceID) || (operation != OperationActivationPrepare && operation != OperationActivationComplete) || !isHex(requestID, 16) || !isHex(digest, 32) {
		return ActivationStatusRequest{}, ErrInvalid
	}
	id, err := NewRequestID()
	if err != nil {
		return ActivationStatusRequest{}, err
	}
	nonce, err := NewNonce()
	if err != nil {
		return ActivationStatusRequest{}, err
	}
	return ActivationStatusRequest{Format: ActivationStatusFormat, Origin: origin, HubID: hub.HubID, AccountID: account, OwnerID: owner, ActivationID: activationID, DeviceID: deviceID, TargetOperation: operation, TargetRequestID: requestID, TargetPacketDigest: digest, RequestID: id, ClientNonce: nonce, IssuedAt: formatUTC(now)}, nil
}
