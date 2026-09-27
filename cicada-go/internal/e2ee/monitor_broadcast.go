package e2ee

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	MonitorBroadcastVersion                = 1
	MonitorBroadcastConsentEnvelopeVersion = 2
	MonitorBroadcastClientBodyMaxBytes     = 16 * 1024
	MonitorBroadcastType                   = "MONITOR_BROADCAST"
	monitorBroadcastAAD                    = "cicada/client/monitor-broadcast/aad/v1\x00"
	monitorBroadcastSign                   = "cicada/client/monitor-broadcast/sign/v1\x00"
	maxMonitorBroadcastBody                = 64 * 1024
	maxMonitorBroadcastWire                = 256 * 1024
)

// MonitorBroadcastContext binds one Client-created body to the exact approved
// operation and Monitor SessionBinding. Its fields must be supplied from
// trusted records when verifying or opening; this package does not decide
// whether the Client was authorized or whether the approval is still usable.
type MonitorBroadcastContext struct {
	HubID                   string `json:"hub_id"`
	OwnerID                 string `json:"owner_id"`
	ClientDeviceID          string `json:"client_device_id"`
	ClientSessionEpoch      uint64 `json:"client_session_epoch"`
	ClientKeyVersion        int64  `json:"client_key_version"`
	ApprovalID              string `json:"approval_id"`
	BroadcastID             string `json:"broadcast_id"`
	GroupID                 string `json:"group_id"`
	MonitorEndpointID       string `json:"monitor_endpoint_id"`
	MonitorKeyID            string `json:"monitor_key_id"`
	MonitorBindingID        string `json:"monitor_binding_id"`
	MonitorBindingEpoch     uint64 `json:"monitor_binding_epoch"`
	BodySHA256              string `json:"body_sha256"`
	RecipientSnapshotSHA256 string `json:"recipient_snapshot_sha256"`
	ExpiresAt               string `json:"expires_at"`
	ConsentSHA256           string `json:"consent_sha256,omitempty"`
	ConfirmRequestSequence  uint64 `json:"confirm_request_sequence,omitempty"`
}

type MonitorBroadcastEnvelope struct {
	Type      string                  `json:"type"`
	Version   int                     `json:"version"`
	Suite     string                  `json:"suite"`
	Context   MonitorBroadcastContext `json:"context"`
	Sealed    json.RawMessage         `json:"sealed"`
	Signature []byte                  `json:"signature"`
}

func (context MonitorBroadcastContext) validate() error {
	for _, value := range []string{context.HubID, context.OwnerID, context.ClientDeviceID,
		context.ApprovalID, context.BroadcastID, context.GroupID,
		context.MonitorEndpointID, context.MonitorKeyID, context.MonitorBindingID} {
		if !monitorBroadcastID(value) {
			return errors.New("monitor broadcast requires bounded ASCII identities")
		}
	}
	if context.ClientSessionEpoch == 0 || context.ClientKeyVersion <= 0 ||
		context.MonitorBindingEpoch == 0 || !monitorBroadcastDigest(context.BodySHA256) ||
		!monitorBroadcastDigest(context.RecipientSnapshotSHA256) {
		return ErrInvalidEnvelope
	}
	if (context.ConsentSHA256 == "") != (context.ConfirmRequestSequence == 0) ||
		(context.ConsentSHA256 != "" && !monitorBroadcastDigest(context.ConsentSHA256)) {
		return ErrInvalidEnvelope
	}
	if len(context.ExpiresAt) == 0 || context.ExpiresAt[len(context.ExpiresAt)-1] != 'Z' {
		return errors.New("monitor broadcast expiry must be canonical UTC")
	}
	expires, err := time.Parse(time.RFC3339Nano, context.ExpiresAt)
	if err != nil || expires.Format(time.RFC3339Nano) != context.ExpiresAt {
		return errors.New("monitor broadcast expiry must be canonical UTC")
	}
	return nil
}

func monitorBroadcastID(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '_' || char == ':' || char == '-') {
			return false
		}
	}
	return true
}

func monitorBroadcastDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func monitorBroadcastAADBytes(context MonitorBroadcastContext) ([]byte, error) {
	if err := context.validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(context)
	if err != nil {
		return nil, err
	}
	return append([]byte(monitorBroadcastAAD), encoded...), nil
}

func monitorBroadcastSignedBytes(envelope MonitorBroadcastEnvelope) ([]byte, error) {
	envelope.Signature = nil
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return append([]byte(monitorBroadcastSign), encoded...), nil
}

func decodeMonitorBroadcastJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidEnvelope
	}
	return nil
}

// SealMonitorBroadcast encrypts exact UTF-8 body bytes for one pinned Monitor
// Endpoint. Persist the returned bytes and sequence together; retries must
// reuse them instead of resealing or allocating another sequence.
func SealMonitorBroadcast(sender *Identity, monitor PublicIdentity, context MonitorBroadcastContext, body []byte, sequence uint64) ([]byte, error) {
	maxBody := maxMonitorBroadcastBody
	version := MonitorBroadcastVersion
	if context.ConsentSHA256 != "" {
		if sequence != context.ConfirmRequestSequence {
			return nil, ErrInvalidEnvelope
		}
		maxBody = MonitorBroadcastClientBodyMaxBytes
		version = MonitorBroadcastConsentEnvelopeVersion
	}
	if sender == nil || sender.signingPrivate == nil || sequence == 0 ||
		len(body) == 0 || len(body) > maxBody || !utf8.Valid(body) {
		return nil, ErrInvalidEnvelope
	}
	if err := context.validate(); err != nil {
		return nil, err
	}
	if err := ValidatePublicIdentity(monitor); err != nil || context.MonitorKeyID != monitor.ID {
		return nil, ErrInvalidEnvelope
	}
	sum := sha256.Sum256(body)
	if context.BodySHA256 != hex.EncodeToString(sum[:]) {
		return nil, errors.New("monitor broadcast body digest mismatch")
	}
	aad, err := monitorBroadcastAADBytes(context)
	if err != nil {
		return nil, err
	}
	sealed, err := Seal(sender, monitor, body, aad, sequence)
	if err != nil {
		return nil, err
	}
	envelope := MonitorBroadcastEnvelope{Type: MonitorBroadcastType, Version: version,
		Suite: Algorithm, Context: context, Sealed: json.RawMessage(sealed)}
	signed, err := monitorBroadcastSignedBytes(envelope)
	if err != nil {
		return nil, err
	}
	envelope.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sender.signingPrivate, signed, nil, true, envelope.Signature); err != nil {
		return nil, fmt.Errorf("sign monitor broadcast: %w", err)
	}
	wire, err := json.Marshal(envelope)
	if err != nil || len(wire) > maxMonitorBroadcastWire {
		return nil, ErrInvalidEnvelope
	}
	return wire, nil
}

// VerifyMonitorBroadcast authenticates the opaque frame, trusted context and
// both pinned public identities without decrypting. A successful verification
// does not establish caller authorization, approval validity, recipient
// membership, or whether the body matches its digest; Guard and the Monitor
// open step enforce those separate conditions.
func VerifyMonitorBroadcast(data []byte, expectedClient, expectedMonitor PublicIdentity, expected MonitorBroadcastContext) (uint64, error) {
	_, sequence, err := verifyMonitorBroadcast(data, expectedClient, expectedMonitor, expected)
	return sequence, err
}

func verifyMonitorBroadcast(data []byte, expectedClient, expectedMonitor PublicIdentity, expected MonitorBroadcastContext) (MonitorBroadcastEnvelope, uint64, error) {
	if len(data) == 0 || len(data) > maxMonitorBroadcastWire {
		return MonitorBroadcastEnvelope{}, 0, ErrInvalidEnvelope
	}
	if err := expected.validate(); err != nil {
		return MonitorBroadcastEnvelope{}, 0, err
	}
	if err := ValidatePublicIdentity(expectedMonitor); err != nil || expected.MonitorKeyID != expectedMonitor.ID {
		return MonitorBroadcastEnvelope{}, 0, ErrInvalidEnvelope
	}
	_, clientSigningKey, err := validatePublic(expectedClient)
	if err != nil {
		return MonitorBroadcastEnvelope{}, 0, err
	}
	var envelope MonitorBroadcastEnvelope
	if err := decodeMonitorBroadcastJSON(data, &envelope); err != nil {
		return MonitorBroadcastEnvelope{}, 0, fmt.Errorf("decode monitor broadcast: %w", err)
	}
	version := MonitorBroadcastVersion
	maxBody := maxMonitorBroadcastBody
	if expected.ConsentSHA256 != "" {
		version = MonitorBroadcastConsentEnvelopeVersion
		maxBody = MonitorBroadcastClientBodyMaxBytes
	}
	if envelope.Type != MonitorBroadcastType || envelope.Version != version ||
		envelope.Suite != Algorithm || envelope.Context != expected ||
		len(envelope.Sealed) == 0 || len(envelope.Signature) != mldsa65.SignatureSize {
		return MonitorBroadcastEnvelope{}, 0, ErrInvalidEnvelope
	}
	signed, err := monitorBroadcastSignedBytes(envelope)
	if err != nil || !mldsa65.Verify(clientSigningKey, signed, nil, envelope.Signature) {
		return MonitorBroadcastEnvelope{}, 0, errors.New("monitor broadcast signature verification failed")
	}
	var sealed Envelope
	if err := decodeMonitorBroadcastJSON(envelope.Sealed, &sealed); err != nil {
		return MonitorBroadcastEnvelope{}, 0, fmt.Errorf("decode monitor broadcast ciphertext: %w", err)
	}
	if sealed.Version != ProtocolVersion || sealed.Algorithm != Algorithm || sealed.Sequence == 0 ||
		sealed.SenderID != expectedClient.ID || !bytes.Equal(sealed.SenderSigningPublic, expectedClient.SigningPublic) ||
		len(sealed.KEMCiphertext) != mlkem768.CiphertextSize || len(sealed.Nonce) != 12 ||
		len(sealed.Ciphertext) < 17 || len(sealed.Ciphertext) > maxBody+16 ||
		len(sealed.Signature) != mldsa65.SignatureSize || sealed.SessionEpoch != 0 ||
		sealed.SessionCounter != 0 || len(sealed.SessionOffer) != 0 {
		return MonitorBroadcastEnvelope{}, 0, ErrInvalidEnvelope
	}
	if expected.ConsentSHA256 != "" && sealed.Sequence != expected.ConfirmRequestSequence {
		return MonitorBroadcastEnvelope{}, 0, ErrInvalidEnvelope
	}
	innerSignature := sealed.Signature
	sealed.Signature = nil
	innerSigned, err := json.Marshal(sealed)
	if err != nil || !mldsa65.Verify(clientSigningKey, innerSigned, nil, innerSignature) {
		return MonitorBroadcastEnvelope{}, 0, errors.New("monitor broadcast ciphertext signature verification failed")
	}
	return envelope, sealed.Sequence, nil
}

// OpenMonitorBroadcast requires the current Monitor private identity and the
// exact trusted context. The returned sequence still needs an atomic durable
// replay/single-use check in the Node and approval ledger.
func OpenMonitorBroadcast(monitor *Identity, expectedClient PublicIdentity, expected MonitorBroadcastContext, data []byte) ([]byte, uint64, error) {
	if monitor == nil || monitor.kemPrivate == nil {
		return nil, 0, ErrInvalidEnvelope
	}
	envelope, sequence, err := verifyMonitorBroadcast(data, expectedClient, monitor.Public(), expected)
	if err != nil {
		return nil, 0, err
	}
	aad, err := monitorBroadcastAADBytes(expected)
	if err != nil {
		return nil, 0, err
	}
	body, openedSequence, err := Open(monitor, expectedClient, envelope.Sealed, aad)
	if err != nil {
		return nil, 0, err
	}
	maxBody := maxMonitorBroadcastBody
	if expected.ConsentSHA256 != "" {
		maxBody = MonitorBroadcastClientBodyMaxBytes
	}
	if sequence != openedSequence || len(body) == 0 || len(body) > maxBody || !utf8.Valid(body) {
		return nil, 0, ErrInvalidEnvelope
	}
	sum := sha256.Sum256(body)
	if expected.BodySHA256 != hex.EncodeToString(sum[:]) {
		return nil, 0, errors.New("monitor broadcast body digest mismatch")
	}
	return body, sequence, nil
}
