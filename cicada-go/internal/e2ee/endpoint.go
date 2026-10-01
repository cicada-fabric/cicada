package e2ee

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	EndpointEnvelopeVersion = 1
	EndpointEnvelopeSuite   = Algorithm
	endpointAADDomain       = "cicada/fabric/endpoint-envelope/v1\x00"
	maxEndpointPlaintext    = 64 * 1024
	maxEndpointWire         = 256 * 1024
)

// EndpointMessageContext is authenticated as AEAD associated data. A caller
// must construct the expected value from trusted SessionBinding, membership,
// message and link records before opening an envelope. The untrusted envelope
// header is never an authorization source by itself.
type EndpointMessageContext struct {
	MessageID                  string `json:"message_id"`
	Kind                       string `json:"kind"`
	RequestID                  string `json:"request_id,omitempty"`
	ReplyTo                    string `json:"reply_to,omitempty"`
	ParentRequestID            string `json:"parent_request_id,omitempty"`
	SenderEndpointID           string `json:"sender_endpoint_id"`
	SenderPrincipalID          string `json:"sender_principal_id"`
	SenderOwnerID              string `json:"sender_owner_id"`
	SenderGroupID              string `json:"sender_group_id"`
	SenderMembershipRevision   int64  `json:"sender_membership_revision"`
	SenderBindingEpoch         uint64 `json:"sender_binding_epoch"`
	SenderKeyID                string `json:"sender_key_id"`
	ReceiverEndpointID         string `json:"receiver_endpoint_id"`
	ReceiverPrincipalID        string `json:"receiver_principal_id"`
	ReceiverOwnerID            string `json:"receiver_owner_id"`
	ReceiverGroupID            string `json:"receiver_group_id"`
	ReceiverMembershipRevision int64  `json:"receiver_membership_revision"`
	ReceiverBindingEpoch       uint64 `json:"receiver_binding_epoch"`
	ReceiverKeyID              string `json:"receiver_key_id"`
	LinkID                     string `json:"link_id,omitempty"`
	LinkRevision               int64  `json:"link_revision,omitempty"`
	TransportHubID             string `json:"transport_hub_id,omitempty"`
}

type EndpointMessageEnvelope struct {
	Version   int                    `json:"version"`
	Suite     string                 `json:"suite"`
	Context   EndpointMessageContext `json:"context"`
	Sealed    json.RawMessage        `json:"sealed"`
	Signature []byte                 `json:"signature"`
}

func (context EndpointMessageContext) validate() error {
	for _, value := range []string{context.MessageID, context.SenderEndpointID,
		context.SenderPrincipalID, context.SenderOwnerID, context.SenderGroupID,
		context.SenderKeyID, context.ReceiverEndpointID, context.ReceiverPrincipalID,
		context.ReceiverOwnerID, context.ReceiverGroupID, context.ReceiverKeyID} {
		if !canonicalEndpointToken(value, true) {
			return errors.New("endpoint envelope requires bounded canonical identities")
		}
	}
	for _, value := range []string{context.RequestID, context.ReplyTo, context.ParentRequestID, context.LinkID, context.TransportHubID} {
		if !canonicalEndpointToken(value, false) {
			return errors.New("endpoint envelope has invalid optional identity")
		}
	}
	if context.SenderEndpointID == context.ReceiverEndpointID ||
		context.SenderMembershipRevision <= 0 || context.ReceiverMembershipRevision <= 0 ||
		context.SenderBindingEpoch == 0 || context.ReceiverBindingEpoch == 0 ||
		(context.LinkID == "") != (context.LinkRevision == 0) || context.LinkRevision < 0 {
		return errors.New("endpoint envelope has invalid binding or link scope")
	}
	switch context.Kind {
	case "SEND":
		if context.RequestID != "" || context.ReplyTo != "" || context.ParentRequestID != "" {
			return errors.New("SEND cannot carry request correlation")
		}
	case "REQUEST":
		if context.RequestID == "" || context.ReplyTo != "" {
			return errors.New("REQUEST requires one request id")
		}
	case "REPLY":
		if context.RequestID == "" || context.ReplyTo == "" {
			return errors.New("REPLY requires request and parent message ids")
		}
	default:
		return errors.New("unsupported endpoint envelope kind")
	}
	return nil
}

func canonicalEndpointToken(value string, required bool) bool {
	if value == "" {
		return !required
	}
	if len(value) > 256 || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, "/\\") || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func endpointAAD(context EndpointMessageContext) ([]byte, error) {
	if err := context.validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(context)
	if err != nil {
		return nil, err
	}
	return append([]byte(endpointAADDomain), encoded...), nil
}

// SealEndpointMessage builds a self-describing ciphertext for one pinned
// Endpoint recipient. The caller must persist the returned exact bytes and
// sequence before transport, then reuse them on retry rather than resealing.
func SealEndpointMessage(sender *Identity, recipient PublicIdentity, context EndpointMessageContext, plaintext []byte, sequence uint64) ([]byte, error) {
	if sender == nil || sequence == 0 || len(plaintext) == 0 || len(plaintext) > maxEndpointPlaintext {
		return nil, errors.New("invalid endpoint message sender, sequence or size")
	}
	if context.SenderKeyID != sender.Public().ID || context.ReceiverKeyID != recipient.ID {
		return nil, errors.New("endpoint context key identity mismatch")
	}
	aad, err := endpointAAD(context)
	if err != nil {
		return nil, err
	}
	sealed, err := Seal(sender, recipient, plaintext, aad, sequence)
	if err != nil {
		return nil, err
	}
	envelope := EndpointMessageEnvelope{Version: EndpointEnvelopeVersion,
		Suite: EndpointEnvelopeSuite, Context: context, Sealed: json.RawMessage(sealed)}
	unsigned, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	envelope.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sender.signingPrivate, unsigned, nil, true, envelope.Signature); err != nil {
		return nil, fmt.Errorf("sign Endpoint route and ciphertext: %w", err)
	}
	wire, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if len(wire) > maxEndpointWire {
		return nil, ErrInvalidEnvelope
	}
	return wire, nil
}

// OpenEndpointMessage checks an expected trusted route and pinned public key
// before decrypting. The returned sequence still needs an atomic, durable
// replay check in the receiving Node's inbox transaction.
func OpenEndpointMessage(recipient *Identity, expectedSender PublicIdentity, expected EndpointMessageContext, data []byte) ([]byte, uint64, error) {
	if len(data) == 0 || len(data) > maxEndpointWire {
		return nil, 0, ErrInvalidEnvelope
	}
	if recipient == nil || expected.SenderKeyID != expectedSender.ID ||
		expected.ReceiverKeyID != recipient.Public().ID {
		return nil, 0, errors.New("endpoint expected key identity mismatch")
	}
	if err := expected.validate(); err != nil {
		return nil, 0, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope EndpointMessageEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, 0, fmt.Errorf("decode endpoint envelope: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, 0, errors.New("endpoint envelope has trailing data")
	}
	if envelope.Version != EndpointEnvelopeVersion || envelope.Suite != EndpointEnvelopeSuite ||
		envelope.Context != expected || len(envelope.Sealed) == 0 ||
		len(envelope.Signature) != mldsa65.SignatureSize {
		return nil, 0, ErrInvalidEnvelope
	}
	_, senderKey, err := validatePublic(expectedSender)
	if err != nil {
		return nil, 0, err
	}
	signature := envelope.Signature
	envelope.Signature = nil
	unsigned, err := json.Marshal(envelope)
	if err != nil || !mldsa65.Verify(senderKey, unsigned, nil, signature) {
		return nil, 0, errors.New("Endpoint route signature verification failed")
	}
	aad, err := endpointAAD(expected)
	if err != nil {
		return nil, 0, err
	}
	plaintext, sequence, err := Open(recipient, expectedSender, envelope.Sealed, aad)
	if err != nil {
		return nil, 0, err
	}
	if len(plaintext) == 0 || len(plaintext) > maxEndpointPlaintext || sequence == 0 {
		return nil, 0, ErrInvalidEnvelope
	}
	return plaintext, sequence, nil
}
