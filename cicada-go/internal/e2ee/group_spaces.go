package e2ee

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	GroupSpaceEnvelopeVersion = 1
	GroupSpaceMaxBody         = 16 * 1024
	groupSpaceAADDomain       = "cicada/group-space/reader/v1\x00"
	groupSpaceBodyDomain      = "cicada/group-space/body/v1\x00"
	groupSpaceOuterDomain     = "cicada/group-space/outer/v1\x00"
)

// GroupSpaceContext is fixed by a Hub reservation and checked against that
// reservation by every reader. HistoryGrantID is empty for original readers.
type GroupSpaceContext struct {
	HubID              string `json:"hub_id"`
	NetworkID          string `json:"network_id"`
	GroupID            string `json:"group_id"`
	RecordID           string `json:"record_id"`
	Sequence           int64  `json:"sequence"`
	Kind               string `json:"kind"`
	TopicID            string `json:"topic_id,omitempty"`
	CorrectsID         string `json:"corrects_id,omitempty"`
	Status             string `json:"status,omitempty"`
	SnapshotDigest     string `json:"snapshot_digest"`
	ProducerEndpointID string `json:"producer_endpoint_id"`
	ProducerKeyID      string `json:"producer_key_id"`
	ReaderEndpointID   string `json:"reader_endpoint_id"`
	ReaderKeyID        string `json:"reader_key_id"`
	HistoryGrantID     string `json:"history_grant_id,omitempty"`
	ReservedAt         string `json:"reserved_at"`
	ExpiresAt          string `json:"expires_at"`
}

func (c GroupSpaceContext) validate() error {
	for _, value := range []string{c.HubID, c.NetworkID, c.GroupID, c.RecordID,
		c.SnapshotDigest, c.ProducerEndpointID, c.ProducerKeyID,
		c.ReaderEndpointID, c.ReaderKeyID, c.ReservedAt, c.ExpiresAt} {
		if !canonicalEndpointToken(value, true) {
			return ErrInvalidEnvelope
		}
	}
	for _, value := range []string{c.TopicID, c.CorrectsID, c.Status, c.HistoryGrantID} {
		if !canonicalEndpointToken(value, false) {
			return ErrInvalidEnvelope
		}
	}
	if c.Sequence <= 0 {
		return ErrInvalidEnvelope
	}
	switch c.Kind {
	case "JOURNAL", "TOPIC", "REPLY", "TOPIC_STATUS":
	default:
		return ErrInvalidEnvelope
	}
	return nil
}

// GroupSpaceSignedBody preserves the original producer's signature when an
// independently authorized reader receives a later history envelope.
type GroupSpaceSignedBody struct {
	Version   int               `json:"version"`
	Context   GroupSpaceContext `json:"context"`
	Plaintext []byte            `json:"plaintext"`
	Signature []byte            `json:"signature"`
}

// GroupSpaceReaderEnvelope is one recipient's independent ML-KEM/AES-GCM
// envelope. The outer signature binds AAD metadata that the Hub can verify
// without seeing the plaintext.
type GroupSpaceReaderEnvelope struct {
	Version   int               `json:"version"`
	Suite     string            `json:"suite"`
	Context   GroupSpaceContext `json:"context"`
	Sealed    json.RawMessage   `json:"sealed"`
	Signature []byte            `json:"signature"`
}

func groupSpaceBodyContext(c GroupSpaceContext) GroupSpaceContext {
	c.ReaderEndpointID = ""
	c.ReaderKeyID = ""
	c.HistoryGrantID = ""
	return c
}

func groupSpaceSignedBytes(domain string, value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), encoded...), nil
}

func newGroupSpaceSignedBody(sender *Identity, context GroupSpaceContext, plaintext []byte) ([]byte, error) {
	if sender == nil || sender.signingPrivate == nil || len(plaintext) == 0 || len(plaintext) > GroupSpaceMaxBody ||
		context.ProducerKeyID != sender.Public().ID {
		return nil, ErrInvalidEnvelope
	}
	body := GroupSpaceSignedBody{Version: GroupSpaceEnvelopeVersion,
		Context: groupSpaceBodyContext(context), Plaintext: append([]byte(nil), plaintext...)}
	unsigned, err := groupSpaceSignedBytes(groupSpaceBodyDomain, body)
	if err != nil {
		return nil, err
	}
	body.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sender.signingPrivate, unsigned, nil, true, body.Signature); err != nil {
		return nil, err
	}
	return json.Marshal(body)
}

// SignGroupSpaceBody returns the exact inner bytes to reuse for every original
// reader. It is also the only plaintext-bearing object accepted for rewrap.
func SignGroupSpaceBody(sender *Identity, context GroupSpaceContext, plaintext []byte) ([]byte, error) {
	if err := context.validate(); err != nil {
		return nil, err
	}
	return newGroupSpaceSignedBody(sender, context, plaintext)
}

func VerifyGroupSpaceBody(expectedProducer PublicIdentity, context GroupSpaceContext, encoded []byte) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > GroupSpaceMaxBody+16*1024 {
		return nil, ErrInvalidEnvelope
	}
	var body GroupSpaceSignedBody
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return nil, err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidEnvelope
	}
	if body.Version != GroupSpaceEnvelopeVersion || body.Context != groupSpaceBodyContext(context) ||
		len(body.Plaintext) == 0 || len(body.Plaintext) > GroupSpaceMaxBody ||
		len(body.Signature) != mldsa65.SignatureSize || expectedProducer.ID != context.ProducerKeyID {
		return nil, ErrInvalidEnvelope
	}
	_, signing, err := validatePublic(expectedProducer)
	if err != nil {
		return nil, err
	}
	sig := body.Signature
	body.Signature = nil
	unsigned, err := groupSpaceSignedBytes(groupSpaceBodyDomain, body)
	if err != nil || !mldsa65.Verify(signing, unsigned, nil, sig) {
		return nil, errors.New("Group Space producer signature verification failed")
	}
	return append([]byte(nil), body.Plaintext...), nil
}

// SealGroupSpaceReader encrypts an already producer-signed body to one
// recipient. The signer is the producer for an original write or a current
// authorized holder for a separately granted history rewrap.
func SealGroupSpaceReader(signer *Identity, recipient PublicIdentity,
	context GroupSpaceContext, signedBody []byte, sequence uint64) ([]byte, error) {
	if signer == nil || sequence == 0 || context.ReaderKeyID != recipient.ID ||
		len(signedBody) == 0 || len(signedBody) > GroupSpaceMaxBody+16*1024 {
		return nil, ErrInvalidEnvelope
	}
	if err := context.validate(); err != nil {
		return nil, err
	}
	aad, err := groupSpaceSignedBytes(groupSpaceAADDomain, context)
	if err != nil {
		return nil, err
	}
	sealed, err := Seal(signer, recipient, signedBody, aad, sequence)
	if err != nil {
		return nil, err
	}
	outer := GroupSpaceReaderEnvelope{Version: GroupSpaceEnvelopeVersion,
		Suite: Algorithm, Context: context, Sealed: sealed}
	unsigned, err := groupSpaceSignedBytes(groupSpaceOuterDomain, outer)
	if err != nil {
		return nil, err
	}
	outer.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(signer.signingPrivate, unsigned, nil, true, outer.Signature); err != nil {
		return nil, err
	}
	return json.Marshal(outer)
}

// VerifyGroupSpaceReader authenticates public metadata and ciphertext at the
// Hub, without decrypting. expectedSigner must come from a trusted key grant.
func VerifyGroupSpaceReader(expectedSigner PublicIdentity, expected GroupSpaceContext, wire []byte) error {
	if len(wire) == 0 || len(wire) > 64*1024 || expected.validate() != nil {
		return ErrInvalidEnvelope
	}
	var outer GroupSpaceReaderEnvelope
	dec := json.NewDecoder(bytes.NewReader(wire))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&outer); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidEnvelope
	}
	if outer.Version != GroupSpaceEnvelopeVersion || outer.Suite != Algorithm ||
		outer.Context != expected || len(outer.Sealed) == 0 ||
		len(outer.Signature) != mldsa65.SignatureSize {
		return ErrInvalidEnvelope
	}
	_, key, err := validatePublic(expectedSigner)
	if err != nil {
		return err
	}
	sig := outer.Signature
	outer.Signature = nil
	unsigned, err := groupSpaceSignedBytes(groupSpaceOuterDomain, outer)
	if err != nil || !mldsa65.Verify(key, unsigned, nil, sig) {
		return errors.New("Group Space reader envelope signature verification failed")
	}
	var inner Envelope
	if err := json.Unmarshal(outer.Sealed, &inner); err != nil || inner.SenderID != expectedSigner.ID ||
		len(inner.Ciphertext) == 0 || len(inner.Ciphertext) > GroupSpaceMaxBody+20*1024 {
		return ErrInvalidEnvelope
	}
	return nil
}

// OpenGroupSpaceReader returns the verified producer-signed inner bytes and
// body. A later history rewrap may have a different outer signer.
func OpenGroupSpaceReader(reader *Identity, expectedSigner, expectedProducer PublicIdentity,
	expected GroupSpaceContext, wire []byte) ([]byte, []byte, error) {
	if reader == nil || reader.Public().ID != expected.ReaderKeyID {
		return nil, nil, ErrInvalidEnvelope
	}
	if err := VerifyGroupSpaceReader(expectedSigner, expected, wire); err != nil {
		return nil, nil, err
	}
	var outer GroupSpaceReaderEnvelope
	if err := json.Unmarshal(wire, &outer); err != nil {
		return nil, nil, err
	}
	aad, err := groupSpaceSignedBytes(groupSpaceAADDomain, expected)
	if err != nil {
		return nil, nil, err
	}
	signedBody, _, err := Open(reader, expectedSigner, outer.Sealed, aad)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := VerifyGroupSpaceBody(expectedProducer, expected, signedBody)
	if err != nil {
		return nil, nil, fmt.Errorf("verify Group Space body: %w", err)
	}
	return plaintext, signedBody, nil
}
