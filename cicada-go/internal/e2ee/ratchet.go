package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const maxRatchetSkip = 1024

// RatchetState is durable state for one direction of a peer session. RootKey
// and chain keys are secrets and must only be persisted in protected state.
type RatchetState struct {
	Epoch           uint64
	RootKey         []byte `json:"-"`
	SendChainKey    []byte `json:"-"`
	ReceiveChainKey []byte `json:"-"`
	SendCount       uint64
	ReceiveCount    uint64
	LocalID         string
	RemoteID        string
}

type SessionOffer struct {
	Version             int    `json:"version"`
	Epoch               uint64 `json:"epoch"`
	SenderID            string `json:"sender_id"`
	RecipientID         string `json:"recipient_id"`
	KEMCiphertext       []byte `json:"kem_ciphertext"`
	SenderSigningPublic []byte `json:"sender_signing_public"`
	Signature           []byte `json:"signature"`
}

// NewSessionOffer creates a signed, one-time ML-KEM session bootstrap. The
// returned root remains private to the caller; the recipient derives it after
// authenticating and decapsulating the offer.
func NewSessionOffer(sender *Identity, recipient PublicIdentity, epoch uint64) (offer, root []byte, err error) {
	if sender == nil || sender.signingPrivate == nil {
		return nil, nil, errors.New("nil session sender identity")
	}
	if epoch == 0 {
		return nil, nil, errors.New("session epoch must be positive")
	}
	kemPublic, _, err := validatePublic(recipient)
	if err != nil {
		return nil, nil, fmt.Errorf("validate session recipient: %w", err)
	}
	ciphertext := make([]byte, mlkem768.CiphertextSize)
	shared := make([]byte, mlkem768.SharedKeySize)
	kemPublic.EncapsulateTo(ciphertext, shared, nil)
	root = sessionRoot(shared, sender.public.ID, recipient.ID, epoch)
	unsigned := SessionOffer{Version: ProtocolVersion, Epoch: epoch, SenderID: sender.public.ID,
		RecipientID: recipient.ID, KEMCiphertext: ciphertext, SenderSigningPublic: sender.public.SigningPublic}
	data, err := json.Marshal(unsigned)
	if err != nil {
		return nil, nil, err
	}
	unsigned.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sender.signingPrivate, data, nil, true, unsigned.Signature); err != nil {
		return nil, nil, fmt.Errorf("sign session offer: %w", err)
	}
	offer, err = json.Marshal(unsigned)
	return offer, root, err
}

// AcceptSessionOffer authenticates a bootstrap and derives the shared root.
func AcceptSessionOffer(recipient *Identity, expectedSender PublicIdentity, data []byte) (uint64, []byte, error) {
	if recipient == nil || recipient.kemPrivate == nil {
		return 0, nil, errors.New("nil session recipient identity")
	}
	var offer SessionOffer
	if err := json.Unmarshal(data, &offer); err != nil {
		return 0, nil, fmt.Errorf("decode session offer: %w", err)
	}
	if offer.Version != ProtocolVersion || offer.Epoch == 0 || offer.RecipientID != recipient.public.ID || offer.SenderID != expectedSender.ID || len(offer.KEMCiphertext) != mlkem768.CiphertextSize || len(offer.Signature) != mldsa65.SignatureSize || string(offer.SenderSigningPublic) != string(expectedSender.SigningPublic) {
		return 0, nil, ErrInvalidEnvelope
	}
	_, signingPublic, err := validatePublic(expectedSender)
	if err != nil {
		return 0, nil, err
	}
	signature := offer.Signature
	offer.Signature = nil
	unsigned, err := json.Marshal(offer)
	if err != nil || !mldsa65.Verify(signingPublic, unsigned, nil, signature) {
		return 0, nil, errors.New("session offer signature verification failed")
	}
	shared := make([]byte, mlkem768.SharedKeySize)
	recipient.kemPrivate.DecapsulateTo(shared, offer.KEMCiphertext)
	return offer.Epoch, sessionRoot(shared, expectedSender.ID, recipient.public.ID, offer.Epoch), nil
}

// NewRatchetState initializes directional chains from a shared session root.
func NewRatchetState(epoch uint64, root []byte, localID, remoteID string) (*RatchetState, error) {
	if epoch == 0 || len(root) < 32 || strings.TrimSpace(localID) == "" || strings.TrimSpace(remoteID) == "" {
		return nil, errors.New("invalid ratchet state")
	}
	state := &RatchetState{Epoch: epoch, RootKey: append([]byte(nil), root...), LocalID: localID, RemoteID: remoteID}
	state.SendChainKey = chainKey(root, localID, remoteID)
	state.ReceiveChainKey = chainKey(root, remoteID, localID)
	return state, nil
}

func (state *RatchetState) NextSend() (uint64, []byte, error) {
	if state == nil || len(state.SendChainKey) == 0 {
		return 0, nil, errors.New("ratchet send chain is unavailable")
	}
	if state.SendCount == ^uint64(0) {
		return 0, nil, errors.New("ratchet send counter exhausted; rotate session")
	}
	state.SendCount++
	key := hmacBytes(state.SendChainKey, []byte("message"))
	state.SendChainKey = hmacBytes(state.SendChainKey, []byte("next"))
	return state.SendCount, key, nil
}

func (state *RatchetState) NextReceive(counter uint64) ([]byte, error) {
	if state == nil || len(state.ReceiveChainKey) == 0 {
		return nil, errors.New("ratchet receive chain is unavailable")
	}
	if counter <= state.ReceiveCount {
		return nil, ErrReplay
	}
	if counter-state.ReceiveCount > maxRatchetSkip {
		return nil, errors.New("ratchet message skipped too far")
	}
	var key []byte
	for state.ReceiveCount < counter {
		state.ReceiveCount++
		key = hmacBytes(state.ReceiveChainKey, []byte("message"))
		state.ReceiveChainKey = hmacBytes(state.ReceiveChainKey, []byte("next"))
	}
	return key, nil
}

// SealRatchet encrypts with the next directional chain key. offer is included
// only on the first message after a rotation.
func SealRatchet(sender *Identity, recipient PublicIdentity, state *RatchetState, sequence uint64, offer []byte, message, aad []byte) ([]byte, error) {
	if sender == nil || sender.signingPrivate == nil || state == nil || state.LocalID != sender.public.ID || state.RemoteID != recipient.ID {
		return nil, errors.New("invalid ratchet sender state")
	}
	counter, key, err := state.NextSend()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	envelope := Envelope{Version: ProtocolVersion, Algorithm: Algorithm, Sequence: sequence, SenderID: sender.public.ID,
		SenderSigningPublic: sender.public.SigningPublic, Nonce: nonce, SessionEpoch: state.Epoch,
		SessionCounter: counter, SessionOffer: append([]byte(nil), offer...)}
	header, err := ratchetHeader(envelope)
	if err != nil {
		return nil, err
	}
	derived := hkdfSHA256(key, nil, append([]byte("cicada/e2ee/v1/ratchet"), aad...), 32)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	envelope.Ciphertext = gcm.Seal(nil, nonce, message, append(append([]byte(nil), aad...), header...))
	unsigned := envelope
	unsigned.Signature = nil
	data, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	envelope.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sender.signingPrivate, data, nil, true, envelope.Signature); err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

// OpenRatchet verifies, decrypts, and advances a receive chain. A nil state
// is bootstrapped from the signed offer embedded in the first message.
func OpenRatchet(recipient *Identity, expectedSender PublicIdentity, data, aad []byte, state *RatchetState) ([]byte, *RatchetState, error) {
	if recipient == nil {
		return nil, nil, errors.New("nil ratchet recipient identity")
	}
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, nil, err
	}
	if envelope.Version != ProtocolVersion || envelope.Algorithm != Algorithm || envelope.Sequence == 0 || envelope.SessionEpoch == 0 || envelope.SessionCounter == 0 || len(envelope.Nonce) != 12 || len(envelope.Signature) != mldsa65.SignatureSize || envelope.SenderID != expectedSender.ID || string(envelope.SenderSigningPublic) != string(expectedSender.SigningPublic) {
		return nil, nil, ErrInvalidEnvelope
	}
	_, signingPublic, err := validatePublic(expectedSender)
	if err != nil {
		return nil, nil, err
	}
	signature := envelope.Signature
	unsigned := envelope
	unsigned.Signature = nil
	unsignedBytes, err := json.Marshal(unsigned)
	if err != nil || !mldsa65.Verify(signingPublic, unsignedBytes, nil, signature) {
		return nil, nil, errors.New("ratchet envelope signature verification failed")
	}
	if state == nil {
		if len(envelope.SessionOffer) == 0 {
			return nil, nil, errors.New("ratchet session offer is required")
		}
		epoch, root, offerErr := AcceptSessionOffer(recipient, expectedSender, envelope.SessionOffer)
		if offerErr != nil || epoch != envelope.SessionEpoch {
			return nil, nil, ErrInvalidEnvelope
		}
		state, err = NewRatchetState(epoch, root, recipient.public.ID, expectedSender.ID)
		if err != nil {
			return nil, nil, err
		}
	} else if len(envelope.SessionOffer) != 0 && envelope.SessionEpoch > state.Epoch {
		epoch, root, offerErr := AcceptSessionOffer(recipient, expectedSender, envelope.SessionOffer)
		if offerErr != nil || epoch != envelope.SessionEpoch {
			return nil, nil, ErrInvalidEnvelope
		}
		state, err = NewRatchetState(epoch, root, recipient.public.ID, expectedSender.ID)
		if err != nil {
			return nil, nil, err
		}
	} else if len(envelope.SessionOffer) != 0 && envelope.SessionEpoch == state.Epoch && state.ReceiveCount != 0 {
		return nil, nil, ErrReplay
	} else if state.Epoch != envelope.SessionEpoch {
		return nil, nil, errors.New("ratchet session epoch mismatch")
	}
	key, err := state.NextReceive(envelope.SessionCounter)
	if err != nil {
		return nil, nil, err
	}
	header, err := ratchetHeader(envelope)
	if err != nil {
		return nil, nil, err
	}
	derived := hkdfSHA256(key, nil, append([]byte("cicada/e2ee/v1/ratchet"), aad...), 32)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, append(append([]byte(nil), aad...), header...))
	if err != nil {
		return nil, nil, errors.New("ratchet ciphertext authentication failed")
	}
	return plaintext, state, nil
}

type ratchetEnvelopeHeader struct {
	Version             int    `json:"version"`
	Algorithm           string `json:"algorithm"`
	SenderID            string `json:"sender_id"`
	SenderSigningPublic []byte `json:"sender_signing_public"`
	Nonce               []byte `json:"nonce"`
	SessionEpoch        uint64 `json:"session_epoch"`
	SessionCounter      uint64 `json:"session_counter"`
	SessionOffer        []byte `json:"session_offer,omitempty"`
}

func ratchetHeader(envelope Envelope) ([]byte, error) {
	return json.Marshal(ratchetEnvelopeHeader{Version: envelope.Version, Algorithm: envelope.Algorithm,
		SenderID: envelope.SenderID, SenderSigningPublic: envelope.SenderSigningPublic, Nonce: envelope.Nonce,
		SessionEpoch: envelope.SessionEpoch, SessionCounter: envelope.SessionCounter, SessionOffer: envelope.SessionOffer})
}

func sessionRoot(shared []byte, senderID, recipientID string, epoch uint64) []byte {
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], epoch)
	info := append([]byte("cicada/e2ee/v1/session-root"), number[:]...)
	info = append(info, []byte(senderID)...)
	info = append(info, []byte(recipientID)...)
	return hkdfSHA256(shared, nil, info, 32)
}

func chainKey(root []byte, senderID, recipientID string) []byte {
	info := append([]byte("cicada/e2ee/v1/chain"), []byte(senderID+"\x00"+recipientID)...)
	return hkdfSHA256(root, nil, info, 32)
}

func hmacBytes(key, value []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(value)
	return mac.Sum(nil)
}
