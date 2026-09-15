// Package e2ee implements Cicada's post-quantum authenticated message
// envelope. The package deliberately delegates the cryptographic primitives
// to Cloudflare CIRCL's FIPS 203 ML-KEM-768 and FIPS 204 ML-DSA-65
// implementations. It owns only the wire framing, key derivation, replay
// checks, and AES-GCM message protection needed by the Peer Link transport.
package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	ProtocolVersion = 1
	Algorithm       = "ML-KEM-768+ML-DSA-65/AES-256-GCM"
	maxReplayIDs    = 4096
)

var (
	ErrInvalidEnvelope = errors.New("invalid E2EE envelope")
	ErrReplay          = errors.New("E2EE envelope replayed")
	ErrWrongSender     = errors.New("E2EE envelope sender does not match contact")
)

// PublicIdentity is safe to publish to a contact directory. Public keys are
// encoded by encoding/json as base64 strings on the wire.
type PublicIdentity struct {
	ID            string `json:"id"`
	KEMPublic     []byte `json:"kem_public"`
	SigningPublic []byte `json:"signing_public"`
}

// Identity contains the private ML-KEM and ML-DSA keys for one Cicada peer.
// Keep MarshalBinary's result in a permissions-protected secret store.
type Identity struct {
	kemPrivate     *mlkem768.PrivateKey
	signingPrivate *mldsa65.PrivateKey
	public         PublicIdentity
}

type identityDisk struct {
	Version        int    `json:"version"`
	KEMPrivate     []byte `json:"kem_private"`
	SigningPrivate []byte `json:"signing_private"`
}

// Envelope is the authenticated, encrypted transport object. The sender's
// signing public key is included so a relay can forward an opaque message;
// Open still requires the expected contact identity to prevent key swapping.
type Envelope struct {
	Version             int    `json:"version"`
	Algorithm           string `json:"algorithm"`
	Sequence            uint64 `json:"sequence"`
	KEMCiphertext       []byte `json:"kem_ciphertext"`
	Nonce               []byte `json:"nonce"`
	Ciphertext          []byte `json:"ciphertext"`
	SenderID            string `json:"sender_id"`
	SenderSigningPublic []byte `json:"sender_signing_public"`
	Signature           []byte `json:"signature"`
}

type envelopeHeader struct {
	Version             int    `json:"version"`
	Algorithm           string `json:"algorithm"`
	Sequence            uint64 `json:"sequence"`
	KEMCiphertext       []byte `json:"kem_ciphertext"`
	Nonce               []byte `json:"nonce"`
	SenderID            string `json:"sender_id"`
	SenderSigningPublic []byte `json:"sender_signing_public"`
}

// ReplayGuard rejects duplicate sequence numbers while allowing bounded
// out-of-order delivery, which is required for an offline queue transport.
type ReplayGuard struct {
	mu   sync.Mutex
	seen map[uint64]struct{}
}

func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{seen: make(map[uint64]struct{}, maxReplayIDs)}
}

func (g *ReplayGuard) accept(sequence uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.seen[sequence]; exists {
		return ErrReplay
	}
	if len(g.seen) >= maxReplayIDs {
		// The oldest value is not semantically important to the protocol. The
		// bounded set prevents an offline peer from exhausting memory.
		for oldest := range g.seen {
			delete(g.seen, oldest)
			break
		}
	}
	g.seen[sequence] = struct{}{}
	return nil
}

// NewIdentity creates a new contact identity using cryptographically secure
// randomness from crypto/rand.
func NewIdentity() (*Identity, error) {
	kemPublic, kemPrivate, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ML-KEM key: %w", err)
	}
	signingPublic, signingPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ML-DSA key: %w", err)
	}
	return identityFromKeys(kemPublic, kemPrivate, signingPublic, signingPrivate)
}

func identityFromKeys(kemPublic *mlkem768.PublicKey, kemPrivate *mlkem768.PrivateKey, signingPublic *mldsa65.PublicKey, signingPrivate *mldsa65.PrivateKey) (*Identity, error) {
	kemBytes, err := kemPublic.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ML-KEM public key: %w", err)
	}
	signingBytes, err := signingPublic.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ML-DSA public key: %w", err)
	}
	return &Identity{
		kemPrivate:     kemPrivate,
		signingPrivate: signingPrivate,
		public: PublicIdentity{
			ID:            identityID(kemBytes, signingBytes),
			KEMPublic:     append([]byte(nil), kemBytes...),
			SigningPublic: append([]byte(nil), signingBytes...),
		},
	}, nil
}

func identityID(kemPublic, signingPublic []byte) string {
	hash := sha256.New()
	_, _ = hash.Write(kemPublic)
	_, _ = hash.Write(signingPublic)
	sum := hash.Sum(nil)
	return "pq1-" + hex.EncodeToString(sum[:16])
}

func (identity *Identity) Public() PublicIdentity {
	if identity == nil {
		return PublicIdentity{}
	}
	return PublicIdentity{
		ID:            identity.public.ID,
		KEMPublic:     append([]byte(nil), identity.public.KEMPublic...),
		SigningPublic: append([]byte(nil), identity.public.SigningPublic...),
	}
}

// MarshalBinary serializes only the private identity. Callers must store its
// result as a secret and never place it in an event, log, or relay payload.
func (identity *Identity) MarshalBinary() ([]byte, error) {
	if identity == nil || identity.kemPrivate == nil || identity.signingPrivate == nil {
		return nil, errors.New("nil E2EE identity")
	}
	kemPrivate, err := identity.kemPrivate.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ML-KEM private key: %w", err)
	}
	signingPrivate, err := identity.signingPrivate.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ML-DSA private key: %w", err)
	}
	return json.Marshal(identityDisk{Version: ProtocolVersion, KEMPrivate: kemPrivate, SigningPrivate: signingPrivate})
}

// UnmarshalIdentity restores a private identity and verifies its public ID.
func UnmarshalIdentity(data []byte) (*Identity, error) {
	var disk identityDisk
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, fmt.Errorf("decode E2EE identity: %w", err)
	}
	if disk.Version != ProtocolVersion {
		return nil, fmt.Errorf("unsupported E2EE identity version: %d", disk.Version)
	}
	if len(disk.KEMPrivate) != mlkem768.PrivateKeySize {
		return nil, fmt.Errorf("decode ML-KEM private key: invalid length %d", len(disk.KEMPrivate))
	}
	kemPrivate := new(mlkem768.PrivateKey)
	kemPrivate.Unpack(disk.KEMPrivate)
	signingPrivate := new(mldsa65.PrivateKey)
	if err := signingPrivate.UnmarshalBinary(disk.SigningPrivate); err != nil {
		return nil, fmt.Errorf("decode ML-DSA private key: %w", err)
	}
	kemPublic, ok := kemPrivate.Public().(*mlkem768.PublicKey)
	if !ok {
		return nil, errors.New("ML-KEM private key returned an unexpected public key")
	}
	signingPublic, ok := signingPrivate.Public().(*mldsa65.PublicKey)
	if !ok {
		return nil, errors.New("ML-DSA private key returned an unexpected public key")
	}
	return identityFromKeys(kemPublic, kemPrivate, signingPublic, signingPrivate)
}

func validatePublic(public PublicIdentity) (*mlkem768.PublicKey, *mldsa65.PublicKey, error) {
	if public.ID == "" || len(public.KEMPublic) != mlkem768.PublicKeySize || len(public.SigningPublic) != mldsa65.PublicKeySize {
		return nil, nil, ErrInvalidEnvelope
	}
	if identityID(public.KEMPublic, public.SigningPublic) != public.ID {
		return nil, nil, ErrInvalidEnvelope
	}
	kemPublic := new(mlkem768.PublicKey)
	kemPublic.Unpack(public.KEMPublic)
	signingPublic := new(mldsa65.PublicKey)
	if err := signingPublic.UnmarshalBinary(public.SigningPublic); err != nil {
		return nil, nil, fmt.Errorf("decode contact ML-DSA key: %w", err)
	}
	return kemPublic, signingPublic, nil
}

// ValidatePublicIdentity checks key sizes and the self-derived stable ID
// before a contact is trusted or persisted.
func ValidatePublicIdentity(public PublicIdentity) error {
	_, _, err := validatePublic(public)
	return err
}

// Seal encrypts one message for recipient. sequence must be unique for the
// sender/contact direction; callers should persist the counter durably.
func Seal(sender *Identity, recipient PublicIdentity, message, aad []byte, sequence uint64) ([]byte, error) {
	if sender == nil || sender.signingPrivate == nil {
		return nil, errors.New("nil sender identity")
	}
	kemPublic, _, err := validatePublic(recipient)
	if err != nil {
		return nil, fmt.Errorf("validate recipient identity: %w", err)
	}
	kemCiphertext := make([]byte, mlkem768.CiphertextSize)
	sharedSecret := make([]byte, mlkem768.SharedKeySize)
	kemPublic.EncapsulateTo(kemCiphertext, sharedSecret, nil)
	key, err := deriveKey(sharedSecret, aad, sequence)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES-256 cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate AES-GCM nonce: %w", err)
	}
	header := envelopeHeader{
		Version: ProtocolVersion, Algorithm: Algorithm, Sequence: sequence,
		KEMCiphertext: kemCiphertext, Nonce: nonce, SenderID: sender.public.ID,
		SenderSigningPublic: sender.public.SigningPublic,
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("encode E2EE header: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, message, append(append([]byte(nil), aad...), headerBytes...))
	unsigned := Envelope{
		Version: header.Version, Algorithm: header.Algorithm, Sequence: header.Sequence,
		KEMCiphertext: kemCiphertext, Nonce: nonce, Ciphertext: ciphertext,
		SenderID: header.SenderID, SenderSigningPublic: header.SenderSigningPublic,
	}
	unsignedBytes, err := json.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("encode E2EE envelope: %w", err)
	}
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sender.signingPrivate, unsignedBytes, nil, true, signature); err != nil {
		return nil, fmt.Errorf("sign E2EE envelope: %w", err)
	}
	unsigned.Signature = signature
	return json.Marshal(unsigned)
}

// Open authenticates and decrypts an envelope. expectedSender is mandatory so
// a relay cannot replace a contact's public key in the message itself.
func Open(recipient *Identity, expectedSender PublicIdentity, data, aad []byte) ([]byte, uint64, error) {
	return open(recipient, expectedSender, data, aad, nil)
}

// OpenWithReplayGuard additionally rejects duplicate sequence numbers.
func OpenWithReplayGuard(recipient *Identity, expectedSender PublicIdentity, data, aad []byte, guard *ReplayGuard) ([]byte, uint64, error) {
	return open(recipient, expectedSender, data, aad, guard)
}

func open(recipient *Identity, expectedSender PublicIdentity, data, aad []byte, guard *ReplayGuard) ([]byte, uint64, error) {
	if recipient == nil || recipient.kemPrivate == nil {
		return nil, 0, errors.New("nil recipient identity")
	}
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, 0, fmt.Errorf("decode E2EE envelope: %w", err)
	}
	if envelope.Version != ProtocolVersion || envelope.Algorithm != Algorithm || len(envelope.Nonce) != 12 || len(envelope.Signature) != mldsa65.SignatureSize {
		return nil, 0, ErrInvalidEnvelope
	}
	if expectedSender.ID != envelope.SenderID || string(expectedSender.SigningPublic) != string(envelope.SenderSigningPublic) {
		return nil, 0, ErrWrongSender
	}
	_, signingPublic, err := validatePublic(expectedSender)
	if err != nil {
		return nil, 0, fmt.Errorf("validate sender identity: %w", err)
	}
	unsigned := envelope
	unsigned.Signature = nil
	unsignedBytes, err := json.Marshal(unsigned)
	if err != nil {
		return nil, 0, fmt.Errorf("encode signed E2EE envelope: %w", err)
	}
	if !mldsa65.Verify(signingPublic, unsignedBytes, nil, envelope.Signature) {
		return nil, 0, errors.New("E2EE envelope signature verification failed")
	}
	if len(envelope.KEMCiphertext) != mlkem768.CiphertextSize {
		return nil, 0, ErrInvalidEnvelope
	}
	sharedSecret := make([]byte, mlkem768.SharedKeySize)
	recipient.kemPrivate.DecapsulateTo(sharedSecret, envelope.KEMCiphertext)
	key, err := deriveKey(sharedSecret, aad, envelope.Sequence)
	if err != nil {
		return nil, 0, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, fmt.Errorf("create AES-256 cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, fmt.Errorf("create AES-GCM: %w", err)
	}
	header := envelopeHeader{
		Version: envelope.Version, Algorithm: envelope.Algorithm, Sequence: envelope.Sequence,
		KEMCiphertext: envelope.KEMCiphertext, Nonce: envelope.Nonce, SenderID: envelope.SenderID,
		SenderSigningPublic: envelope.SenderSigningPublic,
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, 0, fmt.Errorf("encode E2EE header: %w", err)
	}
	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, append(append([]byte(nil), aad...), headerBytes...))
	if err != nil {
		return nil, 0, errors.New("E2EE ciphertext authentication failed")
	}
	if guard != nil {
		if err := guard.accept(envelope.Sequence); err != nil {
			return nil, 0, err
		}
	}
	return plaintext, envelope.Sequence, nil
}

func deriveKey(sharedSecret, aad []byte, sequence uint64) ([]byte, error) {
	var sequenceBytes [8]byte
	binary.BigEndian.PutUint64(sequenceBytes[:], sequence)
	info := append([]byte("cicada/e2ee/v1/key"), sequenceBytes[:]...)
	info = append(info, aad...)
	return hkdfSHA256(sharedSecret, nil, info, 32), nil
}

// hkdfSHA256 is RFC 5869's extract-and-expand construction. Keeping this tiny
// implementation local avoids adding a second crypto dependency to the Go
// 1.22 build while retaining the standard, reviewed construction.
func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)
	result := make([]byte, 0, length)
	previous := []byte{}
	for counter := byte(1); len(result) < length; counter++ {
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(previous)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		result = append(result, previous...)
	}
	return result[:length]
}
