package appvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"sync"
)

const (
	passwordProtectorID = "PBKDF2-SHA256-600000-AES256GCM-v1"
	passwordIterations  = 600000
	passwordSaltBytes   = 32
	passwordNonceBytes  = 12
)

// PasswordProtector is a deterministic/test unlock backend. Production
// Windows uses the current-user DPAPI protector; this backend is not the
// Windows default. Create one per vault open and close it with the vault.
type PasswordProtector struct {
	mu         sync.Mutex
	passphrase []byte
	closed     bool
}

func NewPasswordProtector(passphrase []byte) (*PasswordProtector, error) {
	if len(passphrase) < 10 || len(passphrase) > 1024 {
		return nil, ErrInvalidVault
	}
	return &PasswordProtector{passphrase: append([]byte(nil), passphrase...)}, nil
}

func (p *PasswordProtector) ID() string { return passwordProtectorID }

func (p *PasswordProtector) WrapKey(context, key []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(key) != 32 || len(context) == 0 || len(context) > 2048 {
		return nil, ErrInvalidVault
	}
	salt := make([]byte, passwordSaltBytes)
	nonce := make([]byte, passwordNonceBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, ErrInvalidVault
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrInvalidVault
	}
	wrappingKey, err := p.deriveKey(salt)
	if err != nil {
		return nil, ErrInvalidVault
	}
	defer clear(wrappingKey)
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, ErrInvalidVault
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidVault
	}
	ciphertext := gcm.Seal(nil, nonce, key, context)
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	clear(ciphertext)
	return result, nil
}

func (p *PasswordProtector) UnwrapKey(context, wrapped []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(context) == 0 || len(context) > 2048 || len(wrapped) != passwordSaltBytes+passwordNonceBytes+32+16 {
		return nil, ErrInvalidVault
	}
	salt := wrapped[:passwordSaltBytes]
	nonce := wrapped[passwordSaltBytes : passwordSaltBytes+passwordNonceBytes]
	ciphertext := wrapped[passwordSaltBytes+passwordNonceBytes:]
	wrappingKey, err := p.deriveKey(salt)
	if err != nil {
		return nil, ErrInvalidVault
	}
	defer clear(wrappingKey)
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, ErrInvalidVault
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidVault
	}
	key, err := gcm.Open(nil, nonce, ciphertext, context)
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, ErrInvalidVault
	}
	return key, nil
}

// deriveKey consumes the supplied passphrase after the single create/open KDF
// operation. Go's standard-library PBKDF2 currently accepts a string, whose
// runtime copy cannot be reliably erased; the mutable source buffer is still
// cleared immediately.
func (p *PasswordProtector) deriveKey(salt []byte) ([]byte, error) {
	if len(p.passphrase) == 0 {
		return nil, ErrInvalidVault
	}
	passphrase := string(p.passphrase)
	clear(p.passphrase)
	p.passphrase = nil
	return pbkdf2.Key(sha256.New, passphrase, salt, passwordIterations, 32)
}

func (p *PasswordProtector) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	clear(p.passphrase)
	p.passphrase = nil
}

var _ Protector = (*PasswordProtector)(nil)
