package appvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/gofrs/flock"
)

const maxPreRegistrationPlainBytes = maxIdentityBytes + maxStateBytes + 18

var preRegistrationMagic = []byte("CICAPR01\x00")

// PreRegistrationScope binds an ordinary App identity before an account or
// Owner is known. Callers must first verify the Hub and retain a stable local
// installation ID; a file header is not a source of trusted Hub information.
// None of these public locator fields is a pairing secret or authorization.
type PreRegistrationScope struct {
	Origin         string
	HubID          string
	HubFingerprint string
	InstallationID string
}

// NewInstallationID mints a local installation identifier. Retain the same ID
// across restarts; making a new ID does not recover, replace or revoke a device.
func NewInstallationID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", ErrInvalidVault
	}
	return hexString(id[:]), nil
}

// PreRegistrationPath uses a separate namespace from account/Owner vaults.
// Public scope values are length-prefixed before hashing, never path segments.
func PreRegistrationPath(root string, scope PreRegistrationScope) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || validatePreRegistrationScope(scope) != nil {
		return "", ErrInvalidVault
	}
	context := preRegistrationContext(scope)
	sum := sha256.Sum256(context)
	return filepath.Join(root, "pre-registration", hexString(sum[:])+".pending"), nil
}

// PreRegistrationStore keeps one immutable, newly generated App identity and
// one bounded opaque recovery snapshot. The caller can atomically retain S and
// the original request together. This layer never interprets a DTO, HTTP error,
// expiry or authorization result and never automatically discards a request.
// Production Windows uses NewPlatformProtector; password protection is a test
// backend. The caller owns any detached secret bytes and must clear them.
type PreRegistrationStore struct {
	mu         sync.Mutex
	path       string
	scope      PreRegistrationScope
	protector  Protector
	lock       *flock.Flock
	fileInfo   os.FileInfo
	fileDigest [32]byte
	dataKey    []byte
	wrappedKey []byte
	private    []byte
	state      []byte
	revision   uint64
	closed     bool
	poisoned   bool
}

func (*PreRegistrationStore) String() string   { return "AppPreRegistration<protected>" }
func (*PreRegistrationStore) GoString() string { return "AppPreRegistration<protected>" }

// CreatePreRegistration never replaces an existing file or imports an Owner
// identity. No identity handle is exposed before the first durable publication.
// If publication is uncertain, close/reopen the same scope; never create a new
// installation ID as an automatic recovery action.
func CreatePreRegistration(root string, scope PreRegistrationScope, protector Protector) (*PreRegistrationStore, error) {
	s, err := newPreRegistrationStore(root, scope, protector)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(s.path); !errors.Is(err, os.ErrNotExist) {
		_ = s.Close()
		if err == nil {
			return nil, ErrVaultExists
		}
		return nil, ErrInvalidVault
	}
	identity, err := appkeys.Generate()
	if err == nil {
		s.private, err = identity.MarshalBinary()
		identity.Close()
	}
	if err == nil {
		s.dataKey = make([]byte, 32)
		_, err = rand.Read(s.dataKey)
	}
	if err == nil {
		s.wrappedKey, err = protector.WrapKey(preRegistrationContext(scope), s.dataKey)
	}
	if err != nil || len(s.private) == 0 || len(s.private) > maxIdentityBytes || len(s.wrappedKey) == 0 || len(s.wrappedKey) > maxWrappedKeyBytes {
		_ = s.Close()
		return nil, ErrInvalidVault
	}
	if err := s.persist(0, nil, true); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// OpenPreRegistration authenticates the exact expected Hub/installation scope.
// Missing, corrupt or mismatched state never causes automatic key generation.
func OpenPreRegistration(root string, expected PreRegistrationScope, protector Protector) (*PreRegistrationStore, error) {
	s, err := newPreRegistrationStore(root, expected, protector)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(s.path); errors.Is(err, os.ErrNotExist) {
		_ = s.Close()
		return nil, os.ErrNotExist
	}
	data, info, err := readVaultFile(s.path)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	defer clear(data)
	if err := s.open(data); err != nil {
		_ = s.Close()
		return nil, err
	}
	s.fileInfo, s.fileDigest = info, sha256.Sum256(data)
	return s, nil
}

func newPreRegistrationStore(root string, scope PreRegistrationScope, protector Protector) (*PreRegistrationStore, error) {
	path, err := PreRegistrationPath(root, scope)
	if err != nil || protector == nil || !validProtectorID(protector.ID()) {
		return nil, ErrInvalidVault
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := acquireVaultLock(path)
	if err != nil {
		return nil, err
	}
	return &PreRegistrationStore{path: path, scope: scope, protector: protector, lock: lock}, nil
}

// Identity returns a detached ordinary App identity. There is no Owner-signer
// purpose or identity-replacement operation in this store.
func (s *PreRegistrationStore) Identity() (*appkeys.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireOpen(); err != nil {
		return nil, err
	}
	return appkeys.ParseIdentity(s.private)
}

func (s *PreRegistrationStore) LoadState() ([]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireOpen(); err != nil {
		return nil, 0, err
	}
	return bytes.Clone(s.state), s.revision, nil
}

// CompareAndSwapState writes an entire opaque snapshot, at most 1 MiB. Only
// the current revision is accepted. Identical bytes at that revision are a
// no-op; stale revisions conflict even when bytes match. A nil snapshot is a
// versioned tombstone, retaining the identity and revision. Only the eventual
// protocol adapter can decide when authenticated settlement permits clearing
// the original request. There is no expiry/HTTP-error cleanup or delete API.
func (s *PreRegistrationStore) CompareAndSwapState(expected uint64, state []byte) (uint64, error) {
	if len(state) > maxStateBytes {
		return 0, ErrInvalidVault
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireOpen(); err != nil {
		return 0, err
	}
	if expected != s.revision {
		return s.revision, ErrStateConflict
	}
	if bytes.Equal(state, s.state) {
		return s.revision, s.verifyCurrentFile(false)
	}
	if s.revision == ^uint64(0) {
		return s.revision, ErrStateConflict
	}
	if err := s.persist(s.revision+1, state, false); err != nil {
		return s.revision, err
	}
	clear(s.state)
	s.state, s.revision = bytes.Clone(state), s.revision+1
	return s.revision, nil
}

func (s *PreRegistrationStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, data := range [][]byte{s.dataKey, s.wrappedKey, s.private, s.state} {
		clear(data)
	}
	s.dataKey, s.wrappedKey, s.private, s.state = nil, nil, nil, nil
	var err error
	if s.lock != nil {
		err = s.lock.Unlock()
		s.lock = nil
	}
	if closer, ok := s.protector.(interface{ Close() }); ok {
		closer.Close()
	}
	return err
}

func (s *PreRegistrationStore) requireOpen() error {
	if s == nil || s.closed || s.lock == nil {
		return ErrClosed
	}
	if s.poisoned {
		return ErrCommitUncertain
	}
	return nil
}

func (s *PreRegistrationStore) verifyCurrentFile(create bool) error {
	if err := verifyLockFile(s.path+".lock", s.lock); err != nil {
		return err
	}
	if create {
		if _, err := os.Lstat(s.path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return ErrVaultExists
	}
	data, info, err := readVaultFile(s.path)
	if err != nil {
		return err
	}
	defer clear(data)
	if s.fileInfo == nil || !os.SameFile(info, s.fileInfo) || sha256.Sum256(data) != s.fileDigest {
		return ErrInvalidVault
	}
	return nil
}

func (s *PreRegistrationStore) persist(revision uint64, state []byte, create bool) error {
	if err := s.requireOpen(); err != nil {
		return err
	}
	if err := s.verifyCurrentFile(create); err != nil {
		return err
	}
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.BigEndian, uint16(1))
	_ = binary.Write(&payload, binary.BigEndian, uint32(len(s.private)))
	payload.Write(s.private)
	_ = binary.Write(&payload, binary.BigEndian, revision)
	_ = binary.Write(&payload, binary.BigEndian, uint32(len(state)))
	payload.Write(state)
	defer clear(payload.Bytes())
	sealed, err := s.seal(payload.Bytes())
	if err != nil {
		return err
	}
	defer clear(sealed)
	committed, err := writeVaultAtomic(s.path, sealed, !create)
	if err != nil {
		if committed {
			s.poisoned = true
			return ErrCommitUncertain
		}
		return err
	}
	actual, info, err := readVaultFile(s.path)
	defer clear(actual)
	if err != nil || !bytes.Equal(actual, sealed) {
		s.poisoned = true
		return ErrCommitUncertain
	}
	s.fileInfo, s.fileDigest = info, sha256.Sum256(sealed)
	return nil
}

func (s *PreRegistrationStore) seal(plain []byte) ([]byte, error) {
	if len(plain) == 0 || len(plain) > maxPreRegistrationPlainBytes {
		return nil, ErrInvalidVault
	}
	block, err := aes.NewCipher(s.dataKey)
	if err != nil {
		return nil, ErrInvalidVault
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidVault
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrInvalidVault
	}
	var header bytes.Buffer
	header.Write(preRegistrationMagic)
	_ = binary.Write(&header, binary.BigEndian, uint16(1))
	writeField(&header, []byte(s.protector.ID()))
	for _, field := range preRegistrationFields(s.scope) {
		writeField(&header, []byte(field))
	}
	writeField(&header, s.wrappedKey)
	header.Write(nonce)
	_ = binary.Write(&header, binary.BigEndian, uint32(len(plain)+gcm.Overhead()))
	return gcm.Seal(header.Bytes(), nonce, plain, header.Bytes()), nil
}

func (s *PreRegistrationStore) open(data []byte) error {
	if len(data) > maxVaultFileBytes || len(data) < len(preRegistrationMagic) || !bytes.Equal(data[:len(preRegistrationMagic)], preRegistrationMagic) {
		return ErrInvalidVault
	}
	r := bytes.NewReader(data[len(preRegistrationMagic):])
	var version uint16
	if binary.Read(r, binary.BigEndian, &version) != nil || version != 1 {
		return ErrInvalidVault
	}
	read := func(max int) ([]byte, error) {
		var size uint16
		if binary.Read(r, binary.BigEndian, &size) != nil || int(size) > max || int(size) > r.Len() {
			return nil, ErrInvalidVault
		}
		value := make([]byte, size)
		_, err := io.ReadFull(r, value)
		return value, err
	}
	pid, err := read(64)
	if err != nil || string(pid) != s.protector.ID() {
		return ErrInvalidVault
	}
	for _, field := range preRegistrationFields(s.scope) {
		value, err := read(maxScopeText)
		if err != nil {
			return ErrInvalidVault
		}
		if string(value) != field {
			return ErrScopeMismatch
		}
	}
	wrapped, err := read(maxWrappedKeyBytes)
	if err != nil || len(wrapped) == 0 || r.Len() < 16 {
		return ErrInvalidVault
	}
	defer clear(wrapped)
	nonce := make([]byte, 12)
	_, _ = io.ReadFull(r, nonce)
	var size uint32
	if binary.Read(r, binary.BigEndian, &size) != nil || size < 16 || size > maxPreRegistrationPlainBytes+16 || int(size) != r.Len() {
		return ErrInvalidVault
	}
	headerBytes := len(data) - r.Len()
	key, err := s.protector.UnwrapKey(preRegistrationContext(s.scope), wrapped)
	if err != nil || len(key) != 32 {
		clear(key)
		return ErrInvalidVault
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return ErrInvalidVault
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ErrInvalidVault
	}
	plain, err := gcm.Open(nil, nonce, data[headerBytes:], data[:headerBytes])
	if err != nil {
		return ErrInvalidVault
	}
	defer clear(plain)
	if err := s.decodePayload(plain); err != nil {
		return err
	}
	s.dataKey, s.wrappedKey = bytes.Clone(key), bytes.Clone(wrapped)
	return nil
}

func (s *PreRegistrationStore) decodePayload(plain []byte) error {
	if len(plain) > maxPreRegistrationPlainBytes {
		return ErrInvalidVault
	}
	r := bytes.NewReader(plain)
	var version uint16
	var privateSize, stateSize uint32
	var revision uint64
	if binary.Read(r, binary.BigEndian, &version) != nil || version != 1 || binary.Read(r, binary.BigEndian, &privateSize) != nil ||
		privateSize == 0 || privateSize > maxIdentityBytes || int(privateSize) > r.Len() {
		return ErrInvalidVault
	}
	private := make([]byte, privateSize)
	defer clear(private)
	_, _ = io.ReadFull(r, private)
	identity, err := appkeys.ParseIdentity(private)
	if err != nil {
		return ErrInvalidVault
	}
	identity.Close()
	if binary.Read(r, binary.BigEndian, &revision) != nil || binary.Read(r, binary.BigEndian, &stateSize) != nil ||
		stateSize > maxStateBytes || int(stateSize) != r.Len() || revision == 0 && stateSize != 0 {
		return ErrInvalidVault
	}
	s.private = bytes.Clone(private)
	s.state = bytes.Clone(plain[len(plain)-int(stateSize):])
	s.revision = revision
	return nil
}

func preRegistrationFields(scope PreRegistrationScope) []string {
	return []string{scope.Origin, scope.HubID, scope.HubFingerprint, scope.InstallationID}
}

func preRegistrationContext(scope PreRegistrationScope) []byte {
	var b bytes.Buffer
	b.WriteString("cicada/appvault/pre-registration/key-wrap/v1\x00")
	for _, field := range preRegistrationFields(scope) {
		writeField(&b, []byte(field))
	}
	return b.Bytes()
}

func validatePreRegistrationScope(scope PreRegistrationScope) error {
	if !validOrigin(scope.Origin) || !validID(scope.HubID) || !validFingerprint(scope.HubFingerprint) || len(scope.InstallationID) != 32 || !isLowerHex(scope.InstallationID) {
		return ErrInvalidVault
	}
	return nil
}
