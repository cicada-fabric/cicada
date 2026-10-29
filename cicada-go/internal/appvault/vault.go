// Package appvault stores per-Hub App identities and pending protocol state.
// Private records are encrypted with AES-256-GCM and authenticated to the
// complete Hub/account/Owner scope. It never writes plaintext key material.
package appvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/gofrs/flock"
)

const (
	vaultVersion       = uint16(1)
	maxVaultFileBytes  = 8 << 20
	maxVaultPlainBytes = 4 << 20
	maxIdentityBytes   = 64 << 10
	maxStateBytes      = 1 << 20
	// Legacy 21 including tombstones, three shared scoped work records,
	// and at most eight Node records. Existing byte ceilings still apply.
	maxStateRecords    = 32
	maxVaultEntries    = 2
	maxScopeText       = 256
	maxWrappedKeyBytes = 4096
)

var (
	ErrInvalidVault  = errors.New("invalid App vault")
	ErrScopeMismatch = errors.New("App vault scope mismatch")
	ErrVaultBusy     = errors.New("App vault is already open by another process")
	ErrVaultExists   = errors.New("App vault already exists")
	ErrClosed        = errors.New("App vault is closed")
	ErrKeyExists     = errors.New("App vault key purpose already has a different identity")
	ErrStateConflict = errors.New("App vault state version conflict")
	ErrStateNotFound = errors.New("App vault state not found")
	ErrUnsupportedOS = errors.New("App vault platform protection is unavailable")
	// ErrCommitUncertain means an atomic write may already have replaced the
	// on-disk vault, but a later durability or validation step failed. The
	// caller must close and reopen before reading or attempting another write.
	ErrCommitUncertain = errors.New("App vault commit outcome uncertain; close and reopen")
)

type Purpose string

const (
	PurposeOwnerSigner Purpose = "OWNER_SIGNER"
	PurposeAppDevice   Purpose = "APP_DEVICE"
)

// Scope is immutable for a vault. HubFingerprint is the complete 64-digit
// lowercase SHA-256 pin over the canonical full Hub identity, not a short ID.
type Scope struct {
	HubID          string `json:"hub_id"`
	HubFingerprint string `json:"hub_fingerprint"`
	Origin         string `json:"origin"`
	AccountID      string `json:"account_id"`
	OwnerID        string `json:"owner_id"`
}

// Protector wraps the random vault data key. The payload itself is always
// protected by this package with AES-256-GCM. Implementations must bind the
// supplied context to their wrapping operation.
type Protector interface {
	ID() string
	WrapKey(context, key []byte) ([]byte, error)
	UnwrapKey(context, wrapped []byte) ([]byte, error)
}

type EntryInfo struct {
	Purpose Purpose `json:"purpose"`
	KeyID   string  `json:"key_id"`
}

type diskEntry struct {
	Purpose Purpose `json:"purpose"`
	KeyID   string  `json:"key_id"`
	Private []byte  `json:"private_identity"`
}

type diskState struct {
	Namespace string `json:"namespace"`
	Version   uint64 `json:"version"`
	Payload   []byte `json:"payload"`
}

type diskPayload struct {
	Version int         `json:"version"`
	Entries []diskEntry `json:"entries"`
	States  []diskState `json:"states"`
}

type stateValue struct {
	version uint64
	payload []byte
}

type Vault struct {
	mu         sync.Mutex
	path       string
	scope      Scope
	protector  Protector
	dataKey    []byte
	wrappedKey []byte
	lock       *flock.Flock
	fileInfo   os.FileInfo
	entries    map[Purpose]diskEntry
	states     map[string]stateValue
	closed     bool
	poisoned   bool
}

var vaultMagic = []byte("CICAPPV1\x00")

// Create exclusively creates an empty vault. It never replaces an existing
// vault; callers must explicitly open and use its current scope.
func Create(path string, scope Scope, protector Protector) (*Vault, error) {
	if err := validateInputs(path, scope, protector); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := acquireVaultLock(path)
	if err != nil {
		return nil, err
	}
	v := &Vault{path: path, scope: scope, protector: protector, lock: lock,
		entries: make(map[Purpose]diskEntry), states: make(map[string]stateValue)}
	if err := v.initializeKey(); err != nil {
		_ = v.Close()
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		_ = v.Close()
		return nil, ErrVaultExists
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = v.Close()
		return nil, ErrInvalidVault
	}
	if err := v.persist(true); err != nil {
		_ = v.Close()
		return nil, err
	}
	return v, nil
}

// Open verifies the exact scope and decrypts a bounded vault. Only one process
// may hold a vault open for mutation at a time.
func Open(path string, expected Scope, protector Protector) (*Vault, error) {
	if err := validateInputs(path, expected, protector); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := acquireVaultLock(path)
	if err != nil {
		return nil, err
	}
	v := &Vault{path: path, scope: expected, protector: protector, lock: lock,
		entries: make(map[Purpose]diskEntry), states: make(map[string]stateValue)}
	data, info, err := readVaultFile(path)
	if err != nil {
		_ = v.Close()
		return nil, err
	}
	defer clear(data)
	plain, dataKey, wrappedKey, err := openEnvelope(data, expected, protector)
	if err != nil {
		_ = v.Close()
		return nil, err
	}
	defer clear(plain)
	v.dataKey = dataKey
	v.wrappedKey = wrappedKey
	if err := v.decodePayload(plain); err != nil {
		_ = v.Close()
		return nil, err
	}
	v.fileInfo = info
	return v, nil
}

func (v *Vault) Scope() Scope {
	if v == nil {
		return Scope{}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.scope
}

// Put adds one identity for its purpose. Repeating the same key is idempotent;
// replacing an existing purpose with a different key is never implicit.
func (v *Vault) Put(purpose Purpose, identity *appkeys.Identity) error {
	if !validPurpose(purpose) || identity == nil {
		return ErrInvalidVault
	}
	public := identity.Public()
	if !validKeyID(public.ID) {
		return ErrInvalidVault
	}
	private, err := identity.MarshalBinary()
	if err != nil || len(private) == 0 || len(private) > maxIdentityBytes {
		clear(private)
		return ErrInvalidVault
	}
	defer clear(private)
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return err
	}
	if existing, ok := v.entries[purpose]; ok {
		if existing.KeyID == public.ID && bytes.Equal(existing.Private, private) {
			return nil
		}
		return ErrKeyExists
	}
	if len(v.entries) >= maxVaultEntries {
		return ErrInvalidVault
	}
	entries := cloneEntries(v.entries)
	entries[purpose] = diskEntry{Purpose: purpose, KeyID: public.ID, Private: append([]byte(nil), private...)}
	if err := v.persistWith(entries, v.states, false); err != nil {
		clearEntries(entries)
		return err
	}
	clearEntries(v.entries)
	v.entries = entries
	return nil
}

// Get returns a newly parsed identity handle. Closing it does not affect the
// vault's stored record or any other identity handle.
func (v *Vault) Get(purpose Purpose, keyID string) (*appkeys.Identity, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return nil, err
	}
	entry, ok := v.entries[purpose]
	if !ok || entry.KeyID != keyID {
		return nil, ErrStateNotFound
	}
	identity, err := appkeys.ParseIdentity(entry.Private)
	if err != nil || identity.Public().ID != entry.KeyID {
		if identity != nil {
			identity.Close()
		}
		return nil, ErrInvalidVault
	}
	return identity, nil
}

func (v *Vault) List() ([]EntryInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return nil, err
	}
	result := make([]EntryInfo, 0, len(v.entries))
	for purpose, entry := range v.entries {
		result = append(result, EntryInfo{Purpose: purpose, KeyID: entry.KeyID})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Purpose < result[j].Purpose })
	return result, nil
}

// LoadState returns a detached copy of a bounded encrypted pending-operation
// state. Version 0 means no state has ever been written in this namespace.
func (v *Vault) LoadState(namespace string) (payload []byte, version uint64, found bool, err error) {
	if !validNamespace(namespace) {
		return nil, 0, false, ErrInvalidVault
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return nil, 0, false, err
	}
	state, ok := v.states[namespace]
	if !ok {
		return nil, 0, false, nil
	}
	return append([]byte(nil), state.payload...), state.version, true, nil
}

// CompareAndSwapState stores an opaque encrypted pending protocol record only
// if expectedVersion matches. A nil payload is a versioned tombstone; it never
// resets a namespace's generation to zero.
func (v *Vault) CompareAndSwapState(namespace string, expectedVersion uint64, payload []byte) (uint64, error) {
	if !validNamespace(namespace) || len(payload) > maxStateBytes {
		return 0, ErrInvalidVault
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return 0, err
	}
	current, ok := v.states[namespace]
	if !ok {
		current.version = 0
	}
	if current.version != expectedVersion || current.version == ^uint64(0) {
		return current.version, ErrStateConflict
	}
	states := cloneStates(v.states)
	states[namespace] = stateValue{version: current.version + 1, payload: append([]byte(nil), payload...)}
	if len(states) > maxStateRecords {
		clearStates(states)
		return current.version, ErrInvalidVault
	}
	if err := v.persistWith(v.entries, states, false); err != nil {
		clearStates(states)
		return current.version, err
	}
	clearStates(v.states)
	v.states = states
	return current.version + 1, nil
}

// CheckStateUpdates checks the existing per-record, record-count and complete
// encrypted payload budgets without writing or changing any CAS generation.
// Callers still persist their exact request before network. It reserves no
// permission and does not replace CompareAndSwapState's concurrency check.
func (v *Vault) CheckStateUpdates(updates map[string][]byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return err
	}
	states := cloneStates(v.states)
	defer clearStates(states)
	for namespace, payload := range updates {
		if !validNamespace(namespace) || len(payload) > maxStateBytes {
			return ErrInvalidVault
		}
		state := states[namespace]
		if state.version == 0 {
			state.version = 1
		}
		clear(state.payload)
		state.payload = append([]byte(nil), payload...)
		states[namespace] = state
	}
	data, err := encodePayload(v.entries, states)
	clear(data)
	return err
}

func (v *Vault) Close() error {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	clearEntries(v.entries)
	clearStates(v.states)
	clear(v.dataKey)
	clear(v.wrappedKey)
	v.dataKey = nil
	v.wrappedKey = nil
	v.entries = nil
	v.states = nil
	var err error
	if v.lock != nil {
		err = v.lock.Unlock()
		v.lock = nil
	}
	if closer, ok := v.protector.(interface{ Close() }); ok {
		closer.Close()
	}
	return err
}

func (v *Vault) requireOpen() error {
	if v == nil || v.closed || v.lock == nil {
		return ErrClosed
	}
	if v.poisoned {
		return ErrCommitUncertain
	}
	return nil
}

func (v *Vault) persist(create bool) error { return v.persistWith(v.entries, v.states, create) }

func (v *Vault) persistWith(entries map[Purpose]diskEntry, states map[string]stateValue, create bool) error {
	if err := v.requireOpen(); err != nil {
		return err
	}
	if err := v.verifyCurrentFile(create); err != nil {
		return err
	}
	payload, err := encodePayload(entries, states)
	if err != nil {
		return err
	}
	defer clear(payload)
	sealed, err := sealEnvelope(v.scope, v.protector.ID(), v.wrappedKey, v.dataKey, payload)
	if err != nil {
		return ErrInvalidVault
	}
	defer clear(sealed)
	committed, err := writeVaultAtomic(v.path, sealed, !create)
	if err != nil {
		if committed {
			v.poisoned = true
			return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
		}
		return err
	}
	info, err := checkVaultFile(v.path)
	if err != nil {
		v.poisoned = true
		return fmt.Errorf("%w: post-write file validation failed", ErrCommitUncertain)
	}
	v.fileInfo = info
	return nil
}

func (v *Vault) verifyCurrentFile(create bool) error {
	info, err := os.Lstat(v.path)
	if create {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return ErrVaultExists
	}
	if err != nil || v.fileInfo == nil || !os.SameFile(info, v.fileInfo) {
		return ErrInvalidVault
	}
	if _, err := checkVaultFile(v.path); err != nil {
		return ErrInvalidVault
	}
	return nil
}

func (v *Vault) decodePayload(data []byte) error {
	if len(data) == 0 || len(data) > maxVaultPlainBytes {
		return ErrInvalidVault
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var payload diskPayload
	if err := decoder.Decode(&payload); err != nil {
		return ErrInvalidVault
	}
	defer clearDiskPayload(&payload)
	if err := decoder.Decode(new(any)); err != io.EOF || payload.Version != int(vaultVersion) || len(payload.Entries) > maxVaultEntries || len(payload.States) > maxStateRecords {
		return ErrInvalidVault
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		clear(canonical)
		return ErrInvalidVault
	}
	canonicalMatches := bytes.Equal(canonical, data)
	clear(canonical)
	if !canonicalMatches {
		return ErrInvalidVault
	}
	for _, entry := range payload.Entries {
		if !validPurpose(entry.Purpose) || !validKeyID(entry.KeyID) || len(entry.Private) == 0 || len(entry.Private) > maxIdentityBytes {
			return ErrInvalidVault
		}
		if _, exists := v.entries[entry.Purpose]; exists {
			return ErrInvalidVault
		}
		identity, err := appkeys.ParseIdentity(entry.Private)
		if err != nil || identity.Public().ID != entry.KeyID {
			if identity != nil {
				identity.Close()
			}
			return ErrInvalidVault
		}
		identity.Close()
		v.entries[entry.Purpose] = diskEntry{Purpose: entry.Purpose, KeyID: entry.KeyID, Private: append([]byte(nil), entry.Private...)}
	}
	for _, state := range payload.States {
		if !validNamespace(state.Namespace) || state.Version == 0 || len(state.Payload) > maxStateBytes {
			return ErrInvalidVault
		}
		if _, exists := v.states[state.Namespace]; exists {
			return ErrInvalidVault
		}
		v.states[state.Namespace] = stateValue{version: state.Version, payload: append([]byte(nil), state.Payload...)}
	}
	return nil
}

func encodePayload(entries map[Purpose]diskEntry, states map[string]stateValue) ([]byte, error) {
	if len(entries) > maxVaultEntries || len(states) > maxStateRecords {
		return nil, ErrInvalidVault
	}
	payload := diskPayload{Version: int(vaultVersion)}
	defer clearDiskPayload(&payload)
	for purpose, entry := range entries {
		if !validPurpose(purpose) || entry.Purpose != purpose || !validKeyID(entry.KeyID) || len(entry.Private) == 0 || len(entry.Private) > maxIdentityBytes {
			return nil, ErrInvalidVault
		}
		payload.Entries = append(payload.Entries, diskEntry{Purpose: purpose, KeyID: entry.KeyID, Private: append([]byte(nil), entry.Private...)})
	}
	for namespace, state := range states {
		if !validNamespace(namespace) || state.version == 0 || len(state.payload) > maxStateBytes {
			return nil, ErrInvalidVault
		}
		payload.States = append(payload.States, diskState{Namespace: namespace, Version: state.version, Payload: append([]byte(nil), state.payload...)})
	}
	sort.Slice(payload.Entries, func(i, j int) bool { return payload.Entries[i].Purpose < payload.Entries[j].Purpose })
	sort.Slice(payload.States, func(i, j int) bool { return payload.States[i].Namespace < payload.States[j].Namespace })
	data, err := json.Marshal(payload)
	if err != nil || len(data) > maxVaultPlainBytes {
		clear(data)
		return nil, ErrInvalidVault
	}
	return data, nil
}

func clearDiskPayload(payload *diskPayload) {
	if payload == nil {
		return
	}
	for i := range payload.Entries {
		clear(payload.Entries[i].Private)
		payload.Entries[i].Private = nil
	}
	for i := range payload.States {
		clear(payload.States[i].Payload)
		payload.States[i].Payload = nil
	}
}

func sealEnvelope(scope Scope, protectorID string, wrapped, dataKey, plain []byte) ([]byte, error) {
	if len(dataKey) != 32 || len(wrapped) == 0 || len(wrapped) > maxWrappedKeyBytes {
		return nil, ErrInvalidVault
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, ErrInvalidVault
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidVault
	}
	// Ciphertext length is plaintext length plus the fixed GCM tag. Re-encode
	// the header with this exact length so the entire public header is AAD.
	header, err := encodeHeader(scope, protectorID, wrapped, nonce, uint32(len(plain)+gcm.Overhead()))
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, header)
	defer clear(ciphertext)
	if uint32(len(ciphertext)) != uint32(len(plain)+gcm.Overhead()) {
		return nil, ErrInvalidVault
	}
	return append(header, ciphertext...), nil
}

func openEnvelope(data []byte, expected Scope, protector Protector) ([]byte, []byte, []byte, error) {
	header, encodedScope, protectorID, wrapped, nonce, ciphertext, err := decodeHeader(data)
	if err != nil {
		clear(wrapped)
		clear(nonce)
		clear(ciphertext)
		clear(header)
		return nil, nil, nil, ErrInvalidVault
	}
	defer clear(header)
	defer clear(nonce)
	defer clear(ciphertext)
	keepWrapped := false
	defer func() {
		if !keepWrapped {
			clear(wrapped)
		}
	}()
	if encodedScope != expected {
		return nil, nil, nil, ErrScopeMismatch
	}
	if protectorID != protector.ID() || len(ciphertext) < 16 || len(ciphertext) > maxVaultPlainBytes+16 {
		return nil, nil, nil, ErrInvalidVault
	}
	context := scopeContext(expected)
	defer clear(context)
	dataKey, err := protector.UnwrapKey(context, wrapped)
	if err != nil || len(dataKey) != 32 {
		clear(dataKey)
		clear(wrapped)
		return nil, nil, nil, ErrInvalidVault
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		clear(dataKey)
		clear(wrapped)
		return nil, nil, nil, ErrInvalidVault
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		clear(dataKey)
		clear(wrapped)
		return nil, nil, nil, ErrInvalidVault
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		clear(dataKey)
		clear(wrapped)
		return nil, nil, nil, ErrInvalidVault
	}
	keepWrapped = true
	return plain, dataKey, wrapped, nil
}

func (v *Vault) initializeKey() error {
	v.dataKey = make([]byte, 32)
	if _, err := rand.Read(v.dataKey); err != nil {
		clear(v.dataKey)
		return ErrInvalidVault
	}
	context := scopeContext(v.scope)
	defer clear(context)
	wrapped, err := v.protector.WrapKey(context, v.dataKey)
	if err != nil || len(wrapped) == 0 || len(wrapped) > maxWrappedKeyBytes {
		clear(v.dataKey)
		clear(wrapped)
		v.dataKey = nil
		return ErrInvalidVault
	}
	v.wrappedKey = append([]byte(nil), wrapped...)
	clear(wrapped)
	return nil
}

func encodeHeader(scope Scope, protectorID string, wrapped, nonce []byte, ciphertextLen uint32) ([]byte, error) {
	if !validProtectorID(protectorID) || len(wrapped) == 0 || len(wrapped) > maxWrappedKeyBytes || len(nonce) != 12 {
		return nil, ErrInvalidVault
	}
	var b bytes.Buffer
	b.Write(vaultMagic)
	_ = binary.Write(&b, binary.BigEndian, vaultVersion)
	writeField(&b, []byte(protectorID))
	for _, value := range []string{scope.HubID, scope.HubFingerprint, scope.Origin, scope.AccountID, scope.OwnerID} {
		writeField(&b, []byte(value))
	}
	writeField(&b, wrapped)
	b.Write(nonce)
	_ = binary.Write(&b, binary.BigEndian, ciphertextLen)
	if b.Len() > 8192 {
		return nil, ErrInvalidVault
	}
	return b.Bytes(), nil
}

func decodeHeader(data []byte) (header []byte, scope Scope, protectorID string, wrapped, nonce, ciphertext []byte, err error) {
	valid := false
	defer func() {
		if !valid {
			clear(header)
			clear(wrapped)
			clear(nonce)
			clear(ciphertext)
		}
	}()
	if len(data) < len(vaultMagic)+2+12+4 || len(data) > maxVaultFileBytes || !bytes.Equal(data[:len(vaultMagic)], vaultMagic) {
		err = ErrInvalidVault
		return
	}
	r := bytes.NewReader(data[len(vaultMagic):])
	var version uint16
	if binary.Read(r, binary.BigEndian, &version) != nil || version != vaultVersion {
		err = ErrInvalidVault
		return
	}
	read := func(max int) ([]byte, bool) {
		var n uint16
		if binary.Read(r, binary.BigEndian, &n) != nil || int(n) > max || int(n) > r.Len() {
			return nil, false
		}
		value := make([]byte, int(n))
		if _, e := io.ReadFull(r, value); e != nil {
			return nil, false
		}
		return value, true
	}
	pid, ok := read(64)
	if !ok {
		err = ErrInvalidVault
		return
	}
	protectorID = string(pid)
	fields := make([]string, 5)
	for i := range fields {
		value, good := read(maxScopeText)
		if !good {
			err = ErrInvalidVault
			return
		}
		fields[i] = string(value)
	}
	scope = Scope{HubID: fields[0], HubFingerprint: fields[1], Origin: fields[2], AccountID: fields[3], OwnerID: fields[4]}
	wrapped, ok = read(maxWrappedKeyBytes)
	if !ok || r.Len() < 12+4 {
		err = ErrInvalidVault
		return
	}
	nonce = make([]byte, 12)
	if _, err = io.ReadFull(r, nonce); err != nil {
		return
	}
	var ctLen uint32
	if binary.Read(r, binary.BigEndian, &ctLen) != nil || ctLen > maxVaultPlainBytes+16 || int(ctLen) != r.Len() {
		err = ErrInvalidVault
		return
	}
	headerLen := len(data) - r.Len()
	header = append([]byte(nil), data[:headerLen]...)
	ciphertext = append([]byte(nil), data[headerLen:]...)
	if validateScope(scope) != nil || !validProtectorID(protectorID) {
		err = ErrInvalidVault
		return
	}
	valid = true
	return
}

func scopeContext(scope Scope) []byte {
	var b bytes.Buffer
	b.WriteString("cicada/appvault/key-wrap/v1\x00")
	for _, value := range []string{scope.HubID, scope.HubFingerprint, scope.Origin, scope.AccountID, scope.OwnerID} {
		writeField(&b, []byte(value))
	}
	return b.Bytes()
}

func writeField(w io.Writer, value []byte) {
	_ = binary.Write(w, binary.BigEndian, uint16(len(value)))
	_, _ = w.Write(value)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func hexString(b []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2], out[i*2+1] = alphabet[v>>4], alphabet[v&0x0f]
	}
	return string(out)
}

func validateInputs(path string, scope Scope, protector Protector) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || validateScope(scope) != nil || protector == nil || !validProtectorID(protector.ID()) {
		return ErrInvalidVault
	}
	return nil
}

func validateScope(s Scope) error {
	if !validID(s.HubID) || !validID(s.AccountID) || !validID(s.OwnerID) || !validFingerprint(s.HubFingerprint) || !validOrigin(s.Origin) {
		return ErrInvalidVault
	}
	return nil
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > maxScopeText {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validFingerprint(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validOrigin(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u == nil || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.RawPath != "" || u.Host == "" {
		return false
	}
	if value != strings.TrimSpace(value) || strings.ContainsAny(value, "\\\r\n\t") || u.Host != strings.ToLower(u.Host) {
		return false
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return false
	}
	if port := u.Port(); port != "" {
		if port == "0" || port[0] == '0' || u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80" {
			return false
		}
		for _, c := range port {
			if c < '0' || c > '9' {
				return false
			}
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return false
		}
	}
	canonicalHost := host
	if ip := net.ParseIP(host); ip != nil {
		canonicalHost = ip.String()
		if strings.Contains(canonicalHost, ":") {
			canonicalHost = "[" + canonicalHost + "]"
		}
	} else {
		if len(host) > 253 || strings.ContainsAny(host, "_:/[]") {
			return false
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return false
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		canonicalHost += ":" + port
	}
	if u.Host != canonicalHost {
		return false
	}
	if u.Scheme == "https" {
		return value == "https://"+u.Host
	}
	if u.Scheme != "http" {
		return false
	}
	if value != "http://"+u.Host {
		return false
	}
	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()
}

func validPurpose(p Purpose) bool { return p == PurposeOwnerSigner || p == PurposeAppDevice }
func validKeyID(s string) bool {
	return len(s) == 36 && strings.HasPrefix(s, "pq1-") && isLowerHex(s[4:])
}

func isLowerHex(s string) bool {
	if s == "" || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validNamespace(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validProtectorID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func cloneEntries(source map[Purpose]diskEntry) map[Purpose]diskEntry {
	result := make(map[Purpose]diskEntry, len(source)+1)
	for purpose, entry := range source {
		result[purpose] = diskEntry{Purpose: entry.Purpose, KeyID: entry.KeyID, Private: append([]byte(nil), entry.Private...)}
	}
	return result
}

func cloneStates(source map[string]stateValue) map[string]stateValue {
	result := make(map[string]stateValue, len(source)+1)
	for namespace, value := range source {
		result[namespace] = stateValue{version: value.version, payload: append([]byte(nil), value.payload...)}
	}
	return result
}

func clearEntries(entries map[Purpose]diskEntry) {
	for purpose, entry := range entries {
		clear(entry.Private)
		delete(entries, purpose)
	}
}

func clearStates(states map[string]stateValue) {
	for namespace, state := range states {
		clear(state.payload)
		delete(states, namespace)
	}
}

func checkVaultFile(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maxVaultFileBytes {
		return nil, ErrInvalidVault
	}
	if err := validatePlatformVaultFile(path, info); err != nil {
		return nil, ErrInvalidVault
	}
	return info, nil
}

func readVaultFile(path string) ([]byte, os.FileInfo, error) {
	info, err := checkVaultFile(path)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, ErrInvalidVault
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, ErrInvalidVault
	}
	data, err := io.ReadAll(io.LimitReader(f, maxVaultFileBytes+1))
	if err != nil || len(data) > maxVaultFileBytes {
		clear(data)
		return nil, nil, ErrInvalidVault
	}
	return data, info, nil
}

func acquireVaultLock(path string) (*flock.Flock, error) {
	lockPath := path + ".lock"
	if err := ensureLockFile(lockPath); err != nil {
		return nil, ErrInvalidVault
	}
	lock := flock.New(lockPath, flock.SetPermissions(0o600))
	locked, err := lock.TryLock()
	if err != nil {
		return nil, ErrInvalidVault
	}
	if !locked {
		return nil, ErrVaultBusy
	}
	if err := verifyLockFile(lockPath, lock); err != nil {
		_ = lock.Unlock()
		return nil, ErrInvalidVault
	}
	return lock, nil
}

func (v *Vault) String() string {
	if v == nil {
		return "AppVault<nil>"
	}
	return fmt.Sprintf("AppVault<%s>", filepath.Base(v.path))
}
