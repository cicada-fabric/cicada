package appvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

const (
	maxPreRegistrationCandidates = 16
	// Sixteen payloads and their lock files fit comfortably. Bound unrelated
	// names and incomplete atomic-write files too, without deleting any of them.
	maxPreRegistrationDirectoryEntries = 64
)

var (
	ErrPreRegistrationLimit   = errors.New("App pre-registration discovery limit exceeded")
	ErrPreRegistrationChanged = errors.New("App pre-registration files changed during discovery; retry recovery")
)

// PreRegistrationInfo is locally authenticated locator metadata, not a logged-in
// profile, current Hub-pin check or enrollment/management authorization. A
// controller must explicitly select and reopen a record, then verify its Hub
// pin against the current Hub before any network recovery. Never mint another
// InstallationID merely because discovery or reopen failed.
type PreRegistrationInfo struct {
	Scope    PreRegistrationScope
	KeyID    string
	Revision uint64
}

type preRegistrationFileSnapshot struct {
	path   string
	info   os.FileInfo
	digest [32]byte
}

type preRegistrationDiscoveryProtector struct {
	Protector
	once sync.Once
}

func (p *preRegistrationDiscoveryProtector) Close() {
	p.once.Do(func() {
		if closer, ok := p.Protector.(interface{ Close() }); ok {
			closer.Close()
		}
	})
}

// DiscoverPreRegistrations authenticates at most sixteen independent pending
// files. Headers are internal untrusted locators only. A fresh local Protector
// is required for each open; the factory must not contact a candidate origin.
// All stores and identity handles are closed before metadata is returned.
//
// Missing directories are not created. Any busy, invalid, mismatched, changed
// or over-limit entry fails the entire scan with nil results. There is no
// newest-record selection, account-profile insertion, cleanup or key generation.
func DiscoverPreRegistrations(root string, newProtector func() (Protector, error)) ([]PreRegistrationInfo, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || newProtector == nil {
		return nil, ErrInvalidVault
	}
	directory := filepath.Join(root, "pre-registration")
	// Check existing ancestors before treating a missing descendant as empty.
	// Existing namespace directories additionally use the platform's complete
	// private-directory/reparse-point/ACL validation below.
	current := filepath.VolumeName(directory) + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(directory, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if current == directory && validatePrivateParent(root) != nil {
				return nil, ErrInvalidVault
			}
			return nil, nil
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrInvalidVault
		}
	}
	if validatePrivateParent(root) != nil || validatePrivateParent(directory) != nil {
		return nil, ErrInvalidVault
	}
	initial, err := os.Lstat(directory)
	if err != nil {
		return nil, ErrPreRegistrationChanged
	}
	names, err := preRegistrationNames(directory, initial)
	if err != nil {
		return nil, err
	}
	var results []PreRegistrationInfo
	var files []preRegistrationFileSnapshot
	for _, name := range names {
		info, file, err := authenticatePreRegistration(root, name, directory, initial, newProtector)
		if err != nil {
			return nil, err
		}
		results = append(results, info)
		files = append(files, file)
	}
	finalNames, err := preRegistrationNames(directory, initial)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(names, finalNames) {
		return nil, ErrPreRegistrationChanged
	}
	for _, file := range files {
		data, info, err := readVaultFile(file.path)
		same := err == nil && os.SameFile(info, file.info) && sha256.Sum256(data) == file.digest
		clear(data)
		if !same {
			return nil, ErrPreRegistrationChanged
		}
	}
	if !samePreRegistrationDirectory(directory, initial) {
		return nil, ErrPreRegistrationChanged
	}
	return results, nil
}

func samePreRegistrationDirectory(directory string, expected os.FileInfo) bool {
	current, err := os.Lstat(directory)
	return err == nil && os.SameFile(current, expected) && validatePrivateParent(directory) == nil
}

func preRegistrationNames(directory string, expected os.FileInfo) ([]string, error) {
	if !samePreRegistrationDirectory(directory, expected) {
		return nil, ErrPreRegistrationChanged
	}
	dir, err := os.Open(directory)
	if err != nil {
		return nil, ErrPreRegistrationChanged
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(opened, expected) {
		return nil, ErrPreRegistrationChanged
	}
	names, err := dir.Readdirnames(maxPreRegistrationDirectoryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrInvalidVault
	}
	if len(names) > maxPreRegistrationDirectoryEntries {
		return nil, ErrPreRegistrationLimit
	}
	var pending []string
	for _, name := range names {
		// Include obvious Windows filename aliases in validation. The exact
		// scope-derived path check must refuse them, not report an empty install.
		if strings.EqualFold(filepath.Ext(strings.TrimRight(name, " .")), ".pending") {
			pending = append(pending, name)
		}
	}
	if len(pending) > maxPreRegistrationCandidates {
		return nil, ErrPreRegistrationLimit
	}
	slices.Sort(pending) // Stable locator order, never a newest/mtime preference.
	if !samePreRegistrationDirectory(directory, expected) {
		return nil, ErrPreRegistrationChanged
	}
	return pending, nil
}

func authenticatePreRegistration(root, name, directory string, expectedDirectory os.FileInfo, newProtector func() (Protector, error)) (result PreRegistrationInfo, file preRegistrationFileSnapshot, err error) {
	path := filepath.Join(directory, name)
	data, initial, err := readVaultFile(path)
	if err != nil {
		return result, file, err
	}
	defer clear(data)
	scope, err := preRegistrationLocator(data)
	if err != nil {
		return result, file, err
	}
	expected, err := PreRegistrationPath(root, scope)
	if err != nil || path != expected {
		return result, file, ErrScopeMismatch
	}
	protector, err := newProtector()
	ownedProtector := &preRegistrationDiscoveryProtector{Protector: protector}
	defer ownedProtector.Close()
	if err != nil {
		if errors.Is(err, ErrUnsupportedOS) {
			return result, file, ErrUnsupportedOS
		}
		return result, file, ErrInvalidVault
	}
	if protector == nil {
		return result, file, ErrInvalidVault
	}
	if !samePreRegistrationDirectory(directory, expectedDirectory) {
		return result, file, ErrPreRegistrationChanged
	}
	store, err := OpenPreRegistration(root, scope, ownedProtector)
	if err != nil {
		return result, file, err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil && err == nil {
			result, file, err = PreRegistrationInfo{}, preRegistrationFileSnapshot{}, ErrInvalidVault
		}
	}()
	digest := sha256.Sum256(data)
	if !os.SameFile(initial, store.fileInfo) || digest != store.fileDigest || !samePreRegistrationDirectory(directory, expectedDirectory) {
		return result, file, ErrPreRegistrationChanged
	}
	identity, err := store.Identity()
	if err != nil {
		return result, file, err
	}
	keyID := identity.Public().ID
	identity.Close()
	if err := store.verifyCurrentFile(false); err != nil {
		return result, file, ErrPreRegistrationChanged
	}
	return PreRegistrationInfo{Scope: scope, KeyID: keyID, Revision: store.revision}, preRegistrationFileSnapshot{path, store.fileInfo, digest}, nil
}

// preRegistrationLocator decodes only a bounded public header prefix. Its
// result never escapes discovery unless OpenPreRegistration authenticates the
// entire file with the exact scope and current-user protection backend.
func preRegistrationLocator(data []byte) (PreRegistrationScope, error) {
	if len(data) < len(preRegistrationMagic)+2 || !bytes.Equal(data[:len(preRegistrationMagic)], preRegistrationMagic) {
		return PreRegistrationScope{}, ErrInvalidVault
	}
	r := bytes.NewReader(data[len(preRegistrationMagic):])
	var version uint16
	if binary.Read(r, binary.BigEndian, &version) != nil || version != 1 {
		return PreRegistrationScope{}, ErrInvalidVault
	}
	read := func(limit int) (string, error) {
		var size uint16
		if binary.Read(r, binary.BigEndian, &size) != nil || int(size) > limit || int(size) > r.Len() {
			return "", ErrInvalidVault
		}
		value := make([]byte, size)
		_, err := io.ReadFull(r, value)
		return string(value), err
	}
	pid, err := read(64)
	if err != nil || !validProtectorID(pid) {
		return PreRegistrationScope{}, ErrInvalidVault
	}
	var values [4]string
	for i := range values {
		values[i], err = read(maxScopeText)
		if err != nil {
			return PreRegistrationScope{}, ErrInvalidVault
		}
	}
	scope := PreRegistrationScope{Origin: values[0], HubID: values[1], HubFingerprint: values[2], InstallationID: values[3]}
	if validatePreRegistrationScope(scope) != nil {
		return PreRegistrationScope{}, ErrInvalidVault
	}
	return scope, nil
}
