// Package nodekeys stores Endpoint private identities in a Node-local state
// directory. The stateDir argument is already scoped to one Node; this package
// never reads or writes Control's e2ee identity or Hub Store.
package nodekeys

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	diskVersion       = 1
	keyDirectoryName  = "endpoint-keys"
	keyFileMode       = 0o600
	keyDirectoryMode  = 0o700
	maxIdentityRecord = 64 * 1024
)

// identityRecord binds the private key bytes to their stable Fabric
// Endpoint. Public is stored as a consistency check against corrupt or
// misrouted private-key data; it is not a source of Endpoint authorization.
type identityRecord struct {
	Version    int                 `json:"version"`
	EndpointID string              `json:"endpoint_id"`
	Public     e2ee.PublicIdentity `json:"public_identity"`
	Private    []byte              `json:"private_identity"`
}

// LoadExisting reads one already enrolled Endpoint identity. It never creates
// a state directory, key directory or replacement key. Receiving an encrypted
// payload for a missing Monitor identity must fail closed.
func LoadExisting(stateDir, endpointID string) (*e2ee.Identity, error) {
	if err := validateEndpointID(endpointID); err != nil {
		return nil, err
	}
	root, err := cleanStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	if err := inspectExistingStateDirectory(root); err != nil {
		return nil, err
	}
	keyDir := filepath.Join(root, keyDirectoryName)
	info, err := os.Lstat(keyDir)
	if err != nil {
		return nil, fmt.Errorf("inspect existing Node Endpoint key directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != keyDirectoryMode {
		return nil, errors.New("Node Endpoint key directory must be a real 0700 directory")
	}
	return readIdentity(identityPath(keyDir, endpointID), endpointID)
}

func inspectExistingStateDirectory(path string) error {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(abs)
	current := volume + string(filepath.Separator)
	rest := strings.TrimPrefix(abs, current)
	for _, component := range strings.Split(rest, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect existing Node-local state path %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("Node-local state path component %q is not a real directory", current)
		}
		if current == abs && info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("Node-local state directory is group or world writable: mode %04o", info.Mode().Perm())
		}
	}
	return nil
}

// LoadOrCreate returns the persistent identity for endpointID under the
// Node-local stateDir. New identities are installed atomically without
// replacing an existing identity, including when multiple processes race.
// endpointID must be a canonical stable Endpoint identifier from trusted local
// binding state; this function does not authenticate or authorize that value.
func LoadOrCreate(stateDir, endpointID string) (*e2ee.Identity, error) {
	if err := validateEndpointID(endpointID); err != nil {
		return nil, err
	}
	root, err := cleanStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	if err := ensureStateDirectory(root); err != nil {
		return nil, err
	}
	keyDir := filepath.Join(root, keyDirectoryName)
	if err := ensurePrivateKeyDirectory(keyDir); err != nil {
		return nil, err
	}
	path := identityPath(keyDir, endpointID)

	identity, err := readIdentity(path, endpointID)
	if err == nil {
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	identity, err = e2ee.NewIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate Endpoint E2EE identity: %w", err)
	}
	private, err := identity.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("encode Endpoint E2EE identity: %w", err)
	}
	record := identityRecord{Version: diskVersion, EndpointID: endpointID,
		Public: identity.Public(), Private: private}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode Endpoint identity record: %w", err)
	}
	if len(encoded) > maxIdentityRecord {
		return nil, errors.New("Endpoint identity record exceeds size limit")
	}

	installed, err := installWithoutReplace(keyDir, path, encoded)
	if err != nil {
		return nil, err
	}
	if !installed {
		// Another process won the create race. Use only the complete record it
		// atomically installed; never replace it with our newly generated key.
		return readIdentity(path, endpointID)
	}
	return identity, nil
}

func validateEndpointID(endpointID string) error {
	if endpointID == "" || len(endpointID) > 256 || strings.TrimSpace(endpointID) != endpointID {
		return errors.New("Endpoint ID must be a non-empty canonical identifier")
	}
	for i, value := range endpointID {
		valid := value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
			value >= '0' && value <= '9' || value == '_' || value == '-' || value == '.'
		if !valid || (i == 0 && !(value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9')) {
			return errors.New("Endpoint ID contains unsupported path or control characters")
		}
	}
	return nil
}

func cleanStateDir(stateDir string) (string, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return "", errors.New("Node-local state directory is required")
	}
	for _, component := range strings.Split(stateDir, string(filepath.Separator)) {
		if component == ".." {
			return "", errors.New("Node-local state directory cannot contain parent traversal")
		}
	}
	clean := filepath.Clean(stateDir)
	absolute, err := filepath.Abs(clean)
	if err != nil {
		return "", fmt.Errorf("resolve Node-local state directory: %w", err)
	}
	return absolute, nil
}

func identityPath(keyDir, endpointID string) string {
	digest := sha256.Sum256([]byte(endpointID))
	return filepath.Join(keyDir, "identity-"+hex.EncodeToString(digest[:])+".json")
}

func readIdentity(path, expectedEndpointID string) (*e2ee.Identity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("inspect Endpoint identity file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Endpoint identity file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Endpoint identity path is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o400 == 0 {
		return nil, fmt.Errorf("Endpoint identity file has insecure mode %04o", info.Mode().Perm())
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Endpoint identity file: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat Endpoint identity file: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(openedInfo, pathInfo) || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Endpoint identity path changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxIdentityRecord+1))
	if err != nil {
		return nil, fmt.Errorf("read Endpoint identity file: %w", err)
	}
	if len(data) == 0 || len(data) > maxIdentityRecord {
		return nil, errors.New("Endpoint identity file is empty or exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record identityRecord
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode Endpoint identity file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("Endpoint identity file has trailing data")
	}
	if record.Version != diskVersion {
		return nil, fmt.Errorf("unsupported Endpoint identity file version %d", record.Version)
	}
	if record.EndpointID != expectedEndpointID {
		return nil, errors.New("Endpoint identity file belongs to a different Endpoint")
	}
	if err := e2ee.ValidatePublicIdentity(record.Public); err != nil {
		return nil, fmt.Errorf("validate stored Endpoint public identity: %w", err)
	}
	identity, err := e2ee.UnmarshalIdentity(record.Private)
	if err != nil {
		return nil, fmt.Errorf("restore Endpoint private identity: %w", err)
	}
	public := identity.Public()
	if public.ID != record.Public.ID || !bytes.Equal(public.KEMPublic, record.Public.KEMPublic) ||
		!bytes.Equal(public.SigningPublic, record.Public.SigningPublic) {
		return nil, errors.New("Endpoint private identity does not match stored public identity")
	}
	return identity, nil
}

// installWithoutReplace returns installed=false if another caller already
// installed this endpoint's record. Hard-link creation is atomic and fails if
// target exists; rename is deliberately avoided because it would replace keys.
func installWithoutReplace(directory, target string, data []byte) (installed bool, retErr error) {
	temporary, err := os.CreateTemp(directory, ".endpoint-identity-*")
	if err != nil {
		return false, fmt.Errorf("create temporary Endpoint identity file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) && retErr == nil {
			retErr = fmt.Errorf("remove temporary Endpoint identity file: %w", err)
		}
	}()
	if err := temporary.Chmod(keyFileMode); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("protect temporary Endpoint identity file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("write temporary Endpoint identity file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("sync temporary Endpoint identity file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("close temporary Endpoint identity file: %w", err)
	}
	if err := os.Link(temporaryPath, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("install Endpoint identity without replacement: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return true, err
	}
	return true, nil
}

func ensureStateDirectory(path string) error {
	if err := ensureDirectoriesWithoutSymlinks(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Node-local state directory: %w", err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("Node-local state directory is group or world writable: mode %04o", info.Mode().Perm())
	}
	return nil
}

func ensurePrivateKeyDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, keyDirectoryMode); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create Node Endpoint key directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect Node Endpoint key directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Node Endpoint key directory must be a real directory")
	}
	if info.Mode().Perm() != keyDirectoryMode {
		return fmt.Errorf("Node Endpoint key directory must have mode 0700, got %04o", info.Mode().Perm())
	}
	return nil
}

func ensureDirectoriesWithoutSymlinks(path string) error {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(abs)
	current := volume + string(filepath.Separator)
	rest := strings.TrimPrefix(abs, current)
	for _, component := range strings.Split(rest, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if mkdirErr := os.Mkdir(current, keyDirectoryMode); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return fmt.Errorf("create Node-local state directory %q: %w", current, mkdirErr)
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return fmt.Errorf("inspect Node-local state path %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("Node-local state path component %q is not a real directory", current)
		}
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Endpoint key directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Endpoint key directory: %w", err)
	}
	return nil
}
