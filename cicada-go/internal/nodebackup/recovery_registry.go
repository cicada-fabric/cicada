package nodebackup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const recoveryRegistryDirectory = ".recovery-pending"

type recoveryRegistration struct {
	Version              int    `json:"version"`
	NodeID               string `json:"node_id"`
	Status               string `json:"recovery_status"`
	BackupManifestSHA256 string `json:"backup_manifest_sha256"`
	CreatedAt            string `json:"created_at"`
	Reason               string `json:"reason"`
}

func recoveryRegistrationPath(stateRoot, nodeID string) string {
	return filepath.Join(stateRoot, "nodes", recoveryRegistryDirectory,
		"node-"+url.PathEscape(nodeID)+".json")
}

// RecoveryQuarantineActive reports whether the Node has either the external
// restore registration or the original in-tree recovery marker. Existing but
// malformed entries still mean quarantined; inspection errors fail closed.
func RecoveryQuarantineActive(stateDir, nodeID string) (bool, error) {
	stateRoot, err := canonicalPath(stateDir)
	if err != nil {
		return false, err
	}
	if err := validateNodeID(nodeID); err != nil {
		return false, err
	}
	nodesDir := filepath.Join(stateRoot, "nodes")
	if err := requireDirectoryIfPresent(nodesDir, 0); err != nil {
		return false, err
	} else if _, statErr := os.Lstat(nodesDir); errors.Is(statErr, os.ErrNotExist) {
		return false, nil
	}

	registryDir := filepath.Join(nodesDir, recoveryRegistryDirectory)
	if err := requireDirectoryIfPresent(registryDir, privateDirMode.Perm()); err != nil {
		return false, err
	} else if _, statErr := os.Lstat(registryDir); statErr == nil {
		path := recoveryRegistrationPath(stateRoot, nodeID)
		if _, statErr := os.Lstat(path); statErr == nil {
			return true, nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return false, fmt.Errorf("inspect Node recovery registration: %w", statErr)
		}
	}

	nodeDir := nodeStatePath(stateRoot, nodeID)
	if err := requireDirectoryIfPresent(nodeDir, 0); err != nil {
		return false, err
	} else if _, statErr := os.Lstat(nodeDir); errors.Is(statErr, os.ErrNotExist) {
		return false, nil
	}
	markerPath := filepath.Join(nodeDir, recoveryMarker)
	if _, err := os.Lstat(markerPath); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect Node recovery marker: %w", err)
	}
	return false, nil
}

func ensureRecoveryRegistration(stateRoot string, manifest *Manifest) (created bool, retErr error) {
	nodesDir := filepath.Join(stateRoot, "nodes")
	registryDir := filepath.Join(nodesDir, recoveryRegistryDirectory)
	if err := ensurePrivateDirectory(registryDir); err != nil {
		return false, err
	}
	// Persist the registry directory entry before writing the registration. A
	// crash during restore must leave either no registration and no published
	// Node, or a visible registration that prevents Agent startup.
	if err := syncDirectory(stateRoot); err != nil {
		return false, fmt.Errorf("sync Node StateDir before recovery registration: %w", err)
	}
	if err := syncDirectory(nodesDir); err != nil {
		return false, fmt.Errorf("sync Node state root before recovery registration: %w", err)
	}

	path := recoveryRegistrationPath(stateRoot, manifest.NodeID)
	if _, err := os.Lstat(path); err == nil {
		if err := verifyRecoveryRegistration(path, manifest); err != nil {
			return false, err
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect existing Node recovery registration: %w", err)
	}

	registration := recoveryRegistration{Version: 1, NodeID: manifest.NodeID, Status: "pending",
		BackupManifestSHA256: digestManifest(*manifest),
		CreatedAt:            time.Now().UTC().Format(time.RFC3339Nano), Reason: recoveryPendingReason}
	data, err := json.MarshalIndent(registration, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encode Node recovery registration: %w", err)
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, privateFileMode)
	if errors.Is(err, os.ErrExist) {
		if verifyErr := verifyRecoveryRegistration(path, manifest); verifyErr != nil {
			return false, verifyErr
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("create Node recovery registration: %w", err)
	}
	created = true
	closed := false
	defer func() {
		if !closed {
			if closeErr := file.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close Node recovery registration: %w", closeErr))
			}
		}
	}()
	if err := file.Chmod(privateFileMode); err != nil {
		return created, fmt.Errorf("protect Node recovery registration: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return created, fmt.Errorf("write Node recovery registration: %w", err)
	}
	if err := file.Sync(); err != nil {
		return created, fmt.Errorf("sync Node recovery registration: %w", err)
	}
	closeErr := file.Close()
	closed = true
	if closeErr != nil {
		return created, fmt.Errorf("close Node recovery registration: %w", closeErr)
	}
	if err := syncDirectory(registryDir); err != nil {
		return created, fmt.Errorf("sync Node recovery registry directory: %w", err)
	}
	return created, nil
}

func verifyRecoveryRegistration(path string, manifest *Manifest) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != privateFileMode.Perm() || info.Size() > 16*1024 {
		return fmt.Errorf("Node recovery registration is missing or invalid: %w", ErrBackupInvalid)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read Node recovery registration: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var registration recoveryRegistration
	if err := decoder.Decode(&registration); err != nil {
		return fmt.Errorf("decode Node recovery registration: %w", ErrBackupInvalid)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("Node recovery registration has trailing data: %w", ErrBackupInvalid)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, registration.CreatedAt)
	if err != nil {
		return fmt.Errorf("Node recovery registration timestamp is invalid: %w", ErrBackupInvalid)
	}
	expected := recoveryRegistration{Version: 1, NodeID: manifest.NodeID, Status: "pending",
		BackupManifestSHA256: digestManifest(*manifest),
		CreatedAt:            createdAt.UTC().Format(time.RFC3339Nano), Reason: recoveryPendingReason}
	expectedBytes, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		return fmt.Errorf("encode expected Node recovery registration: %w", ErrBackupInvalid)
	}
	expectedBytes = append(expectedBytes, '\n')
	if !bytes.Equal(data, expectedBytes) {
		return fmt.Errorf("Node recovery registration does not match the verified backup: %w", ErrBackupInvalid)
	}
	return nil
}

func removeRecoveryRegistration(stateRoot, nodeID string) error {
	path := recoveryRegistrationPath(stateRoot, nodeID)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	} else if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return syncDirectory(filepath.Dir(path))
}

func ensurePrivateDirectory(path string) error {
	if err := os.Mkdir(path, privateDirMode); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create private Node recovery registry: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != privateDirMode.Perm() {
		return fmt.Errorf("Node recovery registry directory is invalid: %w", ErrBackupInvalid)
	}
	return nil
}

func requireDirectoryIfPresent(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Node recovery path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || mode != 0 && info.Mode().Perm() != mode {
		return fmt.Errorf("Node recovery path is not a private directory: %w", ErrBackupInvalid)
	}
	return nil
}
