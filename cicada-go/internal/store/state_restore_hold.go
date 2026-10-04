package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const (
	stateRestoreMarker   = ".hub-restore-pending.json"
	stateRestoreRegistry = ".hub-restore-pending"
)

var ErrStateRestoreQuarantined = errors.New("Hub StateDir is quarantined after restore; independent authority and counter reconciliation is required before startup")

// canonicalRestoreTarget resolves existing parent aliases, including when the
// target does not exist yet. The target itself must not be a symlink. Registry
// coordinates belong to this exact parent-local filesystem namespace, not HOME
// or a process-wide configuration. Moving restored data is not activation.
func canonicalRestoreTarget(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", ErrStateBackupPathUnsafe
	}
	abs, err := filepath.Abs(path)
	if err != nil || abs == string(filepath.Separator) {
		return "", ErrStateBackupPathUnsafe
	}
	if info, err := os.Lstat(abs); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", ErrStateBackupPathUnsafe
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(abs)
	tail := []string{filepath.Base(abs)}
	for {
		resolved, err := filepath.EvalSymlinks(parent)
		if err == nil {
			info, statErr := os.Stat(resolved)
			if statErr != nil || !info.IsDir() {
				return "", ErrStateBackupPathUnsafe
			}
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) || parent == string(filepath.Separator) {
			return "", err
		}
		tail = append(tail, filepath.Base(parent))
		parent = filepath.Dir(parent)
	}
}

func stateRestoreRegistrationPath(target string) string {
	digest := sha256.Sum256([]byte(target))
	return filepath.Join(filepath.Dir(target), stateRestoreRegistry, hex.EncodeToString(digest[:])+".json")
}

// StateRestoreQuarantineActive is read-only. Either marker is sufficient to
// hold startup, including a malformed marker or a missing paired marker.
// Inspection errors never turn unknown recovery state into permission.
func StateRestoreQuarantineActive(stateDir string) (bool, error) {
	target, err := canonicalRestoreTarget(stateDir)
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(filepath.Join(target, stateRestoreMarker)); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	registry := filepath.Dir(stateRestoreRegistrationPath(target))
	if info, err := os.Lstat(registry); err == nil {
		if !stateRestorePrivateDirectory(info) {
			return false, ErrStateBackupPathUnsafe
		}
	} else if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else {
		return false, err
	}
	if _, err := os.Lstat(stateRestoreRegistrationPath(target)); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return false, nil
}

// RequireStateRestoreStartupAllowed guards production server constructors
// before any writable Store, identity creation or listener. Store.New remains
// the low-level maintenance primitive; opening it is not activation authority.
func RequireStateRestoreStartupAllowed(stateDir string) error {
	target, err := canonicalRestoreTarget(stateDir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStateRestoreQuarantined, err)
	}
	registered, err := hubRestoreStartupPermission(target)
	if registered {
		if err != nil {
			return fmt.Errorf("%w: %v", ErrStateRestoreQuarantined, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStateRestoreQuarantined, err)
	}
	held, err := StateRestoreQuarantineActive(target)
	if err != nil {
		return fmt.Errorf("cannot verify Hub restore quarantine: %w: %v", ErrStateRestoreQuarantined, err)
	}
	if held {
		return ErrStateRestoreQuarantined
	}
	return nil
}

func stateRestorePrivateDirectory(info os.FileInfo) bool {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode() != os.ModeDir|0700 {
		return false
	}
	// Match the existing portable TLS ownership check: unknown ownership fails
	// closed rather than assuming this process owns an existing registry.
	v := reflect.ValueOf(info.Sys())
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return false
	}
	uid := v.Elem().FieldByName("Uid")
	return uid.IsValid() && uid.CanUint() && uid.Uint() == uint64(os.Geteuid())
}

func reservedStateRestorePath(path string) bool {
	path = filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	return path == hubRestoreSourceMarker || strings.HasPrefix(path, hubRestoreSourceMarker+"/") || path == hubRestoreAuthorityDirectory || strings.HasPrefix(path, hubRestoreAuthorityDirectory+"/") || path == stateRestoreMarker || strings.HasPrefix(path, stateRestoreMarker+"/") ||
		path == stateRestoreRegistry || strings.HasPrefix(path, stateRestoreRegistry+"/")
}

// registerStateRestoreHold runs only after the archived inventory has been
// verified. The added marker is not archived data. Registration is durable
// before publish, and is deliberately retained on every later failure.
func registerStateRestoreHold(staging, target string, manifest *StateBackupManifest) error {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	hold := struct {
		Version        int    `json:"version"`
		Target         string `json:"target_state_dir"`
		ManifestSHA256 string `json:"backup_manifest_sha256"`
		Status         string `json:"recovery_status"`
		CreatedAt      string `json:"created_at"`
	}{1, target, hex.EncodeToString(digest[:]), "pending", time.Now().UTC().Format(time.RFC3339Nano)}
	if err := writePrivateJSON(filepath.Join(staging, stateRestoreMarker), hold); err != nil {
		return fmt.Errorf("write Hub recovery marker: %w", err)
	}
	if err := syncDirectory(staging); err != nil {
		return err
	}
	registry := filepath.Dir(stateRestoreRegistrationPath(target))
	if err := os.Mkdir(registry, stateBackupDirMode); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create Hub recovery registry: %w", err)
	}
	info, err := os.Lstat(registry)
	if err != nil || !stateRestorePrivateDirectory(info) {
		return ErrStateBackupPathUnsafe
	}
	if err := syncDirectory(filepath.Dir(target)); err != nil {
		return err
	}
	if err := writePrivateJSON(stateRestoreRegistrationPath(target), hold); err != nil {
		return fmt.Errorf("register Hub recovery hold: %w", err)
	}
	return syncDirectory(registry)
}
