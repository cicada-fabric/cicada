//go:build linux || darwin

package appvault

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gofrs/flock"
)

func ensurePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || rejectSymlinkComponents(path) != nil {
		return ErrInvalidVault
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return ErrInvalidVault
		}
	} else if err != nil {
		return ErrInvalidVault
	}
	if rejectSymlinkComponents(path) != nil {
		return ErrInvalidVault
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ErrInvalidVault
	}
	return nil
}

func ensureLockFile(path string) error {
	if err := validatePrivateParent(filepath.Dir(path)); err != nil {
		return err
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	created := err == nil
	if errors.Is(err, syscall.EEXIST) {
		fd, err = syscall.Open(path, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	}
	if err != nil {
		return ErrInvalidVault
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrInvalidVault
	}
	if created {
		if err := f.Chmod(0o600); err != nil {
			return ErrInvalidVault
		}
	} else if info.Mode().Perm() != 0o600 {
		return ErrInvalidVault
	}
	return nil
}

func verifyLockFile(path string, lock *flock.Flock) error {
	if lock == nil || !lock.Locked() || lock.Path() != path || validatePrivateParent(filepath.Dir(path)) != nil {
		return ErrInvalidVault
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return ErrInvalidVault
	}
	return nil
}

func validatePlatformVaultFile(path string, info os.FileInfo) error {
	if info.Mode().Perm() != 0o600 || validatePrivateParent(filepath.Dir(path)) != nil {
		return ErrInvalidVault
	}
	return nil
}

func writeVaultAtomic(path string, data []byte, replace bool) (bool, error) {
	parent := filepath.Dir(path)
	if err := validatePrivateParent(parent); err != nil || len(data) == 0 || len(data) > maxVaultFileBytes {
		return false, ErrInvalidVault
	}
	if replace {
		if _, err := checkVaultFile(path); err != nil {
			return false, ErrInvalidVault
		}
	} else if _, err := os.Lstat(path); err == nil {
		return false, ErrVaultExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, ErrInvalidVault
	}

	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return false, ErrInvalidVault
	}
	temporary := filepath.Join(parent, ".cicada-appvault-"+hexString(random[:]))
	f, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false, ErrInvalidVault
	}
	if err = f.Chmod(0o600); err == nil {
		err = writeAll(f, data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		_ = os.Remove(temporary)
		return false, ErrInvalidVault
	}

	committed := false
	if replace {
		if err := os.Rename(temporary, path); err != nil {
			_ = os.Remove(temporary)
			return false, ErrInvalidVault
		}
		committed = true
	} else {
		if err := os.Link(temporary, path); err != nil {
			_ = os.Remove(temporary)
			if errors.Is(err, os.ErrExist) {
				return false, ErrVaultExists
			}
			return false, ErrInvalidVault
		}
		committed = true
		if err := os.Remove(temporary); err != nil {
			return true, ErrInvalidVault
		}
	}
	if err := syncVaultParentDirectory(parent); err != nil {
		return true, ErrInvalidVault
	}
	return committed, nil
}

func validatePrivateParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || rejectSymlinkComponents(path) != nil {
		return ErrInvalidVault
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ErrInvalidVault
	}
	return nil
}

func rejectSymlinkComponents(path string) error {
	clean := filepath.Clean(path)
	if clean != path {
		return ErrInvalidVault
	}
	current := string(filepath.Separator)
	missing := false
	for _, part := range strings.Split(strings.TrimPrefix(path, current), current) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		if missing {
			continue
		}
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			missing = true
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalidVault
		}
	}
	return nil
}

var syncVaultParentDirectory = syncVaultParentDirectoryImpl

func syncVaultParentDirectoryImpl(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
