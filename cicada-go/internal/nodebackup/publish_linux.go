//go:build linux

package nodebackup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func publishNewDirectory(source, destination string) error {
	if err := renameNoReplace(source, destination); err != nil {
		if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY) {
			return ErrBackupExists
		}
		return fmt.Errorf("atomically publish Node backup: %w", err)
	}
	return syncDirectory(filepath.Dir(destination))
}

func publishRestoreDirectory(source, destination string) (bool, error) {
	removedEmptyTarget := false
	info, err := os.Lstat(destination)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false, ErrRestoreTargetBusy
		}
		contents, readErr := os.ReadDir(destination)
		if readErr != nil {
			return false, fmt.Errorf("recheck Node restore target: %w", readErr)
		}
		if len(contents) != 0 {
			return false, ErrRestoreTargetBusy
		}
		// Removing only an empty directory makes an existing empty target
		// portable across filesystems. AT_REMOVEDIR also fails closed if the
		// target was swapped for a symlink or file after the checks above.
		if removeErr := unix.Unlinkat(unix.AT_FDCWD, destination, unix.AT_REMOVEDIR); removeErr != nil {
			if !errors.Is(removeErr, unix.ENOENT) {
				if errors.Is(removeErr, unix.ENOTEMPTY) || errors.Is(removeErr, unix.EEXIST) || errors.Is(removeErr, unix.ENOTDIR) {
					return false, ErrRestoreTargetBusy
				}
				return false, fmt.Errorf("remove empty Node restore target: %w", removeErr)
			}
		} else {
			removedEmptyTarget = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("recheck Node restore target: %w", err)
	}
	if err := renameNoReplace(source, destination); err != nil {
		if removedEmptyTarget {
			// Preserve the caller's empty target where possible, but never
			// replace a path another process may have created in the meantime.
			if mkdirErr := os.Mkdir(destination, privateDirMode); mkdirErr == nil {
				_ = syncDirectory(filepath.Dir(destination))
			} else if !errors.Is(mkdirErr, os.ErrExist) {
				err = errors.Join(err, fmt.Errorf("restore empty Node target after publish failure: %w", mkdirErr))
			}
		}
		if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY) {
			return false, ErrRestoreTargetBusy
		}
		return false, fmt.Errorf("atomically publish quarantined Node restore: %w", err)
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return true, fmt.Errorf("sync published Node restore parent: %w", err)
	}
	return true, nil
}

func renameNoReplace(source, destination string) error {
	return unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE)
}
