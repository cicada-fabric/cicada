//go:build !linux

package nodebackup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func publishNewDirectory(source, destination string) error {
	if _, err := os.Lstat(destination); err == nil {
		return ErrBackupExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect Node backup destination: %w", err)
	}
	if err := os.Rename(source, destination); err != nil {
		return fmt.Errorf("atomically publish Node backup: %w", err)
	}
	return syncDirectory(filepath.Dir(destination))
}

func publishRestoreDirectory(source, destination string) error {
	removedEmptyTarget := false
	info, err := os.Lstat(destination)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrRestoreTargetBusy
		}
		contents, readErr := os.ReadDir(destination)
		if readErr != nil {
			return fmt.Errorf("recheck Node restore target: %w", readErr)
		}
		if len(contents) != 0 {
			return ErrRestoreTargetBusy
		}
		if removeErr := os.Remove(destination); removeErr != nil {
			if !errors.Is(removeErr, os.ErrNotExist) {
				return fmt.Errorf("remove empty Node restore target: %w", removeErr)
			}
		} else {
			removedEmptyTarget = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("recheck Node restore target: %w", err)
	}
	if err := os.Rename(source, destination); err != nil {
		if removedEmptyTarget {
			// Recreate the old empty target only if no concurrent path now
			// occupies it; never remove or replace that new path.
			if mkdirErr := os.Mkdir(destination, privateDirMode); mkdirErr == nil {
				_ = syncDirectory(filepath.Dir(destination))
			} else if !errors.Is(mkdirErr, os.ErrExist) {
				err = errors.Join(err, fmt.Errorf("restore empty Node target after publish failure: %w", mkdirErr))
			}
		}
		if errors.Is(err, os.ErrExist) {
			return ErrRestoreTargetBusy
		}
		return fmt.Errorf("atomically publish quarantined Node restore: %w", err)
	}
	return syncDirectory(filepath.Dir(destination))
}
