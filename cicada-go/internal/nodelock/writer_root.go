package nodelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofrs/flock"
)

const writerRootMaintenanceName = ".writer-root.maintenance.lock"

// AcquireWriterRoot coordinates all Hub-specific Node Agents that share one
// WriterRoot. Agents take this shared lock for their lifetime; they remain
// concurrent with one another. Offline backup/restore takes the exclusive
// counterpart and fails immediately while any Agent or operator writer holds
// the shared lock.
func AcquireWriterRoot(writerRoot string) (*Lock, error) {
	return acquireWriterRoot(writerRoot, false)
}

// AcquireWriterRootExclusive attempts an offline shared-state maintenance
// window. It never waits for a live Agent to stop.
func AcquireWriterRootExclusive(writerRoot string) (*Lock, error) {
	return acquireWriterRoot(writerRoot, true)
}

func acquireWriterRoot(writerRoot string, exclusive bool) (*Lock, error) {
	writerRoot = strings.TrimSpace(writerRoot)
	if writerRoot == "" {
		return nil, errors.New("shared Node WriterRoot is required")
	}
	absolute, err := filepath.Abs(filepath.Clean(writerRoot))
	if err != nil {
		return nil, fmt.Errorf("resolve shared Node WriterRoot: %w", err)
	}
	if err := rejectWriterRootSymlinkComponents(absolute); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("create shared Node WriterRoot: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("shared Node WriterRoot must be a real private directory")
	}
	path := filepath.Join(absolute, writerRootMaintenanceName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err == nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("close shared WriterRoot lock file: %w", closeErr)
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("prepare shared WriterRoot lock file: %w", err)
	}
	beforeLockInfo, err := os.Lstat(path)
	if err != nil || beforeLockInfo.Mode()&os.ModeSymlink != 0 || !beforeLockInfo.Mode().IsRegular() {
		return nil, errors.New("shared WriterRoot lock path is unsafe")
	}
	lock := flock.New(path, flock.SetPermissions(0o600))
	if exclusive {
		locked, err := lock.TryLock()
		if err != nil {
			return nil, fmt.Errorf("lock shared WriterRoot for maintenance: %w", err)
		}
		if !locked {
			return nil, ErrBusy
		}
	} else {
		locked, err := lock.TryRLock()
		if err != nil {
			return nil, fmt.Errorf("lock shared WriterRoot: %w", err)
		}
		if !locked {
			return nil, ErrBusy
		}
	}
	lockedInfo, err := os.Lstat(path)
	if err != nil || lockedInfo.Mode()&os.ModeSymlink != 0 || !lockedInfo.Mode().IsRegular() || !os.SameFile(beforeLockInfo, lockedInfo) {
		_ = lock.Unlock()
		return nil, errors.New("shared WriterRoot lock path is unsafe")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = lock.Unlock()
		return nil, fmt.Errorf("protect shared WriterRoot lock file: %w", err)
	}
	return &Lock{file: lock}, nil
}

func rejectWriterRootSymlinkComponents(absolute string) error {
	volume := filepath.VolumeName(absolute)
	current := volume + string(filepath.Separator)
	remainder := strings.TrimPrefix(absolute, current)
	for _, component := range strings.Split(remainder, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect shared WriterRoot path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("shared Node WriterRoot path contains a symbolic link")
		}
	}
	return nil
}
