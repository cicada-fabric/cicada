package componentinstall

import (
	"errors"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

func validateManagedDirectory(info fs.FileInfo) error {
	// POSIX mode bits do not establish Windows ownership or ACL protection.
	// Native installation/ACL acceptance requires a separate Windows gate.
	if !info.IsDir() {
		return errors.New("component path must be a directory")
	}
	return nil
}

func tryFileLock(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
}
