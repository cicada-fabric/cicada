package componentinstall

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func validateManagedDirectory(info fs.FileInfo) error {
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("component directory must not be writable by other users")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || uint64(stat.Uid) != uint64(os.Geteuid()) {
		return errors.New("component directory must belong to the current user")
	}
	return nil
}

func tryFileLock(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
