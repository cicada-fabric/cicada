//go:build linux

package store

import "golang.org/x/sys/unix"

// No remove or two-rename fallback: an unsupported exchange remains held.
func hubRestoreDirectoryExchange(target, staging string) error {
	return unix.Renameat2(unix.AT_FDCWD, target, unix.AT_FDCWD, staging, unix.RENAME_EXCHANGE)
}
