//go:build !linux

package store

import "errors"

// Compile portability does not imply safe activation support on this OS.
func hubRestoreDirectoryExchange(target, staging string) error {
	return errors.New("atomic Hub directory exchange is unsupported on this operating system; restore remains held")
}
