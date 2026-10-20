//go:build linux || darwin

package apppaths

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func validatePlatformRoot(selected string) error {
	// Traverse every existing ancestor without accepting a link. A missing
	// suffix is only a location proposal; the component's protected writer is
	// still responsible for atomic creation and private state-file permissions.
	current := selected
	leaf := true
	for {
		info, err := os.Lstat(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return ErrInvalidRoot
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return ErrInvalidRoot
			}
			if leaf && stat.Uid != uint32(os.Geteuid()) {
				return ErrInvalidRoot
			}
			if info.Mode().Perm()&0022 != 0 {
				// A sticky temporary ancestor cannot remove an existing
				// user-owned child. It is never itself an acceptable user root.
				if current == selected || info.Mode()&os.ModeSticky == 0 {
					return ErrInvalidRoot
				}
			}
			if stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0 {
				return ErrInvalidRoot
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current, leaf = parent, false
	}
}
