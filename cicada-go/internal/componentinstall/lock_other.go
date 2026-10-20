//go:build !linux && !windows

package componentinstall

import (
	"errors"
	"io/fs"
	"os"
)

func validateManagedDirectory(fs.FileInfo) error {
	return errors.New("unsupported component installation platform")
}

func tryFileLock(*os.File) error { return errors.New("unsupported component installation platform") }
