//go:build windows

package appcore

import (
	"errors"
	"os"
	"path/filepath"
)

func nativeVaultRoot() (string, error) {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" || !filepath.IsAbs(local) {
		return "", errors.New("Windows Local AppData is unavailable")
	}
	return filepath.Join(local, "CICADA", "vaults"), nil
}
