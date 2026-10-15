//go:build !windows

package appcore

import (
	"os"
	"path/filepath"
)

func nativeVaultRoot() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil || root == "" {
		return "", err
	}
	return filepath.Join(root, "CICADA", "vaults"), nil
}
