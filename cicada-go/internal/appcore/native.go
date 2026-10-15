package appcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/cicada-ai/cicada/internal/appvault"
)

type VaultOpener func(context.Context, appvault.Scope, bool) (*appvault.Vault, error)

// OpenNativeController constructs the desktop App core with the platform
// vault protector and a no-proxy, redirect-rejecting HTTPS client. On Windows
// this uses current-user DPAPI. Other platforms compile for development but
// return an unsupported-platform vault error when a vault is opened.
func OpenNativeController() (Controller, error) {
	root, err := nativeVaultRoot()
	if err != nil || root == "" {
		return nil, errors.New("native App configuration directory unavailable")
	}
	return NewController(Config{HTTP: NewHTTPClient(), OpenVault: NewPlatformVaultOpener(filepath.Join(root, "CICADA", "vaults"))})
}

// NewPlatformVaultOpener returns a scope-derived file path under root. The
// filename hashes all scope fields, preventing path injection and keeping
// different Hub/account/Owner pins in separate vaults.
func NewPlatformVaultOpener(root string) VaultOpener {
	return platformVaultOpener(root)
}

func scopeVaultPath(root string, scope appvault.Scope) (string, error) {
	if root == "" {
		return "", errors.New("invalid App vault location")
	}
	encoded, err := json.Marshal(scope)
	if err != nil {
		return "", errors.New("invalid App vault scope")
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return filepath.Join(root, hex.EncodeToString(digest[:])+".vault"), nil
}
